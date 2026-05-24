//! Top-level `Db<V>` façade. Owns the Pager, header state, writer slot, and
//! reader registration table. H ships a single-realm minimal surface;
//! multi-realm + catalog support lands later.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::sync::Mutex as AsyncMutex;

use crate::btree::BTree;
use crate::catalog::codec::CatalogRowKind;
use crate::catalog::codec::{Catalog, RealmQuotas, RekeyStateRow, SegmentKind, SegmentMeta};
use crate::crypto::CipherId;
use crate::crypto::kdf::{derive_hk, derive_mk};
use crate::errors::PagedbError;
use crate::observability::DbStats;
use crate::options::OpenOptions;
use crate::pager::header::{ActiveSlot, bootstrap_header, commit_header};
use crate::pager::structural_header::MainDbHeaderFields;
use crate::pager::{Pager, PagerConfig};
use crate::segment::reader::SegmentReader;
use crate::segment::types::GcStats;
use crate::segment::writer::SegmentWriter;
use crate::vfs::Vfs;
use crate::{CommitId, RealmId, Result};

use super::mode::{DbMode, FROZEN_READERS_LOCK_PATH, OBSERVERS_LOCK_PATH, WRITER_LOCK_PATH};
use super::policy::ReaderStallPolicy;
use super::read::{ReadTxn, delete_pin_rows, make_pin_handle};
use super::write::WriteTxn;

/// A segment tombstone that was deferred because a reader was pinning it at
/// commit time.
#[derive(Debug, Clone)]
pub(crate) struct PendingTombstone {
    pub segment_id: [u8; 16],
    pub commit_id: u64,
}

/// One registered reader's pin record. Held in the `Db`'s tracked-reader `Vec`.
#[derive(Debug)]
pub(crate) struct TrackedReader {
    pub entry_id: u64,
    pub commit_id: CommitId,
    #[allow(dead_code)]
    pub root_page_id: u64,
    pub next_page_id: u64,
    pub catalog_root_page_id: u64,
    pub non_abortable: bool,
}

/// Writer state, guarded by the writer mutex. Holds the current root and
/// allocation cursor; on commit the new values get persisted to the header.
pub(crate) struct WriterState {
    pub root_page_id: u64,
    pub next_page_id: u64,
    pub active_slot: ActiveSlot,
    pub latest_commit_id: u64,
    pub seq: u64,
    pub catalog_root_page_id: u64,
    pub catalog_root_txn_id: u64,
    /// Root page id of the commit-history B+ tree (0 = not yet created).
    pub commit_history_root_page_id: u64,
    /// Version / `txn_id` of the commit-history tree's last write.
    pub commit_history_root_version: u64,
    /// Cached number of entries in the commit-history tree. Maintained by
    /// `write_commit_history_entry` so pruning can skip the full
    /// `collect_range` scan when the count is provably below the retain
    /// limit. `None` means "not yet populated; refresh from disk on first
    /// use". Re-populated lazily after a reopen.
    pub commit_history_count: Option<u64>,
}

/// Top-level handle to an open database.
///
/// `V` must implement `Clone`; the `Db` keeps one `Arc<V>` for header
/// operations while the `Pager` owns a separate cloned instance for data I/O.
/// `MemVfs` satisfies this via its own `#[derive(Clone)]` (shared `Arc`
/// internals). Native VFS backends introduced in later slices will satisfy it
/// the same way.
pub struct Db<V: Vfs + Clone> {
    pub(crate) pager: Arc<Pager<V>>,
    pub(crate) realm_id: RealmId,
    pub(crate) page_size: usize,
    /// Header Key (HK) used to sign A/B header commits. Held in an `RwLock`
    /// so it can be updated atomically during an online rekey without
    /// rebuilding the `Db` handle.
    pub(crate) hk: parking_lot::RwLock<crate::crypto::keys::DerivedKey>,
    pub(crate) main_db_path: String,
    pub(crate) vfs: Arc<V>,
    pub(crate) writer: Arc<AsyncMutex<WriterState>>,
    pub(crate) tracked_readers: parking_lot::Mutex<Vec<TrackedReader>>,
    pub(crate) reader_seq: AtomicU64,
    pub(crate) latest_commit: AtomicU64,
    pub(crate) stall_policy: parking_lot::Mutex<ReaderStallPolicy>,
    pub(crate) cipher_id: CipherId,
    pub(crate) mk_epoch: AtomicU64,
    pub(crate) file_id: [u8; 16],
    pub(crate) kek_salt: [u8; 16],
    pub(crate) segment_id_counter: std::sync::atomic::AtomicU64,
    pub(crate) pending_tombstones: parking_lot::Mutex<Vec<PendingTombstone>>,
    /// Reader-pin rows that need to be deleted from the catalog at the next
    /// catalog commit opportunity. Populated by `ReadTxn::drop`; drained by
    /// the next writer commit or explicit `gc_now` call.
    pub(crate) pending_pin_deletes: parking_lot::Mutex<Vec<(u32, u64)>>,
    pub(crate) options: OpenOptions,
    /// Running total of bytes currently charged to `mmap_view_scratch_bytes`.
    /// Shared with live `MmapView` handles via `Arc` so they can decrement on drop.
    pub(crate) mmap_bytes_in_use: std::sync::Arc<AtomicU64>,
    /// Cumulative spill bytes written to the current active write transaction's
    /// tmp file. Reset to 0 when the write transaction commits or aborts.
    pub(crate) spill_bytes_in_use: AtomicU64,
    /// Monotonically increasing counter assigned to each `WriteTxn` at begin.
    /// Each txn gets `txn_seq.fetch_add(1, Relaxed)` (first txn gets 1 since
    /// we start at 0 and add-then-use the pre-increment value + 1).
    pub(crate) txn_seq: AtomicU64,
    /// The mode this handle was opened with (Standalone, Follower, `ReadOnly`, Observer).
    pub(crate) mode: DbMode,
    /// Set of reader `entry_id`s that have been aborted by `AbortOldest` stall
    /// policy. Checked at the start of every `ReadTxn` operation; the entry is
    /// removed once the reader observes the abort.
    pub(crate) aborted_readers: parking_lot::Mutex<std::collections::HashSet<u64>>,
    /// Sentinel-lock handles acquired at open. Released (dropped) when the `Db` drops.
    pub(crate) sentinel_locks: Vec<<V as Vfs>::LockHandle>,
    /// Snapshot of the four reader-visible fields, published atomically at
    /// each writer commit. Read-only path for `begin_read*`: avoids contending
    /// the async writer mutex just to copy four `u64`s. Shared via `Arc` with
    /// `PinHandle` so durable-pin commit paths can also publish.
    pub(crate) snapshot: Arc<parking_lot::RwLock<ReaderSnapshot>>,
    /// Cross-commit cache of page IDs known to be safely reusable. Populated
    /// on commit when `skip_freelist_persistence_when_no_readers` is enabled
    /// and no readers were pinned: instead of orphaning freed pages, recycle
    /// them in-memory so the next writer txn's `allocate_page` pops from
    /// here before bumping `next_page_id`. Keeps the file size bounded under
    /// the fast-free option. Shared with each session's `BTree` via the same
    /// `Arc` so all three trees in a txn (main, catalog, history) draw from
    /// the same pool.
    pub(crate) free_page_cache: Arc<parking_lot::Mutex<Vec<u64>>>,
}

/// Reader-visible state, refreshed by the writer at commit time.
#[derive(Debug, Clone, Copy)]
#[allow(clippy::struct_field_names)]
pub(crate) struct ReaderSnapshot {
    pub commit_id: u64,
    pub root_page_id: u64,
    pub next_page_id: u64,
    pub catalog_root_page_id: u64,
}

impl<V: Vfs + Clone> Db<V> {
    /// Bootstrap a fresh database. Creates `main.db`, writes an initial A/B
    /// header in slot A with `seq=1`. Full `Db::open` variants (read-only,
    /// observer, follower, etc.) land in a later slice.
    ///
    /// `V` must be `Clone`: the `Db` retains an `Arc<V>` for header operations
    /// while the `Pager` owns a separately cloned VFS instance for page I/O.
    pub async fn open_internal(
        vfs: V,
        kek: [u8; 32],
        page_size: usize,
        realm: RealmId,
    ) -> Result<Self> {
        Self::open_internal_with_options_and_cipher(
            vfs,
            kek,
            page_size,
            realm,
            OpenOptions::default(),
            CipherId::Aes256Gcm,
        )
        .await
    }

    /// Like `open_internal` but with explicit cipher selection.
    pub async fn open_internal_with_cipher(
        vfs: V,
        kek: [u8; 32],
        page_size: usize,
        realm: RealmId,
        cipher_id: CipherId,
    ) -> Result<Self> {
        Self::open_internal_with_options_and_cipher(
            vfs,
            kek,
            page_size,
            realm,
            OpenOptions::default(),
            cipher_id,
        )
        .await
    }

    /// Like `open_internal` but with explicit memory budgets.
    pub async fn open_internal_with_options(
        vfs: V,
        kek: [u8; 32],
        page_size: usize,
        realm: RealmId,
        options: OpenOptions,
    ) -> Result<Self> {
        Self::open_internal_with_options_and_cipher(
            vfs,
            kek,
            page_size,
            realm,
            options,
            CipherId::Aes256Gcm,
        )
        .await
    }

    /// Full constructor: explicit cipher and explicit memory budgets.
    pub async fn open_internal_with_options_and_cipher(
        vfs: V,
        kek: [u8; 32],
        page_size: usize,
        realm: RealmId,
        options: OpenOptions,
        cipher_id: CipherId,
    ) -> Result<Self> {
        let main_db_path = "/main.db".to_string();
        let file_id = [0xAB; 16];
        let kek_salt = [0xCD; 16];
        let mk_epoch = 0u64;

        let mk = derive_mk(&kek, &kek_salt, mk_epoch)?;
        let hk = derive_hk(&mk)?;

        let initial = MainDbHeaderFields {
            format_version: 1,
            cipher_id: cipher_id.as_byte(),
            page_size_log2: page_size_log2(page_size)?,
            flags: 0,
            file_id,
            kek_salt,
            mk_epoch,
            seq: 1,
            active_root_page_id: 0,
            active_root_txn_id: 0,
            counter_anchor: 0,
            commit_id: CommitId(0),
            free_list_root: [0; 16],
            catalog_root: [0; 16],
            apply_journal_root_page_id: 0,
            apply_journal_root_version: 0,
            commit_history_root_page_id: 0,
            commit_history_root_version: 0,
            restore_mode: 0,
            next_page_id: 4,

            commit_retain_policy_tag: 0,

            commit_retain_policy_value: 0,
        };
        bootstrap_header(&vfs, &main_db_path, &hk, &initial, page_size).await?;

        let cfg = PagerConfig {
            page_size,
            buffer_pool_pages: options.buffer_pool_pages,
            segment_cache_pages: options.segment_cache_pages,
            cipher_id,
            mk_epoch,
            main_db_file_id: file_id,
            main_db_path: main_db_path.clone(),
            anchor_budget: options.anchor_budget,
            dek_lru_capacity: 256,
            // Standalone: never retry on AEAD failure — treat it as corruption.
            observer_retry_count: 0,
            metrics_enabled: options.metrics_enabled,
        };
        let vfs_arc = Arc::new(vfs);
        let vfs_for_pager = V::clone(&*vfs_arc);
        let pager = Pager::open(vfs_for_pager, mk, cfg).await?;

        let writer = WriterState {
            root_page_id: 0,
            next_page_id: 4,
            active_slot: ActiveSlot::A,
            latest_commit_id: 0,
            seq: 1,
            catalog_root_page_id: 0,
            catalog_root_txn_id: 0,
            commit_history_root_page_id: 0,
            commit_history_root_version: 0,
            // Fresh DB: the commit-history tree is empty.
            commit_history_count: Some(0),
        };

        Ok(Self {
            pager: Arc::new(pager),
            realm_id: realm,
            page_size,
            hk: parking_lot::RwLock::new(hk),
            main_db_path,
            vfs: vfs_arc,
            writer: Arc::new(AsyncMutex::new(writer)),
            tracked_readers: parking_lot::Mutex::new(Vec::new()),
            reader_seq: AtomicU64::new(0),
            latest_commit: AtomicU64::new(0),
            stall_policy: parking_lot::Mutex::new(ReaderStallPolicy::default()),
            cipher_id,
            mk_epoch: AtomicU64::new(mk_epoch),
            file_id,
            kek_salt,
            segment_id_counter: AtomicU64::new(0),
            pending_tombstones: parking_lot::Mutex::new(Vec::new()),
            pending_pin_deletes: parking_lot::Mutex::new(Vec::new()),
            options,
            mmap_bytes_in_use: std::sync::Arc::new(AtomicU64::new(0)),
            spill_bytes_in_use: AtomicU64::new(0),
            txn_seq: AtomicU64::new(0),
            mode: DbMode::Standalone,
            aborted_readers: parking_lot::Mutex::new(std::collections::HashSet::new()),
            sentinel_locks: Vec::new(),
            snapshot: Arc::new(parking_lot::RwLock::new(ReaderSnapshot {
                commit_id: 0,
                root_page_id: 0,
                next_page_id: 4,
                catalog_root_page_id: 0,
            })),
            free_page_cache: Arc::new(parking_lot::Mutex::new(Vec::new())),
        })
    }

    /// Like `open_existing` but with explicit memory budgets.
    pub async fn open_existing_with_options(
        vfs: V,
        kek: [u8; 32],
        page_size: usize,
        realm: RealmId,
        options: OpenOptions,
    ) -> Result<Self> {
        Self::open_existing_inner(vfs, kek, page_size, realm, options).await
    }

    /// Open an existing database that was previously created with
    /// `open_internal`. Reads and verifies both A/B header slots, picks the
    /// active one, recovers the nonce generator, and restores catalog state.
    pub async fn open_existing(
        vfs: V,
        kek: [u8; 32],
        page_size: usize,
        realm: RealmId,
    ) -> Result<Self> {
        Self::open_existing_inner(vfs, kek, page_size, realm, OpenOptions::default()).await
    }

    #[allow(clippy::too_many_lines)]
    async fn open_existing_inner(
        vfs: V,
        kek: [u8; 32],
        page_size: usize,
        realm: RealmId,
        options: OpenOptions,
    ) -> Result<Self> {
        use crate::vfs::VfsFile;
        use crate::vfs::types::OpenMode;

        let main_db_path = "/main.db".to_string();

        // Read both raw header pages to extract kek_salt and mk_epoch without
        // yet knowing HK. We try each header page's own kek_salt to derive HK
        // and verify, then pick the winner by seq.
        let f = vfs.open(&main_db_path, OpenMode::ReadWrite).await?;
        let mut buf_a = vec![0u8; page_size];
        let mut buf_b = vec![0u8; page_size];
        let _ = f.read_at(0, &mut buf_a).await?;
        let page_size_u64 = u64::try_from(page_size)
            .map_err(|_| PagedbError::Io(std::io::Error::other("page_size > u64")))?;
        let _ = f.read_at(page_size_u64, &mut buf_b).await?;
        drop(f);

        // Try to verify each slot with the kek_salt embedded in that slot's
        // cleartext header. kek_salt is at bytes 32..48, mk_epoch at 48..56.
        let try_decode = |buf: &[u8]| -> Option<MainDbHeaderFields> {
            if buf.len() < 56 {
                return None;
            }
            let mut salt = [0u8; 16];
            salt.copy_from_slice(&buf[32..48]);
            let mut ep_bytes = [0u8; 8];
            ep_bytes.copy_from_slice(&buf[48..56]);
            let ep = u64::from_le_bytes(ep_bytes);
            let mk = derive_mk(&kek, &salt, ep).ok()?;
            let hk = derive_hk(&mk).ok()?;
            crate::pager::format::structural_header::decode_main_db_header(buf, &hk, page_size).ok()
        };

        let a = try_decode(&buf_a);
        let b = try_decode(&buf_b);

        let (fields, active_slot) = match (a, b) {
            (Some(a), Some(b)) => {
                if a.seq >= b.seq {
                    (a, ActiveSlot::A)
                } else {
                    (b, ActiveSlot::B)
                }
            }
            (Some(a), None) => (a, ActiveSlot::A),
            (None, Some(b)) => (b, ActiveSlot::B),
            (None, None) => {
                return Err(PagedbError::corruption(
                    crate::errors::CorruptionDetail::HeaderUnverifiable,
                ));
            }
        };

        let cipher_id = CipherId::from_byte(fields.cipher_id)?;
        let mk_epoch = fields.mk_epoch;
        let file_id = fields.file_id;
        let kek_salt = fields.kek_salt;

        let mk = derive_mk(&kek, &kek_salt, mk_epoch)?;
        let hk = derive_hk(&mk)?;

        let cfg = PagerConfig {
            page_size,
            buffer_pool_pages: options.buffer_pool_pages,
            segment_cache_pages: options.segment_cache_pages,
            cipher_id,
            mk_epoch,
            main_db_file_id: file_id,
            main_db_path: main_db_path.clone(),
            anchor_budget: options.anchor_budget,
            dek_lru_capacity: 256,
            // Observer mode retry count is set here from options. For
            // Standalone / ReadOnly / Follower, the caller leaves it at 0.
            observer_retry_count: options.observer_retry_count,
            metrics_enabled: options.metrics_enabled,
        };
        let vfs_arc = Arc::new(vfs);
        let vfs_for_pager = V::clone(&*vfs_arc);
        let pager = Pager::open(vfs_for_pager, mk, cfg).await?;
        pager.recover_main_nonce(fields.counter_anchor);

        // Decode catalog_root from the 16-byte field: page_id LE u64 || txn_id LE u64.
        let catalog_root_page_id = {
            let mut b = [0u8; 8];
            b.copy_from_slice(&fields.catalog_root[..8]);
            u64::from_le_bytes(b)
        };
        let catalog_root_txn_id = {
            let mut b = [0u8; 8];
            b.copy_from_slice(&fields.catalog_root[8..]);
            u64::from_le_bytes(b)
        };

        let latest_commit = fields.commit_id.0;
        let writer = WriterState {
            root_page_id: fields.active_root_page_id,
            next_page_id: fields.next_page_id,
            active_slot,
            latest_commit_id: latest_commit,
            seq: fields.seq,
            catalog_root_page_id,
            catalog_root_txn_id,
            commit_history_root_page_id: fields.commit_history_root_page_id,
            commit_history_root_version: fields.commit_history_root_version,
            // Lazily populated on first `write_commit_history_entry` call.
            commit_history_count: None,
        };

        let pager_arc = Arc::new(pager);

        // Replay any pending apply journal before catalog reconciliation.
        // Per architecture §6: the journal must run first so that catalog
        // reconciliation sees the post-replay disk state. In this slice no
        // producer sets a non-zero page id, so this is a no-op for all
        // existing code paths.
        crate::recovery::journal::replay_apply_journal(
            &*vfs_arc,
            fields.apply_journal_root_page_id,
            fields.apply_journal_root_version,
        )
        .await?;

        // Walk the catalog and reconcile each segment file against its expected path.
        crate::recovery::reconcile_catalog(
            &*vfs_arc,
            pager_arc.clone(),
            &hk,
            realm,
            catalog_root_page_id,
            fields.next_page_id,
            page_size,
            file_id,
            latest_commit,
        )
        .await?;

        let db = Self {
            pager: pager_arc,
            realm_id: realm,
            page_size,
            hk: parking_lot::RwLock::new(hk),
            main_db_path,
            vfs: vfs_arc,
            writer: Arc::new(AsyncMutex::new(writer)),
            tracked_readers: parking_lot::Mutex::new(Vec::new()),
            reader_seq: AtomicU64::new(0),
            latest_commit: AtomicU64::new(latest_commit),
            stall_policy: parking_lot::Mutex::new(ReaderStallPolicy::default()),
            cipher_id,
            mk_epoch: AtomicU64::new(mk_epoch),
            file_id,
            kek_salt,
            segment_id_counter: AtomicU64::new(0),
            pending_tombstones: parking_lot::Mutex::new(Vec::new()),
            pending_pin_deletes: parking_lot::Mutex::new(Vec::new()),
            options,
            mmap_bytes_in_use: std::sync::Arc::new(AtomicU64::new(0)),
            spill_bytes_in_use: AtomicU64::new(0),
            txn_seq: AtomicU64::new(0),
            mode: DbMode::Standalone,
            aborted_readers: parking_lot::Mutex::new(std::collections::HashSet::new()),
            sentinel_locks: Vec::new(),
            snapshot: Arc::new(parking_lot::RwLock::new(ReaderSnapshot {
                commit_id: latest_commit,
                root_page_id: fields.active_root_page_id,
                next_page_id: fields.next_page_id,
                catalog_root_page_id,
            })),
            free_page_cache: Arc::new(parking_lot::Mutex::new(Vec::new())),
        };

        // If an online rekey was interrupted (crash or abort), resume and
        // complete it before handing out the handle.
        {
            let state_guard = db.writer.lock().await;
            let watermark = db.load_rekey_watermark(&state_guard).await?;
            drop(state_guard);
            if let Some(target_epoch) = watermark {
                db.rekey_db(kek, target_epoch).await?;
            }
        }

        // Remove stale and expired reader-pin rows: own-PID rows from a prior
        // process incarnation (crash without cleanup) and rows whose
        // expires_unix_seconds is in the past.
        {
            let mut state = db.writer.lock().await;
            let hk_clone = db.hk.read().clone();
            let _ = cleanup_stale_reader_pins(
                &db.pager,
                &db.vfs,
                &db.main_db_path,
                &hk_clone,
                db.realm_id,
                db.page_size,
                db.cipher_id,
                db.file_id,
                db.kek_salt,
                db.mk_epoch.load(Ordering::SeqCst),
                &mut state,
            )
            .await;
            // Snapshot may have advanced by the bulk-pin-cleanup commit
            // performed inside cleanup_stale_reader_pins.
            db.publish_snapshot(&state);
        }

        // Durable monotonicity recovery for named counters.
        //
        // If a write transaction was lost (power-cut after the deferred-free
        // row was written but before the header swap completed), counter rows
        // in the catalog may have values below the `counter_anchor` persisted
        // in the A/B header. Bump any such rows up to `counter_anchor` so that
        // counters never go backward.
        if fields.counter_anchor > 0 {
            let _ = db.recover_counter_monotonicity(fields.counter_anchor).await;
        }

        Ok(db)
    }

    /// Scan catalog counter rows and bump any whose stored value is less than
    /// `anchor` up to `anchor`. Called once at open to recover monotonicity
    /// after a torn write. Errors are silently ignored (best-effort); a failure
    /// here does not prevent the database from opening.
    async fn recover_counter_monotonicity(&self, anchor: u64) -> Result<()> {
        let (cat_root, next) = {
            let state = self.writer.lock().await;
            (state.catalog_root_page_id, state.next_page_id)
        };
        if cat_root == 0 {
            return Ok(());
        }
        let counter_prefix = vec![crate::catalog::codec::CatalogRowKind::Counter as u8];
        let mut end_prefix = counter_prefix.clone();
        end_prefix.push(0xFF);

        let cat_tree = BTree::open(
            self.pager.clone(),
            self.realm_id,
            cat_root,
            next,
            self.page_size,
        );
        let rows = cat_tree.collect_range(&counter_prefix, &end_prefix).await?;
        let mut rows_to_bump: Vec<(Vec<u8>, u64)> = Vec::new();
        for (k, v) in &rows {
            if let Ok(val) = Catalog::decode_counter(v) {
                if val < anchor {
                    rows_to_bump.push((k.clone(), anchor));
                    tracing::debug!(
                        name = "counter.monotonicity_recover",
                        old_value = val,
                        anchor,
                        "bumping counter to anchor"
                    );
                }
            }
        }
        if rows_to_bump.is_empty() {
            return Ok(());
        }

        // Perform a mini write-txn to persist the bumped values.
        let state = self.writer.lock().await;
        let mut cat_tree_w = BTree::open(
            self.pager.clone(),
            self.realm_id,
            state.catalog_root_page_id,
            state.next_page_id,
            self.page_size,
        );
        for (k, v) in &rows_to_bump {
            let encoded = Catalog::encode_counter(*v);
            cat_tree_w.put(k, &encoded).await?;
        }
        cat_tree_w.flush().await?;
        let new_cat_root = cat_tree_w.root_page_id();
        let new_next = cat_tree_w.next_page_id().max(state.next_page_id);
        let new_commit_id = state.latest_commit_id + 1;
        let new_seq = state.seq + 1;
        let counter_anchor = self.pager.pending_anchor();
        let mut catalog_root_bytes = [0u8; 16];
        catalog_root_bytes[..8].copy_from_slice(&new_cat_root.to_le_bytes());
        catalog_root_bytes[8..].copy_from_slice(&new_commit_id.to_le_bytes());
        let fields = MainDbHeaderFields {
            format_version: 1,
            cipher_id: self.cipher_id.as_byte(),
            page_size_log2: page_size_log2(self.page_size)?,
            flags: 0,
            file_id: self.file_id,
            kek_salt: self.kek_salt,
            mk_epoch: self.mk_epoch.load(Ordering::SeqCst),
            seq: new_seq,
            active_root_page_id: state.root_page_id,
            active_root_txn_id: state.latest_commit_id,
            counter_anchor,
            commit_id: CommitId(new_commit_id),
            free_list_root: [0u8; 16],
            catalog_root: catalog_root_bytes,
            apply_journal_root_page_id: 0,
            apply_journal_root_version: 0,
            commit_history_root_page_id: state.commit_history_root_page_id,
            commit_history_root_version: state.commit_history_root_version,
            restore_mode: 0,
            next_page_id: new_next,
            commit_retain_policy_tag: 0,
            commit_retain_policy_value: 0,
        };
        let hk_clone = self.hk.read().clone();
        let _new_slot = commit_header(
            &*self.vfs,
            &self.main_db_path,
            &hk_clone,
            &fields,
            state.active_slot,
            self.page_size,
        )
        .await?;
        self.pager.commit_anchor(counter_anchor)?;
        Ok(())
    }

    /// Write per-realm quota caps into the catalog B+ tree and persist the
    /// updated catalog root to the A/B header.
    pub async fn set_realm_quotas(&self, realm: RealmId, quotas: RealmQuotas) -> Result<()> {
        let mut state = self.writer.lock().await;
        let key = Catalog::quota_key(realm);
        let value = Catalog::encode_realm_quotas(&quotas);

        let mut cat_tree = BTree::open(
            self.pager.clone(),
            self.realm_id,
            state.catalog_root_page_id,
            state.next_page_id,
            self.page_size,
        );
        cat_tree.put(&key, &value).await?;
        cat_tree.flush().await?;

        let new_catalog_root = cat_tree.root_page_id();
        let new_next = cat_tree.next_page_id();
        let new_catalog_txn_id = state.latest_commit_id + 1;

        let new_seq = state.seq + 1;
        let counter_anchor = self.pager.pending_anchor();
        let mut catalog_root_bytes = [0u8; 16];
        catalog_root_bytes[..8].copy_from_slice(&new_catalog_root.to_le_bytes());
        catalog_root_bytes[8..].copy_from_slice(&new_catalog_txn_id.to_le_bytes());

        let fields = MainDbHeaderFields {
            format_version: 1,
            cipher_id: self.cipher_id.as_byte(),
            page_size_log2: page_size_log2(self.page_size)?,
            flags: 0,
            file_id: self.file_id,
            kek_salt: self.kek_salt,
            mk_epoch: self.mk_epoch.load(Ordering::SeqCst),
            seq: new_seq,
            active_root_page_id: state.root_page_id,
            active_root_txn_id: state.latest_commit_id,
            counter_anchor,
            commit_id: CommitId(state.latest_commit_id),
            free_list_root: [0; 16],
            catalog_root: catalog_root_bytes,
            apply_journal_root_page_id: 0,
            apply_journal_root_version: 0,
            commit_history_root_page_id: 0,
            commit_history_root_version: 0,
            restore_mode: 0,
            next_page_id: new_next,

            commit_retain_policy_tag: 0,

            commit_retain_policy_value: 0,
        };
        let hk_clone = { self.hk.read().clone() };
        let new_slot = commit_header(
            &*self.vfs,
            &self.main_db_path,
            &hk_clone,
            &fields,
            state.active_slot,
            self.page_size,
        )
        .await?;
        self.pager.commit_anchor(counter_anchor)?;

        state.catalog_root_page_id = new_catalog_root;
        state.catalog_root_txn_id = new_catalog_txn_id;
        state.next_page_id = new_next;
        state.active_slot = new_slot;
        state.seq = new_seq;

        Ok(())
    }

    /// Read per-realm quota caps from the catalog B+ tree. Returns
    /// `RealmQuotas::default()` if no entry has been written for this realm.
    pub async fn realm_quotas(&self, realm: RealmId) -> Result<RealmQuotas> {
        let state = self.writer.lock().await;
        let key = Catalog::quota_key(realm);
        let cat_tree = BTree::open(
            self.pager.clone(),
            self.realm_id,
            state.catalog_root_page_id,
            state.next_page_id,
            self.page_size,
        );
        drop(state);
        match cat_tree.get(&key).await? {
            Some(bytes) => Catalog::decode_realm_quotas(&bytes),
            None => Ok(RealmQuotas::default()),
        }
    }

    /// Open a read transaction pinned to the current committed root. Inserts a
    /// durable reader-pin row in the catalog so cross-process GC can see the pin
    /// even after a crash. The pin is deleted (best-effort) when the `ReadTxn`
    /// drops via the `pending_pin_deletes` queue, which is drained by the next
    /// writer commit or `gc_now`. If the process crashes before cleanup, the next
    /// writer open scans and removes stale pin rows.
    pub async fn begin_read(&self) -> Result<ReadTxn<'_, V>> {
        // Only insert a durable pin on Standalone handles; ReadOnly / Follower
        // handles that cannot write to their own catalog use the in-memory path.
        let can_write_catalog = matches!(self.mode, crate::txn::mode::DbMode::Standalone);

        let (commit_id, root_page_id, next_page_id, catalog_root_page_id) = {
            let w = self.writer.lock().await;
            (
                CommitId(w.latest_commit_id),
                w.root_page_id,
                w.next_page_id,
                w.catalog_root_page_id,
            )
        };
        let txn = self.register_read(
            commit_id,
            root_page_id,
            next_page_id,
            catalog_root_page_id,
            false,
        );

        if can_write_catalog {
            let lease_seconds = 30u64;
            let lease_id = next_lease_id();
            let own_pid = std::process::id();
            let pin_handle = crate::txn::read::make_pin_handle(
                self.pager.clone(),
                self.realm_id,
                self.page_size,
                self.main_db_path.clone(),
                self.vfs.clone(),
                self.hk.read().clone(),
                self.mk_epoch.load(Ordering::SeqCst),
                self.cipher_id,
                self.file_id,
                self.kek_salt,
                self.latest_commit.load(Ordering::SeqCst),
                self.snapshot.clone(),
                own_pid,
                lease_id,
                lease_seconds,
            );
            // Insert the pin row. On failure (e.g., no catalog yet or during
            // bootstrap), fall through to in-memory-only tracking.
            {
                let mut state = self.writer.lock().await;
                if state.catalog_root_page_id != 0 {
                    let _ = crate::txn::read::insert_pin_row(
                        &pin_handle,
                        &mut state,
                        commit_id.0,
                        root_page_id,
                        catalog_root_page_id,
                    )
                    .await;
                    return Ok(txn.with_durable_pin(own_pid, lease_id));
                }
            }
        }

        Ok(txn)
    }

    /// Like [`begin_read`] but marks the reader as non-abortable. The
    /// `AbortOldest` stall policy skips non-abortable readers; if all blocking
    /// readers are non-abortable, the policy falls through to `Reject`
    /// semantics for the writer.
    ///
    /// Use this for long-running operations (e.g. snapshot export) that must
    /// not be interrupted mid-stream.
    #[allow(clippy::unused_async)] // async signature preserved for API stability
    pub async fn begin_read_non_abortable(&self) -> Result<ReadTxn<'_, V>> {
        // Lock-free fast path: read the published snapshot without touching
        // the async writer mutex. The snapshot is updated by the writer at
        // each commit (see `publish_snapshot`), and is always internally
        // consistent — a reader either sees the previous commit fully or the
        // new commit fully, never a torn mix.
        let snap = *self.snapshot.read();
        Ok(self.register_read(
            CommitId(snap.commit_id),
            snap.root_page_id,
            snap.next_page_id,
            snap.catalog_root_page_id,
            true,
        ))
    }

    /// Publish a new reader-visible snapshot. Called by writer commit paths
    /// after `state` has been mutated to reflect a freshly durable commit.
    /// Cheap (a single `parking_lot::RwLock` write, no async).
    pub(crate) fn publish_snapshot(&self, state: &WriterState) {
        *self.snapshot.write() = ReaderSnapshot {
            commit_id: state.latest_commit_id,
            root_page_id: state.root_page_id,
            next_page_id: state.next_page_id,
            catalog_root_page_id: state.catalog_root_page_id,
        };
    }

    /// Register a reader with a snapshot pin. Stores the reader in the
    /// tracked-readers table and returns a `ReadTxn` carrying the unique
    /// `entry_id` used to unregister on drop.
    pub(crate) fn register_read(
        &self,
        commit_id: CommitId,
        root_page_id: u64,
        next_page_id: u64,
        catalog_root_page_id: u64,
        non_abortable: bool,
    ) -> ReadTxn<'_, V> {
        let entry_id = self.reader_seq.fetch_add(1, Ordering::Relaxed);
        let mut readers = self.tracked_readers.lock();
        readers.push(TrackedReader {
            entry_id,
            commit_id,
            root_page_id,
            next_page_id,
            catalog_root_page_id,
            non_abortable,
        });
        drop(readers);
        ReadTxn::new(
            self,
            commit_id,
            root_page_id,
            next_page_id,
            catalog_root_page_id,
            entry_id,
        )
    }

    /// Unregister a reader by its unique `entry_id`. Called from `ReadTxn::drop`.
    /// Uses `swap_remove` for O(1) amortised removal; order in the Vec is
    /// not semantically significant.
    pub(crate) fn unregister_read(&self, entry_id: u64) {
        let mut readers = self.tracked_readers.lock();
        if let Some(pos) = readers.iter().position(|r| r.entry_id == entry_id) {
            readers.swap_remove(pos);
        }
    }

    /// Open a write transaction. Acquires the exclusive writer slot.
    /// Returns `PagedbError::ReadOnly` if the handle is not in Standalone mode.
    pub async fn begin_write(&self) -> Result<WriteTxn<'_, V>> {
        if !matches!(self.mode, DbMode::Standalone) {
            return Err(PagedbError::ReadOnly);
        }
        tracing::debug!(name = "txn.begin_write", "opening write transaction");
        WriteTxn::begin(self).await
    }

    /// Return the most recently published `CommitId`.
    pub fn latest_commit(&self) -> CommitId {
        CommitId(self.latest_commit.load(Ordering::SeqCst))
    }

    /// Replace the reader stall policy. Takes effect on the next stall
    /// evaluation (enforcement lands when the persistent free-list arrives).
    pub fn set_reader_stall_policy(&self, policy: ReaderStallPolicy) {
        *self.stall_policy.lock() = policy;
    }

    /// Read the current reader stall policy.
    pub fn reader_stall_policy(&self) -> ReaderStallPolicy {
        *self.stall_policy.lock()
    }

    /// Check whether reader `entry_id` has been aborted by the stall policy.
    /// Removes the entry from the abort set (one-shot: the reader observes the
    /// abort exactly once).
    pub(crate) fn take_reader_abort(&self, entry_id: u64) -> bool {
        self.aborted_readers.lock().remove(&entry_id)
    }

    /// Evaluate the reader stall policy against the current deferred-free queue
    /// length. Called by `WriteTxn::commit` after building the new deferred-free
    /// list. Returns `Ok(())` to proceed with commit, or an error to abort.
    ///
    /// Side effect for `AbortOldest`: marks the oldest abortable tracked reader
    /// in `aborted_readers` so its next operation returns `Aborted`.
    pub(crate) fn evaluate_stall_policy(&self, deferred_free_count: u64) -> crate::Result<()> {
        let threshold = self.options.reader_stall_threshold_pages;
        if deferred_free_count <= threshold {
            return Ok(());
        }
        let policy = *self.stall_policy.lock();
        if matches!(policy, ReaderStallPolicy::Unbounded) {
            return Ok(());
        }
        // Check whether any tracked reader is actually pinning (blocking drain).
        let oldest_blocking = {
            let readers = self.tracked_readers.lock();
            readers.iter().map(|r| r.commit_id.0).min()
        };
        let Some(oldest_commit) = oldest_blocking else {
            // No readers at all — no stall.
            return Ok(());
        };
        match policy {
            ReaderStallPolicy::Reject => Err(PagedbError::deferred_free_backlog(
                deferred_free_count,
                oldest_commit,
            )),
            ReaderStallPolicy::AbortOldest => {
                // Find the oldest abortable reader and mark it aborted.
                let readers = self.tracked_readers.lock();
                let victim = readers
                    .iter()
                    .filter(|r| !r.non_abortable)
                    .min_by_key(|r| r.commit_id.0);
                if let Some(v) = victim {
                    let eid = v.entry_id;
                    drop(readers);
                    self.aborted_readers.lock().insert(eid);
                    Ok(())
                } else {
                    // All blocking readers are non-abortable → fall through to Reject.
                    drop(readers);
                    Err(PagedbError::deferred_free_backlog(
                        deferred_free_count,
                        oldest_commit,
                    ))
                }
            }
            ReaderStallPolicy::Unbounded => Ok(()),
        }
    }

    /// Create a fresh segment in the given realm. The returned writer holds a
    /// handle to `seg/.staging/<hex(segment_id)>`. Sealing the writer makes
    /// the file durable; publication requires a catalog link.
    pub async fn create_segment(
        &self,
        realm: RealmId,
        kind: SegmentKind,
    ) -> Result<SegmentWriter<V>> {
        self.vfs.mkdir_all("seg/.staging").await?;
        let segment_id = self.next_segment_id();
        SegmentWriter::create_internal(self.pager.clone(), realm, segment_id, self.file_id, kind)
            .await
    }

    /// Open a segment by `(realm, name)` resolved against the live catalog.
    pub async fn open_segment(&self, realm: RealmId, name: &str) -> Result<SegmentReader<V>> {
        let meta = self.lookup_segment(realm, name).await?;
        let limit = u64::try_from(self.options.mmap_view_scratch_bytes).unwrap_or(u64::MAX);
        SegmentReader::open_internal(
            self.pager.clone(),
            meta,
            self.mmap_bytes_in_use.clone(),
            limit,
        )
        .await
    }

    /// List segments in `realm` whose names start with `prefix`. Live catalog.
    pub async fn list_segments(&self, realm: RealmId, prefix: &str) -> Result<Vec<SegmentMeta>> {
        let (catalog_root, next) = {
            let writer = self.writer.lock().await;
            (writer.catalog_root_page_id, writer.next_page_id)
        };
        if catalog_root == 0 {
            return Ok(Vec::new());
        }
        let tree = BTree::open(
            self.pager.clone(),
            self.realm_id,
            catalog_root,
            next,
            self.page_size,
        );
        let start = Catalog::segment_key(realm, prefix.as_bytes())?;
        let mut end = start.clone();
        end.push(0xFF);
        let rows = tree.collect_range(&start, &end).await?;
        let mut out = Vec::with_capacity(rows.len());
        for (_k, v) in rows {
            let meta = Catalog::decode_segment_meta(&v)?;
            out.push(meta);
        }
        Ok(out)
    }

    /// Scan the catalog for durable reader-pin rows. Returns the minimum
    /// `commit_id` among non-expired pins, or `u64::MAX` if there are none.
    /// This supplements the in-memory `tracked_readers` check with cross-process
    /// readers whose pins are only visible via the catalog.
    pub(crate) async fn min_durable_reader_commit(&self, catalog_root: u64, next: u64) -> u64 {
        if catalog_root == 0 {
            return u64::MAX;
        }
        let now = crate::txn::read::unix_now_seconds();
        let tree = BTree::open(
            self.pager.clone(),
            self.realm_id,
            catalog_root,
            next,
            self.page_size,
        );
        let start = Catalog::reader_pin_range_start();
        let end = Catalog::reader_pin_range_end();
        let Ok(rows) = tree.collect_range(&start, &end).await else {
            return u64::MAX;
        };
        let own_pid = std::process::id();
        let mut min_commit = u64::MAX;
        for (k, v) in &rows {
            // Skip own-PID pins (they're accounted for in-memory).
            if k.len() >= 5 {
                let mut pid_buf = [0u8; 4];
                pid_buf.copy_from_slice(&k[1..5]);
                if u32::from_be_bytes(pid_buf) == own_pid {
                    continue;
                }
            }
            if let Ok(pv) = Catalog::decode_reader_pin(v) {
                if pv.expires_unix_seconds >= now {
                    min_commit = min_commit.min(pv.commit_id);
                }
            }
        }
        min_commit
    }

    /// Drain any reader-pin rows that were queued for deletion by dropped
    /// `ReadTxn` handles. Called by `gc_now` and can be called by callers that
    /// want to reclaim catalog space between compaction cycles.
    pub async fn drain_pending_pin_deletes(&self) -> Result<()> {
        let to_delete: Vec<(u32, u64)> = {
            let mut pending = self.pending_pin_deletes.lock();
            std::mem::take(&mut *pending)
        };
        if to_delete.is_empty() {
            return Ok(());
        }
        let pin = make_pin_handle(
            self.pager.clone(),
            self.realm_id,
            self.page_size,
            self.main_db_path.clone(),
            self.vfs.clone(),
            self.hk.read().clone(),
            self.mk_epoch.load(Ordering::SeqCst),
            self.cipher_id,
            self.file_id,
            self.kek_salt,
            self.latest_commit.load(Ordering::SeqCst),
            self.snapshot.clone(),
            std::process::id(),
            0, // lease_id unused for bulk deletes
            30,
        );
        let mut state = self.writer.lock().await;
        delete_pin_rows(&pin, &mut state, &to_delete).await
    }

    /// Process pending deferred tombstones and delete files in `seg/.tombstone/`.
    /// Returns statistics on reclaimed segments and bytes.
    pub async fn gc_now(&self) -> Result<GcStats> {
        let _span = tracing::debug_span!("gc.run");
        self.try_drain_pending_tombstones().await?;
        // Best-effort: drain any queued reader-pin deletes.
        let _ = self.drain_pending_pin_deletes().await;
        let (count, bytes) = crate::recovery::gc::delete_tombstone_files(&*self.vfs).await?;
        Ok(GcStats {
            reclaimed_segments: count,
            reclaimed_bytes: bytes,
        })
    }

    /// Re-evaluate each pending tombstone. If a segment is no longer pinned by
    /// any tracked reader, rename it from the live path to the tombstone
    /// directory now.
    async fn try_drain_pending_tombstones(&self) -> Result<()> {
        let pending = self.pending_tombstones.lock().clone();
        let mut still_pending: Vec<PendingTombstone> = Vec::new();
        for entry in pending {
            if self.segment_id_is_reader_pinned(entry.segment_id).await? {
                still_pending.push(entry);
                continue;
            }
            let live = format!(
                "seg/{}",
                crate::segment::writer::hex_lower(&entry.segment_id)
            );
            let tomb = format!(
                "seg/.tombstone/{}.{}",
                crate::segment::writer::hex_lower(&entry.segment_id),
                entry.commit_id
            );
            self.vfs.mkdir_all("seg/.tombstone").await?;
            // The file may have already been moved (e.g., by reconciliation).
            // Ignore rename errors in that case.
            self.vfs.rename(&live, &tomb).await.ok();
            self.vfs.sync_dir("seg/.tombstone").await.ok();
        }
        *self.pending_tombstones.lock() = still_pending;
        Ok(())
    }

    /// Return `true` if any currently tracked reader's catalog snapshot
    /// contains `segment_id`.
    pub(crate) async fn segment_id_is_reader_pinned(&self, segment_id: [u8; 16]) -> Result<bool> {
        let snapshots = {
            let readers = self.tracked_readers.lock();
            readers
                .iter()
                .map(|r| (r.catalog_root_page_id, r.next_page_id))
                .collect::<Vec<_>>()
        };
        for (root, next) in snapshots {
            if root == 0 {
                continue;
            }
            let tree = BTree::open(
                self.pager.clone(),
                self.realm_id,
                root,
                next,
                self.page_size,
            );
            let start = vec![0x01u8];
            let end = vec![0x02u8];
            let rows = tree.collect_range(&start, &end).await?;
            for (_, v) in rows {
                let meta = Catalog::decode_segment_meta(&v)?;
                if meta.segment_id == segment_id {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    async fn lookup_segment(&self, realm: RealmId, name: &str) -> Result<SegmentMeta> {
        let (catalog_root, next) = {
            let writer = self.writer.lock().await;
            (writer.catalog_root_page_id, writer.next_page_id)
        };
        if catalog_root == 0 {
            return Err(PagedbError::NotFound);
        }
        let tree = BTree::open(
            self.pager.clone(),
            self.realm_id,
            catalog_root,
            next,
            self.page_size,
        );
        let key = Catalog::segment_key(realm, name.as_bytes())?;
        let value = tree.get(&key).await?.ok_or(PagedbError::NotFound)?;
        Catalog::decode_segment_meta(&value)
    }

    // -----------------------------------------------------------------------
    // Mode-aware constructors
    // -----------------------------------------------------------------------

    /// Open a database in **Standalone** (full writer) mode.
    ///
    /// Acquires exclusive `.writer.lock`. Refuses with `RestoredNotPromoted`
    /// if the on-disk header's `restore_mode` is 2 (`ReadOnly` restored snapshot).
    /// Refuses with `AlreadyOpen` if another handle already holds the writer lock.
    pub async fn open(
        vfs: V,
        kek: [u8; 32],
        page_size: usize,
        realm: RealmId,
        options: OpenOptions,
    ) -> Result<Self> {
        Self::open_with_mode(vfs, kek, page_size, realm, options, DbMode::Standalone).await
    }

    /// Open a database in **`ReadOnly`** mode on a frozen-snapshot directory.
    ///
    /// Refuses with `WriterPresent` if `.writer.lock` is currently held.
    /// Acquires shared `.frozen_readers.lock`.
    pub async fn open_read_only(
        vfs: V,
        kek: [u8; 32],
        page_size: usize,
        realm: RealmId,
        options: OpenOptions,
    ) -> Result<Self> {
        Self::open_with_mode(vfs, kek, page_size, realm, options, DbMode::ReadOnly).await
    }

    /// Open a database in **Observer** mode.
    ///
    /// Best-effort read-only even when a writer is active.
    /// Acquires shared `.observers.lock`.
    pub async fn open_observer(
        vfs: V,
        kek: [u8; 32],
        page_size: usize,
        realm: RealmId,
        options: OpenOptions,
    ) -> Result<Self> {
        Self::open_with_mode(vfs, kek, page_size, realm, options, DbMode::Observer).await
    }

    async fn open_with_mode(
        vfs: V,
        kek: [u8; 32],
        page_size: usize,
        realm: RealmId,
        options: OpenOptions,
        mode: DbMode,
    ) -> Result<Self> {
        use crate::vfs::types::OpenMode;

        // Enforce: observer_retry_count is only meaningful in Observer mode.
        // For all other modes, override it to 0 so AEAD failures remain hard
        // corruption signals rather than being silently retried.
        let options = if matches!(mode, DbMode::Observer) {
            options
        } else {
            OpenOptions {
                observer_retry_count: 0,
                ..options
            }
        };

        let mut locks: Vec<<V as Vfs>::LockHandle> = Vec::new();

        // Probe whether main.db exists.
        let main_db_exists = vfs.open("/main.db", OpenMode::Read).await.is_ok();

        match mode {
            DbMode::Standalone | DbMode::Follower => {
                // For Standalone, check restore_mode before acquiring the writer lock
                // so we don't hold the lock unnecessarily on early refusal.
                if main_db_exists && mode == DbMode::Standalone {
                    let restore_mode = peek_restore_mode(&vfs, &kek, page_size).await?;
                    if restore_mode == 2 {
                        return Err(PagedbError::RestoredNotPromoted);
                    }
                }
                let lock = vfs
                    .lock_exclusive(WRITER_LOCK_PATH)
                    .await
                    .map_err(|_| PagedbError::AlreadyOpen)?;
                locks.push(lock);
            }
            DbMode::ReadOnly => {
                // Refuse if a writer is active: attempt an exclusive grab of
                // the writer lock as a probe. If it succeeds, no writer is
                // present — drop it immediately and proceed. If it fails,
                // a writer holds the lock and we return WriterPresent.
                match vfs.lock_exclusive(WRITER_LOCK_PATH).await {
                    Ok(_probe) => {
                        // Lock was free; _probe drops here, releasing the probe lock.
                    }
                    Err(_) => {
                        return Err(PagedbError::WriterPresent);
                    }
                }
                let lock = vfs
                    .lock_shared(FROZEN_READERS_LOCK_PATH)
                    .await
                    .map_err(|_| PagedbError::AlreadyLocked)?;
                locks.push(lock);
            }
            DbMode::Observer => {
                let lock = vfs
                    .lock_shared(OBSERVERS_LOCK_PATH)
                    .await
                    .map_err(|_| PagedbError::AlreadyLocked)?;
                locks.push(lock);
            }
        }

        // Delegate to the appropriate lower-level constructor.
        let mut db = if main_db_exists {
            Self::open_existing_with_options(vfs, kek, page_size, realm, options).await?
        } else {
            Self::open_internal_with_options(vfs, kek, page_size, realm, options).await?
        };
        db.mode = mode;
        db.sentinel_locks = locks;
        Ok(db)
    }

    /// Return the mode this handle was opened with.
    pub fn mode(&self) -> DbMode {
        self.mode
    }

    /// Returns `true` iff this handle is a full writer (Standalone mode).
    pub fn is_writer(&self) -> bool {
        matches!(self.mode, DbMode::Standalone)
    }

    /// Returns `true` iff `apply_incremental` is callable on this handle
    /// (Follower mode only).
    pub fn can_apply_incremental(&self) -> bool {
        matches!(self.mode, DbMode::Follower)
    }

    /// Returns `true` iff `rekey_into_writer` is callable on this handle
    /// (`ReadOnly` or Follower).
    pub fn can_rekey_into_writer(&self) -> bool {
        matches!(self.mode, DbMode::ReadOnly | DbMode::Follower)
    }

    /// Stub: rekey a restored `Db` (`ReadOnly` or Follower) into a Standalone writer.
    /// Full implementation is out of scope for this slice.
    pub fn rekey_into_writer(self, _new_kek: [u8; 32]) -> Result<Self> {
        Err(PagedbError::Unsupported)
    }

    /// Online rekey: re-encrypt every main.db B+ tree page and every linked
    /// segment under a new `mk_epoch` derived from `kek` and the existing
    /// `kek_salt`. Resumes automatically if a prior rekey was interrupted.
    ///
    /// On return `Ok(())`, all on-disk data uses `new_mk_epoch` and the A/B
    /// header records the new epoch. The in-memory `Db` is updated in-place
    /// (the pager's active key and epoch are switched atomically before the
    /// final flush). No reopen is required.
    ///
    /// # Errors
    /// Returns `Unsupported` if this handle is not in Standalone mode.
    #[allow(clippy::too_many_lines)]
    pub async fn rekey_db(&self, kek: [u8; 32], new_mk_epoch: u64) -> Result<()> {
        let _span = tracing::debug_span!("rekey.run", new_mk_epoch);
        if !matches!(self.mode, crate::txn::mode::DbMode::Standalone) {
            return Err(PagedbError::Unsupported);
        }

        let new_mk = derive_mk(&kek, &self.kek_salt, new_mk_epoch)?;
        let derived_hk = derive_hk(&new_mk)?;
        let old_epoch = self.mk_epoch.load(Ordering::SeqCst);
        let old_mk = derive_mk(&kek, &self.kek_salt, old_epoch)?;

        // Acquire writer lock for the entire rekey operation.
        let mut state = self.writer.lock().await;

        // Check for an in-flight rekey from a prior crash and compute start
        // position. A rekey watermark row under key [0x03] indicates a prior
        // incomplete rekey.
        let (main_db_done, segments_start_idx) = self.load_rekey_state(&state).await?;

        if !main_db_done {
            // Write the watermark before starting the rewrite so a crash is
            // detectable on the next open.
            self.write_rekey_watermark(&mut state, new_mk_epoch, false, 0)
                .await?;

            // Walk main tree and catalog tree, marking all pages dirty.
            let main_tree = BTree::open(
                self.pager.clone(),
                self.realm_id,
                state.root_page_id,
                state.next_page_id,
                self.page_size,
            );
            main_tree.rekey_walk().await?;

            if state.catalog_root_page_id != 0 {
                let cat_tree = BTree::open(
                    self.pager.clone(),
                    self.realm_id,
                    state.catalog_root_page_id,
                    state.next_page_id,
                    self.page_size,
                );
                cat_tree.rekey_walk().await?;
            }

            // Switch the pager to the new epoch BEFORE flushing so dirty pages
            // are sealed with the new DEK.
            self.pager.set_active_mk_epoch(new_mk.clone(), new_mk_epoch);

            // Flush all dirty pages (now re-encrypted under the new epoch).
            self.pager.flush_main(self.realm_id).await?;

            // Write the new A/B header with the new mk_epoch and mark main_db_done.
            let new_seq = state.seq + 1;
            let counter_anchor = self.pager.pending_anchor();
            let mut catalog_root_bytes = [0u8; 16];
            catalog_root_bytes[..8].copy_from_slice(&state.catalog_root_page_id.to_le_bytes());
            catalog_root_bytes[8..].copy_from_slice(&state.latest_commit_id.to_le_bytes());

            let fields = MainDbHeaderFields {
                format_version: 1,
                cipher_id: self.cipher_id.as_byte(),
                page_size_log2: page_size_log2(self.page_size)?,
                flags: 0,
                file_id: self.file_id,
                kek_salt: self.kek_salt,
                mk_epoch: new_mk_epoch,
                seq: new_seq,
                active_root_page_id: state.root_page_id,
                active_root_txn_id: state.latest_commit_id,
                counter_anchor,
                commit_id: CommitId(state.latest_commit_id),
                free_list_root: [0; 16],
                catalog_root: catalog_root_bytes,
                apply_journal_root_page_id: 0,
                apply_journal_root_version: 0,
                commit_history_root_page_id: 0,
                commit_history_root_version: 0,
                restore_mode: 0,
                next_page_id: state.next_page_id,

                commit_retain_policy_tag: 0,

                commit_retain_policy_value: 0,
            };
            let new_slot = commit_header(
                &*self.vfs,
                &self.main_db_path,
                &derived_hk,
                &fields,
                state.active_slot,
                self.page_size,
            )
            .await?;
            self.pager.commit_anchor(counter_anchor)?;
            state.active_slot = new_slot;
            state.seq = new_seq;

            // Update Db's mk_epoch atomically and switch the HK so subsequent
            // WriteTxn::commit() calls sign headers with the new key material.
            self.mk_epoch.store(new_mk_epoch, Ordering::SeqCst);
            *self.hk.write() = derived_hk.clone();

            // Update watermark: main_db_done = true.
            self.write_rekey_watermark_locked(&mut state, new_mk_epoch, true, 0, &derived_hk)
                .await?;
        }

        // Rekey segments starting from segments_start_idx.
        let all_segments = self.list_all_segments(&state).await?;
        for (idx, meta) in all_segments.iter().enumerate() {
            let idx_u32 = u32::try_from(idx)
                .map_err(|_| PagedbError::Io(std::io::Error::other("segment index overflow")))?;
            if idx_u32 < segments_start_idx {
                continue;
            }
            // Skip segments already on the new epoch.
            if meta.mk_epoch == new_mk_epoch {
                continue;
            }

            // Open segment reader using old epoch MK so the header HMAC and
            // page DEK derivation use the correct key material.
            let mmap_limit =
                u64::try_from(self.options.mmap_view_scratch_bytes).unwrap_or(u64::MAX);
            let reader = SegmentReader::open_internal_with_mk(
                self.pager.clone(),
                meta.clone(),
                &old_mk,
                self.mmap_bytes_in_use.clone(),
                mmap_limit,
            )
            .await?;

            // Create a new segment writer under the new epoch.
            // The pager is already using the new epoch at this point.
            self.vfs.mkdir_all("seg/.staging").await?;
            let new_segment_id = self.next_segment_id();
            let mut writer = SegmentWriter::create_internal(
                self.pager.clone(),
                meta.realm_id,
                new_segment_id,
                self.file_id,
                meta.segment_kind,
            )
            .await?;

            // Copy each data page from old to new segment.
            for page_id in 1..meta.page_count - 1 {
                match reader.read_page(page_id).await {
                    Ok(page_bytes) => {
                        writer
                            .append_page(crate::segment::types::SegmentPageKind::Data, &page_bytes)
                            .await?;
                    }
                    Err(PagedbError::NotFound) => {}
                    Err(e) => return Err(e),
                }
            }

            let new_meta = writer.seal().await?;

            // Link the new segment and tombstone the old one via catalog update.
            // Find the segment name in the catalog.
            let seg_name = self.find_segment_name(&state, &meta.segment_id).await?;

            // Update catalog: replace old segment with new one.
            self.replace_segment_in_catalog(
                &mut state,
                &seg_name,
                &meta.segment_id,
                &new_meta,
                &derived_hk,
                new_mk_epoch,
            )
            .await?;

            // Update watermark progress.
            let next_idx = idx_u32.saturating_add(1);
            self.write_rekey_watermark_locked(
                &mut state,
                new_mk_epoch,
                true,
                next_idx,
                &derived_hk,
            )
            .await?;
        }

        // Clear the rekey watermark.
        self.clear_rekey_watermark(&mut state, &derived_hk).await?;

        // The old epoch is now obsolete; evict its DEK entries.
        // At this point self.mk_epoch already holds new_mk_epoch (set earlier),
        // so we evict entries from any epoch < new_mk_epoch. Since we only
        // advanced by one epoch, evict new_mk_epoch - 1 specifically.
        if new_mk_epoch > 0 {
            self.pager.evict_dek_for_epoch(new_mk_epoch - 1);
        }

        Ok(())
    }

    /// Load the rekey watermark from the catalog, if present.
    /// Returns `Some(target_epoch)` if a rekey is in-flight, `None` if not.
    async fn load_rekey_watermark(&self, state: &WriterState) -> Result<Option<u64>> {
        if state.catalog_root_page_id == 0 {
            return Ok(None);
        }
        let tree = BTree::open(
            self.pager.clone(),
            self.realm_id,
            state.catalog_root_page_id,
            state.next_page_id,
            self.page_size,
        );
        let key = Catalog::rekey_state_key();
        match tree.get(&key).await? {
            None => Ok(None),
            Some(bytes) => {
                let row = Catalog::decode_rekey_state(&bytes)?;
                Ok(Some(row.target_mk_epoch))
            }
        }
    }

    /// Load full rekey watermark state. Returns `(main_db_done, segments_remaining_idx)`.
    async fn load_rekey_state(&self, state: &WriterState) -> Result<(bool, u32)> {
        if state.catalog_root_page_id == 0 {
            return Ok((false, 0));
        }
        let tree = BTree::open(
            self.pager.clone(),
            self.realm_id,
            state.catalog_root_page_id,
            state.next_page_id,
            self.page_size,
        );
        let key = Catalog::rekey_state_key();
        match tree.get(&key).await? {
            None => Ok((false, 0)),
            Some(bytes) => {
                let row = Catalog::decode_rekey_state(&bytes)?;
                Ok((row.main_db_done, row.segments_remaining_idx))
            }
        }
    }

    /// Write a rekey watermark with `main_db_done=false` and no segments
    /// rewritten yet. Exposed for integration tests that need to simulate an
    /// interrupted rekey without accessing private fields.
    pub async fn inject_incomplete_rekey_watermark(&self, target_epoch: u64) -> Result<()> {
        if !matches!(self.mode, crate::txn::mode::DbMode::Standalone) {
            return Err(PagedbError::Unsupported);
        }
        let mut state = self.writer.lock().await;
        self.write_rekey_watermark(&mut state, target_epoch, false, 0)
            .await
    }

    /// Write the rekey watermark into the catalog and commit the header.
    async fn write_rekey_watermark(
        &self,
        state: &mut WriterState,
        target_epoch: u64,
        main_db_done: bool,
        segments_remaining_idx: u32,
    ) -> Result<()> {
        let hk_snapshot = self.hk.read().clone();
        self.write_rekey_watermark_locked(
            state,
            target_epoch,
            main_db_done,
            segments_remaining_idx,
            &hk_snapshot,
        )
        .await
    }

    async fn write_rekey_watermark_locked(
        &self,
        state: &mut WriterState,
        target_epoch: u64,
        main_db_done: bool,
        segments_remaining_idx: u32,
        hk: &crate::crypto::keys::DerivedKey,
    ) -> Result<()> {
        let row = RekeyStateRow {
            target_mk_epoch: target_epoch,
            main_db_done,
            segments_remaining_idx,
        };
        let encoded = Catalog::encode_rekey_state(&row);

        let mut cat_tree = BTree::open(
            self.pager.clone(),
            self.realm_id,
            state.catalog_root_page_id,
            state.next_page_id,
            self.page_size,
        );
        let key = Catalog::rekey_state_key();
        cat_tree.put(&key, &encoded).await?;
        cat_tree.flush().await?;

        let new_catalog_root = cat_tree.root_page_id();
        let new_next = cat_tree.next_page_id().max(state.next_page_id);
        let new_seq = state.seq + 1;
        let counter_anchor = self.pager.pending_anchor();

        let mut catalog_root_bytes = [0u8; 16];
        catalog_root_bytes[..8].copy_from_slice(&new_catalog_root.to_le_bytes());
        catalog_root_bytes[8..].copy_from_slice(&state.latest_commit_id.to_le_bytes());

        let fields = MainDbHeaderFields {
            format_version: 1,
            cipher_id: self.cipher_id.as_byte(),
            page_size_log2: page_size_log2(self.page_size)?,
            flags: 0,
            file_id: self.file_id,
            kek_salt: self.kek_salt,
            mk_epoch: self.mk_epoch.load(Ordering::SeqCst),
            seq: new_seq,
            active_root_page_id: state.root_page_id,
            active_root_txn_id: state.latest_commit_id,
            counter_anchor,
            commit_id: CommitId(state.latest_commit_id),
            free_list_root: [0; 16],
            catalog_root: catalog_root_bytes,
            apply_journal_root_page_id: 0,
            apply_journal_root_version: 0,
            commit_history_root_page_id: 0,
            commit_history_root_version: 0,
            restore_mode: 0,
            next_page_id: new_next,

            commit_retain_policy_tag: 0,

            commit_retain_policy_value: 0,
        };

        let new_slot = commit_header(
            &*self.vfs,
            &self.main_db_path,
            hk,
            &fields,
            state.active_slot,
            self.page_size,
        )
        .await?;
        self.pager.commit_anchor(counter_anchor)?;

        state.catalog_root_page_id = new_catalog_root;
        state.next_page_id = new_next;
        state.active_slot = new_slot;
        state.seq = new_seq;

        Ok(())
    }

    /// List all segment entries in the catalog.
    async fn list_all_segments(&self, state: &WriterState) -> Result<Vec<SegmentMeta>> {
        if state.catalog_root_page_id == 0 {
            return Ok(Vec::new());
        }
        let tree = BTree::open(
            self.pager.clone(),
            self.realm_id,
            state.catalog_root_page_id,
            state.next_page_id,
            self.page_size,
        );
        let start = vec![CatalogRowKind::Segment as u8];
        let mut end = start.clone();
        end.push(0xFF);
        let rows = tree.collect_range(&start, &end).await?;
        let mut out = Vec::with_capacity(rows.len());
        for (_k, v) in rows {
            let meta = Catalog::decode_segment_meta(&v)?;
            out.push(meta);
        }
        Ok(out)
    }

    /// Find the catalog name for a segment by its `segment_id`.
    async fn find_segment_name(
        &self,
        state: &WriterState,
        segment_id: &[u8; 16],
    ) -> Result<String> {
        if state.catalog_root_page_id == 0 {
            return Err(PagedbError::NotFound);
        }
        let tree = BTree::open(
            self.pager.clone(),
            self.realm_id,
            state.catalog_root_page_id,
            state.next_page_id,
            self.page_size,
        );
        let start = vec![CatalogRowKind::Segment as u8];
        let mut end = start.clone();
        end.push(0xFF);
        let rows = tree.collect_range(&start, &end).await?;
        for (k, v) in rows {
            let meta = Catalog::decode_segment_meta(&v)?;
            if meta.segment_id == *segment_id {
                // Key layout: [0x01] || realm_id[16] || name_bytes
                if k.len() > 17 {
                    let name = String::from_utf8_lossy(&k[17..]).into_owned();
                    return Ok(name);
                }
            }
        }
        Err(PagedbError::NotFound)
    }

    /// Replace a segment in the catalog with a new one and commit the header.
    async fn replace_segment_in_catalog(
        &self,
        state: &mut WriterState,
        name: &str,
        old_segment_id: &[u8; 16],
        new_meta: &SegmentMeta,
        hk: &crate::crypto::keys::DerivedKey,
        new_mk_epoch: u64,
    ) -> Result<()> {
        let key = Catalog::segment_key(self.realm_id, name.as_bytes())?;
        let value = Catalog::encode_segment_meta(new_meta);

        let mut cat_tree = BTree::open(
            self.pager.clone(),
            self.realm_id,
            state.catalog_root_page_id,
            state.next_page_id,
            self.page_size,
        );
        cat_tree.put(&key, &value).await?;
        cat_tree.flush().await?;

        let new_catalog_root = cat_tree.root_page_id();
        let new_next = cat_tree.next_page_id().max(state.next_page_id);
        let new_commit_id = state.latest_commit_id + 1;
        let new_seq = state.seq + 1;
        let counter_anchor = self.pager.pending_anchor();

        let mut catalog_root_bytes = [0u8; 16];
        catalog_root_bytes[..8].copy_from_slice(&new_catalog_root.to_le_bytes());
        catalog_root_bytes[8..].copy_from_slice(&new_commit_id.to_le_bytes());

        let fields = MainDbHeaderFields {
            format_version: 1,
            cipher_id: self.cipher_id.as_byte(),
            page_size_log2: page_size_log2(self.page_size)?,
            flags: 0,
            file_id: self.file_id,
            kek_salt: self.kek_salt,
            mk_epoch: new_mk_epoch,
            seq: new_seq,
            active_root_page_id: state.root_page_id,
            active_root_txn_id: state.latest_commit_id,
            counter_anchor,
            commit_id: CommitId(new_commit_id),
            free_list_root: [0; 16],
            catalog_root: catalog_root_bytes,
            apply_journal_root_page_id: 0,
            apply_journal_root_version: 0,
            commit_history_root_page_id: 0,
            commit_history_root_version: 0,
            restore_mode: 0,
            next_page_id: new_next,

            commit_retain_policy_tag: 0,

            commit_retain_policy_value: 0,
        };

        let new_slot = commit_header(
            &*self.vfs,
            &self.main_db_path,
            hk,
            &fields,
            state.active_slot,
            self.page_size,
        )
        .await?;
        self.pager.commit_anchor(counter_anchor)?;

        // Promote the new segment staging file to live.
        self.vfs.mkdir_all("seg").await?;
        let staging = crate::segment::writer::staging_path(&new_meta.segment_id);
        let live = crate::segment::writer::live_path(&new_meta.segment_id);
        self.vfs.rename(&staging, &live).await?;
        self.vfs.sync_dir("seg").await.ok();

        // Tombstone the old segment.
        let old_live = crate::segment::writer::live_path(old_segment_id);
        let tomb = format!(
            "seg/.tombstone/{}.{}",
            crate::segment::writer::hex_lower(old_segment_id),
            new_commit_id,
        );
        self.vfs.mkdir_all("seg/.tombstone").await?;
        self.vfs.rename(&old_live, &tomb).await.ok();
        self.vfs.sync_dir("seg/.tombstone").await.ok();

        state.catalog_root_page_id = new_catalog_root;
        state.next_page_id = new_next;
        state.active_slot = new_slot;
        state.seq = new_seq;
        state.latest_commit_id = new_commit_id;
        self.latest_commit.store(new_commit_id, Ordering::SeqCst);
        self.publish_snapshot(state);

        Ok(())
    }

    /// Remove the rekey watermark row from the catalog and commit.
    async fn clear_rekey_watermark(
        &self,
        state: &mut WriterState,
        hk: &crate::crypto::keys::DerivedKey,
    ) -> Result<()> {
        if state.catalog_root_page_id == 0 {
            return Ok(());
        }
        let mut cat_tree = BTree::open(
            self.pager.clone(),
            self.realm_id,
            state.catalog_root_page_id,
            state.next_page_id,
            self.page_size,
        );
        let key = Catalog::rekey_state_key();
        // Delete returns false if the key wasn't present; ignore that.
        let _ = cat_tree.delete(&key).await?;
        cat_tree.flush().await?;

        let new_catalog_root = cat_tree.root_page_id();
        let new_next = cat_tree.next_page_id().max(state.next_page_id);
        let new_seq = state.seq + 1;
        let counter_anchor = self.pager.pending_anchor();

        let mut catalog_root_bytes = [0u8; 16];
        catalog_root_bytes[..8].copy_from_slice(&new_catalog_root.to_le_bytes());
        catalog_root_bytes[8..].copy_from_slice(&state.latest_commit_id.to_le_bytes());

        let fields = MainDbHeaderFields {
            format_version: 1,
            cipher_id: self.cipher_id.as_byte(),
            page_size_log2: page_size_log2(self.page_size)?,
            flags: 0,
            file_id: self.file_id,
            kek_salt: self.kek_salt,
            mk_epoch: self.mk_epoch.load(Ordering::SeqCst),
            seq: new_seq,
            active_root_page_id: state.root_page_id,
            active_root_txn_id: state.latest_commit_id,
            counter_anchor,
            commit_id: CommitId(state.latest_commit_id),
            free_list_root: [0; 16],
            catalog_root: catalog_root_bytes,
            apply_journal_root_page_id: 0,
            apply_journal_root_version: 0,
            commit_history_root_page_id: 0,
            commit_history_root_version: 0,
            restore_mode: 0,
            next_page_id: new_next,

            commit_retain_policy_tag: 0,

            commit_retain_policy_value: 0,
        };

        let new_slot = commit_header(
            &*self.vfs,
            &self.main_db_path,
            hk,
            &fields,
            state.active_slot,
            self.page_size,
        )
        .await?;
        self.pager.commit_anchor(counter_anchor)?;

        state.catalog_root_page_id = new_catalog_root;
        state.next_page_id = new_next;
        state.active_slot = new_slot;
        state.seq = new_seq;

        Ok(())
    }

    /// Return the `next_page_id` from the current writer state.
    ///
    /// Intended for integration tests that need to know how many pages exist.
    pub async fn next_page_id(&self) -> u64 {
        self.writer.lock().await.next_page_id
    }

    /// Evict all clean and dirty pages for the main realm from the buffer
    /// pool. Intended for integration tests that corrupt pages on disk and
    /// want subsequent reads to see the disk contents rather than cached data.
    pub fn evict_main_pages(&self, realm: crate::RealmId) {
        self.pager.discard_dirty_main(realm);
    }

    /// Return the current size of `main.db` in bytes. Useful for tests that
    /// verify compaction shrinks the file.
    pub async fn main_db_byte_size(&self) -> Result<u64> {
        use crate::vfs::VfsFile;
        use crate::vfs::types::OpenMode;
        let f = self.vfs.open(&self.main_db_path, OpenMode::Read).await?;
        f.len().await
    }

    /// Perform online compaction.
    ///
    /// Drains eligible deferred-free pages into the persistent free-list,
    /// repacks the main and catalog B+ trees into densely-allocated page space,
    /// truncates `main.db` if no reader pins the old high-water range, and
    /// repacks segment files whose garbage ratio exceeds 5%.
    ///
    /// Returns a [`CompactStats`] summary of what was reclaimed.
    pub async fn compact_now(&self) -> Result<crate::compaction::CompactStats> {
        crate::compaction::compact_now(self).await
    }

    /// Perform one incremental compaction step bounded by `budget`.
    ///
    /// Each call holds the writer lock for at most one batch commit, then
    /// releases. The compaction watermark is persisted to the catalog after
    /// each call, so a crash mid-compaction is safe: call `compact_step` again
    /// after reopening to resume from where it left off.
    ///
    /// Returns a [`CompactProgress`] describing what was done and whether more
    /// work remains. Loop until `progress.more_work == false` to compact fully.
    pub async fn compact_step(
        &self,
        budget: crate::compaction::CompactBudget,
    ) -> Result<crate::compaction::CompactProgress> {
        crate::compaction::compact_step(self, budget).await
    }

    /// Look up `commit` in the commit-history B+ tree and, if found, return a
    /// `ReadTxn` pinned to that historical snapshot.
    pub async fn begin_read_at(&self, commit: CommitId) -> Result<ReadTxn<'_, V>> {
        let (history_root, history_next, latest_commit_id) = {
            let w = self.writer.lock().await;
            (
                w.commit_history_root_page_id,
                w.next_page_id,
                w.latest_commit_id,
            )
        };

        // Fast path: current commit.
        if commit.0 == latest_commit_id {
            let w = self.writer.lock().await;
            let cid = CommitId(w.latest_commit_id);
            let root = w.root_page_id;
            let next = w.next_page_id;
            let cat = w.catalog_root_page_id;
            drop(w);
            return Ok(self.register_read(cid, root, next, cat, false));
        }

        if history_root == 0 {
            // History tree not yet written; all historical commits are gone.
            return Err(PagedbError::CommitGone {
                commit,
                oldest_available: CommitId(latest_commit_id),
            });
        }

        let tree = BTree::open(
            self.pager.clone(),
            self.realm_id,
            history_root,
            history_next,
            self.page_size,
        );

        let key = commit.0.to_be_bytes().to_vec();
        if let Some(value) = tree.get(&key).await? {
            let meta = decode_commit_meta(&value)?;
            Ok(self.register_read(
                commit,
                meta.active_root_page_id,
                meta.next_page_id,
                meta.catalog_root_page_id,
                false,
            ))
        } else {
            // Find the oldest available: scan from the beginning.
            let start = 0u64.to_be_bytes().to_vec();
            let end = u64::MAX.to_be_bytes().to_vec();
            let oldest = tree
                .collect_range(&start, &end)
                .await?
                .into_iter()
                .next()
                .map_or(CommitId(latest_commit_id), |(k, _)| {
                    let mut b = [0u8; 8];
                    b.copy_from_slice(&k[..8]);
                    CommitId(u64::from_be_bytes(b))
                });
            Err(PagedbError::CommitGone {
                commit,
                oldest_available: oldest,
            })
        }
    }

    /// Insert a commit-history entry into the commit-history B+ tree, prune
    /// according to the retention policy, and return the updated
    /// `(root_page_id, root_version, new_next_page_id)`.
    #[allow(clippy::too_many_lines)]
    pub(crate) async fn write_commit_history_entry(
        &self,
        state: &mut WriterState,
        new_commit_id: u64,
        meta: CommitHistoryMeta,
    ) -> Result<()> {
        let min_pinned = {
            let readers = self.tracked_readers.lock();
            readers.iter().map(|r| r.commit_id.0).min()
        };

        let mut hist_tree = BTree::open(
            self.pager.clone(),
            self.realm_id,
            state.commit_history_root_page_id,
            state.next_page_id,
            self.page_size,
        );

        // Insert the new entry.
        let key = new_commit_id.to_be_bytes().to_vec();
        let value = encode_commit_meta(&meta);
        let was_new = hist_tree.get(&key).await?.is_none();
        hist_tree.put(&key, &value).await?;

        // Prune according to retention policy.
        let policy = &self.options.commit_history_retain;
        match policy {
            crate::options::RetainPolicy::Unbounded => {
                // No pruning.
                if was_new {
                    state.commit_history_count =
                        Some(state.commit_history_count.unwrap_or(0).saturating_add(1));
                }
            }
            crate::options::RetainPolicy::Count(n) => {
                let count = *n as usize;
                // Fast path: if the cached count is known and the post-insert
                // count is at or below the retain limit, we can skip the
                // full-tree `collect_range` scan entirely.
                let projected = state
                    .commit_history_count
                    .map(|c| if was_new { c.saturating_add(1) } else { c });
                if let Some(p) = projected {
                    if p <= u64::from(*n) {
                        state.commit_history_count = Some(p);
                        // Materialize and return below.
                    } else {
                        // Over-limit: do the scan + prune.
                        let start = 0u64.to_be_bytes().to_vec();
                        let end = u64::MAX.to_be_bytes().to_vec();
                        let all = hist_tree.collect_range(&start, &end).await?;
                        let mut current = all.len() as u64;
                        if all.len() > count {
                            let to_delete = all.len() - count;
                            for (k, _) in all.iter().take(to_delete) {
                                let mut b = [0u8; 8];
                                b.copy_from_slice(&k[..8]);
                                let cid = u64::from_be_bytes(b);
                                if let Some(min) = min_pinned {
                                    if cid >= min {
                                        continue;
                                    }
                                }
                                if hist_tree.delete(k).await? {
                                    current = current.saturating_sub(1);
                                }
                            }
                        }
                        state.commit_history_count = Some(current);
                    }
                } else {
                    // No cached count — do the scan to populate it.
                    let start = 0u64.to_be_bytes().to_vec();
                    let end = u64::MAX.to_be_bytes().to_vec();
                    let all = hist_tree.collect_range(&start, &end).await?;
                    let mut current = all.len() as u64;
                    if all.len() > count {
                        let to_delete = all.len() - count;
                        for (k, _) in all.iter().take(to_delete) {
                            let mut b = [0u8; 8];
                            b.copy_from_slice(&k[..8]);
                            let cid = u64::from_be_bytes(b);
                            if let Some(min) = min_pinned {
                                if cid >= min {
                                    continue;
                                }
                            }
                            if hist_tree.delete(k).await? {
                                current = current.saturating_sub(1);
                            }
                        }
                    }
                    state.commit_history_count = Some(current);
                }
            }
            crate::options::RetainPolicy::Age(duration) => {
                let now_secs = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs());
                let threshold = now_secs.saturating_sub(duration.as_secs());
                let start = 0u64.to_be_bytes().to_vec();
                let end = u64::MAX.to_be_bytes().to_vec();
                let all = hist_tree.collect_range(&start, &end).await?;
                let mut current = all.len() as u64;
                for (k, v) in &all {
                    // Never delete the entry we just inserted.
                    if k == &key {
                        continue;
                    }
                    let meta_v = decode_commit_meta(v)?;
                    if meta_v.unix_seconds < threshold {
                        let mut b = [0u8; 8];
                        b.copy_from_slice(&k[..8]);
                        let cid = u64::from_be_bytes(b);
                        if let Some(min) = min_pinned {
                            if cid >= min {
                                continue;
                            }
                        }
                        if hist_tree.delete(k).await? {
                            current = current.saturating_sub(1);
                        }
                    }
                }
                state.commit_history_count = Some(current);
            }
            crate::options::RetainPolicy::Disabled => {
                // Unreachable: `WriteTxn::commit` skips this call entirely
                // when the policy is `Disabled`. Treat any accidental call as
                // a no-op rather than panicking, to be defensive.
            }
        }

        // Materialize the history tree's dirty leaves into the pager (so the
        // commit's unified `pager.flush_main` picks them up) without issuing a
        // separate fsync. The caller is responsible for flushing the pager.
        hist_tree.materialize_dirty().await?;
        let new_hist_root = hist_tree.root_page_id();
        let new_next = hist_tree.next_page_id().max(state.next_page_id);

        state.commit_history_root_page_id = new_hist_root;
        state.commit_history_root_version = new_commit_id;
        state.next_page_id = new_next;

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Snapshot / restore / incremental-apply
    // -----------------------------------------------------------------------

    /// Full verbatim snapshot of the database at the current `latest_commit`.
    ///
    /// Not available on `wasm32` targets (requires native file system access).
    ///
    /// Takes a non-abortable `ReadTxn` to pin the state while files are copied,
    /// then writes `<dst_path>/manifest`, `<dst_path>/main.db`, and all live
    /// segment files under `<dst_path>/seg/<hex(id)>`.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn snapshot_to(
        &self,
        dst_path: &std::path::Path,
    ) -> crate::Result<crate::snapshot::SnapshotStats> {
        use crate::snapshot::export::{SnapshotManifest, snapshot_full};

        let _span = tracing::debug_span!("snapshot.export");

        // Pin the current state via a non-abortable read txn.
        let txn = {
            let w = self.writer.lock().await;
            let cid = crate::CommitId(w.latest_commit_id);
            let root = w.root_page_id;
            let next = w.next_page_id;
            let cat = w.catalog_root_page_id;
            drop(w);
            self.register_read(cid, root, next, cat, true)
        };

        let (target_commit, next_page_id) = { (txn.commit_id().0, txn.next_page_id()) };

        // Collect live segment ids from the pinned catalog snapshot.
        let segments = txn.list_segments("").await?;
        let segment_ids: Vec<[u8; 16]> = segments.iter().map(|m| m.segment_id).collect();
        let segments_count = u32::try_from(segment_ids.len()).unwrap_or(u32::MAX);

        // The manifest HK-MAC key is the DB's in-memory HK bytes (first 32 bytes).
        let hk_raw: [u8; 32] = {
            let hk_guard = self.hk.read();
            *hk_guard.as_bytes()
        };

        let manifest = SnapshotManifest {
            version: 1,
            kind: 0, // Full
            target_commit,
            base_commit: 0,
            file_id: self.file_id,
            mk_epoch: self.mk_epoch.load(std::sync::atomic::Ordering::SeqCst),
            kek_salt: self.kek_salt,
            cipher_id: self.cipher_id.as_byte(),
            page_size: self.page_size.try_into().unwrap_or(4096),
            next_page_id_at_target: next_page_id,
            segments_count,
            realm_id: self.realm_id.0,
        };

        let src_root = get_vfs_root(&*self.vfs)?;

        let stats = snapshot_full(&src_root, dst_path, &manifest, &hk_raw, &segment_ids).await?;
        drop(txn); // unpin
        Ok(stats)
    }

    /// Associated fn. Copy snapshot from `src_path` into `dst_path` and return
    /// a `Db` in `DbMode::ReadOnly`.
    ///
    /// Verifies the manifest HK-MAC using `kek` before copying; returns
    /// `Corruption` on failure.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn restore_from(
        src_path: &std::path::Path,
        dst_path: &std::path::Path,
        options: crate::options::OpenOptions,
        kek: [u8; 32],
    ) -> crate::Result<crate::txn::db::Db<crate::vfs::tokio_backend::TokioVfs>> {
        use crate::snapshot::export::open_manifest;
        use crate::vfs::tokio_backend::TokioVfs;
        use tokio::fs;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let _span = tracing::debug_span!("snapshot.apply");

        // Verify and parse manifest.
        let manifest_src = src_path.join("manifest");
        let manifest = open_manifest(&manifest_src, &kek).await?;

        // Create destination directory.
        fs::create_dir_all(dst_path)
            .await
            .map_err(crate::errors::PagedbError::Io)?;
        let seg_dst = dst_path.join("seg");
        fs::create_dir_all(&seg_dst)
            .await
            .map_err(crate::errors::PagedbError::Io)?;

        // Copy manifest.
        let mut manifest_bytes = [0u8; 240];
        {
            let mut f = fs::File::open(&manifest_src)
                .await
                .map_err(crate::errors::PagedbError::Io)?;
            f.read_exact(&mut manifest_bytes)
                .await
                .map_err(crate::errors::PagedbError::Io)?;
        }
        {
            let mut f = fs::File::create(dst_path.join("manifest"))
                .await
                .map_err(crate::errors::PagedbError::Io)?;
            f.write_all(&manifest_bytes)
                .await
                .map_err(crate::errors::PagedbError::Io)?;
        }

        // Copy main.db.
        fs::copy(src_path.join("main.db"), dst_path.join("main.db"))
            .await
            .map_err(crate::errors::PagedbError::Io)?;

        // Copy segment files.
        let seg_src = src_path.join("seg");
        if let Ok(mut rd) = fs::read_dir(&seg_src).await {
            while let Ok(Some(entry)) = rd.next_entry().await {
                let name = entry.file_name();
                let src_file = seg_src.join(&name);
                let dst_file = seg_dst.join(&name);
                fs::copy(&src_file, &dst_file)
                    .await
                    .map_err(crate::errors::PagedbError::Io)?;
            }
        }

        // Open the restored Db in ReadOnly mode.
        let page_size = manifest.page_size as usize;
        let realm_id = crate::RealmId(manifest.realm_id);
        let dst_vfs = TokioVfs::new(dst_path);
        Db::<TokioVfs>::open_read_only(dst_vfs, kek, page_size, realm_id, options).await
    }

    /// Page-diff snapshot since `base_commit`. Emits only pages changed since
    /// the base commit, plus segment files new/changed since that commit.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn snapshot_incremental_to(
        &self,
        base_commit: crate::CommitId,
        dst_path: &std::path::Path,
    ) -> crate::Result<crate::snapshot::SnapshotStats> {
        use crate::snapshot::export::{SnapshotManifest, snapshot_incremental};

        // Pin current state.
        let txn = {
            let w = self.writer.lock().await;
            let cid = crate::CommitId(w.latest_commit_id);
            let root = w.root_page_id;
            let next = w.next_page_id;
            let cat = w.catalog_root_page_id;
            drop(w);
            self.register_read(cid, root, next, cat, true)
        };

        let target_commit = txn.commit_id().0;
        let target_next_page_id = txn.next_page_id();

        // Get base snapshot's next_page_id by reading the commit history.
        let base_txn_result = self.begin_read_at(base_commit).await;
        let base_next_page_id = match &base_txn_result {
            Ok(bt) => bt.next_page_id(),
            Err(_) => 0u64,
        };
        let base_catalog_root = match &base_txn_result {
            Ok(bt) => bt.catalog_root_page_id(),
            Err(_) => 0u64,
        };

        // Pages changed = all pages with page_id >= base_next_page_id (allocated after base).
        // Also include all pages reachable from current root that have id >= base_next_page_id.
        let changed_page_ids: Vec<u64> = (base_next_page_id..target_next_page_id).collect();

        // Current segments.
        let current_segments = txn.list_segments("").await?;
        // Base segments (from base catalog).
        let base_segments: Vec<crate::catalog::codec::SegmentMeta> = if base_catalog_root != 0 {
            match &base_txn_result {
                Ok(bt) => bt.list_segments("").await.unwrap_or_default(),
                Err(_) => Vec::new(),
            }
        } else {
            Vec::new()
        };

        // New/changed segments: present in current but absent or different segment_id in base.
        let base_ids: std::collections::HashSet<[u8; 16]> =
            base_segments.iter().map(|m| m.segment_id).collect();
        let new_segments: Vec<[u8; 16]> = current_segments
            .iter()
            .filter(|m| !base_ids.contains(&m.segment_id))
            .map(|m| m.segment_id)
            .collect();

        let segments_count = u32::try_from(new_segments.len()).unwrap_or(u32::MAX);

        let hk_raw: [u8; 32] = {
            let hk_guard = self.hk.read();
            *hk_guard.as_bytes()
        };

        let manifest = SnapshotManifest {
            version: 1,
            kind: 1, // Incremental
            target_commit,
            base_commit: base_commit.0,
            file_id: self.file_id,
            mk_epoch: self.mk_epoch.load(std::sync::atomic::Ordering::SeqCst),
            kek_salt: self.kek_salt,
            cipher_id: self.cipher_id.as_byte(),
            page_size: self.page_size.try_into().unwrap_or(4096),
            next_page_id_at_target: target_next_page_id,
            segments_count,
            realm_id: self.realm_id.0,
        };

        let src_root = get_vfs_root(&*self.vfs)?;

        let stats = snapshot_incremental(
            &src_root,
            dst_path,
            &manifest,
            &hk_raw,
            &new_segments,
            base_next_page_id,
            &changed_page_ids,
        )
        .await?;

        drop(txn);
        Ok(stats)
    }

    /// Apply an incremental snapshot to this Follower handle.
    ///
    /// Reads `src_path/pages.delta` and writes pages directly to `main.db`,
    /// then promotes segment files, then commits the new header.
    #[cfg(not(target_arch = "wasm32"))]
    #[allow(clippy::too_many_lines)]
    pub async fn apply_incremental(
        &self,
        src_path: &std::path::Path,
    ) -> crate::Result<crate::snapshot::ApplyStats> {
        use crate::pager::format::data_page::ENVELOPE_OVERHEAD;
        use crate::pager::format::page_kind::PageKind;
        use crate::pager::format::structural_header::MainDbHeaderFields;
        use crate::pager::header::commit_header;
        use crate::recovery::journal::{
            ApplyJournalRecord, JournalAction, encode_apply_journal, execute_journal_actions,
        };
        use crate::snapshot::apply::{apply_delta_pages, stage_snapshot_segments};

        let _span = tracing::debug_span!("snapshot.apply");

        if !matches!(self.mode, DbMode::Follower) {
            return Err(crate::errors::PagedbError::IdentityForked);
        }

        let manifest_path = src_path.join("manifest");
        // We need kek to verify the manifest, but Db doesn't hold it. Use the
        // HK bytes directly as the "kek" for MAC verification — since the
        // snapshot was created with the HK-raw bytes as the MAC key, we verify
        // with the same material.
        let hk_raw: [u8; 32] = {
            let hk_guard = self.hk.read();
            *hk_guard.as_bytes()
        };
        // Decode manifest using hk_raw as the key directly.
        let manifest_bytes = {
            use tokio::fs;
            use tokio::io::AsyncReadExt;
            let mut f = fs::File::open(&manifest_path)
                .await
                .map_err(crate::errors::PagedbError::Io)?;
            let mut buf = [0u8; 240];
            let _ = f
                .read_exact(&mut buf)
                .await
                .map_err(crate::errors::PagedbError::Io)?;
            buf
        };
        let manifest = crate::snapshot::export::decode_manifest(&manifest_bytes, &hk_raw)?;

        let page_size = manifest.page_size as usize;
        let vfs_root = get_vfs_root(&*self.vfs)?;
        let dst_main_db = vfs_root.join("main.db");

        // Write delta pages to main.db.
        let pages_applied = apply_delta_pages(src_path, &dst_main_db, page_size).await?;

        // Stage new segment files in `.staging/` so they can be promoted
        // atomically after the header swap via the apply journal.
        let dst_seg_root = vfs_root.join("seg");
        let staged_ids = stage_snapshot_segments(src_path, &dst_seg_root).await?;
        let segments_promoted = u32::try_from(staged_ids.len()).unwrap_or(u32::MAX);

        // Build journal actions: one Promote per staged segment.
        let new_commit_id = manifest.target_commit;
        let actions: Vec<JournalAction> = staged_ids
            .iter()
            .map(|&segment_id| JournalAction::Promote { segment_id })
            .collect();

        let mut state = self.writer.lock().await;

        // Select the journal slot by parity of the current version counter.
        // Even version → slot page 2; odd version → slot page 3.
        let journal_version = state.seq;
        let journal_page_id: u64 = if journal_version % 2 == 0 { 2 } else { 3 };

        // Write the journal record to the selected slot page via the Pager's
        // AEAD path. This ensures the journal is authenticated under the same
        // keys as all other pages.
        if !actions.is_empty() {
            let body_len = page_size - ENVELOPE_OVERHEAD;
            let record = ApplyJournalRecord {
                target_commit_id: new_commit_id,
                actions: actions.clone(),
            };
            let body = encode_apply_journal(&record, body_len)?;
            self.pager
                .write_main_page(
                    journal_page_id,
                    self.realm_id,
                    PageKind::ApplyJournal,
                    &body,
                )
                .await?;
            self.pager.flush_main(self.realm_id).await?;
        }

        // Commit the A/B header with the journal root pointing at the slot we
        // just wrote. After this commit, a crash-recovery replay can re-execute
        // the promote renames idempotently.
        let new_next_page_id = manifest.next_page_id_at_target;
        let new_seq = state.seq + 1;
        let counter_anchor = self.pager.pending_anchor();

        let mut catalog_root_bytes = [0u8; 16];
        catalog_root_bytes[..8].copy_from_slice(&state.catalog_root_page_id.to_le_bytes());
        catalog_root_bytes[8..].copy_from_slice(&new_commit_id.to_le_bytes());

        let journal_root_page_id_for_header = if actions.is_empty() {
            0
        } else {
            journal_page_id
        };

        let fields_with_journal = MainDbHeaderFields {
            format_version: 1,
            cipher_id: self.cipher_id.as_byte(),
            page_size_log2: page_size_log2(self.page_size)?,
            flags: 0,
            file_id: self.file_id,
            kek_salt: self.kek_salt,
            mk_epoch: self.mk_epoch.load(std::sync::atomic::Ordering::SeqCst),
            seq: new_seq,
            active_root_page_id: manifest.next_page_id_at_target,
            active_root_txn_id: new_commit_id,
            counter_anchor,
            commit_id: crate::CommitId(new_commit_id),
            free_list_root: [0; 16],
            catalog_root: catalog_root_bytes,
            apply_journal_root_page_id: journal_root_page_id_for_header,
            apply_journal_root_version: journal_version,
            commit_history_root_page_id: 0,
            commit_history_root_version: 0,
            restore_mode: 0,
            next_page_id: new_next_page_id,
            commit_retain_policy_tag: 0,
            commit_retain_policy_value: 0,
        };

        let hk_clone = { self.hk.read().clone() };
        let new_slot = commit_header(
            &*self.vfs,
            &self.main_db_path,
            &hk_clone,
            &fields_with_journal,
            state.active_slot,
            self.page_size,
        )
        .await?;
        self.pager.commit_anchor(counter_anchor)?;

        // The header swap is durable. Execute the journal actions (staging →
        // live renames). Each rename is idempotent; a crash here is safe
        // because replay_apply_journal will re-execute on the next open.
        if actions.is_empty() {
            state.active_slot = new_slot;
            state.seq = new_seq;
        } else {
            execute_journal_actions(&*self.vfs, &actions).await;

            // Clear the journal root by writing a second header commit with
            // apply_journal_root_page_id = 0. This marks the journal as complete.
            let new_seq2 = new_seq + 1;
            let counter_anchor2 = self.pager.pending_anchor();
            let fields_clear = MainDbHeaderFields {
                format_version: 1,
                cipher_id: self.cipher_id.as_byte(),
                page_size_log2: page_size_log2(self.page_size)?,
                flags: 0,
                file_id: self.file_id,
                kek_salt: self.kek_salt,
                mk_epoch: self.mk_epoch.load(std::sync::atomic::Ordering::SeqCst),
                seq: new_seq2,
                active_root_page_id: new_next_page_id,
                active_root_txn_id: new_commit_id,
                counter_anchor: counter_anchor2,
                commit_id: crate::CommitId(new_commit_id),
                free_list_root: [0; 16],
                catalog_root: catalog_root_bytes,
                apply_journal_root_page_id: 0,
                apply_journal_root_version: 0,
                commit_history_root_page_id: 0,
                commit_history_root_version: 0,
                restore_mode: 0,
                next_page_id: new_next_page_id,
                commit_retain_policy_tag: 0,
                commit_retain_policy_value: 0,
            };
            let new_slot2 = commit_header(
                &*self.vfs,
                &self.main_db_path,
                &hk_clone,
                &fields_clear,
                new_slot,
                self.page_size,
            )
            .await?;
            self.pager.commit_anchor(counter_anchor2)?;
            state.active_slot = new_slot2;
            state.seq = new_seq2;
        }

        state.latest_commit_id = new_commit_id;
        state.next_page_id = new_next_page_id;
        self.latest_commit
            .store(new_commit_id, std::sync::atomic::Ordering::SeqCst);
        self.publish_snapshot(&state);

        drop(state);

        Ok(crate::snapshot::ApplyStats {
            pages_applied,
            segments_promoted,
            segments_tombstoned: 0,
        })
    }

    /// Promote a `ReadOnly` handle to `Follower` mode. Only valid when the
    /// current mode is `ReadOnly`. Acquires the writer lock (releases the
    /// frozen-readers lock implicitly by dropping it from `sentinel_locks`).
    pub async fn promote_to_follower(mut self) -> crate::Result<Self> {
        if !matches!(self.mode, DbMode::ReadOnly) {
            return Err(crate::errors::PagedbError::Unsupported);
        }
        // Acquire the exclusive writer lock.
        let lock = self
            .vfs
            .lock_exclusive(crate::txn::mode::WRITER_LOCK_PATH)
            .await
            .map_err(|_| crate::errors::PagedbError::AlreadyOpen)?;
        // Drop the frozen_readers shared lock (it's the only entry).
        self.sentinel_locks.clear();
        self.sentinel_locks.push(lock);
        self.mode = DbMode::Follower;
        Ok(self)
    }

    pub(crate) fn next_segment_id(&self) -> [u8; 16] {
        let counter = self.segment_id_counter.fetch_add(1, Ordering::Relaxed);
        let wall = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX));
        let mut seed = u64::from_le_bytes([
            self.file_id[0],
            self.file_id[1],
            self.file_id[2],
            self.file_id[3],
            self.file_id[4],
            self.file_id[5],
            self.file_id[6],
            self.file_id[7],
        ]) ^ counter
            ^ wall;
        let mut out = [0u8; 16];
        for chunk in out.chunks_mut(8) {
            seed = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = seed;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^= z >> 31;
            chunk.copy_from_slice(&z.to_le_bytes());
        }
        out
    }

    /// Collect a point-in-time snapshot of database runtime metrics.
    pub async fn stats(&self) -> Result<DbStats> {
        use crate::vfs::VfsFile;
        use std::sync::atomic::Ordering as AtOrd;

        // Gather writer-guarded values.
        let (latest_commit_id, next_page_id, catalog_root, catalog_next) = {
            let w = self.writer.lock().await;
            (
                w.latest_commit_id,
                w.next_page_id,
                w.catalog_root_page_id,
                w.next_page_id,
            )
        };

        // Main database file size.
        let main_db_bytes = match self
            .vfs
            .open(&self.main_db_path, crate::vfs::types::OpenMode::Read)
            .await
        {
            Ok(f) => f.len().await.unwrap_or(0),
            Err(_) => 0,
        };

        // Buffer pool stats from cache.
        let buffer_pool_pages = { self.pager.inner.buffer_pool.lock().len() as u64 };
        let buffer_pool_hits = self.pager.inner.buffer_pool_hits.load(AtOrd::Relaxed);
        let buffer_pool_misses = self.pager.inner.buffer_pool_misses.load(AtOrd::Relaxed);

        // Dirty pages across both cache classes.
        let dirty_pages = {
            let bp = self.pager.inner.buffer_pool.lock();
            let sc = self.pager.inner.segment_cache.lock();
            (bp.dirty_for_file(crate::pager::core::FileKey::Main).len()
                + sc.dirty_for_file(crate::pager::core::FileKey::Segment([0u8; 16]))
                    .len()) as u64
        };

        // Tracked readers.
        let tracked_readers = u32::try_from(self.tracked_readers.lock().len()).unwrap_or(u32::MAX);

        // Pending tombstones.
        let pending_tombstones =
            u32::try_from(self.pending_tombstones.lock().len()).unwrap_or(u32::MAX);

        // Segment stats and free-list counts from catalog.
        let (segments_live, segments_total_bytes, free_list_pending_entries) = if catalog_root == 0
        {
            (0u32, 0u64, 0u64)
        } else {
            let tree = BTree::open(
                self.pager.clone(),
                self.realm_id,
                catalog_root,
                catalog_next,
                self.page_size,
            );

            // Segments.
            let seg_start = vec![CatalogRowKind::Segment as u8];
            let mut seg_end = seg_start.clone();
            seg_end.push(0xFF);
            let seg_rows = tree
                .collect_range(&seg_start, &seg_end)
                .await
                .unwrap_or_default();
            let seg_count = u32::try_from(seg_rows.len()).unwrap_or(u32::MAX);
            let seg_bytes: u64 = seg_rows
                .iter()
                .filter_map(|(_k, v)| Catalog::decode_segment_meta(v).ok())
                .map(|m| m.total_bytes)
                .sum();

            // Free-list entries (persistent free-list rows).
            let fl_start = vec![CatalogRowKind::FreeList as u8];
            let mut fl_end = fl_start.clone();
            fl_end.push(0xFF);
            let fl_rows = tree
                .collect_range(&fl_start, &fl_end)
                .await
                .unwrap_or_default();
            let fl_count = fl_rows.len() as u64;

            // Deferred-free entries.
            let df_key = Catalog::deferred_free_key();
            let df_count = match tree.get(&df_key).await {
                Ok(Some(bytes)) => {
                    Catalog::decode_deferred_free(&bytes).map_or(0, |v| v.len() as u64)
                }
                _ => 0,
            };

            (seg_count, seg_bytes, fl_count + df_count)
        };

        Ok(DbStats {
            latest_commit_id,
            mode: self.mode,
            main_db_bytes,
            main_db_next_page_id: next_page_id,
            buffer_pool_pages,
            buffer_pool_hits,
            buffer_pool_misses,
            dirty_pages,
            tracked_readers,
            pending_tombstones,
            segments_live,
            segments_total_bytes,
            mmap_bytes_in_use: self.mmap_bytes_in_use.load(AtOrd::Relaxed),
            mk_epoch: self.mk_epoch.load(AtOrd::SeqCst),
            free_list_pending_entries,
            spill_bytes_in_use: self.spill_bytes_in_use.load(AtOrd::Relaxed),
        })
    }
}

/// Packed representation of a historical commit's roots. 40 bytes on disk:
/// `active_root_page_id` (8) | `catalog_root_page_id` (8) | `free_list_root_page_id` (8)
/// | `next_page_id` (8) | `unix_seconds` (8).
pub(crate) struct CommitHistoryMeta {
    pub active_root_page_id: u64,
    pub catalog_root_page_id: u64,
    pub free_list_root_page_id: u64,
    pub next_page_id: u64,
    pub unix_seconds: u64,
}

pub(crate) fn encode_commit_meta(m: &CommitHistoryMeta) -> Vec<u8> {
    let mut out = Vec::with_capacity(40);
    out.extend_from_slice(&m.active_root_page_id.to_le_bytes());
    out.extend_from_slice(&m.catalog_root_page_id.to_le_bytes());
    out.extend_from_slice(&m.free_list_root_page_id.to_le_bytes());
    out.extend_from_slice(&m.next_page_id.to_le_bytes());
    out.extend_from_slice(&m.unix_seconds.to_le_bytes());
    out
}

pub(crate) fn decode_commit_meta(bytes: &[u8]) -> Result<CommitHistoryMeta> {
    if bytes.len() < 40 {
        return Err(PagedbError::corruption(
            crate::errors::CorruptionDetail::HeaderUnverifiable,
        ));
    }
    let read_u64 = |b: &[u8], off: usize| {
        let mut a = [0u8; 8];
        a.copy_from_slice(&b[off..off + 8]);
        u64::from_le_bytes(a)
    };
    Ok(CommitHistoryMeta {
        active_root_page_id: read_u64(bytes, 0),
        catalog_root_page_id: read_u64(bytes, 8),
        free_list_root_page_id: read_u64(bytes, 16),
        next_page_id: read_u64(bytes, 24),
        unix_seconds: read_u64(bytes, 32),
    })
}

fn page_size_log2(page_size: usize) -> Result<u8> {
    match page_size {
        4096 => Ok(12),
        8192 => Ok(13),
        16384 => Ok(14),
        32768 => Ok(15),
        65536 => Ok(16),
        _ => Err(PagedbError::Unsupported),
    }
}

/// Extract the filesystem root path from a `Vfs` instance. Returns
/// `Err(Unsupported)` for in-memory or non-filesystem VFS backends.
fn get_vfs_root<V: Vfs + Clone>(vfs: &V) -> Result<std::path::PathBuf> {
    vfs.root_path()
        .map(std::path::Path::to_path_buf)
        .ok_or(PagedbError::Unsupported)
}

/// Read the `restore_mode` byte from the on-disk header of an existing
/// `main.db` without fully opening the database.
///
/// Tries both the A and B header slots. Returns the `restore_mode` byte from
/// the first slot that verifies successfully under the given KEK.
async fn peek_restore_mode<V: Vfs + Clone>(
    vfs: &V,
    kek: &[u8; 32],
    page_size: usize,
) -> Result<u8> {
    use crate::vfs::VfsFile;
    use crate::vfs::types::OpenMode;

    let f = vfs.open("/main.db", OpenMode::Read).await?;
    let mut buf_a = vec![0u8; page_size];
    let mut buf_b = vec![0u8; page_size];
    f.read_at(0, &mut buf_a).await?;
    let page_size_u64 = u64::try_from(page_size)
        .map_err(|_| PagedbError::Io(std::io::Error::other("page_size > u64")))?;
    f.read_at(page_size_u64, &mut buf_b).await?;
    drop(f);

    for buf in [&buf_a, &buf_b] {
        if buf.len() < 56 {
            continue;
        }
        let mut kek_salt = [0u8; 16];
        kek_salt.copy_from_slice(&buf[32..48]);
        let mut ep_bytes = [0u8; 8];
        ep_bytes.copy_from_slice(&buf[48..56]);
        let mk_epoch = u64::from_le_bytes(ep_bytes);
        let Ok(mk) = derive_mk(kek, &kek_salt, mk_epoch) else {
            continue;
        };
        let Ok(hk) = derive_hk(&mk) else {
            continue;
        };
        if let Ok(fields) =
            crate::pager::format::structural_header::decode_main_db_header(buf, &hk, page_size)
        {
            return Ok(fields.restore_mode);
        }
    }
    Err(PagedbError::corruption(
        crate::errors::CorruptionDetail::HeaderUnverifiable,
    ))
}

/// Generate a unique lease ID for a reader pin using a monotonic counter mixed
/// with the current Unix timestamp. Not cryptographically random, but uniqueness
/// within a process lifetime is sufficient for the pin-row key.
fn next_lease_id() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering as Ord};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let seq = COUNTER.fetch_add(1, Ord::Relaxed);
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| {
            #[allow(clippy::cast_possible_truncation)]
            let v = d.as_nanos() as u64; // lower 64 bits sufficient for uniqueness
            v
        });
    ts ^ (seq.wrapping_mul(0x9e37_79b9_7f4a_7c15))
}

/// Scan the catalog for durable reader-pin rows that are either stale (written
/// by the current PID from a previous process incarnation) or expired by wall
/// clock. Delete all such rows in a single bulk catalog commit. Called at
/// writer-open time to recover from reader crashes.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn cleanup_stale_reader_pins<V: Vfs + Clone>(
    pager: &Arc<Pager<V>>,
    vfs: &Arc<V>,
    main_db_path: &str,
    hk: &crate::crypto::keys::DerivedKey,
    realm_id: RealmId,
    page_size: usize,
    cipher_id: crate::crypto::CipherId,
    file_id: [u8; 16],
    kek_salt: [u8; 16],
    mk_epoch_val: u64,
    state: &mut WriterState,
) -> Result<()> {
    if state.catalog_root_page_id == 0 {
        return Ok(());
    }
    let now = crate::txn::read::unix_now_seconds();
    let own_pid = std::process::id();
    let tree = BTree::open(
        pager.clone(),
        realm_id,
        state.catalog_root_page_id,
        state.next_page_id,
        page_size,
    );
    let start = crate::catalog::codec::Catalog::reader_pin_range_start();
    let end = crate::catalog::codec::Catalog::reader_pin_range_end();
    let rows = tree.collect_range(&start, &end).await?;

    let stale_keys: Vec<Vec<u8>> = rows
        .into_iter()
        .filter_map(|(k, v)| {
            // Key layout: [0x06] || pid_u32_be[4] || lease_id_u64_be[8]
            if k.len() < 13 {
                return Some(k);
            }
            let mut pid_buf = [0u8; 4];
            pid_buf.copy_from_slice(&k[1..5]);
            let row_pid = u32::from_be_bytes(pid_buf);
            // Own-PID rows from prior incarnation (crash without cleanup).
            if row_pid == own_pid {
                return Some(k);
            }
            // Expired rows.
            if let Ok(pv) = Catalog::decode_reader_pin(&v) {
                if pv.expires_unix_seconds < now {
                    return Some(k);
                }
            }
            None
        })
        .collect();

    if stale_keys.is_empty() {
        return Ok(());
    }

    let mut cat_tree = BTree::open(
        pager.clone(),
        realm_id,
        state.catalog_root_page_id,
        state.next_page_id,
        page_size,
    );
    for k in &stale_keys {
        let _ = cat_tree.delete(k).await;
    }
    cat_tree.flush().await?;
    let new_cat_root = cat_tree.root_page_id();
    let new_next = cat_tree.next_page_id().max(state.next_page_id);
    let new_commit_id = state.latest_commit_id + 1;
    let new_seq = state.seq + 1;
    let counter_anchor = pager.pending_anchor();
    let mut catalog_root_bytes = [0u8; 16];
    catalog_root_bytes[..8].copy_from_slice(&new_cat_root.to_le_bytes());
    catalog_root_bytes[8..].copy_from_slice(&new_commit_id.to_le_bytes());
    let fields = MainDbHeaderFields {
        format_version: 1,
        cipher_id: cipher_id.as_byte(),
        page_size_log2: page_size_log2(page_size)?,
        flags: 0,
        file_id,
        kek_salt,
        mk_epoch: mk_epoch_val,
        seq: new_seq,
        active_root_page_id: state.root_page_id,
        active_root_txn_id: state.latest_commit_id,
        counter_anchor,
        commit_id: CommitId(new_commit_id),
        free_list_root: [0u8; 16],
        catalog_root: catalog_root_bytes,
        apply_journal_root_page_id: 0,
        apply_journal_root_version: 0,
        commit_history_root_page_id: state.commit_history_root_page_id,
        commit_history_root_version: state.commit_history_root_version,
        restore_mode: 0,
        next_page_id: new_next,
        commit_retain_policy_tag: 0,
        commit_retain_policy_value: 0,
    };
    let new_slot = commit_header(
        &**vfs,
        main_db_path,
        hk,
        &fields,
        state.active_slot,
        page_size,
    )
    .await?;
    pager.commit_anchor(counter_anchor)?;
    state.catalog_root_page_id = new_cat_root;
    state.next_page_id = new_next;
    state.active_slot = new_slot;
    state.seq = new_seq;
    state.latest_commit_id = new_commit_id;
    Ok(())
}
