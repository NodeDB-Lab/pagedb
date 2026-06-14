//! Open / bootstrap constructors for `Db<V>` across all handle modes.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::sync::Mutex as AsyncMutex;

use crate::crypto::CipherId;
use crate::crypto::kdf::{derive_hk, derive_mk};
use crate::errors::PagedbError;
use crate::options::OpenOptions;
use crate::pager::header::{ActiveSlot, bootstrap_header};
use crate::pager::structural_header::MainDbHeaderFields;
use crate::pager::{Pager, PagerConfig};
use crate::vfs::Vfs;
use crate::{CommitId, RealmId, Result};

use super::super::mode::{DbMode, FROZEN_READERS_LOCK_PATH, OBSERVERS_LOCK_PATH, WRITER_LOCK_PATH};
use super::super::policy::ReaderStallPolicy;
use super::core::{Db, ReaderSnapshot, WriterState};
use super::util::{cleanup_stale_reader_pins, page_size_log2, peek_restore_mode};

impl<V: Vfs + Clone> Db<V> {
    /// Bootstrap a fresh database. Creates `main.db`, writes an initial A/B
    /// header in slot A with `seq=1`.
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
            free_list_root_page_id: 0,
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
            free_page_consumed: Arc::new(parking_lot::Mutex::new(Vec::new())),
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
        Self::open_existing_inner(vfs, kek, page_size, realm, options, DbMode::Standalone).await
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
        Self::open_existing_inner(
            vfs,
            kek,
            page_size,
            realm,
            OpenOptions::default(),
            DbMode::Standalone,
        )
        .await
    }

    #[allow(clippy::too_many_lines)]
    async fn open_existing_inner(
        vfs: V,
        kek: [u8; 32],
        page_size: usize,
        realm: RealmId,
        options: OpenOptions,
        mode: DbMode,
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
            free_list_root_page_id: super::core::decode_free_list_root(&fields.free_list_root),
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
            mode,
            aborted_readers: parking_lot::Mutex::new(std::collections::HashSet::new()),
            sentinel_locks: Vec::new(),
            snapshot: Arc::new(parking_lot::RwLock::new(ReaderSnapshot {
                commit_id: latest_commit,
                root_page_id: fields.active_root_page_id,
                next_page_id: fields.next_page_id,
                catalog_root_page_id,
            })),
            free_page_cache: Arc::new(parking_lot::Mutex::new(Vec::new())),
            free_page_consumed: Arc::new(parking_lot::Mutex::new(Vec::new())),
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

        // Recovery work that mutates the catalog/header is only valid for
        // handle modes that hold the exclusive writer lock. ReadOnly / Observer
        // must never write, so they skip pin cleanup and backlog draining.
        if matches!(mode, DbMode::Standalone | DbMode::Follower) {
            // Remove every durable reader-pin row left behind by a prior
            // (now-dead) incarnation. Safe to clear all of them while holding
            // the exclusive writer lock — see `cleanup_stale_reader_pins`.
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

        // Delegate to the appropriate lower-level constructor. Pass `mode`
        // through to the existing-DB path so open-time recovery (pin cleanup,
        // backlog drain) runs only for writer-lock-holding modes.
        let mut db = if main_db_exists {
            Self::open_existing_inner(vfs, kek, page_size, realm, options, mode).await?
        } else {
            Self::open_internal_with_options(vfs, kek, page_size, realm, options).await?
        };
        db.mode = mode;
        db.sentinel_locks = locks;
        Ok(db)
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
}
