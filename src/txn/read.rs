//! `ReadTxn` — snapshot read pin. Drops auto-unregister from the `Db`'s
//! tracked-readers table and removes the durable catalog pin row.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::sync::OnceCell;

use crate::btree::BTree;
use crate::btree::node::NodeKind;
use crate::catalog::codec::{Catalog, ReaderPinValue, SegmentMeta};
use crate::errors::PagedbError;
use crate::pager::PageGuard;
use crate::pager::Pager;
use crate::segment::reader::SegmentReader;
use crate::vfs::Vfs;
use crate::{CommitId, RealmId, Result};

use super::db::{Db, WriterState};

/// Shared data needed to refresh or remove the durable pin row. Stored in an
/// `Arc` so it can be passed to standalone async helper functions.
pub(crate) struct PinHandle<V: Vfs + Clone> {
    pub(crate) pager: Arc<Pager<V>>,
    pub(crate) realm_id: RealmId,
    pub(crate) page_size: usize,
    pub(crate) main_db_path: String,
    pub(crate) vfs: Arc<V>,
    pub(crate) hk: parking_lot::RwLock<crate::crypto::keys::DerivedKey>,
    pub(crate) mk_epoch: AtomicU64,
    pub(crate) cipher_id: crate::crypto::CipherId,
    pub(crate) file_id: [u8; 16],
    pub(crate) kek_salt: [u8; 16],
    pub(crate) latest_commit: Arc<AtomicU64>,
    /// Shared reader-visible snapshot (clone of `Db::snapshot`). Updated by
    /// the durable-pin micro-commit path so non-abortable readers observe the
    /// new commit immediately.
    pub(crate) snapshot: Arc<parking_lot::RwLock<crate::txn::db::ReaderSnapshot>>,
    pub(crate) pid: u32,
    pub(crate) lease_id: u64,
    pub(crate) lease_seconds: u64,
}

/// A snapshot-isolated read handle. Holds the `BTree` root and allocation
/// cursor at the time the transaction was opened. Unregisters automatically
/// on drop.
pub struct ReadTxn<'db, V: Vfs + Clone> {
    db: &'db Db<V>,
    commit_id: CommitId,
    root_page_id: u64,
    next_page_id: u64,
    catalog_root_page_id: u64,
    entry_id: u64,
    /// The `(pid, lease_id)` pair of the durable pin row inserted at `begin_read`
    /// time, if any. On drop, this pair is pushed to `Db::pending_pin_deletes`
    /// so the next writer commit or `gc_now` can delete the row. `None` if no
    /// durable pin was created (`ReadOnly` / Follower mode, or no catalog yet).
    durable_pin: Option<(u32, u64)>,
    /// Cached pinned guard + decoded kind for the snapshot's root page. Lazy
    /// init on first `get`; reused by every subsequent `get`, skipping one
    /// buffer-pool lookup per call.
    cached_root: OnceCell<(PageGuard, NodeKind)>,
    /// Cached pinned guard + decoded kind for the catalog tree's root page.
    /// Same idea as `cached_root`, for the catalog descent path.
    cached_catalog_root: OnceCell<(PageGuard, NodeKind)>,
}

impl<'db, V: Vfs + Clone> ReadTxn<'db, V> {
    pub(crate) fn new(
        db: &'db Db<V>,
        commit_id: CommitId,
        root_page_id: u64,
        next_page_id: u64,
        catalog_root_page_id: u64,
        entry_id: u64,
    ) -> Self {
        Self {
            db,
            commit_id,
            root_page_id,
            next_page_id,
            catalog_root_page_id,
            entry_id,
            durable_pin: None,
            cached_root: OnceCell::new(),
            cached_catalog_root: OnceCell::new(),
        }
    }

    /// Record the `(pid, lease_id)` of the durable pin row created at
    /// `begin_read` time, so the pin can be deleted on drop.
    pub(crate) fn with_durable_pin(mut self, pid: u32, lease_id: u64) -> Self {
        self.durable_pin = Some((pid, lease_id));
        self
    }

    /// The `CommitId` this snapshot is pinned to.
    #[must_use]
    pub fn commit_id(&self) -> CommitId {
        self.commit_id
    }

    /// The allocation cursor at the time this snapshot was opened.
    #[must_use]
    pub fn next_page_id(&self) -> u64 {
        self.next_page_id
    }

    /// The catalog B+ tree root page id at this snapshot.
    #[must_use]
    pub fn catalog_root_page_id(&self) -> u64 {
        self.catalog_root_page_id
    }

    fn tree(&self) -> BTree<V> {
        BTree::open(
            self.db.pager.clone(),
            self.db.realm_id,
            self.root_page_id,
            self.next_page_id,
            self.db.page_size,
        )
    }

    fn catalog_tree(&self) -> BTree<V> {
        BTree::open(
            self.db.pager.clone(),
            self.db.realm_id,
            self.catalog_root_page_id,
            self.next_page_id,
            self.db.page_size,
        )
    }

    /// Check whether this reader has been aborted by the stall policy. If so,
    /// removes the abort flag (one-shot) and returns `Err(PagedbError::Aborted)`.
    fn check_abort(&self) -> Result<()> {
        if self.db.take_reader_abort(self.entry_id) {
            return Err(PagedbError::Aborted);
        }
        Ok(())
    }

    pub async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.check_abort()?;
        if self.root_page_id == 0 {
            return Ok(None);
        }
        let tree = self.tree();
        let (root_guard, root_kind) = self
            .cached_root
            .get_or_try_init(|| tree.read_node_guard(self.root_page_id))
            .await?;
        tree.get_with_cached_root(key, root_guard, *root_kind).await
    }

    pub async fn scan(&self, start: &[u8], end: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        self.check_abort()?;
        self.tree().collect_range(start, end).await
    }

    pub async fn scan_rev(&self, start: &[u8], end: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        self.check_abort()?;
        self.tree().scan_rev(start, end).await
    }

    pub async fn scan_prefix(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        self.check_abort()?;
        self.tree().scan_prefix(prefix).await
    }

    /// Open a segment by name resolved against the catalog snapshot pinned to
    /// this read transaction's commit. Unaffected by catalog mutations in
    /// subsequent commits.
    pub async fn open_segment(&self, name: &str) -> Result<SegmentReader<V>> {
        self.check_abort()?;
        if self.catalog_root_page_id == 0 {
            return Err(PagedbError::NotFound);
        }
        let tree = self.catalog_tree();
        let key = Catalog::segment_key(self.db.realm_id, name.as_bytes())?;
        let (root_guard, root_kind) = self
            .cached_catalog_root
            .get_or_try_init(|| tree.read_node_guard(self.catalog_root_page_id))
            .await?;
        let value = tree
            .get_with_cached_root(&key, root_guard, *root_kind)
            .await?
            .ok_or(PagedbError::NotFound)?;
        let meta = Catalog::decode_segment_meta(&value)?;
        let limit = u64::try_from(self.db.options.mmap_view_scratch_bytes).unwrap_or(u64::MAX);
        SegmentReader::open_internal(
            self.db.pager.clone(),
            meta,
            self.db.mmap_bytes_in_use.clone(),
            limit,
        )
        .await
    }

    /// List segments whose names start with `prefix`, resolved against the
    /// pinned catalog snapshot.
    pub async fn list_segments(&self, prefix: &str) -> Result<Vec<SegmentMeta>> {
        if self.catalog_root_page_id == 0 {
            return Ok(Vec::new());
        }
        let tree = self.catalog_tree();
        let start = Catalog::segment_key(self.db.realm_id, prefix.as_bytes())?;
        let mut end = start.clone();
        end.push(0xFF);
        let rows = tree.collect_range(&start, &end).await?;
        let mut out = Vec::with_capacity(rows.len());
        for (_k, v) in rows {
            out.push(Catalog::decode_segment_meta(&v)?);
        }
        Ok(out)
    }

    #[must_use]
    pub fn realm_id(&self) -> RealmId {
        self.db.realm_id
    }
}

impl<V: Vfs + Clone> Drop for ReadTxn<'_, V> {
    fn drop(&mut self) {
        // Remove from in-memory tracked-readers table first.
        self.db.unregister_read(self.entry_id);
        // Queue the durable pin row for deletion. The next catalog commit
        // (writer commit, gc_now, or open) will drain this queue. If this
        // process crashes before the queue is drained, the next writer open
        // will clean up stale pin rows via the catalog scan at open time.
        if let Some((pid, lease_id)) = self.durable_pin.take() {
            self.db.pending_pin_deletes.lock().push((pid, lease_id));
        }
    }
}

/// Insert a new pin row in the catalog. Called by `Db::begin_read` while
/// holding the writer lock.
pub(crate) async fn insert_pin_row<V: Vfs + Clone>(
    pin: &PinHandle<V>,
    state: &mut WriterState,
    commit_id: u64,
    root_page_id: u64,
    catalog_root_page_id: u64,
) -> Result<()> {
    let expires = unix_now_seconds() + pin.lease_seconds;
    let pv = ReaderPinValue {
        commit_id,
        root_page_id,
        catalog_root_page_id,
        free_list_root_page_id: 0,
        expires_unix_seconds: expires,
        flags: 0,
    };
    let key = Catalog::reader_pin_key(pin.pid, pin.lease_id);
    let value = Catalog::encode_reader_pin(&pv);
    catalog_micro_commit(pin, state, &key, &value).await
}

/// Delete a set of pin rows from the catalog. `pins` is a list of `(pid,
/// lease_id)` pairs. Called by `Db::drain_pending_pin_deletes`.
pub(crate) async fn delete_pin_rows<V: Vfs + Clone>(
    pin: &PinHandle<V>,
    state: &mut WriterState,
    pids_leases: &[(u32, u64)],
) -> Result<()> {
    if pids_leases.is_empty() || state.catalog_root_page_id == 0 {
        return Ok(());
    }
    let mut cat_tree = BTree::open(
        pin.pager.clone(),
        pin.realm_id,
        state.catalog_root_page_id,
        state.next_page_id,
        pin.page_size,
    );
    let mut any_deleted = false;
    for (pid, lease_id) in pids_leases {
        let key = Catalog::reader_pin_key(*pid, *lease_id);
        if cat_tree.delete(&key).await? {
            any_deleted = true;
        }
    }
    if !any_deleted {
        return Ok(());
    }
    cat_tree.flush().await?;
    let new_cat_root = cat_tree.root_page_id();
    let new_next = cat_tree.next_page_id().max(state.next_page_id);
    let new_commit_id = state.latest_commit_id + 1;
    let new_seq = state.seq + 1;
    let counter_anchor = pin.pager.pending_anchor();
    let mut catalog_root_bytes = [0u8; 16];
    catalog_root_bytes[..8].copy_from_slice(&new_cat_root.to_le_bytes());
    catalog_root_bytes[8..].copy_from_slice(&new_commit_id.to_le_bytes());
    let fields = make_header_fields(
        pin,
        state,
        new_next,
        new_commit_id,
        new_seq,
        counter_anchor,
        catalog_root_bytes,
    );
    let hk_clone = pin.hk.read().clone();
    let new_slot = crate::pager::header::commit_header(
        &*pin.vfs,
        &pin.main_db_path,
        &hk_clone,
        &fields,
        state.active_slot,
        pin.page_size,
    )
    .await?;
    pin.pager.commit_anchor(counter_anchor)?;
    state.catalog_root_page_id = new_cat_root;
    state.next_page_id = new_next;
    state.active_slot = new_slot;
    state.seq = new_seq;
    state.latest_commit_id = new_commit_id;
    pin.latest_commit.store(new_commit_id, Ordering::SeqCst);
    *pin.snapshot.write() = crate::txn::db::ReaderSnapshot {
        commit_id: state.latest_commit_id,
        root_page_id: state.root_page_id,
        next_page_id: state.next_page_id,
        catalog_root_page_id: state.catalog_root_page_id,
    };
    Ok(())
}

/// Write a single catalog key-value pair in a micro-commit: put, flush, commit header.
async fn catalog_micro_commit<V: Vfs + Clone>(
    pin: &PinHandle<V>,
    state: &mut WriterState,
    key: &[u8],
    value: &[u8],
) -> Result<()> {
    let mut cat_tree = BTree::open(
        pin.pager.clone(),
        pin.realm_id,
        state.catalog_root_page_id,
        state.next_page_id,
        pin.page_size,
    );
    cat_tree.put(key, value).await?;
    cat_tree.flush().await?;
    let new_cat_root = cat_tree.root_page_id();
    let new_next = cat_tree.next_page_id().max(state.next_page_id);
    let new_commit_id = state.latest_commit_id + 1;
    let new_seq = state.seq + 1;
    let counter_anchor = pin.pager.pending_anchor();
    let mut catalog_root_bytes = [0u8; 16];
    catalog_root_bytes[..8].copy_from_slice(&new_cat_root.to_le_bytes());
    catalog_root_bytes[8..].copy_from_slice(&new_commit_id.to_le_bytes());
    let fields = make_header_fields(
        pin,
        state,
        new_next,
        new_commit_id,
        new_seq,
        counter_anchor,
        catalog_root_bytes,
    );
    let hk_clone = pin.hk.read().clone();
    let new_slot = crate::pager::header::commit_header(
        &*pin.vfs,
        &pin.main_db_path,
        &hk_clone,
        &fields,
        state.active_slot,
        pin.page_size,
    )
    .await?;
    pin.pager.commit_anchor(counter_anchor)?;
    state.catalog_root_page_id = new_cat_root;
    state.next_page_id = new_next;
    state.active_slot = new_slot;
    state.seq = new_seq;
    state.latest_commit_id = new_commit_id;
    pin.latest_commit.store(new_commit_id, Ordering::SeqCst);
    *pin.snapshot.write() = crate::txn::db::ReaderSnapshot {
        commit_id: state.latest_commit_id,
        root_page_id: state.root_page_id,
        next_page_id: state.next_page_id,
        catalog_root_page_id: state.catalog_root_page_id,
    };
    Ok(())
}

fn make_header_fields<V: Vfs + Clone>(
    pin: &PinHandle<V>,
    state: &WriterState,
    new_next: u64,
    new_commit_id: u64,
    new_seq: u64,
    counter_anchor: u64,
    catalog_root_bytes: [u8; 16],
) -> crate::pager::structural_header::MainDbHeaderFields {
    crate::pager::structural_header::MainDbHeaderFields {
        format_version: 1,
        cipher_id: pin.cipher_id.as_byte(),
        page_size_log2: page_size_log2(pin.page_size),
        flags: 0,
        file_id: pin.file_id,
        kek_salt: pin.kek_salt,
        mk_epoch: pin.mk_epoch.load(Ordering::SeqCst),
        seq: new_seq,
        active_root_page_id: state.root_page_id,
        active_root_txn_id: state.latest_commit_id,
        counter_anchor,
        commit_id: crate::CommitId(new_commit_id),
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
    }
}

fn page_size_log2(page_size: usize) -> u8 {
    match page_size {
        8192 => 13,
        16384 => 14,
        32768 => 15,
        65536 => 16,
        _ => 12, // 4096 and any unrecognised size treated as 4096
    }
}

/// Current Unix timestamp in whole seconds. Falls back to 0 on platforms where
/// `SystemTime` is unavailable.
pub(crate) fn unix_now_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Build a `PinHandle` from `Db` fields. Helper used by `begin_read` and
/// `drain_pending_pin_deletes`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn make_pin_handle<V: Vfs + Clone>(
    pager: Arc<Pager<V>>,
    realm_id: RealmId,
    page_size: usize,
    main_db_path: String,
    vfs: Arc<V>,
    hk_snapshot: crate::crypto::keys::DerivedKey,
    mk_epoch_val: u64,
    cipher_id: crate::crypto::CipherId,
    file_id: [u8; 16],
    kek_salt: [u8; 16],
    latest_commit_val: u64,
    snapshot: Arc<parking_lot::RwLock<crate::txn::db::ReaderSnapshot>>,
    pid: u32,
    lease_id: u64,
    lease_seconds: u64,
) -> PinHandle<V> {
    PinHandle {
        pager,
        realm_id,
        page_size,
        main_db_path,
        vfs,
        hk: parking_lot::RwLock::new(hk_snapshot),
        mk_epoch: AtomicU64::new(mk_epoch_val),
        cipher_id,
        file_id,
        kek_salt,
        latest_commit: Arc::new(AtomicU64::new(latest_commit_val)),
        snapshot,
        pid,
        lease_id,
        lease_seconds,
    }
}
