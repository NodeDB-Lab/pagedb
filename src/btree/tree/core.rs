//! `BTree` — the `CoW` shadow-paging B+ tree.

use std::collections::HashMap;
use std::sync::Arc;

use crate::errors::PagedbError;
use crate::pager::format::page_kind::PageKind;
use crate::pager::{PageGuard, Pager};
use crate::vfs::Vfs;
use crate::{RealmId, Result};

use crate::btree::internal::Internal;
use crate::btree::leaf::Leaf;
use crate::btree::node::{NodeKind, body_capacity, read_header};

/// `CoW` B+ tree backed by the Pager. Single writer per instance; concurrent
/// reads through `&self`.
pub struct BTree<V: Vfs> {
    pub(super) pager: Arc<Pager<V>>,
    pub(super) realm_id: RealmId,
    pub(super) root_page_id: u64,
    pub(super) next_page_id: u64,
    pub(super) freed: Vec<u64>,
    pub(super) page_size: usize,
    /// Minimum `page_id` that may be recycled from `freed` within this session.
    /// Pages below this threshold were live in prior snapshots and may still be
    /// accessed by pinned readers; they must not be overwritten until the
    /// deferred-free queue allows it. Set to `next_page_id` when any reader is
    /// tracked; set to 0 when no readers are pinned (safe to recycle freely).
    pub(super) reuse_threshold: u64,
    /// Leaves modified during this write session but not yet promoted via
    /// `CoW` to a fresh page. Keyed by the leaf's current `page_id` as referenced
    /// by the tree spine. All mutations happen in place; encode + spine
    /// redirect happens in batch at [`flush`](Self::flush). Splits are
    /// flushed eagerly (they alter the tree shape and must propagate up).
    pub(super) dirty_leaves: HashMap<u64, Leaf>,
    /// Old leaf `page_ids` that have been pulled into [`Self::dirty_leaves`] but
    /// not yet replaced by a fresh `CoW` page. These pages will be freed at
    /// flush time; [`Self::drain_freed`] reports them now so the deferred-free
    /// queue (and the reader stall policy) sees an accurate page count
    /// *before* `flush()` runs.
    pub(super) scheduled_frees: Vec<u64>,
    /// For each dirty leaf, the path of internal `page_ids` from the root down
    /// to (but not including) the leaf. Captured at first-touch so flush can
    /// walk only the affected spine instead of scanning the whole tree.
    pub(super) dirty_parent_paths: HashMap<u64, Vec<u64>>,
    /// Leaves produced by splits during this write session. Keyed by the
    /// **fresh** `page_id` they will occupy on disk. Unlike `dirty_leaves`,
    /// no `CoW` is needed at flush time — they're already pinned to fresh
    /// page ids on a `CoW`'d spine. Encode + pager write happens at flush so
    /// the encode work batches with the rest and lands in the pager's
    /// parallel-AEAD flush. In-place mutation by subsequent puts targeting
    /// the same leaf is allowed; no further allocation needed.
    pub(super) fresh_leaves: HashMap<u64, Leaf>,
    /// Cross-commit pool of reusable page IDs, shared (via `Arc`) across the
    /// main, catalog, and history `BTree`s of one `Db`. Allocation pops from
    /// here before bumping `next_page_id`, recycling pages freed by earlier
    /// commits (once no reader or retained-history root can observe them) so
    /// the file stays bounded under sustained writes. `None` for callers that
    /// haven't wired a shared cache (e.g. compaction's repack trees), which
    /// keep bump-only allocation.
    pub(super) free_page_cache: Option<Arc<parking_lot::Mutex<Vec<u64>>>>,
    /// Sink recording page ids drawn from `free_page_cache` and reused this
    /// session. The commit path removes them from the durable free-list (they
    /// now hold live committed data). Shared (via `Arc`) across the txn's trees.
    pub(super) free_page_consumed: Option<Arc<parking_lot::Mutex<Vec<u64>>>>,
    /// Last key successfully appended via [`Self::put_append`]. Used to
    /// enforce the monotonic-key invariant on subsequent calls and to
    /// invalidate the cached path when any non-append mutation (regular
    /// `put`, `delete`) runs.
    pub(super) append_last_key: Option<Vec<u8>>,
    /// Cached path from the root to the rightmost leaf, populated lazily
    /// by [`Self::put_append`] on the first call after invalidation. While
    /// `Some`, subsequent monotonic `put_append` calls skip the
    /// `path_to_leaf_for_key` descent and go straight to
    /// [`Self::put_at_path`]. Invalidated by any split, any regular `put`,
    /// any `delete`, and when the txn opens.
    pub(super) append_cached_path: Option<Vec<u64>>,
}

impl<V: Vfs> BTree<V> {
    pub fn open(
        pager: Arc<Pager<V>>,
        realm_id: RealmId,
        root_page_id: u64,
        next_page_id: u64,
        page_size: usize,
    ) -> Self {
        let next = next_page_id.max(4);
        Self {
            pager,
            realm_id,
            root_page_id,
            next_page_id: next,
            freed: Vec::new(),
            page_size,
            reuse_threshold: 0,
            dirty_leaves: HashMap::new(),
            scheduled_frees: Vec::new(),
            dirty_parent_paths: HashMap::new(),
            fresh_leaves: HashMap::new(),
            free_page_cache: None,
            free_page_consumed: None,
            append_last_key: None,
            append_cached_path: None,
        }
    }

    /// Set the reuse threshold. Any freed page with `page_id < threshold` will
    /// not be recycled within this session; it goes to `self.freed` for later
    /// deferred-queue promotion. Call with `next_page_id` when tracked readers
    /// are present; call with `0` when no readers are pinned.
    pub fn set_reuse_threshold(&mut self, threshold: u64) {
        self.reuse_threshold = threshold;
    }

    /// Wire in the `Db`'s shared free-page cache. After this call,
    /// `allocate_page` pops from the shared pool before bumping `next_page_id`.
    /// The pool is loaded at `begin_write` with the durable free-list's
    /// floor-safe pages, so recycling from it is always snapshot-safe.
    pub fn set_free_page_cache(&mut self, cache: Arc<parking_lot::Mutex<Vec<u64>>>) {
        self.free_page_cache = Some(cache);
    }

    /// Wire the shared sink that records cache pages reused this session, so the
    /// commit path can remove them from the durable free-list. Set alongside
    /// [`Self::set_free_page_cache`].
    pub fn set_free_page_consumed(&mut self, consumed: Arc<parking_lot::Mutex<Vec<u64>>>) {
        self.free_page_consumed = Some(consumed);
    }

    #[must_use]
    pub fn root_page_id(&self) -> u64 {
        self.root_page_id
    }

    #[must_use]
    pub fn next_page_id(&self) -> u64 {
        self.next_page_id
    }

    /// Advance the allocation cursor to at least `value`. No-op if the current
    /// cursor is already at or beyond `value`. Used to synchronise the shared
    /// page-id space between two trees that allocate from the same namespace.
    pub fn set_next_page_id(&mut self, value: u64) {
        if value > self.next_page_id {
            self.next_page_id = value;
        }
    }

    pub(super) fn allocate_page(&mut self) -> u64 {
        // First, recycle a page freed earlier *in this same session*, gated by
        // the reuse threshold: a page below it may still be live in a pinned
        // reader's snapshot, so it can't be reused until the durable free-list
        // clears it (it leaves via `drain_freed` at commit instead).
        if self.reuse_threshold == 0 {
            if let Some(id) = self.freed.pop() {
                return id;
            }
        } else if let Some(pos) = self
            .freed
            .iter()
            .rposition(|&id| id >= self.reuse_threshold)
        {
            return self.freed.remove(pos);
        }
        // Then draw from the shared cross-commit cache. It is loaded at txn
        // begin with *only* free-list pages below the reclamation floor — pages
        // no live reader and no retained-history root can observe — so reusing
        // them is safe regardless of `reuse_threshold`. Record each draw so the
        // commit path removes it from the durable free-list.
        if let Some(cache) = &self.free_page_cache {
            if let Some(id) = cache.lock().pop() {
                if let Some(consumed) = &self.free_page_consumed {
                    consumed.lock().push(id);
                }
                return id;
            }
        }
        let id = self.next_page_id;
        self.next_page_id += 1;
        id
    }

    pub(super) fn free_page(&mut self, page_id: u64) {
        self.freed.push(page_id);
    }

    pub(super) async fn read_node_kind(&self, page_id: u64) -> Result<NodeKind> {
        let (_g, kind) = self.read_node_guard(page_id).await?;
        Ok(kind)
    }

    /// Read a B+ tree node page without knowing its kind in advance. Tries
    /// the Leaf AAD first; on AEAD mismatch (= page is actually Internal)
    /// retries with the Internal AAD. Returns the pinned page guard and the
    /// decoded kind so the caller can build the matching accessor on
    /// borrowed bytes without a second cache lookup.
    pub(crate) async fn read_node_guard(&self, page_id: u64) -> Result<(PageGuard, NodeKind)> {
        match self
            .pager
            .read_main_page(page_id, self.realm_id, PageKind::BTreeLeaf)
            .await
        {
            Ok(g) => {
                let kind = read_header(g.body_ref())?.kind;
                Ok((g, kind))
            }
            Err(PagedbError::ChecksumFailure) => {
                let g = self
                    .pager
                    .read_main_page(page_id, self.realm_id, PageKind::BTreeInternal)
                    .await?;
                let kind = read_header(g.body_ref())?.kind;
                Ok((g, kind))
            }
            Err(e) => Err(e),
        }
    }

    pub(super) async fn read_leaf(&self, page_id: u64) -> Result<Leaf> {
        // Shadowing rule: if the txn has a dirty or fresh in-memory copy of
        // this leaf, reads must observe it (read-your-own-writes within the
        // txn).
        if let Some(leaf) = self.fresh_leaves.get(&page_id) {
            return Ok(leaf.clone());
        }
        if let Some(leaf) = self.dirty_leaves.get(&page_id) {
            return Ok(leaf.clone());
        }
        let guard = self
            .pager
            .read_main_page(page_id, self.realm_id, PageKind::BTreeLeaf)
            .await?;
        let body = guard.body();
        Leaf::decode(&body)
    }

    /// Decode the leaf at `page_id` directly from the buffer pool, bypassing
    /// the dirty-leaf cache. Used when transitioning a leaf into the cache for
    /// the first time in a write txn.
    pub(super) async fn decode_leaf_from_pager(&self, page_id: u64) -> Result<Leaf> {
        let guard = self
            .pager
            .read_main_page(page_id, self.realm_id, PageKind::BTreeLeaf)
            .await?;
        Leaf::decode(guard.body_ref())
    }

    pub(super) async fn read_internal(&self, page_id: u64) -> Result<Internal> {
        let guard = self
            .pager
            .read_main_page(page_id, self.realm_id, PageKind::BTreeInternal)
            .await?;
        let body = guard.body();
        Internal::decode(&body)
    }

    pub(super) async fn write_leaf(&self, page_id: u64, leaf: &Leaf) -> Result<()> {
        let mut body = vec![0u8; body_capacity(self.page_size)];
        leaf.encode(&mut body)?;
        self.pager
            .write_main_page(page_id, self.realm_id, PageKind::BTreeLeaf, &body)
            .await
    }

    pub(super) async fn write_internal(&self, page_id: u64, internal: &Internal) -> Result<()> {
        let mut body = vec![0u8; body_capacity(self.page_size)];
        internal.encode(&mut body)?;
        self.pager
            .write_main_page(page_id, self.realm_id, PageKind::BTreeInternal, &body)
            .await
    }
}
