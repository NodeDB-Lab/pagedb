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
    /// Cross-commit pool of pre-vetted reusable page IDs, shared (via `Arc`)
    /// across all `BTree`s opened by the same `Db`. Allocation pops from
    /// here before bumping `next_page_id`, keeping the file size bounded
    /// when `OpenOptions::skip_freelist_persistence_when_no_readers` orphans
    /// would otherwise accumulate. `None` for callers that haven't wired a
    /// shared cache (compaction, history tree) — those keep bump-only
    /// allocation.
    pub(super) free_page_cache: Option<Arc<parking_lot::Mutex<Vec<u64>>>>,
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
    /// `allocate_page` will pop from the shared pool before bumping
    /// `next_page_id`. Pages pushed into the pool by an earlier writer
    /// commit (via [`Self::push_to_shared_cache`]) become reusable here.
    pub fn set_free_page_cache(&mut self, cache: Arc<parking_lot::Mutex<Vec<u64>>>) {
        self.free_page_cache = Some(cache);
    }

    /// Push `page_ids` into the shared free-page cache, if one is wired.
    /// Used by the writer commit path when the no-reader fast-free option
    /// is active: instead of orphaning freed pages, hand them to the next
    /// txn's allocator.
    pub fn push_to_shared_cache(&self, page_ids: &[u64]) {
        if let Some(cache) = &self.free_page_cache {
            let mut guard = cache.lock();
            guard.extend(page_ids.iter().copied());
        }
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
        // Reuse a freed page only if it is at or above the reuse threshold.
        // Pages below the threshold may still be live in pinned reader snapshots.
        if self.reuse_threshold == 0 {
            // No readers pinned: recycle freely.
            if let Some(id) = self.freed.pop() {
                return id;
            }
            // Consult the cross-commit shared cache (pages handed off by
            // earlier writer commits under the no-reader fast-free option).
            // Only safe to draw from this when no readers are pinned — the
            // cache contract is "always safe to immediately reuse."
            if let Some(cache) = &self.free_page_cache {
                if let Some(id) = cache.lock().pop() {
                    return id;
                }
            }
        } else {
            // Readers pinned: only recycle pages that were allocated during
            // this session (>= reuse_threshold) and thus cannot be in any
            // prior snapshot. The shared cache is bypassed here because
            // pages in it predate this session and may be visible to a
            // pinned reader at an older commit.
            if let Some(pos) = self
                .freed
                .iter()
                .rposition(|&id| id >= self.reuse_threshold)
            {
                let id = self.freed.remove(pos);
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
