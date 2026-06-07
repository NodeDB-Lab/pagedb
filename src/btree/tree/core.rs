//! `BTree` — the `CoW` shadow-paging B+ tree.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use crate::errors::PagedbError;
use crate::pager::format::page_kind::PageKind;
use crate::pager::{PageGuard, Pager};
use crate::vfs::Vfs;
use crate::{RealmId, Result};

use super::internal::{Internal, InternalAccessor, InternalEntry};
use super::leaf::{Leaf, LeafAccessor, LeafValue, LeafValueRef};
use super::node::{NodeKind, body_capacity, read_header};
use super::overflow;
use super::split::{split_internal, split_leaf};

/// `CoW` B+ tree backed by the Pager. Single writer per instance; concurrent
/// reads through `&self`.
pub struct BTree<V: Vfs> {
    pager: Arc<Pager<V>>,
    realm_id: RealmId,
    root_page_id: u64,
    next_page_id: u64,
    freed: Vec<u64>,
    page_size: usize,
    /// Minimum `page_id` that may be recycled from `freed` within this session.
    /// Pages below this threshold were live in prior snapshots and may still be
    /// accessed by pinned readers; they must not be overwritten until the
    /// deferred-free queue allows it. Set to `next_page_id` when any reader is
    /// tracked; set to 0 when no readers are pinned (safe to recycle freely).
    reuse_threshold: u64,
    /// Leaves modified during this write session but not yet promoted via
    /// `CoW` to a fresh page. Keyed by the leaf's current `page_id` as referenced
    /// by the tree spine. All mutations happen in place; encode + spine
    /// redirect happens in batch at [`flush`](Self::flush). Splits are
    /// flushed eagerly (they alter the tree shape and must propagate up).
    dirty_leaves: HashMap<u64, Leaf>,
    /// Old leaf `page_ids` that have been pulled into [`Self::dirty_leaves`] but
    /// not yet replaced by a fresh `CoW` page. These pages will be freed at
    /// flush time; [`Self::drain_freed`] reports them now so the deferred-free
    /// queue (and the reader stall policy) sees an accurate page count
    /// *before* `flush()` runs.
    scheduled_frees: Vec<u64>,
    /// For each dirty leaf, the path of internal `page_ids` from the root down
    /// to (but not including) the leaf. Captured at first-touch so flush can
    /// walk only the affected spine instead of scanning the whole tree.
    dirty_parent_paths: HashMap<u64, Vec<u64>>,
    /// Leaves produced by splits during this write session. Keyed by the
    /// **fresh** `page_id` they will occupy on disk. Unlike `dirty_leaves`,
    /// no `CoW` is needed at flush time — they're already pinned to fresh
    /// page ids on a `CoW`'d spine. Encode + pager write happens at flush so
    /// the encode work batches with the rest and lands in the pager's
    /// parallel-AEAD flush. In-place mutation by subsequent puts targeting
    /// the same leaf is allowed; no further allocation needed.
    fresh_leaves: HashMap<u64, Leaf>,
    /// Cross-commit pool of pre-vetted reusable page IDs, shared (via `Arc`)
    /// across all `BTree`s opened by the same `Db`. Allocation pops from
    /// here before bumping `next_page_id`, keeping the file size bounded
    /// when `OpenOptions::skip_freelist_persistence_when_no_readers` orphans
    /// would otherwise accumulate. `None` for callers that haven't wired a
    /// shared cache (compaction, history tree) — those keep bump-only
    /// allocation.
    free_page_cache: Option<Arc<parking_lot::Mutex<Vec<u64>>>>,
    /// Last key successfully appended via [`Self::put_append`]. Used to
    /// enforce the monotonic-key invariant on subsequent calls and to
    /// invalidate the cached path when any non-append mutation (regular
    /// `put`, `delete`) runs.
    append_last_key: Option<Vec<u8>>,
    /// Cached path from the root to the rightmost leaf, populated lazily
    /// by [`Self::put_append`] on the first call after invalidation. While
    /// `Some`, subsequent monotonic `put_append` calls skip the
    /// `path_to_leaf_for_key` descent and go straight to
    /// [`Self::put_at_path`]. Invalidated by any split, any regular `put`,
    /// any `delete`, and when the txn opens.
    append_cached_path: Option<Vec<u64>>,
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

    fn allocate_page(&mut self) -> u64 {
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

    fn free_page(&mut self, page_id: u64) {
        self.freed.push(page_id);
    }

    async fn read_node_kind(&self, page_id: u64) -> Result<NodeKind> {
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

    async fn read_leaf(&self, page_id: u64) -> Result<Leaf> {
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
    async fn decode_leaf_from_pager(&self, page_id: u64) -> Result<Leaf> {
        let guard = self
            .pager
            .read_main_page(page_id, self.realm_id, PageKind::BTreeLeaf)
            .await?;
        Leaf::decode(guard.body_ref())
    }

    async fn read_internal(&self, page_id: u64) -> Result<Internal> {
        let guard = self
            .pager
            .read_main_page(page_id, self.realm_id, PageKind::BTreeInternal)
            .await?;
        let body = guard.body();
        Internal::decode(&body)
    }

    async fn write_leaf(&self, page_id: u64, leaf: &Leaf) -> Result<()> {
        let mut body = vec![0u8; body_capacity(self.page_size)];
        leaf.encode(&mut body)?;
        self.pager
            .write_main_page(page_id, self.realm_id, PageKind::BTreeLeaf, &body)
            .await
    }

    async fn write_internal(&self, page_id: u64, internal: &Internal) -> Result<()> {
        let mut body = vec![0u8; body_capacity(self.page_size)];
        internal.encode(&mut body)?;
        self.pager
            .write_main_page(page_id, self.realm_id, PageKind::BTreeInternal, &body)
            .await
    }

    /// Get a value by key. Returns `None` if not found.
    ///
    /// Zero-allocation tree descent: each level reads the page through a
    /// [`PageGuard`], builds a borrowed accessor over the decrypted body, and
    /// either descends or extracts the value. The only allocation on the hit
    /// path is the final owned `Vec<u8>` copy of the inline value (or the
    /// overflow chain reassembly for large values).
    pub async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        if self.root_page_id == 0 {
            return Ok(None);
        }
        // Root could itself be a fresh leaf (single-leaf tree mutated in
        // this txn). Pull the value from the cache instead of the pager.
        if let Some(leaf) = self.fresh_leaves.get(&self.root_page_id) {
            return Self::value_from_cached_leaf(&self.pager, self.realm_id, leaf, key).await;
        }
        let (root_guard, root_kind) = self.read_node_guard(self.root_page_id).await?;
        self.get_from_node(key, self.root_page_id, &root_guard, root_kind)
            .await
    }

    /// Resolve `key` against an in-memory `Leaf` (from `fresh_leaves` /
    /// `dirty_leaves`), following any overflow chain via the pager.
    async fn value_from_cached_leaf(
        pager: &Arc<Pager<V>>,
        realm_id: RealmId,
        leaf: &Leaf,
        key: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        match leaf.get(key) {
            None => Ok(None),
            Some(LeafValue::Inline(v)) => Ok(Some(v.clone())),
            Some(LeafValue::Overflow {
                total_len,
                root_page_id,
            }) => {
                let v = overflow::read_chain(pager, realm_id, *root_page_id, *total_len).await?;
                Ok(Some(v))
            }
        }
    }

    /// Variant of [`get`](Self::get) that takes a caller-owned, already-pinned
    /// root [`PageGuard`]. Lets read transactions cache the root for the
    /// lifetime of the txn so subsequent gets skip the root cache lookup.
    pub async fn get_with_cached_root(
        &self,
        key: &[u8],
        root_guard: &PageGuard,
        root_kind: NodeKind,
    ) -> Result<Option<Vec<u8>>> {
        if self.root_page_id == 0 {
            return Ok(None);
        }
        self.get_from_node(key, self.root_page_id, root_guard, root_kind)
            .await
    }

    /// Descend from `start_guard` (the page at `start_page_id`) toward a
    /// leaf, extracting the value at `key` if present. Consults the
    /// dirty-leaf cache at the leaf level — within a write txn, leaves
    /// mutated by `put`/`delete` shadow the buffer-pool bytes.
    async fn get_from_node(
        &self,
        key: &[u8],
        start_page_id: u64,
        start_guard: &PageGuard,
        start_kind: NodeKind,
    ) -> Result<Option<Vec<u8>>> {
        // Handle the first level using the borrowed guard.
        let next_page_id = match start_kind {
            NodeKind::Leaf => {
                return self
                    .extract_leaf_value(key, start_page_id, start_guard)
                    .await;
            }
            NodeKind::Internal => InternalAccessor::new(start_guard.body_ref())?.child_for(key),
        };
        // Descend from the first child onward. Subsequent guards are owned.
        let mut page_id = next_page_id;
        loop {
            // Fresh-from-split leaves only live in `fresh_leaves` until
            // flush. If the next child is one, resolve from cache.
            if let Some(leaf) = self.fresh_leaves.get(&page_id) {
                return Self::value_from_cached_leaf(&self.pager, self.realm_id, leaf, key).await;
            }
            let (guard, kind) = self.read_node_guard(page_id).await?;
            match kind {
                NodeKind::Leaf => return self.extract_leaf_value(key, page_id, &guard).await,
                NodeKind::Internal => {
                    let next = InternalAccessor::new(guard.body_ref())?.child_for(key);
                    drop(guard);
                    page_id = next;
                }
            }
        }
    }

    async fn extract_leaf_value(
        &self,
        key: &[u8],
        leaf_page_id: u64,
        leaf_guard: &PageGuard,
    ) -> Result<Option<Vec<u8>>> {
        // Within a write txn, the dirty + fresh caches shadow the buffer-pool
        // bytes. The cached decoded form is the source of truth for any leaf
        // they hold.
        if let Some(leaf) = self
            .fresh_leaves
            .get(&leaf_page_id)
            .or_else(|| self.dirty_leaves.get(&leaf_page_id))
        {
            return match leaf.get(key) {
                None => Ok(None),
                Some(LeafValue::Inline(v)) => Ok(Some(v.clone())),
                Some(LeafValue::Overflow {
                    total_len,
                    root_page_id,
                }) => {
                    let v =
                        overflow::read_chain(&self.pager, self.realm_id, *root_page_id, *total_len)
                            .await?;
                    Ok(Some(v))
                }
            };
        }
        let leaf = LeafAccessor::new(leaf_guard.body_ref())?;
        let Some(idx) = leaf.find(key) else {
            return Ok(None);
        };
        match leaf.value_at(idx)? {
            LeafValueRef::Inline(v) => Ok(Some(v.to_vec())),
            LeafValueRef::Overflow {
                total_len,
                root_page_id,
            } => {
                let v = overflow::read_chain(&self.pager, self.realm_id, root_page_id, total_len)
                    .await?;
                Ok(Some(v))
            }
        }
    }

    /// Insert or overwrite a key-value pair.
    pub async fn put(&mut self, key: &[u8], value: &[u8]) -> Result<()> {
        // Build the leaf value — inline if small enough, overflow chain otherwise.
        let leaf_value = if value.len() > self.page_size / 4 {
            let realm = self.realm_id;
            let ps = self.page_size;
            let pager = Arc::clone(&self.pager);
            let root_id =
                overflow::write_chain(&pager, realm, value, ps, &mut || self.allocate_page())
                    .await?;
            LeafValue::Overflow {
                total_len: value.len() as u64,
                root_page_id: root_id,
            }
        } else {
            LeafValue::Inline(value.to_vec())
        };

        if self.root_page_id == 0 {
            let new_root = self.allocate_page();
            let mut leaf = Leaf::new();
            leaf.upsert(key, leaf_value);
            // Write directly to the pager so the empty-tree root is visible
            // to subsequent reads. Future puts on this leaf pull it through
            // the dirty cache on first touch (see `ensure_leaf_dirty`).
            self.write_leaf(new_root, &leaf).await?;
            self.root_page_id = new_root;
            // Any cached append path is now stale (root changed).
            self.append_cached_path = None;
            return Ok(());
        }

        // Descend to find the leaf page_id. Returns the path; we'll fetch the
        // leaf via the dirty-cache-aware helper below.
        let path = self.path_to_leaf_for_key(key).await?;
        // Regular `put` invalidates the append cache — caller may have
        // mutated keys that aren't in monotonic order vs the cache.
        self.append_cached_path = None;
        self.append_last_key = None;
        let _split = self.put_at_path(path, key, leaf_value).await?;
        Ok(())
    }

    /// Insert `(key, leaf_value)` using a pre-computed `path` from the root
    /// to the target leaf. Returns `true` if the operation triggered a leaf
    /// split (in which case `path` is now stale and the caller must
    /// discard any cached version of it).
    ///
    /// Callers MUST guarantee `path` is currently valid — i.e. all
    /// internal-node `page_id`s along it still point at the same children
    /// they did at descent time, and the terminal leaf at `path[-1]` still
    /// holds the records that would receive `key`. The hot path of
    /// `put_append` exploits this to skip a full `path_to_leaf_for_key`
    /// descent on monotonic-key workloads.
    async fn put_at_path(
        &mut self,
        path: Vec<u64>,
        key: &[u8],
        leaf_value: LeafValue,
    ) -> Result<bool> {
        let leaf_page_id = *path.last().expect("non-empty path");

        // Two cases:
        // (1) leaf is in `fresh_leaves` — it was created by an earlier split
        //     during this txn. It's already on a fresh page id; mutate in
        //     place, no `CoW`.
        // (2) otherwise — pull through the dirty-leaf cache as usual.
        let leaf_is_fresh = self.fresh_leaves.contains_key(&leaf_page_id);
        if !leaf_is_fresh {
            self.ensure_leaf_dirty(leaf_page_id, &path).await?;
        }

        let leaf: &mut Leaf = if leaf_is_fresh {
            self.fresh_leaves
                .get_mut(&leaf_page_id)
                .expect("fresh_leaves contains key")
        } else {
            self.dirty_leaves
                .get_mut(&leaf_page_id)
                .expect("ensure_leaf_dirty populated")
        };

        let monotonic = leaf.records.last().is_some_and(|(k, _)| key > k.as_slice())
            && !leaf.records.iter().any(|(k, _)| k.as_slice() == key);

        let (_is_new, old_value) = leaf.upsert(key, leaf_value);
        let fits = leaf.fits(self.page_size);

        // Free old overflow chain if a record was replaced (refcount-aware).
        if let Some(LeafValue::Overflow {
            root_page_id: old_root,
            ..
        }) = old_value
        {
            let new_cow_page = self.allocate_page();
            match overflow::release(&self.pager, self.realm_id, old_root, new_cow_page).await? {
                overflow::ReleaseResult::Freed { freed_pages } => {
                    for pid in freed_pages {
                        self.free_page(pid);
                    }
                    self.free_page(new_cow_page);
                }
                overflow::ReleaseResult::Decremented {
                    new_root_page_id: _,
                } => {
                    self.free_page(old_root);
                }
            }
        }

        if fits {
            // Stay in the dirty cache. No allocate_page, no spine update,
            // no encode. The flush() pass batches all of that.
            return Ok(false);
        }

        // Split path: leaf overflowed. Pull it out of whichever cache it
        // lives in, split into two fresh pages, propagate the new separator
        // up the spine, and stash both halves in `fresh_leaves` for encoding
        // at flush time.
        let leaf = if leaf_is_fresh {
            self.fresh_leaves
                .remove(&leaf_page_id)
                .expect("fresh before split")
        } else {
            // The leaf was scheduled for freeing when it entered the dirty
            // cache; remove it from that list since the split path takes
            // over the free.
            if let Some(pos) = self.scheduled_frees.iter().position(|&p| p == leaf_page_id) {
                self.scheduled_frees.swap_remove(pos);
            }
            self.dirty_parent_paths.remove(&leaf_page_id);
            self.dirty_leaves
                .remove(&leaf_page_id)
                .expect("dirty before split")
        };
        let new_leaf_page = self.allocate_page();
        let (mut left, mut right, sep_key) = split_leaf(leaf, monotonic, self.page_size);
        let right_page = self.allocate_page();
        left.left_sibling = 0;
        left.right_sibling = 0;
        right.left_sibling = 0;
        right.right_sibling = 0;
        // Defer encode + pager write until flush. Both halves are pinned to
        // fresh page ids; no further CoW or spine fix-up is required.
        self.fresh_leaves.insert(new_leaf_page, left);
        self.fresh_leaves.insert(right_page, right);
        self.free_page(leaf_page_id);
        self.propagate_split_up(path, new_leaf_page, right_page, sep_key)
            .await?;
        Ok(true)
    }

    /// Append a key-value pair under the monotonic-key invariant. Subsequent
    /// monotonic calls skip the `path_to_leaf_for_key` descent by reusing
    /// the cached rightmost path; only splits and explicitly-invalidating
    /// operations (regular `put`/`delete`) force a re-descent.
    ///
    /// # Errors
    ///
    /// Returns [`PagedbError::AppendNotMonotonic`] if `key` is not strictly
    /// greater than the previously-appended key in this `BTree` session.
    /// Intended for op-logs, time-series indexes, FTS posting-list builds —
    /// any workload where the embedder can guarantee monotonic-key insert.
    pub async fn put_append(&mut self, key: &[u8], value: &[u8]) -> Result<()> {
        // Monotonic invariant: strictly greater than the last appended key.
        if let Some(last) = &self.append_last_key {
            if key <= last.as_slice() {
                return Err(PagedbError::AppendNotMonotonic);
            }
        }

        // Empty tree: delegate to the regular `put` path, which initializes
        // the root and writes the first leaf. After it returns, seed the
        // append cache with the new key.
        if self.root_page_id == 0 {
            self.put(key, value).await?;
            self.append_last_key = Some(key.to_vec());
            // The cached path needs a real descent on the next call.
            return Ok(());
        }

        // Build the leaf value (inline or overflow).
        let leaf_value = if value.len() > self.page_size / 4 {
            let realm = self.realm_id;
            let ps = self.page_size;
            let pager = Arc::clone(&self.pager);
            let root_id =
                overflow::write_chain(&pager, realm, value, ps, &mut || self.allocate_page())
                    .await?;
            LeafValue::Overflow {
                total_len: value.len() as u64,
                root_page_id: root_id,
            }
        } else {
            LeafValue::Inline(value.to_vec())
        };

        // Fast path: cached rightmost path is valid → skip descent.
        let path = if let Some(cached) = self.append_cached_path.take() {
            cached
        } else {
            self.path_to_rightmost_leaf().await?
        };
        let path_for_retry = path.clone();
        let split = self.put_at_path(path, key, leaf_value).await?;
        self.append_last_key = Some(key.to_vec());
        if split {
            // Split rewrote the rightmost leaf into two new leaves and
            // possibly CoW'd the spine. The cached path is stale.
            // Re-establish on next call via a fresh `path_to_rightmost_leaf`.
            self.append_cached_path = None;
        } else {
            self.append_cached_path = Some(path_for_retry);
        }
        Ok(())
    }

    /// Descend from the root taking the rightmost child at every internal
    /// node. Returns the path (internal `page_ids` followed by the rightmost
    /// leaf `page_id`). Used by [`Self::put_append`] to seed the cached
    /// path after invalidation.
    async fn path_to_rightmost_leaf(&self) -> Result<Vec<u64>> {
        let mut path = Vec::new();
        let mut page_id = self.root_page_id;
        loop {
            path.push(page_id);
            // Fresh-from-split leaves only live in `fresh_leaves`.
            if self.fresh_leaves.contains_key(&page_id) {
                return Ok(path);
            }
            let (guard, kind) = self.read_node_guard(page_id).await?;
            if kind == NodeKind::Leaf {
                return Ok(path);
            }
            let internal = Internal::decode(guard.body_ref())?;
            drop(guard);
            // Rightmost child of an internal node: the last entry's
            // `right_child`, or `leftmost_child` if the entries list is empty.
            page_id = internal
                .entries
                .last()
                .map_or(internal.leftmost_child, |e| e.right_child);
        }
    }

    /// Pull `page_id`'s leaf into [`Self::dirty_leaves`] if not already there.
    /// Decodes from the pager on first touch; subsequent calls are no-ops.
    /// On first touch also (a) schedules `page_id` for freeing and (b) records
    /// the leaf's spine path so flush can `CoW` only the affected internals.
    /// `path` ends at `page_id` (the leaf); the internals are `path[..len-1]`.
    async fn ensure_leaf_dirty(&mut self, page_id: u64, path: &[u64]) -> Result<()> {
        if self.dirty_leaves.contains_key(&page_id) {
            return Ok(());
        }
        let leaf = self.decode_leaf_from_pager(page_id).await?;
        self.dirty_leaves.insert(page_id, leaf);
        self.scheduled_frees.push(page_id);
        let parent_chain = if path.len() <= 1 {
            Vec::new()
        } else {
            path[..path.len() - 1].to_vec()
        };
        self.dirty_parent_paths.insert(page_id, parent_chain);
        Ok(())
    }

    /// Delete a key. Returns `true` if the key was present.
    pub async fn delete(&mut self, key: &[u8]) -> Result<bool> {
        // `delete` may have removed the previously-appended max, so the
        // monotonic invariant on `put_append` can no longer be enforced
        // against `append_last_key`. Reset the append state.
        self.append_cached_path = None;
        self.append_last_key = None;
        if self.root_page_id == 0 {
            return Ok(false);
        }
        let path = self.path_to_leaf_for_key(key).await?;
        let leaf_page_id = *path.last().expect("non-empty path");
        let leaf_is_fresh = self.fresh_leaves.contains_key(&leaf_page_id);
        if !leaf_is_fresh {
            self.ensure_leaf_dirty(leaf_page_id, &path).await?;
        }
        let removed = if leaf_is_fresh {
            self.fresh_leaves
                .get_mut(&leaf_page_id)
                .expect("fresh contains key")
                .remove(key)
        } else {
            self.dirty_leaves
                .get_mut(&leaf_page_id)
                .expect("dirty after ensure")
                .remove(key)
        };
        match removed {
            None => return Ok(false),
            Some(LeafValue::Overflow {
                root_page_id: old_root,
                ..
            }) => {
                let new_cow_page = self.allocate_page();
                match overflow::release(&self.pager, self.realm_id, old_root, new_cow_page).await? {
                    overflow::ReleaseResult::Freed { freed_pages } => {
                        for pid in freed_pages {
                            self.free_page(pid);
                        }
                        self.free_page(new_cow_page);
                    }
                    overflow::ReleaseResult::Decremented {
                        new_root_page_id: _,
                    } => {
                        self.free_page(old_root);
                    }
                }
            }
            Some(LeafValue::Inline(_)) => {}
        }
        // Leaf stays in dirty cache; flush() materializes it.
        Ok(true)
    }

    // ─── Navigation helpers ──────────────────────────────────────────────────

    /// Given an internal node and a child `page_id`, return the `page_id` of the
    /// NEXT child (to the right), or `None` if `child` is the rightmost. Used by
    /// the parent-mediated scan in [`next_leaf_after`](Self::next_leaf_after).
    fn right_sibling_child(internal: &Internal, child: u64) -> Option<u64> {
        if internal.leftmost_child == child {
            return internal.entries.first().map(|e| e.right_child);
        }
        for (i, e) in internal.entries.iter().enumerate() {
            if e.right_child == child {
                return internal.entries.get(i + 1).map(|ne| ne.right_child);
            }
        }
        None
    }

    // ─── Spine propagation ───────────────────────────────────────────────────

    async fn propagate_split_up(
        &mut self,
        path: Vec<u64>,
        new_left_child: u64,
        new_right_child: u64,
        promoted_key: Vec<u8>,
    ) -> Result<()> {
        let mut child_old = *path.last().expect("non-empty path");
        let mut left_replacement = new_left_child;
        let mut sep_to_insert = promoted_key;
        let mut right_to_insert = new_right_child;
        let mut levels_remaining = path.len() - 1;

        loop {
            if levels_remaining == 0 {
                let new_root_page = self.allocate_page();
                let internal = Internal {
                    leftmost_child: left_replacement,
                    entries: vec![InternalEntry {
                        key: sep_to_insert,
                        right_child: right_to_insert,
                    }],
                };
                self.write_internal(new_root_page, &internal).await?;
                self.root_page_id = new_root_page;
                return Ok(());
            }

            let internal_page = path[levels_remaining - 1];
            let mut internal = self.read_internal(internal_page).await?;

            if internal.leftmost_child == child_old {
                internal.leftmost_child = left_replacement;
            } else {
                for e in &mut internal.entries {
                    if e.right_child == child_old {
                        e.right_child = left_replacement;
                        break;
                    }
                }
            }
            internal.upsert(&sep_to_insert, right_to_insert);

            let new_internal_page = self.allocate_page();
            if !internal.fits(self.page_size) {
                let (left, right, promoted) = split_internal(internal);
                let right_internal_page = self.allocate_page();
                self.write_internal(new_internal_page, &left).await?;
                self.write_internal(right_internal_page, &right).await?;
                self.free_page(internal_page);
                // An internal page that other dirty leaves' parent paths
                // reference has been replaced and freed; remap them. The
                // split case promotes the old internal: keys ≤ promoted live
                // on `new_internal_page`, the rest on `right_internal_page`.
                // For path-remapping (used only to find ancestors to CoW)
                // either replacement is acceptable, so substitute with the
                // left replacement.
                self.remap_dirty_parent_paths(internal_page, new_internal_page);
                child_old = internal_page;
                left_replacement = new_internal_page;
                right_to_insert = right_internal_page;
                sep_to_insert = promoted;
                levels_remaining -= 1;
                continue;
            }

            self.write_internal(new_internal_page, &internal).await?;
            self.free_page(internal_page);
            self.remap_dirty_parent_paths(internal_page, new_internal_page);

            let mut child_old_chain = internal_page;
            let mut child_new_chain = new_internal_page;
            for i in (0..levels_remaining - 1).rev() {
                let p = path[i];
                let mut node = self.read_internal(p).await?;
                if node.leftmost_child == child_old_chain {
                    node.leftmost_child = child_new_chain;
                } else {
                    for e in &mut node.entries {
                        if e.right_child == child_old_chain {
                            e.right_child = child_new_chain;
                            break;
                        }
                    }
                }
                let new_p = self.allocate_page();
                self.write_internal(new_p, &node).await?;
                self.free_page(p);
                self.remap_dirty_parent_paths(p, new_p);
                child_old_chain = p;
                child_new_chain = new_p;
            }
            self.root_page_id = child_new_chain;
            return Ok(());
        }
    }

    /// Substitute every occurrence of `old` with `new` in cached dirty-leaf
    /// parent paths. Used after a split or a spine `CoW` in
    /// [`propagate_split_up`](Self::propagate_split_up) replaces an internal
    /// page that other dirty leaves' paths reference.
    fn remap_dirty_parent_paths(&mut self, old: u64, new: u64) {
        if self.dirty_parent_paths.is_empty() {
            return;
        }
        for path in self.dirty_parent_paths.values_mut() {
            for p in path.iter_mut() {
                if *p == old {
                    *p = new;
                }
            }
        }
    }

    // ─── Read-side range operations ──────────────────────────────────────────

    /// Forward range scan: `start` inclusive, `end` exclusive.
    ///
    /// Parent-mediated traversal: walks the tree via internal nodes to find
    /// each successive leaf, rather than chasing leaf sibling pointers. This
    /// lets the write path skip sibling-pointer `CoW` (saves ~2 leaf rewrites
    /// per put) at the cost of one extra internal-node lookup per leaf
    /// boundary crossed during a scan.
    pub async fn collect_range(&self, start: &[u8], end: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        if self.root_page_id == 0 {
            return Ok(Vec::new());
        }
        let mut path = self.path_to_leaf_for_key(start).await?;
        let mut out: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        loop {
            let leaf_id = *path.last().expect("non-empty path");
            let leaf = self.read_leaf(leaf_id).await?;
            for (k, v) in &leaf.records {
                if k.as_slice() >= end {
                    return Ok(out);
                }
                if k.as_slice() >= start {
                    let val = self.resolve_leaf_value(v).await?;
                    out.push((k.clone(), val));
                }
            }
            match self.next_leaf_after(&path).await? {
                Some(next_path) => path = next_path,
                None => return Ok(out),
            }
        }
    }

    /// Descend from the root to the leaf that would contain `key`, returning
    /// the full path (internal `page_ids` followed by the leaf `page_id`).
    async fn path_to_leaf_for_key(&self, key: &[u8]) -> Result<Vec<u64>> {
        let mut path = Vec::new();
        let mut page_id = self.root_page_id;
        loop {
            path.push(page_id);
            // Fresh leaves (from in-txn splits) live only in `fresh_leaves`
            // until flush — the pager has no copy yet. Short-circuit the
            // descent before attempting a pager read.
            if self.fresh_leaves.contains_key(&page_id) {
                return Ok(path);
            }
            let (guard, kind) = self.read_node_guard(page_id).await?;
            if kind == NodeKind::Leaf {
                return Ok(path);
            }
            let next = InternalAccessor::new(guard.body_ref())?.child_for(key);
            drop(guard);
            page_id = next;
        }
    }

    /// Given a `path` ending at a leaf, return the path to the next leaf to
    /// the right (in key order), or `None` if `path` is the rightmost leaf.
    ///
    /// Walks up the path looking for the first ancestor where the current
    /// subtree isn't the rightmost child, then descends the leftmost branch
    /// of the next sibling.
    async fn next_leaf_after(&self, path: &[u64]) -> Result<Option<Vec<u64>>> {
        if path.len() < 2 {
            // Root is a leaf; no next leaf.
            return Ok(None);
        }
        let mut child = path[path.len() - 1];
        for i in (0..path.len() - 1).rev() {
            let (guard, _kind) = self.read_node_guard(path[i]).await?;
            let internal = Internal::decode(guard.body_ref())?;
            drop(guard);
            if let Some(next_child) = Self::right_sibling_child(&internal, child) {
                // Build the path: prefix up to `i`, then descend leftmost from `next_child`.
                let mut new_path: Vec<u64> = path[..=i].to_vec();
                let mut cur = next_child;
                loop {
                    new_path.push(cur);
                    // A fresh-from-split leaf has no pager presence yet.
                    if self.fresh_leaves.contains_key(&cur) {
                        return Ok(Some(new_path));
                    }
                    let (g, k) = self.read_node_guard(cur).await?;
                    if k == NodeKind::Leaf {
                        return Ok(Some(new_path));
                    }
                    let internal = Internal::decode(g.body_ref())?;
                    drop(g);
                    cur = internal.leftmost_child;
                }
            }
            child = path[i];
        }
        Ok(None)
    }

    /// Reverse range scan: `start` inclusive, `end` exclusive. Returns results
    /// in descending key order. Collects matching records forward then reverses.
    pub async fn scan_rev(&self, start: &[u8], end: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let mut forward = self.collect_range(start, end).await?;
        forward.reverse();
        Ok(forward)
    }

    /// Prefix scan: returns all records whose key starts with `prefix`, in
    /// ascending order.
    pub async fn scan_prefix(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        if self.root_page_id == 0 {
            return Ok(Vec::new());
        }
        let mut path = self.path_to_leaf_for_key(prefix).await?;
        let mut out: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        loop {
            let leaf_id = *path.last().expect("non-empty path");
            let leaf = self.read_leaf(leaf_id).await?;
            let mut past_prefix = false;
            for (k, v) in &leaf.records {
                if k.as_slice() < prefix {
                    continue;
                }
                if !k.starts_with(prefix) {
                    past_prefix = true;
                    break;
                }
                let val = self.resolve_leaf_value(v).await?;
                out.push((k.clone(), val));
            }
            if past_prefix {
                return Ok(out);
            }
            match self.next_leaf_after(&path).await? {
                Some(next_path) => path = next_path,
                None => return Ok(out),
            }
        }
    }

    /// Batch insert of sorted `(key, value)` pairs. Sorted input is required;
    /// individual puts are issued per record.
    ///
    /// Per-leaf batching (amortising `CoW`) is a deferred performance
    /// optimisation; this implementation is correct for all inputs.
    pub async fn put_batch(&mut self, pairs: Vec<(Vec<u8>, Vec<u8>)>) -> Result<()> {
        for (k, v) in pairs {
            self.put(&k, &v).await?;
        }
        Ok(())
    }

    /// Batch delete of sorted keys.
    ///
    /// Per-leaf batching is a deferred performance optimisation; this
    /// implementation is correct for all inputs.
    pub async fn delete_batch(&mut self, keys: Vec<Vec<u8>>) -> Result<()> {
        for k in keys {
            self.delete(&k).await?;
        }
        Ok(())
    }

    /// Delete all records where `start <= key < end`. Returns the count of
    /// deleted records. Empty leaves are left in place (rebalancing is
    /// deferred).
    ///
    /// Implementation: collect the full set of matching keys via a forward
    /// scan, then delete each one individually. This avoids the multi-path
    /// `CoW` complexity of in-place range mutation.
    pub async fn delete_range(&mut self, start: &[u8], end: &[u8]) -> Result<u64> {
        if self.root_page_id == 0 {
            return Ok(0);
        }
        // Collect all keys in range (keys only, no values needed).
        let mut page_id = self.root_page_id;
        loop {
            if self.fresh_leaves.contains_key(&page_id) {
                break;
            }
            let kind = self.read_node_kind(page_id).await?;
            if kind == NodeKind::Leaf {
                break;
            }
            let internal = self.read_internal(page_id).await?;
            page_id = internal.child_for(start);
        }
        let mut keys_to_delete: Vec<Vec<u8>> = Vec::new();
        let mut next = page_id;
        'outer: while next != 0 {
            let leaf = self.read_leaf(next).await?;
            for (k, _) in &leaf.records {
                if k.as_slice() >= end {
                    break 'outer;
                }
                if k.as_slice() >= start {
                    keys_to_delete.push(k.clone());
                }
            }
            next = leaf.right_sibling;
        }
        let count = keys_to_delete.len() as u64;
        for key in keys_to_delete {
            self.delete(&key).await?;
        }
        Ok(count)
    }

    /// Resolve a `LeafValue` to its raw bytes. Follows overflow chains as
    /// needed.
    async fn resolve_leaf_value(&self, v: &LeafValue) -> Result<Vec<u8>> {
        match v {
            LeafValue::Inline(b) => Ok(b.clone()),
            LeafValue::Overflow {
                total_len,
                root_page_id,
            } => overflow::read_chain(&self.pager, self.realm_id, *root_page_id, *total_len).await,
        }
    }

    pub async fn flush(&mut self) -> Result<()> {
        self.flush_dirty_leaves().await?;
        self.pager.flush_main(self.realm_id).await
    }

    /// Materialize the dirty-leaf cache into the pager (`CoW` new pages, update
    /// spine, update `root_page_id`) WITHOUT issuing a pager-level flush /
    /// fsync. Callers that bundle multiple trees into a single commit use this
    /// to coalesce all page writes behind one `pager.flush_main` fsync.
    pub async fn materialize_dirty(&mut self) -> Result<()> {
        self.flush_dirty_leaves().await
    }

    /// Materialize the dirty-leaf cache into the buffer pool. For each leaf
    /// cached at its on-disk `page_id`, allocate a fresh page (`CoW`), encode +
    /// write to the new page, and record the redirect. Then walk only the
    /// affected ancestors (collected from per-leaf parent paths) bottom-up,
    /// `CoW`'ing each internal that points at a redirected child. Finally
    /// drain `fresh_leaves` (created by splits during this txn) — they're
    /// already pinned to fresh page ids on a `CoW`'d spine, so we just encode
    /// + write them at those ids without any redirect work.
    async fn flush_dirty_leaves(&mut self) -> Result<()> {
        // Materialize fresh-from-split leaves first. They don't participate
        // in the redirect/spine walk; just encode + write at their pinned
        // page ids. Doing them upfront also ensures the pager has every
        // fresh page before any subsequent `read_node_guard` in this flush
        // touches the spine.
        if !self.fresh_leaves.is_empty() {
            let fresh: Vec<(u64, Leaf)> = self.fresh_leaves.drain().collect();
            for (page_id, leaf) in fresh {
                self.write_leaf(page_id, &leaf).await?;
            }
        }
        if self.dirty_leaves.is_empty() {
            return Ok(());
        }
        let dirties: Vec<(u64, Leaf)> = self.dirty_leaves.drain().collect();
        let parent_paths: HashMap<u64, Vec<u64>> = self.dirty_parent_paths.drain().collect();
        let mut redirects: HashMap<u64, u64> = HashMap::with_capacity(dirties.len());
        for (old_page_id, leaf) in dirties {
            let new_page_id = self.allocate_page();
            self.write_leaf(new_page_id, &leaf).await?;
            redirects.insert(old_page_id, new_page_id);
            // The old leaf page goes through `scheduled_frees` →
            // `drain_freed`; the caller drains it into the deferred-free queue.
        }
        // Group affected internals by depth (index in the path from the root).
        let mut internals_by_depth: BTreeMap<usize, BTreeSet<u64>> = BTreeMap::new();
        for path in parent_paths.values() {
            for (depth, &page_id) in path.iter().enumerate() {
                internals_by_depth.entry(depth).or_default().insert(page_id);
            }
        }
        // Process deepest-first so each parent's children are already
        // redirected by the time the parent is rewritten.
        let mut spine_frees: Vec<u64> = Vec::new();
        for page_ids in internals_by_depth.values().rev() {
            for &old_page_id in page_ids {
                let mut internal = self.read_internal(old_page_id).await?;
                let mut changed = false;
                if let Some(&new_child) = redirects.get(&internal.leftmost_child) {
                    internal.leftmost_child = new_child;
                    changed = true;
                }
                for e in &mut internal.entries {
                    if let Some(&new_child) = redirects.get(&e.right_child) {
                        e.right_child = new_child;
                        changed = true;
                    }
                }
                if !changed {
                    continue;
                }
                let new_page_id = self.allocate_page();
                self.write_internal(new_page_id, &internal).await?;
                redirects.insert(old_page_id, new_page_id);
                spine_frees.push(old_page_id);
            }
        }
        if let Some(&new_root) = redirects.get(&self.root_page_id) {
            self.root_page_id = new_root;
        }
        for pid in spine_frees {
            self.free_page(pid);
        }
        Ok(())
    }

    /// Drain and return all `page_ids` that were freed during this tree's
    /// mutation session, plus any leaf pages scheduled for freeing at the
    /// upcoming `flush`. After this call, both `self.freed` and
    /// `self.scheduled_frees` are empty.
    pub fn drain_freed(&mut self) -> Vec<u64> {
        let mut out = std::mem::take(&mut self.freed);
        out.append(&mut self.scheduled_frees);
        out
    }

    /// Bulk-load sorted `(key, value)` pairs into a freshly-created tree
    /// without any `CoW` overhead. The tree must be empty (`root_page_id == 0`).
    ///
    /// All records are first placed into as few leaves as needed, then internal
    /// nodes are built bottom-up. Each page is written exactly once; no freed
    /// pages are generated. The resulting layout is dense and compact.
    ///
    /// Overflow values are NOT supported in bulk-load; callers must ensure all
    /// values fit inline (`value.len()` ≤ `page_size` / 4). For compaction use-
    /// cases, the pairs come from `collect_range` which already resolves
    /// overflow chains into inline bytes.
    ///
    /// Returns `Err` if the tree is not empty.
    #[allow(clippy::too_many_lines)]
    pub async fn bulk_load(&mut self, pairs: Vec<(Vec<u8>, Vec<u8>)>) -> Result<()> {
        if self.root_page_id != 0 {
            return Err(PagedbError::Io(std::io::Error::other(
                "bulk_load: tree must be empty",
            )));
        }
        if pairs.is_empty() {
            return Ok(());
        }

        // Build leaves greedily: pack as many records as fit into each leaf.
        // No sibling pointers yet — we'll wire them up at the end.
        let mut leaves: Vec<(u64, Vec<u8>)> = Vec::new(); // (page_id, first_key)

        let body_cap = super::node::body_capacity(self.page_size);
        let mut current_leaf = Leaf::new();

        let flush_leaf = |leaf: &Leaf, page_id: u64, next_id: u64| {
            let _ = (leaf, page_id, next_id); // will write below
        };
        let _ = flush_leaf; // suppress unused-variable lint (closure is a placeholder)

        // First pass: group records into leaves.
        let mut leaf_groups: Vec<Vec<(Vec<u8>, Vec<u8>)>> = Vec::new();
        for (k, v) in &pairs {
            let entry_size = {
                let suffix_len = k.len(); // conservative: no prefix compression yet
                2 + suffix_len + 2 + v.len() // slot entry (inline value)
            };
            // Rough check: header + slot_dir entry + record body
            let projected = super::node::HEADER_LEN
                + (current_leaf.records.len() + 1) * 2
                + current_leaf
                    .records
                    .iter()
                    .map(|(ck, cv)| 2 + ck.len() + cv.encoded_size())
                    .sum::<usize>()
                + entry_size;
            if projected > body_cap && !current_leaf.records.is_empty() {
                leaf_groups.push(
                    std::mem::take(&mut current_leaf.records)
                        .into_iter()
                        .map(|(lk, lv)| {
                            let vbytes = match lv {
                                LeafValue::Inline(b) => b,
                                LeafValue::Overflow { .. } => Vec::new(),
                            };
                            (lk, vbytes)
                        })
                        .collect(),
                );
                current_leaf = Leaf::new();
            }
            current_leaf.upsert(k, LeafValue::Inline(v.clone()));
        }
        if !current_leaf.records.is_empty() {
            leaf_groups.push(
                std::mem::take(&mut current_leaf.records)
                    .into_iter()
                    .map(|(lk, lv)| {
                        let vbytes = match lv {
                            LeafValue::Inline(b) => b,
                            LeafValue::Overflow { .. } => Vec::new(),
                        };
                        (lk, vbytes)
                    })
                    .collect(),
            );
        }

        // Second pass: allocate page_ids and write leaves with correct sibling pointers.
        let n_leaves = leaf_groups.len();
        let page_ids: Vec<u64> = (0..n_leaves).map(|_| self.allocate_page()).collect();

        for (i, group) in leaf_groups.iter().enumerate() {
            let mut leaf = Leaf {
                left_sibling: if i == 0 { 0 } else { page_ids[i - 1] },
                right_sibling: if i + 1 < n_leaves { page_ids[i + 1] } else { 0 },
                records: group
                    .iter()
                    .map(|(k, v)| (k.clone(), LeafValue::Inline(v.clone())))
                    .collect(),
            };
            leaf.records.sort_by(|(a, _), (b, _)| a.cmp(b)); // already sorted
            self.write_leaf(page_ids[i], &leaf).await?;
            let first_key = group.first().map(|(k, _)| k.clone()).unwrap_or_default();
            leaves.push((page_ids[i], first_key));
        }

        if leaves.len() == 1 {
            self.root_page_id = leaves[0].0;
            return Ok(());
        }

        // Build internal nodes bottom-up.
        // Each level has a list of (page_id, separator_key) for each node.
        let mut current_level: Vec<(u64, Vec<u8>)> = leaves;

        loop {
            if current_level.len() == 1 {
                self.root_page_id = current_level[0].0;
                break;
            }

            // Group children into internal nodes. Each internal node can hold
            // a limited number of children.
            let mut new_level: Vec<(u64, Vec<u8>)> = Vec::new();
            let mut remaining = &current_level[..];

            while !remaining.is_empty() {
                // Determine how many children fit in one internal node.
                // An internal entry is: key_len (2) + key + child_page_id (8).
                // Header is 24 bytes. Slot directory: 2 bytes per entry.
                // Leftmost child takes no key slot.
                let mut count = 1usize; // leftmost child
                let mut used = super::node::HEADER_LEN;
                for item in remaining.iter().skip(1) {
                    let sep_key = &item.1;
                    let entry_bytes = 2 + sep_key.len() + 8 + 2; // record + slot
                    if used + entry_bytes > body_cap {
                        break;
                    }
                    used += entry_bytes;
                    count += 1;
                }
                let chunk = &remaining[..count];
                remaining = &remaining[count..];

                let leftmost_child = chunk[0].0;
                let entries: Vec<super::internal::InternalEntry> = chunk[1..]
                    .iter()
                    .map(|(pid, sep)| super::internal::InternalEntry {
                        key: sep.clone(),
                        right_child: *pid,
                    })
                    .collect();

                let internal = super::internal::Internal {
                    leftmost_child,
                    entries,
                };
                let pid = self.allocate_page();
                self.write_internal(pid, &internal).await?;
                // Separator for this node: the first key of leftmost child.
                let sep = chunk[0].1.clone();
                new_level.push((pid, sep));
            }

            current_level = new_level;
        }

        Ok(())
    }

    /// Walk every page reachable from `self.root_page_id` (internal nodes,
    /// leaves, overflow chains) and rewrite each one under the pager's current
    /// `mk_epoch`. Pages are read via epoch-routing (so old-epoch pages decrypt
    /// correctly) and marked dirty so the next flush re-seals them under the
    /// new epoch.
    ///
    /// Returns the count of pages touched.
    pub async fn rekey_walk(&self) -> Result<u64> {
        if self.root_page_id == 0 {
            return Ok(0);
        }
        let mut stack: Vec<u64> = vec![self.root_page_id];
        let mut count: u64 = 0;
        while let Some(page_id) = stack.pop() {
            // Determine kind by reading node header via epoch-routed path.
            // Try leaf page kind first; on AAD mismatch try internal.
            let (is_leaf, body_bytes) = {
                match self
                    .pager
                    .read_main_page(page_id, self.realm_id, PageKind::BTreeLeaf)
                    .await
                {
                    Ok(g) => {
                        let body = g.body();
                        let header = super::node::read_header(&body)?;
                        let is_leaf = header.kind == super::node::NodeKind::Leaf;
                        (is_leaf, body.to_vec())
                    }
                    Err(PagedbError::ChecksumFailure) => {
                        let g = self
                            .pager
                            .read_main_page(page_id, self.realm_id, PageKind::BTreeInternal)
                            .await?;
                        let body = g.body();
                        (false, body.to_vec())
                    }
                    Err(e) => return Err(e),
                }
            };

            if is_leaf {
                // Collect overflow chains referenced by this leaf.
                let leaf = super::leaf::Leaf::decode(&body_bytes)?;
                for (_k, v) in &leaf.records {
                    if let super::leaf::LeafValue::Overflow {
                        root_page_id: ov_root,
                        ..
                    } = v
                    {
                        // Rewrite root page (v2 OverflowRoot or v1 Overflow).
                        let root_info =
                            super::overflow::read_root_page(&self.pager, self.realm_id, *ov_root)
                                .await?;
                        let root_kind = if root_info.is_v2 {
                            PageKind::OverflowRoot
                        } else {
                            PageKind::Overflow
                        };
                        self.pager
                            .rewrite_page_under_current_epoch(*ov_root, self.realm_id, root_kind)
                            .await?;
                        count += 1;
                        // Walk and rewrite chain pages (always PageKind::Overflow).
                        let mut next = root_info.next;
                        while next != 0 {
                            let ov_guard = self
                                .pager
                                .read_main_page(next, self.realm_id, PageKind::Overflow)
                                .await?;
                            let ov_body = ov_guard.body();
                            let (ov_next, _) = super::overflow::decode_overflow(&ov_body)?;
                            drop(ov_guard);
                            self.pager
                                .rewrite_page_under_current_epoch(
                                    next,
                                    self.realm_id,
                                    PageKind::Overflow,
                                )
                                .await?;
                            count += 1;
                            next = ov_next;
                        }
                    }
                }
                // Rewrite the leaf page.
                self.pager
                    .rewrite_page_under_current_epoch(page_id, self.realm_id, PageKind::BTreeLeaf)
                    .await?;
                count += 1;
            } else {
                // Internal node: push children onto stack.
                let internal = super::internal::Internal::decode(&body_bytes)?;
                stack.push(internal.leftmost_child);
                for entry in &internal.entries {
                    stack.push(entry.right_child);
                }
                // Rewrite the internal page.
                self.pager
                    .rewrite_page_under_current_epoch(
                        page_id,
                        self.realm_id,
                        PageKind::BTreeInternal,
                    )
                    .await?;
                count += 1;
            }
        }
        Ok(count)
    }

    /// Collect all page IDs reachable from this tree's root (internal nodes,
    /// leaves, overflow chains) into `out`. Used by the deep-walk integrity
    /// checker to identify orphan pages.
    #[allow(clippy::too_many_lines)]
    pub async fn collect_all_page_ids(
        &self,
        out: &mut std::collections::BTreeSet<u64>,
    ) -> Result<()> {
        if self.root_page_id == 0 {
            return Ok(());
        }
        let mut stack: Vec<u64> = vec![self.root_page_id];
        while let Some(page_id) = stack.pop() {
            if !out.insert(page_id) {
                // Already visited.
                continue;
            }
            let (is_leaf, body_bytes) = {
                match self
                    .pager
                    .read_main_page(page_id, self.realm_id, PageKind::BTreeLeaf)
                    .await
                {
                    Ok(g) => {
                        let body = g.body();
                        let header = super::node::read_header(&body)?;
                        let is_leaf = header.kind == super::node::NodeKind::Leaf;
                        (is_leaf, body.to_vec())
                    }
                    Err(crate::errors::PagedbError::ChecksumFailure) => {
                        match self
                            .pager
                            .read_main_page(page_id, self.realm_id, PageKind::BTreeInternal)
                            .await
                        {
                            Ok(g) => (false, g.body().to_vec()),
                            Err(_) => continue, // unreadable — best effort
                        }
                    }
                    Err(_) => continue,
                }
            };

            if is_leaf {
                let Ok(leaf) = super::leaf::Leaf::decode(&body_bytes) else {
                    continue;
                };
                for (_k, v) in &leaf.records {
                    if let super::leaf::LeafValue::Overflow {
                        root_page_id: ov_root,
                        ..
                    } = v
                    {
                        self.collect_overflow_chain(*ov_root, out).await;
                    }
                }
            } else {
                // Internal node: push child page IDs.
                let Ok(internal) = super::internal::Internal::decode(&body_bytes) else {
                    continue;
                };
                if internal.leftmost_child != 0 {
                    stack.push(internal.leftmost_child);
                }
                for entry in &internal.entries {
                    if entry.right_child != 0 {
                        stack.push(entry.right_child);
                    }
                }
            }
        }
        Ok(())
    }

    /// Walk an overflow chain starting at `root` and insert all page IDs into
    /// `out`. Best-effort: stops on any read failure.
    async fn collect_overflow_chain(&self, root: u64, out: &mut std::collections::BTreeSet<u64>) {
        let mut first = true;
        let mut chain_id = root;
        while chain_id != 0 {
            if !out.insert(chain_id) {
                break;
            }
            let kind = if first {
                first = false;
                PageKind::OverflowRoot
            } else {
                PageKind::Overflow
            };
            let g = match self
                .pager
                .read_main_page(chain_id, self.realm_id, kind)
                .await
            {
                Ok(g) => g,
                Err(crate::errors::PagedbError::ChecksumFailure) => {
                    match self
                        .pager
                        .read_main_page(chain_id, self.realm_id, PageKind::Overflow)
                        .await
                    {
                        Ok(g) => g,
                        Err(_) => break,
                    }
                }
                Err(_) => break,
            };
            let body = g.body();
            if body.len() < 8 {
                break;
            }
            let mut b = [0u8; 8];
            b.copy_from_slice(&body[..8]);
            chain_id = u64::from_le_bytes(b);
        }
    }
}
