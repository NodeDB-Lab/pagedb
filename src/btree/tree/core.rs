//! `BTree` — the `CoW` shadow-paging B+ tree.

use std::collections::BTreeSet;
use std::sync::Arc;

use rustc_hash::FxHashMap;

use crate::errors::PagedbError;
use crate::pager::format::page_kind::PageKind;
use crate::pager::{PageGuard, Pager};
use crate::vfs::Vfs;
use crate::{RealmId, Result};

use crate::btree::internal::{self, Internal};
use crate::btree::leaf::Leaf;
use crate::btree::node::{NodeKind, OFF_DUAL_USE, body_capacity, read_header, write_u64_le};
use crate::btree::overflow;
use crate::btree::tree::page_source::PageSource;

/// Encoded size a value of `value_len` bytes will occupy in a leaf record,
/// computed before the value is built.
///
/// The preflight counterpart to [`LeafValue::encoded_size`], and it must agree
/// with it — both sides read the same constant rather than restating the
/// layout.
fn stored_leaf_value_encoded_size(value_len: usize, page_size: usize) -> Result<usize> {
    if value_len > overflow::inline_value_threshold(page_size) {
        Ok(crate::btree::leaf::OVERFLOW_REF_ENCODED_SIZE)
    } else {
        2usize
            .checked_add(value_len)
            .ok_or(PagedbError::PayloadTooLarge)
    }
}

/// A descent reached a page twice, or followed a zero child pointer.
///
/// Both mean the pointer graph has no terminator, which no honest writer can
/// produce. Named for the walk rather than reported as a generic header
/// failure, so `fsck` can say which page repeated and in which structure.
pub(super) fn malformed_btree_topology(structure: &'static str, page_id: u64) -> PagedbError {
    PagedbError::page_chain_cycle(structure, page_id)
}

// Keep common shallow descents stack-only and small; deeper trees spill into
// the exact set instead of weakening cycle detection.
const INLINE_SEEN_PAGE_IDS: usize = 4;

/// Duplicate-page detector for B-tree descents. Shallow trees stay on the
/// inline array; deeper trees preserve exact detection through the overflow set.
pub(super) struct SeenPageIds {
    /// Which walk this is, so a rejection can name the structure it was in.
    structure: &'static str,
    inline: [u64; INLINE_SEEN_PAGE_IDS],
    len: usize,
    overflow: Option<BTreeSet<u64>>,
}

impl SeenPageIds {
    pub(super) fn new(structure: &'static str) -> Self {
        Self {
            structure,
            inline: [0; INLINE_SEEN_PAGE_IDS],
            len: 0,
            overflow: None,
        }
    }

    pub(super) fn from_existing(structure: &'static str, path: &[u64]) -> Result<Self> {
        let mut seen = Self::new(structure);
        for &page_id in path {
            seen.insert(page_id)?;
        }
        Ok(seen)
    }

    pub(super) fn insert(&mut self, page_id: u64) -> Result<()> {
        if page_id == 0 || !self.insert_inner(page_id) {
            return Err(malformed_btree_topology(self.structure, page_id));
        }
        Ok(())
    }

    fn insert_inner(&mut self, page_id: u64) -> bool {
        if let Some(overflow) = &mut self.overflow {
            return overflow.insert(page_id);
        }
        if self.inline[..self.len].contains(&page_id) {
            return false;
        }
        if self.len < INLINE_SEEN_PAGE_IDS {
            self.inline[self.len] = page_id;
            self.len += 1;
            return true;
        }
        let mut overflow = BTreeSet::new();
        overflow.extend(self.inline);
        let inserted = overflow.insert(page_id);
        self.overflow = Some(overflow);
        inserted
    }
}

/// `CoW` B+ tree backed by the Pager. Single writer per instance; concurrent
/// reads through `&self`.
pub struct BTree<V: Vfs> {
    pub(super) pager: Arc<Pager<V>>,
    pub(super) realm_id: RealmId,
    pub(super) root_page_id: u64,
    pub(super) next_page_id: u64,
    pub(super) freed: Vec<u64>,
    /// The subset of pages freed this session that `allocate_page` may hand
    /// back immediately — i.e. those that satisfied the reuse rule below at the
    /// moment they were freed. Eligibility is decided once, in
    /// [`Self::free_page`], because neither input to that decision can move
    /// afterwards: [`PageSource`] is fixed for the tree's whole life, and the
    /// sink it carries cannot shrink while the session runs. Deciding it here
    /// keeps allocation O(1); evaluating it per allocation instead meant
    /// rescanning `freed` against the sink on every call, which is quadratic in
    /// the number of pages a flush touches and made large flushes effectively
    /// never finish. Drained together with `freed` by `drain_freed`.
    pub(super) freed_reusable: Vec<u64>,
    pub(super) page_size: usize,
    /// Leaves modified during this write session but not yet promoted via
    /// `CoW` to a fresh page. Keyed by the leaf's current `page_id` as referenced
    /// by the tree spine. All mutations happen in place; encode + spine
    /// redirect happens in batch at [`flush`](Self::flush). Splits are
    /// flushed eagerly (they alter the tree shape and must propagate up).
    /// Keyed by `page_id`, so the DoS-resistant `SipHash` default costs a
    /// measurable slice of every put and buys nothing. `FxHashMap` throughout
    /// the write session's page-id maps.
    pub(super) dirty_leaves: FxHashMap<u64, Leaf>,
    /// Old leaf `page_ids` that have been pulled into [`Self::dirty_leaves`] but
    /// not yet replaced by a fresh `CoW` page. These pages will be freed at
    /// flush time; [`Self::drain_freed`] reports them now so the deferred-free
    /// queue (and the reader stall policy) sees an accurate page count
    /// *before* `flush()` runs.
    pub(super) scheduled_frees: Vec<u64>,
    /// For each dirty leaf, the path of internal `page_ids` from the root down
    /// to (but not including) the leaf. Captured at first-touch so flush can
    /// walk only the affected spine instead of scanning the whole tree.
    pub(super) dirty_parent_paths: FxHashMap<u64, Vec<u64>>,
    /// Leaves produced by splits during this write session. Keyed by the
    /// **fresh** `page_id` they will occupy on disk. Unlike `dirty_leaves`,
    /// no `CoW` is needed at flush time — they're already pinned to fresh
    /// page ids on a `CoW`'d spine. Encode + pager write happens at flush so
    /// the encode work batches with the rest and lands in the pager's
    /// parallel-AEAD flush. In-place mutation by subsequent puts targeting
    /// the same leaf is allowed; no further allocation needed.
    pub(super) fresh_leaves: FxHashMap<u64, Leaf>,
    /// Where this tree may allocate from beyond bumping `next_page_id`: the
    /// session's reuse threshold and its shared free-page cache, supplied as
    /// one value at [`Self::open_session`] and never afterwards. `None` for
    /// trees opened outside a write session (readers, compaction's repack
    /// trees), which bump-allocate and may recycle anything they free — they
    /// own every page they touch.
    ///
    /// One field rather than three because [`Self::free_page`] reads all of it
    /// on the first free: a threshold arriving late would misclassify pages
    /// already banked, and a cache without its sink would hand out pages whose
    /// draw nothing recorded. Neither state is constructible.
    pub(super) page_source: Option<PageSource>,
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
    /// Open a tree that allocates only by bumping its own cursor and may
    /// recycle anything it frees. For a tree in a write session — one sharing
    /// the `Db`'s free-page cache, and holding back pages a reader snapshot or
    /// the last durable header may still name — use [`Self::open_session`].
    pub fn open(
        pager: Arc<Pager<V>>,
        realm_id: RealmId,
        root_page_id: u64,
        next_page_id: u64,
        page_size: usize,
    ) -> Self {
        Self::new(pager, realm_id, root_page_id, next_page_id, page_size, None)
    }

    /// Open a tree belonging to `source`'s write session.
    ///
    /// The source is supplied here and nowhere else. [`Self::free_page`]
    /// decides reuse eligibility at the moment of the free, so a threshold or a
    /// consumed-page sink that could arrive later would leave pages classified
    /// against state that has since changed; taking it at construction is what
    /// rules that out rather than asking callers to sequence their calls
    /// correctly.
    pub fn open_session(
        pager: Arc<Pager<V>>,
        realm_id: RealmId,
        root_page_id: u64,
        next_page_id: u64,
        page_size: usize,
        source: PageSource,
    ) -> Self {
        Self::new(
            pager,
            realm_id,
            root_page_id,
            next_page_id,
            page_size,
            Some(source),
        )
    }

    fn new(
        pager: Arc<Pager<V>>,
        realm_id: RealmId,
        root_page_id: u64,
        next_page_id: u64,
        page_size: usize,
        page_source: Option<PageSource>,
    ) -> Self {
        let next = next_page_id.max(4);
        Self {
            pager,
            realm_id,
            root_page_id,
            next_page_id: next,
            freed: Vec::new(),
            freed_reusable: Vec::new(),
            page_size,
            page_source,
            dirty_leaves: FxHashMap::default(),
            scheduled_frees: Vec::new(),
            dirty_parent_paths: FxHashMap::default(),
            fresh_leaves: FxHashMap::default(),
            append_last_key: None,
            append_cached_path: None,
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
        // First, recycle a page freed earlier *in this same session*, gated by
        // the reuse threshold: a page below it may still be live in a pinned
        // reader's snapshot, so it can't be reused until the durable free-list
        // clears it (it leaves via `drain_freed` at commit instead).
        //
        // Exception: a below-threshold page originally drawn from the shared
        // cache this session (recorded in the source's consumed sink) is free
        // per the last durable header regardless of what this session wrote to
        // it since, so recycling it again in-session is crash-safe — a failed
        // or torn commit leaves the durable header referencing none of its
        // content. Without this, every cache-drawn page freed by a later
        // in-session split is burned for the rest of the txn and allocation
        // falls through to bump growth.
        //
        // `free_page` has already applied that rule to each freed page, so the
        // eligible ones are exactly `freed_reusable` and this is a pop, not a
        // search.
        if let Some(id) = self.freed_reusable.pop() {
            assert!(
                id >= 4,
                "allocate_page recycled reserved page {id} from freed"
            );
            return id;
        }
        // Then draw from the shared cross-commit cache. It is loaded at txn
        // begin with *only* free-list pages below the reclamation floor — pages
        // no live reader and no retained-history root can observe — so reusing
        // them is safe regardless of `reuse_threshold`. Record each draw so the
        // commit path removes it from the durable free-list.
        if let Some(source) = &self.page_source {
            if let Some(id) = source.cache.lock().pop() {
                assert!(
                    id >= 4,
                    "allocate_page recycled reserved page {id} from free-list cache"
                );
                source.consumed.record(id);
                return id;
            }
        }
        let id = self.next_page_id;
        assert!(
            id >= 4,
            "allocate_page bumped into reserved page {id} (next_page_id corrupted low)"
        );
        self.next_page_id += 1;
        id
    }

    pub(super) fn free_page(&mut self, page_id: u64) {
        // Pages 0..=3 are reserved (A/B headers + apply-journal) and must never
        // enter the free-list: freeing one lets a later allocation hand it back
        // as a data/overflow page, producing a wild pointer into a header page.
        assert!(
            page_id >= 4,
            "free_page called on reserved page {page_id} (use-after-free / wild pointer)"
        );
        if self.is_reusable_in_session(page_id) {
            self.freed_reusable.push(page_id);
        } else {
            self.freed.push(page_id);
        }
    }

    /// Whether a page freed now may be recycled within this session. See
    /// [`Self::allocate_page`] for the reasoning behind each arm: below the
    /// threshold a page may still be live in the last durable header or a
    /// pinned reader's snapshot, unless it was drawn from the shared free-page
    /// cache this session, in which case the durable header references none of
    /// its content.
    ///
    /// A tree with no page source holds nothing back: it allocated every page
    /// it can free, so no snapshot and no durable header names them.
    fn is_reusable_in_session(&self, page_id: u64) -> bool {
        let Some(source) = &self.page_source else {
            return true;
        };
        // A zero threshold needs no special case: every page id clears it.
        page_id >= source.reuse_threshold || source.consumed.contains(page_id)
    }

    pub(super) fn validate_insert_record_fits(&self, key: &[u8], value: &[u8]) -> Result<()> {
        let value_encoded_size = stored_leaf_value_encoded_size(value.len(), self.page_size)?;
        if !Leaf::single_record_fits_encoded(key.len(), value_encoded_size, self.page_size)
            || !internal::separator_fits(key.len(), self.page_size)
        {
            return Err(PagedbError::PayloadTooLarge);
        }
        Ok(())
    }

    /// Read a B+ tree node page without knowing its kind in advance. The pager
    /// authenticates under the page's own header kind byte, so leaf and internal
    /// nodes are each read correctly in a single pass. The encrypted body header
    /// must agree with that authenticated envelope kind; disagreement indicates
    /// a malformed page, not a different node type. Returns the pinned page guard
    /// and decoded kind so the caller can build the matching accessor on borrowed
    /// bytes without a second cache lookup.
    pub(crate) async fn read_node_guard(&self, page_id: u64) -> Result<(PageGuard, NodeKind)> {
        let (guard, authenticated_kind) = self.pager.read_main_node(page_id, self.realm_id).await?;
        let decoded_kind = read_header(guard.body_ref())?.kind;
        let expected_kind = match authenticated_kind {
            PageKind::BTreeLeaf => NodeKind::Leaf,
            PageKind::BTreeInternal => NodeKind::Internal,
            // Unreachable today: `KindBinding::Node` already restricts the
            // authenticated kind to the two node kinds on both the warm and
            // cold pager paths. Kept so this boundary stays total if the pager
            // ever admits another kind here — a silent widening would otherwise
            // turn into a mis-typed accessor rather than an error.
            _ => return Err(PagedbError::IllegalPageKind),
        };
        if decoded_kind != expected_kind {
            // The envelope is authenticated and the body is not, so name both
            // and the page: this is a mis-routed page, not damaged content, and
            // an operator chasing it needs to know which side to trust.
            return Err(PagedbError::node_kind_mismatch(
                Some(page_id),
                expected_kind.name(),
                decoded_kind.name(),
            ));
        }
        Ok((guard, decoded_kind))
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

    /// Copy the internal page at `old_page_id` to `new_page_id`, repointing the
    /// single child link that referenced `child_old` at `child_new`.
    ///
    /// Propagating a split rewrites one child pointer per ancestor and leaves
    /// every separator untouched. Going through `read_internal` to do that
    /// decodes the whole node — an owned `Vec<u8>` per separator key — and then
    /// re-encodes those same keys unchanged, which on a full node is well over a
    /// hundred allocations to move eight bytes. Copy the body and patch the
    /// field instead.
    ///
    /// Silently copies unchanged if no link matches, matching what the
    /// decode-and-mutate path did: a spine that does not reference the child it
    /// is being told about is a structural problem for the caller to detect, not
    /// something to start failing here.
    pub(super) async fn cow_internal_repointing_child(
        &self,
        old_page_id: u64,
        new_page_id: u64,
        child_old: u64,
        child_new: u64,
    ) -> Result<()> {
        let guard = self
            .pager
            .read_main_page(old_page_id, self.realm_id, PageKind::BTreeInternal)
            .await?;
        let mut body = guard.body_ref().to_vec();
        {
            let accessor = internal::InternalAccessor::from_guard(&guard)?;
            if accessor.leftmost_child() == child_old {
                write_u64_le(&mut body, OFF_DUAL_USE, child_new);
            } else if let Some(idx) =
                (0..accessor.slot_count()).find(|&i| accessor.right_child_at(i) == child_old)
            {
                let offset = accessor.right_child_offset(idx);
                write_u64_le(&mut body, offset, child_new);
            }
        }
        drop(guard);
        self.pager
            .write_main_page(new_page_id, self.realm_id, PageKind::BTreeInternal, &body)
            .await
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::BTree;
    use crate::RealmId;
    use crate::btree::tree::page_source::{ConsumedPages, PageSource};
    use crate::crypto::CipherId;
    use crate::crypto::kdf::derive_mk;
    use crate::pager::{Pager, PagerConfig};
    use crate::vfs::memory::MemVfs;

    const PAGE: usize = 4096;

    /// A session source over an empty cache, with its sink returned so a test
    /// can seed pages the allocator is to treat as cache-drawn.
    fn session(reuse_threshold: u64) -> (PageSource, Arc<ConsumedPages>) {
        let consumed = ConsumedPages::new();
        let source = PageSource::new(
            reuse_threshold,
            Arc::new(parking_lot::Mutex::new(Vec::new())),
            &consumed,
        );
        (source, consumed)
    }

    async fn fresh_tree(source: Option<PageSource>) -> BTree<MemVfs> {
        let mk = derive_mk(&[1u8; 32], &[0u8; 16], 0).unwrap();
        let cfg = PagerConfig {
            page_size: PAGE,
            buffer_pool_pages: 256,
            segment_cache_pages: 16,
            cipher_id: CipherId::Aes256Gcm,
            mk_epoch: 0,
            main_db_file_id: [0xAB; 16],
            main_db_path: "/main.db".into(),
            anchor_budget: 100_000_000,
            dek_lru_capacity: 16,
            observer_retry_count: 0,
            metrics_enabled: true,
        };
        let pager = Arc::new(Pager::open(MemVfs::new(), mk, cfg).await.unwrap());
        let realm = RealmId::new([1; 16]);
        match source {
            Some(source) => BTree::open_session(pager, realm, 0, 4, PAGE, source),
            None => BTree::open(pager, realm, 0, 4, PAGE),
        }
    }

    /// Below-threshold frees must not be recycled in-session, above-threshold
    /// ones must be, and a cache-drawn page recorded in the consumed sink must
    /// be recyclable even below the threshold. Same rule the per-allocation
    /// scan used to apply; asserted here now that `free_page` decides it once.
    #[tokio::test(flavor = "current_thread")]
    async fn reuse_eligibility_matches_the_threshold_rule() {
        let (source, consumed) = session(1000);
        let mut tree = fresh_tree(Some(source)).await;

        // Below threshold and never drawn from the cache: not recyclable now.
        tree.free_page(500);
        assert_eq!(tree.allocate_page(), 4, "bumped, not recycled");

        // At or above the threshold: recyclable immediately.
        tree.free_page(1500);
        assert_eq!(tree.allocate_page(), 1500);

        // Below threshold but drawn from the shared cache this session.
        consumed.handle().record(600);
        tree.free_page(600);
        assert_eq!(tree.allocate_page(), 600);

        // The one page held back is still reported as freed this session.
        assert_eq!(tree.drain_freed(), vec![500]);
    }

    /// A tree opened without a page source owns every page it can free, so it
    /// recycles them all and never holds one back.
    #[tokio::test(flavor = "current_thread")]
    async fn a_tree_without_a_page_source_recycles_everything() {
        let mut tree = fresh_tree(None).await;
        tree.free_page(9);
        assert_eq!(tree.allocate_page(), 9);
        assert!(tree.drain_freed().is_empty());
    }

    /// Eligibility is settled at the moment of the free and does not change
    /// afterwards. A page held back stays held back even if the same id is
    /// later recorded as cache-drawn — the deciding state only ever grows, so
    /// deciding early can only be conservative, never unsafe. The old
    /// per-allocation scan would have promoted this page; that difference is
    /// intended, and this pins it.
    #[tokio::test(flavor = "current_thread")]
    async fn a_page_held_back_is_not_promoted_by_a_later_record() {
        let (source, consumed) = session(1000);
        let mut tree = fresh_tree(Some(source)).await;

        tree.free_page(500);
        consumed.handle().record(500);

        assert_eq!(tree.allocate_page(), 4, "bumped, not promoted");
        assert_eq!(tree.drain_freed(), vec![500]);
    }

    /// Neither freeing nor allocating may scan a collection that grows with the
    /// flush. A hang detector, not a benchmark — the only wall-clock assertion
    /// in `src/`, and the bound is ~1000x the fixed cost, so only a return to a
    /// linear scan can exceed it. Two such scans are in scope: allocation over
    /// `freed`, and the free-time eligibility test over `free_page_consumed`.
    ///
    /// `consumed` is therefore seeded at the size the free-list window permits
    /// (`WINDOW_PAGES × chain_capacity(page_size)`), not at a token count: that
    /// is what bounds it in a real flush, and a smaller seed cannot see the
    /// free-time term at all.
    #[tokio::test(flavor = "current_thread")]
    async fn allocation_cost_does_not_grow_with_the_freed_list() {
        const N: u64 = 20_000;
        let window = crate::pager::freelist::WINDOW_PAGES
            * crate::pager::freelist::layout::chain_capacity(PAGE);
        let (source, consumed) = session(N * 2);
        let mut tree = fresh_tree(Some(source)).await;

        // Seed the sink at window scale *before* the frees, so every free below
        // pays the eligibility test against a full-size `consumed`.
        {
            let sink = consumed.handle();
            for id in (N * 4)..(N * 4 + window as u64) {
                sink.record(id);
            }
        }

        // Every one of these is below the threshold and absent from `consumed`,
        // so it is ineligible: before the fix each allocation scanned all of
        // them and, per entry, all of `consumed`.
        for id in 4..N {
            tree.free_page(id);
        }

        let start = std::time::Instant::now();
        for _ in 0..N {
            tree.allocate_page();
        }
        let elapsed = start.elapsed();
        assert!(
            elapsed < std::time::Duration::from_secs(10),
            "{N} allocations against {N} held-back frees took {elapsed:?} — \
             allocation is scanning the freed list again"
        );
    }
}
