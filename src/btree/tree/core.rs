//! `BTree` — the `CoW` shadow-paging B+ tree.

use std::collections::BTreeSet;
use std::sync::Arc;

use rustc_hash::{FxHashMap, FxHashSet};

use crate::errors::PagedbError;
use crate::pager::format::page_kind::PageKind;
use crate::pager::{PageGuard, Pager};
use crate::vfs::Vfs;
use crate::{RealmId, Result};

use crate::btree::internal::{self, Internal};
use crate::btree::leaf::Leaf;
use crate::btree::node::{NodeKind, OFF_DUAL_USE, body_capacity, read_header, write_u64_le};
use crate::btree::overflow;

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
    /// [`Self::free_page`], because both inputs to that decision are
    /// monotonic: `reuse_threshold` is fixed for the session and
    /// `free_page_consumed` only grows. Deciding it here keeps allocation O(1);
    /// evaluating it per allocation instead meant rescanning `freed` against
    /// `free_page_consumed` on every call, which is quadratic in the number of
    /// pages a flush touches and made large flushes effectively never finish.
    /// Drained together with `freed` by `drain_freed`.
    pub(super) freed_reusable: Vec<u64>,
    pub(super) page_size: usize,
    /// Minimum `page_id` that may be recycled from `freed` within this session.
    /// Pages below this threshold existed before the session began: they are
    /// still referenced by the last durable header (a copy-on-write free does
    /// not unreference them on disk until the *next* header lands) and may
    /// also be pinned by reader snapshots. They must not be overwritten
    /// in-session; they re-enter circulation through the deferred-free queue
    /// once the free-list naming them is durable. Callers set this to the
    /// session-start `next_page_id`, so only pages bump-allocated within the
    /// session are recyclable immediately.
    pub(super) reuse_threshold: u64,
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
    ///
    /// A set, not a list: [`Self::free_page`] tests membership once per freed
    /// page, and the size is bounded by the free-list window
    /// (`WINDOW_PAGES × chain_capacity(page_size)`) rather than by anything
    /// small — a linear test here would keep the per-free cost proportional to
    /// the window. Nothing reads the insertion order or needs duplicates.
    pub(super) free_page_consumed: Option<Arc<parking_lot::Mutex<FxHashSet<u64>>>>,
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
            freed_reusable: Vec::new(),
            page_size,
            reuse_threshold: 0,
            dirty_leaves: FxHashMap::default(),
            scheduled_frees: Vec::new(),
            dirty_parent_paths: FxHashMap::default(),
            fresh_leaves: FxHashMap::default(),
            free_page_cache: None,
            free_page_consumed: None,
            append_last_key: None,
            append_cached_path: None,
        }
    }

    /// Set the reuse threshold. Any freed page with `page_id < threshold` will
    /// not be recycled within this session; it goes to `self.freed` for later
    /// deferred-queue promotion. Call with the session-start `next_page_id`:
    /// pages below it are still referenced by the last durable header and must
    /// keep their on-disk bytes until the header that frees them is durable.
    ///
    /// Must be called before the first free: [`Self::free_page`] decides reuse
    /// eligibility at the moment of the free, so a threshold arriving later
    /// would leave already-classified pages judged against the wrong one. Every
    /// caller sets it on a fresh tree, which the `debug_assert` states.
    pub fn set_reuse_threshold(&mut self, threshold: u64) {
        debug_assert!(
            self.freed.is_empty() && self.freed_reusable.is_empty(),
            "set_reuse_threshold after a free: eligibility is decided at free time"
        );
        self.reuse_threshold = threshold;
    }

    /// Wire in the `Db`'s shared free-page cache. After this call,
    /// `allocate_page` pops from the shared pool before bumping `next_page_id`.
    /// The pool is loaded at `begin_write` with the floor-safe pages of the
    /// bounded free-list window the following commit rewrites, so recycling
    /// from it is always snapshot-safe.
    ///
    /// The pool is draw-only: nothing here may push into it. The commit deletes
    /// a recycled id from the chain by finding it in that window, so an id
    /// pushed in from elsewhere would be handed out while the unscanned tail
    /// still named it — the same page id given to two live structures.
    pub fn set_free_page_cache(&mut self, cache: Arc<parking_lot::Mutex<Vec<u64>>>) {
        debug_assert!(
            self.freed.is_empty() && self.freed_reusable.is_empty(),
            "set_free_page_cache after a free: eligibility is decided at free time"
        );
        self.free_page_cache = Some(cache);
    }

    /// Wire the shared sink that records cache pages reused this session, so the
    /// commit path can remove them from the durable free-list. Set alongside
    /// [`Self::set_free_page_cache`].
    pub fn set_free_page_consumed(&mut self, consumed: Arc<parking_lot::Mutex<FxHashSet<u64>>>) {
        debug_assert!(
            self.freed.is_empty() && self.freed_reusable.is_empty(),
            "set_free_page_consumed after a free: eligibility is decided at free time"
        );
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
        //
        // Exception: a below-threshold page originally drawn from the shared
        // cache this session (recorded in `free_page_consumed`) is free per
        // the last durable header regardless of what this session wrote to it
        // since, so recycling it again in-session is crash-safe — a failed or
        // torn commit leaves the durable header referencing none of its
        // content. Without this, every cache-drawn page freed by a later
        // in-session split is burned for the rest of the txn and allocation
        // falls through to bump growth.
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
        if let Some(cache) = &self.free_page_cache {
            if let Some(id) = cache.lock().pop() {
                assert!(
                    id >= 4,
                    "allocate_page recycled reserved page {id} from free-list cache"
                );
                if let Some(consumed) = &self.free_page_consumed {
                    consumed.lock().insert(id);
                }
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
    fn is_reusable_in_session(&self, page_id: u64) -> bool {
        // A zero threshold needs no special case: every page id clears it.
        if page_id >= self.reuse_threshold {
            return true;
        }
        self.free_page_consumed
            .as_ref()
            .is_some_and(|c| c.lock().contains(&page_id))
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

    use super::{BTree, FxHashSet};
    use crate::RealmId;
    use crate::crypto::CipherId;
    use crate::crypto::kdf::derive_mk;
    use crate::pager::{Pager, PagerConfig};
    use crate::vfs::memory::MemVfs;

    const PAGE: usize = 4096;

    async fn fresh_tree() -> BTree<MemVfs> {
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
        BTree::open(pager, RealmId::new([1; 16]), 0, 4, PAGE)
    }

    /// Below-threshold frees must not be recycled in-session, above-threshold
    /// ones must be, and a cache-drawn page recorded in `free_page_consumed`
    /// must be recyclable even below the threshold. Same rule the per-allocation
    /// scan used to apply; asserted here now that `free_page` decides it once.
    #[tokio::test(flavor = "current_thread")]
    async fn reuse_eligibility_matches_the_threshold_rule() {
        let mut tree = fresh_tree().await;
        let consumed = Arc::new(parking_lot::Mutex::new(FxHashSet::default()));
        tree.set_free_page_consumed(Arc::clone(&consumed));
        tree.set_reuse_threshold(1000);

        // Below threshold and never drawn from the cache: not recyclable now.
        tree.free_page(500);
        assert_eq!(tree.allocate_page(), 4, "bumped, not recycled");

        // At or above the threshold: recyclable immediately.
        tree.free_page(1500);
        assert_eq!(tree.allocate_page(), 1500);

        // Below threshold but drawn from the shared cache this session.
        consumed.lock().insert(600);
        tree.free_page(600);
        assert_eq!(tree.allocate_page(), 600);

        // The one page held back is still reported as freed this session.
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
        let mut tree = fresh_tree().await;
        let consumed = Arc::new(parking_lot::Mutex::new(FxHashSet::default()));
        tree.set_free_page_consumed(Arc::clone(&consumed));
        tree.set_reuse_threshold(N * 2);

        // Seed the sink at window scale *before* the frees, so every free below
        // pays the eligibility test against a full-size `consumed`.
        {
            let mut c = consumed.lock();
            for id in (N * 4)..(N * 4 + window as u64) {
                c.insert(id);
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
