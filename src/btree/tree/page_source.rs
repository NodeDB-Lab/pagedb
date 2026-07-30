//! Where a write session's pages come from, supplied to a tree as one value.
//!
//! Reuse eligibility is decided when a page is freed, not when one is
//! allocated (see [`BTree::free_page`](super::core::BTree::free_page)). That is
//! only sound while every input to the decision is already in place at the
//! first free and cannot move afterwards, so the inputs travel together in
//! [`PageSource`] and are handed over once, at
//! [`BTree::open_session`](super::core::BTree::open_session). There is no
//! setter for any of them: a tree either has a session's page source for its
//! whole life or has none and bump-allocates.
//!
//! [`ConsumedPages`] carries the other half of that guarantee. A page recorded
//! there is eligible for in-session reuse, and pages already banked on the
//! strength of that record cannot be un-banked — so the sink must not shrink
//! while a session is running. Trees therefore hold a [`ConsumedHandle`], which
//! can record and test but cannot empty; emptying is [`ConsumedPages::take`],
//! reachable only from whoever owns the sink, at a transaction boundary.

use std::sync::Arc;

use rustc_hash::FxHashSet;

/// Page ids the allocator drew from the shared free-page cache and reused this
/// session. The commit path removes them from the durable free-list — they now
/// hold live committed data — and [`BTree::free_page`] consults them: a page
/// drawn from the cache is free as of the last durable header regardless of
/// what this session wrote to it, so it may be recycled again in-session even
/// from below the reuse threshold.
///
/// A set, not a list: membership is tested once per freed page, and the size is
/// bounded by the free-list window (`WINDOW_PAGES × chain_capacity(page_size)`)
/// rather than by anything small — a linear test would keep the per-free cost
/// proportional to that window. Nothing reads insertion order or needs
/// duplicates.
///
/// [`BTree::free_page`]: super::core::BTree::free_page
#[derive(Debug, Default)]
pub struct ConsumedPages(parking_lot::Mutex<FxHashSet<u64>>);

impl ConsumedPages {
    /// An empty sink, ready to be shared with a session's trees via
    /// [`Self::handle`].
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// A tree's view of this sink: record and test, never empty. Handing trees
    /// this instead of the `Arc` is what makes the sink's monotonicity within a
    /// session a property of the types rather than of caller discipline.
    #[must_use]
    pub fn handle(self: &Arc<Self>) -> ConsumedHandle {
        ConsumedHandle(Arc::clone(self))
    }

    /// Empty the sink and return what it held.
    ///
    /// A transaction-boundary operation, and the only way to empty it. Calling
    /// this while a session's trees are still allocating would strip the record
    /// that made already-banked pages eligible, leaving them banked on a reason
    /// that no longer exists — which is why no [`ConsumedHandle`] can reach it.
    pub fn take(&self) -> FxHashSet<u64> {
        std::mem::take(&mut *self.0.lock())
    }
}

/// A tree's handle on a session's [`ConsumedPages`]. Clone-shared across the
/// trees of one transaction.
#[derive(Clone, Debug)]
pub struct ConsumedHandle(Arc<ConsumedPages>);

impl ConsumedHandle {
    pub(crate) fn record(&self, page_id: u64) {
        self.0.0.lock().insert(page_id);
    }

    pub(crate) fn contains(&self, page_id: u64) -> bool {
        self.0.0.lock().contains(&page_id)
    }
}

/// The pages a write session may allocate from, beyond bumping its own cursor.
///
/// Constructed once per session and cloned to each of its trees, so a tree can
/// never observe a partly-wired source — a cache without the sink that records
/// draws from it, or a threshold arriving after pages have already been
/// classified against the default.
#[derive(Clone, Debug)]
pub struct PageSource {
    /// Minimum `page_id` that may be recycled from within this session. Pages
    /// below it existed before the session began: they are still referenced by
    /// the last durable header (a copy-on-write free does not unreference them
    /// on disk until the *next* header lands) and may also be pinned by reader
    /// snapshots, so their bytes must survive until the header that frees them
    /// is durable. They re-enter circulation through the deferred-free queue.
    ///
    /// Callers pass the session-start `next_page_id`, so only pages
    /// bump-allocated within the session are recyclable immediately. Zero means
    /// every freed page is (the commit-history tree, whose pages no reader
    /// snapshot names).
    pub(crate) reuse_threshold: u64,
    /// Cross-commit pool of reusable page ids, shared across the main, catalog
    /// and history trees of one `Db`. Loaded at `begin_write` with *only*
    /// free-list pages below the reclamation floor — pages no live reader and
    /// no retained-history root can observe — so drawing from it is safe
    /// regardless of `reuse_threshold`.
    ///
    /// Draw-only: nothing may push into it. The commit deletes a recycled id
    /// from the chain by finding it in the scanned window, so an id pushed in
    /// from elsewhere would be handed out while the unscanned tail still named
    /// it — the same page id given to two live structures.
    pub(crate) cache: Arc<parking_lot::Mutex<Vec<u64>>>,
    /// Where draws from `cache` are recorded.
    pub(crate) consumed: ConsumedHandle,
}

impl PageSource {
    /// Bind a session's allocation state to one value. `reuse_threshold` is the
    /// session-start `next_page_id` for trees a reader may hold a snapshot of,
    /// and zero for those none can.
    #[must_use]
    pub fn new(
        reuse_threshold: u64,
        cache: Arc<parking_lot::Mutex<Vec<u64>>>,
        consumed: &Arc<ConsumedPages>,
    ) -> Self {
        Self {
            reuse_threshold,
            cache,
            consumed: consumed.handle(),
        }
    }
}
