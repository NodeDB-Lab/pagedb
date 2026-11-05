//! `PagerInner`: shared cache state that `PageGuard` keeps reachable.

use std::sync::atomic::{AtomicU64, Ordering as AtomOrd};

use crate::pager::cache::{FileKey, PageCache};

/// Internal shared state. Stored in an `Arc` so `PageGuard` can keep the
/// cache reachable without borrowing the Pager.
pub(crate) struct PagerInner {
    pub(crate) buffer_pool: parking_lot::Mutex<PageCache>,
    pub(crate) segment_cache: parking_lot::Mutex<PageCache>,
    /// Cumulative cache hits on the buffer pool (main.db pages only).
    pub(crate) buffer_pool_hits: AtomicU64,
    /// Cumulative cache misses on the buffer pool (main.db pages only).
    pub(crate) buffer_pool_misses: AtomicU64,
    /// When `false`, `record_hit` and `record_miss` short-circuit before any
    /// atomic op. For embedders that don't poll
    /// [`DbStats`](crate::observability::DbStats).
    pub(crate) metrics_enabled: bool,
}

impl PagerInner {
    pub(crate) fn cache_for_key(&self, file: FileKey) -> &parking_lot::Mutex<PageCache> {
        match file {
            FileKey::Main => &self.buffer_pool,
            FileKey::ApplyJournal(_) => &self.segment_cache,
        }
    }

    /// Increment the hit counter for the given file class.
    pub(crate) fn record_hit(&self, file: FileKey) {
        if self.metrics_enabled && matches!(file, FileKey::Main) {
            self.buffer_pool_hits.fetch_add(1, AtomOrd::Relaxed);
        }
    }

    /// Increment the miss counter for the given file class.
    pub(crate) fn record_miss(&self, file: FileKey) {
        if self.metrics_enabled && matches!(file, FileKey::Main) {
            self.buffer_pool_misses.fetch_add(1, AtomOrd::Relaxed);
        }
    }
}
