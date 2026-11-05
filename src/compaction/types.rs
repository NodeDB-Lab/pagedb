//! Public types describing compaction budgets, per-step progress, and
//! aggregate statistics returned by [`compact_now`](super::compact_now).

/// Per-call budget for [`Db::compact_step`](crate::Db::compact_step).
///
/// `compact_step` runs one atomic pass and ignores both fields. They remain
/// for interface stability.
#[non_exhaustive]
#[derive(Debug, Clone, Copy)]
pub struct CompactBudget {
    /// Intended page-relocation limit per call. `compact_step` ignores it.
    pub max_pages_relocated: u64,
    /// Intended wall-clock limit in milliseconds. `compact_step` ignores it.
    pub max_duration_ms: u64,
}

impl Default for CompactBudget {
    fn default() -> Self {
        Self {
            max_pages_relocated: 256,
            max_duration_ms: 500,
        }
    }
}

impl CompactBudget {
    /// Construct a `CompactBudget` with explicit limits.
    #[must_use]
    pub fn new(max_pages_relocated: u64, max_duration_ms: u64) -> Self {
        Self {
            max_pages_relocated,
            max_duration_ms,
        }
    }
}

/// Progress report returned by [`Db::compact_step`](crate::Db::compact_step).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Default)]
pub struct CompactProgress {
    /// Number of `main.db` pages reclaimed in this call.
    pub pages_relocated: u64,
    /// Bytes truncated from `main.db` in this call.
    pub bytes_freed: u64,
    /// Always `false`. One call runs the whole pass or declines.
    pub more_work: bool,
    /// Always `None`. `compact_step` keeps no resumable watermark.
    pub watermark: Option<u64>,
    /// True when compaction declined to run because a reader pinned the page
    /// range. See [`CompactStats::declined_readers_pinned`].
    ///
    /// `more_work` stays `false` in that case: another call does nothing until
    /// the readers drop, so a caller looping on `more_work` would spin.
    pub declined_readers_pinned: bool,
}

/// Statistics returned by [`Db::compact_now`](crate::Db::compact_now).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Default)]
pub struct CompactStats {
    /// Number of main.db pages reclaimed (moved to free-list or freed by
    /// repacking).
    pub main_db_pages_reclaimed: u64,
    /// Number of segment files repacked.
    pub segments_repacked: u32,
    /// Bytes truncated from main.db by moving the high-water-mark down.
    pub bytes_truncated: u64,
    /// True when compaction declined to run at all because a reader pinned the
    /// page range.
    ///
    /// Every other field is zero in that case, which is otherwise
    /// indistinguishable from a successful pass that found nothing to reclaim.
    /// A caller retrying on the strength of a zero result needs to know which
    /// one it got: one means "already dense", the other means "try again with
    /// no readers".
    pub declined_readers_pinned: bool,
}
