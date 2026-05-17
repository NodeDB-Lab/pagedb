//! Public types describing compaction budgets, per-step progress, and
//! aggregate statistics returned by [`compact_now`](super::compact_now).

/// Per-call budget for [`Db::compact_step`](crate::Db::compact_step).
///
/// Both fields bound the work done in a single call. The call releases the
/// writer lock once either limit is reached or no more work remains.
#[non_exhaustive]
#[derive(Debug, Clone, Copy)]
pub struct CompactBudget {
    /// Maximum number of pages that may be relocated (written to new
    /// low-address slots) in a single call.
    pub max_pages_relocated: u64,
    /// Wall-clock time limit in milliseconds. The call checks this after each
    /// batch commit and returns early if the budget is exhausted.
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
    /// Number of pages relocated in this call.
    pub pages_relocated: u64,
    /// Bytes freed (truncated) in this call. Non-zero only on the final step.
    pub bytes_freed: u64,
    /// `true` if at least one more call to `compact_step` is needed to finish.
    pub more_work: bool,
    /// The `frontier_page_id` persisted to the catalog watermark after this
    /// call. `None` if the compaction session is complete (watermark cleared).
    pub watermark: Option<u64>,
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
}
