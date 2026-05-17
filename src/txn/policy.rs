//! Reader stall policy: how the writer reacts when reader pins block
//! reclamation.

/// What to do when an open reader pins resources the writer needs to reclaim.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ReaderStallPolicy {
    /// Oldest conflicting user reader's next op returns `PagedbError::Aborted`.
    /// Default. Internal readers with `non_abortable = true` are exempt.
    #[default]
    AbortOldest,
    /// New writes return `FreeListExhausted` / `SegmentTombstoneStalled` /
    /// `ReadersPinningTruncatedRange`. Readers continue.
    Reject,
    /// Free-list grows / tombstoned-but-pinned files accumulate. Batch /
    /// analytics workloads only.
    Unbounded,
}
