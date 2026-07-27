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
    /// No reader is disturbed: the write that would need the pinned resources
    /// is refused instead. A commit blocked by the deferred-free backlog
    /// returns `PagedbError::DeferredFreeBacklog`; an apply whose segment
    /// tombstone a reader still pins returns
    /// `PagedbError::ReadersPinningTruncatedRange` and stays retryable.
    Reject,
    /// Free-list grows / tombstoned-but-pinned files accumulate. Batch /
    /// analytics workloads only.
    Unbounded,
}
