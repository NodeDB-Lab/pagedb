//! The shared writer fields a candidate commit advances, held aside until the
//! header that makes them durable has been written.

use super::core::WriterState;

/// The subset of [`WriterState`] a commit must advance *before* it can know
/// whether it will succeed: the allocation cursor (advanced by materializing
/// the trees) and the commit-history root, version, and cached row count
/// (advanced by writing this commit's history entry).
///
/// The invariant this type exists to hold: **a candidate commit that does not
/// become durable must leave no trace in shared state.** Advancing the live
/// `WriterState` in place breaks it two ways. The allocation cursor would stay
/// advanced over pages the refused attempt bump-allocated and then discarded,
/// and the next *successful* commit would persist that inflated cursor — so
/// those ids end up below the durable cursor, referenced by no root and named
/// by no free-list entry, leaked for the life of the store. Worse, the
/// commit-history root would name a tree whose pages died with the failed
/// transaction's dirty set, so the next commit would open a root that was
/// never written.
///
/// So the commit path advances *this* copy and calls [`Self::publish`] only
/// once the A/B header naming these values is durable. Every fallible step
/// before that point may return with no unwind, because there is nothing to
/// unwind — which is also why a fallible check added between materialization
/// and the header write cannot reintroduce the leak.
#[derive(Clone, Copy)]
pub(crate) struct PendingWriterState {
    pub next_page_id: u64,
    pub commit_history_root_page_id: u64,
    pub commit_history_root_version: u64,
    pub commit_history_count: Option<u64>,
}

impl PendingWriterState {
    /// Start from what the still-durable header describes.
    pub(crate) fn capture(state: &WriterState) -> Self {
        Self {
            next_page_id: state.next_page_id,
            commit_history_root_page_id: state.commit_history_root_page_id,
            commit_history_root_version: state.commit_history_root_version,
            commit_history_count: state.commit_history_count,
        }
    }

    /// Fold the candidate's advances into the shared writer state. Call only
    /// after the header carrying these values is durable.
    pub(crate) fn publish(self, state: &mut WriterState) {
        state.next_page_id = self.next_page_id;
        state.commit_history_root_page_id = self.commit_history_root_page_id;
        state.commit_history_root_version = self.commit_history_root_version;
        state.commit_history_count = self.commit_history_count;
    }
}
