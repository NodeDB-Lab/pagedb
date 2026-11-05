//! Live apply-journal reconciliation after an incremental header swap.

use crate::errors::PagedbError;
use crate::pager::anchor::HeaderCursor;
use crate::pager::header::commit_header;
use crate::vfs::Vfs;
use crate::{CommitId, Result};

use super::core::{Db, WriterState};
use super::segment::SegmentReconciliation;

impl<V: Vfs + Clone> Db<V> {
    /// Retry the journal named by the current durable header. The pointer stays
    /// live until all promotions and tombstones have completed. A reader-pinned
    /// tombstone is safe to publish, but blocks later applies until GC drains it.
    pub(crate) async fn retry_pending_apply_journal(&self) -> Result<()> {
        let mut state = self.writer.lock().await;
        // Keep reader admission closed while pin-aware journal reconciliation,
        // header clear, and snapshot publication make the target visible.
        // Writer before visibility is the global destructive-operation order.
        let visibility = self.visibility_gate.write().await;
        self.ensure_usable()?;
        self.retry_pending_apply_journal_visible(&mut state, &visibility)
            .await
    }

    /// Reconcile the pending journal while the caller already holds both the
    /// writer state and the visibility gate.
    ///
    /// Splitting the guards out is what lets an incremental apply keep reader
    /// admission closed continuously from before its image swap through this
    /// publication. Two things in this window are not safe to expose:
    /// `tombstone_segment` decides defer-versus-delete from a scan of
    /// `tracked_readers` and then renames the live file away, so a reader that
    /// registered after the scan would hold a base catalog naming a file that
    /// no longer exists; and until `publish_snapshot` runs, the live `main.db`
    /// is the target image while the published snapshot still names base
    /// roots. Releasing and re-taking the gate here would reopen exactly that
    /// window.
    pub(crate) async fn retry_pending_apply_journal_visible(
        &self,
        state: &mut WriterState,
        _visibility: &tokio::sync::RwLockWriteGuard<'_, ()>,
    ) -> Result<()> {
        let journal_id = state.pending_apply_journal_id;
        if journal_id == [0; 16] {
            return Ok(());
        }

        let Ok(Some(record)) =
            crate::recovery::journal::replay_apply_journal(&self.pager, self.realm_id, journal_id)
                .await
        else {
            let commit = CommitId(state.latest_commit_id);
            self.poison(commit);
            return Err(PagedbError::durably_committed_but_unpublished(commit));
        };

        let Ok(reconciliation) = self.reconcile_journal_actions(&record.actions).await else {
            let commit = CommitId(state.latest_commit_id);
            self.poison(commit);
            return Err(PagedbError::durably_committed_but_unpublished(commit));
        };
        match reconciliation {
            SegmentReconciliation::Deferred => {
                // Every promote has completed before reconciliation can report
                // a deferred tombstone, so target readers may now attach while
                // the durable pointer keeps the delete work retryable.
                self.publish_snapshot(state);
                return Err(PagedbError::ReadersPinningTruncatedRange);
            }
            SegmentReconciliation::Complete => {}
        }
        // Inside the window: the pin scan has run and the tombstone rename has
        // happened, and the target is not published yet.
        #[cfg(test)]
        self.pause_in_apply_publication_window().await;

        let header_cursor = self.pager.header_cursor()?;
        let next_seq = header_cursor.next_seq()?;
        let counter_anchor = self.pager.pending_anchor();
        let fields = self.state_header_fields(state, next_seq, counter_anchor)?;
        let hk = self.hk.read().clone();
        let Ok(next_slot) = commit_header(
            &*self.vfs,
            &self.main_db_path,
            &hk,
            &fields,
            header_cursor.slot,
            self.page_size,
        )
        .await
        else {
            let commit = CommitId(state.latest_commit_id);
            self.poison(commit);
            return Err(PagedbError::durably_committed_but_unpublished(commit));
        };
        self.pager.note_header_written(HeaderCursor {
            slot: next_slot,
            seq: next_seq,
        });

        if self.pager.commit_anchor(counter_anchor).is_err() {
            let commit = CommitId(state.latest_commit_id);
            self.poison(commit);
            return Err(PagedbError::durably_committed_but_unpublished(commit));
        }

        state.pending_apply_journal_id = [0; 16];
        self.publish_snapshot(state);

        // The clear header and anchor are durable before the sidecar becomes
        // an orphan. Removal is cleanup: a later open retries an orphan sweep.
        if let Err(error) = self.pager.remove_journal(journal_id).await {
            tracing::debug!(name = "apply_journal.orphan", error = %error, "retaining recoverable apply-journal orphan");
        }
        Ok(())
    }
}
