//! Live apply-journal reconciliation after an incremental header swap.

use crate::errors::PagedbError;
use crate::pager::header::commit_header;
use crate::pager::structural_header::MainDbHeaderFields;
use crate::vfs::Vfs;
use crate::{CommitId, Result};

use super::core::{Db, WriterState, encode_free_list_root, encode_root_ref};
use super::segment::SegmentReconciliation;
use super::util::page_size_log2;

impl<V: Vfs + Clone> Db<V> {
    /// Retry the journal named by the current durable header. The pointer stays
    /// live until all promotions and tombstones have completed. A reader-pinned
    /// tombstone is safe to publish, but blocks later applies until GC drains it.
    pub(crate) async fn retry_pending_apply_journal(&self) -> Result<()> {
        let mut state = self.writer.lock().await;
        // Keep reader admission closed while pin-aware journal reconciliation,
        // header clear, and snapshot publication make the target visible.
        let _visibility = self.visibility_gate.write().await;
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
                self.publish_snapshot(&state);
                return Err(PagedbError::ReadersPinningTruncatedRange);
            }
            SegmentReconciliation::Complete => {}
        }

        let next_seq = state
            .seq
            .checked_add(1)
            .ok_or_else(|| PagedbError::arithmetic_overflow("apply-journal clear sequence"))?;
        let counter_anchor = self.pager.pending_anchor();
        let fields = cleared_header_fields(self, &state, next_seq, counter_anchor)?;
        let hk = self.hk.read().clone();
        let Ok(next_slot) = commit_header(
            &*self.vfs,
            &self.main_db_path,
            &hk,
            &fields,
            state.active_slot,
            self.page_size,
        )
        .await
        else {
            let commit = CommitId(state.latest_commit_id);
            self.poison(commit);
            return Err(PagedbError::durably_committed_but_unpublished(commit));
        };

        if self.pager.commit_anchor(counter_anchor).is_err() {
            let commit = CommitId(state.latest_commit_id);
            self.poison(commit);
            return Err(PagedbError::durably_committed_but_unpublished(commit));
        }

        state.active_slot = next_slot;
        state.seq = next_seq;
        state.pending_apply_journal_id = [0; 16];
        self.publish_snapshot(&state);
        drop(state);

        // The clear header and anchor are durable before the sidecar becomes
        // an orphan. Removal is cleanup: a later open retries an orphan sweep.
        if let Err(error) = self.pager.remove_journal(journal_id).await {
            tracing::debug!(name = "apply_journal.orphan", error = %error, "retaining recoverable apply-journal orphan");
        }
        Ok(())
    }
}

fn cleared_header_fields<V: Vfs + Clone>(
    db: &Db<V>,
    state: &WriterState,
    seq: u64,
    counter_anchor: u64,
) -> Result<MainDbHeaderFields> {
    Ok(MainDbHeaderFields {
        format_version: 1,
        cipher_id: db.cipher_id.as_byte(),
        page_size_log2: page_size_log2(db.page_size)?,
        flags: 0,
        file_id: db.file_id,
        kek_salt: db.kek_salt,
        mk_epoch: db.mk_epoch.load(std::sync::atomic::Ordering::SeqCst),
        seq,
        active_root_page_id: state.root_page_id,
        active_root_txn_id: state.latest_commit_id,
        counter_anchor,
        commit_id: CommitId(state.latest_commit_id),
        free_list_root: encode_free_list_root(state.free_list_root_page_id),
        catalog_root: encode_root_ref(state.catalog_root_page_id, state.catalog_root_txn_id),
        apply_journal_root_page_id: 0,
        apply_journal_root_version: 0,
        commit_history_root_page_id: state.commit_history_root_page_id,
        commit_history_root_version: state.commit_history_root_version,
        restore_mode: state.restore_mode,
        next_page_id: state.next_page_id,
        commit_retain_policy_tag: state.commit_retain_policy_tag,
        commit_retain_policy_value: state.commit_retain_policy_value,
    })
}
