// SPDX-License-Identifier: Apache-2.0

//! Follower incremental apply orchestration.

use super::super::core::Db;
use crate::snapshot::apply::{discard_staged_image, staged_image_path};
use crate::txn::mode::DbMode;
use crate::vfs::Vfs;

impl<V: Vfs + Clone> Db<V> {
    /// Apply an incremental snapshot to this Follower handle.
    ///
    /// The target state is assembled in a staged copy of `main.db` and renamed
    /// over it. That rename is the operation's only commit point: an apply
    /// interrupted before it leaves the follower wholly at its base commit, and
    /// one interrupted after it leaves the follower wholly at the target. There
    /// is no ordering in between that can produce a mix of the two.
    ///
    /// # Registered readers
    ///
    /// An apply never overwrites a page a registered reader can reach, so a
    /// reader always sees its own snapshot.
    ///
    /// A reader pinned at the base commit never conflicts. A delta cannot name a
    /// page the base reaches. A reader pinned further back can reach a page a
    /// later commit freed and the producer recycled. An apply whose delta
    /// rewrites such a page returns
    /// [`PagedbError::ApplyBlockedByPinnedReader`](crate::PagedbError::ApplyBlockedByPinnedReader).
    /// A reader whose pages cannot be walked counts as a conflict too.
    ///
    /// The refusal changes nothing in `main.db`. The handle stays at its base
    /// commit. Finish that reader and call this again with the same delta. The
    /// reader stall policy does not change this outcome.
    ///
    /// Each distinct pinned state older than the base costs one walk of its data
    /// and catalog trees, twice per apply. The second walk runs with reader
    /// admission closed. An apply with no such reader walks nothing extra.
    ///
    /// # Retained commits
    ///
    /// An apply prunes the retained commits it overwrote, so
    /// [`begin_read_at`](Self::begin_read_at) reports
    /// [`PagedbError::CommitGone`](crate::PagedbError::CommitGone) for them.
    /// The newest such commit and every older commit leave the history together.
    /// A retained commit that cannot be walked counts as overwritten. A commit
    /// that survives an apply still reads its own values, after a reopen too.
    /// A reader already open on a pruned commit stays valid, because the apply
    /// refuses to rewrite a page it can reach.
    ///
    /// The screen reads each retained page the base does not reach once per apply.
    /// It runs with reader admission closed. A delta with no pages reads nothing.
    pub async fn apply_incremental(
        &self,
        src_path: &std::path::Path,
    ) -> crate::Result<crate::snapshot::ApplyStats> {
        self.ensure_usable()?;
        let _span = tracing::debug_span!("snapshot.apply");

        self.require_mode(
            "apply_incremental",
            DbMode::Follower,
            crate::txn::db::DbModeCapabilities::applies_incremental_snapshots,
        )?;
        // An apply owns the complete protocol, including recovery, validation,
        // image staging, and post-header reconciliation. A waiting caller
        // re-checks poison state after it acquires the gate.
        let _apply_guard = self.apply_gate.lock().await;
        self.ensure_usable()?;

        // A durable target with an uncleared journal must converge before a
        // later apply can overwrite its retry pointer or staging set.
        self.retry_pending_apply_journal().await?;

        let staged_image = staged_image_path(&self.main_db_path);
        // A scratch left behind by an interrupted apply describes a state no
        // durable header names. It is never resumed, only rebuilt: its base may
        // predate the commit this attempt is starting from.
        discard_staged_image(&*self.vfs, &staged_image).await;

        let outcome = self
            .stage_and_swap_incremental(src_path, &staged_image)
            .await;
        if outcome.is_err() {
            self.discard_failed_apply(&staged_image).await;
        }
        outcome
    }

    /// Drop what a failed apply left behind.
    ///
    /// Whatever the attempt produced went to the scratch or to the page cache,
    /// never to `main.db`. Dropping both makes the base image read back from
    /// disk, so no partially-built state survives the retry.
    ///
    /// The apply released the writer lock when it failed. Dirty pages present
    /// now can belong to another writer, so this waits for the lock. A writer
    /// flushes before it releases, so every dirty page left under the lock is
    /// this apply's.
    ///
    /// A cache fault here stays latched for the next operation, and the caller
    /// receives the original error.
    pub(super) async fn discard_failed_apply(&self, staged_image: &str) {
        let _writer = self.writer.lock().await;
        self.pager.discard_dirty_main();
        // Deliberate discard: a cache fault stays latched and the next operation
        // reports it. The caller returns the original error.
        let _ = self.pager.reset_main_pages();
        discard_staged_image(&*self.vfs, staged_image).await;
    }
}
