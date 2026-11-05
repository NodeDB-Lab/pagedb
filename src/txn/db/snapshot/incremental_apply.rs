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
            // Whatever this attempt produced went to the scratch or to the page
            // cache, never to `main.db`. Drop both so the base image is read
            // back from disk and no partially-built state survives the retry.
            // A cache fault here stays latched for the next operation, and the
            // caller receives the original error.
            self.pager.discard_dirty_main(self.realm_id);
            let _ = self.pager.reset_main_pages();
            discard_staged_image(&*self.vfs, &staged_image).await;
        }
        outcome
    }
}
