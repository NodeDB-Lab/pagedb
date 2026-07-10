//! Garbage collection: deferred-tombstone draining and physical deletion.

use crate::Result;
use crate::segment::types::GcStats;
use crate::vfs::Vfs;

use super::core::Db;

impl<V: Vfs + Clone> Db<V> {
    /// Process pending deferred tombstones and delete files in `seg/.tombstone/`.
    /// Returns statistics on reclaimed segments and bytes.
    pub async fn gc_now(&self) -> Result<GcStats> {
        self.ensure_usable()?;
        let _span = tracing::debug_span!("gc.run");
        self.retry_pending_apply_journal().await?;
        // Writer before visibility is the global destructive-operation order.
        // Keep the gate through pin evaluation, rename, directory sync, and
        // physical tombstone deletion.
        let _writer = self.writer.lock().await;
        let _visibility = self.visibility_gate.write().await;
        self.try_drain_pending_tombstones().await?;
        let (count, bytes) = crate::recovery::gc::delete_tombstone_files(&*self.vfs).await?;
        Ok(GcStats {
            reclaimed_segments: count,
            reclaimed_bytes: bytes,
        })
    }

    /// Re-evaluate each pending tombstone. If a segment is no longer pinned by
    /// any tracked reader, rename it from the live path to the tombstone
    /// directory now.
    async fn try_drain_pending_tombstones(&self) -> Result<()> {
        let pending = std::mem::take(&mut *self.pending_tombstones.lock());
        for entry in pending {
            if self.segment_id_is_reader_pinned(entry.segment_id).await? {
                self.enqueue_pending_tombstone(entry);
                continue;
            }
            let effects = [crate::txn::write::SegmentSideEffect::Tombstone {
                segment_id: entry.segment_id,
                tombstone_commit_id: None,
            }];
            self.reconcile_segment_effects(&effects, entry.commit_id)
                .await?;
        }
        Ok(())
    }
}
