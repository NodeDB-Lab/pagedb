//! Garbage collection: deferred-tombstone draining and physical deletion.

use crate::Result;
use crate::segment::types::GcStats;
use crate::vfs::Vfs;

use super::core::{Db, PendingTombstone};

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
        let (drained, drained_bytes) = self.try_drain_pending_tombstones().await?;
        // Retirement reclaims each file as it happens, so the drain above is
        // where almost everything is freed. The sweep still runs because a
        // crash between the rename and the removal leaves a file parked here.
        let (swept, swept_bytes) = crate::recovery::gc::delete_tombstone_files(&*self.vfs).await?;
        Ok(GcStats {
            reclaimed_segments: drained.saturating_add(swept),
            reclaimed_bytes: drained_bytes.saturating_add(swept_bytes),
        })
    }

    /// Re-evaluate every pending tombstone, reclaiming each segment that no
    /// reader pins any more. Returns `(segments, bytes)` reclaimed.
    ///
    /// Entries still pinned are put back for a later attempt. Normal commits
    /// drain this queue too, so reaching it here is the exception rather than
    /// the mechanism.
    ///
    /// An entry whose reclamation fails is put back as well, along with every
    /// entry this call had taken but not yet reached. The queue is the only
    /// record that a retired file still needs deleting, so dropping an entry on
    /// an I/O error leaks that file for the life of the store — and the caller
    /// surfaces the error, so a retry has somewhere to resume from.
    async fn try_drain_pending_tombstones(&self) -> Result<(u64, u64)> {
        let pending = std::mem::take(&mut *self.pending_tombstones.lock());
        let mut count: u64 = 0;
        let mut bytes: u64 = 0;
        let mut pending = pending.into_iter();
        while let Some(entry) = pending.next() {
            match self.reclaim_pending_tombstone(&entry).await {
                Ok(None) => {}
                Ok(Some(len)) => {
                    count += 1;
                    bytes = bytes.saturating_add(len);
                }
                Err(error) => {
                    self.enqueue_pending_tombstone(entry);
                    for remaining in pending {
                        self.enqueue_pending_tombstone(remaining);
                    }
                    return Err(error);
                }
            }
        }
        Ok((count, bytes))
    }

    /// Reclaim one deferred tombstone, returning the bytes freed, or `None`
    /// when nothing was reclaimed — because a reader still pins the segment, or
    /// because a commit-time retirement already deleted the file. Counting the
    /// latter would report space freed that this call did not free.
    async fn reclaim_pending_tombstone(&self, entry: &PendingTombstone) -> Result<Option<u64>> {
        if self.segment_id_is_reader_pinned(entry.segment_id).await? {
            self.enqueue_pending_tombstone(entry.clone());
            return Ok(None);
        }
        // Measured before reclaiming — afterwards the file is gone.
        let len = self.live_segment_len(entry.segment_id).await?;
        let effects = [crate::txn::write::SegmentSideEffect::Tombstone {
            segment_id: entry.segment_id,
            tombstone_commit_id: None,
        }];
        self.reconcile_segment_effects(&effects, entry.commit_id)
            .await?;
        Ok(len)
    }
}
