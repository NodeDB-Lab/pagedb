//! Garbage collection: deferred-tombstone draining and reader-pin-delete
//! draining.

use std::sync::atomic::Ordering;

use crate::Result;
use crate::segment::types::GcStats;
use crate::vfs::Vfs;

use super::super::read::{delete_pin_rows, make_pin_handle};
use super::core::{Db, PendingTombstone};

impl<V: Vfs + Clone> Db<V> {
    /// Drain any reader-pin rows that were queued for deletion by dropped
    /// `ReadTxn` handles. Called by `gc_now` and can be called by callers that
    /// want to reclaim catalog space between compaction cycles.
    pub async fn drain_pending_pin_deletes(&self) -> Result<()> {
        let to_delete: Vec<(u32, u64)> = {
            let mut pending = self.pending_pin_deletes.lock();
            std::mem::take(&mut *pending)
        };
        if to_delete.is_empty() {
            return Ok(());
        }
        let pin = make_pin_handle(
            self.pager.clone(),
            self.realm_id,
            self.page_size,
            self.main_db_path.clone(),
            self.vfs.clone(),
            self.hk.read().clone(),
            self.mk_epoch.load(Ordering::SeqCst),
            self.cipher_id,
            self.file_id,
            self.kek_salt,
            self.latest_commit.load(Ordering::SeqCst),
            self.snapshot.clone(),
            std::process::id(),
            0, // lease_id unused for bulk deletes
            30,
        );
        let mut state = self.writer.lock().await;
        delete_pin_rows(&pin, &mut state, &to_delete).await
    }

    /// Process pending deferred tombstones and delete files in `seg/.tombstone/`.
    /// Returns statistics on reclaimed segments and bytes.
    pub async fn gc_now(&self) -> Result<GcStats> {
        let _span = tracing::debug_span!("gc.run");
        self.try_drain_pending_tombstones().await?;
        // Best-effort: drain any queued reader-pin deletes.
        let _ = self.drain_pending_pin_deletes().await;
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
        let pending = self.pending_tombstones.lock().clone();
        let mut still_pending: Vec<PendingTombstone> = Vec::new();
        for entry in pending {
            if self.segment_id_is_reader_pinned(entry.segment_id).await? {
                still_pending.push(entry);
                continue;
            }
            let live = format!("seg/{}", crate::hex::to_hex_lower(&entry.segment_id));
            let tomb = format!(
                "seg/.tombstone/{}.{}",
                crate::hex::to_hex_lower(&entry.segment_id),
                entry.commit_id
            );
            self.vfs.mkdir_all("seg/.tombstone").await?;
            // The file may have already been moved (e.g., by reconciliation).
            // Ignore rename errors in that case.
            self.vfs.rename(&live, &tomb).await.ok();
            self.vfs.sync_dir("seg/.tombstone").await.ok();
        }
        *self.pending_tombstones.lock() = still_pending;
        Ok(())
    }
}
