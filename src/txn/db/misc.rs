//! Miscellaneous handle accessors: mode predicates, page/file-size queries,
//! cache eviction, compaction entry points, and runtime statistics.

use crate::Result;
use crate::btree::BTree;
use crate::catalog::codec::{Catalog, CatalogRowKind};
use crate::observability::DbStats;
use crate::vfs::types::OpenMode;
use crate::vfs::{Vfs, VfsFile};
use std::sync::atomic::Ordering as AtOrd;

use super::super::mode::DbMode;
use super::core::Db;

impl<V: Vfs + Clone> Db<V> {
    /// Return the mode this handle was opened with.
    pub fn mode(&self) -> DbMode {
        self.mode
    }

    /// Returns `true` iff this handle is a full writer (Standalone mode).
    pub fn is_writer(&self) -> bool {
        matches!(self.mode, DbMode::Standalone)
    }

    /// Returns `true` iff `apply_incremental` is callable on this handle
    /// (Follower mode only).
    pub fn can_apply_incremental(&self) -> bool {
        matches!(self.mode, DbMode::Follower)
    }

    /// Returns `true` iff `rekey_into_writer` is callable on this handle
    /// (`ReadOnly` or Follower).
    pub fn can_rekey_into_writer(&self) -> bool {
        matches!(self.mode, DbMode::ReadOnly | DbMode::Follower)
    }

    /// Stub: rekey a restored `Db` (`ReadOnly` or Follower) into a Standalone writer.
    /// Full implementation is out of scope for this slice.
    pub fn rekey_into_writer(self, _new_kek: [u8; 32]) -> Result<Self> {
        self.ensure_usable()?;
        Err(crate::errors::PagedbError::Unsupported)
    }

    /// Return the `next_page_id` from the current writer state.
    ///
    /// Intended for integration tests that need to know how many pages exist.
    #[allow(clippy::unused_async)] // async signature preserved for API stability
    pub async fn next_page_id(&self) -> u64 {
        self.snapshot.read().next_page_id
    }

    /// Evict all clean and dirty pages for the main realm from the buffer
    /// pool. Intended for integration tests that corrupt pages on disk and
    /// want subsequent reads to see the disk contents rather than cached data.
    pub fn evict_main_pages(&self, realm: crate::RealmId) {
        self.pager.discard_dirty_main(realm);
    }

    /// Return the current size of `main.db` in bytes. Useful for tests that
    /// verify compaction shrinks the file.
    pub async fn main_db_byte_size(&self) -> Result<u64> {
        self.ensure_usable()?;
        let f = self.vfs.open(&self.main_db_path, OpenMode::Read).await?;
        f.len().await
    }

    /// Perform online compaction.
    ///
    /// Drains eligible deferred-free pages into the persistent free-list,
    /// repacks the main and catalog B+ trees into densely-allocated page space,
    /// truncates `main.db` if no reader pins the old high-water range, and
    /// repacks segment files whose garbage ratio exceeds 5%.
    ///
    /// Returns a [`CompactStats`] summary of what was reclaimed.
    pub async fn compact_now(&self) -> Result<crate::compaction::CompactStats> {
        self.ensure_usable()?;
        crate::compaction::compact_now(self).await
    }

    /// Perform one incremental compaction step bounded by `budget`.
    ///
    /// Each call holds the writer lock for at most one batch commit, then
    /// releases. The compaction watermark is persisted to the catalog after
    /// each call, so a crash mid-compaction is safe: call `compact_step` again
    /// after reopening to resume from where it left off.
    ///
    /// Returns a [`CompactProgress`] describing what was done and whether more
    /// work remains. Loop until `progress.more_work == false` to compact fully.
    pub async fn compact_step(
        &self,
        budget: crate::compaction::CompactBudget,
    ) -> Result<crate::compaction::CompactProgress> {
        self.ensure_usable()?;
        crate::compaction::compact_step(self, budget).await
    }

    /// Collect a point-in-time snapshot of database runtime metrics.
    pub async fn stats(&self) -> Result<DbStats> {
        // Stats that describe reader-visible state must use the publication
        // snapshot, which remains at the prior commit while a handle is
        // poisoned after a post-header reconciliation failure.
        let snapshot = *self.snapshot.read();
        let (next_page_id, catalog_root, catalog_next, free_list_root) = (
            snapshot.next_page_id,
            snapshot.catalog_root_page_id,
            snapshot.next_page_id,
            snapshot.free_list_root_page_id,
        );
        let latest_commit_id = snapshot.commit_id;

        // Durable free-list depth (chain rooted at the header's free_list_root).
        let free_list_pending_entries =
            crate::pager::freelist::read_chain(&self.pager, self.realm_id, free_list_root)
                .await
                .map_or(0, |(entries, _)| entries.len() as u64);

        // Main database file size.
        let main_db_bytes = match self
            .vfs
            .open(&self.main_db_path, crate::vfs::types::OpenMode::Read)
            .await
        {
            Ok(f) => f.len().await.unwrap_or(0),
            Err(_) => 0,
        };

        // Buffer pool stats from cache.
        let buffer_pool_pages = { self.pager.inner.buffer_pool.lock().len() as u64 };
        let buffer_pool_hits = self.pager.inner.buffer_pool_hits.load(AtOrd::Relaxed);
        let buffer_pool_misses = self.pager.inner.buffer_pool_misses.load(AtOrd::Relaxed);

        // Dirty pages across both cache classes.
        let dirty_pages = {
            let bp = self.pager.inner.buffer_pool.lock();
            let sc = self.pager.inner.segment_cache.lock();
            (bp.dirty_for_file(crate::pager::core::FileKey::Main).len()
                + sc.dirty_for_file(crate::pager::core::FileKey::Segment([0u8; 16]))
                    .len()) as u64
        };

        // Tracked readers.
        let tracked_readers = u32::try_from(self.tracked_readers.lock().len()).unwrap_or(u32::MAX);

        // Pending tombstones.
        let pending_tombstones =
            u32::try_from(self.pending_tombstones.lock().len()).unwrap_or(u32::MAX);

        // Segment stats from catalog.
        let (segments_live, segments_total_bytes) = if catalog_root == 0 {
            (0u32, 0u64)
        } else {
            let tree = BTree::open(
                self.pager.clone(),
                self.realm_id,
                catalog_root,
                catalog_next,
                self.page_size,
            );

            let seg_start = vec![CatalogRowKind::Segment as u8];
            let mut seg_end = seg_start.clone();
            seg_end.push(0xFF);
            let seg_rows = tree
                .collect_range(&seg_start, &seg_end)
                .await
                .unwrap_or_default();
            let seg_count = u32::try_from(seg_rows.len()).unwrap_or(u32::MAX);
            let seg_bytes: u64 = seg_rows
                .iter()
                .filter_map(|(_k, v)| Catalog::decode_segment_meta(v).ok())
                .map(|m| m.total_bytes)
                .sum();

            (seg_count, seg_bytes)
        };

        Ok(DbStats {
            latest_commit_id,
            mode: self.mode,
            main_db_bytes,
            main_db_next_page_id: next_page_id,
            buffer_pool_pages,
            buffer_pool_hits,
            buffer_pool_misses,
            dirty_pages,
            tracked_readers,
            pending_tombstones,
            segments_live,
            segments_total_bytes,
            mmap_bytes_in_use: self.mmap_bytes_in_use.load(AtOrd::Relaxed),
            mk_epoch: self.mk_epoch.load(AtOrd::SeqCst),
            free_list_pending_entries,
            spill_bytes_in_use: self.spill_bytes_in_use.load(AtOrd::Relaxed),
        })
    }
}
