//! Miscellaneous handle accessors: mode predicates, page/file-size queries,
//! cache eviction, compaction entry points, and runtime statistics.

use crate::Result;
use crate::btree::BTree;
use crate::catalog::codec::{Catalog, CatalogRowKind};
use crate::observability::DbStats;
use crate::vfs::Vfs;

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
        Err(crate::errors::PagedbError::Unsupported)
    }

    /// Return the `next_page_id` from the current writer state.
    ///
    /// Intended for integration tests that need to know how many pages exist.
    pub async fn next_page_id(&self) -> u64 {
        self.writer.lock().await.next_page_id
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
        use crate::vfs::VfsFile;
        use crate::vfs::types::OpenMode;
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
        crate::compaction::compact_step(self, budget).await
    }

    /// Collect a point-in-time snapshot of database runtime metrics.
    pub async fn stats(&self) -> Result<DbStats> {
        use crate::vfs::VfsFile;
        use std::sync::atomic::Ordering as AtOrd;

        // Gather writer-guarded values.
        let (latest_commit_id, next_page_id, catalog_root, catalog_next) = {
            let w = self.writer.lock().await;
            (
                w.latest_commit_id,
                w.next_page_id,
                w.catalog_root_page_id,
                w.next_page_id,
            )
        };

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

        // Segment stats and free-list counts from catalog.
        let (segments_live, segments_total_bytes, free_list_pending_entries) = if catalog_root == 0
        {
            (0u32, 0u64, 0u64)
        } else {
            let tree = BTree::open(
                self.pager.clone(),
                self.realm_id,
                catalog_root,
                catalog_next,
                self.page_size,
            );

            // Segments.
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

            // Free-list entries (persistent free-list rows).
            let fl_start = vec![CatalogRowKind::FreeList as u8];
            let mut fl_end = fl_start.clone();
            fl_end.push(0xFF);
            let fl_rows = tree
                .collect_range(&fl_start, &fl_end)
                .await
                .unwrap_or_default();
            let fl_count = fl_rows.len() as u64;

            // Deferred-free entries.
            let df_key = Catalog::deferred_free_key();
            let df_count = match tree.get(&df_key).await {
                Ok(Some(bytes)) => {
                    Catalog::decode_deferred_free(&bytes).map_or(0, |v| v.len() as u64)
                }
                _ => 0,
            };

            (seg_count, seg_bytes, fl_count + df_count)
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
