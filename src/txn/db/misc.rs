//! Miscellaneous handle accessors: mode predicates, page/file-size queries,
//! cache eviction, compaction entry points, and runtime statistics.

use crate::Result;
use crate::btree::BTree;
use crate::catalog::codec::{Catalog, CatalogRowKind};
use crate::crypto::SecretKey;
use crate::errors::PagedbError;
use crate::observability::DbStats;
use crate::vfs::types::OpenMode;
use crate::vfs::{Vfs, VfsFile};
use std::sync::atomic::Ordering as AtOrd;

use super::super::mode::DbMode;
use super::core::Db;

/// Segment catalog rows read per batch while aggregating `stats()`. Rows are a
/// fixed-width authenticated value, so this is a few KiB resident regardless of
/// how many segments a realm has linked.
const SEGMENT_ROW_BATCH: usize = 512;

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
    pub fn rekey_into_writer(self, new_kek: impl Into<SecretKey>) -> Result<Self> {
        let _new_kek = new_kek.into();
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
    /// Returns a [`crate::CompactStats`] summary of what was reclaimed.
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
    /// Returns a [`crate::CompactProgress`] describing what was done and
    /// whether more work remains. Loop until `progress.more_work == false` to
    /// compact fully.
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
        // Counted in place rather than collected: how many pages the free list
        // is carrying grows with the database, and a metrics call must not size
        // an allocation by it.
        let free_list_pending_entries =
            crate::pager::freelist::count_chain(&self.pager, self.realm_id, free_list_root).await?;

        // Main database file size.
        let main_db_bytes = self
            .vfs
            .open(&self.main_db_path, crate::vfs::types::OpenMode::Read)
            .await?
            .len()
            .await?;

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

            // Streamed in bounded batches: how many segments a realm has linked
            // is the embedder's business, and a metrics call must not size an
            // allocation by it.
            let seg_prefix = [CatalogRowKind::Segment as u8];
            let mut cursor: Vec<u8> = seg_prefix.to_vec();
            let mut seg_count = 0u32;
            let mut seg_bytes = 0u64;
            loop {
                let batch = tree
                    .collect_prefix_batch_from(&seg_prefix, &cursor, SEGMENT_ROW_BATCH)
                    .await?;
                let Some((last_key, _)) = batch.last() else {
                    break;
                };
                cursor.clear();
                cursor.extend_from_slice(last_key);
                cursor.push(0);
                let exhausted = batch.len() < SEGMENT_ROW_BATCH;

                for (_key, value) in &batch {
                    seg_count = seg_count.saturating_add(1);
                    seg_bytes = seg_bytes
                        .checked_add(Catalog::decode_segment_meta(value)?.total_bytes)
                        .ok_or_else(|| {
                            PagedbError::arithmetic_overflow("stats.segments_total_bytes")
                        })?;
                }
                if exhausted {
                    break;
                }
            }

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

#[cfg(test)]
mod tests {
    use crate::btree::BTree;
    use crate::catalog::codec::Catalog;
    use crate::vfs::memory::MemVfs;
    use crate::{Db, PagedbError, RealmId, SegmentKind, SegmentPageKind};

    const PAGE: usize = 4096;
    const REALM: RealmId = RealmId::new([0xA5; 16]);

    #[tokio::test(flavor = "current_thread")]
    async fn stats_surfaces_malformed_segment_catalog_row() {
        let db = Db::open_internal(MemVfs::new(), [9u8; 32], PAGE, REALM)
            .await
            .unwrap();
        let mut segment = db
            .create_segment(REALM, SegmentKind::Unspecified)
            .await
            .unwrap();
        segment
            .append_page(SegmentPageKind::Data, b"stats")
            .await
            .unwrap();
        let meta = segment.seal().await.unwrap();
        {
            let mut txn = db.begin_write().await.unwrap();
            txn.link_segment("good", &meta).await.unwrap();
            txn.commit().await.unwrap();
        }

        let (catalog_root, next_page_id) = {
            let state = db.writer.lock().await;
            (state.catalog_root_page_id, state.next_page_id)
        };
        let mut tree = BTree::open(
            db.pager.clone(),
            db.realm_id,
            catalog_root,
            next_page_id,
            db.page_size,
        );
        tree.put(
            &Catalog::segment_key(REALM, b"bad").unwrap(),
            b"not a segment meta",
        )
        .await
        .unwrap();
        tree.flush().await.unwrap();
        {
            let mut state = db.writer.lock().await;
            state.catalog_root_page_id = tree.root_page_id();
            state.next_page_id = state.next_page_id.max(tree.next_page_id());
            db.publish_snapshot(&state);
        }

        let err = db
            .stats()
            .await
            .expect_err("malformed segment metadata must surface");
        assert!(matches!(err, PagedbError::Corruption(_)));
    }
}
