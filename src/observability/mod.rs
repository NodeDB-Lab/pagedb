//! Runtime observability: `DbStats` and supporting helpers.

use crate::txn::mode::DbMode;

/// Point-in-time snapshot of database runtime metrics.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct DbStats {
    /// Commit sequence number of the most recently committed write transaction.
    pub latest_commit_id: u64,
    /// Operating mode of the open `Db` handle.
    pub mode: DbMode,
    /// Size of the main database file in bytes at the time of the call.
    pub main_db_bytes: u64,
    /// Next page id that will be allocated by the writer (monotonic watermark).
    pub main_db_next_page_id: u64,
    /// Current number of pages resident in the buffer pool (main.db cache).
    pub buffer_pool_pages: u64,
    /// Cumulative cache hits on the buffer pool since the `Db` was opened.
    pub buffer_pool_hits: u64,
    /// Cumulative cache misses on the buffer pool since the `Db` was opened.
    pub buffer_pool_misses: u64,
    /// Number of dirty (unflushed) pages currently in both cache classes combined.
    pub dirty_pages: u64,
    /// Number of read transactions currently registered with the `Db`.
    pub tracked_readers: u32,
    /// Number of segment tombstones that are deferred pending reader drain.
    pub pending_tombstones: u32,
    /// Number of live segments recorded in the catalog.
    pub segments_live: u32,
    /// Sum of `total_bytes` across all live catalog segments.
    pub segments_total_bytes: u64,
    /// Bytes currently charged to decrypted mmap scratch views.
    pub mmap_bytes_in_use: u64,
    /// Current master-key epoch (advances on each successful `rekey_db`).
    pub mk_epoch: u64,
    /// Number of entries currently in the persistent free-list (both
    /// free-list rows and deferred-free pairs combined).
    pub free_list_pending_entries: u64,
    /// Cumulative spill bytes written to the per-transaction tmp file for the
    /// currently active write transaction, or 0 if no write transaction is active.
    pub spill_bytes_in_use: u64,
}
