//! Reader registration, snapshot publication, stall-policy evaluation, and
//! historical (`begin_read_at`) reads.

use std::sync::atomic::Ordering;

use crate::btree::BTree;
use crate::catalog::codec::Catalog;
use crate::errors::PagedbError;
use crate::vfs::Vfs;
use crate::{CommitId, Result};

use super::super::mode::DbMode;
use super::super::policy::ReaderStallPolicy;
use super::super::read::ReadTxn;
use super::super::write::WriteTxn;
use super::core::{Db, ReaderSnapshot, TrackedReader, WriterState, decode_commit_meta};
use super::util::next_lease_id;

impl<V: Vfs + Clone> Db<V> {
    /// Open a read transaction pinned to the current committed root. Inserts a
    /// durable reader-pin row in the catalog so cross-process GC can see the pin
    /// even after a crash. The pin is deleted (best-effort) when the `ReadTxn`
    /// drops via the `pending_pin_deletes` queue, which is drained by the next
    /// writer commit or `gc_now`. If the process crashes before cleanup, the next
    /// writer open scans and removes stale pin rows.
    pub async fn begin_read(&self) -> Result<ReadTxn<'_, V>> {
        // Only insert a durable pin on Standalone handles; ReadOnly / Follower
        // handles that cannot write to their own catalog use the in-memory path.
        let can_write_catalog = matches!(self.mode, crate::txn::mode::DbMode::Standalone);

        let (commit_id, root_page_id, next_page_id, catalog_root_page_id) = {
            let w = self.writer.lock().await;
            (
                CommitId(w.latest_commit_id),
                w.root_page_id,
                w.next_page_id,
                w.catalog_root_page_id,
            )
        };
        let txn = self.register_read(
            commit_id,
            root_page_id,
            next_page_id,
            catalog_root_page_id,
            false,
        );

        if can_write_catalog {
            let lease_seconds = 30u64;
            let lease_id = next_lease_id();
            let own_pid = std::process::id();
            let pin_handle = crate::txn::read::make_pin_handle(
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
                own_pid,
                lease_id,
                lease_seconds,
            );
            // Insert the pin row. On failure (e.g., no catalog yet or during
            // bootstrap), fall through to in-memory-only tracking.
            {
                let mut state = self.writer.lock().await;
                if state.catalog_root_page_id != 0 {
                    let _ = crate::txn::read::insert_pin_row(
                        &pin_handle,
                        &mut state,
                        commit_id.0,
                        root_page_id,
                        catalog_root_page_id,
                    )
                    .await;
                    return Ok(txn.with_durable_pin(own_pid, lease_id));
                }
            }
        }

        Ok(txn)
    }

    /// Like [`begin_read`] but marks the reader as non-abortable. The
    /// `AbortOldest` stall policy skips non-abortable readers; if all blocking
    /// readers are non-abortable, the policy falls through to `Reject`
    /// semantics for the writer.
    ///
    /// Use this for long-running operations (e.g. snapshot export) that must
    /// not be interrupted mid-stream.
    #[allow(clippy::unused_async)] // async signature preserved for API stability
    pub async fn begin_read_non_abortable(&self) -> Result<ReadTxn<'_, V>> {
        // Lock-free fast path: read the published snapshot without touching
        // the async writer mutex. The snapshot is updated by the writer at
        // each commit (see `publish_snapshot`), and is always internally
        // consistent — a reader either sees the previous commit fully or the
        // new commit fully, never a torn mix.
        let snap = *self.snapshot.read();
        Ok(self.register_read(
            CommitId(snap.commit_id),
            snap.root_page_id,
            snap.next_page_id,
            snap.catalog_root_page_id,
            true,
        ))
    }

    /// Publish a new reader-visible snapshot. Called by writer commit paths
    /// after `state` has been mutated to reflect a freshly durable commit.
    /// Cheap (a single `parking_lot::RwLock` write, no async).
    pub(crate) fn publish_snapshot(&self, state: &WriterState) {
        *self.snapshot.write() = ReaderSnapshot {
            commit_id: state.latest_commit_id,
            root_page_id: state.root_page_id,
            next_page_id: state.next_page_id,
            catalog_root_page_id: state.catalog_root_page_id,
        };
    }

    /// Register a reader with a snapshot pin. Stores the reader in the
    /// tracked-readers table and returns a `ReadTxn` carrying the unique
    /// `entry_id` used to unregister on drop.
    pub(crate) fn register_read(
        &self,
        commit_id: CommitId,
        root_page_id: u64,
        next_page_id: u64,
        catalog_root_page_id: u64,
        non_abortable: bool,
    ) -> ReadTxn<'_, V> {
        let entry_id = self.reader_seq.fetch_add(1, Ordering::Relaxed);
        let mut readers = self.tracked_readers.lock();
        readers.push(TrackedReader {
            entry_id,
            commit_id,
            root_page_id,
            next_page_id,
            catalog_root_page_id,
            non_abortable,
        });
        drop(readers);
        ReadTxn::new(
            self,
            commit_id,
            root_page_id,
            next_page_id,
            catalog_root_page_id,
            entry_id,
        )
    }

    /// Unregister a reader by its unique `entry_id`. Called from `ReadTxn::drop`.
    /// Uses `swap_remove` for O(1) amortised removal; order in the Vec is
    /// not semantically significant.
    pub(crate) fn unregister_read(&self, entry_id: u64) {
        let mut readers = self.tracked_readers.lock();
        if let Some(pos) = readers.iter().position(|r| r.entry_id == entry_id) {
            readers.swap_remove(pos);
        }
    }

    /// Open a write transaction. Acquires the exclusive writer slot.
    /// Returns `PagedbError::ReadOnly` if the handle is not in Standalone mode.
    pub async fn begin_write(&self) -> Result<WriteTxn<'_, V>> {
        if !matches!(self.mode, DbMode::Standalone) {
            return Err(PagedbError::ReadOnly);
        }
        tracing::debug!(name = "txn.begin_write", "opening write transaction");
        WriteTxn::begin(self).await
    }

    /// Return the most recently published `CommitId`.
    pub fn latest_commit(&self) -> CommitId {
        CommitId(self.latest_commit.load(Ordering::SeqCst))
    }

    /// Replace the reader stall policy. Takes effect on the next stall
    /// evaluation (enforcement lands when the persistent free-list arrives).
    pub fn set_reader_stall_policy(&self, policy: ReaderStallPolicy) {
        *self.stall_policy.lock() = policy;
    }

    /// Read the current reader stall policy.
    pub fn reader_stall_policy(&self) -> ReaderStallPolicy {
        *self.stall_policy.lock()
    }

    /// Check whether reader `entry_id` has been aborted by the stall policy.
    /// Removes the entry from the abort set (one-shot: the reader observes the
    /// abort exactly once).
    pub(crate) fn take_reader_abort(&self, entry_id: u64) -> bool {
        self.aborted_readers.lock().remove(&entry_id)
    }

    /// Evaluate the reader stall policy against the current deferred-free queue
    /// length. Called by `WriteTxn::commit` after building the new deferred-free
    /// list. Returns `Ok(())` to proceed with commit, or an error to abort.
    ///
    /// Side effect for `AbortOldest`: marks the oldest abortable tracked reader
    /// in `aborted_readers` so its next operation returns `Aborted`.
    pub(crate) fn evaluate_stall_policy(&self, deferred_free_count: u64) -> crate::Result<()> {
        let threshold = self.options.reader_stall_threshold_pages;
        if deferred_free_count <= threshold {
            return Ok(());
        }
        let policy = *self.stall_policy.lock();
        if matches!(policy, ReaderStallPolicy::Unbounded) {
            return Ok(());
        }
        // Check whether any tracked reader is actually pinning (blocking drain).
        let oldest_blocking = {
            let readers = self.tracked_readers.lock();
            readers.iter().map(|r| r.commit_id.0).min()
        };
        let Some(oldest_commit) = oldest_blocking else {
            // No readers at all — no stall.
            return Ok(());
        };
        match policy {
            ReaderStallPolicy::Reject => Err(PagedbError::deferred_free_backlog(
                deferred_free_count,
                oldest_commit,
            )),
            ReaderStallPolicy::AbortOldest => {
                // Find the oldest abortable reader and mark it aborted.
                let readers = self.tracked_readers.lock();
                let victim = readers
                    .iter()
                    .filter(|r| !r.non_abortable)
                    .min_by_key(|r| r.commit_id.0);
                if let Some(v) = victim {
                    let eid = v.entry_id;
                    drop(readers);
                    self.aborted_readers.lock().insert(eid);
                    Ok(())
                } else {
                    // All blocking readers are non-abortable → fall through to Reject.
                    drop(readers);
                    Err(PagedbError::deferred_free_backlog(
                        deferred_free_count,
                        oldest_commit,
                    ))
                }
            }
            ReaderStallPolicy::Unbounded => Ok(()),
        }
    }

    /// Scan the catalog for durable reader-pin rows. Returns the minimum
    /// `commit_id` among non-expired pins, or `u64::MAX` if there are none.
    /// This supplements the in-memory `tracked_readers` check with cross-process
    /// readers whose pins are only visible via the catalog.
    pub(crate) async fn min_durable_reader_commit(&self, catalog_root: u64, next: u64) -> u64 {
        if catalog_root == 0 {
            return u64::MAX;
        }
        let now = crate::txn::read::unix_now_seconds();
        let tree = BTree::open(
            self.pager.clone(),
            self.realm_id,
            catalog_root,
            next,
            self.page_size,
        );
        let start = Catalog::reader_pin_range_start();
        let end = Catalog::reader_pin_range_end();
        let Ok(rows) = tree.collect_range(&start, &end).await else {
            return u64::MAX;
        };
        let own_pid = std::process::id();
        let mut min_commit = u64::MAX;
        for (k, v) in &rows {
            // Skip own-PID pins (they're accounted for in-memory).
            if k.len() >= 5 {
                let mut pid_buf = [0u8; 4];
                pid_buf.copy_from_slice(&k[1..5]);
                if u32::from_be_bytes(pid_buf) == own_pid {
                    continue;
                }
            }
            if let Ok(pv) = Catalog::decode_reader_pin(v) {
                if pv.expires_unix_seconds >= now {
                    min_commit = min_commit.min(pv.commit_id);
                }
            }
        }
        min_commit
    }

    /// Look up `commit` in the commit-history B+ tree and, if found, return a
    /// `ReadTxn` pinned to that historical snapshot.
    pub async fn begin_read_at(&self, commit: CommitId) -> Result<ReadTxn<'_, V>> {
        let (history_root, history_next, latest_commit_id) = {
            let w = self.writer.lock().await;
            (
                w.commit_history_root_page_id,
                w.next_page_id,
                w.latest_commit_id,
            )
        };

        // Fast path: current commit.
        if commit.0 == latest_commit_id {
            let w = self.writer.lock().await;
            let cid = CommitId(w.latest_commit_id);
            let root = w.root_page_id;
            let next = w.next_page_id;
            let cat = w.catalog_root_page_id;
            drop(w);
            return Ok(self.register_read(cid, root, next, cat, false));
        }

        if history_root == 0 {
            // History tree not yet written; all historical commits are gone.
            return Err(PagedbError::CommitGone {
                commit,
                oldest_available: CommitId(latest_commit_id),
            });
        }

        let tree = BTree::open(
            self.pager.clone(),
            self.realm_id,
            history_root,
            history_next,
            self.page_size,
        );

        let key = commit.0.to_be_bytes().to_vec();
        if let Some(value) = tree.get(&key).await? {
            let meta = decode_commit_meta(&value)?;
            Ok(self.register_read(
                commit,
                meta.active_root_page_id,
                meta.next_page_id,
                meta.catalog_root_page_id,
                false,
            ))
        } else {
            // Find the oldest available: scan from the beginning.
            let start = 0u64.to_be_bytes().to_vec();
            let end = u64::MAX.to_be_bytes().to_vec();
            let oldest = tree
                .collect_range(&start, &end)
                .await?
                .into_iter()
                .next()
                .map_or(CommitId(latest_commit_id), |(k, _)| {
                    let mut b = [0u8; 8];
                    b.copy_from_slice(&k[..8]);
                    CommitId(u64::from_be_bytes(b))
                });
            Err(PagedbError::CommitGone {
                commit,
                oldest_available: oldest,
            })
        }
    }
}
