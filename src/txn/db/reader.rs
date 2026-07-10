//! Reader registration, snapshot publication, stall-policy evaluation, and
//! historical (`begin_read_at`) reads.

use std::sync::atomic::Ordering;

use crate::btree::BTree;
use crate::errors::PagedbError;
use crate::vfs::Vfs;
use crate::{CommitId, Result};

use super::super::mode::DbMode;
use super::super::policy::ReaderStallPolicy;
use super::super::read::ReadTxn;
use super::super::write::WriteTxn;
use super::core::{Db, ReaderSnapshot, TrackedReader, WriterState, decode_commit_meta};

impl<V: Vfs + Clone> Db<V> {
    /// Open a read transaction pinned to the current published root. Reader
    /// tracking is local to this `Db` handle and never mutates durable state.
    #[allow(clippy::unused_async)] // async signature preserved for API stability
    pub async fn begin_read(&self) -> Result<ReadTxn<'_, V>> {
        self.ensure_usable()?;
        let _admission = self.visibility_gate.read().await;
        let snap = *self.snapshot.read();
        #[cfg(test)]
        self.pause_after_snapshot_selection().await;
        Ok(self.register_read(
            CommitId(snap.commit_id),
            snap.root_page_id,
            snap.next_page_id,
            snap.catalog_root_page_id,
            false,
        ))
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
        self.ensure_usable()?;
        let _admission = self.visibility_gate.read().await;
        // The snapshot and registration remain under the admission gate, so a
        // destructive writer cannot decide reader-pin eligibility between them.
        let snap = *self.snapshot.read();
        #[cfg(test)]
        self.pause_after_snapshot_selection().await;
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
            free_list_root_page_id: state.free_list_root_page_id,
            commit_history_root_page_id: state.commit_history_root_page_id,
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
        #[cfg(test)]
        self.notify_reader_registered();
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
        self.ensure_usable()?;
        if !matches!(self.mode, DbMode::Standalone) {
            return Err(PagedbError::ReadOnly);
        }
        tracing::debug!(name = "txn.begin_write", "opening write transaction");
        WriteTxn::begin(self).await
    }

    /// Return the most recently published `CommitId`.
    pub fn latest_commit(&self) -> CommitId {
        CommitId(self.snapshot.read().commit_id)
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

    /// Look up `commit` in the commit-history B+ tree and, if found, return a
    /// `ReadTxn` pinned to that historical snapshot.
    pub async fn begin_read_at(&self, commit: CommitId) -> Result<ReadTxn<'_, V>> {
        self.ensure_usable()?;
        let _admission = self.visibility_gate.read().await;
        let snap = *self.snapshot.read();
        if commit.0 == snap.commit_id {
            #[cfg(test)]
            self.pause_after_snapshot_selection().await;
            return Ok(self.register_read(
                CommitId(snap.commit_id),
                snap.root_page_id,
                snap.next_page_id,
                snap.catalog_root_page_id,
                false,
            ));
        }
        let history_root = snap.commit_history_root_page_id;
        let history_next = snap.next_page_id;
        let latest_commit_id = snap.commit_id;

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
            #[cfg(test)]
            self.pause_after_snapshot_selection().await;
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::catalog::codec::SegmentKind;
    use crate::segment::types::SegmentPageKind;
    use crate::vfs::memory::MemVfs;
    use crate::{Db, RealmId};

    use super::super::core::VisibilityTestHook;

    const PAGE: usize = 4096;
    const KEK: [u8; 32] = [0xD1; 32];
    const REALM: RealmId = RealmId::new([0xD2; 16]);

    async fn linked_segment(db: &Db<MemVfs>, name: &str, bytes: &[u8]) {
        let mut writer = db
            .create_segment(REALM, SegmentKind::Unspecified)
            .await
            .unwrap();
        writer
            .append_page(SegmentPageKind::Data, bytes)
            .await
            .unwrap();
        let meta = writer.seal().await.unwrap();
        let mut txn = db.begin_write().await.unwrap();
        txn.link_segment(name, &meta).await.unwrap();
        txn.commit().await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn admission_before_tombstone_registration_preserves_old_segment() {
        let db = Arc::new(
            Db::open_internal(MemVfs::new(), KEK, PAGE, REALM)
                .await
                .unwrap(),
        );
        linked_segment(&db, "old", b"old-page").await;

        let hook = Arc::new(VisibilityTestHook::default());
        db.install_visibility_test_hook(hook.clone());

        let reader_db = db.clone();
        let reader_hook = hook.clone();
        let reader_task = tokio::spawn(async move {
            let reader = reader_db.begin_read().await.unwrap();
            reader_hook.reader_may_read.notified().await;
            reader
                .open_segment("old")
                .await
                .unwrap()
                .read_page(1)
                .await
                .unwrap()
        });
        hook.reader_selected.notified().await;

        let writer_db = db.clone();
        let writer_task = tokio::spawn(async move {
            let mut txn = writer_db.begin_write().await.unwrap();
            txn.unlink_segment("old").await.unwrap();
            txn.commit().await.unwrap()
        });
        hook.writer_waiting.notified().await;

        hook.allow_reader_registration.notify_one();
        hook.reader_registered.notified().await;
        writer_task.await.unwrap();

        hook.reader_may_read.notify_one();
        let page = reader_task.await.unwrap();
        assert!(page.starts_with(b"old-page"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn admission_before_compaction_check_blocks_reclamation() {
        let db = Arc::new(
            Db::open_internal(MemVfs::new(), KEK, PAGE, REALM)
                .await
                .unwrap(),
        );
        {
            let mut txn = db.begin_write().await.unwrap();
            for index in 0..80_u32 {
                txn.put(
                    format!("key-{index:03}").as_bytes(),
                    &[u8::try_from(index).unwrap(); 64],
                )
                .await
                .unwrap();
            }
            txn.commit().await.unwrap();
        }
        {
            let mut txn = db.begin_write().await.unwrap();
            for index in 0..70_u32 {
                txn.delete(format!("key-{index:03}").as_bytes())
                    .await
                    .unwrap();
            }
            txn.commit().await.unwrap();
        }

        let hook = Arc::new(VisibilityTestHook::default());
        db.install_visibility_test_hook(hook.clone());

        let reader_db = db.clone();
        let reader_hook = hook.clone();
        let reader_task = tokio::spawn(async move {
            let reader = reader_db.begin_read().await.unwrap();
            reader_hook.reader_may_read.notified().await;
            reader.get(b"key-079").await.unwrap()
        });
        hook.reader_selected.notified().await;

        let compact_db = db.clone();
        let compact_task =
            tokio::spawn(async move { crate::compaction::compact_now(&compact_db).await });
        hook.writer_waiting.notified().await;

        hook.allow_reader_registration.notify_one();
        hook.reader_registered.notified().await;
        let stats = compact_task.await.unwrap().unwrap();
        assert_eq!(stats.bytes_truncated, 0);

        hook.reader_may_read.notify_one();
        let expected = [79_u8; 64];
        assert_eq!(
            reader_task.await.unwrap().as_deref(),
            Some(expected.as_slice())
        );
    }
}
