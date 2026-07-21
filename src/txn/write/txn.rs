//! `WriteTxn` — exclusive write session backed by a `CoW` B+ tree. On commit,
//! flushes dirty pages, writes the new A/B header, and advances the
//! visibility commit id. The commit body lives in [`super::commit`].

use std::sync::atomic::Ordering;

use tokio::sync::{MutexGuard, RwLockWriteGuard};

use crate::btree::BTree;
use crate::catalog::codec::{Catalog, RealmQuotas, SegmentMeta};
use crate::crypto::cipher::Cipher;
use crate::errors::{PagedbError, QuotaKind};
use crate::vfs::Vfs;
use crate::{RealmId, Result};

use super::super::db::{Db, WriterState};
use super::counter::CounterRef;
use super::spill::SpillSegmentMeta;

/// Deferred filesystem operation applied after the A/B header is durable.
pub(crate) enum SegmentSideEffect {
    Promote {
        segment_id: [u8; 16],
    },
    Tombstone {
        segment_id: [u8; 16],
        /// `None` uses the enclosing durable commit. Apply-journal entries
        /// carry their recorded tombstone commit explicitly.
        tombstone_commit_id: Option<u64>,
    },
}

/// An exclusive write transaction. At most one `WriteTxn` exists per `Db` at
/// any time — the writer mutex enforces this. Either `commit` or `abort` must
/// be called; if the `WriteTxn` is dropped without either, dirty pages are
/// silently discarded (equivalent to abort).
pub struct WriteTxn<'db, V: Vfs + Clone> {
    pub(super) db: &'db Db<V>,
    pub(super) guard: MutexGuard<'db, WriterState>,
    /// Held from the reclamation-floor scan through commit publication.
    pub(super) visibility_guard: RwLockWriteGuard<'db, ()>,
    pub(super) btree: BTree<V>,
    pub(super) catalog_tree: BTree<V>,
    pub(super) pending_segments: Vec<SegmentSideEffect>,
    pub(super) committed_or_aborted: bool,
    /// Monotonic per-txn sequence number; assigned at `begin` from
    /// `Db::txn_seq.fetch_add(1, Relaxed) + 1`. The first `WriteTxn` on a
    /// fresh Db gets `txn_seq == 1`, making `tmp/scratch-1` predictable in
    /// tests.
    pub(crate) txn_seq: u64,
    /// Lazily derived spill cipher. `None` until the first `spill_scope` append.
    pub(crate) spill_cipher: Option<Cipher>,
    /// Lazily created path to the per-txn spill tmp file (`tmp/scratch-<seq>`).
    pub(crate) spill_path: Option<String>,
    /// Cumulative bytes (ciphertext body + tag) written to the spill file.
    pub(crate) spill_bytes_used: u64,
    /// Per-append metadata used by `SpillScope::read` to reconstruct AAD/nonce.
    pub(crate) spill_segments: Vec<SpillSegmentMeta>,
    /// The durable free-list's `(commit_id, page_id)` entries as loaded at
    /// begin. The commit path rewrites the chain from these (minus the pages
    /// reused this txn, plus the pages freed this txn).
    pub(crate) free_set_loaded: Vec<(u64, u64)>,
    /// Page ids the old free-list chain occupied at begin. They become free
    /// once this commit's new chain supersedes them.
    pub(crate) old_chain_pages: Vec<u64>,
    /// Reclamation floor at begin: free-list entries tagged below this are
    /// drainable (no snapshot pins them). The reader-stall policy is evaluated
    /// at commit against only the entries at/above it — the backlog genuinely
    /// stuck behind a reader pin — not the drainable remainder.
    pub(crate) reclaim_floor: u64,
}

impl<'db, V: Vfs + Clone> WriteTxn<'db, V> {
    pub(crate) async fn begin(db: &'db Db<V>) -> Result<WriteTxn<'db, V>> {
        db.ensure_usable()?;
        let guard = db.writer.lock().await;
        db.ensure_usable()?;
        #[cfg(test)]
        db.notify_writer_waiting();
        let visibility_guard = db.visibility_gate.write().await;

        // Pages freed *within this txn* must never be recycled within the same
        // txn if they existed before it began: a copy-on-write free means the
        // page is still referenced by the last durable header, and its bytes
        // must stay intact on disk until the header that unreferences it is
        // itself durable. Overwriting such a page and then crashing (or failing
        // the commit after some pages flushed) leaves the durable header
        // pointing at foreign content — detected only later as an AEAD/MAC
        // failure on read, with the store unrecoverable.
        //
        // The threshold is therefore always `next_page_id` as of begin: only
        // pages bump-allocated *by this txn* (id >= threshold, referenced by no
        // header and no snapshot) are recyclable in-session. Pre-existing pages
        // freed here become reusable on a later txn's begin, via the shared
        // cache below, once the free-list naming them is durable and the
        // reclamation floor clears them.
        //
        // (Previously this was 0 when no reader was tracked, which recycled
        // durable-header-referenced pages in-session and silently corrupted the
        // store under crash or commit-failure timing.)
        let min_reader = {
            let readers = db.tracked_readers.lock();
            readers.iter().map(|r| r.commit_id.0).min()
        };
        let reuse_threshold = guard.next_page_id;

        // Load the durable free-list and rebuild the shared allocator cache with
        // exactly the pages below the reclamation floor — the older of the
        // oldest live-reader pin and the oldest retained commit-history root.
        // Those are observable by no snapshot, so they are safe to recycle now.
        let history_floor = db
            .oldest_retained_history_commit(guard.commit_history_root_page_id, guard.next_page_id)
            .await?;
        let floor = min_reader
            .unwrap_or(u64::MAX)
            .min(history_floor.map_or(u64::MAX, |h| h.saturating_add(1)));
        let (free_set_loaded, old_chain_pages) = crate::pager::freelist::read_chain(
            &db.pager,
            db.realm_id,
            guard.free_list_root_page_id,
        )
        .await?;
        {
            let mut cache = db.free_page_cache.lock();
            cache.clear();
            for (cid, pid) in &free_set_loaded {
                if *cid < floor {
                    cache.push(*pid);
                }
            }
        }
        db.free_page_consumed.lock().clear();

        let mut btree = BTree::open(
            db.pager.clone(),
            db.realm_id,
            guard.root_page_id,
            guard.next_page_id,
            db.page_size,
        );
        btree.set_reuse_threshold(reuse_threshold);
        btree.set_free_page_cache(db.free_page_cache.clone());
        btree.set_free_page_consumed(db.free_page_consumed.clone());
        let mut catalog_tree = BTree::open(
            db.pager.clone(),
            db.realm_id,
            guard.catalog_root_page_id,
            guard.next_page_id,
            db.page_size,
        );
        catalog_tree.set_reuse_threshold(reuse_threshold);
        catalog_tree.set_free_page_cache(db.free_page_cache.clone());
        catalog_tree.set_free_page_consumed(db.free_page_consumed.clone());
        // Assign a txn_seq starting from 1: fetch_add returns the old value (0
        // for the first call), so we add 1 to produce 1-based ids.
        let txn_seq = db.txn_seq.fetch_add(1, Ordering::Relaxed) + 1;
        Ok(Self {
            db,
            guard,
            visibility_guard,
            btree,
            catalog_tree,
            pending_segments: Vec::new(),
            committed_or_aborted: false,
            txn_seq,
            spill_cipher: None,
            spill_path: None,
            spill_bytes_used: 0,
            spill_segments: Vec::new(),
            free_set_loaded,
            old_chain_pages,
            reclaim_floor: floor,
        })
    }

    pub async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.btree.get(key).await
    }

    pub async fn put(&mut self, key: &[u8], value: &[u8]) -> Result<()> {
        self.btree.put(key, value).await
    }

    /// Append a key-value pair under the monotonic-key invariant.
    ///
    /// Subsequent calls within the same `WriteTxn` skip the
    /// `path_to_leaf_for_key` descent by reusing the cached rightmost
    /// path; splits and explicitly-invalidating operations (regular `put`,
    /// `delete`) force a re-descent on the next call.
    ///
    /// Intended for op-logs, time-series indexes, FTS posting-list builds
    /// — any workload where the embedder can guarantee monotonically
    /// increasing keys.
    ///
    /// # Errors
    ///
    /// Returns [`PagedbError::AppendNotMonotonic`] if `key` is not
    /// strictly greater than the previously-appended key in this txn.
    pub async fn put_append(&mut self, key: &[u8], value: &[u8]) -> Result<()> {
        self.btree.put_append(key, value).await
    }

    pub async fn delete(&mut self, key: &[u8]) -> Result<bool> {
        self.btree.delete(key).await
    }

    pub async fn put_batch(&mut self, sorted: Vec<(Vec<u8>, Vec<u8>)>) -> Result<()> {
        self.btree.put_batch(sorted).await
    }

    pub async fn delete_batch(&mut self, sorted: Vec<Vec<u8>>) -> Result<()> {
        self.btree.delete_batch(sorted).await
    }

    pub async fn delete_range(&mut self, start: &[u8], end: &[u8]) -> Result<u64> {
        self.btree.delete_range(start, end).await
    }

    /// Return a `CounterRef` scoped to this transaction for the named counter.
    ///
    /// The returned handle borrows `self` mutably for its lifetime. Use the
    /// counter, drop the handle, then continue with other transaction
    /// operations. The name must be at most `MAX_SEGMENT_NAME_LEN` bytes
    /// (`PagedbError::NameTooLong` otherwise).
    pub fn counter<'tx>(&'tx mut self, name: &str) -> Result<CounterRef<'tx, V>> {
        let key = Catalog::counter_key(name.as_bytes())?;
        Ok(CounterRef {
            catalog_tree: &mut self.catalog_tree,
            main_tree: &mut self.btree,
            key,
        })
    }

    /// Register a segment under `name` in the catalog and schedule promotion
    /// of its staging file to the live path on commit.
    pub async fn link_segment(&mut self, name: &str, meta: &SegmentMeta) -> Result<()> {
        let key = Catalog::segment_key(self.db.realm_id, name.as_bytes())?;
        if self.catalog_tree.get(&key).await?.is_some() {
            return Err(PagedbError::AlreadyLinked);
        }
        self.enforce_segment_bytes_quota(meta.realm_id, meta.total_bytes, 0)
            .await?;
        let value = Catalog::encode_segment_meta(meta);
        self.sync_allocator_to_catalog();
        self.catalog_tree.put(&key, &value).await?;
        self.sync_allocator_from_catalog();
        self.pending_segments.push(SegmentSideEffect::Promote {
            segment_id: meta.segment_id,
        });
        Ok(())
    }

    /// Remove the catalog row for `name` and schedule a tombstone rename on commit.
    pub async fn unlink_segment(&mut self, name: &str) -> Result<()> {
        let key = Catalog::segment_key(self.db.realm_id, name.as_bytes())?;
        let value = self
            .catalog_tree
            .get(&key)
            .await?
            .ok_or(PagedbError::NotLinked)?;
        let meta = Catalog::decode_segment_meta(&value)?;
        self.sync_allocator_to_catalog();
        let removed = self.catalog_tree.delete(&key).await?;
        self.sync_allocator_from_catalog();
        if !removed {
            return Err(PagedbError::NotLinked);
        }
        self.pending_segments.push(SegmentSideEffect::Tombstone {
            segment_id: meta.segment_id,
            tombstone_commit_id: None,
        });
        Ok(())
    }

    /// Atomically swap the segment recorded under `name`: tombstone the old
    /// segment id and promote `new_meta`'s staging file on commit.
    pub async fn replace_segment(&mut self, name: &str, new_meta: &SegmentMeta) -> Result<()> {
        let key = Catalog::segment_key(self.db.realm_id, name.as_bytes())?;
        let existing = self
            .catalog_tree
            .get(&key)
            .await?
            .ok_or(PagedbError::NotLinked)?;
        let old_meta = Catalog::decode_segment_meta(&existing)?;
        self.enforce_segment_bytes_quota(
            new_meta.realm_id,
            new_meta.total_bytes,
            old_meta.total_bytes,
        )
        .await?;
        let value = Catalog::encode_segment_meta(new_meta);
        self.sync_allocator_to_catalog();
        self.catalog_tree.put(&key, &value).await?;
        self.sync_allocator_from_catalog();
        self.pending_segments.push(SegmentSideEffect::Tombstone {
            segment_id: old_meta.segment_id,
            tombstone_commit_id: None,
        });
        self.pending_segments.push(SegmentSideEffect::Promote {
            segment_id: new_meta.segment_id,
        });
        Ok(())
    }

    /// Check if the realm's committed segment bytes plus `new_bytes` minus
    /// `delta_remove_bytes` would exceed the configured cap. Returns `Ok(())`
    /// when no cap is set or the projected total is within the limit.
    async fn enforce_segment_bytes_quota(
        &self,
        realm: RealmId,
        new_bytes: u64,
        delta_remove_bytes: u64,
    ) -> Result<()> {
        let quota_key = Catalog::quota_key(realm);
        let quotas = match self.catalog_tree.get(&quota_key).await? {
            Some(v) => Catalog::decode_realm_quotas(&v)?,
            None => RealmQuotas::default(),
        };
        let Some(limit) = quotas.max_segment_bytes else {
            return Ok(());
        };
        // Scan all catalog segment rows for this realm to sum committed bytes.
        let mut prefix = Vec::with_capacity(17);
        prefix.push(0x01u8); // CatalogRowKind::Segment
        prefix.extend_from_slice(&realm.0);
        let rows = self.catalog_tree.scan_prefix(&prefix).await?;
        let mut committed: u64 = 0;
        for (_, v) in rows {
            let meta = Catalog::decode_segment_meta(&v)?;
            committed = committed.saturating_add(meta.total_bytes);
        }
        let after_remove = committed.saturating_sub(delta_remove_bytes);
        let projected = after_remove.saturating_add(new_bytes);
        if projected > limit {
            return Err(PagedbError::quota(
                realm,
                QuotaKind::SegmentBytes,
                projected,
                limit,
            ));
        }
        Ok(())
    }

    /// Discard all in-flight dirty pages without writing anything durable.
    /// The spill tmp file (if created) is removed before returning (best-effort;
    /// errors are ignored).
    pub async fn abort(mut self) {
        tracing::debug!(name = "txn.abort", "write transaction aborted");
        self.db.pager.discard_dirty_main(self.db.realm_id);
        self.committed_or_aborted = true;
        self.db
            .spill_bytes_in_use
            .store(0, std::sync::atomic::Ordering::Relaxed);
        self.cleanup_spill_async().await;
    }

    /// Before a catalog operation: ensure the catalog tree's allocator cursor
    /// is at least as high as the main tree's, so neither tree allocates the
    /// same page id.
    pub(super) fn sync_allocator_to_catalog(&mut self) {
        let main_next = self.btree.next_page_id();
        let cat_next = self.catalog_tree.next_page_id();
        let shared = main_next.max(cat_next);
        self.catalog_tree.set_next_page_id(shared);
    }

    /// After a catalog operation: propagate any catalog allocation advances
    /// back to the main tree so subsequent main-tree allocations stay above.
    pub(super) fn sync_allocator_from_catalog(&mut self) {
        let cat_next = self.catalog_tree.next_page_id();
        self.btree.set_next_page_id(cat_next);
    }
}

impl<V: Vfs + Clone> Drop for WriteTxn<'_, V> {
    fn drop(&mut self) {
        if !self.committed_or_aborted {
            self.db.pager.discard_dirty_main(self.db.realm_id);
        }
    }
}
