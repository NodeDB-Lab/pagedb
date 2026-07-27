//! Catalog-backed operations: realm-quota persistence and commit-history
//! maintenance.

use std::sync::atomic::Ordering;

use crate::btree::BTree;
use crate::catalog::codec::{Catalog, RealmQuotas};
use crate::errors::PagedbError;
use crate::pager::anchor::HeaderCursor;
use crate::pager::header::commit_header;
use crate::vfs::Vfs;
use crate::{RealmId, Result};

use super::core::{
    CommitHistoryMeta, Db, HeaderFieldsParams, decode_commit_meta, encode_commit_meta,
    encode_root_ref,
};
use super::pending::PendingWriterState;

/// Named-counter rows read per batch while validating them at open. Rows are a
/// fixed-width authenticated value, so this is a few KiB resident regardless of
/// how many counters the embedder has named.
const COUNTER_ROW_BATCH: usize = 512;

/// Commit-history rows read per batch while pruning by age. A key is 8 bytes
/// and a row 40, so this is a few tens of KiB resident regardless of how deep
/// retention has run.
const HISTORY_PRUNE_BATCH: usize = 512;

impl<V: Vfs + Clone> Db<V> {
    /// The oldest commit id still retained in the commit-history index, or
    /// `None` when history is disabled or the index is empty. Pages reachable
    /// from this commit's root (or any newer one) must not be recycled, so it
    /// is one of the two floors gating free-page reclamation (the other is the
    /// oldest live reader pin). Reads only the leftmost spine of the history
    /// tree — O(height), not O(retained count).
    pub(crate) async fn oldest_retained_history_commit(
        &self,
        commit_history_root_page_id: u64,
        next_page_id: u64,
    ) -> Result<Option<u64>> {
        if matches!(
            self.options.commit_history_retain,
            crate::options::RetainPolicy::Disabled
        ) || commit_history_root_page_id == 0
        {
            return Ok(None);
        }
        let hist = BTree::open(
            self.pager.clone(),
            self.realm_id,
            commit_history_root_page_id,
            next_page_id,
            self.page_size,
        );
        let Some(key) = hist.first_key().await? else {
            return Ok(None);
        };
        if key.len() != 8 {
            return Err(PagedbError::catalog_row_invalid("commit_history.key"));
        }
        let mut b = [0u8; 8];
        b.copy_from_slice(&key[..8]);
        Ok(Some(u64::from_be_bytes(b)))
    }

    /// Authenticate and decode every persisted named-counter row during open.
    ///
    /// Named counters are already atomic with catalog-root publication, so
    /// recovery validates their encoding but never rewrites their values.
    ///
    /// Rows are streamed in bounded batches: how many counters an embedder has
    /// named is its business, and open must not size an allocation by it.
    pub(super) async fn validate_counter_rows(
        &self,
        catalog_root_page_id: u64,
        next_page_id: u64,
    ) -> Result<()> {
        if catalog_root_page_id == 0 {
            return Ok(());
        }

        let prefix = [crate::catalog::codec::CatalogRowKind::Counter as u8];
        let tree = BTree::open(
            self.pager.clone(),
            self.realm_id,
            catalog_root_page_id,
            next_page_id,
            self.page_size,
        );
        let mut cursor: Vec<u8> = prefix.to_vec();
        loop {
            let batch = tree
                .collect_prefix_batch_from(&prefix, &cursor, COUNTER_ROW_BATCH)
                .await?;
            let Some((last_key, _)) = batch.last() else {
                return Ok(());
            };
            cursor.clear();
            cursor.extend_from_slice(last_key);
            // The exact successor of `last_key` in the key ordering: resume
            // strictly past the row just validated without re-reading it.
            cursor.push(0);
            let exhausted = batch.len() < COUNTER_ROW_BATCH;

            for (_key, value) in &batch {
                Catalog::decode_counter(value)?;
            }
            if exhausted {
                return Ok(());
            }
        }
    }

    /// Write per-realm quota caps into the catalog B+ tree and persist the
    /// updated catalog root to the A/B header.
    pub async fn set_realm_quotas(&self, realm: RealmId, quotas: RealmQuotas) -> Result<()> {
        self.ensure_usable()?;
        let mut state = self.writer.lock().await;
        self.ensure_usable()?;
        let key = Catalog::quota_key(realm);
        let value = Catalog::encode_realm_quotas(&quotas);

        let mut cat_tree = BTree::open(
            self.pager.clone(),
            self.realm_id,
            state.catalog_root_page_id,
            state.next_page_id,
            self.page_size,
        );
        cat_tree.put(&key, &value).await?;
        cat_tree.flush().await?;

        let new_catalog_root = cat_tree.root_page_id();
        let new_next = cat_tree.next_page_id();
        let new_catalog_txn_id = state
            .latest_commit_id
            .checked_add(1)
            .ok_or_else(|| PagedbError::arithmetic_overflow("catalog transaction id"))?;

        let header_cursor = self.pager.header_cursor()?;
        let new_seq = header_cursor.next_seq()?;
        let counter_anchor = self.pager.pending_anchor();
        let catalog_root_bytes = encode_root_ref(new_catalog_root, new_catalog_txn_id);

        let fields = self.header_fields(HeaderFieldsParams {
            mk_epoch: self.mk_epoch.load(Ordering::SeqCst),
            seq: new_seq,
            active_root_page_id: state.root_page_id,
            active_root_txn_id: state.latest_commit_id,
            counter_anchor,
            commit_id: state.latest_commit_id,
            catalog_root: catalog_root_bytes,
            commit_history_root_page_id: state.commit_history_root_page_id,
            commit_history_root_version: state.commit_history_root_version,
            free_list_root_page_id: state.free_list_root_page_id,
            next_page_id: new_next,
        })?;
        let hk_clone = { self.hk.read().clone() };
        let new_slot = commit_header(
            &*self.vfs,
            &self.main_db_path,
            &hk_clone,
            &fields,
            header_cursor.slot,
            self.page_size,
        )
        .await?;
        self.pager.note_header_written(HeaderCursor {
            slot: new_slot,
            seq: new_seq,
        });

        state.catalog_root_page_id = new_catalog_root;
        state.catalog_root_txn_id = new_catalog_txn_id;
        state.next_page_id = new_next;
        let _ = self
            .finish_durable_commit(
                &state,
                crate::CommitId(state.latest_commit_id),
                counter_anchor,
                &[],
            )
            .await?;

        Ok(())
    }

    /// Read per-realm quota caps from the catalog B+ tree. Returns
    /// `RealmQuotas::default()` if no entry has been written for this realm.
    pub async fn realm_quotas(&self, realm: RealmId) -> Result<RealmQuotas> {
        self.ensure_usable()?;
        let snapshot = *self.snapshot.read();
        let key = Catalog::quota_key(realm);
        let cat_tree = BTree::open(
            self.pager.clone(),
            self.realm_id,
            snapshot.catalog_root_page_id,
            snapshot.next_page_id,
            self.page_size,
        );
        match cat_tree.get(&key).await? {
            Some(bytes) => Catalog::decode_realm_quotas(&bytes),
            None => Ok(RealmQuotas::default()),
        }
    }

    /// Insert the new commit-history entry and prune per the retention policy.
    /// Returns the page ids freed by this tree's copy-on-write and pruning.
    ///
    /// Those ids go into the commit's free-list entry set like any other free,
    /// and deliberately **not** straight into the shared allocator cache. The
    /// cache is loaded once, at `begin_write`, from the bounded window of the
    /// durable chain that the following commit rewrites; a page pushed in from
    /// anywhere else would be handed to an allocator without the chain entry
    /// naming it ever being located, so nothing would delete it and the
    /// unscanned tail would keep naming it. One page id, two owners.
    ///
    /// `state` is the *candidate* writer state, not the shared one: this call
    /// is fallible at several points and runs long before the header that
    /// would make its new root durable, so a commit that never publishes must
    /// leave the shared state naming the old root. See [`PendingWriterState`].
    #[allow(clippy::too_many_lines)]
    pub(crate) async fn write_commit_history_entry(
        &self,
        state: &mut PendingWriterState,
        new_commit_id: u64,
        meta: CommitHistoryMeta,
    ) -> Result<Vec<u64>> {
        let min_pinned = {
            let readers = self.tracked_readers.lock();
            readers.iter().map(|r| r.commit_id.0).min()
        };

        let mut hist_tree = BTree::open(
            self.pager.clone(),
            self.realm_id,
            state.commit_history_root_page_id,
            state.next_page_id,
            self.page_size,
        );
        // The commit-history tree is not part of any reader's pinned snapshot
        // (readers track the data and catalog roots, never the history root), so
        // every page its copy-on-write/prune frees is immediately reusable
        // in-session — hence the zero reuse threshold.
        //
        // Sharing the allocator cache is a one-way street: this tree *draws*
        // from it (recording each draw in the consumed sink, which is what
        // deletes the entry from the rewritten window at commit) and never
        // pushes into it. Its own frees leave through `drain_freed` into the
        // commit's entry set instead, so no page reaches an allocator without
        // the window entry that names it having been located first.
        hist_tree.set_reuse_threshold(0);
        hist_tree.set_free_page_cache(self.free_page_cache.clone());
        hist_tree.set_free_page_consumed(self.free_page_consumed.clone());

        // Insert the new entry.
        let key = new_commit_id.to_be_bytes().to_vec();
        let value = encode_commit_meta(&meta);
        let was_new = hist_tree.get(&key).await?.is_none();
        hist_tree.put(&key, &value).await?;

        // Prune according to retention policy.
        let policy = &self.options.commit_history_retain;
        match policy {
            crate::options::RetainPolicy::Unbounded => {
                // No pruning.
                if was_new {
                    state.commit_history_count =
                        Some(state.commit_history_count.unwrap_or(0).saturating_add(1));
                }
            }
            crate::options::RetainPolicy::Count(n) => {
                let count = *n as usize;
                // Fast path: if the cached count is known and the post-insert
                // count is at or below the retain limit, we can skip the
                // full-tree scan entirely.
                let projected = state
                    .commit_history_count
                    .map(|c| if was_new { c.saturating_add(1) } else { c });
                if let Some(p) = projected {
                    if p <= u64::from(*n) {
                        state.commit_history_count = Some(p);
                        // Materialize and return below.
                    } else {
                        // Over-limit: do the scan + prune.
                        let all = hist_tree.collect_all().await?;
                        let mut current = all.len() as u64;
                        if all.len() > count {
                            let to_delete = all.len() - count;
                            for (k, _) in all.iter().take(to_delete) {
                                let mut b = [0u8; 8];
                                b.copy_from_slice(&k[..8]);
                                let cid = u64::from_be_bytes(b);
                                if let Some(min) = min_pinned {
                                    if cid >= min {
                                        continue;
                                    }
                                }
                                if hist_tree.delete(k).await? {
                                    current = current.saturating_sub(1);
                                }
                            }
                        }
                        state.commit_history_count = Some(current);
                    }
                } else {
                    // No cached count — do the scan to populate it.
                    let all = hist_tree.collect_all().await?;
                    let mut current = all.len() as u64;
                    if all.len() > count {
                        let to_delete = all.len() - count;
                        for (k, _) in all.iter().take(to_delete) {
                            let mut b = [0u8; 8];
                            b.copy_from_slice(&k[..8]);
                            let cid = u64::from_be_bytes(b);
                            if let Some(min) = min_pinned {
                                if cid >= min {
                                    continue;
                                }
                            }
                            if hist_tree.delete(k).await? {
                                current = current.saturating_sub(1);
                            }
                        }
                    }
                    state.commit_history_count = Some(current);
                }
            }
            crate::options::RetainPolicy::Age(duration) => {
                let now_secs = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs());
                let threshold = now_secs.saturating_sub(duration.as_secs());
                // History keys are the commit id big-endian, so lexicographic
                // key order is commit order and the prunable rows are always a
                // prefix of the oldest ones. Streaming that prefix in
                // fixed-size batches holds one batch resident instead of one
                // entry per retained commit — retention can be arbitrarily
                // deep, and this runs on every commit. The first row that must
                // be kept ends the walk: every row after it is a later commit,
                // so it is neither older than the threshold nor below the
                // reader floor.
                let mut deleted: u64 = 0;
                let mut cursor: Vec<u8> = Vec::new();
                'prune: loop {
                    let batch = hist_tree
                        .collect_batch_from(&cursor, HISTORY_PRUNE_BATCH)
                        .await?;
                    let Some((last_key, _)) = batch.last() else {
                        break;
                    };
                    cursor.clear();
                    cursor.extend_from_slice(last_key);
                    // The exact successor of `last_key` in the key ordering:
                    // resume strictly past the row just examined.
                    cursor.push(0);
                    let exhausted = batch.len() < HISTORY_PRUNE_BATCH;

                    for (k, v) in &batch {
                        // Never delete the entry we just inserted.
                        if k == &key {
                            break 'prune;
                        }
                        if k.len() != 8 {
                            return Err(PagedbError::catalog_row_invalid("commit_history.key"));
                        }
                        let mut b = [0u8; 8];
                        b.copy_from_slice(&k[..8]);
                        let cid = u64::from_be_bytes(b);
                        if min_pinned.is_some_and(|min| cid >= min) {
                            break 'prune;
                        }
                        if decode_commit_meta(v)?.unix_seconds >= threshold {
                            break 'prune;
                        }
                        if hist_tree.delete(k).await? {
                            deleted = deleted.saturating_add(1);
                        }
                    }

                    if exhausted {
                        break;
                    }
                }
                let projected = state
                    .commit_history_count
                    .map(|c| if was_new { c.saturating_add(1) } else { c });
                state.commit_history_count = projected.map(|c| c.saturating_sub(deleted));
            }
            crate::options::RetainPolicy::Disabled => {
                // Unreachable: `WriteTxn::commit` skips this call entirely
                // when the policy is `Disabled`. Treat any accidental call as
                // a no-op rather than panicking, to be defensive.
            }
        }

        // Materialize the history tree's dirty leaves into the pager (so the
        // commit's unified `pager.flush_main` picks them up) without issuing a
        // separate fsync. The caller is responsible for flushing the pager.
        hist_tree.materialize_dirty().await?;
        // Capture spine/prune frees after materialization (they are realized
        // during the flush, not before it).
        let freed: Vec<u64> = hist_tree
            .drain_freed()
            .into_iter()
            .filter(|&p| p >= 4)
            .collect();
        let new_hist_root = hist_tree.root_page_id();
        let new_next = hist_tree.next_page_id().max(state.next_page_id);

        state.commit_history_root_page_id = new_hist_root;
        state.commit_history_root_version = new_commit_id;
        state.next_page_id = new_next;

        Ok(freed)
    }
}

#[cfg(test)]
mod tests {
    use crate::vfs::memory::MemVfs;
    use crate::{Db, PagedbError, RealmId};

    use super::*;

    const PAGE: usize = 4096;
    const REALM: RealmId = RealmId::new([0xA7; 16]);

    #[tokio::test(flavor = "current_thread")]
    async fn counter_recovery_surfaces_malformed_counter_row() {
        let db = Db::open_internal(MemVfs::new(), [9u8; 32], PAGE, REALM)
            .await
            .unwrap();
        {
            let mut txn = db.begin_write().await.unwrap();
            let mut counter = txn.counter("bad-counter").unwrap();
            counter.set(5).await.unwrap();
            drop(counter);
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
        tree.put(&Catalog::counter_key(&[0xFF]).unwrap(), b"bad")
            .await
            .unwrap();
        tree.flush().await.unwrap();

        let err = db
            .validate_counter_rows(tree.root_page_id(), tree.next_page_id())
            .await
            .expect_err("malformed counter row must surface during recovery validation");
        assert!(matches!(err, PagedbError::Corruption(_)));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn oldest_retained_history_commit_surfaces_malformed_history_key() {
        for malformed_key in [b"x".as_slice(), b"123456789".as_slice()] {
            let db = Db::open_internal(MemVfs::new(), [9u8; 32], PAGE, REALM)
                .await
                .unwrap();
            let next_page_id = db.writer.lock().await.next_page_id;
            let mut history =
                BTree::open(db.pager.clone(), db.realm_id, 0, next_page_id, db.page_size);
            history
                .put(malformed_key, b"malformed history")
                .await
                .unwrap();
            history.flush().await.unwrap();

            let err = db
                .oldest_retained_history_commit(history.root_page_id(), history.next_page_id())
                .await
                .expect_err("malformed history key must surface");
            assert!(matches!(err, PagedbError::Corruption(_)));
        }
    }
}
