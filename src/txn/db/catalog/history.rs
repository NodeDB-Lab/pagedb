//! The commit-history index: appending an entry per commit, and pruning it back
//! to the configured retention.
//!
//! Both the append and the prune run on every commit, so neither may cost what
//! the index already holds. Retention is tracked across commits and the prune
//! streams the prefix it deletes; nothing here materialises the tree.

use crate::Result;
use crate::btree::BTree;
use crate::errors::PagedbError;
use crate::vfs::Vfs;

use crate::txn::db::core::{CommitHistoryMeta, Db, decode_commit_meta, encode_commit_meta};
use crate::txn::db::pending::PendingWriterState;

/// Commit-history rows read per batch while pruning. A key is 8 bytes and a row
/// 40, so this is a few tens of KiB resident regardless of how deep retention
/// has run.
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
        let mut hist_tree = BTree::open_session(
            self.pager.clone(),
            self.realm_id,
            state.commit_history_root_page_id,
            state.next_page_id,
            self.page_size,
            crate::btree::PageSource::new(
                0,
                self.free_page_cache.clone(),
                &self.free_page_consumed,
            ),
        );

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
                // The retained count is tracked across commits, so the usual
                // commit knows whether it is over the limit without reading the
                // tree at all. It is unknown only on the first commit after
                // opening an existing store, and is recovered there by counting
                // in bounded batches — never by materialising the tree, which
                // would size an allocation by how deep retention has run and
                // put that on every commit once the limit is passed.
                let known = match state.commit_history_count {
                    Some(cached) => cached,
                    None => count_history_rows(&hist_tree).await?,
                };
                let total = if was_new {
                    known.saturating_add(1)
                } else {
                    known
                };
                let excess = total.saturating_sub(u64::from(*n));
                let deleted = if excess == 0 {
                    0
                } else {
                    prune_oldest_history_rows(&mut hist_tree, excess, min_pinned).await?
                };
                state.commit_history_count = Some(total.saturating_sub(deleted));
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

/// Count the rows the commit-history index holds, streaming them in bounded
/// batches.
///
/// Reached only when the tracked count is unknown — the first commit after
/// opening an existing store. Retention can be arbitrarily deep, so the count
/// is accumulated rather than the rows collected: the answer is a number, and
/// holding the tree to produce it would size an allocation by the embedder's
/// retention setting.
async fn count_history_rows<V: Vfs + Clone>(tree: &BTree<V>) -> Result<u64> {
    let mut total: u64 = 0;
    let mut cursor: Vec<u8> = Vec::new();
    loop {
        let batch = tree
            .collect_batch_from(&cursor, HISTORY_PRUNE_BATCH)
            .await?;
        let Some((last_key, _)) = batch.last() else {
            return Ok(total);
        };
        total = total.saturating_add(batch.len() as u64);
        if batch.len() < HISTORY_PRUNE_BATCH {
            return Ok(total);
        }
        cursor.clear();
        cursor.extend_from_slice(last_key);
        // The exact successor of `last_key` in the key ordering: resume
        // strictly past the row just counted.
        cursor.push(0);
    }
}

/// Delete up to `excess` of the oldest rows, stopping at the first row a live
/// reader still pins. Returns how many were deleted.
///
/// History keys are the commit id big-endian, so key order is commit order and
/// the prunable rows are always a prefix of the oldest ones. The prefix is
/// streamed in fixed-size batches: in the steady state `excess` is 1, and the
/// cost of a commit is the row it removes rather than the depth of the
/// retention behind it.
///
/// The first pinned row ends the walk rather than being skipped: every row
/// after it is a later commit, so it is pinned too.
async fn prune_oldest_history_rows<V: Vfs + Clone>(
    tree: &mut BTree<V>,
    excess: u64,
    min_pinned: Option<u64>,
) -> Result<u64> {
    let mut deleted: u64 = 0;
    let mut cursor: Vec<u8> = Vec::new();
    while deleted < excess {
        // Ask for what is left to delete, not for a fixed batch. The steady
        // state removes a single row, and reading a full batch to find it would
        // charge every commit the batch size instead of the work. The cap is
        // what bounds residency when a real backlog has to drain.
        let want = usize::try_from(excess - deleted)
            .unwrap_or(HISTORY_PRUNE_BATCH)
            .min(HISTORY_PRUNE_BATCH);
        let batch = tree.collect_batch_from(&cursor, want).await?;
        let Some((last_key, _)) = batch.last() else {
            break;
        };
        cursor.clear();
        cursor.extend_from_slice(last_key);
        cursor.push(0);
        let exhausted = batch.len() < want;

        for (key, _) in &batch {
            if deleted >= excess {
                return Ok(deleted);
            }
            if key.len() != 8 {
                return Err(PagedbError::catalog_row_invalid("commit_history.key"));
            }
            let mut raw = [0u8; 8];
            raw.copy_from_slice(&key[..8]);
            if min_pinned.is_some_and(|min| u64::from_be_bytes(raw) >= min) {
                return Ok(deleted);
            }
            if tree.delete(key).await? {
                deleted = deleted.saturating_add(1);
            }
        }
        if exhausted {
            break;
        }
    }
    Ok(deleted)
}

#[cfg(test)]
mod tests {
    use crate::btree::BTree;
    use crate::options::RetainPolicy;
    use crate::vfs::memory::MemVfs;
    use crate::{Db, OpenOptions, PagedbError, RealmId};

    const PAGE: usize = 4096;
    const REALM: RealmId = RealmId::new([0xA7; 16]);

    /// A commit must not cost what retention holds.
    ///
    /// Retention holds the reclamation floor down, so a deep history keeps a
    /// large set of free-list entries un-recyclable. Nothing on the commit path
    /// may walk that set: what the commit does is bounded by what it changed,
    /// and the depth of retention is a property of the store, not of the write.
    ///
    /// Both depths are past the point where the bounded free-list window is
    /// full, so the window's own fixed cost is the same on each side and the
    /// only thing varying is how much retention holds. Comparing a depth below
    /// saturation against one above it would measure the window filling up,
    /// which is a constant, and read as a scaling term that is not there.
    #[tokio::test(flavor = "current_thread")]
    async fn commit_cost_does_not_scale_with_retention_depth() {
        use std::sync::atomic::Ordering;

        async fn steady_state_commit_cost(retain: u32) -> u64 {
            let db = Db::open_internal_with_options(
                MemVfs::new(),
                [7u8; 32],
                PAGE,
                REALM,
                OpenOptions::default().with_commit_history_retain(RetainPolicy::Count(retain)),
            )
            .await
            .unwrap();
            for _ in 0..(u64::from(retain) + 8) {
                db.begin_write().await.unwrap().commit().await.unwrap();
            }
            let lookups = || {
                db.pager.inner.buffer_pool_hits.load(Ordering::Relaxed)
                    + db.pager.inner.buffer_pool_misses.load(Ordering::Relaxed)
            };
            let before = lookups();
            db.begin_write().await.unwrap().commit().await.unwrap();
            lookups() - before
        }

        let shallow = steady_state_commit_cost(1024).await;
        let deep = steady_state_commit_cost(2048).await;

        assert!(
            deep < shallow * 2,
            "a commit cost {deep} page lookups at a 2048-row retention against {shallow} at \
             1024 — twice the rows: the commit path is walking what retention holds"
        );
    }

    /// Once retention is at its limit every commit is a prune, and the prune
    /// must cost the row it removes rather than the depth of the index behind
    /// it.
    ///
    /// Isolated by holding the index size fixed and varying only whether
    /// pruning happens: an unbounded policy builds the same tree and never
    /// prunes, so the difference between the two is the prune and nothing else.
    /// Comparing across retention settings instead would fold in the cost of a
    /// taller tree, which is legitimate and would mask what is being measured.
    #[tokio::test(flavor = "current_thread")]
    async fn pruning_history_costs_the_row_it_removes_not_the_depth_retained() {
        use std::sync::atomic::Ordering;

        const ROWS: u64 = 2048;

        async fn steady_state_commit_cost(policy: RetainPolicy) -> u64 {
            let db = Db::open_internal_with_options(
                MemVfs::new(),
                [7u8; 32],
                PAGE,
                REALM,
                OpenOptions::default().with_commit_history_retain(policy),
            )
            .await
            .unwrap();

            for _ in 0..(ROWS + 8) {
                db.begin_write().await.unwrap().commit().await.unwrap();
            }

            let lookups = || {
                db.pager.inner.buffer_pool_hits.load(Ordering::Relaxed)
                    + db.pager.inner.buffer_pool_misses.load(Ordering::Relaxed)
            };
            let before = lookups();
            db.begin_write().await.unwrap().commit().await.unwrap();
            lookups() - before
        }

        let pruning =
            steady_state_commit_cost(RetainPolicy::Count(u32::try_from(ROWS).expect("fits"))).await;
        let not_pruning = steady_state_commit_cost(RetainPolicy::Unbounded).await;

        assert!(
            pruning <= not_pruning + 16,
            "a commit that prunes one row from a {ROWS}-row index cost {pruning} page lookups \
             against {not_pruning} for the same index with no pruning: the prune is reading \
             back what retention holds"
        );
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
