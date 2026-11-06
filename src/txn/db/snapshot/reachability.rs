// SPDX-License-Identifier: Apache-2.0

//! Published and reader-visible page sets.

use super::super::catalog::history_policy::{ALL_HISTORY_ROWS, proves_unreadable_pages};
use super::super::catalog::history_seals::HistorySealScan;
use super::super::core::{Db, ReaderSnapshot, WriterState, decode_commit_meta};
use crate::pager::Pager;
use crate::vfs::Vfs;
use std::collections::BTreeSet;
use std::sync::Arc;

/// Commit-history rows read per batch while screening them against a delta.
/// Rows are 40 bytes, so this is a few KiB resident however deep retention runs.
const HISTORY_ROW_BATCH: usize = 512;

/// Every page the data and catalog trees rooted at the two ids reach.
///
/// Takes the `Pager` explicitly rather than reading it off the `Db`: an apply
/// walks the *target*'s roots, and those live in a staged image that only a
/// dedicated read-only view is pointed at.
pub(super) async fn collect_tree_page_ids<V: Vfs + Clone>(
    pager: &Arc<Pager<V>>,
    realm_id: crate::RealmId,
    page_size: usize,
    active_root_page_id: u64,
    catalog_root_page_id: u64,
    next_page_id: u64,
) -> crate::Result<BTreeSet<u64>> {
    let mut page_ids = BTreeSet::new();
    for root_page_id in [active_root_page_id, catalog_root_page_id] {
        if root_page_id == 0 {
            continue;
        }
        let tree = crate::btree::BTree::open(
            pager.clone(),
            realm_id,
            root_page_id,
            next_page_id,
            page_size,
        );
        tree.collect_all_page_ids(&mut page_ids).await?;
    }
    Ok(page_ids)
}

impl<V: Vfs + Clone> Db<V> {
    /// Refuse a delta that rewrites a page a registered reader can reach.
    ///
    /// The delta screen covers the published base only. A reader pinned further
    /// back can reach a page a later commit freed. The producer recycles that
    /// id. The new bytes authenticate under the same page id, so that reader
    /// receives them with no error.
    ///
    /// A reader at the base roots is skipped, because the screen already covers
    /// it. Readers sharing a pinned state share one walk. A reader whose pages
    /// cannot be walked counts as a conflict, because nothing proves it disjoint.
    ///
    /// Reads the live Pager, which serves the unchanged base image until the swap.
    pub(super) async fn refuse_delta_reaching_pinned_reader(
        &self,
        base: ReaderSnapshot,
        delta_page_ids: &BTreeSet<u64>,
    ) -> crate::Result<()> {
        let pinned: BTreeSet<(u64, u64, u64, u64)> = {
            let readers = self.tracked_readers.lock();
            readers
                .iter()
                .filter(|reader| {
                    reader.root_page_id != base.root_page_id
                        || reader.catalog_root_page_id != base.catalog_root_page_id
                })
                .map(|reader| {
                    (
                        reader.commit_id.0,
                        reader.root_page_id,
                        reader.catalog_root_page_id,
                        reader.next_page_id,
                    )
                })
                .collect()
        };
        for (commit, root_page_id, catalog_root_page_id, next_page_id) in pinned {
            let conflict = match collect_tree_page_ids(
                &self.pager,
                self.realm_id,
                self.page_size,
                root_page_id,
                catalog_root_page_id,
                next_page_id,
            )
            .await
            {
                Ok(reachable) => !reachable.is_disjoint(delta_page_ids),
                Err(error) => {
                    tracing::debug!(
                        name = "apply.pinned_reader_unwalkable",
                        commit,
                        error = %error,
                        "refusing an apply over a reader whose pages cannot be walked"
                    );
                    true
                }
            };
            if conflict {
                return Err(crate::errors::PagedbError::apply_blocked_by_pinned_reader(
                    crate::CommitId(commit),
                ));
            }
        }
        Ok(())
    }

    /// The newest row an apply must prune, or `None` when every row stays.
    ///
    /// Rows this handle must not keep leave whatever the delta names, so nothing
    /// walks them.
    pub(super) async fn history_rows_apply_prunes(
        &self,
        state: &WriterState,
        visited: BTreeSet<u64>,
        delta_page_ids: &BTreeSet<u64>,
    ) -> crate::Result<Option<u64>> {
        if self.history_rows_gone(state) {
            return Ok(Some(ALL_HISTORY_ROWS));
        }
        self.newest_history_row_reaching_delta(state, visited, delta_page_ids)
            .await
    }

    /// The newest retained commit whose pages a delta overwrites, or `None` when
    /// every row stays intact.
    ///
    /// A retained row reaches pages a later commit freed and the producer can
    /// recycle. An apply over such a page leaves the row naming newer bytes.
    /// So that row and every older row must leave the carried history.
    ///
    /// Rows run newest to oldest and stop at the first overlap. Pruning a prefix
    /// keeps the oldest retained commit monotonic.
    ///
    /// A row also leaves when seal order proves an earlier apply overwrote it. See
    /// the `history_seals` module. This needs each shared page's newest seal, so
    /// the scan also reads the pages a row shares with the base, once each.
    ///
    /// `visited` arrives holding the base's reader-visible pages. The delta screen
    /// proved them disjoint from the delta. When the store cannot show seal order,
    /// a row at the base roots reads nothing, and each other page is read once
    /// across all rows.
    ///
    /// A row that cannot be walked counts as an overlap, because nothing proves
    /// it disjoint. Reads the live Pager, which serves the unchanged base image.
    async fn newest_history_row_reaching_delta(
        &self,
        state: &WriterState,
        mut visited: BTreeSet<u64>,
        delta_page_ids: &BTreeSet<u64>,
    ) -> crate::Result<Option<u64>> {
        if state.commit_history_root_page_id == 0 || delta_page_ids.is_empty() {
            return Ok(None);
        }
        let history = crate::btree::BTree::open(
            self.pager.clone(),
            self.realm_id,
            state.commit_history_root_page_id,
            state.next_page_id,
            self.page_size,
        );
        let mut scan = self.begin_history_seal_scan(state);
        let mut before: Option<bytes::Bytes> = None;
        loop {
            let batch = history
                .collect_rev_batch_before(before.as_deref(), HISTORY_ROW_BATCH)
                .await?;
            for (key, row) in &batch {
                let commit = <[u8; 8]>::try_from(&key[..]).map_err(|_| {
                    crate::errors::PagedbError::catalog_row_invalid("commit_history.key")
                })?;
                let commit = u64::from_be_bytes(commit);
                if self
                    .history_row_reaches_delta(commit, row, &mut visited, &mut scan, delta_page_ids)
                    .await?
                {
                    return Ok(Some(commit));
                }
            }
            if batch.len() < HISTORY_ROW_BATCH {
                return Ok(None);
            }
            before = batch.last().map(|(key, _)| key.clone());
        }
    }

    /// Whether one history row reaches a delta page, holds a page sealed after a
    /// later commit's root, or has pages that cannot authenticate.
    ///
    /// Pruning is durable, so only proof about the page bytes prunes a row. An I/O
    /// error or a cache fault says nothing about them, so it fails the apply instead.
    async fn history_row_reaches_delta(
        &self,
        commit: u64,
        row: &[u8],
        visited: &mut BTreeSet<u64>,
        scan: &mut HistorySealScan,
        delta_page_ids: &BTreeSet<u64>,
    ) -> crate::Result<bool> {
        let walked = if scan.void().is_some() {
            self.collect_history_row_pages(row, visited).await
        } else {
            self.scan_history_row_pages(commit, row, scan).await
        };
        match walked {
            Ok(reached) => Ok(reached.is_none_or(|pages| !pages.is_disjoint(delta_page_ids))),
            Err(error) if proves_unreadable_pages(&error) => {
                tracing::debug!(
                    name = "apply.history_row_unwalkable",
                    commit,
                    error = %error,
                    "pruning a retained commit whose pages cannot authenticate"
                );
                Ok(true)
            }
            Err(error) => Err(error),
        }
    }

    /// The row's new pages, or `None` when seal order proves it stale.
    async fn scan_history_row_pages(
        &self,
        commit: u64,
        row: &[u8],
        scan: &mut HistorySealScan,
    ) -> crate::Result<Option<BTreeSet<u64>>> {
        let meta = decode_commit_meta(row)?;
        let (reached, resealed) = self.scan_history_row(scan, &meta).await?;
        if let Some(found) = resealed {
            tracing::warn!(
                name = "apply.history_row_resealed",
                commit,
                page = found.page.page_id,
                page_counter = found.page.counter,
                later_root = found.later_root.page_id,
                later_root_counter = found.later_root.counter,
                "pruning a retained commit with a page sealed after it"
            );
            return Ok(None);
        }
        Ok(Some(reached))
    }

    /// The pages one history row reaches that `visited` does not hold yet.
    ///
    /// The row's own `next_page_id` bounds its trees. Its free-list root is
    /// superseded writer metadata that no reader follows, so it stays unread.
    async fn collect_history_row_pages(
        &self,
        row: &[u8],
        visited: &mut BTreeSet<u64>,
    ) -> crate::Result<Option<BTreeSet<u64>>> {
        let meta = decode_commit_meta(row)?;
        let mut reached = BTreeSet::new();
        for root_page_id in [meta.active_root_page_id, meta.catalog_root_page_id] {
            crate::btree::BTree::open(
                self.pager.clone(),
                self.realm_id,
                root_page_id,
                meta.next_page_id,
                self.page_size,
            )
            .collect_unvisited_page_ids(visited, &mut reached)
            .await?;
        }
        Ok(Some(reached))
    }
}

/// Every page a published state occupies: the reader-visible data and catalog
/// trees, plus the free-list chain and commit-history tree hanging off the same
/// header.
///
/// This is deliberately wider than the set that defines a delta. A delta is
/// target-reachable minus base-*reader-visible*, because those are the only
/// pages both sides of the protocol can name; the free-list chain and
/// commit-history tree are the follower's own and invisible to the producer.
/// Subtracting the wider set when deciding which pages a delta should contain
/// would turn every page the producer legitimately allocated over a
/// follower-local page into an unexplained set mismatch.
///
/// A verbatim export needs the wider set instead, as a length floor: the copied
/// `main.db` must physically contain every page its header names, not only the
/// ones a reader can walk to.
pub(super) async fn collect_published_page_ids<V: Vfs + Clone>(
    db: &Db<V>,
    snapshot: ReaderSnapshot,
) -> crate::Result<BTreeSet<u64>> {
    let mut published = collect_tree_page_ids(
        &db.pager,
        db.realm_id,
        db.page_size,
        snapshot.root_page_id,
        snapshot.catalog_root_page_id,
        snapshot.next_page_id,
    )
    .await?;
    if snapshot.commit_history_root_page_id != 0 {
        let history = crate::btree::BTree::open(
            db.pager.clone(),
            db.realm_id,
            snapshot.commit_history_root_page_id,
            snapshot.next_page_id,
            db.page_size,
        );
        history.collect_all_page_ids(&mut published).await?;
    }
    if snapshot.free_list_root_page_id != 0 {
        let (_entries, chain_pages) = crate::pager::freelist::read_chain(
            &db.pager,
            db.realm_id,
            snapshot.free_list_root_page_id,
        )
        .await?;
        published.extend(chain_pages);
    }
    Ok(published)
}
