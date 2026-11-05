// SPDX-License-Identifier: Apache-2.0

//! Published and reader-visible page sets.

use super::super::core::{Db, ReaderSnapshot};
use crate::pager::Pager;
use crate::vfs::Vfs;
use std::collections::BTreeSet;
use std::sync::Arc;

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
    /// would receive them with no error.
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
