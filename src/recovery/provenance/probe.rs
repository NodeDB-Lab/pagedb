//! Answering, for one page id, the question an authentication failure raises
//! and cannot answer on its own: was this page in use, was it free, or was it
//! somehow both.
//!
//! A page that will not authenticate has several possible causes with very
//! different consequences. If the page is reachable from a live root *and*
//! named by the free list, it was handed to two owners — a page reused while
//! still referenced, which silently destroys data and will do so again. If it
//! is reachable and not free, or free and not reachable, the store's structures
//! are consistent and the fault is in the page's own bytes: a torn write or a
//! media error, bad but bounded. If it is neither, the page is a leak.
//!
//! Distinguishing those is a matter of reading the roots and the free list,
//! which the layer that detects the failure cannot do — the pager knows page
//! identity, not what references it. So the probe lives here and is asked for
//! by page id, from a handle that has both.

use std::collections::BTreeSet;

use crate::Db;
use crate::btree::BTree;
use crate::pager::freelist::ChainWalk;
use crate::vfs::Vfs;
use crate::{RealmId, Result};

/// Which of the store's structures claim a page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageStanding {
    /// Reachable from a live root and named by the free list. The page was
    /// handed to two owners; an authentication failure here is a symptom, and
    /// the reuse is the fault.
    LiveAndFree,
    /// Reachable from a live root and not free. The structures agree that this
    /// page is in use, so a failure to authenticate it is about its bytes.
    Live,
    /// Named by the free list and reachable from nothing. Consistent: a free
    /// page holds whatever it last held, and nothing should be reading it.
    Free,
    /// Claimed by neither, and below the allocation cursor. A leak — space that
    /// no root reaches and no free-list entry will return.
    Orphaned,
    /// At or above the allocation cursor: never allocated.
    BeyondCursor,
    /// Reachable from no root, and the free list could not be read to say
    /// whether it is free or leaked.
    ///
    /// Distinct from [`Self::Orphaned`] because the difference is a claim about
    /// the allocator, and the structure that would support it is the damaged
    /// one. What it does establish is the half that matters most: no live root
    /// refers to this page, so nothing is reading it as data.
    FreeListUnreadable,
}

/// What the store says about one page.
#[derive(Debug, Clone)]
pub struct PageProvenance {
    pub page_id: u64,
    pub standing: PageStanding,
    /// The commit that freed it, when the free list names it.
    pub freed_by_commit: Option<u64>,
    /// Roots that reach it, by name (`"data"`, `"catalog"`, `"commit-history"`).
    pub reachable_from: Vec<&'static str>,
    /// Allocation cursor the answer was computed against.
    pub next_page_id: u64,
    /// Whether the free-list half of the answer could be computed at all.
    ///
    /// `false` means the chain would not read, so `freed_by_commit` is `None`
    /// for lack of evidence rather than because the page is not free.
    pub free_list_readable: bool,
}

impl PageProvenance {
    /// Whether this page shows the store handing one id to two owners.
    #[must_use]
    pub fn is_double_owned(&self) -> bool {
        self.standing == PageStanding::LiveAndFree
    }
}

impl<V: Vfs + Clone> Db<V> {
    /// What this store's roots and free list say about `page_id`.
    ///
    /// Answer this after any page fails to authenticate, before concluding
    /// anything about the cause: [`PageStanding::LiveAndFree`] means a page was
    /// reused while still referenced and the store has a structural fault that
    /// will recur, while every other standing points at the page's own bytes.
    ///
    /// Deliberately expensive — it walks each live root — because it runs once,
    /// on a failure that has already stopped the work it interrupted, and the
    /// alternative is not knowing.
    pub async fn page_provenance(&self, page_id: u64) -> Result<PageProvenance> {
        let (data_root, catalog_root, history_root, next_page_id, free_list_root) = {
            let state = self.writer.lock().await;
            (
                state.root_page_id,
                state.catalog_root_page_id,
                state.commit_history_root_page_id,
                state.next_page_id,
                state.free_list_root_page_id,
            )
        };

        let mut reachable_from = Vec::new();
        for (name, root) in [
            ("data", data_root),
            ("catalog", catalog_root),
            ("commit-history", history_root),
        ] {
            if root == 0 {
                continue;
            }
            let mut pages = BTreeSet::new();
            BTree::open(
                self.pager.clone(),
                self.realm_id,
                root,
                next_page_id,
                self.page_size,
            )
            .collect_all_page_ids(&mut pages)
            .await?;
            if pages.contains(&page_id) {
                reachable_from.push(name);
            }
        }

        // The free-list half is best-effort. This runs precisely when something
        // failed to authenticate, and one of the things that can fail is the
        // free-list chain itself — including the page being asked about. Letting
        // that error escape makes the probe unanswerable exactly when the answer
        // matters, so an unreadable chain narrows the verdict instead of
        // replacing it: root reachability alone still separates "live page that
        // something also freed" from "page no root refers to".
        let free_list = free_list_entry(self, self.realm_id, free_list_root, page_id).await;
        let free_list_readable = free_list.is_ok();
        let freed_by_commit = free_list.unwrap_or(None);

        let standing = match (reachable_from.is_empty(), freed_by_commit.is_some()) {
            (false, true) => PageStanding::LiveAndFree,
            (false, false) => PageStanding::Live,
            (true, true) => PageStanding::Free,
            // Without a readable free list, "no root reaches it" cannot be
            // sharpened into orphaned-versus-free: the structure that would
            // distinguish them is the damaged one.
            (true, false) if !free_list_readable => PageStanding::FreeListUnreadable,
            (true, false) if page_id >= next_page_id => PageStanding::BeyondCursor,
            (true, false) => PageStanding::Orphaned,
        };

        Ok(PageProvenance {
            page_id,
            standing,
            freed_by_commit,
            reachable_from,
            next_page_id,
            free_list_readable,
        })
    }
}

/// The commit that freed `page_id`, if the chain names it.
///
/// Walks rather than materialising: the chain is as long as the store is free,
/// and this runs on a failure path where holding all of it would be a second
/// problem on top of the first.
async fn free_list_entry<V: Vfs + Clone>(
    db: &Db<V>,
    realm_id: RealmId,
    head: u64,
    page_id: u64,
) -> Result<Option<u64>> {
    let mut walk = ChainWalk::new(head);
    while walk.advance(&db.pager, realm_id).await?.is_some() {
        if let Some((commit_id, _)) = walk
            .entries()
            .iter()
            .find(|(_, candidate)| *candidate == page_id)
        {
            return Ok(Some(*commit_id));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::PageStanding;
    use crate::vfs::memory::MemVfs;
    use crate::{Db, RealmId};

    const PAGE: usize = 4096;
    const REALM: RealmId = RealmId::new([0x3C; 16]);

    async fn seeded() -> Db<MemVfs> {
        let db = Db::open_internal(MemVfs::new(), [4u8; 32], PAGE, REALM)
            .await
            .unwrap();
        for i in 0..32u32 {
            let mut txn = db.begin_write().await.unwrap();
            txn.put(format!("k{i}").as_bytes(), b"value").await.unwrap();
            txn.commit().await.unwrap();
        }
        db
    }

    /// A page the data root reaches is in use, and the probe must say so
    /// without qualification — that is what makes the contrary answer mean
    /// something.
    #[tokio::test(flavor = "current_thread")]
    async fn a_page_the_root_reaches_reads_as_live() {
        let db = seeded().await;
        let root = db.writer.lock().await.root_page_id;

        let provenance = db.page_provenance(root).await.unwrap();
        assert_eq!(provenance.standing, PageStanding::Live);
        assert!(provenance.reachable_from.contains(&"data"));
        assert_eq!(provenance.freed_by_commit, None);
        assert!(!provenance.is_double_owned());
    }

    /// A page the free list names and no root reaches is consistent: it holds
    /// whatever it last held and nothing should be reading it.
    #[tokio::test(flavor = "current_thread")]
    async fn a_freed_page_reads_as_free_and_names_the_commit_that_freed_it() {
        let db = seeded().await;
        let (head, realm) = {
            let state = db.writer.lock().await;
            (state.free_list_root_page_id, db.realm_id)
        };
        let (entries, _) = crate::pager::freelist::read_chain(&db.pager, realm, head)
            .await
            .unwrap();
        let Some(&(commit_id, page_id)) = entries.first() else {
            panic!("the fixture must leave at least one page on the free list");
        };

        let provenance = db.page_provenance(page_id).await.unwrap();
        assert_eq!(provenance.standing, PageStanding::Free);
        assert_eq!(provenance.freed_by_commit, Some(commit_id));
        assert!(provenance.reachable_from.is_empty());
        assert!(!provenance.is_double_owned());
    }

    /// The finding the probe exists for. A page reachable from a live root and
    /// simultaneously named by the free list was handed to two owners, and no
    /// amount of detail about the failing page's own bytes would reveal it.
    #[tokio::test(flavor = "current_thread")]
    async fn a_page_that_is_both_reachable_and_free_reads_as_double_owned() {
        let db = seeded().await;
        let (root, next_page_id, head) = {
            let state = db.writer.lock().await;
            (
                state.root_page_id,
                state.next_page_id,
                state.free_list_root_page_id,
            )
        };

        // Forge the fault this probe is meant to name: record a page the data
        // root still reaches as free. That is precisely what reusing a
        // referenced page leaves behind.
        let (mut entries, chain_pages) =
            crate::pager::freelist::read_chain(&db.pager, db.realm_id, head)
                .await
                .unwrap();
        entries.push((1, root));
        let hosts: Vec<u64> = chain_pages.clone();
        crate::pager::freelist::write_chain(
            &db.pager,
            db.realm_id,
            db.page_size,
            &hosts,
            &entries,
            crate::pager::freelist::ChainTail::EMPTY,
        )
        .await
        .unwrap();
        db.pager.flush_main(db.realm_id).await.unwrap();
        {
            let mut state = db.writer.lock().await;
            state.free_list_root_page_id = hosts[0];
            state.next_page_id = next_page_id;
        }

        let provenance = db.page_provenance(root).await.unwrap();
        assert_eq!(provenance.standing, PageStanding::LiveAndFree);
        assert!(
            provenance.is_double_owned(),
            "a page both reachable and free is the store handing one id to two owners"
        );
        assert_eq!(provenance.freed_by_commit, Some(1));
    }

    /// A page past the allocation cursor was never handed out, so it is not a
    /// leak and must not read as one.
    #[tokio::test(flavor = "current_thread")]
    async fn a_page_past_the_cursor_reads_as_never_allocated() {
        let db = seeded().await;
        let next_page_id = db.writer.lock().await.next_page_id;

        let provenance = db.page_provenance(next_page_id + 10).await.unwrap();
        assert_eq!(provenance.standing, PageStanding::BeyondCursor);
    }
}
