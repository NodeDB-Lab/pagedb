//! Folding the pages a catalog-only header commit superseded into the durable
//! free list.

use crate::Result;
use crate::vfs::Vfs;

use super::core::{Db, WriterState};

/// A rewritten free-list chain, staged in the Pager. Only the header that names
/// `root_page_id` makes it durable, so `WriterState` must not take these values
/// before that header lands.
pub(crate) struct FoldedFreeList {
    pub root_page_id: u64,
    pub entries: Option<u64>,
    pub next_page_id: u64,
}

impl<V: Vfs + Clone> Db<V> {
    /// Fold `freed_pages` into the free list, as the commit path does.
    ///
    /// Every catalog rewrite outside `WriteTxn` routes its copy-on-write leftovers
    /// here. Without it the pages are reachable from no root and named by no
    /// free-list entry. Entries carry the commit id after the latest one. The
    /// reclamation floor therefore withholds any page a live reader or retained
    /// root names.
    ///
    /// A bounded window, spliced onto the retained tail, is enough. The fold only
    /// prepends entries, so nothing here needs a view of the complete set. Hosts
    /// are empty, so no page reaches an allocator from this path. The window
    /// carries no duplicate-safety obligation beyond deleting what it rewrites.
    pub(crate) async fn fold_freed_catalog_pages(
        &self,
        state: &WriterState,
        freed_pages: &[u64],
        next_page_id: u64,
    ) -> Result<FoldedFreeList> {
        if freed_pages.is_empty() {
            return Ok(FoldedFreeList {
                root_page_id: state.free_list_root_page_id,
                entries: state.free_list_entries,
                next_page_id,
            });
        }
        let window = crate::pager::freelist::read_chain_prefix(
            &self.pager,
            self.realm_id,
            state.free_list_root_page_id,
            crate::pager::freelist::WINDOW_PAGES,
        )
        .await?;
        let mut entries = window.entries;
        // The latest commit's retained row still reaches these pages. An entry is
        // reusable when its tag is at or below the oldest row. Tagging one past
        // the latest holds them until that row is gone.
        let freed_at = state.latest_commit_id.saturating_add(1);
        entries.extend(freed_pages.iter().map(|&page_id| (freed_at, page_id)));
        // Chain pages are writer-only metadata that no reader snapshot traverses.
        // They carry a commit id below every real floor and are recyclable at
        // once. The ordinary commit path uses the same rule.
        entries.extend(
            window
                .chain_pages
                .into_iter()
                .map(|page_id| (crate::pager::freelist::CHAIN_METADATA_CID, page_id)),
        );
        let (root_page_id, next_page_id) = crate::pager::freelist::rewrite_chain(
            &self.pager,
            self.realm_id,
            self.page_size,
            entries,
            Vec::new(),
            next_page_id,
            window.tail,
        )
        .await?;
        // The head is dirty in the cache unless the window rewrote no entries.
        let entries =
            crate::pager::freelist::count_chain(&self.pager, self.realm_id, root_page_id).await?;
        Ok(FoldedFreeList {
            root_page_id,
            entries: Some(entries),
            next_page_id,
        })
    }
}
