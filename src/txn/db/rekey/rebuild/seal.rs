//! Finish the scratch image: its catalog, its free list, and its own header.

use std::collections::BTreeMap;

use crate::Result;
use crate::btree::BTree;
use crate::catalog::codec::{Catalog, RekeyIntent, RekeyStage};
use crate::crypto::DerivedKey;
use crate::pager::PageKind;
use crate::pager::core::RebuildImage;
use crate::pager::freelist::CHAIN_METADATA_CID;
use crate::pager::header::{ActiveSlot, commit_header};
use crate::pager::page_space::{FIRST_ALLOCATABLE_PAGE_ID, page_offset};
use crate::txn::db::core::encode_free_list_root;
use crate::txn::db::{Db, WriterState};
use crate::vfs::{OpenMode, Vfs, VfsFile};

/// What the scratch header names. `WriterState` takes these values at the rename.
pub(super) struct ScratchImage {
    pub catalog_root_page_id: u64,
    pub next_page_id: u64,
    pub free_list_root_page_id: u64,
    pub free_list_entries: Option<u64>,
    pub header_seq: u64,
    pub counter_anchor: u64,
}

/// The pages below `next_page_id` that the rebuild did not copy.
fn unnamed_pages(named: &BTreeMap<u64, PageKind>, next_page_id: u64) -> Vec<u64> {
    (FIRST_ALLOCATABLE_PAGE_ID..next_page_id)
        .filter(|page_id| !named.contains_key(page_id))
        .collect()
}

impl<V: Vfs + Clone> Db<V> {
    /// Size `scratch` to `next_page_id` pages, and make the size durable.
    ///
    /// Every page the rebuild does not write reads as zeros, on every backend.
    pub(super) async fn size_scratch(&self, scratch: &str, next_page_id: u64) -> Result<()> {
        let len = page_offset(next_page_id, self.page_size, "rekey scratch length")?;
        let mut file = self.vfs.open(scratch, OpenMode::CreateOrOpen).await?;
        file.set_len(len).await?;
        file.sync().await
    }

    /// Write the `MainDone` intent into the scratch catalog and the target-epoch
    /// header into the scratch's slot A. The scratch is then a complete `main.db`.
    /// Nothing here touches the live file or `state`.
    ///
    /// A page the rebuild did not copy is a zero hole, and no root and no free
    /// list named it. The free list names it now, so the space stays usable and a
    /// deep walk has no leak to report. This is safe where inferring free pages on
    /// a live file is not. The page holds nothing, so a wrong inference loses
    /// nothing a reference can still read.
    pub(super) async fn seal_scratch_image(
        &self,
        state: &WriterState,
        intent: &RekeyIntent,
        named: &BTreeMap<u64, PageKind>,
        scratch_path: &str,
        image: &RebuildImage,
        target_header_key: &DerivedKey,
    ) -> Result<ScratchImage> {
        let mut main_done = intent.clone();
        main_done.stage = RekeyStage::MainDone;
        let mut catalog = BTree::open(
            self.pager.clone(),
            self.realm_id,
            state.catalog_root_page_id,
            state.next_page_id,
            self.page_size,
        );
        catalog
            .put(
                &Catalog::rekey_state_key(),
                &Catalog::encode_rekey_intent(&main_done),
            )
            .await?;
        catalog.materialize_dirty().await?;

        let freed_tag = Self::catalog_free_tag(state);
        let mut new_entries: Vec<(u64, u64)> = catalog
            .drain_freed()
            .into_iter()
            .map(|page_id| (freed_tag, page_id))
            .collect();
        new_entries.extend(
            unnamed_pages(named, state.next_page_id)
                .into_iter()
                .map(|page_id| (CHAIN_METADATA_CID, page_id)),
        );
        let folded = self
            .fold_free_entries(
                state.free_list_root_page_id,
                state.free_list_entries,
                new_entries,
                catalog.next_page_id().max(state.next_page_id),
            )
            .await?;

        self.size_scratch(scratch_path, folded.next_page_id).await?;
        self.pager.flush_main_to_image(self.realm_id, image).await?;

        // Built after the flush, so its anchor covers every page the flush sealed.
        let header_seq = self.pager.header_cursor()?.next_seq()?;
        let mut fields = self.rekey_header_fields(
            state,
            intent.target_mk_epoch,
            header_seq,
            catalog.root_page_id(),
            folded.next_page_id,
        )?;
        fields.free_list_root = encode_free_list_root(folded.root_page_id);
        // Naming slot B as the previous one writes slot A. Slot B stays zeros, so
        // slot A is the only header the file can open with until the next write.
        commit_header(
            &*self.vfs,
            scratch_path,
            target_header_key,
            &fields,
            ActiveSlot::B,
            self.page_size,
        )
        .await?;

        Ok(ScratchImage {
            catalog_root_page_id: catalog.root_page_id(),
            next_page_id: folded.next_page_id,
            free_list_root_page_id: folded.root_page_id,
            free_list_entries: folded.entries,
            header_seq,
            counter_anchor: fields.counter_anchor,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unnamed_pages_are_the_allocatable_ids_no_walk_recorded() {
        let named = BTreeMap::from([(4, PageKind::BTreeLeaf), (6, PageKind::Free)]);
        assert_eq!(unnamed_pages(&named, 8), vec![5, 7]);
        assert_eq!(unnamed_pages(&named, 4), Vec::<u64>::new());
    }
}
