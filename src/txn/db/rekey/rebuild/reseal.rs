//! Copy every named page into the scratch file under the target key.
//!
//! The walks read through the pager, so each read picks its key from the page's
//! own envelope. A `main.db` from an earlier release, with both keys in it, reads
//! here with no extra work. The cached plaintext stays valid, because the scratch
//! holds the same logical page at the same id.

use std::collections::BTreeMap;

use crate::Result;
use crate::btree::BTree;
use crate::errors::PagedbError;
use crate::pager::PageKind;
use crate::pager::core::RebuildImage;
use crate::pager::page_space::{is_reserved, page_offset};
use crate::txn::db::catalog::history_policy::proves_unreadable_pages;
use crate::txn::db::core::decode_commit_meta;
use crate::txn::db::{Db, WriterState};
use crate::vfs::{OpenMode, Vfs, VfsFile, read_exact_at};

use super::super::main::HISTORY_ROOT_BATCH;

/// Read the cleartext kind byte of a `main.db` page, or `None` when the page
/// has been cleared.
///
/// Only selects which AAD binding to authenticate under. The pager still
/// checks the full envelope against that same kind. A tampered byte cannot
/// launder a page into another role. It fails the tag instead.
async fn read_main_page_kind<F: VfsFile + ?Sized>(
    file: &mut F,
    offset: u64,
) -> Result<Option<PageKind>> {
    let mut envelope = [0u8; 2];
    read_exact_at(file, offset, &mut envelope).await?;
    if envelope == [0, 0] {
        return Ok(None);
    }
    let kind = PageKind::from_byte(envelope[1])?;
    if !kind.is_main_db() {
        return Err(PagedbError::IllegalPageKind);
    }
    Ok(Some(kind))
}

impl<V: Vfs + Clone> Db<V> {
    /// Copy every page a root, a retained row, or the free list names into
    /// `scratch`, then flush. Returns those page ids. A page outside the result
    /// has no copy in `scratch`.
    ///
    /// One traversal map spans every root. Retained snapshots share most of their
    /// pages, so the walk stays proportional to unique pages. The map holds one
    /// entry per named page.
    pub(super) async fn reseal_named_pages_to(
        &self,
        state: &WriterState,
        scratch: &RebuildImage,
    ) -> Result<BTreeMap<u64, PageKind>> {
        let mut named = BTreeMap::new();
        for root_page_id in [state.root_page_id, state.catalog_root_page_id] {
            BTree::open(
                self.pager.clone(),
                self.realm_id,
                root_page_id,
                state.next_page_id,
                self.page_size,
            )
            .rekey_walk_unique(&mut named, scratch)
            .await?;
        }
        if state.commit_history_root_page_id != 0 {
            self.reseal_retained_history_roots(state, &mut named, scratch)
                .await?;
        }
        self.reseal_free_list(state, &mut named, scratch).await?;
        self.pager
            .flush_main_to_image(self.realm_id, scratch)
            .await?;
        Ok(named)
    }

    /// Copy the free list, blanking every named page that nothing can still read.
    ///
    /// A free-list entry does not prove a page is dead. An entry at or above the
    /// reclamation floor names a page a live reader or retained root can reach.
    /// Those pages keep their content. An entry below the floor holds no data.
    /// It gets a fresh blank page without a read. A torn page therefore costs
    /// nothing. Old plaintext never reaches disk under the target key.
    ///
    /// `named` holds every page the root walks re-sealed. A store written by an
    /// earlier release tags rekey-freed catalog pages with the latest commit. A
    /// retained row can name those pages while the floor passes them. Membership
    /// here therefore overrides the floor. Chain pages join `named` first. A blank
    /// chain page ends the walk early, and an early end loses the rest of the
    /// chain.
    ///
    /// The floor is read once. A reader admitted later pins the published
    /// snapshot, whose pages are not free-listed. A later historical reader pins
    /// a retained row, whose pages are in `named`.
    ///
    /// A page outside `named` is out of every retained row's reach, whatever its
    /// tag says. Only a registered reader can still read it. A page that fails to
    /// authenticate therefore gets a blank page unless a reader's pin covers its
    /// tag. A hole stays a hole.
    ///
    /// Resident cost is one id per named page and one page of entries.
    async fn reseal_free_list(
        &self,
        state: &WriterState,
        named: &mut BTreeMap<u64, PageKind>,
        scratch: &RebuildImage,
    ) -> Result<()> {
        let root_page_id = state.free_list_root_page_id;
        if root_page_id == 0 {
            return Ok(());
        }

        let mut chain = crate::pager::freelist::ChainWalk::new(root_page_id);
        while let Some(chain_page_id) = chain.advance(&self.pager, self.realm_id).await? {
            self.pager
                .reseal_page_to(chain_page_id, self.realm_id, PageKind::Free, scratch)
                .await?;
            named.insert(chain_page_id, PageKind::Free);
        }

        let floor = self.reclamation_floor(state).await?;
        let reader_pin = self.oldest_reader_pin();
        let mut file = self.vfs.open(&self.main_db_path, OpenMode::Read).await?;
        let mut walk = crate::pager::freelist::ChainWalk::new(root_page_id);
        while let Some(chain_page_id) = walk.advance(&self.pager, self.realm_id).await? {
            for &(freed_at, page_id) in walk.entries() {
                if is_reserved(page_id) {
                    return Err(PagedbError::reserved_page_referenced(
                        chain_page_id,
                        page_id,
                    ));
                }
                if named.contains_key(&page_id) {
                    continue;
                }
                named.insert(page_id, PageKind::Free);
                if freed_at < floor {
                    self.pager
                        .write_blank_free_page_to(page_id, self.realm_id, scratch)
                        .await?;
                } else {
                    self.reseal_free_page_keeping_content(
                        &mut file,
                        page_id,
                        freed_at < reader_pin,
                        scratch,
                    )
                    .await?;
                }
            }
        }
        Ok(())
    }

    /// The oldest registered reader's commit, or `u64::MAX` with no reader.
    fn oldest_reader_pin(&self) -> u64 {
        self.tracked_readers
            .lock()
            .iter()
            .map(|reader| reader.commit_id.0)
            .min()
            .unwrap_or(u64::MAX)
    }

    /// Copy a named free page with its content when it authenticates. A hole
    /// stays a hole. A page that fails to authenticate is replaced with a blank
    /// page only when `unreachable` says no reader can name it.
    /// Otherwise the error returns. That error is real corruption, and the page
    /// bytes in the live file are the evidence.
    async fn reseal_free_page_keeping_content(
        &self,
        file: &mut V::File,
        page_id: u64,
        unreachable: bool,
        scratch: &RebuildImage,
    ) -> Result<()> {
        let offset = page_offset(page_id, self.page_size, "free-list page offset")?;
        let kind = match read_main_page_kind(file, offset).await {
            Ok(Some(kind)) => kind,
            Ok(None) => return Ok(()),
            Err(error) if unreachable => {
                return self
                    .blank_unreadable_free_page(page_id, error, scratch)
                    .await;
            }
            Err(error) => return Err(error),
        };
        let verified = self
            .pager
            .read_main_page(page_id, self.realm_id, kind)
            .await
            .map(drop);
        if let Err(error) = verified {
            if unreachable {
                return self
                    .blank_unreadable_free_page(page_id, error, scratch)
                    .await;
            }
            return Err(error);
        }
        self.pager
            .reseal_page_to(page_id, self.realm_id, kind, scratch)
            .await
    }

    /// Write a blank copy of a free page whose read reported `error`.
    /// Return `error` instead when it says nothing about the page's bytes.
    async fn blank_unreadable_free_page(
        &self,
        page_id: u64,
        error: PagedbError,
        scratch: &RebuildImage,
    ) -> Result<()> {
        if !proves_unreadable_pages(&error) {
            return Err(error);
        }
        tracing::warn!(
            page_id,
            %error,
            "free page cannot authenticate during rekey; replacing it with a blank page"
        );
        self.pager
            .write_blank_free_page_to(page_id, self.realm_id, scratch)
            .await
    }

    /// Copy the commit-history index and every reader-visible root its retained
    /// rows still name.
    ///
    /// `begin_read_at` resolves a commit through this index and then opens the
    /// data and catalog roots recorded in the row. Copy-on-write means those
    /// roots are usually unreachable from the current header. A rebuild that
    /// walked only the current header leaves every retained snapshot naming
    /// pages the new file does not hold. Copying them is part of the success
    /// contract. Failing here is correct. Completing after a partial walk
    /// recreates exactly that defect.
    ///
    /// The row's own `next_page_id` bounds each historical tree. Using the
    /// current allocator bound instead silently widens an old tree's
    /// addressable page space beyond what its metadata claims.
    async fn reseal_retained_history_roots(
        &self,
        state: &WriterState,
        named: &mut BTreeMap<u64, PageKind>,
        scratch: &RebuildImage,
    ) -> Result<()> {
        let history_tree = BTree::open(
            self.pager.clone(),
            self.realm_id,
            state.commit_history_root_page_id,
            state.next_page_id,
            self.page_size,
        );
        history_tree.rekey_walk_unique(named, scratch).await?;

        // Retention can be unbounded, so the rows stream in fixed-size
        // batches. The resident cost is one batch, not one entry per retained
        // commit.
        let mut cursor: Vec<u8> = Vec::new();
        loop {
            let batch = history_tree
                .collect_batch_from(&cursor, HISTORY_ROOT_BATCH)
                .await?;
            let Some((last_key, _)) = batch.last() else {
                return Ok(());
            };
            cursor.clear();
            cursor.extend_from_slice(last_key);
            cursor.push(0);
            let exhausted = batch.len() < HISTORY_ROOT_BATCH;

            for (_, value) in &batch {
                let historical = decode_commit_meta(value)?;
                // Only the data and catalog roots are reader-visible. The row's
                // free-list root is writer-only metadata. A later commit can
                // already have recycled its superseded chain pages. Following it
                // reinterprets a live page as `PageKind::Free`. Only the
                // current header's live chain is safe to walk.
                for root_page_id in [
                    historical.active_root_page_id,
                    historical.catalog_root_page_id,
                ] {
                    if root_page_id == 0 {
                        continue;
                    }
                    BTree::open(
                        self.pager.clone(),
                        self.realm_id,
                        root_page_id,
                        historical.next_page_id,
                        self.page_size,
                    )
                    .rekey_walk_unique(named, scratch)
                    .await?;
                }
            }

            if exhausted {
                return Ok(());
            }
        }
    }
}
