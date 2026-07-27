//! Main-database rekey transition and durable intent publication.

use std::collections::BTreeMap;
use std::sync::atomic::Ordering;

use subtle::ConstantTimeEq;

use crate::Result;
use crate::btree::BTree;
use crate::catalog::codec::{Catalog, RekeyIntent, RekeyStage};
use crate::crypto::kdf::{derive_hk, derive_mk};
use crate::crypto::{CipherId, DerivedKey, MasterKey, SecretKey};
use crate::errors::PagedbError;
use crate::pager::PageKind;
use crate::pager::anchor::HeaderCursor;
use crate::pager::header::commit_header;
use crate::pager::structural_header::MainDbHeaderFields;
use crate::vfs::{OpenMode, Vfs, VfsFile, read_exact_at};

#[cfg(test)]
use super::super::core::RekeyTestFault;
use super::super::core::{
    Db, WriterState, decode_commit_meta, encode_free_list_root, encode_root_ref,
};
use super::intent::{intent_proof, validate_intent_for_current_cipher};

/// Commit-history rows read per batch while rekeying the roots they name.
/// Rows are 40 bytes, so this is a few KiB resident regardless of how deep
/// retention runs.
const HISTORY_ROOT_BATCH: usize = 512;

/// One catalog rewrite a rekey stage is about to make durable.
///
/// The new root and allocation cursor, the pages the rewrite superseded, and
/// the segment side effects it publishes all describe the same transition, so
/// they travel together rather than as loose positional arguments.
pub(super) struct RekeyCatalogCommit<'a> {
    pub catalog_root_page_id: u64,
    pub next_page_id: u64,
    pub freed_pages: &'a [u64],
    pub effects: &'a [crate::txn::write::SegmentSideEffect],
}

/// Read the cleartext kind byte of a `main.db` page, or `None` when the page
/// has been cleared.
///
/// Only selects which AAD binding to authenticate under; the pager still
/// verifies the full envelope against that same kind, so a tampered byte
/// cannot launder a page into another role — it fails the tag instead.
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
    /// Rekey the reachable main database and every catalog-linked immutable
    /// segment under `new_mk_epoch`.
    pub async fn rekey_db(&self, kek: impl Into<SecretKey>, new_mk_epoch: u64) -> Result<()> {
        let kek = kek.into();
        self.ensure_usable()?;
        if !matches!(self.mode, crate::txn::mode::DbMode::Standalone) {
            return Err(PagedbError::Unsupported);
        }
        if new_mk_epoch == 0 || new_mk_epoch <= self.mk_epoch.load(Ordering::SeqCst) {
            return Err(PagedbError::rekey_state_invalid("rekey.target_mk_epoch"));
        }

        let source_epoch = self.mk_epoch.load(Ordering::SeqCst);
        let source_header_key = self.hk.read().clone();
        let supplied_source_header_key =
            derive_hk(&derive_mk(kek.as_bytes(), &self.kek_salt, source_epoch)?)?;
        let cipher_id = self.cipher_id.as_byte();
        let source_proof = intent_proof(
            &source_header_key,
            &self.file_id,
            &self.kek_salt,
            source_epoch,
            new_mk_epoch,
            source_epoch,
            cipher_id,
        )?;
        let supplied_source_proof = intent_proof(
            &supplied_source_header_key,
            &self.file_id,
            &self.kek_salt,
            source_epoch,
            new_mk_epoch,
            source_epoch,
            cipher_id,
        )?;
        let same_kek = bool::from(source_proof.ct_eq(&supplied_source_proof));
        let target_master_key = derive_mk(kek.as_bytes(), &self.kek_salt, new_mk_epoch)?;
        let target_header_key = derive_hk(&target_master_key)?;
        let intent = RekeyIntent {
            source_mk_epoch: source_epoch,
            target_mk_epoch: new_mk_epoch,
            source_cipher_id: cipher_id,
            target_cipher_id: cipher_id,
            same_kek,
            stage: RekeyStage::Intent,
            source_hk_proof: source_proof,
            target_hk_proof: intent_proof(
                &target_header_key,
                &self.file_id,
                &self.kek_salt,
                source_epoch,
                new_mk_epoch,
                new_mk_epoch,
                cipher_id,
            )?,
        };
        let mut state = self.writer.lock().await;
        self.write_rekey_intent_locked(&mut state, &intent, source_epoch, &source_header_key)
            .await?;
        #[cfg(test)]
        self.interrupt_rekey_if_requested(RekeyTestFault::Intent)?;
        self.pager
            .install_mk_epoch(target_master_key, new_mk_epoch, self.cipher_id);
        self.resume_rekey_locked(&mut state, intent).await
    }

    pub(in crate::txn::db) async fn resume_rekey_intent(&self) -> Result<()> {
        let mut state = self.writer.lock().await;
        let intent = self
            .load_rekey_intent(&state)
            .await?
            .ok_or_else(|| PagedbError::rekey_state_invalid("rekey.intent_missing"))?;
        self.resume_rekey_locked(&mut state, intent).await
    }

    async fn resume_rekey_locked(
        &self,
        state: &mut WriterState,
        mut intent: RekeyIntent,
    ) -> Result<()> {
        validate_intent_for_current_cipher(&intent, self.cipher_id.as_byte())?;
        let source_cipher = CipherId::from_byte(intent.source_cipher_id)?;
        let target_cipher = CipherId::from_byte(intent.target_cipher_id)?;
        let source_master_key = self.pager.mk_for(intent.source_mk_epoch, source_cipher)?;
        let target_master_key = self.pager.mk_for(intent.target_mk_epoch, target_cipher)?;
        let source_header_key = derive_hk(&source_master_key)?;
        let target_header_key = derive_hk(&target_master_key)?;
        let source_proof = intent_proof(
            &source_header_key,
            &self.file_id,
            &self.kek_salt,
            intent.source_mk_epoch,
            intent.target_mk_epoch,
            intent.source_mk_epoch,
            intent.source_cipher_id,
        )?;
        let target_proof = intent_proof(
            &target_header_key,
            &self.file_id,
            &self.kek_salt,
            intent.source_mk_epoch,
            intent.target_mk_epoch,
            intent.target_mk_epoch,
            intent.target_cipher_id,
        )?;
        if !bool::from(source_proof.ct_eq(&intent.source_hk_proof))
            || !bool::from(target_proof.ct_eq(&intent.target_hk_proof))
        {
            return Err(PagedbError::rekey_counterpart_key_invalid(
                intent.source_mk_epoch,
                intent.target_mk_epoch,
            ));
        }

        // After this point the Pager may write with the target epoch while
        // the durable A/B header still names the source epoch. That state has
        // no safe in-process rollback: dirty and cached pages may already
        // depend on target-key routing. Preserve existing reader snapshots,
        // poison the handle, and require recovery through a fresh open.
        let mut target_epoch_active = matches!(
            intent.stage,
            RekeyStage::HeaderTargetPublished | RekeyStage::MainDone | RekeyStage::SegmentsPending
        );
        let result = async {
            if matches!(intent.stage, RekeyStage::Intent) {
                target_epoch_active = true;
                self.rewrite_rekey_main_pages(state, &mut intent, &target_master_key)
                    .await?;
            }
            if matches!(intent.stage, RekeyStage::MainPagesTargetReadable) {
                target_epoch_active = true;
                self.publish_rekey_target_header(
                    state,
                    &mut intent,
                    &target_master_key,
                    &target_header_key,
                )
                .await?;
            }
            self.finish_rekey_locked(state, &mut intent, &target_header_key)
                .await
        }
        .await;

        match result {
            Ok(()) => Ok(()),
            Err(error) if target_epoch_active => {
                let commit = crate::CommitId(state.latest_commit_id);
                self.poison(commit);
                tracing::error!(
                    commit = commit.0,
                    error = %error,
                    "rekey target epoch activation failed before recovery completed; reopening required"
                );
                Err(PagedbError::rekey_target_epoch_activated(commit, error))
            }
            Err(error) => Err(error),
        }
    }

    async fn rewrite_rekey_main_pages(
        &self,
        state: &WriterState,
        intent: &mut RekeyIntent,
        target_master_key: &MasterKey,
    ) -> Result<()> {
        // Rewriting is idempotent only when the active writer epoch is the
        // target: recovery may revisit pages already rewritten before the
        // target header was published.
        self.pager
            .set_active_mk_epoch(target_master_key.clone(), intent.target_mk_epoch);
        // One traversal set spans every root below. Retained snapshots share
        // most of their pages by construction, so this is what keeps the walk
        // proportional to unique reachable pages instead of to the number of
        // retained commits. It is bounded by the page count of the live
        // database, strictly below the dirty-page set the same walk is already
        // accumulating in the buffer pool for the single `flush_main` at the
        // end — a page id and kind against a whole decrypted page.
        let mut rewritten = BTreeMap::new();
        let main_tree = BTree::open(
            self.pager.clone(),
            self.realm_id,
            state.root_page_id,
            state.next_page_id,
            self.page_size,
        );
        main_tree.rekey_walk_unique(&mut rewritten).await?;
        if state.commit_history_root_page_id != 0 {
            self.rewrite_retained_history_roots(state, &mut rewritten)
                .await?;
        }
        self.rewrite_free_list_pages(state.free_list_root_page_id)
            .await?;
        // Keep the catalog path carrying the intent source-readable until
        // target-header publication. This is the durable admission anchor
        // for an ordinary open that can verify only the stale A/B side.
        self.pager
            .set_active_mk_epoch(target_master_key.clone(), intent.target_mk_epoch);
        self.pager.flush_main(self.realm_id).await?;
        intent.stage = RekeyStage::MainPagesTargetReadable;
        #[cfg(test)]
        self.interrupt_rekey_if_requested(RekeyTestFault::MainPagesTargetReadable)?;
        Ok(())
    }

    /// Re-encrypt both the durable free-list chain and every reusable page it
    /// names. Rewriting only the chain would leave those pages sealed under
    /// the retired epoch, so a later allocation could not authenticate them.
    ///
    /// The walk is streamed one chain page at a time. Touching every named page
    /// is inherently proportional to the free list's size in IO, but holding
    /// their ids was proportional to it in memory too, on a path that already
    /// flushes to stay inside the buffer-pool budget. Streaming keeps a single
    /// page of ids resident instead.
    ///
    /// Re-sealing a page twice is harmless — the second read opens it under the
    /// epoch the first one wrote and marks it dirty again — so no cross-page
    /// deduplication set is needed to tolerate a chain that names one page more
    /// than once.
    async fn rewrite_free_list_pages(&self, root_page_id: u64) -> Result<()> {
        if root_page_id == 0 {
            return Ok(());
        }

        let mut file = self.vfs.open(&self.main_db_path, OpenMode::Read).await?;
        let mut walk = crate::pager::freelist::ChainWalk::new(root_page_id);
        while let Some(chain_page_id) = walk.advance(&self.pager, self.realm_id).await? {
            let named: Vec<u64> = walk.entries().iter().map(|&(_, page_id)| page_id).collect();
            self.pager
                .rewrite_page_under_current_epoch(
                    chain_page_id,
                    self.realm_id,
                    crate::pager::PageKind::Free,
                )
                .await?;
            for page_id in named {
                let offset = page_id
                    .checked_mul(self.page_size as u64)
                    .ok_or_else(|| PagedbError::arithmetic_overflow("free-list page offset"))?;
                let Some(kind) = read_main_page_kind(&mut file, offset).await? else {
                    continue;
                };
                self.pager
                    .rewrite_page_under_current_epoch(page_id, self.realm_id, kind)
                    .await?;
            }
        }
        Ok(())
    }

    /// Re-seal the live catalog tree under the target epoch.
    ///
    /// Every other reader-visible root is re-sealed before the target header is
    /// published. The catalog is the one that cannot be: until the target
    /// header is durable it must stay source-readable, because it carries the
    /// rekey intent that an open able to verify only the stale A/B side uses to
    /// admit recovery. So it is re-sealed here instead, once that anchor is in
    /// place and while both keys are still installed.
    ///
    /// The walk is the same bounded, deduplicating traversal the data tree
    /// uses — proportional to unique reachable catalog pages, not to the size
    /// of the file.
    async fn rewrite_rekey_catalog_pages(&self, state: &WriterState) -> Result<()> {
        if state.catalog_root_page_id == 0 {
            return Ok(());
        }
        let catalog = BTree::open(
            self.pager.clone(),
            self.realm_id,
            state.catalog_root_page_id,
            state.next_page_id,
            self.page_size,
        );
        catalog.rekey_walk_unique(&mut BTreeMap::new()).await?;
        Ok(())
    }

    /// Rewrite the commit-history index and every reader-visible root its
    /// retained rows still name.
    ///
    /// `begin_read_at` resolves a commit through this index and then opens the
    /// data and catalog roots recorded in the row. Copy-on-write means those
    /// roots are usually unreachable from the current header, so a rekey that
    /// walked only the current header would return `Ok(())`, retire the source
    /// epoch, and leave every retained snapshot naming pages that no live key
    /// can open. Rewriting them is part of the success contract, not extra
    /// safety: failing here is correct, because completing after a partial walk
    /// recreates exactly that defect.
    ///
    /// The row's own `next_page_id` bounds each historical tree. Using the
    /// current allocator bound instead would silently widen an old tree's
    /// addressable page space beyond what its metadata claims.
    async fn rewrite_retained_history_roots(
        &self,
        state: &WriterState,
        rewritten: &mut BTreeMap<u64, crate::pager::PageKind>,
    ) -> Result<()> {
        let history_tree = BTree::open(
            self.pager.clone(),
            self.realm_id,
            state.commit_history_root_page_id,
            state.next_page_id,
            self.page_size,
        );
        history_tree.rekey_walk_unique(rewritten).await?;

        // Retention can be unbounded, so the rows are streamed in fixed-size
        // batches rather than collected: the resident cost is one batch, not
        // one entry per retained commit. Rewriting the index first means each
        // batch is read back through the pages this walk has already re-sealed.
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
                // free-list root is writer-only metadata whose superseded chain
                // pages a later commit may already have recycled; following it
                // would reinterpret a live page as `PageKind::Free`, so only the
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
                    .rekey_walk_unique(rewritten)
                    .await?;
                }
            }

            if exhausted {
                return Ok(());
            }
        }
    }

    async fn publish_rekey_target_header(
        &self,
        state: &mut WriterState,
        intent: &mut RekeyIntent,
        target_master_key: &MasterKey,
        target_header_key: &DerivedKey,
    ) -> Result<()> {
        self.pager
            .set_active_mk_epoch(target_master_key.clone(), intent.target_mk_epoch);
        intent.stage = RekeyStage::HeaderTargetPublished;
        self.write_rekey_intent_locked(state, intent, intent.target_mk_epoch, target_header_key)
            .await?;
        self.mk_epoch
            .store(intent.target_mk_epoch, Ordering::SeqCst);
        *self.hk.write() = target_header_key.clone();
        #[cfg(test)]
        self.interrupt_rekey_if_requested(RekeyTestFault::HeaderTargetPublished)?;
        Ok(())
    }

    async fn finish_rekey_locked(
        &self,
        state: &mut WriterState,
        intent: &mut RekeyIntent,
        target_header_key: &DerivedKey,
    ) -> Result<()> {
        if matches!(intent.stage, RekeyStage::HeaderTargetPublished) {
            self.rewrite_rekey_catalog_pages(state).await?;
            // The pages the intent write above superseded are already on the
            // durable free list, so this pass also re-seals them; from here on
            // every catalog page is target-sealed and later transitions can
            // only supersede target-epoch pages.
            self.rewrite_free_list_pages(state.free_list_root_page_id)
                .await?;
            self.pager.flush_main(self.realm_id).await?;
            intent.stage = RekeyStage::MainDone;
            self.write_rekey_intent_locked(
                state,
                intent,
                intent.target_mk_epoch,
                target_header_key,
            )
            .await?;
        }
        if !matches!(intent.stage, RekeyStage::SegmentsPending) {
            intent.stage = RekeyStage::SegmentsPending;
            self.write_rekey_intent_locked(
                state,
                intent,
                intent.target_mk_epoch,
                target_header_key,
            )
            .await?;
        }
        self.migrate_rekey_segments(state, intent, target_header_key)
            .await?;
        if self.rekey_segments_pending(state, intent).await? {
            return Err(PagedbError::rekey_state_invalid("rekey.segments_pending"));
        }
        self.clear_rekey_intent_locked(state, intent.target_mk_epoch, target_header_key)
            .await?;
        self.retire_rekey_source_when_safe(
            intent.source_mk_epoch,
            CipherId::from_byte(intent.source_cipher_id)?,
        )
    }

    pub(super) async fn load_rekey_intent(
        &self,
        state: &WriterState,
    ) -> Result<Option<RekeyIntent>> {
        if state.catalog_root_page_id == 0 {
            return Ok(None);
        }
        let tree = BTree::open(
            self.pager.clone(),
            self.realm_id,
            state.catalog_root_page_id,
            state.next_page_id,
            self.page_size,
        );
        let Some(bytes) = tree.get(&Catalog::rekey_state_key()).await? else {
            return Ok(None);
        };
        let intent = Catalog::decode_rekey_state(&bytes)?;
        validate_intent_for_current_cipher(&intent, self.cipher_id.as_byte())?;
        Ok(Some(intent))
    }

    pub(super) async fn write_rekey_intent_locked(
        &self,
        state: &mut WriterState,
        intent: &RekeyIntent,
        header_epoch: u64,
        header_hk: &DerivedKey,
    ) -> Result<()> {
        let mut tree = BTree::open(
            self.pager.clone(),
            self.realm_id,
            state.catalog_root_page_id,
            state.next_page_id,
            self.page_size,
        );
        tree.put(
            &Catalog::rekey_state_key(),
            &Catalog::encode_rekey_intent(intent),
        )
        .await?;
        tree.flush().await?;
        let freed_pages = tree.drain_freed();
        self.commit_rekey_catalog_root(
            state,
            RekeyCatalogCommit {
                catalog_root_page_id: tree.root_page_id(),
                next_page_id: tree.next_page_id(),
                freed_pages: &freed_pages,
                effects: &[],
            },
            header_epoch,
            header_hk,
        )
        .await
        .map(|_| ())
    }

    async fn clear_rekey_intent_locked(
        &self,
        state: &mut WriterState,
        header_epoch: u64,
        header_hk: &DerivedKey,
    ) -> Result<()> {
        if state.catalog_root_page_id == 0 {
            return Ok(());
        }
        let mut tree = BTree::open(
            self.pager.clone(),
            self.realm_id,
            state.catalog_root_page_id,
            state.next_page_id,
            self.page_size,
        );
        let _ = tree.delete(&Catalog::rekey_state_key()).await?;
        tree.flush().await?;
        let freed_pages = tree.drain_freed();
        self.commit_rekey_catalog_root(
            state,
            RekeyCatalogCommit {
                catalog_root_page_id: tree.root_page_id(),
                next_page_id: tree.next_page_id(),
                freed_pages: &freed_pages,
                effects: &[],
            },
            header_epoch,
            header_hk,
        )
        .await
        .map(|_| ())
    }

    /// Fold pages a rekey-time catalog rewrite superseded into the durable free
    /// list, returning the allocation cursor the header must record.
    ///
    /// Every ordinary commit routes its copy-on-write leftovers here. Without
    /// it a rekey abandons pages at each intent transition: unreachable from
    /// any root, absent from the free list, and — once the source epoch is
    /// retired — sealed under a key that no longer exists. Entries carry the
    /// current commit id, so the reclamation floor still withholds any page a
    /// live reader or retained history root can still name.
    async fn record_rekey_freed_pages(
        &self,
        state: &mut WriterState,
        freed_pages: &[u64],
        next_page_id: u64,
    ) -> Result<u64> {
        if freed_pages.is_empty() {
            return Ok(next_page_id);
        }
        // A bounded window, spliced onto the retained tail, for the same reason
        // the commit path uses one: the fold only prepends entries, so nothing
        // here needs a view of the complete set. Hosts are empty, so no page
        // reaches an allocator from this path at all and the window carries no
        // duplicate-safety obligation beyond deleting what it rewrites.
        let window = crate::pager::freelist::read_chain_prefix(
            &self.pager,
            self.realm_id,
            state.free_list_root_page_id,
            crate::pager::freelist::WINDOW_PAGES,
        )
        .await?;
        let mut entries = window.entries;
        entries.extend(
            freed_pages
                .iter()
                .map(|&page_id| (state.latest_commit_id, page_id)),
        );
        // Chain pages are writer-only metadata that no reader snapshot ever
        // traverses, so they carry a commit id below every real floor and are
        // immediately recyclable — the same rule the ordinary commit path uses.
        entries.extend(
            window
                .chain_pages
                .into_iter()
                .map(|page_id| (crate::pager::freelist::CHAIN_METADATA_CID, page_id)),
        );
        let (new_free_list_root, new_next_page_id) = crate::pager::freelist::rewrite_chain(
            &self.pager,
            self.realm_id,
            self.page_size,
            entries,
            Vec::new(),
            next_page_id,
            window.tail,
        )
        .await?;
        state.free_list_root_page_id = new_free_list_root;
        self.pager.flush_main(self.realm_id).await?;
        Ok(new_next_page_id)
    }

    pub(super) async fn commit_rekey_catalog_root(
        &self,
        state: &mut WriterState,
        catalog: RekeyCatalogCommit<'_>,
        header_epoch: u64,
        hk: &DerivedKey,
    ) -> Result<super::super::segment::SegmentReconciliation> {
        let RekeyCatalogCommit {
            catalog_root_page_id,
            next_page_id,
            freed_pages,
            effects,
        } = catalog;
        let next_page_id = self
            .record_rekey_freed_pages(state, freed_pages, next_page_id)
            .await?;
        let next_page_id = next_page_id.max(state.next_page_id);
        // Re-sealing pages under the target epoch refreshes the anchor whenever
        // the window runs out, so the live cursor — not this writer's memory of
        // it — names the slot this header supersedes.
        let header_cursor = self.pager.header_cursor()?;
        let new_seq = header_cursor.next_seq()?;
        let counter_anchor = self.pager.pending_anchor();
        let fields = self.rekey_header_fields(
            state,
            header_epoch,
            new_seq,
            catalog_root_page_id,
            next_page_id,
        )?;
        let slot = commit_header(
            &*self.vfs,
            &self.main_db_path,
            hk,
            &fields,
            header_cursor.slot,
            self.page_size,
        )
        .await?;
        self.pager
            .note_header_written(HeaderCursor { slot, seq: new_seq });
        state.catalog_root_page_id = catalog_root_page_id;
        state.next_page_id = next_page_id;
        self.finish_durable_commit(
            state,
            crate::CommitId(state.latest_commit_id),
            counter_anchor,
            effects,
        )
        .await
    }

    fn rekey_header_fields(
        &self,
        state: &WriterState,
        mk_epoch: u64,
        seq: u64,
        catalog_root_page_id: u64,
        next_page_id: u64,
    ) -> Result<MainDbHeaderFields> {
        let journal = state.pending_apply_journal_id;
        let journal_page_id = u64::from_le_bytes(
            journal[..8]
                .try_into()
                .map_err(|_| PagedbError::arithmetic_overflow("apply journal page id"))?,
        );
        let journal_version = u64::from_le_bytes(
            journal[8..]
                .try_into()
                .map_err(|_| PagedbError::arithmetic_overflow("apply journal version"))?,
        );
        Ok(MainDbHeaderFields {
            format_version: self.format_version,
            cipher_id: self.cipher_id.as_byte(),
            page_size_log2: super::super::util::page_size_log2(self.page_size)?,
            flags: self.header_flags,
            file_id: self.file_id,
            kek_salt: self.kek_salt,
            mk_epoch,
            seq,
            active_root_page_id: state.root_page_id,
            active_root_txn_id: state.latest_commit_id,
            counter_anchor: self.pager.pending_anchor(),
            commit_id: crate::CommitId(state.latest_commit_id),
            free_list_root: encode_free_list_root(state.free_list_root_page_id),
            catalog_root: encode_root_ref(catalog_root_page_id, state.catalog_root_txn_id),
            apply_journal_root_page_id: journal_page_id,
            apply_journal_root_version: journal_version,
            commit_history_root_page_id: state.commit_history_root_page_id,
            commit_history_root_version: state.commit_history_root_version,
            restore_mode: state.restore_mode,
            next_page_id,
            commit_retain_policy_tag: state.commit_retain_policy_tag,
            commit_retain_policy_value: state.commit_retain_policy_value,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::btree::BTree;
    use crate::catalog::codec::{Catalog, RekeyIntent, RekeyStage};
    use crate::vfs::memory::MemVfs;
    use crate::vfs::types::OpenMode;
    use crate::vfs::{Vfs, VfsFile};
    use crate::{RealmId, SegmentKind, SegmentPageKind};

    const PAGE: usize = 4096;
    const REALM: RealmId = RealmId::new([0x41; 16]);
    const SOURCE_KEK: [u8; 32] = [0x51; 32];
    const TARGET_KEK: [u8; 32] = [0x52; 32];
    const WRONG_KEK: [u8; 32] = [0x53; 32];

    async fn interrupted_rekey(point: RekeyTestFault) -> MemVfs {
        let vfs = MemVfs::new();
        let db = Db::open_internal(vfs.clone(), SOURCE_KEK, PAGE, REALM)
            .await
            .unwrap();
        let mut writer = db
            .create_segment(REALM, SegmentKind::Unspecified)
            .await
            .unwrap();
        writer
            .append_page(SegmentPageKind::Data, b"rekey-boundary")
            .await
            .unwrap();
        let meta = writer.seal().await.unwrap();
        let mut txn = db.begin_write().await.unwrap();
        txn.link_segment("boundary", &meta).await.unwrap();
        txn.commit().await.unwrap();

        db.interrupt_rekey_after(point);
        assert!(db.rekey_db(TARGET_KEK, 1).await.is_err());
        drop(db);
        vfs
    }

    #[tokio::test(flavor = "current_thread")]
    async fn target_epoch_activation_failure_poisoned_handle_requires_reopen() {
        let vfs = MemVfs::new();
        let db = Db::open_internal(vfs.clone(), SOURCE_KEK, PAGE, REALM)
            .await
            .unwrap();
        let mut writer = db.begin_write().await.unwrap();
        writer.put(b"preserved", b"source-epoch").await.unwrap();
        writer.commit().await.unwrap();
        let existing_reader = db.begin_read().await.unwrap();

        db.interrupt_rekey_after(RekeyTestFault::MainPagesTargetReadable);
        let durable_commit = match db.rekey_db(TARGET_KEK, 1).await {
            Err(PagedbError::RekeyTargetEpochActivated { commit, source }) => {
                assert!(matches!(*source, PagedbError::Io(_)));
                commit
            }
            other => panic!("expected poisoned-handle error, got {other:?}"),
        };

        assert!(matches!(
            db.rekey_db(TARGET_KEK, 1).await,
            Err(PagedbError::DurablyCommittedButUnpublished { commit }) if commit == durable_commit
        ));
        assert!(matches!(
            db.begin_write().await,
            Err(PagedbError::DurablyCommittedButUnpublished { commit }) if commit == durable_commit
        ));
        assert_eq!(
            existing_reader.get(b"preserved").await.unwrap().as_deref(),
            Some(b"source-epoch".as_slice())
        );

        drop(existing_reader);
        drop(db);
        let reopened = Db::open_existing_with_counterpart_kek(
            vfs,
            SOURCE_KEK,
            TARGET_KEK,
            PAGE,
            REALM,
            crate::OpenOptions::default(),
        )
        .await
        .unwrap();
        let reader = reopened.begin_read().await.unwrap();
        assert_eq!(
            reader.get(b"preserved").await.unwrap().as_deref(),
            Some(b"source-epoch".as_slice())
        );
    }

    /// A rekey re-seals every reachable page and writes no header between the
    /// intent row and the target-header publication, so the whole re-seal draws
    /// nonces from one anchor window. On a store larger than that window it must
    /// still complete — and the anchor must end more than a whole budget above
    /// where it started, which only an advance *during* the re-seal can produce.
    #[tokio::test(flavor = "current_thread")]
    async fn rekey_is_not_bounded_by_the_anchor_budget() {
        const BUDGET: u64 = 64;
        let vfs = MemVfs::new();
        let db = Db::open_internal_with_options(
            vfs,
            SOURCE_KEK,
            PAGE,
            REALM,
            crate::OpenOptions::default().with_anchor_budget(BUDGET),
        )
        .await
        .unwrap();

        let spilled = vec![0x5Eu8; 3000]; // each value takes an overflow page
        for round in 0..8u32 {
            let mut txn = db.begin_write().await.unwrap();
            for index in 0..40u32 {
                txn.put(format!("r-{round:02}-{index:04}").as_bytes(), &spilled)
                    .await
                    .unwrap();
            }
            txn.commit().await.unwrap();
        }

        let before = db.pager.durable_anchor();
        db.rekey_db(TARGET_KEK, 1)
            .await
            .expect("a rekey must not be bounded by the anchor budget");
        let after = db.pager.durable_anchor();
        assert!(
            after > before.saturating_add(BUDGET),
            "the re-seal must advance the anchor past a whole window; it moved \
             from {before} to {after} with a budget of {BUDGET}"
        );

        let reader = db.begin_read().await.unwrap();
        assert_eq!(
            reader.get(b"r-07-0039").await.unwrap().as_deref(),
            Some(spilled.as_slice()),
            "a rekeyed store must read back under the target key"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn completed_rekey_retires_source_epoch_and_keeps_target_lease() {
        let db = Db::open_internal(MemVfs::new(), SOURCE_KEK, PAGE, REALM)
            .await
            .unwrap();

        db.rekey_db(TARGET_KEK, 1).await.unwrap();

        assert!(matches!(
            db.pager.mk_for(0, db.cipher_id),
            Err(PagedbError::MissingPersistedKey { mk_epoch: 0, .. })
        ));
        assert!(db.pager.mk_for(1, db.cipher_id).is_ok());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn old_read_transaction_delays_source_retirement_until_drop() {
        let db = Db::open_internal(MemVfs::new(), SOURCE_KEK, PAGE, REALM)
            .await
            .unwrap();
        let mut writer = db
            .create_segment(REALM, SegmentKind::Unspecified)
            .await
            .unwrap();
        writer
            .append_page(SegmentPageKind::Data, b"reader-pinned-source")
            .await
            .unwrap();
        let meta = writer.seal().await.unwrap();
        let mut txn = db.begin_write().await.unwrap();
        txn.link_segment("reader-pinned", &meta).await.unwrap();
        txn.commit().await.unwrap();

        let old_txn = db.begin_read().await.unwrap();
        db.rekey_db(TARGET_KEK, 1).await.unwrap();
        assert!(db.pager.mk_for(0, db.cipher_id).is_ok());

        let old_reader = old_txn.open_segment("reader-pinned").await.unwrap();
        assert!(
            old_reader
                .read_page(1)
                .await
                .unwrap()
                .starts_with(b"reader-pinned-source")
        );
        drop(old_txn);

        assert!(matches!(
            db.pager.mk_for(0, db.cipher_id),
            Err(PagedbError::MissingPersistedKey { mk_epoch: 0, .. })
        ));
        assert!(
            old_reader
                .read_page(1)
                .await
                .unwrap()
                .starts_with(b"reader-pinned-source")
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn direct_segment_reader_keeps_source_lease_after_retirement() {
        let db = Db::open_internal(MemVfs::new(), SOURCE_KEK, PAGE, REALM)
            .await
            .unwrap();
        let mut writer = db
            .create_segment(REALM, SegmentKind::Unspecified)
            .await
            .unwrap();
        writer
            .append_page(SegmentPageKind::Data, b"direct-reader-source")
            .await
            .unwrap();
        let meta = writer.seal().await.unwrap();
        let mut txn = db.begin_write().await.unwrap();
        txn.link_segment("direct-reader", &meta).await.unwrap();
        txn.commit().await.unwrap();

        let reader = db.open_segment(REALM, "direct-reader").await.unwrap();
        db.rekey_db(TARGET_KEK, 1).await.unwrap();
        assert!(matches!(
            db.pager.mk_for(0, db.cipher_id),
            Err(PagedbError::MissingPersistedKey { mk_epoch: 0, .. })
        ));
        assert!(
            reader
                .read_page(1)
                .await
                .unwrap()
                .starts_with(b"direct-reader-source")
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn interrupted_kek_change_requires_explicit_counterpart_and_resumes_in_both_orders() {
        let boundaries = [
            RekeyTestFault::Intent,
            RekeyTestFault::MainPagesTargetReadable,
            RekeyTestFault::HeaderTargetPublished,
            RekeyTestFault::SegmentSeal,
            RekeyTestFault::ProgressRowCommit,
            RekeyTestFault::CatalogSwapEffects,
            RekeyTestFault::ProgressDeletion,
        ];
        for point in boundaries {
            for (primary, counterpart) in [(SOURCE_KEK, TARGET_KEK), (TARGET_KEK, SOURCE_KEK)] {
                let vfs = interrupted_rekey(point).await;
                let db = Db::open_existing_with_counterpart_kek(
                    vfs,
                    primary,
                    counterpart,
                    PAGE,
                    REALM,
                    crate::OpenOptions::default(),
                )
                .await
                .unwrap();
                let reader = db.open_segment(REALM, "boundary").await.unwrap();
                assert!(
                    reader
                        .read_page(1)
                        .await
                        .unwrap()
                        .starts_with(b"rekey-boundary")
                );
            }
        }
    }

    /// Every interruption boundary of the rekey protocol must reopen to a state
    /// the protocol's own invariants accept, not merely to one that opens.
    ///
    /// The resume runs during open, so afterwards there is no intent row left to
    /// resume from, the source epoch is retired — the transition's own
    /// completion condition — and the segment reads back under the target key.
    /// The deep walk then holds the whole store to its structural contract,
    /// including the pages each durable stage superseded: a stage that abandons
    /// its copy-on-write leftovers leaves them unreachable from every root and
    /// absent from the free list, which is a leak the reopened writer owns.
    #[tokio::test(flavor = "current_thread")]
    async fn every_rekey_boundary_resumes_to_a_completed_store_without_leaks() {
        let boundaries = [
            RekeyTestFault::Intent,
            RekeyTestFault::MainPagesTargetReadable,
            RekeyTestFault::HeaderTargetPublished,
            RekeyTestFault::SegmentSeal,
            RekeyTestFault::ProgressRowCommit,
            RekeyTestFault::CatalogSwapEffects,
            RekeyTestFault::ProgressDeletion,
        ];
        for point in boundaries {
            let vfs = interrupted_rekey(point).await;
            let db = Db::open_existing_with_counterpart_kek(
                vfs,
                SOURCE_KEK,
                TARGET_KEK,
                PAGE,
                REALM,
                crate::OpenOptions::default(),
            )
            .await
            .unwrap();

            {
                let state = db.writer.lock().await;
                assert!(
                    db.load_rekey_intent(&state).await.unwrap().is_none(),
                    "{point:?}: the resumed rekey must clear its durable intent"
                );
            }
            assert!(
                matches!(
                    db.pager.mk_for(0, db.cipher_id),
                    Err(PagedbError::MissingPersistedKey { mk_epoch: 0, .. })
                ),
                "{point:?}: a completed rekey retires the source epoch"
            );

            let reader = db.open_segment(REALM, "boundary").await.unwrap();
            assert!(
                reader
                    .read_page(1)
                    .await
                    .unwrap()
                    .starts_with(b"rekey-boundary"),
                "{point:?}: the migrated segment must read back under the target key"
            );
            drop(reader);

            let report = crate::recovery::deep_walk::run_deep_walk(&db)
                .await
                .unwrap();
            assert!(report.is_clean(), "{point:?}: deep walk report: {report:?}");
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn missing_or_wrong_counterpart_does_not_mutate_a_kek_change_intent() {
        let vfs = interrupted_rekey(RekeyTestFault::Intent).await;
        let header_before = {
            let header = vfs.open("/main.db", OpenMode::Read).await.unwrap();
            let mut bytes = vec![0u8; PAGE * 2];
            header.read_at(0, &mut bytes).await.unwrap();
            bytes
        };
        assert!(matches!(
            Db::open_existing(vfs.clone(), SOURCE_KEK, PAGE, REALM).await,
            Err(PagedbError::RekeyResumeKeyRequired { .. })
        ));
        assert!(matches!(
            Db::open_existing_with_counterpart_kek(
                vfs.clone(),
                SOURCE_KEK,
                WRONG_KEK,
                PAGE,
                REALM,
                crate::OpenOptions::default(),
            )
            .await,
            Err(PagedbError::RekeyCounterpartKeyInvalid { .. })
        ));
        let header_after = {
            let header = vfs.open("/main.db", OpenMode::Read).await.unwrap();
            let mut bytes = vec![0u8; PAGE * 2];
            header.read_at(0, &mut bytes).await.unwrap();
            bytes
        };
        assert_eq!(header_after, header_before);
        let resumed = Db::open_existing_with_counterpart_kek(
            vfs,
            SOURCE_KEK,
            TARGET_KEK,
            PAGE,
            REALM,
            crate::OpenOptions::default(),
        )
        .await
        .unwrap();
        assert!(resumed.open_segment(REALM, "boundary").await.is_ok());
    }

    /// A rekey-state row of an unrecognised shape names a transition this
    /// build cannot reason about. Recovery must refuse the whole database
    /// rather than guess at a migration and rotate keys on the guess.
    #[tokio::test(flavor = "current_thread")]
    async fn unrecognised_rekey_state_row_fails_recovery() {
        let vfs = MemVfs::new();
        let db = Db::open_internal(vfs.clone(), SOURCE_KEK, PAGE, REALM)
            .await
            .unwrap();
        let mut writer = db
            .create_segment(REALM, SegmentKind::Unspecified)
            .await
            .unwrap();
        writer
            .append_page(SegmentPageKind::Data, b"segment-data")
            .await
            .unwrap();
        let meta = writer.seal().await.unwrap();
        let mut txn = db.begin_write().await.unwrap();
        txn.link_segment("linked", &meta).await.unwrap();
        txn.commit().await.unwrap();

        let mut state = db.writer.lock().await;
        let mut catalog = BTree::open(
            db.pager.clone(),
            db.realm_id,
            state.catalog_root_page_id,
            state.next_page_id,
            db.page_size,
        );
        let mut off_width = [0u8; 13];
        off_width[..8].copy_from_slice(&1u64.to_le_bytes());
        catalog
            .put(&Catalog::rekey_state_key(), &off_width)
            .await
            .unwrap();
        catalog.flush().await.unwrap();
        let source_header_key = db.hk.read().clone();
        let freed_pages = catalog.drain_freed();
        db.commit_rekey_catalog_root(
            &mut state,
            RekeyCatalogCommit {
                catalog_root_page_id: catalog.root_page_id(),
                next_page_id: catalog.next_page_id(),
                freed_pages: &freed_pages,
                effects: &[],
            },
            0,
            &source_header_key,
        )
        .await
        .unwrap();
        drop(state);
        drop(db);

        let reopened = Db::open_existing(vfs, SOURCE_KEK, PAGE, REALM).await;
        assert!(
            matches!(
                reopened,
                Err(PagedbError::Corruption(
                    crate::errors::CorruptionDetail::CatalogRowInvalid {
                        field: "rekey.framing"
                    }
                ))
            ),
            "expected a typed catalog-row rejection, got a different outcome"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn stale_ab_header_falls_back_with_both_rekey_keys() {
        let vfs = interrupted_rekey(RekeyTestFault::HeaderTargetPublished).await;
        let mut header = vfs.open("/main.db", OpenMode::ReadWrite).await.unwrap();
        header.write_at(0, &[0]).await.unwrap();
        drop(header);

        let resumed = Db::open_existing_with_counterpart_kek(
            vfs,
            SOURCE_KEK,
            TARGET_KEK,
            PAGE,
            REALM,
            crate::OpenOptions::default(),
        )
        .await
        .unwrap();
        assert!(resumed.open_segment(REALM, "boundary").await.is_ok());
    }

    #[test]
    fn mixed_cipher_intent_is_rejected_by_codec_before_admission() {
        let intent = RekeyIntent {
            source_mk_epoch: 0,
            target_mk_epoch: 1,
            source_cipher_id: 1,
            target_cipher_id: 2,
            same_kek: true,
            stage: RekeyStage::Intent,
            source_hk_proof: [0; 16],
            target_hk_proof: [0; 16],
        };
        assert!(matches!(
            Catalog::decode_rekey_state(&Catalog::encode_rekey_intent(&intent)),
            Err(PagedbError::RekeyStateInvalid {
                field: "target_cipher_id"
            })
        ));
    }
}
