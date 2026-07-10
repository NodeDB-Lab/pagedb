//! Main-database rekey transition and durable intent publication.

use std::sync::atomic::Ordering;

use subtle::ConstantTimeEq;

use crate::Result;
use crate::btree::BTree;
use crate::catalog::codec::{Catalog, RekeyIntent, RekeyStage, RekeyStateRow};
use crate::crypto::kdf::{derive_hk, derive_mk};
use crate::crypto::{CipherId, DerivedKey, MasterKey, SecretKey};
use crate::errors::PagedbError;
use crate::pager::header::commit_header;
use crate::pager::structural_header::MainDbHeaderFields;
use crate::vfs::Vfs;

#[cfg(test)]
use super::super::core::RekeyTestFault;
use super::super::core::{Db, WriterState, encode_free_list_root, encode_root_ref};
use super::intent::{intent_proof, migrate_legacy, validate_intent_for_current_cipher};

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
            return Err(PagedbError::corruption(
                crate::errors::CorruptionDetail::HeaderUnverifiable,
            ));
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
        let intent = self.load_rekey_intent(&state).await?.ok_or_else(|| {
            PagedbError::corruption(crate::errors::CorruptionDetail::HeaderUnverifiable)
        })?;
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
        let main_tree = BTree::open(
            self.pager.clone(),
            self.realm_id,
            state.root_page_id,
            state.next_page_id,
            self.page_size,
        );
        main_tree.rekey_walk().await?;
        if state.commit_history_root_page_id != 0 {
            let history_tree = BTree::open(
                self.pager.clone(),
                self.realm_id,
                state.commit_history_root_page_id,
                state.next_page_id,
                self.page_size,
            );
            history_tree.rekey_walk().await?;
        }
        if state.free_list_root_page_id != 0 {
            let (_, chain_pages) = crate::pager::freelist::read_chain(
                &self.pager,
                self.realm_id,
                state.free_list_root_page_id,
            )
            .await?;
            for page_id in chain_pages {
                self.pager
                    .rewrite_page_under_current_epoch(
                        page_id,
                        self.realm_id,
                        crate::pager::PageKind::Free,
                    )
                    .await?;
            }
        }
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
            return Err(PagedbError::corruption(
                crate::errors::CorruptionDetail::HeaderUnverifiable,
            ));
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
        match Catalog::decode_rekey_state(&bytes)? {
            RekeyStateRow::V1(intent) => {
                validate_intent_for_current_cipher(&intent, self.cipher_id.as_byte())?;
                Ok(Some(intent))
            }
            RekeyStateRow::Legacy(legacy) => {
                let source_epoch = self.mk_epoch.load(Ordering::SeqCst);
                let source_header_key = self.hk.read().clone();
                let intent = migrate_legacy(
                    &legacy,
                    source_epoch,
                    self.cipher_id.as_byte(),
                    &source_header_key,
                    &self.file_id,
                    &self.kek_salt,
                )?;
                validate_intent_for_current_cipher(&intent, self.cipher_id.as_byte())?;
                Ok(Some(intent))
            }
        }
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
        self.commit_rekey_catalog_root(
            state,
            tree.root_page_id(),
            tree.next_page_id(),
            header_epoch,
            header_hk,
            &[],
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
        self.commit_rekey_catalog_root(
            state,
            tree.root_page_id(),
            tree.next_page_id(),
            header_epoch,
            header_hk,
            &[],
        )
        .await
        .map(|_| ())
    }

    pub(super) async fn commit_rekey_catalog_root(
        &self,
        state: &mut WriterState,
        catalog_root_page_id: u64,
        next_page_id: u64,
        header_epoch: u64,
        hk: &DerivedKey,
        effects: &[crate::txn::write::SegmentSideEffect],
    ) -> Result<super::super::segment::SegmentReconciliation> {
        let next_page_id = next_page_id.max(state.next_page_id);
        let new_seq = state
            .seq
            .checked_add(1)
            .ok_or_else(|| PagedbError::arithmetic_overflow("rekey header sequence"))?;
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
            state.active_slot,
            self.page_size,
        )
        .await?;
        state.catalog_root_page_id = catalog_root_page_id;
        state.next_page_id = next_page_id;
        state.active_slot = slot;
        state.seq = new_seq;
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

    #[tokio::test(flavor = "current_thread")]
    async fn legacy_intent_is_migrated_conservatively_during_recovery() {
        let vfs = MemVfs::new();
        let db = Db::open_internal(vfs.clone(), SOURCE_KEK, PAGE, REALM)
            .await
            .unwrap();
        let mut writer = db
            .create_segment(REALM, SegmentKind::Unspecified)
            .await
            .unwrap();
        writer
            .append_page(SegmentPageKind::Data, b"legacy-intent")
            .await
            .unwrap();
        let meta = writer.seal().await.unwrap();
        let mut txn = db.begin_write().await.unwrap();
        txn.link_segment("legacy", &meta).await.unwrap();
        txn.commit().await.unwrap();

        let mut state = db.writer.lock().await;
        let mut catalog = BTree::open(
            db.pager.clone(),
            db.realm_id,
            state.catalog_root_page_id,
            state.next_page_id,
            db.page_size,
        );
        let mut legacy = [0u8; crate::catalog::codec::LEGACY_REKEY_STATE_LEN];
        legacy[..8].copy_from_slice(&1u64.to_le_bytes());
        catalog
            .put(&Catalog::rekey_state_key(), &legacy)
            .await
            .unwrap();
        catalog.flush().await.unwrap();
        let source_header_key = db.hk.read().clone();
        db.commit_rekey_catalog_root(
            &mut state,
            catalog.root_page_id(),
            catalog.next_page_id(),
            0,
            &source_header_key,
            &[],
        )
        .await
        .unwrap();
        drop(state);
        drop(db);

        let reopened = Db::open_existing(vfs, SOURCE_KEK, PAGE, REALM)
            .await
            .unwrap();
        let reader = reopened.open_segment(REALM, "legacy").await.unwrap();
        assert!(
            reader
                .read_page(1)
                .await
                .unwrap()
                .starts_with(b"legacy-intent")
        );
        assert_eq!(
            reopened.mk_epoch.load(std::sync::atomic::Ordering::SeqCst),
            1
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
    fn mixed_cipher_v1_intent_is_rejected_by_codec_before_admission() {
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
