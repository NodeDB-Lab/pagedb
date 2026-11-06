//! Main-database rekey transition and durable intent publication.

use std::sync::atomic::Ordering;

use subtle::ConstantTimeEq;

use crate::Result;
use crate::btree::BTree;
use crate::catalog::codec::{Catalog, RekeyIntent, RekeyStage};
use crate::crypto::kdf::{derive_hk, derive_mk};
use crate::crypto::{CipherId, DerivedKey, MasterKey, SecretKey};
use crate::errors::PagedbError;
use crate::pager::anchor::HeaderCursor;
use crate::pager::header::commit_header;
use crate::pager::structural_header::MainDbHeaderFields;
use crate::vfs::Vfs;

#[cfg(test)]
use super::super::core::RekeyTestFault;
use super::super::core::{Db, WriterState, encode_free_list_root, encode_root_ref};
use super::intent::{intent_proof, validate_intent_for_current_cipher};
use super::rebuild::stage_needs_rebuild;

/// Commit-history rows read per batch while rekeying the roots they name.
/// Rows are 40 bytes, so this is a few KiB resident regardless of how deep
/// retention runs.
pub(super) const HISTORY_ROOT_BATCH: usize = 512;

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
    /// The commit-history tree this header publishes, when it moves.
    pub history: Option<RekeyHistoryRoot>,
}

/// A rewritten commit-history tree. `WriterState` takes it with its header.
pub(super) struct RekeyHistoryRoot {
    pub root_page_id: u64,
    pub root_version: u64,
    pub entry_count: Option<u64>,
}

impl<V: Vfs + Clone> Db<V> {
    /// Rekey the main database and every catalog-linked immutable segment under
    /// `new_mk_epoch`.
    ///
    /// A read-only walk runs first, and an error there changes nothing. A live
    /// page that fails authentication refuses the rekey. A retained commit whose
    /// pages fail authentication leaves durably with every older commit, and
    /// [`begin_read_at`](Self::begin_read_at) then reports them gone.
    ///
    /// The rekey rebuilds `main.db` in a scratch file and renames it into place.
    /// That needs free space up to the size of `main.db`. Pages nothing names do
    /// not survive the rename, so no page stays under the source key.
    ///
    /// An error before the rename leaves the handle usable and `main.db` intact,
    /// with every page under the source key. No target key stays in the handle.
    /// On a full device the rekey also withdraws its intent and returns
    /// [`PagedbError::RekeyNoSpace`], and the store opens as it did before. Any other
    /// error, or a dropped future, leaves the intent durable, and exports return
    /// [`PagedbError::RekeyPending`] until it settles. Three things settle it:
    ///
    /// - The next `rekey_db`, with any target key. It replaces the intent.
    /// - The next open with both keys. It finishes the rekey.
    /// - The next open with the source key alone. It proves every page is under
    ///   the source key, then withdraws the intent. The target key is not needed.
    ///
    /// From the rename on, the store needs the target key to open at all, and the
    /// source key too until the rekey finishes. Keep both until this call returns
    /// `Ok`, or until a reopen finishes the rekey. Losing either one past the rename
    /// loses the store or its unmigrated segments.
    ///
    /// A linked segment that fails to authenticate refuses the rekey before any
    /// write. Unlink it first, because the rekey cannot move it off the source key.
    /// A segment file sealed before the rename cannot link after it. See
    /// [`PagedbError::SegmentEpochStale`].
    pub async fn rekey_db(&self, kek: impl Into<SecretKey>, new_mk_epoch: u64) -> Result<()> {
        let kek = kek.into();
        self.ensure_usable()?;
        self.require_mode(
            "rekey_db",
            crate::txn::mode::DbMode::Standalone,
            crate::txn::db::DbModeCapabilities::allows_store_maintenance,
        )?;
        if new_mk_epoch == 0 || new_mk_epoch <= self.mk_epoch.load(Ordering::SeqCst) {
            return Err(PagedbError::rekey_state_invalid("rekey.target_mk_epoch"));
        }

        let source_epoch = self.mk_epoch.load(Ordering::SeqCst);
        let source_header_key = self.hk.read().clone();
        let (intent, target_master_key) =
            self.new_rekey_intent(&kek, source_epoch, &source_header_key, new_mk_epoch)?;
        let mut state = self.writer.lock().await;
        self.ensure_usable()?;
        // Read-only, so an error here leaves the store and the handle as they were.
        let pruned_through = self.history_rows_rekey_prunes(&state).await?;
        self.refuse_rekey_over_unverifiable_segment(&state).await?;
        // `state` takes each write's values only once its header landed, so memory
        // and the header agree throughout. An error before that point leaves the
        // handle usable. A header write with an unknown outcome poisons it, in
        // `commit_rekey_catalog_root`. This guard drops the pages of a write that
        // stopped before its header.
        let unpublished = self.discard_unpublished_pages_on_drop();
        let first_writes = async {
            if let Some(pruned_through) = pruned_through {
                self.prune_history_rows_locked(
                    &mut state,
                    pruned_through,
                    source_epoch,
                    &source_header_key,
                )
                .await?;
            }
            self.write_rekey_intent_locked(&mut state, &intent, source_epoch, &source_header_key)
                .await
        }
        .await;
        match first_writes {
            Ok(()) => unpublished.disarm(),
            Err(error) => {
                drop(unpublished);
                return Err(match error {
                    PagedbError::NoSpace => PagedbError::rekey_no_space(source_epoch, new_mk_epoch),
                    other => other,
                });
            }
        }
        #[cfg(test)]
        self.interrupt_rekey_if_requested(RekeyTestFault::Intent)?;
        let source_master_key = self.pager.mk_for(source_epoch, self.cipher_id)?;
        let outcome = self
            .resume_rekey_locked(&mut state, intent, &source_master_key, &target_master_key)
            .await;
        if matches!(outcome, Err(PagedbError::RekeyNoSpace { .. }))
            && let Err(error) = self
                .withdraw_rekey_intent(&mut state, source_epoch, &source_header_key)
                .await
        {
            tracing::error!(
                %error,
                "a rekey intent stayed on a full device, and the next open resumes it"
            );
        }
        outcome
    }

    /// The intent row for a rekey to `new_mk_epoch` under `kek`, and the target key.
    fn new_rekey_intent(
        &self,
        kek: &SecretKey,
        source_epoch: u64,
        source_header_key: &DerivedKey,
        new_mk_epoch: u64,
    ) -> Result<(RekeyIntent, MasterKey)> {
        let supplied_source_header_key =
            derive_hk(&derive_mk(kek.as_bytes(), &self.kek_salt, source_epoch)?)?;
        let cipher_id = self.cipher_id.as_byte();
        let source_proof = intent_proof(
            source_header_key,
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
        Ok((intent, target_master_key))
    }

    /// Remove a durable intent whose rebuild never renamed, so the next open needs
    /// neither room for a rebuild nor the target key.
    ///
    /// The caller proves `main.db` holds no page under the target key, so nothing
    /// else is left to undo. `rekey_db` knows this, because its handle sealed under
    /// the source key throughout. An open proves it by reading every page's envelope.
    /// An error here leaves the intent, and the store stays intact.
    pub(super) async fn withdraw_rekey_intent(
        &self,
        state: &mut WriterState,
        source_epoch: u64,
        source_header_key: &DerivedKey,
    ) -> Result<()> {
        let unpublished = self.discard_unpublished_pages_on_drop();
        let outcome = self
            .clear_rekey_intent_locked(state, source_epoch, source_header_key)
            .await;
        if outcome.is_ok() {
            unpublished.disarm();
        }
        outcome
    }

    pub(in crate::txn::db) async fn resume_rekey_intent(&self) -> Result<()> {
        let mut state = self.writer.lock().await;
        let mut intent = self
            .load_rekey_intent(&state)
            .await?
            .ok_or_else(|| PagedbError::rekey_state_invalid("rekey.intent_missing"))?;
        if intent.same_kek && intent.target_hk_proof == [0; 16] {
            self.persist_legacy_rekey_proof(&mut state, &mut intent)
                .await?;
        }
        self.settle_history_for_resume(&mut state, &intent).await?;
        let source_master_key = self.pager.mk_for(
            intent.source_mk_epoch,
            CipherId::from_byte(intent.source_cipher_id)?,
        )?;
        let target_master_key = self.pager.mk_for(
            intent.target_mk_epoch,
            CipherId::from_byte(intent.target_cipher_id)?,
        )?;
        self.resume_rekey_locked(&mut state, intent, &source_master_key, &target_master_key)
            .await
    }

    /// Run a rekey from its durable intent, under keys the caller supplies. A
    /// `rekey_db` holds the target key here and nowhere in the pager, so a rebuild
    /// that stops before its rename leaves no trace of that key.
    async fn resume_rekey_locked(
        &self,
        state: &mut WriterState,
        mut intent: RekeyIntent,
        source_master_key: &MasterKey,
        target_master_key: &MasterKey,
    ) -> Result<()> {
        validate_intent_for_current_cipher(&intent, self.cipher_id.as_byte())?;
        let source_header_key = derive_hk(source_master_key)?;
        let target_header_key = derive_hk(target_master_key)?;
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

        // Any stage before `MainDone` rebuilds `main.db` in a scratch file. An error
        // before its rename leaves the live file and this handle as they were, so
        // it returns as it is. Past the rename, durable state runs ahead of memory
        // and only a reopen can settle it. A resume at `MainDone` from an earlier
        // release's file keeps whatever unnamed pages that file holds.
        let rebuilt = stage_needs_rebuild(intent.stage);
        if rebuilt {
            self.rebuild_main_under_target_key(
                state,
                &mut intent,
                target_master_key,
                &target_header_key,
            )
            .await?;
        }

        // The header names the target epoch from here on, and every later stage
        // writes it. A rekey advances no commit, so the poison names the latest one.
        let commit = crate::CommitId(state.latest_commit_id);
        let publish = self.arm_durable_publish(commit);
        let result = async {
            #[cfg(test)]
            {
                if rebuilt {
                    self.interrupt_rekey_if_requested(RekeyTestFault::MainDone)?;
                }
            }
            self.finish_rekey_locked(state, &mut intent, &target_header_key)
                .await
        }
        .await;

        match result {
            Ok(()) => {
                publish.disarm();
                Ok(())
            }
            Err(error) => {
                tracing::error!(
                    commit = commit.0,
                    error = %error,
                    "rekey failed past its rename, so a reopen is required"
                );
                // The guard poisons as it drops.
                drop(publish);
                Err(PagedbError::rekey_target_epoch_activated(commit, error))
            }
        }
    }

    async fn finish_rekey_locked(
        &self,
        state: &mut WriterState,
        intent: &mut RekeyIntent,
        target_header_key: &DerivedKey,
    ) -> Result<()> {
        if !matches!(intent.stage, RekeyStage::SegmentsPending) {
            intent.stage = RekeyStage::SegmentsPending;
            self.write_rekey_intent_locked(
                state,
                intent,
                intent.target_mk_epoch,
                target_header_key,
            )
            .await?;
            #[cfg(test)]
            self.interrupt_rekey_if_requested(RekeyTestFault::SegmentsPending)?;
        }
        let left_behind = self
            .migrate_rekey_segments(state, intent, target_header_key)
            .await?;
        if left_behind == 0 && self.rekey_segments_pending(state, intent).await? {
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
                history: None,
            },
            header_epoch,
            header_hk,
        )
        .await
        .map(|_| ())
    }

    pub(super) async fn clear_rekey_intent_locked(
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
                history: None,
            },
            header_epoch,
            header_hk,
        )
        .await
        .map(|_| ())
    }

    /// Make one catalog rewrite durable under one header.
    ///
    /// Pages the rewrite superseded join the free list here, as every ordinary
    /// commit's copy-on-write leftovers do. Without it a rekey abandons pages at
    /// each intent transition. No root reaches them and the free list lacks them.
    /// Once the source epoch is retired, a key that no longer exists seals them.
    /// Entries carry the commit id after the latest one. The reclamation floor
    /// therefore still withholds any page a live reader or retained history root
    /// can name.
    ///
    /// `state` takes the new values only after the header lands. An error or a drop
    /// before that point leaves memory describing the durable header. The caller
    /// drops the staged pages, and the handle stays usable. From the header write
    /// through publication the guard poisons, because the header outcome can be
    /// unknown.
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
            history,
        } = catalog;
        let folded = self
            .fold_freed_catalog_pages(state, freed_pages, next_page_id)
            .await?;
        if !freed_pages.is_empty() {
            self.pager.flush_main(self.realm_id).await?;
        }
        let next_page_id = folded.next_page_id.max(state.next_page_id);
        // An anchor refresh can run whenever the window runs out, so the live
        // cursor — not this writer's memory of it — names the slot this header
        // supersedes.
        let header_cursor = self.pager.header_cursor()?;
        let new_seq = header_cursor.next_seq()?;
        let mut fields = self.rekey_header_fields(
            state,
            header_epoch,
            new_seq,
            catalog_root_page_id,
            next_page_id,
        )?;
        fields.free_list_root = encode_free_list_root(folded.root_page_id);
        if let Some(history) = &history {
            fields.commit_history_root_page_id = history.root_page_id;
            fields.commit_history_root_version = history.root_version;
        }
        let counter_anchor = fields.counter_anchor;
        let commit = crate::CommitId(state.latest_commit_id);
        let publish = self.arm_durable_publish(commit);
        let slot = match commit_header(
            &*self.vfs,
            &self.main_db_path,
            hk,
            &fields,
            header_cursor.slot,
            self.page_size,
        )
        .await
        {
            Ok(slot) => slot,
            Err(error) => return Err(publish.header_write_failed(error)),
        };
        self.pager
            .note_header_written(HeaderCursor { slot, seq: new_seq });
        state.catalog_root_page_id = catalog_root_page_id;
        state.next_page_id = next_page_id;
        state.free_list_root_page_id = folded.root_page_id;
        state.free_list_entries = folded.entries;
        if let Some(history) = history {
            state.commit_history_root_page_id = history.root_page_id;
            state.commit_history_root_version = history.root_version;
            state.commit_history_count = history.entry_count;
        }
        let outcome = self
            .finish_durable_commit(state, commit, counter_anchor, effects)
            .await;
        // An error above poisoned the handle itself, with the first cause.
        publish.disarm();
        outcome
    }

    pub(super) fn rekey_header_fields(
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
            realm_id: self.realm_id,
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

        // Past the rename. A stop before it no longer activates anything.
        db.interrupt_rekey_after(RekeyTestFault::MainDone);
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

    /// A stop before the rename leaves `main.db` whole, so the handle stays usable
    /// and its header, epoch, and readers stay as they were. A reopen still finishes
    /// the rekey from the durable intent.
    #[tokio::test(flavor = "current_thread")]
    async fn a_rekey_stopped_before_the_rename_leaves_the_handle_usable_and_a_reopen_finishes_it() {
        for point in [
            RekeyTestFault::MainPagesTargetReadable,
            RekeyTestFault::HeaderTargetPublished,
        ] {
            let vfs = MemVfs::new();
            let db = Db::open_internal(vfs.clone(), SOURCE_KEK, PAGE, REALM)
                .await
                .unwrap();
            let mut writer = db.begin_write().await.unwrap();
            writer.put(b"preserved", b"source-epoch").await.unwrap();
            writer.commit().await.unwrap();
            let existing_reader = db.begin_read().await.unwrap();

            db.interrupt_rekey_after(point);
            assert!(db.rekey_db(TARGET_KEK, 1).await.is_err(), "{point:?}");

            db.ensure_usable().unwrap();
            assert_eq!(db.mk_epoch.load(Ordering::SeqCst), 0, "{point:?}");
            assert_eq!(db.pager.active_mk_epoch(), 0, "{point:?}");
            assert_eq!(
                existing_reader.get(b"preserved").await.unwrap().as_deref(),
                Some(b"source-epoch".as_slice())
            );
            drop(existing_reader);
            let mut writer = db.begin_write().await.unwrap();
            writer.put(b"after-the-stop", b"value").await.unwrap();
            writer.commit().await.unwrap();
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
            assert_eq!(reopened.mk_epoch.load(Ordering::SeqCst), 1, "{point:?}");
            let reader = reopened.begin_read().await.unwrap();
            assert_eq!(
                reader.get(b"after-the-stop").await.unwrap().as_deref(),
                Some(b"value".as_slice())
            );
        }
    }

    /// A rekey re-seals every reachable page and writes no header before its rename,
    /// so the whole re-seal draws nonces from one anchor window. On a store larger
    /// than that window it must still complete — and the anchor must end more than
    /// a whole budget above where it started, which only an advance *during* the
    /// re-seal can produce.
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

    /// The last reader may leave *during* the deferral, and the retirement must
    /// still complete.
    ///
    /// Deferring is two facts that have to agree: a reader exists, and an
    /// obligation is recorded where the drain will find it. Nothing pins the
    /// first fact in place — the reader's `drop` is a plain unregister that can
    /// land at any instant, including between the two. When it did, the drain
    /// read an empty obligation list and the record arrived after the only
    /// thing that ever reads it had gone: `rekey_db` returned `Ok(())` while the
    /// superseded master key stayed leasable for the life of the handle, with no
    /// error, no log line, and nothing to query. This drives the reader out at
    /// exactly that instant and requires the epoch to retire anyway.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_reader_leaving_mid_deferral_still_retires_the_source_epoch() {
        let db = Db::open_internal(MemVfs::new(), SOURCE_KEK, PAGE, REALM)
            .await
            .unwrap();
        // Move the active epoch off 0 so retiring it is a real retirement
        // rather than the active-epoch refusal.
        let target_mk = derive_mk(&TARGET_KEK, &db.kek_salt, 1).unwrap();
        db.pager.set_active_mk_epoch(target_mk, 1);

        // Left to race, the reader can be gone before the critical section is
        // even entered, the deferral is never taken, and every assertion below
        // passes against the unfixed code. So the hook drives the reader out
        // itself, from the one instant the bug needed.
        let departure = std::sync::Arc::new(std::sync::Barrier::new(2));
        let deferrals = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let hook_departure = departure.clone();
        let hook_deferrals = deferrals.clone();
        db.install_retirement_defer_hook(std::sync::Arc::new(move |db: &Db<MemVfs>| {
            hook_deferrals.fetch_add(1, Ordering::Relaxed);
            hook_departure.wait();
            // `unregister_read` releases `tracked_readers` before it touches
            // the retirement list held here, so this cannot deadlock.
            for _ in 0..5_000 {
                if db.tracked_readers.lock().is_empty() {
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            panic!("the reader never left; the window under test was not reached");
        }));

        let read = db.begin_read().await.unwrap();
        assert!(
            db.pager.mk_for(0, db.cipher_id).is_ok(),
            "the source epoch must still be leasable while a reader holds it"
        );

        std::thread::scope(|scope| {
            scope.spawn(|| {
                departure.wait();
                drop(read);
            });
            db.retire_rekey_source_when_safe(0, db.cipher_id)
        })
        .unwrap();
        db.clear_retirement_defer_hook();

        assert_eq!(
            deferrals.load(Ordering::Relaxed),
            1,
            "the retirement must have been deferred; otherwise the reader left \
             before the window and the race was never staged"
        );
        assert!(
            db.tracked_readers.lock().is_empty(),
            "the reader must be gone before the retirement is judged"
        );
        assert!(
            db.pending_key_retirements.lock().is_empty(),
            "an obligation no reader is waiting on must not survive the deferral"
        );
        assert!(
            matches!(
                db.pager.mk_for(0, db.cipher_id),
                Err(PagedbError::MissingPersistedKey { mk_epoch: 0, .. })
            ),
            "a reader leaving mid-deferral must not leave the source epoch leasable"
        );
    }

    /// Queue two obligations, then make the first one refuse to retire.
    /// Retirements are independent epochs, so the refusal must be kept and
    /// stepped over, not treated as a wall.
    #[tokio::test(flavor = "current_thread")]
    async fn a_refused_retirement_does_not_hold_up_the_obligations_behind_it() {
        let db = Db::open_internal(MemVfs::new(), SOURCE_KEK, PAGE, REALM)
            .await
            .unwrap();
        let target_mk = derive_mk(&TARGET_KEK, &db.kek_salt, 1).unwrap();
        db.pager.set_active_mk_epoch(target_mk, 1);
        let spare_mk = derive_mk(&TARGET_KEK, &db.kek_salt, 2).unwrap();
        db.pager.install_mk_epoch(spare_mk, 2, db.cipher_id);

        let read = db.begin_read().await.unwrap();
        db.retire_rekey_source_when_safe(0, db.cipher_id).unwrap();
        db.retire_rekey_source_when_safe(2, db.cipher_id).unwrap();

        // Epoch 0 is the active one by the time the drain runs, which is the
        // one condition `retire_mk_epoch` refuses.
        let source_mk = derive_mk(&SOURCE_KEK, &db.kek_salt, 0).unwrap();
        db.pager.set_active_mk_epoch(source_mk, 0);
        drop(read);

        assert!(
            db.pager.mk_for(2, db.cipher_id).is_err(),
            "an epoch queued behind a refusal must still be retired"
        );
        let queued: Vec<u64> = db
            .pending_key_retirements
            .lock()
            .iter()
            .map(|pending| pending.epoch)
            .collect();
        assert_eq!(
            queued,
            vec![0],
            "the refused epoch — and only it — must stay queued for the next attempt"
        );
    }

    /// A drain runs only when the last reader leaves, so an obligation it
    /// failed to clear has no second drain coming while the reader set stays
    /// empty. The next rotation is the only thing left that can retry it.
    #[tokio::test(flavor = "current_thread")]
    async fn a_rotation_with_no_readers_retires_the_backlog_it_inherits() {
        let db = Db::open_internal(MemVfs::new(), SOURCE_KEK, PAGE, REALM)
            .await
            .unwrap();
        let target_mk = derive_mk(&TARGET_KEK, &db.kek_salt, 1).unwrap();
        db.pager.set_active_mk_epoch(target_mk, 1);

        let read = db.begin_read().await.unwrap();
        db.retire_rekey_source_when_safe(0, db.cipher_id).unwrap();
        let source_mk = derive_mk(&SOURCE_KEK, &db.kek_salt, 0).unwrap();
        db.pager.set_active_mk_epoch(source_mk, 0);
        drop(read);
        assert_eq!(
            db.pending_key_retirements.lock().len(),
            1,
            "the refused epoch must have been kept"
        );

        let target_mk = derive_mk(&TARGET_KEK, &db.kek_salt, 1).unwrap();
        db.pager.set_active_mk_epoch(target_mk, 1);
        let spare_mk = derive_mk(&TARGET_KEK, &db.kek_salt, 2).unwrap();
        db.pager.install_mk_epoch(spare_mk, 2, db.cipher_id);
        db.retire_rekey_source_when_safe(2, db.cipher_id).unwrap();

        assert!(
            db.pending_key_retirements.lock().is_empty(),
            "a rotation that finds no reader must clear the backlog, not just its own epoch"
        );
        assert!(
            db.pager.mk_for(0, db.cipher_id).is_err(),
            "the inherited obligation must actually have been retired"
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
            RekeyTestFault::MainFileRenamed,
            RekeyTestFault::MainDone,
            RekeyTestFault::SegmentsPending,
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
            RekeyTestFault::MainFileRenamed,
            RekeyTestFault::MainDone,
            RekeyTestFault::SegmentsPending,
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
        // Past the rename. Before it, the source key alone can withdraw the intent.
        let vfs = interrupted_rekey(RekeyTestFault::SegmentsPending).await;
        let header_before = {
            let header = vfs.open("/main.db", OpenMode::Read).await.unwrap();
            let mut bytes = vec![0u8; PAGE * 2];
            header.read_at(0, &mut bytes).await.unwrap();
            bytes
        };
        assert!(matches!(
            Db::open_existing(vfs.clone(), TARGET_KEK, PAGE, REALM).await,
            Err(PagedbError::RekeyResumeKeyRequired { .. })
        ));
        assert!(matches!(
            Db::open_existing_with_counterpart_kek(
                vfs.clone(),
                TARGET_KEK,
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
                history: None,
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

    /// The rename leaves one header, in slot A. The `SegmentsPending` write fills
    /// slot B, so this is the first point with two target headers. Losing the newer
    /// one falls back to slot A at `MainDone`, and the resume redoes the rest.
    #[tokio::test(flavor = "current_thread")]
    async fn stale_ab_header_falls_back_with_both_rekey_keys() {
        let vfs = interrupted_rekey(RekeyTestFault::SegmentsPending).await;
        let mut header = vfs.open("/main.db", OpenMode::ReadWrite).await.unwrap();
        header.write_at(PAGE as u64, &[0]).await.unwrap();
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

    /// Before the rename the live file holds two source headers, so a torn newer
    /// one falls back to the older one. Which of them names the intent decides
    /// whether a rekey resumes. Either way, every commit reads back.
    #[tokio::test(flavor = "current_thread")]
    async fn a_torn_live_header_before_the_rename_opens_with_both_rekey_keys() {
        for slot in [0, 1] {
            let vfs = interrupted_rekey(RekeyTestFault::HeaderTargetPublished).await;
            let mut header = vfs.open("/main.db", OpenMode::ReadWrite).await.unwrap();
            header.write_at(slot * PAGE as u64, &[0]).await.unwrap();
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
            assert!(
                resumed.open_segment(REALM, "boundary").await.is_ok(),
                "{slot}"
            );
        }
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
