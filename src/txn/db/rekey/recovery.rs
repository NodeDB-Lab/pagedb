//! Rekey admission before recovery touches mixed-epoch catalog state.

use subtle::ConstantTimeEq;

use crate::Result;
use crate::catalog::codec::{RekeyIntent, RekeyStage};
use crate::crypto::kdf::{derive_hk, derive_mk};
use crate::crypto::{CipherId, MasterKey, SecretKey};
use crate::errors::PagedbError;
use crate::pager::page_space::{FIRST_ALLOCATABLE_PAGE_ID, page_offset};
use crate::vfs::{OpenMode, Vfs, VfsFile, read_exact_at};

use super::super::core::{Db, WriterState};
use super::intent::intent_proof;

/// What a durable rekey intent asks of this open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::txn::db) enum RekeyAdmission {
    /// No intent is durable.
    NotPending,
    /// Both keys are installed. A writer finishes the rekey.
    Resume,
    /// Only the source key is present, and no page sits under the target key.
    SourceKeyOnly,
}

impl<V: Vfs + Clone> Db<V> {
    /// Establish every epoch lease required by a durable intent before catalog
    /// reconciliation. A KEK-changing interruption is never auto-recovered
    /// with a guessed or persisted counterpart key.
    ///
    /// The one exception needs no target key at all. An intent whose rebuild never
    /// renamed leaves every page under the source key. See
    /// [`Self::pending_rekey_left_source_intact`].
    ///
    /// Admission writes nothing. A legacy intent gets its target proof in memory
    /// here, and the resume persists it. That write folds the free list, so it
    /// waits for the mode gate and the chain detach.
    pub(in crate::txn::db) async fn admit_rekey_recovery(
        &self,
        primary_kek: &SecretKey,
        counterpart_kek: Option<&SecretKey>,
    ) -> Result<RekeyAdmission> {
        let state = self.writer.lock().await;
        let Some(mut intent) = self.load_rekey_intent(&state).await? else {
            return Ok(RekeyAdmission::NotPending);
        };
        let source_intact = self.pending_rekey_left_source_intact_locked(&intent);
        drop(state);
        let source_cipher = CipherId::from_byte(intent.source_cipher_id)?;
        let target_cipher = CipherId::from_byte(intent.target_cipher_id)?;

        if intent.same_kek && intent.target_hk_proof == [0; 16] {
            let target_master_key = derive_mk(
                primary_kek.as_bytes(),
                &self.kek_salt,
                intent.target_mk_epoch,
            )?;
            intent.target_hk_proof = self.legacy_target_proof(&intent, &target_master_key)?;
        }

        let proof_context = RekeyProofContext {
            file_id: &self.file_id,
            salt: &self.kek_salt,
            source_epoch: intent.source_mk_epoch,
            target_epoch: intent.target_mk_epoch,
        };
        let source_spec = RekeyProofSpec {
            epoch: intent.source_mk_epoch,
            cipher_id: intent.source_cipher_id,
            proof: &intent.source_hk_proof,
        };
        let target_spec = RekeyProofSpec {
            epoch: intent.target_mk_epoch,
            cipher_id: intent.target_cipher_id,
            proof: &intent.target_hk_proof,
        };
        let key_pair = resolve_rekey_key_pair(
            primary_kek,
            counterpart_kek,
            &proof_context,
            source_spec,
            target_spec,
            intent.same_kek,
        );
        let (source_master_key, target_master_key) = match key_pair {
            Err(error @ PagedbError::RekeyResumeKeyRequired { .. }) => {
                let source_key_held =
                    matching_key(primary_kek, &proof_context, &source_spec)?.is_some();
                if source_key_held && source_intact && self.every_page_under_epoch(&intent).await? {
                    return Ok(RekeyAdmission::SourceKeyOnly);
                }
                return Err(error);
            }
            other => other?,
        };

        self.pager
            .install_mk_epoch(source_master_key, intent.source_mk_epoch, source_cipher);
        self.pager
            .install_mk_epoch(target_master_key, intent.target_mk_epoch, target_cipher);
        Ok(RekeyAdmission::Resume)
    }

    /// Whether a pending rekey has written no page under its target key, so that a
    /// handle needs no target key to read this store.
    ///
    /// The intent row cannot say which release wrote it, because a new field is a
    /// format change. The file can. Only stage `Intent` with the source
    /// epoch in the header can be free of target pages. The envelope of every page
    /// then settles it, and that holds for an intent from any release. A rebuild
    /// from this build writes target pages only into its scratch. An earlier release
    /// wrote them in place, and one such page answers `false`.
    ///
    /// An intent with no target proof comes from a much earlier release, and this
    /// path leaves it alone.
    pub(in crate::txn::db) async fn pending_rekey_left_source_intact(&self) -> Result<bool> {
        let state = self.writer.lock().await;
        let Some(intent) = self.load_rekey_intent(&state).await? else {
            return Ok(false);
        };
        drop(state);
        Ok(self.pending_rekey_left_source_intact_locked(&intent)
            && self.every_page_under_epoch(&intent).await?)
    }

    fn pending_rekey_left_source_intact_locked(&self, intent: &RekeyIntent) -> bool {
        matches!(intent.stage, RekeyStage::Intent)
            && intent.target_hk_proof != [0; 16]
            && self.mk_epoch.load(std::sync::atomic::Ordering::SeqCst) == intent.source_mk_epoch
    }

    /// Whether every page envelope in `main.db` names the intent's source epoch or
    /// holds zeros. This reads 12 bytes per page, including pages past the cursor.
    async fn every_page_under_epoch(&self, intent: &RekeyIntent) -> Result<bool> {
        let mut file = self.vfs.open(&self.main_db_path, OpenMode::Read).await?;
        let page_size = u64::try_from(self.page_size)
            .map_err(|_| PagedbError::arithmetic_overflow("page size"))?;
        let pages = file.len().await? / page_size;
        let mut envelope = [0u8; 12];
        for page_id in FIRST_ALLOCATABLE_PAGE_ID..pages {
            let offset = page_offset(page_id, self.page_size, "rekey envelope sweep")?;
            read_exact_at(&mut file, offset, &mut envelope).await?;
            let mut epoch = [0u8; 8];
            epoch.copy_from_slice(&envelope[4..12]);
            if envelope != [0u8; 12] && u64::from_le_bytes(epoch) != intent.source_mk_epoch {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Remove an intent an open proved has no page under its target key. The open
    /// holds only the source key, so it cannot finish the rekey.
    pub(in crate::txn::db) async fn withdraw_rekey_with_source_key(&self) -> Result<()> {
        let mut state = self.writer.lock().await;
        let source_epoch = self.mk_epoch.load(std::sync::atomic::Ordering::SeqCst);
        let source_header_key = self.hk.read().clone();
        tracing::warn!(
            source_epoch,
            "an open with only the source key withdraws a rekey that never renamed its rebuild"
        );
        self.withdraw_rekey_intent(&mut state, source_epoch, &source_header_key)
            .await
    }

    /// The target proof an intent from an earlier release left as zeros.
    fn legacy_target_proof(
        &self,
        intent: &RekeyIntent,
        target_master_key: &MasterKey,
    ) -> Result<[u8; 16]> {
        intent_proof(
            &derive_hk(target_master_key)?,
            &self.file_id,
            &self.kek_salt,
            intent.source_mk_epoch,
            intent.target_mk_epoch,
            intent.target_mk_epoch,
            intent.target_cipher_id,
        )
    }

    /// Write the target proof into a legacy intent row. Admission installed the
    /// target key this derives from.
    pub(super) async fn persist_legacy_rekey_proof(
        &self,
        state: &mut WriterState,
        intent: &mut RekeyIntent,
    ) -> Result<()> {
        let target_cipher = CipherId::from_byte(intent.target_cipher_id)?;
        let target_master_key = self.pager.mk_for(intent.target_mk_epoch, target_cipher)?;
        intent.target_hk_proof = self.legacy_target_proof(intent, &target_master_key)?;
        let source_header_key = self.hk.read().clone();
        let header_epoch = self.mk_epoch.load(std::sync::atomic::Ordering::SeqCst);
        self.write_rekey_intent_locked(state, intent, header_epoch, &source_header_key)
            .await
    }
}

struct RekeyProofContext<'a> {
    file_id: &'a [u8; 16],
    salt: &'a [u8; 16],
    source_epoch: u64,
    target_epoch: u64,
}

#[derive(Clone, Copy)]
struct RekeyProofSpec<'a> {
    epoch: u64,
    cipher_id: u8,
    proof: &'a [u8; 16],
}

fn resolve_rekey_key_pair(
    primary_kek: &SecretKey,
    counterpart_kek: Option<&SecretKey>,
    context: &RekeyProofContext<'_>,
    source_spec: RekeyProofSpec<'_>,
    target_spec: RekeyProofSpec<'_>,
    same_kek: bool,
) -> Result<(MasterKey, MasterKey)> {
    let source_primary = matching_key(primary_kek, context, &source_spec)?;
    let target_primary = matching_key(primary_kek, context, &target_spec)?;
    if same_kek {
        return source_primary.zip(target_primary).ok_or_else(|| {
            PagedbError::rekey_counterpart_key_invalid(context.source_epoch, context.target_epoch)
        });
    }

    let counterpart = counterpart_kek.ok_or_else(|| {
        PagedbError::rekey_resume_key_required(context.source_epoch, context.target_epoch)
    })?;
    let source_counterpart = matching_key(counterpart, context, &source_spec)?;
    let target_counterpart = matching_key(counterpart, context, &target_spec)?;
    source_primary
        .zip(target_counterpart)
        .or_else(|| source_counterpart.zip(target_primary))
        .ok_or_else(|| {
            PagedbError::rekey_counterpart_key_invalid(context.source_epoch, context.target_epoch)
        })
}

fn matching_key(
    kek: &SecretKey,
    context: &RekeyProofContext<'_>,
    spec: &RekeyProofSpec<'_>,
) -> Result<Option<MasterKey>> {
    let mk = derive_mk(kek.as_bytes(), context.salt, spec.epoch)?;
    let hk = derive_hk(&mk)?;
    let derived_proof = intent_proof(
        &hk,
        context.file_id,
        context.salt,
        context.source_epoch,
        context.target_epoch,
        spec.epoch,
        spec.cipher_id,
    )?;
    Ok(bool::from(derived_proof.ct_eq(spec.proof)).then_some(mk))
}
