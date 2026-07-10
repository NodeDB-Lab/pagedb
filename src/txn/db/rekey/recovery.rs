//! Rekey admission before recovery touches mixed-epoch catalog state.

use subtle::ConstantTimeEq;

use crate::Result;
use crate::catalog::codec::RekeyIntent;
use crate::crypto::kdf::{derive_hk, derive_mk};
use crate::crypto::{CipherId, MasterKey, SecretKey};
use crate::errors::PagedbError;
use crate::vfs::Vfs;

use super::super::core::{Db, WriterState};
use super::intent::intent_proof;

impl<V: Vfs + Clone> Db<V> {
    /// Establish every epoch lease required by a durable intent before catalog
    /// reconciliation. A KEK-changing interruption is never auto-recovered
    /// with a guessed or persisted counterpart key.
    pub(in crate::txn::db) async fn admit_rekey_recovery(
        &self,
        primary_kek: &SecretKey,
        counterpart_kek: Option<&SecretKey>,
    ) -> Result<bool> {
        let mut state = self.writer.lock().await;
        let Some(mut intent) = self.load_rekey_intent(&state).await? else {
            return Ok(false);
        };
        let source_cipher = CipherId::from_byte(intent.source_cipher_id)?;
        let target_cipher = CipherId::from_byte(intent.target_cipher_id)?;

        if intent.same_kek && intent.target_hk_proof == [0; 16] {
            self.persist_legacy_rekey_proof(&mut state, &mut intent, primary_kek, target_cipher)
                .await?;
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
        let (source_master_key, target_master_key) = resolve_rekey_key_pair(
            primary_kek,
            counterpart_kek,
            &proof_context,
            source_spec,
            target_spec,
            intent.same_kek,
        )?;

        self.pager
            .install_mk_epoch(source_master_key, intent.source_mk_epoch, source_cipher);
        self.pager
            .install_mk_epoch(target_master_key, intent.target_mk_epoch, target_cipher);
        Ok(true)
    }

    async fn persist_legacy_rekey_proof(
        &self,
        state: &mut WriterState,
        intent: &mut RekeyIntent,
        primary_kek: &SecretKey,
        target_cipher: CipherId,
    ) -> Result<()> {
        let target_master_key = derive_mk(
            primary_kek.as_bytes(),
            &self.kek_salt,
            intent.target_mk_epoch,
        )?;
        let target_header_key = derive_hk(&target_master_key)?;
        intent.target_hk_proof = intent_proof(
            &target_header_key,
            &self.file_id,
            &self.kek_salt,
            intent.source_mk_epoch,
            intent.target_mk_epoch,
            intent.target_mk_epoch,
            intent.target_cipher_id,
        )?;
        self.pager
            .install_mk_epoch(target_master_key, intent.target_mk_epoch, target_cipher);
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
