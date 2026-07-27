//! Durable rekey-intent validation and admission.

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::Result;
use crate::catalog::codec::RekeyIntent;
use crate::crypto::DerivedKey;
use crate::errors::PagedbError;

const REKEY_PROOF_DOMAIN: &[u8] = b"pagedb/rekey-proof/v1";

pub(crate) fn intent_proof(
    hk: &DerivedKey,
    file_id: &[u8; 16],
    kek_salt: &[u8; 16],
    source_epoch: u64,
    target_epoch: u64,
    proof_epoch: u64,
    cipher_id: u8,
) -> Result<[u8; 16]> {
    let mut mac = Hmac::<Sha256>::new_from_slice(hk.as_bytes())
        .map_err(|_| PagedbError::Io(std::io::Error::other("rekey proof key length")))?;
    mac.update(REKEY_PROOF_DOMAIN);
    mac.update(file_id);
    mac.update(kek_salt);
    mac.update(&source_epoch.to_le_bytes());
    mac.update(&target_epoch.to_le_bytes());
    mac.update(&proof_epoch.to_le_bytes());
    mac.update(&[cipher_id]);
    let digest = mac.finalize().into_bytes();
    let mut proof = [0u8; 16];
    proof.copy_from_slice(&digest[..16]);
    Ok(proof)
}

pub(crate) fn validate_intent(intent: &RekeyIntent) -> Result<()> {
    if intent.target_mk_epoch == 0 || intent.target_mk_epoch <= intent.source_mk_epoch {
        return Err(PagedbError::rekey_state_invalid("rekey.target_mk_epoch"));
    }
    crate::crypto::CipherId::from_byte(intent.source_cipher_id)?;
    crate::crypto::CipherId::from_byte(intent.target_cipher_id)?;
    Ok(())
}

/// Rekey rotates KEK material only. The public operation has no cipher
/// selection, so an intent may never introduce a mixed-cipher transition.
pub(crate) fn validate_intent_for_current_cipher(
    intent: &RekeyIntent,
    current_cipher_id: u8,
) -> Result<()> {
    validate_intent(intent)?;
    if intent.source_cipher_id != current_cipher_id {
        return Err(PagedbError::rekey_state_invalid("source_cipher_id"));
    }
    if intent.target_cipher_id != current_cipher_id {
        return Err(PagedbError::rekey_state_invalid("target_cipher_id"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::codec::{Catalog, RekeyStage};

    fn intent() -> RekeyIntent {
        RekeyIntent {
            source_mk_epoch: 0,
            target_mk_epoch: 9,
            source_cipher_id: 1,
            target_cipher_id: 1,
            same_kek: false,
            stage: RekeyStage::Intent,
            source_hk_proof: [3; 16],
            target_hk_proof: [4; 16],
        }
    }

    #[test]
    fn proof_binds_rekey_identity_and_transition_fields() {
        let hk = DerivedKey::from_bytes([0xA1; 32]);
        let file_id = [0xB2; 16];
        let kek_salt = [0xC3; 16];
        let proof = intent_proof(&hk, &file_id, &kek_salt, 4, 5, 4, 1).unwrap();
        assert_ne!(
            proof,
            intent_proof(&hk, &[0xB3; 16], &kek_salt, 4, 5, 4, 1).unwrap()
        );
        assert_ne!(
            proof,
            intent_proof(&hk, &file_id, &[0xC4; 16], 4, 5, 4, 1).unwrap()
        );
        assert_ne!(
            proof,
            intent_proof(&hk, &file_id, &kek_salt, 4, 6, 4, 1).unwrap()
        );
        assert_ne!(
            proof,
            intent_proof(&hk, &file_id, &kek_salt, 4, 5, 5, 1).unwrap()
        );
        assert_ne!(
            proof,
            intent_proof(&hk, &file_id, &kek_salt, 4, 5, 4, 2).unwrap()
        );
    }

    #[test]
    fn intent_rejects_checked_and_reserved_bytes() {
        let mut bytes = Catalog::encode_rekey_intent(&intent());
        bytes[3] = 1;
        assert!(Catalog::decode_rekey_state(&bytes).is_err());
        bytes[3] = 0;
        bytes[56] = 1;
        assert!(Catalog::decode_rekey_state(&bytes).is_err());
    }

    #[test]
    fn intent_rejects_impossible_epochs() {
        let mut invalid = intent();
        invalid.target_mk_epoch = 0;
        let bytes = Catalog::encode_rekey_intent(&invalid);
        assert!(Catalog::decode_rekey_state(&bytes).is_err());
    }

    #[test]
    fn intent_rejects_cipher_transition_at_admission() {
        let mut invalid = intent();
        invalid.target_cipher_id = 2;
        assert!(matches!(
            validate_intent_for_current_cipher(&invalid, 1),
            Err(PagedbError::RekeyStateInvalid {
                field: "target_cipher_id"
            })
        ));
    }
}
