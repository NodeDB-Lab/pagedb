//! HKDF-SHA-256 key derivation chain: KEK → MK → `DEK_realm` / IK / HK.

use hkdf::Hkdf;
use sha2::Sha256;

use crate::RealmId;
use crate::Result;
use crate::errors::PagedbError;

use super::keys::{DerivedKey, MasterKey};

const INFO_MASTER_PREFIX: &[u8] = b"pagedb/master/v1/";
const INFO_REALM_PREFIX: &[u8] = b"pagedb/realm/";
const INFO_REALM_SUFFIX: &[u8] = b"/v1";
const INFO_INTEGRITY: &[u8] = b"pagedb/integrity/v1";
const INFO_HEADER_MAC: &[u8] = b"pagedb/header-mac/v1";

/// Derive the master key from the embedder-supplied KEK.
///
/// `info` = `INFO_MASTER_PREFIX ‖ mk_epoch.to_le_bytes()` (17 + 8 = 25 bytes).
pub fn derive_mk(kek: &[u8; 32], kek_salt: &[u8; 16], mk_epoch: u64) -> Result<MasterKey> {
    let mut info = [0u8; INFO_MASTER_PREFIX.len() + 8];
    info[..INFO_MASTER_PREFIX.len()].copy_from_slice(INFO_MASTER_PREFIX);
    info[INFO_MASTER_PREFIX.len()..].copy_from_slice(&mk_epoch.to_le_bytes());

    let hk = Hkdf::<Sha256>::new(Some(kek_salt), kek);
    let mut out = [0u8; 32];
    hk.expand(&info, &mut out)
        .map_err(|_| PagedbError::Io(std::io::Error::other("hkdf expand failed (mk)")))?;
    Ok(MasterKey::from_bytes(out))
}

/// Derive the per-realm Data Encryption Key (used by AEAD modes).
///
/// `info` = `"pagedb/realm/" ‖ realm_id ‖ "/v1"` (13 + 16 + 3 = 32 bytes).
pub fn derive_dek(mk: &MasterKey, realm_id: RealmId) -> Result<DerivedKey> {
    let mut info = [0u8; INFO_REALM_PREFIX.len() + 16 + INFO_REALM_SUFFIX.len()];
    let mut off = 0;
    info[off..off + INFO_REALM_PREFIX.len()].copy_from_slice(INFO_REALM_PREFIX);
    off += INFO_REALM_PREFIX.len();
    info[off..off + 16].copy_from_slice(&realm_id.0);
    off += 16;
    info[off..off + INFO_REALM_SUFFIX.len()].copy_from_slice(INFO_REALM_SUFFIX);

    expand(mk.as_bytes(), &info)
}

/// Derive the Integrity Key (used by plaintext+MAC mode, shared across realms).
pub fn derive_ik(mk: &MasterKey) -> Result<DerivedKey> {
    expand(mk.as_bytes(), INFO_INTEGRITY)
}

/// Derive the Header Key (used to MAC main.db headers and segment headers/footers).
pub fn derive_hk(mk: &MasterKey) -> Result<DerivedKey> {
    expand(mk.as_bytes(), INFO_HEADER_MAC)
}

/// Derive a transient per-WriteTxn spill key from the master key.
///
/// `info` = `"pagedb/spill/" ‖ file_id[16] ‖ txn_seq.to_le_bytes()[8]` (13 + 16 + 8 = 37 bytes).
/// The key is transient: the tmp file it protects is discarded at commit/abort.
pub fn derive_spill_key(mk: &MasterKey, file_id: &[u8; 16], txn_seq: u64) -> Result<DerivedKey> {
    const PREFIX: &[u8] = b"pagedb/spill/";
    let mut info = [0u8; PREFIX.len() + 16 + 8];
    info[..PREFIX.len()].copy_from_slice(PREFIX);
    info[PREFIX.len()..PREFIX.len() + 16].copy_from_slice(file_id);
    info[PREFIX.len() + 16..].copy_from_slice(&txn_seq.to_le_bytes());
    expand(mk.as_bytes(), &info)
}

fn expand(ikm: &[u8; 32], info: &[u8]) -> Result<DerivedKey> {
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut out = [0u8; 32];
    hk.expand(info, &mut out)
        .map_err(|_| PagedbError::Io(std::io::Error::other("hkdf expand failed")))?;
    Ok(DerivedKey::from_bytes(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_kek() -> [u8; 32] {
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = u8::try_from(i).unwrap();
        }
        k
    }

    #[test]
    fn mk_is_deterministic() {
        let salt = [0xAB; 16];
        let kek = fixed_kek();
        let a = derive_mk(&kek, &salt, 7).unwrap();
        let b = derive_mk(&kek, &salt, 7).unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn different_epoch_yields_different_mk() {
        let salt = [0xAB; 16];
        let kek = fixed_kek();
        let a = derive_mk(&kek, &salt, 7).unwrap();
        let b = derive_mk(&kek, &salt, 8).unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn different_salt_yields_different_mk() {
        let kek = fixed_kek();
        let a = derive_mk(&kek, &[0xAB; 16], 7).unwrap();
        let b = derive_mk(&kek, &[0xCD; 16], 7).unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn dek_isolates_per_realm() {
        let mk = derive_mk(&fixed_kek(), &[0; 16], 0).unwrap();
        let a = derive_dek(&mk, RealmId([0x11; 16])).unwrap();
        let b = derive_dek(&mk, RealmId([0x22; 16])).unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn ik_hk_are_distinct_from_dek() {
        let mk = derive_mk(&fixed_kek(), &[0; 16], 0).unwrap();
        let dek = derive_dek(&mk, RealmId([0x11; 16])).unwrap();
        let ik = derive_ik(&mk).unwrap();
        let hk = derive_hk(&mk).unwrap();
        assert_ne!(dek.as_bytes(), ik.as_bytes());
        assert_ne!(dek.as_bytes(), hk.as_bytes());
        assert_ne!(ik.as_bytes(), hk.as_bytes());
    }
}
