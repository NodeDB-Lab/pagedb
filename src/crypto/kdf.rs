//! HKDF-SHA-256 key derivation chain: KEK → MK → `DEK_realm` / IK / HK.

use hkdf::Hkdf;
use sha2::Sha256;

use crate::RealmId;
use crate::Result;
use crate::errors::PagedbError;

use super::keys::{DerivedKey, MasterKey};

const INFO_MASTER_PREFIX: &[u8] = b"pagedb/master/v1/";
const INFO_REALM_PREFIX: &[u8] = b"pagedb/realm/";
const INFO_INTEGRITY_PREFIX: &[u8] = b"pagedb/integrity/";
const INFO_FILE_INFIX: &[u8] = b"/file/";
const INFO_V2_SUFFIX: &[u8] = b"/v2";
const INFO_HEADER_MAC: &[u8] = b"pagedb/header-mac/v1";

/// Build `prefix ‖ realm_id ‖ "/file/" ‖ file_id ‖ "/v2"`.
///
/// The realm and the file identity are both fixed-width, and the literals
/// around them are constant, so the encoding is unambiguous without a length
/// prefix: no two distinct `(realm, file)` pairs can produce the same bytes.
fn scoped_info<const N: usize>(prefix: &[u8], realm_id: RealmId, file_id: &[u8; 16]) -> [u8; N] {
    let mut info = [0u8; N];
    let mut off = 0;
    info[off..off + prefix.len()].copy_from_slice(prefix);
    off += prefix.len();
    info[off..off + 16].copy_from_slice(&realm_id.0);
    off += 16;
    info[off..off + INFO_FILE_INFIX.len()].copy_from_slice(INFO_FILE_INFIX);
    off += INFO_FILE_INFIX.len();
    info[off..off + 16].copy_from_slice(file_id);
    off += 16;
    info[off..off + INFO_V2_SUFFIX.len()].copy_from_slice(INFO_V2_SUFFIX);
    info
}

/// Width of a `scoped_info` buffer for a given prefix.
const fn scoped_info_len(prefix_len: usize) -> usize {
    prefix_len + 16 + INFO_FILE_INFIX.len() + 16 + INFO_V2_SUFFIX.len()
}

const DEK_INFO_LEN: usize = scoped_info_len(INFO_REALM_PREFIX.len());
const IK_INFO_LEN: usize = scoped_info_len(INFO_INTEGRITY_PREFIX.len());

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

/// Derive the Data Encryption Key for one realm **within one file** (used by
/// AEAD modes).
///
/// `info` = `"pagedb/realm/" ‖ realm_id ‖ "/file/" ‖ file_id ‖ "/v2"`.
///
/// # Why the file identity is part of the key
///
/// An AEAD nonce here is `file_id[0..6] ‖ counter48` (see
/// [`crate::crypto::nonce`]), so a key's nonce space is partitioned only by
/// the leading 6 bytes of the identity that issues into it. `main.db`, every
/// segment, and every apply journal in a realm are separate identities, and
/// those identities are random — which makes a shared per-realm key a birthday
/// problem over 2^48, not a guarantee. Two files whose identities happen to
/// share a 6-byte prefix would issue the same nonce under the same key, and
/// GCM nonce reuse leaks the plaintext XOR and exposes the authentication key.
///
/// Scoping the key by the full 16-byte identity removes the question instead of
/// making it unlikely: each file gets its own key, so its 48-bit counter is the
/// *whole* nonce space for that key and reuse is impossible by construction
/// rather than improbable by measure.
///
/// `file_id` must be the same identity that seeds the file's nonce generator:
/// the header's `file_id` for `main.db`, the `segment_id` for a segment, the
/// journal id for an apply journal.
pub fn derive_dek(mk: &MasterKey, realm_id: RealmId, file_id: &[u8; 16]) -> Result<DerivedKey> {
    let info: [u8; DEK_INFO_LEN] = scoped_info(INFO_REALM_PREFIX, realm_id, file_id);
    expand(mk.as_bytes(), &info)
}

/// Derive the Integrity Key for one realm within one file (used by the
/// plaintext+MAC mode).
///
/// `info` = `"pagedb/integrity/" ‖ realm_id ‖ "/file/" ‖ file_id ‖ "/v2"`.
///
/// An HMAC needs no nonce, so this mode has no reuse hazard to avoid. It is
/// scoped identically to [`derive_dek`] anyway so that "one key per (realm,
/// file, epoch, cipher)" is a single rule with no exception to remember — a
/// mode added later inherits the safe shape by default.
pub fn derive_ik(mk: &MasterKey, realm_id: RealmId, file_id: &[u8; 16]) -> Result<DerivedKey> {
    let info: [u8; IK_INFO_LEN] = scoped_info(INFO_INTEGRITY_PREFIX, realm_id, file_id);
    expand(mk.as_bytes(), &info)
}

/// Derive the Header Key (used to MAC main.db headers and segment headers/footers).
pub fn derive_hk(mk: &MasterKey) -> Result<DerivedKey> {
    expand(mk.as_bytes(), INFO_HEADER_MAC)
}

/// Derive a transient per-WriteTxn spill key from the master key.
///
/// `info` = `"pagedb/spill/" ‖ file_id[16] ‖ spill_epoch[16] ‖ txn_seq.to_le_bytes()[8]`
/// (13 + 16 + 16 + 8 = 53 bytes).
///
/// `spill_epoch` is fresh per open handle. `file_id` and the master key are
/// durable and `txn_seq` restarts at 1 on every open, so those three alone
/// would repeat the same key across two opens of one store — and the spill
/// nonce, built from that same restarting sequence, would repeat with it. The
/// epoch is what keeps each open's spill key distinct, and therefore what makes
/// the sequence a sound nonce source without a durable anchor.
///
/// Nothing reads a spill file written by an earlier open, so there is no
/// durability cost to a per-open key: the scratch a crash leaves behind is
/// swept at the next open, never decrypted.
pub fn derive_spill_key(
    mk: &MasterKey,
    file_id: &[u8; 16],
    spill_epoch: &[u8; 16],
    txn_seq: u64,
) -> Result<DerivedKey> {
    const PREFIX: &[u8] = b"pagedb/spill/";
    let mut info = [0u8; PREFIX.len() + 16 + 16 + 8];
    let mut off = 0;
    info[off..off + PREFIX.len()].copy_from_slice(PREFIX);
    off += PREFIX.len();
    info[off..off + 16].copy_from_slice(file_id);
    off += 16;
    info[off..off + 16].copy_from_slice(spill_epoch);
    off += 16;
    info[off..off + 8].copy_from_slice(&txn_seq.to_le_bytes());
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
    fn spill_key_isolates_per_open_at_the_same_sequence() {
        // The transaction sequence restarts at 1 on every open and also builds
        // the spill nonce, so two opens of one store must not share a key at
        // one sequence.
        let mk = derive_mk(&fixed_kek(), &[0; 16], 0).unwrap();
        let file_id = [0x5A; 16];
        let a = derive_spill_key(&mk, &file_id, &[0x01; 16], 1).unwrap();
        let b = derive_spill_key(&mk, &file_id, &[0x02; 16], 1).unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn spill_key_isolates_per_sequence_within_one_open() {
        let mk = derive_mk(&fixed_kek(), &[0; 16], 0).unwrap();
        let epoch = [0x01; 16];
        let a = derive_spill_key(&mk, &[0x5A; 16], &epoch, 1).unwrap();
        let b = derive_spill_key(&mk, &[0x5A; 16], &epoch, 2).unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn spill_key_isolates_per_store() {
        let mk = derive_mk(&fixed_kek(), &[0; 16], 0).unwrap();
        let epoch = [0x01; 16];
        let a = derive_spill_key(&mk, &[0x5A; 16], &epoch, 1).unwrap();
        let b = derive_spill_key(&mk, &[0xA5; 16], &epoch, 1).unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    const FILE_A: [u8; 16] = [0x5A; 16];
    const FILE_B: [u8; 16] = [0xA5; 16];

    #[test]
    fn dek_isolates_per_realm() {
        let mk = derive_mk(&fixed_kek(), &[0; 16], 0).unwrap();
        let a = derive_dek(&mk, RealmId([0x11; 16]), &FILE_A).unwrap();
        let b = derive_dek(&mk, RealmId([0x22; 16]), &FILE_A).unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    /// The property the whole per-file scoping exists for: two files in one
    /// realm never share a key, so neither can issue a nonce the other has
    /// already used.
    #[test]
    fn dek_isolates_per_file_within_one_realm() {
        let mk = derive_mk(&fixed_kek(), &[0; 16], 0).unwrap();
        let realm = RealmId([0x11; 16]);
        let a = derive_dek(&mk, realm, &FILE_A).unwrap();
        let b = derive_dek(&mk, realm, &FILE_B).unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    /// Identities that collide in the 6 bytes the nonce is built from are
    /// exactly the case a per-realm key could not survive. They must still
    /// derive different keys, so a prefix collision costs nothing.
    #[test]
    fn dek_isolates_files_sharing_a_nonce_prefix() {
        let mk = derive_mk(&fixed_kek(), &[0; 16], 0).unwrap();
        let realm = RealmId([0x11; 16]);
        let mut shared_prefix = FILE_A;
        shared_prefix[15] ^= 0xFF;
        assert_eq!(FILE_A[..6], shared_prefix[..6]);
        let a = derive_dek(&mk, realm, &FILE_A).unwrap();
        let b = derive_dek(&mk, realm, &shared_prefix).unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn ik_isolates_per_realm_and_file() {
        let mk = derive_mk(&fixed_kek(), &[0; 16], 0).unwrap();
        let base = derive_ik(&mk, RealmId([0x11; 16]), &FILE_A).unwrap();
        let other_realm = derive_ik(&mk, RealmId([0x22; 16]), &FILE_A).unwrap();
        let other_file = derive_ik(&mk, RealmId([0x11; 16]), &FILE_B).unwrap();
        assert_ne!(base.as_bytes(), other_realm.as_bytes());
        assert_ne!(base.as_bytes(), other_file.as_bytes());
    }

    #[test]
    fn ik_hk_are_distinct_from_dek() {
        let mk = derive_mk(&fixed_kek(), &[0; 16], 0).unwrap();
        let realm = RealmId([0x11; 16]);
        let dek = derive_dek(&mk, realm, &FILE_A).unwrap();
        let ik = derive_ik(&mk, realm, &FILE_A).unwrap();
        let hk = derive_hk(&mk).unwrap();
        assert_ne!(dek.as_bytes(), ik.as_bytes());
        assert_ne!(dek.as_bytes(), hk.as_bytes());
        assert_ne!(ik.as_bytes(), hk.as_bytes());
    }

    /// The realm/file boundary must not be forgeable by shifting bytes across
    /// it. Fixed-width fields plus constant literals make that structural, and
    /// this pins it: swapping the two 16-byte fields is a different key.
    #[test]
    fn realm_and_file_fields_are_not_interchangeable() {
        let mk = derive_mk(&fixed_kek(), &[0; 16], 0).unwrap();
        let a = derive_dek(&mk, RealmId(FILE_A), &FILE_B).unwrap();
        let b = derive_dek(&mk, RealmId(FILE_B), &FILE_A).unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }
}
