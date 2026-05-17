//! Cipher dispatch for the three on-wire modes.
//!
//! On the wire, the body field of a Format-A page envelope is followed by a
//! 16-byte authentication tag. AEAD modes (AES-256-GCM, ChaCha20-Poly1305) put
//! ciphertext in the body; plaintext+MAC mode puts plaintext in the body with
//! an HMAC-SHA-256-trunc-16 tag computed over `AAD ‖ body`.
//!
//! # Cipher rotation
//!
//! Writes always use the cipher configured at `Db::open` time. Reads use the
//! `cipher_id` byte recorded in each page's on-disk header (offset 0) to
//! dispatch to the correct cipher regardless of the currently configured one.
//! This means a database can be opened with a new cipher after an online
//! rekey: old pages continue to decrypt under their original cipher while new
//! pages are written with the new one. Mixed-cipher coexistence requires no
//! explicit migration pass; pages are silently re-encrypted with the new
//! cipher the first time they are re-written by a copy-on-write operation.

use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::ChaCha20Poly1305;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::Result;
use crate::errors::PagedbError;

use super::aad::Aad;
use super::keys::DerivedKey;
use super::nonce::Nonce;

/// On-wire `cipher_id` byte values. The numeric values are stable and part of
/// the persisted format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CipherId {
    PlaintextMac = 0,
    Aes256Gcm = 1,
    ChaCha20Poly1305 = 2,
}

impl CipherId {
    /// Parse a persisted byte. Reserved values (3..=255) yield `Unsupported`.
    pub fn from_byte(b: u8) -> Result<Self> {
        match b {
            0 => Ok(Self::PlaintextMac),
            1 => Ok(Self::Aes256Gcm),
            2 => Ok(Self::ChaCha20Poly1305),
            _ => Err(PagedbError::Unsupported),
        }
    }

    #[must_use]
    pub fn as_byte(self) -> u8 {
        self as u8
    }
}

const TAG_LEN: usize = 16;
type HmacSha256 = Hmac<Sha256>;

/// Cipher façade. One value of this enum carries the keyed cipher state
/// appropriate to its `CipherId`. Caller selects via `new_*` constructors.
pub enum Cipher {
    PlaintextMac(DerivedKey),  // IK
    Aes256Gcm(Box<Aes256Gcm>), // DEK-keyed
    ChaCha20Poly1305(Box<ChaCha20Poly1305>),
}

impl Cipher {
    #[must_use]
    pub fn new_plaintext_mac(ik: DerivedKey) -> Self {
        Self::PlaintextMac(ik)
    }

    #[must_use]
    pub fn new_aes_gcm(dek: &DerivedKey) -> Self {
        Self::Aes256Gcm(Box::new(Aes256Gcm::new(dek.as_bytes().into())))
    }

    #[must_use]
    pub fn new_chacha20(dek: &DerivedKey) -> Self {
        Self::ChaCha20Poly1305(Box::new(ChaCha20Poly1305::new(dek.as_bytes().into())))
    }

    #[must_use]
    pub fn id(&self) -> CipherId {
        match self {
            Self::PlaintextMac(_) => CipherId::PlaintextMac,
            Self::Aes256Gcm(_) => CipherId::Aes256Gcm,
            Self::ChaCha20Poly1305(_) => CipherId::ChaCha20Poly1305,
        }
    }

    /// Encrypt `body` in place. After the call, the supplied `body` is the
    /// (possibly modified) ciphertext; the returned 16-byte tag is the
    /// authentication tag the caller writes immediately after the body.
    pub fn encrypt(&self, nonce: &Nonce, aad: &Aad, body: &mut [u8]) -> Result<[u8; TAG_LEN]> {
        match self {
            Self::PlaintextMac(ik) => {
                // Body is left as plaintext. Tag = HMAC-SHA-256-trunc-16(IK, AAD ‖ body).
                let mut mac = <HmacSha256 as Mac>::new_from_slice(ik.as_bytes())
                    .map_err(|_| PagedbError::Io(std::io::Error::other("hmac key length")))?;
                mac.update(aad.as_bytes());
                mac.update(body);
                let full = mac.finalize().into_bytes();
                let mut tag = [0u8; TAG_LEN];
                tag.copy_from_slice(&full[..TAG_LEN]);
                Ok(tag)
            }
            Self::Aes256Gcm(c) => {
                let n: &aes_gcm::Nonce<aes_gcm::aes::cipher::consts::U12> = nonce.as_aead_nonce();
                let tag = c
                    .encrypt_in_place_detached(n, aad.as_bytes(), body)
                    .map_err(|_| PagedbError::ChecksumFailure)?;
                let mut out = [0u8; TAG_LEN];
                out.copy_from_slice(tag.as_slice());
                Ok(out)
            }
            Self::ChaCha20Poly1305(c) => {
                let n: &chacha20poly1305::Nonce = nonce.as_chacha_nonce();
                let tag = c
                    .encrypt_in_place_detached(n, aad.as_bytes(), body)
                    .map_err(|_| PagedbError::ChecksumFailure)?;
                let mut out = [0u8; TAG_LEN];
                out.copy_from_slice(tag.as_slice());
                Ok(out)
            }
        }
    }

    /// Decrypt `body` in place. Verifies `tag`; on failure returns
    /// `PagedbError::ChecksumFailure` and leaves `body` in an unspecified
    /// state (caller must discard).
    pub fn decrypt(
        &self,
        nonce: &Nonce,
        aad: &Aad,
        body: &mut [u8],
        tag: &[u8; TAG_LEN],
    ) -> Result<()> {
        match self {
            Self::PlaintextMac(ik) => {
                let mut mac = <HmacSha256 as Mac>::new_from_slice(ik.as_bytes())
                    .map_err(|_| PagedbError::Io(std::io::Error::other("hmac key length")))?;
                mac.update(aad.as_bytes());
                mac.update(body);
                let full = mac.finalize().into_bytes();
                // Constant-time compare on the first 16 bytes.
                if !constant_time_eq(&full[..TAG_LEN], tag) {
                    return Err(PagedbError::ChecksumFailure);
                }
                Ok(())
            }
            Self::Aes256Gcm(c) => {
                let n: &aes_gcm::Nonce<aes_gcm::aes::cipher::consts::U12> = nonce.as_aead_nonce();
                let tag_obj = aes_gcm::Tag::from_slice(tag);
                c.decrypt_in_place_detached(n, aad.as_bytes(), body, tag_obj)
                    .map_err(|_| PagedbError::ChecksumFailure)
            }
            Self::ChaCha20Poly1305(c) => {
                let n: &chacha20poly1305::Nonce = nonce.as_chacha_nonce();
                let tag_obj = chacha20poly1305::Tag::from_slice(tag);
                c.decrypt_in_place_detached(n, aad.as_bytes(), body, tag_obj)
                    .map_err(|_| PagedbError::ChecksumFailure)
            }
        }
    }
}

#[inline]
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc: u8 = 0;
    for (x, y) in a.iter().zip(b) {
        acc |= x ^ y;
    }
    acc == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::RealmId;
    use crate::crypto::aad::{Aad, AadFields};
    use crate::crypto::kdf::{derive_dek, derive_ik, derive_mk};
    use crate::crypto::nonce::Nonce;

    fn fixture() -> (Cipher, Cipher, Cipher, Aad, Nonce) {
        let mk = derive_mk(&[7u8; 32], &[0xAB; 16], 0).unwrap();
        let dek = derive_dek(&mk, RealmId([1; 16])).unwrap();
        let ik = derive_ik(&mk).unwrap();
        let aes = Cipher::new_aes_gcm(&dek);
        let cc = Cipher::new_chacha20(&dek);
        let pt = Cipher::new_plaintext_mac(ik);
        let aad = Aad::from_fields(AadFields {
            cipher_id: 1,
            page_kind: 2,
            mk_epoch: 0,
            page_id: 42,
            realm_id: RealmId([1; 16]),
            segment_id: [0; 16],
        });
        let nonce = Nonce::from_parts(&[0xDE; 6], 1);
        (aes, cc, pt, aad, nonce)
    }

    #[test]
    fn aes_gcm_round_trip() {
        let (aes, _, _, aad, nonce) = fixture();
        let pt = b"hello world".to_vec();
        let mut buf = pt.clone();
        let tag = aes.encrypt(&nonce, &aad, &mut buf).unwrap();
        // Ciphertext should differ from plaintext.
        assert_ne!(buf, pt);
        aes.decrypt(&nonce, &aad, &mut buf, &tag).unwrap();
        assert_eq!(buf, pt);
    }

    #[test]
    fn chacha_round_trip() {
        let (_, cc, _, aad, nonce) = fixture();
        let pt = b"hello world".to_vec();
        let mut buf = pt.clone();
        let tag = cc.encrypt(&nonce, &aad, &mut buf).unwrap();
        assert_ne!(buf, pt);
        cc.decrypt(&nonce, &aad, &mut buf, &tag).unwrap();
        assert_eq!(buf, pt);
    }

    #[test]
    fn plaintext_mac_round_trip_body_stays_clear() {
        let (_, _, pt_cipher, aad, nonce) = fixture();
        let pt = b"hello world".to_vec();
        let mut buf = pt.clone();
        let tag = pt_cipher.encrypt(&nonce, &aad, &mut buf).unwrap();
        // Plaintext mode does not modify the body.
        assert_eq!(buf, pt);
        pt_cipher.decrypt(&nonce, &aad, &mut buf, &tag).unwrap();
        assert_eq!(buf, pt);
    }

    #[test]
    fn aes_tag_tamper_fails() {
        let (aes, _, _, aad, nonce) = fixture();
        let mut buf = b"hello".to_vec();
        let mut tag = aes.encrypt(&nonce, &aad, &mut buf).unwrap();
        tag[0] ^= 1;
        let err = aes.decrypt(&nonce, &aad, &mut buf, &tag).unwrap_err();
        assert!(matches!(err, PagedbError::ChecksumFailure));
    }

    #[test]
    fn chacha_tag_tamper_fails() {
        let (_, cc, _, aad, nonce) = fixture();
        let mut buf = b"hello".to_vec();
        let mut tag = cc.encrypt(&nonce, &aad, &mut buf).unwrap();
        tag[0] ^= 1;
        let err = cc.decrypt(&nonce, &aad, &mut buf, &tag).unwrap_err();
        assert!(matches!(err, PagedbError::ChecksumFailure));
    }

    #[test]
    fn plaintext_mac_tag_tamper_fails() {
        let (_, _, p, aad, nonce) = fixture();
        let mut buf = b"hello".to_vec();
        let mut tag = p.encrypt(&nonce, &aad, &mut buf).unwrap();
        tag[0] ^= 1;
        let err = p.decrypt(&nonce, &aad, &mut buf, &tag).unwrap_err();
        assert!(matches!(err, PagedbError::ChecksumFailure));
    }

    #[test]
    fn plaintext_mac_body_tamper_fails() {
        let (_, _, p, aad, nonce) = fixture();
        let mut buf = b"hello".to_vec();
        let tag = p.encrypt(&nonce, &aad, &mut buf).unwrap();
        buf[0] ^= 1;
        let err = p.decrypt(&nonce, &aad, &mut buf, &tag).unwrap_err();
        assert!(matches!(err, PagedbError::ChecksumFailure));
    }

    #[test]
    fn aad_tamper_fails_all_modes() {
        let (aes, cc, p, aad, nonce) = fixture();
        let bad_aad = Aad::from_fields(AadFields {
            cipher_id: 1,
            page_kind: 2,
            mk_epoch: 0,
            page_id: 43, // <- different
            realm_id: RealmId([1; 16]),
            segment_id: [0; 16],
        });
        for cipher in [&aes, &cc, &p] {
            let mut buf = b"hello".to_vec();
            let tag = cipher.encrypt(&nonce, &aad, &mut buf).unwrap();
            let err = cipher
                .decrypt(&nonce, &bad_aad, &mut buf, &tag)
                .unwrap_err();
            assert!(matches!(err, PagedbError::ChecksumFailure));
        }
    }

    #[test]
    fn cipher_id_round_trip() {
        for id in [
            CipherId::PlaintextMac,
            CipherId::Aes256Gcm,
            CipherId::ChaCha20Poly1305,
        ] {
            assert_eq!(CipherId::from_byte(id.as_byte()).unwrap(), id);
        }
        assert!(matches!(
            CipherId::from_byte(3),
            Err(PagedbError::Unsupported)
        ));
        assert!(matches!(
            CipherId::from_byte(255),
            Err(PagedbError::Unsupported)
        ));
    }
}
