//! Format A — encrypted data page envelope (24-byte header + body + 16-byte
//! AEAD tag). Used for every B+ tree, counter, catalog, and segment data
//! page.

use crate::Result;
use crate::crypto::{Aad, Cipher, CipherId, Nonce};
use crate::errors::PagedbError;

use super::page_kind::PageKind;

pub const HEADER_LEN: usize = 24;
pub const TAG_LEN: usize = 16;
pub const ENVELOPE_OVERHEAD: usize = HEADER_LEN + TAG_LEN;

const OFF_CIPHER_ID: usize = 0;
const OFF_PAGE_KIND: usize = 1;
const OFF_FLAGS: usize = 2;
const OFF_MK_EPOCH: usize = 4;
const OFF_NONCE: usize = 12;
// body starts at HEADER_LEN; tag is at end-TAG_LEN.

/// Parsed header view (fields that the caller cares about after a successful
/// `open_data_page`).
#[derive(Debug, Clone)]
pub struct DataPageHeader {
    pub cipher_id: CipherId,
    pub page_kind: PageKind,
    pub flags: u16,
    pub mk_epoch: u64,
    pub nonce: Nonce,
}

/// Number of usable body bytes in a `page_size`-byte page.
#[must_use]
pub const fn body_capacity(page_size: usize) -> usize {
    page_size - ENVELOPE_OVERHEAD
}

/// Immutable view of the body bytes within a sealed page buffer.
#[must_use]
pub fn body(page: &[u8]) -> &[u8] {
    &page[HEADER_LEN..page.len() - TAG_LEN]
}

/// Mutable view of the body bytes within a page buffer. Caller writes
/// plaintext here before calling `seal_data_page`.
pub fn body_mut(page: &mut [u8]) -> &mut [u8] {
    let end = page.len() - TAG_LEN;
    &mut page[HEADER_LEN..end]
}

/// Seal a data page in place. Caller has already written the plaintext into
/// `body_mut(page_buf)`. After this returns, the page is on-wire form:
/// header bytes are populated, body is replaced by ciphertext (for AEAD
/// modes) or left as plaintext (for plaintext+MAC mode), and the tag is
/// written into the trailing 16 bytes.
///
/// `aad` must already encode the same `cipher_id`, `page_kind`, `mk_epoch`,
/// and other identity fields the header carries — pagedb relies on AAD as
/// the cryptographic binding between the header and the body.
pub fn seal_data_page(
    page_buf: &mut [u8],
    page_kind: PageKind,
    flags: u16,
    mk_epoch: u64,
    nonce: &Nonce,
    aad: &Aad,
    cipher: &Cipher,
) -> Result<()> {
    if page_buf.len() < ENVELOPE_OVERHEAD + 1 {
        return Err(PagedbError::PayloadTooLarge);
    }
    // Encrypt the body in place first, while the buffer is still purely
    // plaintext, so the tag is computed over the actual on-wire bytes.
    let body_end = page_buf.len() - TAG_LEN;
    let tag = {
        let body = &mut page_buf[HEADER_LEN..body_end];
        cipher.encrypt(nonce, aad, body)?
    };
    page_buf[body_end..body_end + TAG_LEN].copy_from_slice(&tag);
    // Write header bytes.
    page_buf[OFF_CIPHER_ID] = cipher.id().as_byte();
    page_buf[OFF_PAGE_KIND] = page_kind.as_byte();
    page_buf[OFF_FLAGS..OFF_FLAGS + 2].copy_from_slice(&flags.to_le_bytes());
    page_buf[OFF_MK_EPOCH..OFF_MK_EPOCH + 8].copy_from_slice(&mk_epoch.to_le_bytes());
    page_buf[OFF_NONCE..OFF_NONCE + 12].copy_from_slice(nonce.as_bytes());
    Ok(())
}

/// Extract the `cipher_id` and `mk_epoch` fields from the on-disk page header
/// bytes without performing decryption. These values drive cipher and DEK
/// selection on the read path: AAD is constructed from on-disk header bytes,
/// not from any pager-level `active_epoch` or configured cipher. This makes
/// mixed-epoch and mixed-cipher page coexistence work correctly without
/// requiring any global invariant.
pub fn extract_page_header_ids(page_buf: &[u8]) -> Result<(CipherId, u64)> {
    if page_buf.len() < ENVELOPE_OVERHEAD + 1 {
        return Err(PagedbError::PayloadTooLarge);
    }
    let cipher_id = CipherId::from_byte(page_buf[OFF_CIPHER_ID])?;
    let mut mk_buf = [0u8; 8];
    mk_buf.copy_from_slice(&page_buf[OFF_MK_EPOCH..OFF_MK_EPOCH + 8]);
    let mk_epoch = u64::from_le_bytes(mk_buf);
    Ok((cipher_id, mk_epoch))
}

/// Open a data page in place. On success, returns the parsed header and the
/// body slot of `page_buf` holds the decrypted plaintext. On failure
/// (`ChecksumFailure`), the body slot is in an unspecified state and the
/// caller must discard the page.
///
/// `expected_aad` must be constructed from the same identity fields the
/// caller expects this page to carry. AAD mismatch surfaces as
/// `ChecksumFailure` (an attacker-meaningful misroute can never produce a
/// usable plaintext).
pub fn open_data_page(
    page_buf: &mut [u8],
    expected_aad: &Aad,
    cipher: &Cipher,
) -> Result<DataPageHeader> {
    if page_buf.len() < ENVELOPE_OVERHEAD + 1 {
        return Err(PagedbError::PayloadTooLarge);
    }
    let cipher_id = CipherId::from_byte(page_buf[OFF_CIPHER_ID])?;
    let page_kind = PageKind::from_byte(page_buf[OFF_PAGE_KIND])?;
    let mut flags_buf = [0u8; 2];
    flags_buf.copy_from_slice(&page_buf[OFF_FLAGS..OFF_FLAGS + 2]);
    let flags = u16::from_le_bytes(flags_buf);
    let mut mk_buf = [0u8; 8];
    mk_buf.copy_from_slice(&page_buf[OFF_MK_EPOCH..OFF_MK_EPOCH + 8]);
    let mk_epoch = u64::from_le_bytes(mk_buf);
    let mut nonce_buf = [0u8; 12];
    nonce_buf.copy_from_slice(&page_buf[OFF_NONCE..OFF_NONCE + 12]);
    let mut file_id6 = [0u8; 6];
    file_id6.copy_from_slice(&nonce_buf[..6]);
    let mut counter_buf = [0u8; 8];
    counter_buf[..6].copy_from_slice(&nonce_buf[6..]);
    let counter = u64::from_le_bytes(counter_buf);
    let nonce = Nonce::from_parts(&file_id6, counter);
    // Defense in depth: cipher.id() must match the byte in the header.
    if cipher.id() != cipher_id {
        return Err(PagedbError::ChecksumFailure);
    }
    // Verify that the header's page_kind byte matches the page_kind encoded
    // in the caller-supplied AAD (AAD layout: cipher_id[0], page_kind[1]).
    // A tampered header byte that differs from the AAD is detectable here
    // before attempting decryption.
    if page_buf[OFF_PAGE_KIND] != expected_aad.0[1] {
        return Err(PagedbError::ChecksumFailure);
    }
    let body_end = page_buf.len() - TAG_LEN;
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&page_buf[body_end..body_end + TAG_LEN]);
    let body = &mut page_buf[HEADER_LEN..body_end];
    cipher.decrypt(&nonce, expected_aad, body, &tag)?;
    Ok(DataPageHeader {
        cipher_id,
        page_kind,
        flags,
        mk_epoch,
        nonce,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::RealmId;
    use crate::crypto::aad::{AadFields, MAIN_DB_SEGMENT_ID};
    use crate::crypto::kdf::{derive_dek, derive_ik, derive_mk};

    const PAGE: usize = 4096;

    fn build_aead(
        realm: RealmId,
        page_id: u64,
        mk: &crate::crypto::MasterKey,
        kind: PageKind,
    ) -> (Cipher, Aad, Nonce) {
        let dek = derive_dek(mk, realm).unwrap();
        let cipher = Cipher::new_aes_gcm(&dek);
        let aad = Aad::from_fields(AadFields {
            cipher_id: cipher.id().as_byte(),
            page_kind: kind.as_byte(),
            mk_epoch: 0,
            page_id,
            realm_id: realm,
            segment_id: MAIN_DB_SEGMENT_ID,
        });
        let nonce = Nonce::from_parts(&[0xAB; 6], 7);
        (cipher, aad, nonce)
    }

    #[test]
    fn aead_round_trip() {
        let mk = derive_mk(&[1u8; 32], &[0u8; 16], 0).unwrap();
        let (cipher, aad, nonce) = build_aead(RealmId([3; 16]), 42, &mk, PageKind::BTreeLeaf);
        let mut buf = vec![0u8; PAGE];
        body_mut(&mut buf)[..5].copy_from_slice(b"hello");
        seal_data_page(&mut buf, PageKind::BTreeLeaf, 0, 0, &nonce, &aad, &cipher).unwrap();
        // Plaintext "hello" should NOT be visible at the body offset after seal under AEAD.
        assert_ne!(&buf[HEADER_LEN..HEADER_LEN + 5], b"hello");
        let header = open_data_page(&mut buf, &aad, &cipher).unwrap();
        assert_eq!(header.page_kind, PageKind::BTreeLeaf);
        assert_eq!(&body(&buf)[..5], b"hello");
    }

    #[test]
    fn plaintext_mac_round_trip_leaves_body_clear() {
        let mk = derive_mk(&[1u8; 32], &[0u8; 16], 0).unwrap();
        let ik = derive_ik(&mk).unwrap();
        let cipher = Cipher::new_plaintext_mac(ik);
        let aad = Aad::from_fields(AadFields {
            cipher_id: cipher.id().as_byte(),
            page_kind: PageKind::BTreeLeaf.as_byte(),
            mk_epoch: 0,
            page_id: 1,
            realm_id: RealmId([0; 16]),
            segment_id: MAIN_DB_SEGMENT_ID,
        });
        let nonce = Nonce::from_parts(&[0xCD; 6], 1);
        let mut buf = vec![0u8; PAGE];
        body_mut(&mut buf)[..5].copy_from_slice(b"plain");
        seal_data_page(&mut buf, PageKind::BTreeLeaf, 0, 0, &nonce, &aad, &cipher).unwrap();
        // Plaintext+MAC mode leaves the body untouched.
        assert_eq!(&buf[HEADER_LEN..HEADER_LEN + 5], b"plain");
        let _ = open_data_page(&mut buf, &aad, &cipher).unwrap();
        assert_eq!(&body(&buf)[..5], b"plain");
    }

    #[test]
    fn tag_tamper_rejected() {
        let mk = derive_mk(&[1u8; 32], &[0u8; 16], 0).unwrap();
        let (cipher, aad, nonce) = build_aead(RealmId([3; 16]), 42, &mk, PageKind::BTreeLeaf);
        let mut buf = vec![0u8; PAGE];
        body_mut(&mut buf)[..5].copy_from_slice(b"hello");
        seal_data_page(&mut buf, PageKind::BTreeLeaf, 0, 0, &nonce, &aad, &cipher).unwrap();
        let last = buf.len() - 1;
        buf[last] ^= 1;
        let err = open_data_page(&mut buf, &aad, &cipher).unwrap_err();
        assert!(matches!(err, PagedbError::ChecksumFailure));
    }

    #[test]
    fn wrong_aad_rejected() {
        let mk = derive_mk(&[1u8; 32], &[0u8; 16], 0).unwrap();
        let (cipher, aad, nonce) = build_aead(RealmId([3; 16]), 42, &mk, PageKind::BTreeLeaf);
        let mut buf = vec![0u8; PAGE];
        body_mut(&mut buf)[..5].copy_from_slice(b"hello");
        seal_data_page(&mut buf, PageKind::BTreeLeaf, 0, 0, &nonce, &aad, &cipher).unwrap();
        let bad_aad = Aad::from_fields(AadFields {
            cipher_id: cipher.id().as_byte(),
            page_kind: PageKind::BTreeLeaf.as_byte(),
            mk_epoch: 0,
            page_id: 99, // wrong page_id
            realm_id: RealmId([3; 16]),
            segment_id: MAIN_DB_SEGMENT_ID,
        });
        let err = open_data_page(&mut buf, &bad_aad, &cipher).unwrap_err();
        assert!(matches!(err, PagedbError::ChecksumFailure));
    }

    #[test]
    fn page_kind_byte_tamper_rejected() {
        let mk = derive_mk(&[1u8; 32], &[0u8; 16], 0).unwrap();
        let (cipher, aad, nonce) = build_aead(RealmId([3; 16]), 42, &mk, PageKind::BTreeLeaf);
        let mut buf = vec![0u8; PAGE];
        body_mut(&mut buf)[..5].copy_from_slice(b"hello");
        seal_data_page(&mut buf, PageKind::BTreeLeaf, 0, 0, &nonce, &aad, &cipher).unwrap();
        // Flip page_kind byte from 0x02 (BTreeLeaf) to 0x01 (BTreeInternal).
        buf[OFF_PAGE_KIND] = PageKind::BTreeInternal.as_byte();
        let err = open_data_page(&mut buf, &aad, &cipher).unwrap_err();
        // AAD on encrypt encoded page_kind=0x02; decode with header byte
        // 0x01 produces a mismatch via cipher binding (AAD includes
        // page_kind), so ChecksumFailure.
        assert!(matches!(err, PagedbError::ChecksumFailure));
    }

    #[test]
    fn unknown_page_kind_byte_rejected_at_parse() {
        let mut buf = vec![0u8; PAGE];
        buf[OFF_CIPHER_ID] = CipherId::Aes256Gcm.as_byte();
        buf[OFF_PAGE_KIND] = 0x77; // invalid
        let mk = derive_mk(&[1u8; 32], &[0u8; 16], 0).unwrap();
        let dek = derive_dek(&mk, RealmId([0; 16])).unwrap();
        let cipher = Cipher::new_aes_gcm(&dek);
        let aad = Aad::from_fields(AadFields {
            cipher_id: cipher.id().as_byte(),
            page_kind: 0x77,
            mk_epoch: 0,
            page_id: 0,
            realm_id: RealmId([0; 16]),
            segment_id: MAIN_DB_SEGMENT_ID,
        });
        let err = open_data_page(&mut buf, &aad, &cipher).unwrap_err();
        assert!(matches!(err, PagedbError::IllegalPageKind));
    }
}
