//! Format C — segment footer page: cleartext-with-HK-MAC region followed by
//! AEAD-encrypted manifest.

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::crypto::aad::{Aad, AadFields, PAGE_KIND_SEGMENT_FOOTER};
use crate::crypto::keys::DerivedKey;
use crate::crypto::{Cipher, Nonce};
use crate::errors::{CorruptionDetail, PagedbError};
use crate::{RealmId, Result};

pub const MAGIC: [u8; 8] = *b"PAGESEAL";

/// Byte offset where the HK-MAC begins for **v1** footers. Pre-MAC cleartext
/// fields:
///
/// ```text
/// magic[8] + format_version[2] + cipher_id[1] + segment_id[16] +
/// parent_file_id[16] + realm_id[16] + mk_epoch[8] + page_count[8] +
/// total_bytes[8] + final_counter[8] + manifest_offset[4] + manifest_len[4]
/// = 99 bytes
/// ```
pub const FOOTER_FIELDS_END_V1: usize = 99;

/// Byte offset where the HK-MAC begins for **v2** footers. Extends v1 by
/// `index_start_page[8] + index_page_count[4]` = 12 additional bytes.
pub const FOOTER_FIELDS_END_V2: usize = FOOTER_FIELDS_END_V1 + 12;

/// Legacy alias kept for internal use.
pub const FOOTER_FIELDS_END: usize = FOOTER_FIELDS_END_V1;

/// 16-byte HMAC-SHA256 truncated tag over bytes `[0 .. FOOTER_FIELDS_END]`.
pub const FOOTER_HEADER_MAC_LEN: usize = 16;

/// Byte offset where the cleartext region ends for **v1** footers.
pub const FOOTER_CLEARTEXT_END_V1: usize = FOOTER_FIELDS_END_V1 + FOOTER_HEADER_MAC_LEN;

/// Byte offset where the cleartext region ends for **v2** footers.
pub const FOOTER_CLEARTEXT_END_V2: usize = FOOTER_FIELDS_END_V2 + FOOTER_HEADER_MAC_LEN;

/// Legacy alias kept for internal use (v1).
pub const FOOTER_CLEARTEXT_END: usize = FOOTER_CLEARTEXT_END_V1;

/// AEAD tag appended after the manifest ciphertext.
pub const MANIFEST_TAG_LEN: usize = 16;

type HmacSha256 = Hmac<Sha256>;

/// Cleartext fields the segment footer carries. The footer also embeds an
/// AEAD-encrypted manifest payload; that is supplied separately to encode /
/// returned separately by decode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentFooterFields {
    pub format_version: u16,
    pub cipher_id: u8,
    pub segment_id: [u8; 16],
    pub parent_file_id: [u8; 16],
    pub realm_id: RealmId,
    pub mk_epoch: u64,
    pub page_count: u64,
    pub total_bytes: u64,
    pub final_counter: u64,
    /// v2 only: first `page_id` of the extent index block (0 = no index / v1).
    pub index_start_page: u64,
    /// v2 only: number of pages in the extent index block (0 = no index / v1).
    pub index_page_count: u32,
}

fn mac_hk(hk: &DerivedKey, bytes: &[u8]) -> Result<[u8; FOOTER_HEADER_MAC_LEN]> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(hk.as_bytes())
        .map_err(|_| PagedbError::Io(std::io::Error::other("hk key length")))?;
    mac.update(bytes);
    let full = mac.finalize().into_bytes();
    let mut out = [0u8; FOOTER_HEADER_MAC_LEN];
    out.copy_from_slice(&full[..FOOTER_HEADER_MAC_LEN]);
    Ok(out)
}

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

fn footer_aad(fields: &SegmentFooterFields) -> Aad {
    // page_id = 0 sentinel; segment-footer page is not part of the paged
    // data record stream. AAD shape stays uniform with Format A.
    Aad::from_fields(AadFields {
        cipher_id: fields.cipher_id,
        page_kind: PAGE_KIND_SEGMENT_FOOTER,
        mk_epoch: fields.mk_epoch,
        page_id: 0,
        realm_id: fields.realm_id,
        segment_id: fields.segment_id,
    })
}

/// Maximum manifest length for the given page size and footer version.
/// The encrypted region is exactly `manifest_len` bytes of ciphertext followed
/// by a 16-byte AEAD tag; all bytes after the tag through `page_size` are zero.
#[must_use]
pub const fn max_manifest_len(page_size: usize) -> usize {
    // v1 layout (smaller cleartext header → more room for manifest).
    page_size - FOOTER_CLEARTEXT_END_V1 - MANIFEST_TAG_LEN
}

/// Maximum manifest length when encoding a v2 footer (larger cleartext header).
#[must_use]
pub const fn max_manifest_len_v2(page_size: usize) -> usize {
    page_size - FOOTER_CLEARTEXT_END_V2 - MANIFEST_TAG_LEN
}

/// Encode a segment footer into a `page_size`-byte buffer.
///
/// `cipher` must be the realm DEK-keyed cipher used for the segment. The
/// AEAD nonce is `final_counter + 1` (reserved by the seal protocol).
///
/// When `fields.format_version == 2` the cleartext region is 12 bytes larger
/// (holding `index_start_page` and `index_page_count`) and the manifest size
/// limit is correspondingly smaller.
#[allow(clippy::too_many_lines)]
pub fn encode_segment_footer(
    fields: &SegmentFooterFields,
    manifest: &[u8],
    hk: &DerivedKey,
    cipher: &Cipher,
    page_size: usize,
) -> Result<Vec<u8>> {
    let (fields_end, cleartext_end, max_mlen) = if fields.format_version == 2 {
        (
            FOOTER_FIELDS_END_V2,
            FOOTER_CLEARTEXT_END_V2,
            max_manifest_len_v2(page_size),
        )
    } else {
        (
            FOOTER_FIELDS_END_V1,
            FOOTER_CLEARTEXT_END_V1,
            max_manifest_len(page_size),
        )
    };

    if page_size < cleartext_end + MANIFEST_TAG_LEN {
        return Err(PagedbError::Unsupported);
    }
    if manifest.len() > max_mlen {
        return Err(PagedbError::ManifestTooLarge);
    }
    if cipher.id().as_byte() != fields.cipher_id {
        return Err(PagedbError::Unsupported);
    }
    if fields.format_version != 1 && fields.format_version != 2 {
        return Err(PagedbError::Unsupported);
    }

    let manifest_offset = u32::try_from(cleartext_end).map_err(|_| PagedbError::Unsupported)?;
    let manifest_len = u32::try_from(manifest.len()).map_err(|_| PagedbError::ManifestTooLarge)?;
    let mut buf = vec![0u8; page_size];

    // Cleartext fields common to v1 and v2 (99 bytes).
    let mut o = 0usize;
    buf[o..o + 8].copy_from_slice(&MAGIC);
    o += 8;
    buf[o..o + 2].copy_from_slice(&fields.format_version.to_le_bytes());
    o += 2;
    buf[o] = fields.cipher_id;
    o += 1;
    buf[o..o + 16].copy_from_slice(&fields.segment_id);
    o += 16;
    buf[o..o + 16].copy_from_slice(&fields.parent_file_id);
    o += 16;
    buf[o..o + 16].copy_from_slice(&fields.realm_id.0);
    o += 16;
    buf[o..o + 8].copy_from_slice(&fields.mk_epoch.to_le_bytes());
    o += 8;
    buf[o..o + 8].copy_from_slice(&fields.page_count.to_le_bytes());
    o += 8;
    buf[o..o + 8].copy_from_slice(&fields.total_bytes.to_le_bytes());
    o += 8;
    buf[o..o + 8].copy_from_slice(&fields.final_counter.to_le_bytes());
    o += 8;
    buf[o..o + 4].copy_from_slice(&manifest_offset.to_le_bytes());
    o += 4;
    buf[o..o + 4].copy_from_slice(&manifest_len.to_le_bytes());
    o += 4;
    debug_assert_eq!(o, FOOTER_FIELDS_END_V1);

    // v2 extension: index_start_page[8] + index_page_count[4].
    if fields.format_version == 2 {
        buf[o..o + 8].copy_from_slice(&fields.index_start_page.to_le_bytes());
        o += 8;
        buf[o..o + 4].copy_from_slice(&fields.index_page_count.to_le_bytes());
        o += 4;
        debug_assert_eq!(o, FOOTER_FIELDS_END_V2);
    }

    debug_assert_eq!(o, fields_end);

    // HK-MAC over bytes [0 .. fields_end].
    let mac = mac_hk(hk, &buf[..o])?;
    buf[o..o + FOOTER_HEADER_MAC_LEN].copy_from_slice(&mac);
    o += FOOTER_HEADER_MAC_LEN;
    debug_assert_eq!(o, cleartext_end);

    // Encrypt manifest.
    let aad = footer_aad(fields);
    let nonce_counter = fields
        .final_counter
        .checked_add(1)
        .ok_or(PagedbError::NonceCounterExhausted)?;
    let nonce = Nonce::from_parts(
        &{
            let mut f = [0u8; 6];
            f.copy_from_slice(&fields.segment_id[..6]);
            f
        },
        nonce_counter,
    );

    let mlen = manifest.len();
    buf[cleartext_end..cleartext_end + mlen].copy_from_slice(manifest);
    let tag = cipher.encrypt(&nonce, &aad, &mut buf[cleartext_end..cleartext_end + mlen])?;
    buf[cleartext_end + mlen..cleartext_end + mlen + MANIFEST_TAG_LEN].copy_from_slice(&tag);

    Ok(buf)
}

/// Decode and verify a segment footer. Returns the cleartext fields and the
/// decrypted manifest bytes.
#[allow(clippy::too_many_lines)]
pub fn decode_segment_footer(
    bytes: &[u8],
    hk: &DerivedKey,
    cipher: &Cipher,
    page_size: usize,
) -> Result<(SegmentFooterFields, Vec<u8>)> {
    if bytes.len() != page_size || page_size < FOOTER_CLEARTEXT_END_V1 + MANIFEST_TAG_LEN {
        return Err(PagedbError::Unsupported);
    }
    if bytes[..8] != MAGIC {
        return Err(PagedbError::corruption(
            CorruptionDetail::HeaderUnverifiable,
        ));
    }

    let mut o = 8usize;
    let format_version = u16_le(&bytes[o..o + 2]);
    o += 2;
    if format_version != 1 && format_version != 2 {
        return Err(PagedbError::Unsupported);
    }
    let cipher_id = bytes[o];
    o += 1;
    let segment_id = arr16(&bytes[o..o + 16]);
    o += 16;
    let parent_file_id = arr16(&bytes[o..o + 16]);
    o += 16;
    let realm_bytes = arr16(&bytes[o..o + 16]);
    o += 16;
    let mk_epoch = u64_le(&bytes[o..o + 8]);
    o += 8;
    let page_count = u64_le(&bytes[o..o + 8]);
    o += 8;
    let total_bytes = u64_le(&bytes[o..o + 8]);
    o += 8;
    let final_counter = u64_le(&bytes[o..o + 8]);
    o += 8;
    let stored_manifest_offset = u32_le(&bytes[o..o + 4]);
    o += 4;
    let stored_manifest_len = u32_le(&bytes[o..o + 4]) as usize;
    o += 4;
    debug_assert_eq!(o, FOOTER_FIELDS_END_V1);

    // v2 extension fields.
    let (index_start_page, index_page_count) = if format_version == 2 {
        if page_size < FOOTER_CLEARTEXT_END_V2 + MANIFEST_TAG_LEN {
            return Err(PagedbError::Unsupported);
        }
        let isp = u64_le(&bytes[o..o + 8]);
        o += 8;
        let ipc = u32_le(&bytes[o..o + 4]);
        o += 4;
        debug_assert_eq!(o, FOOTER_FIELDS_END_V2);
        (isp, ipc)
    } else {
        (0u64, 0u32)
    };

    let fields_end = o;
    let cleartext_end = fields_end + FOOTER_HEADER_MAC_LEN;

    // Verify HK-MAC over bytes [0 .. fields_end].
    let expected_mac = mac_hk(hk, &bytes[..fields_end])?;
    if !constant_time_eq(&expected_mac, &bytes[fields_end..cleartext_end]) {
        return Err(PagedbError::corruption(
            CorruptionDetail::HeaderUnverifiable,
        ));
    }

    // Validate manifest_offset: must equal `cleartext_end` exactly.
    #[allow(clippy::cast_possible_truncation)]
    let expected_offset = cleartext_end as u32;
    if stored_manifest_offset != expected_offset {
        return Err(PagedbError::corruption(
            CorruptionDetail::HeaderUnverifiable,
        ));
    }

    // Validate manifest_len against the correct max for this version.
    let max_mlen = if format_version == 2 {
        max_manifest_len_v2(page_size)
    } else {
        max_manifest_len(page_size)
    };
    if stored_manifest_len > max_mlen {
        return Err(PagedbError::corruption(
            CorruptionDetail::HeaderUnverifiable,
        ));
    }

    let fields = SegmentFooterFields {
        format_version,
        cipher_id,
        segment_id,
        parent_file_id,
        realm_id: RealmId(realm_bytes),
        mk_epoch,
        page_count,
        total_bytes,
        final_counter,
        index_start_page,
        index_page_count,
    };
    if cipher.id().as_byte() != cipher_id {
        return Err(PagedbError::corruption(
            CorruptionDetail::ManifestUnverifiable {
                realm_id: fields.realm_id,
                segment_id,
            },
        ));
    }

    let aad = footer_aad(&fields);
    let nonce_counter = final_counter
        .checked_add(1)
        .ok_or(PagedbError::NonceCounterExhausted)?;
    let mut file_id6 = [0u8; 6];
    file_id6.copy_from_slice(&segment_id[..6]);
    let nonce = Nonce::from_parts(&file_id6, nonce_counter);

    // Decrypt exactly stored_manifest_len bytes of ciphertext.
    let ct_start = cleartext_end;
    let ct_end = ct_start + stored_manifest_len;
    let tag_end = ct_end + MANIFEST_TAG_LEN;

    let mut manifest_buf = bytes[ct_start..ct_end].to_vec();
    let mut tag = [0u8; MANIFEST_TAG_LEN];
    tag.copy_from_slice(&bytes[ct_end..tag_end]);
    cipher
        .decrypt(&nonce, &aad, &mut manifest_buf, &tag)
        .map_err(|_| {
            PagedbError::corruption(CorruptionDetail::ManifestUnverifiable {
                realm_id: fields.realm_id,
                segment_id,
            })
        })?;

    // Zero-tail check: every byte from tag_end through page_size must be zero.
    if bytes[tag_end..page_size].iter().any(|&b| b != 0) {
        return Err(PagedbError::corruption(
            CorruptionDetail::HeaderUnverifiable,
        ));
    }

    Ok((fields, manifest_buf))
}

fn u16_le(b: &[u8]) -> u16 {
    let mut x = [0u8; 2];
    x.copy_from_slice(b);
    u16::from_le_bytes(x)
}
fn u32_le(b: &[u8]) -> u32 {
    let mut x = [0u8; 4];
    x.copy_from_slice(b);
    u32::from_le_bytes(x)
}
fn u64_le(b: &[u8]) -> u64 {
    let mut x = [0u8; 8];
    x.copy_from_slice(b);
    u64::from_le_bytes(x)
}
fn arr16(b: &[u8]) -> [u8; 16] {
    let mut x = [0u8; 16];
    x.copy_from_slice(b);
    x
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::crypto::kdf::{derive_dek, derive_hk, derive_mk};

    const PAGE: usize = 4096;

    fn keys() -> (DerivedKey, Cipher) {
        let mk = derive_mk(&[7u8; 32], &[0u8; 16], 0).unwrap();
        let hk = derive_hk(&mk).unwrap();
        let dek = derive_dek(&mk, RealmId([3; 16])).unwrap();
        let cipher = Cipher::new_aes_gcm(&dek);
        (hk, cipher)
    }

    fn sample() -> SegmentFooterFields {
        SegmentFooterFields {
            format_version: 1,
            cipher_id: 1,
            segment_id: [9; 16],
            parent_file_id: [1; 16],
            realm_id: RealmId([3; 16]),
            mk_epoch: 0,
            page_count: 10,
            total_bytes: 40_960,
            final_counter: 9,
            index_start_page: 0,
            index_page_count: 0,
        }
    }

    fn sample_v2() -> SegmentFooterFields {
        SegmentFooterFields {
            format_version: 2,
            cipher_id: 1,
            segment_id: [9; 16],
            parent_file_id: [1; 16],
            realm_id: RealmId([3; 16]),
            mk_epoch: 0,
            page_count: 10,
            total_bytes: 40_960,
            final_counter: 9,
            index_start_page: 5,
            index_page_count: 3,
        }
    }

    #[test]
    fn round_trip_with_manifest() {
        let (hk, cipher) = keys();
        let fields = sample();
        let manifest = b"engine-defined manifest".to_vec();
        let buf = encode_segment_footer(&fields, &manifest, &hk, &cipher, PAGE).unwrap();
        assert_eq!(buf.len(), PAGE);
        let (f2, m2) = decode_segment_footer(&buf, &hk, &cipher, PAGE).unwrap();
        assert_eq!(f2, fields);
        assert_eq!(m2, manifest);
    }

    #[test]
    fn round_trip_empty_manifest() {
        let (hk, cipher) = keys();
        let fields = sample();
        let buf = encode_segment_footer(&fields, &[], &hk, &cipher, PAGE).unwrap();
        let (f2, m2) = decode_segment_footer(&buf, &hk, &cipher, PAGE).unwrap();
        assert_eq!(f2, fields);
        assert!(m2.is_empty());
    }

    #[test]
    fn manifest_too_large_rejected() {
        let (hk, cipher) = keys();
        let fields = sample();
        let too_big = vec![0u8; max_manifest_len(PAGE) + 1];
        let err = encode_segment_footer(&fields, &too_big, &hk, &cipher, PAGE).unwrap_err();
        assert!(matches!(err, PagedbError::ManifestTooLarge));
    }

    #[test]
    fn footer_mac_tamper_rejected() {
        let (hk, cipher) = keys();
        let fields = sample();
        let mut buf = encode_segment_footer(&fields, b"manifest", &hk, &cipher, PAGE).unwrap();
        // Flip a byte inside the footer_header_mac region [FOOTER_FIELDS_END .. FOOTER_CLEARTEXT_END].
        buf[FOOTER_FIELDS_END + 3] ^= 1;
        let err = decode_segment_footer(&buf, &hk, &cipher, PAGE).unwrap_err();
        assert!(matches!(err, PagedbError::Corruption(_)));
    }

    #[test]
    fn manifest_aead_tamper_rejected() {
        let (hk, cipher) = keys();
        let fields = sample();
        let mut buf = encode_segment_footer(&fields, b"manifest", &hk, &cipher, PAGE).unwrap();
        // Flip a byte inside the manifest ciphertext at FOOTER_CLEARTEXT_END + 2.
        buf[FOOTER_CLEARTEXT_END + 2] ^= 1;
        let err = decode_segment_footer(&buf, &hk, &cipher, PAGE).unwrap_err();
        assert!(matches!(err, PagedbError::Corruption(_)));
    }

    #[test]
    fn cross_segment_id_in_aad_fails() {
        let (hk, cipher) = keys();
        let fields = sample();
        let buf = encode_segment_footer(&fields, b"manifest", &hk, &cipher, PAGE).unwrap();
        // Re-encode with a different segment_id — the AAD binding means the
        // manifest ciphertext bytes must differ.
        let mut other = fields.clone();
        other.segment_id = [10; 16];
        let buf2 = encode_segment_footer(&other, b"manifest", &hk, &cipher, PAGE).unwrap();
        assert_ne!(
            &buf[FOOTER_CLEARTEXT_END..FOOTER_CLEARTEXT_END + 8],
            &buf2[FOOTER_CLEARTEXT_END..FOOTER_CLEARTEXT_END + 8]
        );
    }

    /// Flip a byte in the zero-padding region after the AEAD tag; decoder must
    /// reject with Corruption(HeaderUnverifiable).
    #[test]
    fn zero_tail_after_manifest_rejected() {
        let (hk, cipher) = keys();
        let fields = sample();
        let manifest = b"short".to_vec();
        let mut buf = encode_segment_footer(&fields, &manifest, &hk, &cipher, PAGE).unwrap();
        // Locate the start of the zero-tail.
        let tail_start = FOOTER_CLEARTEXT_END + manifest.len() + MANIFEST_TAG_LEN;
        // Verify that this is actually in the zero region (not out of bounds).
        assert!(
            tail_start < PAGE,
            "zero-tail region must exist for this test"
        );
        buf[tail_start] ^= 1;
        let err = decode_segment_footer(&buf, &hk, &cipher, PAGE).unwrap_err();
        assert!(matches!(err, PagedbError::Corruption(_)));
    }

    /// `manifest_offset` lives at cleartext offset 91 (inside the MAC-covered
    /// region). Flipping one of its bytes must cause MAC failure.
    #[test]
    fn manifest_offset_field_tamper_rejected() {
        // Offset of manifest_offset:
        //   magic[8] + format_version[2] + cipher_id[1] + segment_id[16] +
        //   parent_file_id[16] + realm_id[16] + mk_epoch[8] + page_count[8] +
        //   total_bytes[8] + final_counter[8] = 91.
        const MANIFEST_OFFSET_FIELD: usize = 91;
        let (hk, cipher) = keys();
        let fields = sample();
        let mut buf = encode_segment_footer(&fields, b"manifest", &hk, &cipher, PAGE).unwrap();
        buf[MANIFEST_OFFSET_FIELD] ^= 1;
        let err = decode_segment_footer(&buf, &hk, &cipher, PAGE).unwrap_err();
        assert!(matches!(err, PagedbError::Corruption(_)));
    }

    #[test]
    fn v2_round_trip() {
        let (hk, cipher) = keys();
        let fields = sample_v2();
        let manifest = b"v2-manifest".to_vec();
        let buf = encode_segment_footer(&fields, &manifest, &hk, &cipher, PAGE).unwrap();
        assert_eq!(buf.len(), PAGE);
        let (f2, m2) = decode_segment_footer(&buf, &hk, &cipher, PAGE).unwrap();
        assert_eq!(f2.format_version, 2);
        assert_eq!(f2.index_start_page, 5);
        assert_eq!(f2.index_page_count, 3);
        assert_eq!(m2, manifest);
    }

    #[test]
    fn v2_index_field_tamper_rejected() {
        // Flip a byte in the v2 index_start_page field (at offset FOOTER_FIELDS_END_V1).
        let (hk, cipher) = keys();
        let fields = sample_v2();
        let mut buf = encode_segment_footer(&fields, b"v2", &hk, &cipher, PAGE).unwrap();
        buf[FOOTER_FIELDS_END_V1] ^= 1;
        let err = decode_segment_footer(&buf, &hk, &cipher, PAGE).unwrap_err();
        assert!(matches!(err, PagedbError::Corruption(_)));
    }
}
