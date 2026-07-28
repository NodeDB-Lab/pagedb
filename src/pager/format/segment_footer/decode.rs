use crate::crypto::{Cipher, Nonce};
use crate::errors::{CorruptionDetail, PagedbError};
use crate::{RealmId, Result};

use super::auth::{constant_time_eq, footer_aad, mac_hk};
use super::fields::{
    FOOTER_CLEARTEXT_END, FOOTER_FIELDS_END, FORMAT_VERSION, MAGIC, MANIFEST_TAG_LEN,
    SegmentFooterFields, max_manifest_len,
};

pub fn decode_segment_footer(
    bytes: &[u8],
    hk: &crate::crypto::keys::DerivedKey,
    cipher: &Cipher,
    page_size: usize,
) -> Result<(SegmentFooterFields, Vec<u8>)> {
    let parsed = parse_cleartext(bytes, page_size)?;
    authenticate_cleartext(bytes, hk, &parsed)?;
    let (fields, ciphertext_end, tag_end) = assemble_fields(bytes, &parsed, cipher)?;
    let manifest = authenticate_manifest(bytes, cipher, &fields, ciphertext_end, tag_end)?;
    Ok((fields, manifest))
}

/// Disprove a footer's identity without deciding how to report it.
///
/// Returns `true` only when the cleartext HK-MAC is present and does not
/// match — the one condition that makes a segment's identity *unverifiable*
/// rather than merely unreadable.
///
/// Split out of [`decode_segment_footer`] because the decoder cannot name the
/// segment it just rejected: the identity fields it would quote live in the
/// bytes whose MAC failed. A caller holding the segment's *trusted* identity
/// (the catalog row that routed it here) runs this first and raises the
/// identity-carrying error itself, so exactly one error is constructed — and
/// therefore exactly one report filed — for one failure. Rewriting the
/// decoder's error after the fact would construct two.
///
/// A buffer too short to hold a MAC has nothing to disprove and returns
/// `false`, leaving [`decode_segment_footer`] to raise the framing error that
/// actually describes it.
pub fn footer_identity_is_unverifiable(bytes: &[u8], hk: &crate::crypto::keys::DerivedKey) -> bool {
    if bytes.len() < FOOTER_CLEARTEXT_END {
        return false;
    }
    let Ok(mac) = mac_hk(hk, &bytes[..FOOTER_FIELDS_END]) else {
        return false;
    };
    !constant_time_eq(&mac, &bytes[FOOTER_FIELDS_END..FOOTER_CLEARTEXT_END])
}

struct ParsedFooter {
    manifest_offset: u32,
    manifest_len: usize,
    fields: SegmentFooterFields,
}

fn parse_cleartext(bytes: &[u8], page_size: usize) -> Result<ParsedFooter> {
    if bytes.len() != page_size || page_size < FOOTER_CLEARTEXT_END + MANIFEST_TAG_LEN {
        return Err(PagedbError::Unsupported);
    }
    if bytes[..8] != MAGIC {
        return Err(PagedbError::footer_framing_invalid("magic"));
    }
    let format_version = u16_le(&bytes[8..10]);
    if format_version != FORMAT_VERSION {
        // A version this build does not read is a migration problem, not a
        // damaged footer — say so, or an operator triages the wrong thing.
        return Err(PagedbError::FormatVersionUnsupported {
            stored: format_version,
            supported: FORMAT_VERSION,
        });
    }
    let mut offset = 10;
    let cipher_id = bytes[offset];
    offset += 1;
    let segment_id = arr16(&bytes[offset..offset + 16]);
    offset += 16;
    let parent_file_id = arr16(&bytes[offset..offset + 16]);
    offset += 16;
    let realm_id = RealmId(arr16(&bytes[offset..offset + 16]));
    offset += 16;
    let mk_epoch = u64_le(&bytes[offset..offset + 8]);
    offset += 8;
    let page_count = u64_le(&bytes[offset..offset + 8]);
    offset += 8;
    let total_bytes = u64_le(&bytes[offset..offset + 8]);
    offset += 8;
    let final_counter = u64_le(&bytes[offset..offset + 8]);
    offset += 8;
    let manifest_offset = u32_le(&bytes[offset..offset + 4]);
    offset += 4;
    let manifest_len = usize::try_from(u32_le(&bytes[offset..offset + 4]))
        .map_err(|_| PagedbError::Unsupported)?;
    offset += 4;
    let index_start_page = u64_le(&bytes[offset..offset + 8]);
    let index_page_count = u32_le(&bytes[offset + 8..offset + 12]);
    debug_assert_eq!(offset + 12, FOOTER_FIELDS_END);
    Ok(ParsedFooter {
        manifest_offset,
        manifest_len,
        fields: SegmentFooterFields {
            format_version,
            cipher_id,
            segment_id,
            parent_file_id,
            realm_id,
            mk_epoch,
            page_count,
            total_bytes,
            final_counter,
            index_start_page,
            index_page_count,
        },
    })
}

fn authenticate_cleartext(
    bytes: &[u8],
    hk: &crate::crypto::keys::DerivedKey,
    parsed: &ParsedFooter,
) -> Result<()> {
    let mac = mac_hk(hk, &bytes[..FOOTER_FIELDS_END])?;
    let valid_mac = constant_time_eq(&mac, &bytes[FOOTER_FIELDS_END..FOOTER_CLEARTEXT_END]);
    let expected_offset =
        u32::try_from(FOOTER_CLEARTEXT_END).map_err(|_| PagedbError::Unsupported)?;
    if !valid_mac
        || parsed.manifest_offset != expected_offset
        || parsed.manifest_len > max_manifest_len(bytes.len())
    {
        return Err(PagedbError::footer_framing_invalid(
            "manifest_offset_or_length",
        ));
    }
    Ok(())
}

fn assemble_fields(
    bytes: &[u8],
    parsed: &ParsedFooter,
    cipher: &Cipher,
) -> Result<(SegmentFooterFields, usize, usize)> {
    let fields = parsed.fields.clone();
    if cipher.id().as_byte() != fields.cipher_id {
        return Err(PagedbError::corruption(
            CorruptionDetail::ManifestUnverifiable {
                realm_id: fields.realm_id,
                segment_id: fields.segment_id,
            },
        ));
    }
    let ciphertext_end = FOOTER_CLEARTEXT_END
        .checked_add(parsed.manifest_len)
        .ok_or_else(|| PagedbError::arithmetic_overflow("footer manifest end"))?;
    let tag_end = ciphertext_end
        .checked_add(MANIFEST_TAG_LEN)
        .ok_or_else(|| PagedbError::arithmetic_overflow("footer manifest tag end"))?;
    if tag_end > bytes.len() {
        return Err(PagedbError::footer_framing_invalid("manifest_tag_end"));
    }
    Ok((fields, ciphertext_end, tag_end))
}

fn authenticate_manifest(
    bytes: &[u8],
    cipher: &Cipher,
    fields: &SegmentFooterFields,
    ciphertext_end: usize,
    tag_end: usize,
) -> Result<Vec<u8>> {
    let nonce_counter = fields
        .final_counter
        .checked_add(1)
        .filter(|counter| *counter <= Nonce::COUNTER_MAX)
        .ok_or(PagedbError::NonceCounterExhausted)?;
    let mut file_id = [0u8; 6];
    file_id.copy_from_slice(&fields.segment_id[..6]);
    let nonce = Nonce::from_parts(file_id, nonce_counter);
    let mut manifest = bytes[FOOTER_CLEARTEXT_END..ciphertext_end].to_vec();
    let mut tag = [0u8; MANIFEST_TAG_LEN];
    tag.copy_from_slice(&bytes[ciphertext_end..tag_end]);
    cipher
        .decrypt(&nonce, &footer_aad(fields), &mut manifest, &tag)
        .map_err(|_| {
            PagedbError::corruption(CorruptionDetail::ManifestUnverifiable {
                realm_id: fields.realm_id,
                segment_id: fields.segment_id,
            })
        })?;
    if bytes[tag_end..].iter().any(|byte| *byte != 0) {
        return Err(PagedbError::footer_framing_invalid("trailing_bytes"));
    }
    Ok(manifest)
}

fn u16_le(bytes: &[u8]) -> u16 {
    let mut out = [0u8; 2];
    out.copy_from_slice(bytes);
    u16::from_le_bytes(out)
}

fn u32_le(bytes: &[u8]) -> u32 {
    let mut out = [0u8; 4];
    out.copy_from_slice(bytes);
    u32::from_le_bytes(out)
}

fn u64_le(bytes: &[u8]) -> u64 {
    let mut out = [0u8; 8];
    out.copy_from_slice(bytes);
    u64::from_le_bytes(out)
}

fn arr16(bytes: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out.copy_from_slice(bytes);
    out
}
