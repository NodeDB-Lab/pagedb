use crate::Result;
use crate::crypto::{Cipher, Nonce};
use crate::errors::PagedbError;

use super::auth::{footer_aad, mac_hk};
use super::fields::{
    FOOTER_CLEARTEXT_END_V1, FOOTER_CLEARTEXT_END_V2, FOOTER_FIELDS_END_V1, FOOTER_FIELDS_END_V2,
    FOOTER_HEADER_MAC_LEN, MANIFEST_TAG_LEN, SegmentFooterFields, max_manifest_len,
    max_manifest_len_v2,
};

pub fn encode_segment_footer(
    fields: &SegmentFooterFields,
    manifest: &[u8],
    hk: &crate::crypto::keys::DerivedKey,
    cipher: &Cipher,
    page_size: usize,
) -> Result<Vec<u8>> {
    let (fields_end, cleartext_end) = match fields.format_version {
        1 => (FOOTER_FIELDS_END_V1, FOOTER_CLEARTEXT_END_V1),
        2 => (FOOTER_FIELDS_END_V2, FOOTER_CLEARTEXT_END_V2),
        _ => return Err(PagedbError::Unsupported),
    };
    if page_size < cleartext_end + MANIFEST_TAG_LEN {
        return Err(PagedbError::Unsupported);
    }
    let max_manifest = if fields.format_version == 1 {
        max_manifest_len(page_size)
    } else {
        max_manifest_len_v2(page_size)
    };
    if manifest.len() > max_manifest {
        return Err(PagedbError::ManifestTooLarge);
    }
    if cipher.id().as_byte() != fields.cipher_id {
        return Err(PagedbError::Unsupported);
    }

    let manifest_offset = u32::try_from(cleartext_end).map_err(|_| PagedbError::Unsupported)?;
    let manifest_len = u32::try_from(manifest.len()).map_err(|_| PagedbError::ManifestTooLarge)?;
    let mut out = vec![0u8; page_size];
    let mut offset = 0usize;
    out[offset..offset + 8].copy_from_slice(&super::fields::MAGIC);
    offset += 8;
    out[offset..offset + 2].copy_from_slice(&fields.format_version.to_le_bytes());
    offset += 2;
    out[offset] = fields.cipher_id;
    offset += 1;
    out[offset..offset + 16].copy_from_slice(&fields.segment_id);
    offset += 16;
    out[offset..offset + 16].copy_from_slice(&fields.parent_file_id);
    offset += 16;
    out[offset..offset + 16].copy_from_slice(&fields.realm_id.0);
    offset += 16;
    out[offset..offset + 8].copy_from_slice(&fields.mk_epoch.to_le_bytes());
    offset += 8;
    out[offset..offset + 8].copy_from_slice(&fields.page_count.to_le_bytes());
    offset += 8;
    out[offset..offset + 8].copy_from_slice(&fields.total_bytes.to_le_bytes());
    offset += 8;
    out[offset..offset + 8].copy_from_slice(&fields.final_counter.to_le_bytes());
    offset += 8;
    out[offset..offset + 4].copy_from_slice(&manifest_offset.to_le_bytes());
    offset += 4;
    out[offset..offset + 4].copy_from_slice(&manifest_len.to_le_bytes());
    offset += 4;
    if fields.format_version == 2 {
        out[offset..offset + 8].copy_from_slice(&fields.index_start_page.to_le_bytes());
        offset += 8;
        out[offset..offset + 4].copy_from_slice(&fields.index_page_count.to_le_bytes());
        offset += 4;
    }
    debug_assert_eq!(offset, fields_end);
    let mac = mac_hk(hk, &out[..offset])?;
    out[offset..offset + FOOTER_HEADER_MAC_LEN].copy_from_slice(&mac);
    offset += FOOTER_HEADER_MAC_LEN;
    debug_assert_eq!(offset, cleartext_end);

    let nonce_counter = fields
        .final_counter
        .checked_add(1)
        .filter(|counter| *counter <= Nonce::COUNTER_MAX)
        .ok_or(PagedbError::NonceCounterExhausted)?;
    let mut file_id = [0u8; 6];
    file_id.copy_from_slice(&fields.segment_id[..6]);
    let nonce = Nonce::from_parts(&file_id, nonce_counter);
    let manifest_end = cleartext_end
        .checked_add(manifest.len())
        .ok_or_else(|| PagedbError::arithmetic_overflow("footer manifest end"))?;
    out[cleartext_end..manifest_end].copy_from_slice(manifest);
    let tag = cipher.encrypt(
        &nonce,
        &footer_aad(fields),
        &mut out[cleartext_end..manifest_end],
    )?;
    let tag_end = manifest_end
        .checked_add(MANIFEST_TAG_LEN)
        .ok_or_else(|| PagedbError::arithmetic_overflow("footer manifest tag end"))?;
    out[manifest_end..tag_end].copy_from_slice(&tag);
    Ok(out)
}
