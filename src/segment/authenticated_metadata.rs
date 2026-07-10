use std::sync::Arc;

use crate::Result;
use crate::catalog::codec::{SegmentKind, SegmentMeta};
use crate::crypto::CipherId;
use crate::crypto::kdf::derive_hk;
use crate::crypto::keys::MasterKey;
use crate::errors::PagedbError;
use crate::pager::Pager;
use crate::pager::format::data_page::{body, extract_page_header_ids, open_data_page};
use crate::pager::format::page_kind::PageKind;
use crate::pager::format::segment_footer::{SegmentFooterFields, decode_segment_footer};
use crate::pager::format::structural_header::{SegmentHeaderFields, decode_segment_header};
use crate::vfs::Vfs;
use crate::vfs::VfsFile;

use super::types::{EXTENT_INDEX_ENTRY_LEN, ExtentIndexEntry};
use super::writer::{live_path, staging_path};

pub(crate) struct AuthenticatedSegmentMetadata {
    pub(crate) footer: SegmentFooterFields,
    pub(crate) manifest: Vec<u8>,
    pub(crate) master_key: MasterKey,
}

#[derive(Clone, Copy)]
pub(crate) enum ExpectedSegmentPath {
    Live,
    Staging,
}

pub(crate) fn validate_expected_path(
    meta: &SegmentMeta,
    path: &str,
    expected: ExpectedSegmentPath,
) -> Result<()> {
    let expected_path = match expected {
        ExpectedSegmentPath::Live => live_path(&meta.segment_id),
        ExpectedSegmentPath::Staging => staging_path(&meta.segment_id),
    };
    if path != expected_path {
        return Err(PagedbError::segment_metadata_mismatch("path"));
    }
    Ok(())
}

pub(crate) async fn authenticate_segment_metadata<V: Vfs + Clone>(
    pager: &Arc<Pager<V>>,
    file: &V::File,
    meta: &SegmentMeta,
    parent_file_id: [u8; 16],
    page_size: usize,
) -> Result<AuthenticatedSegmentMetadata> {
    let cipher_id = CipherId::from_byte(meta.cipher_id)?;
    let page_size_u64 =
        u64::try_from(page_size).map_err(|_| PagedbError::segment_geometry_invalid("page_size"))?;
    let expected_bytes = meta
        .page_count
        .checked_mul(page_size_u64)
        .ok_or_else(|| PagedbError::segment_geometry_invalid("page_count * page_size"))?;
    if meta.page_count < 2 {
        return Err(PagedbError::segment_geometry_invalid("page_count"));
    }
    if meta.total_bytes != expected_bytes {
        return Err(PagedbError::segment_geometry_invalid("total_bytes"));
    }
    let file_len = file.len().await?;
    if file_len % page_size_u64 != 0 {
        return Err(PagedbError::segment_geometry_invalid("file_alignment"));
    }
    if file_len != expected_bytes {
        return Err(PagedbError::segment_geometry_invalid("file_length"));
    }
    let footer_page_id = meta.page_count - 1;
    let footer_offset = footer_page_id
        .checked_mul(page_size_u64)
        .ok_or_else(|| PagedbError::segment_geometry_invalid("footer_offset"))?;
    let footer_end = footer_offset
        .checked_add(page_size_u64)
        .ok_or_else(|| PagedbError::segment_geometry_invalid("footer_end"))?;
    if footer_end > file_len {
        return Err(PagedbError::segment_geometry_invalid("footer_bounds"));
    }

    let master_key = pager.mk_for(meta.mk_epoch, cipher_id)?;
    let hk = derive_hk(&master_key)?;
    let mut header_bytes = vec![0u8; page_size];
    let header_read = file.read_at(0, &mut header_bytes).await?;
    if header_read != page_size {
        return Err(PagedbError::segment_geometry_invalid("header_read"));
    }
    let header = decode_segment_header(&header_bytes, &hk, page_size)?;
    validate_header(&header, meta, parent_file_id, page_size)?;

    let mut footer_bytes = vec![0u8; page_size];
    let footer_read = file.read_at(footer_offset, &mut footer_bytes).await?;
    if footer_read != page_size {
        return Err(PagedbError::segment_geometry_invalid("footer_read"));
    }
    let (footer, manifest) = {
        let mut lru = pager.dek_lru().lock();
        let cipher = lru.get_or_derive(meta.realm_id, meta.mk_epoch, cipher_id, &master_key)?;
        decode_segment_footer(&footer_bytes, &hk, cipher, page_size)?
    };
    validate_footer(&footer, meta, parent_file_id, footer_page_id)?;
    let index_context = ExtentIndexDecodeContext {
        pager,
        file,
        meta,
        master_key: &master_key,
        footer: &footer,
        cipher_id,
        page_size,
    };
    decode_extent_index(&index_context).await?;
    Ok(AuthenticatedSegmentMetadata {
        footer,
        manifest,
        master_key,
    })
}

fn validate_header(
    header: &SegmentHeaderFields,
    meta: &SegmentMeta,
    parent_file_id: [u8; 16],
    page_size: usize,
) -> Result<()> {
    if header.format_version != 1 {
        return Err(PagedbError::segment_metadata_mismatch(
            "header.format_version",
        ));
    }
    CipherId::from_byte(header.cipher_id)
        .map_err(|_| PagedbError::segment_metadata_mismatch("header.cipher_id"))?;
    if header.cipher_id != meta.cipher_id {
        return Err(PagedbError::segment_metadata_mismatch("header.cipher_id"));
    }
    let header_kind = SegmentKind::from_byte(header.segment_kind)
        .map_err(|_| PagedbError::segment_metadata_mismatch("header.segment_kind"))?;
    if header_kind != meta.segment_kind {
        return Err(PagedbError::segment_metadata_mismatch(
            "header.segment_kind",
        ));
    }
    if header.segment_id != meta.segment_id {
        return Err(PagedbError::segment_metadata_mismatch("header.segment_id"));
    }
    if header.parent_file_id != parent_file_id {
        return Err(PagedbError::corruption(
            crate::errors::CorruptionDetail::ForeignSegment {
                realm_id: meta.realm_id,
                name: String::new(),
                segment_id: meta.segment_id,
                footer_parent_file_id: header.parent_file_id,
                expected_parent_file_id: parent_file_id,
            },
        ));
    }
    if header.parent_file_id != meta.parent_file_id {
        return Err(PagedbError::segment_metadata_mismatch(
            "header.parent_file_id",
        ));
    }
    if header.realm_id != meta.realm_id {
        return Err(PagedbError::segment_metadata_mismatch("header.realm_id"));
    }
    if header.mk_epoch != meta.mk_epoch {
        return Err(PagedbError::segment_metadata_mismatch("header.mk_epoch"));
    }
    if page_size_log2(page_size)? != header.page_size_log2 {
        return Err(PagedbError::segment_metadata_mismatch(
            "header.page_size_log2",
        ));
    }
    if header.flags != 0 {
        return Err(PagedbError::segment_metadata_mismatch("header.flags"));
    }
    Ok(())
}

fn validate_footer(
    footer: &SegmentFooterFields,
    meta: &SegmentMeta,
    parent_file_id: [u8; 16],
    footer_page_id: u64,
) -> Result<()> {
    CipherId::from_byte(footer.cipher_id)
        .map_err(|_| PagedbError::segment_metadata_mismatch("footer.cipher_id"))?;
    if footer.segment_id != meta.segment_id {
        return Err(PagedbError::segment_metadata_mismatch("footer.segment_id"));
    }
    if footer.parent_file_id != parent_file_id {
        return Err(PagedbError::corruption(
            crate::errors::CorruptionDetail::ForeignSegment {
                realm_id: meta.realm_id,
                name: String::new(),
                segment_id: meta.segment_id,
                footer_parent_file_id: footer.parent_file_id,
                expected_parent_file_id: parent_file_id,
            },
        ));
    }
    if footer.parent_file_id != meta.parent_file_id {
        return Err(PagedbError::segment_metadata_mismatch(
            "footer.parent_file_id",
        ));
    }
    if footer.realm_id != meta.realm_id {
        return Err(PagedbError::segment_metadata_mismatch("footer.realm_id"));
    }
    if footer.mk_epoch != meta.mk_epoch {
        return Err(PagedbError::segment_metadata_mismatch("footer.mk_epoch"));
    }
    if footer.cipher_id != meta.cipher_id {
        return Err(PagedbError::segment_metadata_mismatch("footer.cipher_id"));
    }
    if footer.format_version != meta.format_version {
        return Err(PagedbError::segment_metadata_mismatch(
            "footer.format_version",
        ));
    }
    if footer.page_count != meta.page_count {
        return Err(PagedbError::segment_metadata_mismatch("footer.page_count"));
    }
    if footer.total_bytes != meta.total_bytes {
        return Err(PagedbError::segment_metadata_mismatch("footer.total_bytes"));
    }
    if footer.final_counter != meta.final_counter {
        return Err(PagedbError::segment_metadata_mismatch(
            "footer.final_counter",
        ));
    }
    let expected_final_counter = footer_page_id
        .checked_sub(1)
        .ok_or_else(|| PagedbError::segment_geometry_invalid("footer_page_id"))?;
    if footer.final_counter != expected_final_counter {
        return Err(PagedbError::segment_metadata_mismatch(
            "footer.final_counter_geometry",
        ));
    }
    match footer.format_version {
        1 if footer.index_start_page != 0 || footer.index_page_count != 0 => {
            Err(PagedbError::segment_metadata_mismatch("footer.index"))
        }
        2 if footer.index_page_count == 0 && footer.index_start_page != 0 => {
            Err(PagedbError::segment_metadata_mismatch("footer.index"))
        }
        2 if footer.index_page_count != 0 => {
            let index_end = footer
                .index_start_page
                .checked_add(u64::from(footer.index_page_count))
                .ok_or_else(|| PagedbError::segment_geometry_invalid("footer.index_range"))?;
            if footer.index_start_page == 0 || index_end != footer_page_id {
                return Err(PagedbError::segment_metadata_mismatch("footer.index"));
            }
            Ok(())
        }
        1 | 2 => Ok(()),
        _ => Err(PagedbError::segment_metadata_mismatch(
            "footer.format_version",
        )),
    }
}

pub(crate) struct ExtentIndexDecodeContext<'a, V: Vfs + Clone> {
    pub(crate) pager: &'a Arc<Pager<V>>,
    pub(crate) file: &'a V::File,
    pub(crate) meta: &'a SegmentMeta,
    pub(crate) master_key: &'a MasterKey,
    pub(crate) footer: &'a SegmentFooterFields,
    pub(crate) cipher_id: CipherId,
    pub(crate) page_size: usize,
}

/// Decrypt, decode, and validate every v2 extent-index entry. Both open-time
/// reconciliation and `SegmentReader` use this path so a catalog-referenced
/// segment cannot defer structural index failures until an indexed lookup.
pub(crate) async fn decode_extent_index<V: Vfs + Clone>(
    context: &ExtentIndexDecodeContext<'_, V>,
) -> Result<Vec<ExtentIndexEntry>> {
    if context.footer.index_page_count == 0 {
        return Ok(Vec::new());
    }
    let index_end = context
        .footer
        .index_start_page
        .checked_add(u64::from(context.footer.index_page_count))
        .ok_or_else(|| PagedbError::segment_geometry_invalid("footer.index_range"))?;
    if context.footer.index_start_page == 0 || index_end != context.footer.page_count - 1 {
        return Err(PagedbError::segment_metadata_mismatch("footer.index"));
    }

    let entries_per_page = (context.page_size - crate::pager::format::data_page::ENVELOPE_OVERHEAD)
        / EXTENT_INDEX_ENTRY_LEN;
    if entries_per_page == 0 {
        return Err(PagedbError::segment_geometry_invalid(
            "index.entry_capacity",
        ));
    }
    let mut entries = Vec::new();
    let mut previous_end = 0u64;
    let mut unused_tail = false;
    for page_offset in 0..u64::from(context.footer.index_page_count) {
        let page_id = context
            .footer
            .index_start_page
            .checked_add(page_offset)
            .ok_or_else(|| PagedbError::segment_geometry_invalid("index.page_id"))?;
        let page_body = collect_and_decode_index_page(context, page_id).await?;
        validate_index_entries(
            &page_body,
            context.footer.index_start_page,
            &mut previous_end,
            &mut unused_tail,
            &mut entries,
        )?;
    }
    if entries.is_empty() {
        return Err(PagedbError::segment_metadata_mismatch("index.entry_count"));
    }
    Ok(entries)
}

async fn collect_and_decode_index_page<V: Vfs + Clone>(
    context: &ExtentIndexDecodeContext<'_, V>,
    page_id: u64,
) -> Result<Vec<u8>> {
    let page_size_u64 = u64::try_from(context.page_size)
        .map_err(|_| PagedbError::segment_geometry_invalid("page_size"))?;
    let offset = page_id
        .checked_mul(page_size_u64)
        .ok_or_else(|| PagedbError::segment_geometry_invalid("index.offset"))?;
    let mut page = vec![0u8; context.page_size];
    if context.file.read_at(offset, &mut page).await? != context.page_size {
        return Err(PagedbError::segment_geometry_invalid("index.read"));
    }
    let (cipher_id, mk_epoch) = extract_page_header_ids(&page)?;
    if cipher_id != context.cipher_id {
        return Err(PagedbError::segment_metadata_mismatch(
            "index_page.cipher_id",
        ));
    }
    if mk_epoch != context.meta.mk_epoch {
        return Err(PagedbError::segment_metadata_mismatch(
            "index_page.mk_epoch",
        ));
    }
    let aad = crate::crypto::aad::Aad::from_fields(crate::crypto::aad::AadFields {
        cipher_id: context.meta.cipher_id,
        page_kind: PageKind::SegmentIndex.as_byte(),
        mk_epoch: context.meta.mk_epoch,
        page_id,
        realm_id: context.meta.realm_id,
        segment_id: context.meta.segment_id,
    });
    let mut lru = context.pager.dek_lru().lock();
    let cipher = lru.get_or_derive(
        context.meta.realm_id,
        context.meta.mk_epoch,
        cipher_id,
        context.master_key,
    )?;
    open_data_page(&mut page, &aad, cipher)?;
    Ok(body(&page).to_vec())
}

fn validate_index_entries(
    page_body: &[u8],
    index_start_page: u64,
    previous_end: &mut u64,
    unused_tail: &mut bool,
    entries: &mut Vec<ExtentIndexEntry>,
) -> Result<()> {
    let mut chunks = page_body.chunks_exact(EXTENT_INDEX_ENTRY_LEN);
    if chunks.remainder().iter().any(|byte| *byte != 0) {
        return Err(PagedbError::segment_metadata_mismatch("index.unused_tail"));
    }
    for encoded in &mut chunks {
        if encoded.iter().all(|byte| *byte == 0) {
            *unused_tail = true;
            continue;
        }
        if *unused_tail {
            return Err(PagedbError::segment_metadata_mismatch("index.unused_tail"));
        }
        if encoded[12..16].iter().any(|byte| *byte != 0)
            || encoded[24..32].iter().any(|byte| *byte != 0)
        {
            return Err(PagedbError::segment_metadata_mismatch(
                "index.entry.reserved",
            ));
        }
        let entry_bytes: &[u8; EXTENT_INDEX_ENTRY_LEN] = encoded
            .try_into()
            .map_err(|_| PagedbError::segment_geometry_invalid("index.entry_length"))?;
        let entry = ExtentIndexEntry::decode(entry_bytes);
        if entry.start_page_id == 0 || entry.page_count == 0 {
            return Err(PagedbError::segment_metadata_mismatch("index.entry.zero"));
        }
        let entry_end = entry
            .start_page_id
            .checked_add(u64::from(entry.page_count))
            .ok_or_else(|| PagedbError::segment_geometry_invalid("index.entry_range"))?;
        if entry_end > index_start_page {
            return Err(PagedbError::segment_metadata_mismatch("index.entry.range"));
        }
        if *previous_end != 0 && entry.start_page_id < *previous_end {
            return Err(PagedbError::segment_metadata_mismatch("index.entry.order"));
        }
        *previous_end = entry_end;
        entries.push(entry);
    }
    Ok(())
}

fn page_size_log2(page_size: usize) -> Result<u8> {
    match page_size {
        4096 => Ok(12),
        8192 => Ok(13),
        16384 => Ok(14),
        32768 => Ok(15),
        65536 => Ok(16),
        _ => Err(PagedbError::segment_geometry_invalid("page_size")),
    }
}

#[cfg(test)]
mod tests;
