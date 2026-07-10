use crate::RealmId;

pub const MAGIC: [u8; 8] = *b"PAGESEAL";
pub const FOOTER_FIELDS_END_V1: usize = 99;
pub const FOOTER_FIELDS_END_V2: usize = FOOTER_FIELDS_END_V1 + 12;
pub const FOOTER_FIELDS_END: usize = FOOTER_FIELDS_END_V1;
pub const FOOTER_HEADER_MAC_LEN: usize = 16;
pub const FOOTER_CLEARTEXT_END_V1: usize = FOOTER_FIELDS_END_V1 + FOOTER_HEADER_MAC_LEN;
pub const FOOTER_CLEARTEXT_END_V2: usize = FOOTER_FIELDS_END_V2 + FOOTER_HEADER_MAC_LEN;
pub const FOOTER_CLEARTEXT_END: usize = FOOTER_CLEARTEXT_END_V1;
pub const MANIFEST_TAG_LEN: usize = 16;

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
    pub index_start_page: u64,
    pub index_page_count: u32,
}

#[must_use]
pub const fn max_manifest_len(page_size: usize) -> usize {
    page_size - FOOTER_CLEARTEXT_END_V1 - MANIFEST_TAG_LEN
}

#[must_use]
pub const fn max_manifest_len_v2(page_size: usize) -> usize {
    page_size - FOOTER_CLEARTEXT_END_V2 - MANIFEST_TAG_LEN
}
