use crate::RealmId;

pub const MAGIC: [u8; 8] = *b"PAGESEAL";

/// The only `format_version` this decoder accepts. The field is persisted so a
/// later layout can be introduced without ambiguity; any other value is a
/// footer this build cannot interpret and is rejected as corruption.
pub const FORMAT_VERSION: u16 = 1;

/// End of the MAC-covered cleartext field block.
pub const FOOTER_FIELDS_END: usize = 111;
pub const FOOTER_HEADER_MAC_LEN: usize = 16;
/// End of the cleartext prefix — fields plus their MAC. The encrypted manifest
/// starts here.
pub const FOOTER_CLEARTEXT_END: usize = FOOTER_FIELDS_END + FOOTER_HEADER_MAC_LEN;
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
    page_size - FOOTER_CLEARTEXT_END - MANIFEST_TAG_LEN
}
