//! Format C — segment footer page.

mod auth;
mod decode;
mod encode;
mod fields;

pub use decode::decode_segment_footer;
pub use encode::encode_segment_footer;
pub use fields::{
    FOOTER_CLEARTEXT_END, FOOTER_CLEARTEXT_END_V1, FOOTER_CLEARTEXT_END_V2, FOOTER_FIELDS_END,
    FOOTER_FIELDS_END_V1, FOOTER_FIELDS_END_V2, MAGIC, MANIFEST_TAG_LEN, SegmentFooterFields,
    max_manifest_len, max_manifest_len_v2,
};

#[cfg(test)]
mod tests;
