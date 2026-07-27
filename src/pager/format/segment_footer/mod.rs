//! Format C — segment footer page.

mod auth;
mod decode;
mod encode;
mod fields;

pub use decode::decode_segment_footer;
pub use encode::encode_segment_footer;
pub use fields::{SegmentFooterFields, max_manifest_len, max_manifest_len_v2};
// Layout boundaries the footer tests assert against directly.
#[cfg(test)]
pub use fields::{FOOTER_CLEARTEXT_END, FOOTER_FIELDS_END};

#[cfg(test)]
mod tests;
