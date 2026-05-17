//! Pager: cache, page envelopes, header IO, AEAD dispatch.

pub mod cache;
pub mod core;
pub mod format;
pub mod header;

pub use cache::PageCache;
pub use core::{FileKey, PageGuard, Pager, PagerConfig};
pub use format::{data_page, page_kind::PageKind, segment_footer, structural_header};
