//! Public types for the Segment File API.

/// Segment-legal page kind subset.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SegmentPageKind {
    Data = 0x10,
    Index = 0x11,
    Overflow = 0x12,
}

impl SegmentPageKind {
    #[must_use]
    pub fn as_page_kind(self) -> crate::pager::format::page_kind::PageKind {
        match self {
            Self::Data => crate::pager::format::page_kind::PageKind::SegmentData,
            Self::Index => crate::pager::format::page_kind::PageKind::SegmentIndex,
            Self::Overflow => crate::pager::format::page_kind::PageKind::SegmentOverflow,
        }
    }
}

/// Page identifier within a segment file.
pub type PageId = u64;

/// Bulk-read reference: a contiguous range starting at `start_page_id` of
/// length `count`.
#[non_exhaustive]
#[derive(Debug, Clone, Copy)]
pub struct ExtentRef {
    pub start_page_id: u64,
    pub count: u32,
}

impl ExtentRef {
    /// Construct an `ExtentRef` for `count` pages starting at `start_page_id`.
    #[must_use]
    pub const fn new(start_page_id: u64, count: u32) -> Self {
        Self {
            start_page_id,
            count,
        }
    }
}

/// A read-only zero-copy view over already-decrypted segment data.
///
/// On native platforms (Linux, macOS, Windows) this is backed by an anonymous
/// temporary file mmap'd read-only. On WASM/OPFS the type exists for API
/// surface stability but cannot be constructed; all calls return
/// `PagedbError::Unsupported`.
#[cfg(not(target_arch = "wasm32"))]
pub use super::mmap::MmapView;

/// Unsupported stub for WASM targets.
#[cfg(target_arch = "wasm32")]
#[derive(Debug)]
pub struct MmapView {
    _private: (),
}

/// A single entry in the v2 segment extent index.
///
/// Each entry describes one extent (a contiguous run of pages) appended via
/// `SegmentWriter::append_extent`. Entries are sorted by `start_page_id` to
/// allow binary search during `SegmentReader::find_extent`.
///
/// On-disk encoding (32 bytes, little-endian):
/// `start_page_id[8] || page_count[4] || _pad[4] || logical_bytes[8] || index_page_of_data[8]`
///
/// `index_page_of_data` is reserved for future use (0 in the current implementation).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtentIndexEntry {
    /// First page id of the extent (equals the value returned by `append_extent`).
    pub start_page_id: u64,
    /// Number of pages in the extent.
    pub page_count: u32,
    /// Total logical (plaintext) bytes across all pages in the extent.
    pub logical_bytes: u64,
}

/// Size of one on-disk `ExtentIndexEntry`.
pub const EXTENT_INDEX_ENTRY_LEN: usize = 32;

impl ExtentIndexEntry {
    /// Encode to 32 bytes (little-endian).
    #[must_use]
    pub fn encode(self) -> [u8; EXTENT_INDEX_ENTRY_LEN] {
        let mut buf = [0u8; EXTENT_INDEX_ENTRY_LEN];
        buf[0..8].copy_from_slice(&self.start_page_id.to_le_bytes());
        buf[8..12].copy_from_slice(&self.page_count.to_le_bytes());
        // bytes 12..16 are padding / reserved, left zero
        buf[16..24].copy_from_slice(&self.logical_bytes.to_le_bytes());
        // bytes 24..32 are reserved, left zero
        buf
    }

    /// Decode from 32 bytes.
    #[must_use]
    pub fn decode(buf: &[u8; EXTENT_INDEX_ENTRY_LEN]) -> Self {
        let mut b8 = [0u8; 8];
        b8.copy_from_slice(&buf[0..8]);
        let start_page_id = u64::from_le_bytes(b8);
        let mut b4 = [0u8; 4];
        b4.copy_from_slice(&buf[8..12]);
        let page_count = u32::from_le_bytes(b4);
        b8.copy_from_slice(&buf[16..24]);
        let logical_bytes = u64::from_le_bytes(b8);
        Self {
            start_page_id,
            page_count,
            logical_bytes,
        }
    }
}

/// Statistics returned by `Db::gc_now`.
#[non_exhaustive]
#[derive(Debug, Default, Clone, Copy)]
pub struct GcStats {
    pub reclaimed_segments: u64,
    pub reclaimed_bytes: u64,
}
