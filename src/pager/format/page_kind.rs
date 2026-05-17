//! `PageKind` discriminator. Bound into AEAD AAD on every Format A page;
//! identifies which structural role the page plays.

use crate::Result;
use crate::errors::PagedbError;

/// Internal full set of page kinds. Main.db pages use 0x01..=0x07; segment
/// pages use 0x10..=0x12. The two sets are disjoint; cross-context smuggling
/// is rejected by AAD binding at decryption time, but `from_byte` rejects
/// unknown values at parse time as a defense-in-depth check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum PageKind {
    BTreeInternal = 0x01,
    BTreeLeaf = 0x02,
    Free = 0x03,
    Spill = 0x04,
    Overflow = 0x05,
    Counter = 0x06,
    Catalog = 0x07,
    /// Apply-journal slot page. Written to reserved pages 2 and 3 of main.db
    /// before an `apply_incremental` header swap to record the segment
    /// promotions and tombstones that must be completed after the swap.
    ApplyJournal = 0x08,
    /// v2 overflow root page. Carries a `refcount: u32` in its body header
    /// before the `next` pointer, enabling reference counting for shared
    /// overflow chains. Chain pages (not the root) continue to use
    /// `PageKind::Overflow`.
    OverflowRoot = 0x09,
    SegmentData = 0x10,
    SegmentIndex = 0x11,
    SegmentOverflow = 0x12,
}

impl PageKind {
    pub fn from_byte(b: u8) -> Result<Self> {
        match b {
            0x01 => Ok(Self::BTreeInternal),
            0x02 => Ok(Self::BTreeLeaf),
            0x03 => Ok(Self::Free),
            0x04 => Ok(Self::Spill),
            0x05 => Ok(Self::Overflow),
            0x06 => Ok(Self::Counter),
            0x07 => Ok(Self::Catalog),
            0x08 => Ok(Self::ApplyJournal),
            0x09 => Ok(Self::OverflowRoot),
            0x10 => Ok(Self::SegmentData),
            0x11 => Ok(Self::SegmentIndex),
            0x12 => Ok(Self::SegmentOverflow),
            _ => Err(PagedbError::IllegalPageKind),
        }
    }

    #[must_use]
    pub fn as_byte(self) -> u8 {
        self as u8
    }

    /// True iff this kind is legal in a `main.db` Format A page.
    #[must_use]
    pub fn is_main_db(self) -> bool {
        matches!(
            self,
            Self::BTreeInternal
                | Self::BTreeLeaf
                | Self::Free
                | Self::Spill
                | Self::Overflow
                | Self::Counter
                | Self::Catalog
                | Self::ApplyJournal
                | Self::OverflowRoot
        )
    }

    /// True iff this kind is legal in a segment file Format A page.
    #[must_use]
    pub fn is_segment(self) -> bool {
        matches!(
            self,
            Self::SegmentData | Self::SegmentIndex | Self::SegmentOverflow
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_all_kinds() {
        for k in [
            PageKind::BTreeInternal,
            PageKind::BTreeLeaf,
            PageKind::Free,
            PageKind::Spill,
            PageKind::Overflow,
            PageKind::Counter,
            PageKind::Catalog,
            PageKind::ApplyJournal,
            PageKind::OverflowRoot,
            PageKind::SegmentData,
            PageKind::SegmentIndex,
            PageKind::SegmentOverflow,
        ] {
            assert_eq!(PageKind::from_byte(k.as_byte()).unwrap(), k);
        }
    }

    #[test]
    fn unknown_bytes_rejected() {
        for b in [0x00u8, 0x0A, 0x0F, 0x13, 0x1F, 0x20, 0xFF] {
            assert!(matches!(
                PageKind::from_byte(b),
                Err(PagedbError::IllegalPageKind)
            ));
        }
    }

    #[test]
    fn domain_split() {
        assert!(PageKind::BTreeLeaf.is_main_db() && !PageKind::BTreeLeaf.is_segment());
        assert!(PageKind::SegmentData.is_segment() && !PageKind::SegmentData.is_main_db());
    }
}
