//! Layout of main.db's page-id space.
//!
//! Page ids 0..=3 are reserved and never handed out by the allocator:
//!
//! | id | owner |
//! | -- | ----- |
//! | 0  | structural header, copy A |
//! | 1  | structural header, copy B |
//! | 2  | apply-journal root |
//! | 3  | apply-journal spare |
//!
//! Everything from [`FIRST_ALLOCATABLE_PAGE_ID`] up is tree, overflow, or
//! free-list territory. The distinction matters beyond bookkeeping: the
//! structural headers use a different envelope (HK-MAC, cleartext) than data
//! pages, so a live tree pointer that reaches one is a wild pointer or a
//! use-after-free that recycled a reserved id — never a benign condition.

use crate::Result;
use crate::errors::PagedbError;

/// First page id the allocator may hand out. Ids below this are reserved.
pub const FIRST_ALLOCATABLE_PAGE_ID: u64 = 4;

/// Whether `page_id` names a reserved page that no live tree pointer,
/// overflow link, or free-list entry may reference.
#[must_use]
pub const fn is_reserved(page_id: u64) -> bool {
    page_id < FIRST_ALLOCATABLE_PAGE_ID
}

/// Byte offset of `page_id` in a paged file, or an arithmetic error.
///
/// Page ids reach this from disk — a catalog record, a free-list entry, a
/// header field — so the product is not trusted to fit. `operation` names the
/// caller in the resulting error, since a wrapped offset and a rejected one
/// are indistinguishable by the time a diagnostic reports them.
pub fn page_offset(page_id: u64, page_size: usize, operation: &'static str) -> Result<u64> {
    let page_size =
        u64::try_from(page_size).map_err(|_| PagedbError::arithmetic_overflow(operation))?;
    page_id
        .checked_mul(page_size)
        .ok_or_else(|| PagedbError::arithmetic_overflow(operation))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE: usize = 4096;

    #[test]
    fn offset_scales_by_page_size() {
        assert_eq!(page_offset(0, PAGE, "test").unwrap(), 0);
        assert_eq!(page_offset(4, PAGE, "test").unwrap(), 16_384);
    }

    #[test]
    fn offset_rejects_a_page_id_that_overflows_the_address_space() {
        let first_unrepresentable = (u64::MAX / PAGE as u64) + 1;
        assert!(matches!(
            page_offset(first_unrepresentable, PAGE, "test"),
            Err(PagedbError::ArithmeticOverflow { .. })
        ));
        assert!(page_offset(first_unrepresentable - 1, PAGE, "test").is_ok());
    }
}
