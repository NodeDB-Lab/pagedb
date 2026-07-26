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

/// First page id the allocator may hand out. Ids below this are reserved.
pub const FIRST_ALLOCATABLE_PAGE_ID: u64 = 4;

/// Whether `page_id` names a reserved page that no live tree pointer,
/// overflow link, or free-list entry may reference.
#[must_use]
pub const fn is_reserved(page_id: u64) -> bool {
    page_id < FIRST_ALLOCATABLE_PAGE_ID
}
