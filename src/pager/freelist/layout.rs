//! On-disk layout of a single `PageKind::Free` chain page.
//!
//! ```text
//! [0..8)   next chain page id (LE u64; 0 = end of chain)
//! [8..12)  entry count in this page (LE u32)
//! [12..)   `count` × (commit_id LE u64 ‖ page_id LE u64)
//! ```
//!
//! Nothing here names another page's *offset* — only its id — which is what
//! makes a page removable from the chain by rewriting the page that points at
//! it and nothing else.

use crate::pager::format::data_page::body_capacity;
use crate::{PagedbError, Result};

pub(crate) const ENTRY_LEN: usize = 16;
pub(crate) const PAGE_HEADER_LEN: usize = 12;

/// Freeing-commit tag for pages that only ever hosted the chain itself.
///
/// No reader snapshot traverses the free list, so its superseded chain pages
/// are not gated behind reader pins the way data-page frees are. Real commit
/// ids start at 1, so this sentinel sits below every reclamation floor and the
/// pages are recyclable as soon as the header that supersedes them is durable.
pub const CHAIN_METADATA_CID: u64 = 0;

/// Number of `(commit_id, page_id)` entries one free-list page can hold.
#[must_use]
pub const fn chain_capacity(page_size: usize) -> usize {
    (body_capacity(page_size) - PAGE_HEADER_LEN) / ENTRY_LEN
}

/// Decode a chain page's header into `(next chain page id, entry count)`.
///
/// The count is validated against what the page body can physically hold: an
/// on-disk count above capacity cannot come from
/// [`write_chain`](super::write::write_chain) (which caps chunks at capacity),
/// so the page under the `Free` kind byte holds foreign or torn content.
/// Surfacing corruption here is what keeps the entry slicing below from
/// overrunning — a panic there poisons the pager mutex and wedges every
/// subsequent commit.
pub(crate) fn decode_chain_header(body: &[u8]) -> Result<(u64, usize)> {
    if body.len() < PAGE_HEADER_LEN {
        return Err(PagedbError::corruption(
            crate::errors::CorruptionDetail::CatalogRowInvalid {
                field: "freelist chain page shorter than its header",
            },
        ));
    }
    let mut next_b = [0u8; 8];
    next_b.copy_from_slice(&body[0..8]);
    let next = u64::from_le_bytes(next_b);
    let mut cnt_b = [0u8; 4];
    cnt_b.copy_from_slice(&body[8..12]);
    let count = u32::from_le_bytes(cnt_b) as usize;
    if count > (body.len() - PAGE_HEADER_LEN) / ENTRY_LEN {
        return Err(PagedbError::corruption(
            crate::errors::CorruptionDetail::CatalogRowInvalid {
                field: "freelist chain page entry count exceeds capacity",
            },
        ));
    }
    Ok((next, count))
}

/// Decode entry `index` out of a chain page body.
///
/// Bounds are re-checked rather than assumed from
/// [`decode_chain_header`]'s validation: this runs under the pager mutex on
/// the commit path, so an out-of-range slice would panic while holding it and
/// poison every later commit. A short body is corruption, reported as such.
pub(crate) fn decode_entry(body: &[u8], index: usize) -> Result<(u64, u64)> {
    let offset = PAGE_HEADER_LEN + index * ENTRY_LEN;
    let slot = body.get(offset..offset + ENTRY_LEN).ok_or_else(|| {
        PagedbError::corruption(crate::errors::CorruptionDetail::CatalogRowInvalid {
            field: "freelist chain page entry runs past the page body",
        })
    })?;
    let mut cid_b = [0u8; 8];
    cid_b.copy_from_slice(&slot[0..8]);
    let mut pid_b = [0u8; 8];
    pid_b.copy_from_slice(&slot[8..16]);
    Ok((u64::from_le_bytes(cid_b), u64::from_le_bytes(pid_b)))
}
