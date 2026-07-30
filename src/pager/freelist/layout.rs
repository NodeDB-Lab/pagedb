//! On-disk layout of a single `PageKind::Free` chain page.
//!
//! ```text
//! [0..8)   next chain page id (LE u64; 0 = end of chain)
//! [8..12)  entry count in this page (LE u32)
//! [12..20) suffix entry total: this page's entries plus every later page's
//! [20..28) suffix max commit id: over this page and every later page
//! [28..36) suffix min commit id: over this page and every later page
//! [36..)   `count` × (commit_id LE u64 ‖ page_id LE u64)
//! ```
//!
//! Nothing here names another page's *offset* — only its id — which is what
//! makes a page removable from the chain by rewriting the page that points at
//! it and nothing else.
//!
//! ## Why the page summarises its own suffix
//!
//! Every question the write path asks of the free list is an aggregate over the
//! chain from some page onward — how many entries are there, and could any of
//! them still be pinned. Answering those by traversal ties the cost to how many
//! pages are free in the store, which is to say to the size of the store, on a
//! path that should cost what the commit changed. Each page therefore carries
//! the answer for everything from itself down, and a reader takes it in one
//! page read:
//!
//! - `suffix_entries` on the head is the whole chain's entry count.
//! - `suffix_max_cid < floor` proves nothing from that page on can be stuck
//!   behind a reader pin, so a walk counting stuck entries stops there.
//! - `suffix_min_cid >= floor` proves *everything* from that page on is stuck,
//!   so the same walk takes `suffix_entries` and stops. Without this the walk
//!   would still visit every page of a large stuck backlog to count it entry by
//!   entry, which is the same cost curve one bound further out: deep retention
//!   holds a deep floor, and the backlog behind it grows with it.
//!
//! Between them, only pages that *straddle* the floor are ever descended into.
//!
//! Both are exact, not hints. A summary is written when a page is written and
//! the pages below it are already durable and immutable — a chain is only ever
//! rewritten at the head, spliced onto an untouched tail — so a page's suffix
//! can never go stale under it.

use crate::pager::format::data_page::body_capacity;
use crate::{PagedbError, Result};

pub(crate) const ENTRY_LEN: usize = 16;
pub(crate) const PAGE_HEADER_LEN: usize = 36;

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

/// A chain page's header: where the chain continues, what this page holds, and
/// what everything from this page onward holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ChainPageHeader {
    /// Next chain page id; `0` ends the chain.
    pub next: u64,
    /// Entries stored in this page.
    pub count: usize,
    /// Entries in this page plus every page after it.
    pub suffix_entries: u64,
    /// Largest freeing-commit id in this page or any page after it. `0` when
    /// the suffix holds nothing but chain-metadata sentinels, which is below
    /// every real reclamation floor.
    pub suffix_max_cid: u64,
    /// Smallest freeing-commit id in this page or any page after it.
    /// `u64::MAX` when the suffix is empty, so an empty suffix never reads as
    /// entirely-stuck.
    pub suffix_min_cid: u64,
}

/// Decode a chain page's header.
///
/// The count is validated against what the page body can physically hold: an
/// on-disk count above capacity cannot come from
/// [`write_chain`](super::write::write_chain) (which caps chunks at capacity),
/// so the page under the `Free` kind byte holds foreign or torn content.
/// Surfacing corruption here is what keeps the entry slicing below from
/// overrunning — a panic there poisons the pager mutex and wedges every
/// subsequent commit.
///
/// The suffix summary is checked against this page's own contribution for the
/// same reason: a suffix total below the entries the page itself carries cannot
/// have been written by [`write_chain`], and a reader that trusted it would
/// under-report the backlog the reader-stall policy is defined over. Both
/// fields are load-bearing for correctness, so neither is decoded on trust.
pub(crate) fn decode_chain_header(body: &[u8]) -> Result<ChainPageHeader> {
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
    let mut suffix_b = [0u8; 8];
    suffix_b.copy_from_slice(&body[12..20]);
    let suffix_entries = u64::from_le_bytes(suffix_b);
    let mut max_cid_b = [0u8; 8];
    max_cid_b.copy_from_slice(&body[20..28]);
    let suffix_max_cid = u64::from_le_bytes(max_cid_b);
    let mut min_cid_b = [0u8; 8];
    min_cid_b.copy_from_slice(&body[28..36]);
    let suffix_min_cid = u64::from_le_bytes(min_cid_b);
    if suffix_entries < count as u64 {
        return Err(PagedbError::corruption(
            crate::errors::CorruptionDetail::CatalogRowInvalid {
                field: "freelist chain page suffix total is below its own entry count",
            },
        ));
    }
    Ok(ChainPageHeader {
        next,
        count,
        suffix_entries,
        suffix_max_cid,
        suffix_min_cid,
    })
}

/// Encode a chain page header into the first [`PAGE_HEADER_LEN`] bytes of
/// `body`.
pub(crate) fn encode_chain_header(body: &mut [u8], header: ChainPageHeader) -> Result<()> {
    let count = u32::try_from(header.count)
        .map_err(|_| PagedbError::Io(std::io::Error::other("free-list chunk_len overflow")))?;
    body[0..8].copy_from_slice(&header.next.to_le_bytes());
    body[8..12].copy_from_slice(&count.to_le_bytes());
    body[12..20].copy_from_slice(&header.suffix_entries.to_le_bytes());
    body[20..28].copy_from_slice(&header.suffix_max_cid.to_le_bytes());
    body[28..36].copy_from_slice(&header.suffix_min_cid.to_le_bytes());
    Ok(())
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
