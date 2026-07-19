//! Durable free-page list, stored as a chain of `PageKind::Free` pages rooted
//! at the A/B header's `free_list_root` slot — outside the catalog B+ tree.
//!
//! Keeping the free list out of the catalog is what makes free-page recycling
//! both **durable** (it survives an unclean shutdown — the chain is committed
//! atomically with the header swap) and **bounded** (maintaining it never
//! copies-on-writes the catalog tree, so it adds no per-commit catalog churn).
//!
//! Each entry is a `(commit_id, page_id)` pair: `commit_id` is the commit that
//! freed the page, used at `begin_write` to decide which pages are below the
//! reclamation floor (observable by no reader and no retained-history root) and
//! therefore safe to recycle now. The chain stores *every* free page — those
//! still pinned are simply carried forward until the floor advances past them.
//!
//! Page body layout (`PageKind::Free`):
//! ```text
//! [0..8)   next chain page id (LE u64; 0 = end of chain)
//! [8..12)  entry count in this page (LE u32)
//! [12..)   `count` × (commit_id LE u64 ‖ page_id LE u64)
//! ```

use std::collections::HashSet;

use crate::pager::Pager;
use crate::pager::format::data_page::body_capacity;
use crate::pager::format::page_kind::PageKind;
use crate::vfs::Vfs;
use crate::{PagedbError, RealmId, Result};

const ENTRY_LEN: usize = 16;
const PAGE_HEADER_LEN: usize = 12;

/// Number of `(commit_id, page_id)` entries one free-list page can hold.
#[must_use]
pub const fn chain_capacity(page_size: usize) -> usize {
    (body_capacity(page_size) - PAGE_HEADER_LEN) / ENTRY_LEN
}

/// Walk the free-list chain from `head`, returning all `(commit_id, page_id)`
/// entries and the list of page ids the chain itself occupies. `head == 0` is
/// an empty chain.
pub async fn read_chain<V: Vfs + Clone>(
    pager: &Pager<V>,
    realm_id: RealmId,
    head: u64,
) -> Result<(Vec<(u64, u64)>, Vec<u64>)> {
    let mut entries = Vec::new();
    let mut chain_pages = Vec::new();
    let mut page = head;
    while page != 0 {
        let guard = pager.read_main_page(page, realm_id, PageKind::Free).await?;
        let body = guard.body_ref();
        let mut next_b = [0u8; 8];
        next_b.copy_from_slice(&body[0..8]);
        let next = u64::from_le_bytes(next_b);
        let mut cnt_b = [0u8; 4];
        cnt_b.copy_from_slice(&body[8..12]);
        let count = u32::from_le_bytes(cnt_b) as usize;
        if count > (body.len().saturating_sub(PAGE_HEADER_LEN)) / ENTRY_LEN {
            // On-disk count cannot come from write_chain (which caps chunks at
            // capacity): the page under the Free kind byte holds foreign or
            // torn content. Surface corruption instead of panicking on the
            // slice overrun below — a panic here poisons the pager mutex and
            // wedges every subsequent commit.
            return Err(PagedbError::corruption(
                crate::errors::CorruptionDetail::CatalogRowInvalid {
                    field: "freelist chain page entry count exceeds capacity",
                },
            ));
        }
        for i in 0..count {
            let off = PAGE_HEADER_LEN + i * ENTRY_LEN;
            let mut cid_b = [0u8; 8];
            cid_b.copy_from_slice(&body[off..off + 8]);
            let mut pid_b = [0u8; 8];
            pid_b.copy_from_slice(&body[off + 8..off + 16]);
            entries.push((u64::from_le_bytes(cid_b), u64::from_le_bytes(pid_b)));
        }
        chain_pages.push(page);
        page = next;
    }
    Ok((entries, chain_pages))
}

/// Persist `entries` as a fresh chain, returning the new head page id and the
/// updated `next_page` cursor.
///
/// Chain pages are drawn first from `host_candidates` — pages that are already
/// free and observable by no snapshot, hence safe to overwrite — and only then
/// bump-allocated from `next_page`. A carved host is removed from the persisted
/// entries (it now holds the chain itself). The caller MUST ensure
/// `host_candidates` are a subset of `entries`' pages and disjoint from any
/// live page or the old chain's own pages (which must stay readable until the
/// header swap).
pub async fn rewrite_chain<V: Vfs + Clone>(
    pager: &Pager<V>,
    realm_id: RealmId,
    page_size: usize,
    mut entries: Vec<(u64, u64)>,
    host_candidates: Vec<u64>,
    next_page: u64,
) -> Result<(u64, u64)> {
    let cap = chain_capacity(page_size);
    let total = entries.len();
    let mut next = next_page;
    let mut carved: HashSet<u64> = HashSet::new();
    let mut chain_pages: Vec<u64> = Vec::new();
    let mut hosts = host_candidates.into_iter();
    loop {
        let remaining = total - carved.len();
        let need = if remaining == 0 {
            0
        } else {
            remaining.div_ceil(cap)
        };
        if chain_pages.len() >= need {
            break;
        }
        // Carve a host only while at least one entry would remain afterwards:
        // carving the final entry would leave the chain page with nothing to
        // store and orphan the host (no longer an entry, never a chain page).
        let host = if remaining > 1 { hosts.next() } else { None };
        if let Some(h) = host {
            carved.insert(h);
            chain_pages.push(h);
        } else {
            chain_pages.push(next);
            next += 1;
        }
    }
    entries.retain(|(_, pid)| !carved.contains(pid));
    let head = write_chain(pager, realm_id, page_size, &chain_pages, &entries).await?;
    Ok((head, next))
}

/// Write `entries` across the supplied `chain_pages` (which must provide enough
/// capacity: `chain_pages.len() * chain_capacity(page_size) >= entries.len()`),
/// linking them into a chain. Returns the new head page id, or `0` when there
/// is nothing to write. The pages are inserted into the pager's dirty set; the
/// caller flushes and commits the header (carrying the returned head).
///
/// Every supplied page is written: when the entries run out before the pages
/// do (a host carve in [`rewrite_chain`] can shrink the entry set across a
/// page boundary), the trailing pages carry zero entries but stay properly
/// linked. Skipping them instead would leave the last data page's `next`
/// pointing at a page whose on-disk bytes were never rewritten — a durable
/// chain pointer into stale content, which either fails authentication at the
/// next chain read (wedging every subsequent commit) or, worse, still
/// authenticates as an older chain generation and silently resurrects free
/// entries for pages that are live again.
pub async fn write_chain<V: Vfs + Clone>(
    pager: &Pager<V>,
    realm_id: RealmId,
    page_size: usize,
    chain_pages: &[u64],
    entries: &[(u64, u64)],
) -> Result<u64> {
    if entries.is_empty() {
        return Ok(0);
    }
    let cap = chain_capacity(page_size);
    let body_len = body_capacity(page_size);
    debug_assert!(chain_pages.len() * cap >= entries.len());
    let mut written = 0usize;
    for (i, &page_id) in chain_pages.iter().enumerate() {
        let chunk = &entries[written..(written + cap).min(entries.len())];
        let next = chain_pages.get(i + 1).copied().unwrap_or(0);
        let mut body = vec![0u8; body_len];
        body[0..8].copy_from_slice(&next.to_le_bytes());
        let chunk_len = u32::try_from(chunk.len())
            .map_err(|_| PagedbError::Io(std::io::Error::other("free-list chunk_len overflow")))?;
        body[8..12].copy_from_slice(&chunk_len.to_le_bytes());
        for (j, (cid, pid)) in chunk.iter().enumerate() {
            let off = PAGE_HEADER_LEN + j * ENTRY_LEN;
            body[off..off + 8].copy_from_slice(&cid.to_le_bytes());
            body[off + 8..off + 16].copy_from_slice(&pid.to_le_bytes());
        }
        pager
            .write_main_page(page_id, realm_id, PageKind::Free, &body)
            .await?;
        written += chunk.len();
    }
    Ok(chain_pages[0])
}
