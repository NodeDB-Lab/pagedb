//! Writing chain pages, and rewriting a prefix of the chain onto a retained
//! tail.

use std::collections::HashSet;

use crate::pager::Pager;
use crate::pager::format::data_page::body_capacity;
use crate::pager::format::page_kind::PageKind;
use crate::vfs::Vfs;
use crate::{PagedbError, RealmId, Result};

use super::layout::{ENTRY_LEN, PAGE_HEADER_LEN, chain_capacity};

/// Persist `entries` as a fresh chain prefix spliced onto `tail`, returning the
/// new head page id and the updated `next_page` cursor.
///
/// `tail` is the head of the part of the old chain that is *not* being
/// rewritten (`0` when the whole chain is). Those pages keep their bytes and
/// their links; the last fresh page simply points at the first of them. That
/// works without any format change because a chain page names only page ids and
/// carries its own `next` and count — no page encodes another page's offset,
/// and the header publishes only the head.
///
/// Chain pages are drawn first from `host_candidates` — pages that are already
/// free and observable by no snapshot, hence safe to overwrite — and only then
/// bump-allocated from `next_page`. A carved host is removed from the persisted
/// entries (it now holds the chain itself). The caller MUST ensure
/// `host_candidates` are a subset of `entries`' pages and disjoint from any
/// live page, from the retained tail's own pages, and from the rewritten
/// prefix's pages (which must stay readable until the header swap).
pub async fn rewrite_chain<V: Vfs + Clone>(
    pager: &Pager<V>,
    realm_id: RealmId,
    page_size: usize,
    mut entries: Vec<(u64, u64)>,
    host_candidates: Vec<u64>,
    next_page: u64,
    tail: u64,
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
    let head = write_chain(pager, realm_id, page_size, &chain_pages, &entries, tail).await?;
    Ok((head, next))
}

/// Write `entries` across the supplied `chain_pages` (which must provide enough
/// capacity: `chain_pages.len() * chain_capacity(page_size) >= entries.len()`),
/// linking them into a chain whose last page points at `tail`. Returns the new
/// head page id. The pages are inserted into the pager's dirty set; the caller
/// flushes and commits the header (carrying the returned head).
///
/// With no entries to write the head *is* `tail`: the retained remainder is
/// published directly. Returning `0` there instead would unpublish a tail that
/// still names free pages, losing every one of them.
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
    tail: u64,
) -> Result<u64> {
    if entries.is_empty() {
        return Ok(tail);
    }
    let cap = chain_capacity(page_size);
    let body_len = body_capacity(page_size);
    debug_assert!(chain_pages.len() * cap >= entries.len());
    let mut written = 0usize;
    for (i, &page_id) in chain_pages.iter().enumerate() {
        let chunk = &entries[written..(written + cap).min(entries.len())];
        let next = chain_pages.get(i + 1).copied().unwrap_or(tail);
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
    let head = chain_pages.first().copied().unwrap_or(tail);
    Ok(head)
}
