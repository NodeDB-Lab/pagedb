//! Readers over the free-list chain, all built on one cursor that holds at
//! most a single page of entries at a time.

use crate::pager::Pager;
use crate::pager::format::page_kind::PageKind;
use crate::vfs::Vfs;
use crate::{PagedbError, RealmId, Result};

use super::layout::{decode_chain_header, decode_entry};

/// A cursor that walks the chain one page at a time.
///
/// Resident cost is one page of entries plus two page cursors, regardless of
/// how long the chain is. Callers that need the whole chain materialised
/// ([`read_chain`]) opt into that themselves; nothing on the write hot path
/// does.
///
/// Termination on a cyclic chain comes from Floyd's tortoise-and-hare: the hare
/// takes two links for the tortoise's one, so on a chain that loops it laps the
/// tortoise within one turn of the cycle, and on a chain that ends the tortoise
/// simply reaches the terminator. Both bounds are properties of the chain
/// itself. That is the whole point of the shape: a visited-set detector costs
/// one entry per chain page — the very residency this module exists to bound —
/// and any guard phrased as "stop after N steps" is only as good as the N its
/// caller happened to pass, with a caller that has no better number than the
/// page-id space spinning for 2^64 links before concluding anything.
pub struct ChainWalk {
    tortoise: u64,
    hare: u64,
    entries: Vec<(u64, u64)>,
    decode_entries: bool,
    last_count: usize,
}

impl ChainWalk {
    /// Start a walk at `head` that decodes each page's entries.
    /// `head == 0` is an empty chain.
    #[must_use]
    pub fn new(head: u64) -> Self {
        Self {
            tortoise: head,
            hare: head,
            entries: Vec::new(),
            decode_entries: true,
            last_count: 0,
        }
    }

    /// Start a walk that reads only page headers. Callers that need nothing
    /// but depth or entry counts skip the per-entry decode entirely.
    #[must_use]
    pub fn headers_only(head: u64) -> Self {
        Self {
            decode_entries: false,
            ..Self::new(head)
        }
    }

    /// Entry count declared by the page the last [`Self::advance`] returned,
    /// available whether or not the entries themselves were decoded.
    #[must_use]
    pub fn last_count(&self) -> usize {
        self.last_count
    }

    /// The page id the next [`Self::advance`] will visit; `0` once the walk has
    /// consumed the chain. After a bounded walk this is the head of the
    /// **retained tail** — the self-describing remainder a prefix rewrite
    /// splices onto and never touches.
    #[must_use]
    pub fn tail(&self) -> u64 {
        self.tortoise
    }

    /// Entries carried by the page the last [`Self::advance`] returned.
    #[must_use]
    pub fn entries(&self) -> &[(u64, u64)] {
        &self.entries
    }

    /// Advance one page, returning the page id just visited, or `None` at the
    /// end of the chain.
    pub async fn advance<V: Vfs + Clone>(
        &mut self,
        pager: &Pager<V>,
        realm_id: RealmId,
    ) -> Result<Option<u64>> {
        self.entries.clear();
        let page_id = self.tortoise;
        if page_id == 0 {
            return Ok(None);
        }
        let next = {
            let guard = pager
                .read_main_page(page_id, realm_id, PageKind::Free)
                .await?;
            let body = guard.body_ref();
            let (next, count) = decode_chain_header(body)?;
            self.last_count = count;
            if self.decode_entries {
                self.entries.reserve(count);
                for index in 0..count {
                    self.entries.push(decode_entry(body, index)?);
                }
            }
            next
        };
        self.tortoise = next;

        // Two hare links per tortoise link. The hare reaching the chain's
        // terminator is not a result on its own — the tortoise still has to
        // walk the rest — so it just parks at 0.
        for _ in 0..2 {
            if self.hare == 0 {
                break;
            }
            let (hare_next, _) = read_chain_link(pager, realm_id, self.hare).await?;
            self.hare = hare_next;
        }
        if self.hare != 0 && self.hare == self.tortoise {
            return Err(PagedbError::page_chain_cycle("free_list", self.hare));
        }
        Ok(Some(page_id))
    }
}

/// Read one chain page and return its `(next, entry count)` header.
async fn read_chain_link<V: Vfs + Clone>(
    pager: &Pager<V>,
    realm_id: RealmId,
    page_id: u64,
) -> Result<(u64, usize)> {
    let guard = pager
        .read_main_page(page_id, realm_id, PageKind::Free)
        .await?;
    decode_chain_header(guard.body_ref())
}

/// A bounded window of the chain, plus the page id where the untouched
/// remainder begins.
#[derive(Debug)]
pub struct ChainPrefix {
    /// `(commit_id, page_id)` entries carried by the scanned pages.
    pub entries: Vec<(u64, u64)>,
    /// Page ids the scanned window itself occupies. They become free once a
    /// rewrite supersedes them.
    pub chain_pages: Vec<u64>,
    /// Head of the retained tail; `0` when the walk consumed the whole chain.
    /// A rewritten prefix links its last page here, which is why the tail needs
    /// no rewrite of its own: every one of its pages already carries its own
    /// `next` and count.
    pub tail: u64,
}

/// Walk at most `max_pages` pages from `head`, returning what they carry and
/// where the untouched remainder starts.
///
/// This is the write path's loader. The resident cost is
/// `max_pages × chain_capacity(page_size)` entries — a caller-chosen constant,
/// independent of how many pages are free in the store.
///
/// Only the pages this returns may feed the allocator cache. An id handed to
/// the allocator that this walk did not locate could not be deleted from the
/// chain by the rewrite that follows, so the unscanned tail would still name
/// it: one page id in the chain twice, later handed to two different live
/// structures. A leak is recoverable; that is not.
pub async fn read_chain_prefix<V: Vfs + Clone>(
    pager: &Pager<V>,
    realm_id: RealmId,
    head: u64,
    max_pages: usize,
) -> Result<ChainPrefix> {
    let mut walk = ChainWalk::new(head);
    let mut entries = Vec::new();
    let mut chain_pages = Vec::new();
    while chain_pages.len() < max_pages {
        let Some(page_id) = walk.advance(pager, realm_id).await? else {
            break;
        };
        entries.extend_from_slice(walk.entries());
        chain_pages.push(page_id);
    }
    Ok(ChainPrefix {
        entries,
        chain_pages,
        tail: walk.tail(),
    })
}

/// Walk the whole chain from `head`, returning all `(commit_id, page_id)`
/// entries and the list of page ids the chain itself occupies. `head == 0` is
/// an empty chain.
///
/// Residency is proportional to the number of free pages, so this belongs only
/// to callers that must reason about the complete entry set (a follower's
/// reclaim fold, an export's published-page set, `fsck`). The write path uses
/// [`read_chain_prefix`].
pub async fn read_chain<V: Vfs + Clone>(
    pager: &Pager<V>,
    realm_id: RealmId,
    head: u64,
) -> Result<(Vec<(u64, u64)>, Vec<u64>)> {
    let prefix = read_chain_prefix(pager, realm_id, head, usize::MAX).await?;
    debug_assert_eq!(
        prefix.tail, 0,
        "an unbounded prefix walk must consume the whole chain"
    );
    Ok((prefix.entries, prefix.chain_pages))
}

/// Count the `(commit_id, page_id)` entries the chain rooted at `head` holds,
/// without materialising them. `head == 0` is an empty chain.
pub async fn count_chain<V: Vfs + Clone>(
    pager: &Pager<V>,
    realm_id: RealmId,
    head: u64,
) -> Result<u64> {
    let mut walk = ChainWalk::headers_only(head);
    let mut total: u64 = 0;
    while walk.advance(pager, realm_id).await?.is_some() {
        total = total.saturating_add(walk.last_count() as u64);
    }
    Ok(total)
}

/// Count the chain's entries whose freeing commit is at or above `floor` — the
/// backlog genuinely stuck behind a reader pin, as opposed to the drainable
/// remainder.
///
/// This exists because the reader-stall threshold is defined over the *whole*
/// chain and a bounded prefix walk cannot produce that number. Streaming it
/// bounds **memory**, not IO: the resident cost is one page of entries, but the
/// read cost stays proportional to the number of chain pages. Saying otherwise
/// would require a durable aggregate in the header, which is a format change
/// this deliberately does not make.
pub async fn count_at_or_above_floor<V: Vfs + Clone>(
    pager: &Pager<V>,
    realm_id: RealmId,
    head: u64,
    floor: u64,
) -> Result<u64> {
    let mut walk = ChainWalk::new(head);
    let mut total: u64 = 0;
    while walk.advance(pager, realm_id).await?.is_some() {
        let stuck = walk
            .entries()
            .iter()
            .filter(|(commit_id, _)| *commit_id >= floor)
            .count() as u64;
        total = total.saturating_add(stuck);
    }
    Ok(total)
}
