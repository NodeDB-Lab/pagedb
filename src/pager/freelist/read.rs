//! Readers over the free-list chain, all built on one cursor that holds at
//! most a single page of entries at a time.

use crate::pager::Pager;
use crate::pager::format::page_kind::PageKind;
use crate::vfs::Vfs;
use crate::{PagedbError, RealmId, Result};

use super::layout::{decode_chain_header, decode_entry};

/// What a chain page's header says about everything from that page onward.
///
/// Read in one page access, never by traversal — see the layout module for why
/// the page carries its own suffix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainSummary {
    /// Entries the chain holds from this page down.
    pub entries: u64,
    /// Largest freeing-commit id from this page down. Below every real
    /// reclamation floor when the suffix holds only chain-metadata sentinels.
    pub max_cid: u64,
    /// Smallest freeing-commit id from this page down; `u64::MAX` for an empty
    /// suffix, so emptiness never reads as entirely-stuck.
    pub min_cid: u64,
}

impl Default for ChainSummary {
    fn default() -> Self {
        Self {
            entries: 0,
            max_cid: 0,
            min_cid: u64::MAX,
        }
    }
}

/// The remainder of a chain that a rewrite splices onto rather than rewrites,
/// named together with what it holds.
///
/// The pairing is the point. A page's summary covers everything below it, so a
/// page cannot be encoded without knowing what its successor summarises;
/// carrying the two together makes that a thing the caller states rather than
/// something the writer rediscovers by reading the tail back — which would put
/// hidden IO inside the write and require the tail to already be durable.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ChainTail {
    /// First page of the retained remainder; `0` when there is none.
    pub head: u64,
    /// What that remainder holds, from `head` down.
    pub summary: ChainSummary,
}

impl ChainTail {
    /// No retained remainder: the chain being written ends where it stops.
    ///
    /// Serves the native-only deferred-free reclaim path (`reclaim`); gate it
    /// the same way.
    #[cfg(any(test, not(target_arch = "wasm32")))]
    pub const EMPTY: Self = Self {
        head: 0,
        summary: ChainSummary {
            entries: 0,
            max_cid: 0,
            min_cid: u64::MAX,
        },
    };
}

/// The summary carried by the chain rooted at `head`, or the empty summary when
/// `head` is `0`.
///
/// One page read regardless of chain length: this is the primitive that keeps
/// free-list questions off the write path's cost curve.
pub async fn read_chain_summary<V: Vfs + Clone>(
    pager: &Pager<V>,
    realm_id: RealmId,
    head: u64,
) -> Result<ChainSummary> {
    if head == 0 {
        return Ok(ChainSummary::default());
    }
    let guard = pager.read_main_page(head, realm_id, PageKind::Free).await?;
    let header = decode_chain_header(guard.body_ref())?;
    Ok(ChainSummary {
        entries: header.suffix_entries,
        max_cid: header.suffix_max_cid,
        min_cid: header.suffix_min_cid,
    })
}

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
    last_summary: ChainSummary,
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
            last_summary: ChainSummary::default(),
        }
    }

    /// The suffix summary declared by the page the last [`Self::advance`]
    /// returned.
    #[must_use]
    pub fn last_summary(&self) -> ChainSummary {
        self.last_summary
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
            let header = decode_chain_header(body)?;
            self.last_summary = ChainSummary {
                entries: header.suffix_entries,
                max_cid: header.suffix_max_cid,
                min_cid: header.suffix_min_cid,
            };
            self.entries.reserve(header.count);
            for index in 0..header.count {
                self.entries.push(decode_entry(body, index)?);
            }
            header.next
        };
        self.tortoise = next;

        // Two hare links per tortoise link. The hare reaching the chain's
        // terminator is not a result on its own — the tortoise still has to
        // walk the rest — so it just parks at 0.
        for _ in 0..2 {
            if self.hare == 0 {
                break;
            }
            let hare_next = read_chain_link(pager, realm_id, self.hare).await?;
            self.hare = hare_next;
        }
        if self.hare != 0 && self.hare == self.tortoise {
            return Err(PagedbError::page_chain_cycle("free_list", self.hare));
        }
        Ok(Some(page_id))
    }
}

/// Read one chain page and return where the chain continues.
async fn read_chain_link<V: Vfs + Clone>(
    pager: &Pager<V>,
    realm_id: RealmId,
    page_id: u64,
) -> Result<u64> {
    let guard = pager
        .read_main_page(page_id, realm_id, PageKind::Free)
        .await?;
    Ok(decode_chain_header(guard.body_ref())?.next)
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
    /// The retained remainder and what it holds; empty when the walk consumed
    /// the whole chain. A rewritten prefix links its last page here, which is
    /// why the tail needs no rewrite of its own: every one of its pages already
    /// carries its own `next`, count and suffix summary.
    pub tail: ChainTail,
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
    let tail = walk.tail();
    Ok(ChainPrefix {
        entries,
        chain_pages,
        tail: ChainTail {
            head: tail,
            // One page read, and only when a remainder exists: the rewrite that
            // follows must state what it splices onto, and the walk stopped
            // just short of the page that says so.
            summary: read_chain_summary(pager, realm_id, tail).await?,
        },
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
        prefix.tail.head, 0,
        "an unbounded prefix walk must consume the whole chain"
    );
    Ok((prefix.entries, prefix.chain_pages))
}

/// Count the `(commit_id, page_id)` entries the chain rooted at `head` holds.
/// `head == 0` is an empty chain.
///
/// One page read: the head's suffix summary covers the whole chain by
/// definition. This is reached from `Db::stats`, which an embedder may call per
/// request — a walk here would put the size of the store on the cost of asking
/// how big it is.
pub async fn count_chain<V: Vfs + Clone>(
    pager: &Pager<V>,
    realm_id: RealmId,
    head: u64,
) -> Result<u64> {
    Ok(read_chain_summary(pager, realm_id, head).await?.entries)
}

/// Count the chain's entries whose freeing commit is at or above `floor` — the
/// backlog genuinely stuck behind a reader pin, as opposed to the drainable
/// remainder.
///
/// This exists because the reader-stall threshold is defined over the *whole*
/// chain, which a bounded prefix walk cannot produce on its own. It is exact,
/// and it does not pay for the whole chain to be so: each page declares the
/// largest freeing commit in everything from itself down, so the walk stops at
/// the first page whose suffix cannot reach the floor. Everything past that
/// point is drainable by construction and contributes nothing.
///
/// The cost is therefore proportional to the *stuck* region, which is the
/// quantity the reader-stall policy exists to bound — not to how many pages are
/// free in the store. A commit must cost what it changed.
///
/// The walk no longer authenticates the whole chain on every commit as a side
/// effect. Torn or cyclic pages beyond the stuck region are caught by `fsck` and
/// by the window as it sweeps forward; paying an O(store) read on every commit
/// to find them sooner is the cost this exists to remove.
pub async fn count_at_or_above_floor<V: Vfs + Clone>(
    pager: &Pager<V>,
    realm_id: RealmId,
    head: u64,
    floor: u64,
) -> Result<u64> {
    let mut walk = ChainWalk::new(head);
    let mut total: u64 = 0;
    while walk.advance(pager, realm_id).await?.is_some() {
        let summary = walk.last_summary();
        // Nothing from here down can reach the floor: no entry below is stuck.
        if summary.max_cid < floor {
            break;
        }
        // Everything from here down is at or above it: the suffix total is the
        // answer, without reading any of it. This is what keeps a deep backlog
        // — the state the stall policy exists for — from costing a page read
        // per page of itself on every commit.
        if summary.min_cid >= floor {
            return Ok(total.saturating_add(summary.entries));
        }
        // Straddles the floor, so this page is counted entry by entry.
        let stuck = walk
            .entries()
            .iter()
            .filter(|(commit_id, _)| *commit_id >= floor)
            .count() as u64;
        total = total.saturating_add(stuck);
    }
    Ok(total)
}
