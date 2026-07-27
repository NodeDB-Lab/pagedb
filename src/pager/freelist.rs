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
/// on-disk count above capacity cannot come from [`write_chain`] (which caps
/// chunks at capacity), so the page under the `Free` kind byte holds foreign or
/// torn content. Surfacing corruption here is what keeps the entry slicing
/// below from overrunning — a panic there poisons the pager mutex and wedges
/// every subsequent commit.
fn decode_chain_header(body: &[u8]) -> Result<(u64, usize)> {
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

/// Count the `(commit_id, page_id)` entries the chain rooted at `head` holds,
/// without materialising them. `head == 0` is an empty chain.
///
/// The counting counterpart to [`read_chain`], for callers that need only the
/// depth. Collecting the entries to take their length would size an allocation
/// by how many pages the durable free list is carrying, which grows with the
/// database; this keeps the resident cost at one page guard.
///
/// `page_id_bound` is the allocator's `next_page_id`. Chain pages are real
/// allocated page ids, so a chain that visits more than `page_id_bound` pages
/// must by pigeonhole have revisited one — that bound stands in for the visited
/// set [`read_chain`] keeps, which is itself proportional to the chain length.
pub async fn count_chain<V: Vfs + Clone>(
    pager: &Pager<V>,
    realm_id: RealmId,
    head: u64,
    page_id_bound: u64,
) -> Result<u64> {
    let mut total: u64 = 0;
    let mut steps: u64 = 0;
    let mut page = head;
    while page != 0 {
        if steps >= page_id_bound {
            return Err(PagedbError::page_chain_cycle("free_list", page));
        }
        steps += 1;
        let guard = pager.read_main_page(page, realm_id, PageKind::Free).await?;
        let (next, count) = decode_chain_header(guard.body_ref())?;
        total = total.saturating_add(count as u64);
        drop(guard);
        page = next;
    }
    Ok(total)
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
    let mut seen = HashSet::new();
    let mut page = head;
    while page != 0 {
        if !seen.insert(page) {
            return Err(PagedbError::page_chain_cycle("free_list", page));
        }
        let guard = pager.read_main_page(page, realm_id, PageKind::Free).await?;
        let body = guard.body_ref();
        let (next, count) = decode_chain_header(body)?;
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use crate::crypto::CipherId;
    use crate::crypto::kdf::derive_mk;
    use crate::pager::PagerConfig;
    use crate::vfs::memory::MemVfs;

    use super::*;

    const PAGE: usize = 4096;
    const REALM: RealmId = RealmId::new([0xF1; 16]);

    async fn test_pager() -> Arc<Pager<MemVfs>> {
        let mk = derive_mk(&[0xF2; 32], &[0u8; 16], 0).unwrap();
        let config = PagerConfig {
            page_size: PAGE,
            buffer_pool_pages: 16,
            segment_cache_pages: 16,
            cipher_id: CipherId::Aes256Gcm,
            mk_epoch: 0,
            main_db_file_id: [0xF3; 16],
            main_db_path: "/main.db".into(),
            anchor_budget: 1_000_000,
            dek_lru_capacity: 16,
            observer_retry_count: 0,
            metrics_enabled: true,
        };
        Arc::new(Pager::open(MemVfs::new(), mk, config).await.unwrap())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn read_chain_rejects_cycle_without_hanging() {
        let pager = test_pager().await;
        let mut body = vec![0u8; body_capacity(PAGE)];
        body[0..8].copy_from_slice(&10u64.to_le_bytes());
        pager
            .write_main_page(10, REALM, PageKind::Free, &body)
            .await
            .unwrap();

        let error = tokio::time::timeout(Duration::from_secs(1), read_chain(&pager, REALM, 10))
            .await
            .expect("cycle detection should return before timeout")
            .expect_err("free-list cycles must be corruption");
        assert!(
            matches!(
                error,
                PagedbError::Corruption(crate::errors::CorruptionDetail::PageChainCycle {
                    structure: "free_list",
                    page_id: 10,
                })
            ),
            "expected a free-list PageChainCycle naming page 10, got {error:?}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn count_chain_rejects_cycle_without_hanging() {
        let pager = test_pager().await;
        let mut body = vec![0u8; body_capacity(PAGE)];
        body[0..8].copy_from_slice(&10u64.to_le_bytes());
        pager
            .write_main_page(10, REALM, PageKind::Free, &body)
            .await
            .unwrap();

        let error =
            tokio::time::timeout(Duration::from_secs(1), count_chain(&pager, REALM, 10, 11))
                .await
                .expect("the page-id bound should end the walk before timeout")
                .expect_err("free-list cycles must be corruption");
        assert!(
            matches!(
                error,
                PagedbError::Corruption(crate::errors::CorruptionDetail::PageChainCycle {
                    structure: "free_list",
                    page_id: 10,
                })
            ),
            "expected a free-list PageChainCycle naming page 10, got {error:?}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn count_chain_matches_read_chain_across_pages() {
        let pager = test_pager().await;
        let cap = chain_capacity(PAGE);
        let entries: Vec<(u64, u64)> = (0..(cap * 2 + 3) as u64).map(|i| (i, i + 100)).collect();
        let chain_pages: Vec<u64> = vec![20, 21, 22];
        let head = write_chain(&pager, REALM, PAGE, &chain_pages, &entries)
            .await
            .unwrap();

        let (read, _) = read_chain(&pager, REALM, head).await.unwrap();
        let counted = count_chain(&pager, REALM, head, 64).await.unwrap();
        assert_eq!(counted, read.len() as u64);
        assert_eq!(counted, entries.len() as u64);
    }
}
