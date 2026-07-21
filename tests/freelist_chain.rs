//! Round-trip tests for the durable free-list chain writer, focused on the
//! host-carving boundary: a host carve shrinks the entry set, so the chosen
//! chain pages can outnumber the pages the remaining entries need. Every
//! chosen page must still be written and linked — an unwritten-but-linked
//! page is a durable pointer into stale bytes — and every input page id must
//! come back out either as an entry or as a chain page (no loss, no leak).

use std::collections::BTreeSet;
use std::sync::Arc;

use pagedb::RealmId;
use pagedb::crypto::CipherId;
use pagedb::crypto::kdf::derive_mk;
use pagedb::pager::freelist::{chain_capacity, read_chain, rewrite_chain};
use pagedb::pager::{Pager, PagerConfig};
use pagedb::vfs::memory::MemVfs;

const PAGE: usize = 4096;
const REALM: RealmId = RealmId::new([1; 16]);

async fn fresh_pager() -> Arc<Pager<MemVfs>> {
    let mk = derive_mk(&[1u8; 32], &[0u8; 16], 0).unwrap();
    let cfg = PagerConfig {
        page_size: PAGE,
        buffer_pool_pages: 64,
        segment_cache_pages: 64,
        cipher_id: CipherId::Aes256Gcm,
        mk_epoch: 0,
        main_db_file_id: [0xAB; 16],
        main_db_path: "/main.db".into(),
        anchor_budget: 1_000_000,
        dek_lru_capacity: 16,
        observer_retry_count: 0,
        metrics_enabled: false,
    };
    Arc::new(Pager::open(MemVfs::new(), mk, cfg).await.unwrap())
}

/// Rewrite `total` entries with `host_count` host candidates drawn from the
/// entries' own pages, then read the chain back and check the accounting
/// invariants hold exactly.
async fn round_trip(total: u64, host_count: usize) {
    let pager = fresh_pager().await;
    let entries: Vec<(u64, u64)> = (0..total).map(|i| (7, 1000 + i)).collect();
    let original: BTreeSet<u64> = entries.iter().map(|&(_, pid)| pid).collect();
    let hosts: Vec<u64> = entries
        .iter()
        .take(host_count)
        .map(|&(_, pid)| pid)
        .collect();
    const BUMP_BASE: u64 = 500_000;

    let (head, new_next) = rewrite_chain(&pager, REALM, PAGE, entries, hosts, BUMP_BASE)
        .await
        .unwrap_or_else(|e| panic!("rewrite_chain(total={total}, hosts={host_count}): {e:?}"));

    // The whole chain must read back cleanly — every linked page written.
    let (got, chain_pages) = read_chain(&pager, REALM, head)
        .await
        .unwrap_or_else(|e| panic!("read_chain(total={total}, hosts={host_count}): {e:?}"));

    let got_pids: BTreeSet<u64> = got.iter().map(|&(_, pid)| pid).collect();
    let chain_set: BTreeSet<u64> = chain_pages.iter().copied().collect();

    // No page may be both stored-free and part of the chain's own storage.
    assert!(
        got_pids.is_disjoint(&chain_set),
        "total={total} hosts={host_count}: entry/chain overlap"
    );
    // Conservation: every original page id is either still an entry or now
    // hosts the chain; nothing disappears and nothing foreign appears.
    let carved_hosts: BTreeSet<u64> = chain_set
        .iter()
        .copied()
        .filter(|&p| p < BUMP_BASE)
        .collect();
    let mut reunited = got_pids.clone();
    reunited.extend(carved_hosts.iter().copied());
    assert_eq!(
        reunited, original,
        "total={total} hosts={host_count}: entries + carved hosts != input set"
    );
    // Bump-allocated chain pages must all lie in [BUMP_BASE, new_next).
    for &p in chain_set.iter().filter(|&&p| p >= BUMP_BASE) {
        assert!(p < new_next, "bump chain page {p} beyond returned cursor");
    }
}

/// The exact overshoot boundary: with `cap` entries per page, `cap + 2`
/// entries and two carvable hosts make the final carve drop the page need
/// after the second page was already chosen — the trailing page must still be
/// written and linked, not dangle.
#[tokio::test(flavor = "current_thread")]
async fn carve_boundary_trailing_page_is_written() {
    let cap = chain_capacity(PAGE) as u64;
    round_trip(cap + 2, 4).await;
}

/// Sweep entry counts across several page boundaries with and without hosts.
#[tokio::test(flavor = "current_thread")]
async fn chain_round_trip_sweep() {
    let cap = chain_capacity(PAGE) as u64;
    for total in [
        1,
        2,
        cap - 1,
        cap,
        cap + 1,
        cap + 2,
        2 * cap,
        2 * cap + 1,
        2 * cap + 2,
        3 * cap + 2,
    ] {
        for hosts in [0usize, 1, 2, 5] {
            round_trip(total, hosts).await;
        }
    }
}

/// Degenerate case: a single entry whose own page is the only host candidate
/// must not be carved into hosting an empty chain (which would orphan it).
#[tokio::test(flavor = "current_thread")]
async fn single_entry_sole_host_not_orphaned() {
    round_trip(1, 1).await;
}
