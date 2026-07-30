use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use crate::crypto::CipherId;
use crate::crypto::kdf::derive_mk;
use crate::pager::format::data_page::body_capacity;
use crate::pager::format::page_kind::PageKind;
use crate::pager::{Pager, PagerConfig};
use crate::vfs::memory::MemVfs;
use crate::{PagedbError, RealmId};

use super::layout::chain_capacity;
use super::read::{
    ChainTail, count_at_or_above_floor, count_chain, read_chain, read_chain_prefix,
    read_chain_summary,
};
use super::write::{rewrite_chain, write_chain};

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

/// Hand-lay a chain of `links.len()` pages, each carrying the entries it is
/// paired with, linked in order. Returns the head. One `write_chain` call per
/// page, so nothing is repacked and a sparse chain — the shape a real store
/// accumulates — can be built exactly.
///
/// Laid last page first, threading each page's [`ChainTail`] into the one that
/// links to it: a page summarises everything below it, so it cannot be written
/// before its successor exists. Production builds a chain the same way.
async fn lay_chain(pager: &Pager<MemVfs>, links: &[(u64, Vec<(u64, u64)>)]) -> u64 {
    let mut tail = ChainTail::EMPTY;
    for (host, entries) in links.iter().rev() {
        write_chain(pager, REALM, PAGE, &[*host], entries, tail)
            .await
            .unwrap();
        tail = ChainTail {
            head: *host,
            summary: read_chain_summary(pager, REALM, *host).await.unwrap(),
        };
    }
    tail.head
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

/// `count_chain` answers from the head's suffix summary, so it reads one page
/// however long the chain is. Asserted directly, because it is the property
/// that keeps `Db::stats` — which an embedder may call per request — off the
/// size of the store.
#[tokio::test(flavor = "current_thread")]
async fn count_chain_reads_one_page_however_long_the_chain() {
    let pager = test_pager().await;
    let links: Vec<(u64, Vec<(u64, u64)>)> =
        (0..24u64).map(|i| (20 + i, vec![(1, 500 + i)])).collect();
    let head = lay_chain(&pager, &links).await;

    let before = pager
        .inner
        .buffer_pool_hits
        .load(std::sync::atomic::Ordering::Relaxed)
        + pager
            .inner
            .buffer_pool_misses
            .load(std::sync::atomic::Ordering::Relaxed);
    let total = count_chain(&pager, REALM, head).await.unwrap();
    let reads = pager
        .inner
        .buffer_pool_hits
        .load(std::sync::atomic::Ordering::Relaxed)
        + pager
            .inner
            .buffer_pool_misses
            .load(std::sync::atomic::Ordering::Relaxed)
        - before;

    assert_eq!(total, links.len() as u64, "one entry per laid page");
    assert_eq!(reads, 1, "counting the chain must not walk it");
}

/// Rho shape: `20 → 21 → 22 → 21`. The head is not itself on the cycle, so
/// comparing every link against the head never fires, and the cycle is longer
/// than one link, so a self-loop check never fires either. Only a detector that
/// tracks relative progress ends this walk.
///
/// Asserted through the stall count rather than `count_chain`, which no longer
/// traverses: the readers that still walk the chain are the ones that must
/// terminate on a cycle. A backlog at or above the floor is what keeps this
/// walk going past its early exit, which is also the case where a cycle would
/// otherwise spin.
#[tokio::test(flavor = "current_thread")]
async fn a_stall_count_rejects_a_cycle_reached_through_a_tail() {
    let pager = test_pager().await;
    for (page_id, next) in [(20u64, 21u64), (21, 22), (22, 21)] {
        let mut body = vec![0u8; body_capacity(PAGE)];
        body[0..8].copy_from_slice(&next.to_le_bytes());
        // Two entries whose suffix straddles the floor, so neither summary
        // shortcut fires and the walk descends page by page until the cycle
        // detector stops it. A suffix wholly above or wholly below the floor is
        // answered without descending, and could never spin.
        body[8..12].copy_from_slice(&2u32.to_le_bytes());
        body[12..20].copy_from_slice(&2u64.to_le_bytes());
        body[20..28].copy_from_slice(&u64::MAX.to_le_bytes());
        body[28..36].copy_from_slice(&0u64.to_le_bytes());
        body[36..44].copy_from_slice(&u64::MAX.to_le_bytes());
        body[44..52].copy_from_slice(&(500 + page_id).to_le_bytes());
        body[52..60].copy_from_slice(&0u64.to_le_bytes());
        body[60..68].copy_from_slice(&(600 + page_id).to_le_bytes());
        pager
            .write_main_page(page_id, REALM, PageKind::Free, &body)
            .await
            .unwrap();
    }

    let error = tokio::time::timeout(
        Duration::from_secs(1),
        count_at_or_above_floor(&pager, REALM, 20, 1),
    )
    .await
    .expect("cycle detection should end the walk before timeout")
    .expect_err("free-list cycles must be corruption");
    assert!(
        matches!(
            error,
            PagedbError::Corruption(crate::errors::CorruptionDetail::PageChainCycle {
                structure: "free_list",
                ..
            })
        ),
        "expected a free-list PageChainCycle, got {error:?}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn read_chain_prefix_rejects_a_cycle_inside_the_window() {
    let pager = test_pager().await;
    for (page_id, next) in [(30u64, 31u64), (31, 30)] {
        let mut body = vec![0u8; body_capacity(PAGE)];
        body[0..8].copy_from_slice(&next.to_le_bytes());
        pager
            .write_main_page(page_id, REALM, PageKind::Free, &body)
            .await
            .unwrap();
    }

    let error = tokio::time::timeout(
        Duration::from_secs(1),
        read_chain_prefix(&pager, REALM, 30, 64),
    )
    .await
    .expect("cycle detection should end the bounded walk before timeout")
    .expect_err("free-list cycles must be corruption");
    assert!(
        matches!(
            error,
            PagedbError::Corruption(crate::errors::CorruptionDetail::PageChainCycle {
                structure: "free_list",
                ..
            })
        ),
        "expected a free-list PageChainCycle, got {error:?}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn count_chain_matches_read_chain_across_pages() {
    let pager = test_pager().await;
    let cap = chain_capacity(PAGE);
    let entries: Vec<(u64, u64)> = (0..(cap * 2 + 3) as u64).map(|i| (i, i + 100)).collect();
    let chain_pages: Vec<u64> = vec![20, 21, 22];
    let head = write_chain(
        &pager,
        REALM,
        PAGE,
        &chain_pages,
        &entries,
        ChainTail::EMPTY,
    )
    .await
    .unwrap();

    let (read, _) = read_chain(&pager, REALM, head).await.unwrap();
    let counted = count_chain(&pager, REALM, head).await.unwrap();
    assert_eq!(counted, read.len() as u64);
    assert_eq!(counted, entries.len() as u64);
}

#[tokio::test(flavor = "current_thread")]
async fn prefix_walk_stops_at_the_budget_and_names_the_retained_tail() {
    let pager = test_pager().await;
    let laid: Vec<(u64, Vec<(u64, u64)>)> = (0..5u64)
        .map(|i| (40 + i, vec![(i + 1, 900 + i)]))
        .collect();
    let head = lay_chain(&pager, &laid).await;

    let prefix = read_chain_prefix(&pager, REALM, head, 2).await.unwrap();
    assert_eq!(prefix.chain_pages, vec![40, 41]);
    assert_eq!(prefix.entries, vec![(1, 900), (2, 901)]);
    assert_eq!(
        prefix.tail.head, 42,
        "the tail must name the first page the window did not scan"
    );
}

/// The whole point of the prefix rewrite: fresh pages at the head, the tail
/// untouched and still readable through them. Nothing may be lost across the
/// splice, and the tail's pages must not be rewritten.
#[tokio::test(flavor = "current_thread")]
async fn prefix_rewrite_splices_onto_the_retained_tail() {
    let pager = test_pager().await;
    let laid: Vec<(u64, Vec<(u64, u64)>)> = (0..6u64)
        .map(|i| (50 + i, vec![(i + 1, 800 + i)]))
        .collect();
    let head = lay_chain(&pager, &laid).await;
    let before: BTreeSet<u64> = (0..6u64).map(|i| 800 + i).collect();

    let prefix = read_chain_prefix(&pager, REALM, head, 3).await.unwrap();
    // The scanned window's own pages are superseded and rejoin the entry set,
    // exactly as a commit folds them in.
    let mut entries = prefix.entries.clone();
    entries.extend(prefix.chain_pages.iter().map(|&page_id| (0, page_id)));

    let (new_head, next_page) =
        rewrite_chain(&pager, REALM, PAGE, entries, Vec::new(), 700, prefix.tail)
            .await
            .unwrap();

    let (all, chain_pages) = read_chain(&pager, REALM, new_head).await.unwrap();
    let names: BTreeSet<u64> = all.iter().map(|&(_, page_id)| page_id).collect();
    assert!(
        before.is_subset(&names),
        "the splice dropped entries: {names:?}"
    );
    for superseded in &prefix.chain_pages {
        assert!(
            names.contains(superseded),
            "the superseded window page {superseded} was neither carried nor rehosted"
        );
    }
    // The retained tail keeps its original pages; only the window was rewritten.
    assert!(
        chain_pages.ends_with(&[53, 54, 55]),
        "the retained tail was rewritten: {chain_pages:?}"
    );
    assert!(next_page > 700, "the fresh prefix must have been allocated");
}

/// A window whose entries all drain leaves nothing to write at the head. The
/// retained tail must then be published directly — returning an empty head
/// would strand every page the tail names.
#[tokio::test(flavor = "current_thread")]
async fn an_empty_prefix_publishes_the_retained_tail() {
    let pager = test_pager().await;
    let laid: Vec<(u64, Vec<(u64, u64)>)> = (0..3u64)
        .map(|i| (60 + i, vec![(i + 1, 850 + i)]))
        .collect();
    let head = lay_chain(&pager, &laid).await;

    let prefix = read_chain_prefix(&pager, REALM, head, 1).await.unwrap();
    let (new_head, _next) = rewrite_chain(
        &pager,
        REALM,
        PAGE,
        Vec::new(),
        Vec::new(),
        700,
        prefix.tail,
    )
    .await
    .unwrap();

    assert_eq!(new_head, 61);
    let (all, _) = read_chain(&pager, REALM, new_head).await.unwrap();
    assert_eq!(all, vec![(2, 851), (3, 852)]);
}

#[tokio::test(flavor = "current_thread")]
async fn floor_counter_matches_a_full_materialised_scan() {
    let pager = test_pager().await;
    let cap = chain_capacity(PAGE);
    let entries: Vec<(u64, u64)> = (0..(cap * 3 + 7) as u64)
        .map(|i| (i % 11, i + 100))
        .collect();
    let chain_pages: Vec<u64> = vec![70, 71, 72, 73];
    let head = write_chain(
        &pager,
        REALM,
        PAGE,
        &chain_pages,
        &entries,
        ChainTail::EMPTY,
    )
    .await
    .unwrap();

    for floor in 0..12u64 {
        let streamed = count_at_or_above_floor(&pager, REALM, head, floor)
            .await
            .unwrap();
        let materialised = entries
            .iter()
            .filter(|(commit_id, _)| *commit_id >= floor)
            .count() as u64;
        assert_eq!(
            streamed, materialised,
            "streaming floor counter disagreed at floor {floor}"
        );
    }
}
