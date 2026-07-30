//! Generated adversarial free-list chains.
//!
//! The durable free list is a chain of `PageKind::Free` pages, each carrying a
//! `next` pointer and an entry count that indexes into the rest of the body.
//! Both are authenticated bytes and neither is implied by anything else on the
//! page, so a count above capacity or a `next` pointing back up the chain is a
//! reachable state — and a panic in the entry slicing poisons the pager mutex
//! and wedges every subsequent commit, which is strictly worse than the
//! corruption it would have reported.
//!
//! The walks run on an OS thread with a receive timeout. An async timer cannot
//! be relied on here: the in-memory VFS leaves its futures continuously ready,
//! so a malformed chain loop never yields to the runtime.

use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::RealmId;
use crate::crypto::CipherId;
use crate::crypto::kdf::derive_mk;
use crate::pager::format::data_page::body_capacity;
use crate::pager::freelist::{
    ChainTail, chain_capacity, count_chain, read_chain, rewrite_chain, write_chain,
};
use crate::pager::{PageKind, Pager, PagerConfig};
use crate::vfs::memory::MemVfs;
use proptest::prelude::*;
use proptest::test_runner::{TestCaseError, TestCaseResult, TestRunner};

const PAGE: usize = 4096;
const REALM: RealmId = RealmId::new([0x7B; 16]);
/// Chain pages live in a small pool, so a generated `next` lands on a real page
/// often enough that cycles dominate rather than dangle.
const POOL: usize = 6;
/// Page ids 0..=3 are reserved for the structural headers and the apply-journal
/// slots, so the generated chain starts above them; slot 0 still resolves to
/// page 0, which is how a link into reserved space gets covered.
const FIRST_PAGE: u64 = 4;
/// Where the free-list allocator bump-allocates chain pages from. Kept small
/// and just above the generated entry range: the in-memory VFS stores a file as
/// one dense buffer, so a far-away page id would materialise gigabytes per case
/// for no extra coverage.
const BUMP_BASE: u64 = 1_000;
const PAGE_HEADER_LEN: usize = 12;
const ENTRY_LEN: usize = 16;

fn cases() -> u32 {
    std::env::var("PAGEDB_PROPTEST_CASES")
        .ok()
        .and_then(|raw| raw.parse().ok())
        .unwrap_or(32)
}

/// Wall-clock budget for one whole property run on its own thread.
///
/// Scaled by the case count so a deep soak does not trip the guard, but with a
/// per-case allowance (100ms) far above what a healthy case costs. At the
/// default that is a few seconds — enough to tell a wedge from slow progress,
/// short enough that the failure path does not dominate the suite.
fn walk_timeout() -> Duration {
    Duration::from_millis(2_000 + u64::from(cases()) * 100)
}

fn config() -> ProptestConfig {
    ProptestConfig {
        cases: cases(),
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}

fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(future)
}

async fn fresh_pager() -> Arc<Pager<MemVfs>> {
    let mk = derive_mk(&[0x7C; 32], &[0u8; 16], 0).unwrap();
    let config = PagerConfig {
        page_size: PAGE,
        buffer_pool_pages: 64,
        segment_cache_pages: 64,
        cipher_id: CipherId::Aes256Gcm,
        mk_epoch: 0,
        main_db_file_id: [0x7D; 16],
        main_db_path: "/main.db".into(),
        anchor_budget: 1_000_000,
        dek_lru_capacity: 16,
        observer_retry_count: 0,
        metrics_enabled: false,
    };
    Arc::new(Pager::open(MemVfs::new(), mk, config).await.unwrap())
}

fn run_bounded<S>(
    label: &'static str,
    strategy: S,
    timeout: Duration,
    test: impl Fn(S::Value) -> TestCaseResult + Send + 'static,
) where
    S: Strategy + Send + 'static,
    S::Value: std::fmt::Debug,
{
    let last_input = Arc::new(Mutex::new(String::from("<none>")));
    let thread_input = Arc::clone(&last_input);
    let (sender, receiver) = mpsc::channel();

    std::thread::spawn(move || {
        let mut runner = TestRunner::new(config());
        let outcome = runner.run(&strategy, move |value| {
            *thread_input
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = format!("{value:?}");
            test(value)
        });
        let _ = sender.send(outcome.map_err(|error| error.to_string()));
    });

    match receiver.recv_timeout(timeout) {
        Ok(Ok(())) => {}
        Ok(Err(message)) => panic!("{label}: {message}"),
        Err(_) => {
            let input = last_input
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            panic!("{label}: did not terminate within {timeout:?}; last input: {input}");
        }
    }
}

/// Chain page layout, forged directly so the count can exceed what the page can
/// hold: `next[8] || count[4] || count × (commit_id[8] ‖ page_id[8])`.
fn forged_chain_body(next: u64, declared_count: u32, entries: &[(u64, u64)]) -> Vec<u8> {
    let mut body = vec![0u8; body_capacity(PAGE)];
    body[0..8].copy_from_slice(&next.to_le_bytes());
    body[8..12].copy_from_slice(&declared_count.to_le_bytes());
    for (index, (commit_id, page_id)) in entries.iter().enumerate() {
        let offset = PAGE_HEADER_LEN + index * ENTRY_LEN;
        if offset + ENTRY_LEN > body.len() {
            break;
        }
        body[offset..offset + 8].copy_from_slice(&commit_id.to_le_bytes());
        body[offset + 8..offset + 16].copy_from_slice(&page_id.to_le_bytes());
    }
    body
}

fn pool_page_id(slot: usize) -> u64 {
    match slot % (POOL + 1) {
        0 => 0,
        occupied => FIRST_PAGE + occupied as u64 - 1,
    }
}

/// Per chain page: `(next slot, declared entry count, real entries)`.
type ChainSpec = Vec<(usize, u32, Vec<(u64, u64)>)>;

fn chain_spec() -> impl Strategy<Value = ChainSpec> {
    prop::collection::vec(
        (
            0usize..=POOL,
            prop_oneof![
                0u32..8,
                Just(u32::MAX),
                Just(chain_capacity(PAGE) as u32),
                Just(chain_capacity(PAGE) as u32 + 1),
                any::<u32>(),
            ],
            prop::collection::vec((any::<u64>(), any::<u64>()), 0..=4),
        ),
        1..=POOL,
    )
}

#[test]
fn generated_freelist_chains_terminate_or_report_corruption() {
    run_bounded(
        "freelist read_chain over a generated pointer graph",
        chain_spec(),
        walk_timeout(),
        |pages| {
            block_on(async {
                let pager = fresh_pager().await;
                for (index, (next_slot, declared_count, entries)) in pages.iter().enumerate() {
                    let body =
                        forged_chain_body(pool_page_id(*next_slot), *declared_count, entries);
                    pager
                        .write_main_page(FIRST_PAGE + index as u64, REALM, PageKind::Free, &body)
                        .await
                        .unwrap();
                }
                let _ = read_chain(&pager, REALM, FIRST_PAGE).await;
                // `count_chain` reads only page headers where `read_chain`
                // decodes every entry, so the two take different paths through
                // a forged body and each needs generated coverage.
                let _ = count_chain(&pager, REALM, FIRST_PAGE).await;
            });
            Ok(())
        },
    );
}

#[test]
fn wholly_random_freelist_bodies_never_panic() {
    run_bounded(
        "freelist read_chain over wholly random page bodies",
        prop::collection::vec(
            prop::collection::vec(any::<u8>(), body_capacity(PAGE)),
            1..=3,
        ),
        walk_timeout(),
        |bodies| {
            block_on(async {
                let pager = fresh_pager().await;
                for (index, body) in bodies.iter().enumerate() {
                    pager
                        .write_main_page(FIRST_PAGE + index as u64, REALM, PageKind::Free, body)
                        .await
                        .unwrap();
                }
                let _ = read_chain(&pager, REALM, FIRST_PAGE).await;
                let _ = count_chain(&pager, REALM, FIRST_PAGE).await;
            });
            Ok(())
        },
    );
}

/// Generated entry sets exercise the host-carve boundary at sizes a
/// hand-written case list would never enumerate: the carve shrinks the entry
/// set, so the chosen chain pages can outnumber what the survivors need, and
/// the page accounting has to stay exact across that whole range.
#[test]
fn written_freelist_chains_read_back_without_loss() {
    run_bounded(
        "freelist rewrite_chain / read_chain round trip",
        (
            prop::collection::vec(FIRST_PAGE..BUMP_BASE, 0..=400),
            0usize..=8,
            any::<u64>(),
        ),
        walk_timeout(),
        |(raw_page_ids, host_count, commit_id)| {
            let mut page_ids = raw_page_ids;
            page_ids.sort_unstable();
            page_ids.dedup();
            let entries: Vec<(u64, u64)> = page_ids
                .iter()
                .map(|&page_id| (commit_id, page_id))
                .collect();
            let hosts: Vec<u64> = page_ids.iter().take(host_count).copied().collect();

            let outcome = block_on(async {
                let pager = fresh_pager().await;
                let (head, _next) = rewrite_chain(
                    &pager,
                    REALM,
                    PAGE,
                    entries,
                    hosts,
                    BUMP_BASE,
                    ChainTail::EMPTY,
                )
                .await?;
                read_chain(&pager, REALM, head).await
            });
            let (read_entries, chain_pages) =
                outcome.map_err(|error| TestCaseError::fail(format!("{error:?}")))?;

            // Conservation: every page id put in comes back either as a stored
            // entry or as a page now hosting the chain — never both, never lost.
            let mut recovered: Vec<u64> = read_entries.iter().map(|&(_, id)| id).collect();
            let carved: Vec<u64> = chain_pages
                .iter()
                .copied()
                .filter(|id| *id < BUMP_BASE)
                .collect();
            for id in &carved {
                prop_assert!(!recovered.contains(id), "page {id} is both entry and chain");
            }
            recovered.extend(carved);
            recovered.sort_unstable();
            prop_assert_eq!(recovered, page_ids);
            Ok(())
        },
    );
}

/// The same walk driven from a generated page *layout* rather than a generated
/// entry set: which pages host the chain is itself a shape the walk has to
/// tolerate.
#[test]
fn hand_laid_chains_of_generated_shape_read_back_exactly() {
    run_bounded(
        "freelist write_chain over generated page layouts",
        (
            prop::collection::vec(FIRST_PAGE..=(FIRST_PAGE + POOL as u64 - 1), 1..=POOL),
            prop::collection::vec((any::<u64>(), any::<u64>()), 0..=8),
        ),
        walk_timeout(),
        |(mut chain_pages, entries)| {
            // Chain pages must be distinct: a repeated id is a cycle by
            // construction, which is a different property's subject.
            chain_pages.sort_unstable();
            chain_pages.dedup();
            prop_assume!(entries.len() <= chain_capacity(PAGE) * chain_pages.len());
            let outcome = block_on(async {
                let pager = fresh_pager().await;
                let head = write_chain(
                    &pager,
                    REALM,
                    PAGE,
                    &chain_pages,
                    &entries,
                    ChainTail::EMPTY,
                )
                .await?;
                read_chain(&pager, REALM, head).await
            });
            let (read_entries, _) =
                outcome.map_err(|error| TestCaseError::fail(format!("{error:?}")))?;
            prop_assert_eq!(read_entries, entries);
            Ok(())
        },
    );
}
