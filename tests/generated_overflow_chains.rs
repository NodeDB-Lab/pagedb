//! Generated adversarial overflow chains.
//!
//! An overflow value is a singly-linked page chain whose `next` pointers and
//! whose declared `total_len` both come off disk. The two failure modes that
//! matter are a chain that never ends (a `next` pointing back into the chain)
//! and a `total_len` that would size an allocation before a single chain page
//! has been authenticated. Existing regressions pin one instance of each; these
//! properties generate the pointer graph instead of naming it.
//!
//! Nontermination is detected on an OS thread with a receive timeout rather
//! than an async timer: the in-memory VFS keeps its futures continuously ready,
//! so a malformed loop never yields and a `tokio` timer is not guaranteed to
//! preempt it. Only a separate OS thread can observe the hang.

use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pagedb::RealmId;
use pagedb::btree::overflow::{
    OVERFLOW_ROOT_HEADER_LEN, collect_chain, decode_overflow, encode_overflow,
    overflow_page_capacity, overflow_root_capacity, read_chain, read_root_page,
};
use pagedb::crypto::CipherId;
use pagedb::crypto::kdf::derive_mk;
use pagedb::pager::format::data_page::ENVELOPE_OVERHEAD;
use pagedb::pager::{PageKind, Pager, PagerConfig};
use pagedb::vfs::memory::MemVfs;
use proptest::prelude::*;
use proptest::test_runner::{TestCaseResult, TestRunner};

const PAGE: usize = 4096;
const REALM: RealmId = RealmId::new([0x3C; 16]);
/// Small enough that a generated `next` lands on a real page often, and that
/// cycles are common rather than rare.
const POOL: usize = 6;
/// Page ids 0..=3 are reserved for the structural headers and the apply-journal
/// slots, so the generated graph starts above them; slot 0 still resolves to
/// page 0, which is how "a chain link into reserved space" gets covered.
const FIRST_PAGE: u64 = 4;

fn cases() -> u32 {
    std::env::var("PAGEDB_PROPTEST_CASES")
        .ok()
        .and_then(|raw| raw.parse().ok())
        .unwrap_or(32)
}

/// Wall-clock budget for one whole property run on its own thread.
///
/// Scaled by the case count so a deep soak does not trip the guard, but with a
/// per-case allowance (100ms) far above what a healthy case costs (single-digit
/// milliseconds: one runtime, one pager, a handful of pages). At the default
/// that is a few seconds — enough to tell a wedge from slow progress, short
/// enough that the failure path does not dominate the suite.
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
    let mk = derive_mk(&[0x3D; 32], &[0u8; 16], 0).unwrap();
    let config = PagerConfig {
        page_size: PAGE,
        buffer_pool_pages: 64,
        segment_cache_pages: 64,
        cipher_id: CipherId::Aes256Gcm,
        mk_epoch: 0,
        main_db_file_id: [0x3E; 16],
        main_db_path: "/main.db".into(),
        anchor_budget: 1_000_000,
        dek_lru_capacity: 16,
        observer_retry_count: 0,
        metrics_enabled: false,
    };
    Arc::new(Pager::open(MemVfs::new(), mk, config).await.unwrap())
}

/// Run a property on its own OS thread and fail the test if it does not report
/// back in time. A hang leaks the thread deliberately: the process is going to
/// fail either way, and killing a wedged loop is not something the harness can
/// do safely.
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
            // Recorded before the call so a hang can still name what caused it.
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

/// Root body layout, written here rather than reached for in the library: the
/// root encoder is private and must stay that way, but the layout is part of
/// the persisted format and a test is entitled to forge it.
/// `refcount[4] || next[8] || data_len[4] || data`.
fn forged_root_body(refcount: u32, next: u64, declared_data_len: u32, data: &[u8]) -> Vec<u8> {
    let mut body = vec![0u8; PAGE - ENVELOPE_OVERHEAD];
    body[0..4].copy_from_slice(&refcount.to_le_bytes());
    body[4..12].copy_from_slice(&next.to_le_bytes());
    body[12..16].copy_from_slice(&declared_data_len.to_le_bytes());
    let take = data.len().min(body.len() - OVERFLOW_ROOT_HEADER_LEN);
    body[OVERFLOW_ROOT_HEADER_LEN..OVERFLOW_ROOT_HEADER_LEN + take].copy_from_slice(&data[..take]);
    body
}

/// Map a generated slot index onto a page id in the pool; slot 0 terminates.
fn pool_page_id(slot: usize) -> u64 {
    match slot % (POOL + 1) {
        0 => 0,
        occupied => FIRST_PAGE + occupied as u64 - 1,
    }
}

/// One generated chain: page 1 is the root, pages 2..=POOL are chain pages,
/// each with a generated `next` and a generated declared data length.
type ChainSpec = (Vec<(usize, u16)>, u64);

fn chain_spec() -> impl Strategy<Value = ChainSpec> {
    (
        prop::collection::vec((0usize..=POOL, 0u16..=600), 1..=POOL),
        prop_oneof![
            Just(0u64),
            Just(u64::MAX),
            Just(u64::MAX / 2),
            Just(u64::from(u32::MAX)),
            0u64..8192,
        ],
    )
}

async fn lay_out_chain(pager: &Arc<Pager<MemVfs>>, pages: &[(usize, u16)]) {
    let root_capacity = overflow_root_capacity(PAGE);
    let chain_capacity = overflow_page_capacity(PAGE);
    for (index, &(next_slot, declared_len)) in pages.iter().enumerate() {
        let page_id = FIRST_PAGE + index as u64;
        let next = pool_page_id(next_slot);
        if index == 0 {
            let data = vec![0xAB_u8; usize::from(declared_len).min(root_capacity)];
            let body = forged_root_body(1, next, u32::from(declared_len), &data);
            pager
                .write_main_page(page_id, REALM, PageKind::OverflowRoot, &body)
                .await
                .unwrap();
        } else {
            let data = vec![0xCD_u8; usize::from(declared_len).min(chain_capacity)];
            let mut body = vec![0u8; PAGE - ENVELOPE_OVERHEAD];
            encode_overflow(&mut body, next, &data).unwrap();
            pager
                .write_main_page(page_id, REALM, PageKind::Overflow, &body)
                .await
                .unwrap();
        }
    }
}

#[test]
fn generated_overflow_chains_terminate_or_report_corruption() {
    run_bounded(
        "overflow read_chain over a generated pointer graph",
        chain_spec(),
        walk_timeout(),
        |(pages, total_len)| {
            block_on(async {
                let pager = fresh_pager().await;
                lay_out_chain(&pager, &pages).await;
                // Every one of these walks follows `next` pointers; none may
                // spin, and none may allocate from `total_len` before a page
                // has authenticated.
                let _ = read_root_page(&pager, REALM, FIRST_PAGE).await;
                let _ = read_chain(&pager, REALM, FIRST_PAGE, total_len).await;
                let _ = collect_chain(&pager, REALM, FIRST_PAGE).await;
            });
            Ok(())
        },
    );
}

#[test]
fn absurd_total_len_over_a_valid_chain_is_rejected_not_allocated() {
    run_bounded(
        "overflow read_chain with an absurd total_len",
        (
            0usize..=POOL,
            prop_oneof![Just(u64::MAX), (1u64 << 40)..u64::MAX],
        ),
        walk_timeout(),
        |(next_slot, total_len)| {
            let outcome = block_on(async {
                let pager = fresh_pager().await;
                // A single, well-formed root: the only lie is `total_len`.
                let body = forged_root_body(1, pool_page_id(next_slot), 4, b"data");
                pager
                    .write_main_page(FIRST_PAGE, REALM, PageKind::OverflowRoot, &body)
                    .await
                    .unwrap();
                read_chain(&pager, REALM, FIRST_PAGE, total_len).await
            });
            prop_assert!(
                outcome.is_err(),
                "a total_len of {total_len} cannot be satisfied by a one-page chain"
            );
            Ok(())
        },
    );
}

#[test]
fn wholly_random_overflow_bodies_never_panic() {
    run_bounded(
        "overflow chain over wholly random page bodies",
        (
            prop::collection::vec(
                prop::collection::vec(any::<u8>(), PAGE - ENVELOPE_OVERHEAD),
                1..=3,
            ),
            any::<u64>(),
        ),
        walk_timeout(),
        |(bodies, total_len)| {
            block_on(async {
                let pager = fresh_pager().await;
                for (index, body) in bodies.iter().enumerate() {
                    let kind = if index == 0 {
                        PageKind::OverflowRoot
                    } else {
                        PageKind::Overflow
                    };
                    pager
                        .write_main_page(FIRST_PAGE + index as u64, REALM, kind, body)
                        .await
                        .unwrap();
                }
                let _ = read_root_page(&pager, REALM, FIRST_PAGE).await;
                let _ = read_chain(&pager, REALM, FIRST_PAGE, total_len).await;
                let _ = collect_chain(&pager, REALM, FIRST_PAGE).await;
            });
            Ok(())
        },
    );
}

proptest! {
    #![proptest_config(config())]

    /// The pure chain-page decoder, with no pager in the way: `data_len` is a
    /// `u32` read off disk and used as a slice bound.
    #[test]
    fn random_bytes_never_panic_the_chain_page_decoder(
        body in prop::collection::vec(any::<u8>(), 0..=(PAGE - ENVELOPE_OVERHEAD)),
    ) {
        if let Ok((_, data)) = decode_overflow(&body) {
            // Accepted data must lie inside the body it came from.
            prop_assert!(data.len() + 12 <= body.len());
        }
    }

    /// Declared length against actual body length, pinned so the boundary is
    /// hit on both sides instead of by chance.
    #[test]
    fn hostile_chain_page_data_len_is_bounded_by_the_body(
        next in any::<u64>(),
        declared_len in any::<u32>(),
        body_len in 0usize..=(PAGE - ENVELOPE_OVERHEAD),
    ) {
        let mut body = vec![0u8; body_len];
        if body.len() >= 12 {
            body[0..8].copy_from_slice(&next.to_le_bytes());
            body[8..12].copy_from_slice(&declared_len.to_le_bytes());
        }
        if let Ok((got_next, data)) = decode_overflow(&body) {
            prop_assert_eq!(got_next, next);
            prop_assert_eq!(data.len() as u64, u64::from(declared_len));
            prop_assert!(12 + data.len() <= body.len());
        }
    }
}
