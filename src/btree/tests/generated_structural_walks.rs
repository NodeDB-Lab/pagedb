//! Generated adversarial pointer graphs fed to the B+ tree walks.
//!
//! Descent, sibling iteration and range deletion all follow page ids that came
//! off disk. A page id is 64 bits of authenticated-but-arbitrary data: it can
//! point at the page holding it, at a page already visited, at a reserved page,
//! or at a page that was never allocated. The existing regressions pin one
//! self-referential leaf and one self-referential internal node; this generates
//! the graph instead, so the cycle does not have to be the one someone thought
//! to write down.
//!
//! Every walk runs on an OS thread with a receive timeout. `tokio::time::timeout`
//! would not do: the in-memory VFS resolves every read immediately, so a
//! malformed walk stays continuously ready and never gives the timer a chance
//! to fire. Only a separate OS thread can observe a wedged loop.

use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::RealmId;
use crate::btree::BTree;
use crate::btree::internal::{Internal, InternalEntry};
use crate::btree::leaf::{Leaf, LeafValue};
use crate::btree::node::body_capacity;
use crate::crypto::CipherId;
use crate::crypto::kdf::derive_mk;
use crate::pager::{PageKind, Pager, PagerConfig};
use crate::vfs::memory::MemVfs;
use proptest::prelude::*;
use proptest::test_runner::{TestCaseResult, TestRunner};

const PAGE: usize = 4096;
const REALM: RealmId = RealmId::new([0x2E; 16]);
/// Small graph: a handful of pages makes self-references and short cycles the
/// common case rather than a rare draw.
const POOL: usize = 8;
/// Page ids 0..=3 are reserved for the structural headers and the apply-journal
/// slots, so the generated graph starts above them; slot 0 still resolves to
/// page 0, which is how "a tree pointer into reserved space" gets covered.
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
    let mk = derive_mk(&[0x2F; 32], &[0u8; 16], 0).unwrap();
    let config = PagerConfig {
        page_size: PAGE,
        buffer_pool_pages: 64,
        segment_cache_pages: 64,
        cipher_id: CipherId::Aes256Gcm,
        mk_epoch: 0,
        main_db_file_id: [0x30; 16],
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

/// One generated page. Pointers are pool slots, resolved to page ids 0..=POOL
/// so that "points at itself", "points backwards", and "points at a page that
/// was never written" are all reachable draws.
#[derive(Debug, Clone)]
enum PageSpec {
    Leaf {
        left_sibling: usize,
        right_sibling: usize,
        keys: Vec<u8>,
    },
    Internal {
        leftmost_child: usize,
        children: Vec<(u8, usize)>,
    },
}

fn page_spec() -> impl Strategy<Value = PageSpec> {
    prop_oneof![
        (
            0usize..=POOL,
            0usize..=POOL,
            prop::collection::vec(any::<u8>(), 0..=6),
        )
            .prop_map(|(left_sibling, right_sibling, keys)| PageSpec::Leaf {
                left_sibling,
                right_sibling,
                keys,
            }),
        (
            0usize..=POOL,
            prop::collection::vec((any::<u8>(), 0usize..=POOL), 0..=6),
        )
            .prop_map(|(leftmost_child, children)| PageSpec::Internal {
                leftmost_child,
                children,
            }),
    ]
}

fn slot_to_page_id(slot: usize) -> u64 {
    match slot % (POOL + 1) {
        0 => 0,
        occupied => FIRST_PAGE + occupied as u64 - 1,
    }
}

async fn lay_out_graph(pager: &Arc<Pager<MemVfs>>, specs: &[PageSpec]) {
    for (index, spec) in specs.iter().enumerate() {
        let page_id = FIRST_PAGE + index as u64;
        let mut body = vec![0u8; body_capacity(PAGE)];
        let kind = match spec {
            PageSpec::Leaf {
                left_sibling,
                right_sibling,
                keys,
            } => {
                let mut leaf = Leaf::new();
                leaf.left_sibling = slot_to_page_id(*left_sibling);
                leaf.right_sibling = slot_to_page_id(*right_sibling);
                for key in keys {
                    leaf.upsert(&[*key], LeafValue::Inline(vec![*key; 4]));
                }
                if leaf.encode(&mut body).is_err() {
                    continue;
                }
                PageKind::BTreeLeaf
            }
            PageSpec::Internal {
                leftmost_child,
                children,
            } => {
                let mut entries: Vec<(u8, usize)> = children.clone();
                entries.sort_unstable();
                entries.dedup_by_key(|entry| entry.0);
                let internal = Internal {
                    leftmost_child: slot_to_page_id(*leftmost_child),
                    entries: entries
                        .into_iter()
                        .map(|(key, slot)| InternalEntry {
                            key: vec![key],
                            right_child: slot_to_page_id(slot),
                        })
                        .collect(),
                };
                if internal.encode(&mut body).is_err() {
                    continue;
                }
                PageKind::BTreeInternal
            }
        };
        pager
            .write_main_page(page_id, REALM, kind, &body)
            .await
            .unwrap();
    }
}

#[test]
fn generated_pointer_graphs_never_wedge_the_read_walks() {
    run_bounded(
        "B+ tree read walks over a generated pointer graph",
        (
            prop::collection::vec(page_spec(), 1..=POOL),
            any::<u8>(),
            any::<u8>(),
        ),
        walk_timeout(),
        |(specs, start, end)| {
            block_on(async {
                let pager = fresh_pager().await;
                lay_out_graph(&pager, &specs).await;
                let tree = BTree::open(pager, REALM, FIRST_PAGE, FIRST_PAGE + POOL as u64, PAGE);
                // Descent, forward sibling iteration, reverse iteration, and
                // prefix narrowing each follow a different pointer field.
                let _ = tree.get(&[start]).await;
                let _ = tree.first_key().await;
                let _ = tree.collect_range(&[start], &[end]).await;
                let _ = tree.collect_all().await;
                let _ = tree.scan_rev(&[start], &[end]).await;
                let _ = tree.scan_prefix(&[start]).await;
            });
            Ok(())
        },
    );
}

#[test]
fn generated_pointer_graphs_never_wedge_the_write_walks() {
    run_bounded(
        "B+ tree write walks over a generated pointer graph",
        (
            prop::collection::vec(page_spec(), 1..=POOL),
            any::<u8>(),
            any::<u8>(),
        ),
        walk_timeout(),
        |(specs, start, end)| {
            block_on(async {
                let pager = fresh_pager().await;
                lay_out_graph(&pager, &specs).await;
                let mut tree =
                    BTree::open(pager, REALM, FIRST_PAGE, FIRST_PAGE + POOL as u64, PAGE);
                // `delete_range` walks the leaf sibling chain while mutating
                // it; `put` re-descends after every split. Both are the shapes
                // the existing cycle regressions cover for one fixed graph.
                let _ = tree.delete_range(&[start], &[end]).await;
                let _ = tree.put(&[start], &[end; 8]).await;
                let _ = tree.delete(&[start]).await;
            });
            Ok(())
        },
    );
}

#[test]
fn wholly_random_node_bodies_never_wedge_the_walks() {
    run_bounded(
        "B+ tree walks over wholly random page bodies",
        (
            prop::collection::vec(
                (
                    prop::sample::select(vec![PageKind::BTreeLeaf, PageKind::BTreeInternal]),
                    prop::collection::vec(any::<u8>(), body_capacity(PAGE)),
                ),
                1..=4,
            ),
            any::<u8>(),
        ),
        walk_timeout(),
        |(pages, probe)| {
            block_on(async {
                let pager = fresh_pager().await;
                for (index, (kind, body)) in pages.iter().enumerate() {
                    pager
                        .write_main_page(FIRST_PAGE + index as u64, REALM, *kind, body)
                        .await
                        .unwrap();
                }
                let mut tree =
                    BTree::open(pager, REALM, FIRST_PAGE, FIRST_PAGE + POOL as u64, PAGE);
                let _ = tree.get(&[probe]).await;
                let _ = tree.collect_all().await;
                let _ = tree.delete_range(&[0], &[255]).await;
            });
            Ok(())
        },
    );
}
