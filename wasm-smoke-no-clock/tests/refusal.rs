//! The no-clock wasm32 build: what it must refuse, and what it must not.
//!
//! This crate depends on `pagedb` without the `opfs` feature (default features
//! only), so on `wasm32-unknown-unknown` `clock::clock_available()` is false and
//! `unix_seconds()` answers `None`. An age policy cannot be served there —
//! there is no `now` to compare a recorded timestamp against, so the threshold
//! would be a stand-in and the policy would prune nothing while still reporting
//! itself age-based.
//!
//! What that configuration owes an embedder is a typed refusal at open, before
//! anything is read or written, from every entry point; and clock-free policies
//! still working. Both are asserted here at runtime. This crate exists because
//! nothing else can make those assertions: the sibling `wasm-smoke` crate
//! depends on `pagedb` with `opfs` and can never compile this configuration,
//! and `policy_clock_tests` covers the decision function rather than the call
//! sites that feed it.
//!
//! Deliberately not asserted: that a commit on this build records a zero
//! timestamp. Nothing in the public API exposes a commit's recorded time, and
//! `RetainPolicy::Age` — the only reader of it — is refused here by design.
//!
//! Run with the CI job's `wasm-bindgen-test-runner` invocation.

#![cfg(all(target_arch = "wasm32", target_os = "unknown"))]

use pagedb::vfs::memory::MemVfs;
use pagedb::{Db, OpenOptions, PagedbError, RealmId, RetainPolicy};
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_node_experimental);

const PAGE: usize = 4096;
const KEK: [u8; 32] = [5u8; 32];
const REALM: RealmId = RealmId::new([2u8; 16]);

/// No Tokio time driver on purpose: an embedder driving these futures through
/// `wasm-bindgen-futures` has no Tokio runtime at all, so a test that needed a
/// timer would pass here and fail there.
fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("current-thread runtime")
        .block_on(future)
}

fn age_policy() -> OpenOptions {
    OpenOptions::default()
        .with_commit_history_retain(RetainPolicy::Age(std::time::Duration::from_secs(60)))
}

/// Whether this is the store missing rather than the policy being refused.
///
/// The memory VFS holds no store in these tests, so an entry point that probed
/// before checking reports a missing file instead: `NotFound` from the probe, or
/// the backend's own `Io`/`NotFound` out of `Vfs::open`. Refusing first is the
/// property being pinned, so the two are named apart from a genuine mismatch.
fn probed_before_checking(err: &PagedbError) -> bool {
    match err {
        PagedbError::NotFound => true,
        PagedbError::Io(io) => io.kind() == std::io::ErrorKind::NotFound,
        _ => false,
    }
}

/// The refusal, from whichever entry point produced it.
fn assert_refused(err: Option<PagedbError>, entry: &str) {
    match err {
        Some(PagedbError::RetainPolicyNeedsClock { policy: "Age" }) => {}
        Some(other) if probed_before_checking(&other) => {
            panic!("{entry} reached the store before checking the retention policy: {other:?}");
        }
        other => panic!("{entry} must refuse age retention without a clock, got {other:?}"),
    }
}

/// Every opening entry point refuses an age policy, because none of them can
/// serve it: there is no `now` to compute a pruning threshold from.
#[wasm_bindgen_test]
fn age_retention_is_refused_by_every_open_entry_point() {
    block_on(async {
        assert_refused(
            Db::open(MemVfs::new(), KEK, PAGE, REALM, age_policy())
                .await
                .err(),
            "Db::open",
        );
        assert_refused(
            Db::open_read_only(MemVfs::new(), KEK, PAGE, REALM, age_policy())
                .await
                .err(),
            "Db::open_read_only",
        );
        assert_refused(
            Db::open_observer(MemVfs::new(), KEK, PAGE, REALM, age_policy())
                .await
                .err(),
            "Db::open_observer",
        );
    });
}

/// The rekey-resume entry point refuses an age policy on this build, like every
/// other public open. It reaches the refusal through the shared mode path, so
/// this test pins that the shared check covers it — not that the entry carries a
/// check of its own.
#[wasm_bindgen_test]
fn age_retention_is_refused_by_the_rekey_resume_entry_point() {
    block_on(async {
        assert_refused(
            Db::open_existing_with_counterpart_kek(
                MemVfs::new(),
                KEK,
                KEK,
                PAGE,
                REALM,
                age_policy(),
            )
            .await
            .err(),
            "Db::open_existing_with_counterpart_kek",
        );
    });
}

/// The refusal is not a blanket one: the policies that consult no clock keep
/// working on this build, commit included.
#[wasm_bindgen_test]
fn clock_free_policies_still_open_and_commit_without_a_clock() {
    block_on(async {
        for policy in [
            RetainPolicy::Count(4),
            RetainPolicy::Unbounded,
            RetainPolicy::Disabled,
        ] {
            let opts = OpenOptions::default().with_commit_history_retain(policy.clone());
            let db = Db::open(MemVfs::new(), KEK, PAGE, REALM, opts)
                .await
                .unwrap_or_else(|e| {
                    panic!("{policy:?} consults no clock and must open without one: {e}")
                });
            let mut w = db.begin_write().await.expect("begin_write");
            w.put(b"k", b"v").await.expect("put");
            w.commit()
                .await
                .unwrap_or_else(|e| panic!("{policy:?} must commit without a clock: {e}"));
        }
    });
}
