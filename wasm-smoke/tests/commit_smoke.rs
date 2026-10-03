//! wasm32 commit smoke tests, on the build an embedder actually ships.
//!
//! The invariants these protect, all on `wasm32-unknown-unknown`:
//!
//! - Nothing on the commit path may call `SystemTime::now()`, which panics with
//!   "time not implemented on this platform". The clock is reached only through
//!   `clock::unix_seconds()`.
//! - A corrupted page must be reported as `PagedbError::Corruption`, not turned
//!   into a panic by the read loop's backoff.
//!
//! This crate depends on `pagedb` with the `opfs` feature, which is the build
//! an embedded consumer uses — so the clock exists here, `unix_seconds()`
//! answers `Some`, and the commit tests pin the succeeding path end to end:
//! open, commit, and commit under age retention, none of them touching std's
//! clock. The runtime is built without a Tokio time driver on purpose, so the
//! corrupted-page test exercises the retry loop's `yield_now` backoff for real.
//!
//! The **no-clock** configuration is a different build (`pagedb` without
//! `opfs`) and is not reachable from here: this crate cannot produce it, because
//! its own dependency on `pagedb` fixes the feature for every target in the
//! build. It has its own crate, `wasm-smoke-no-clock`, which depends on `pagedb`
//! without `opfs` and asserts the refusal at every entry point;
//! `txn::db::open::modes::policy_clock_tests` covers the decision function
//! itself, on any target.
//!
//! Not asserted anywhere: the pruned row count. Neither `Db` nor `DbStats`
//! exposes the commit history, and these tests see only the public API.
//!
//! Run with `wasm-pack test --node wasm-smoke` or the CI job's
//! `wasm-bindgen-test-runner` invocation.

#![cfg(all(target_arch = "wasm32", target_os = "unknown"))]

use pagedb::vfs::memory::MemVfs;
use pagedb::vfs::{OpenMode, Vfs, VfsFile};
use pagedb::{Db, OpenOptions, PagedbError, RealmId, RetainPolicy};
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_node_experimental);

const PAGE: usize = 4096;
const KEK: [u8; 32] = [7u8; 32];
const REALM: RealmId = RealmId::new([1u8; 16]);

/// A current-thread runtime keeps the async plumbing identical to native.
/// The memory VFS never yields to the JS event loop, so `block_on` completes
/// without blocking a host callback.
///
/// Deliberately built **without** `enable_time()`. An embedder driving these
/// futures through `wasm-bindgen-futures` has no Tokio runtime at all, so a
/// test that quietly depended on a time driver would pass here and panic
/// there. The page-read retry loop yields instead of sleeping for the same
/// reason.
fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("current-thread runtime")
        .block_on(future)
}

async fn commit_once(policy: &RetainPolicy) -> pagedb::Result<()> {
    let opts = OpenOptions::default().with_commit_history_retain(policy.clone());
    let db = Db::open(MemVfs::new(), KEK, PAGE, REALM, opts).await?;
    let mut w = db.begin_write().await.expect("begin_write");
    w.put(b"k", b"v").await.expect("put");
    w.commit().await.expect("commit");
    Ok(())
}

/// Opening and committing must not reach the std clock on this target.
#[wasm_bindgen_test]
fn commit_does_not_read_the_std_clock() {
    block_on(async {
        commit_once(&RetainPolicy::Unbounded)
            .await
            .expect("Unbounded consults no clock, so it must open and commit");
    });
}

/// Every clock-free policy must clear a commit, not just the one a default
/// configuration happens to use.
#[wasm_bindgen_test]
fn commit_clears_every_clock_free_policy() {
    block_on(async {
        for policy in [RetainPolicy::Unbounded, RetainPolicy::Count(4)] {
            commit_once(&policy)
                .await
                .unwrap_or_else(|e| panic!("a clock-free policy must commit: {e}"));
        }
    });
}

/// Age retention reads the clock on every commit — its pruning threshold is
/// `now - duration` — so it is the policy whose commitment to a wall clock has
/// to be met on the build an embedder ships, not just on the one the default
/// configuration happens to use.
#[wasm_bindgen_test]
fn commit_under_age_retention_does_not_read_the_std_clock() {
    block_on(async {
        commit_once(&RetainPolicy::Age(std::time::Duration::from_secs(60)))
            .await
            .expect("a build with a clock must serve age retention");
    });
}

/// Corrupted pages must be reported, not panicked on.
///
/// This is the case the page-read retry loop exists for: a read-only handle
/// retries an AEAD failure `observer_retry_count` times before reporting
/// corruption, and the backoff between those attempts is the one platform
/// split in this change — `tokio::time::sleep` where a time driver exists,
/// `yield_now` on `wasm32-unknown-unknown`, where an embedder's executor has
/// none and sleeping would panic with "time not implemented on this platform".
/// A panic here would replace a reportable `Corruption` with a crash, so this
/// test is what makes that split load-bearing rather than cosmetic.
#[wasm_bindgen_test]
fn a_corrupted_page_is_reported_as_corruption_not_a_panic() {
    block_on(async {
        let vfs = MemVfs::new();
        let db = Db::open(vfs.clone(), KEK, PAGE, REALM, OpenOptions::default())
            .await
            .expect("open");
        let mut w = db.begin_write().await.expect("begin_write");
        w.put(b"k", b"v").await.expect("put");
        w.commit().await.expect("commit");
        drop(db);

        // Pages 0 and 1 hold the A/B header slots, whose MAC covers the slot;
        // corrupting those would fail *open* with a header error instead of
        // exercising a verified page read. Every page after them is flipped, so
        // whichever page the read path reaches is corrupt. The flip lands
        // mid-page: the page's first bytes carry its cleartext cipher id, and
        // overwriting that reports `Unsupported` before the authenticated read
        // ever fails.
        let mut file = vfs
            .open("/main.db", OpenMode::ReadWrite)
            .await
            .expect("raw open");
        let len = file.len().await.expect("len") as usize;
        let mut byte = [0u8; 1];
        let mut offset = 2 * PAGE;
        while offset + PAGE <= len {
            let mid = (offset + PAGE / 2) as u64;
            file.read_at(mid, &mut byte).await.expect("read");
            byte[0] ^= 0xFF;
            file.write_at(mid, &byte).await.expect("write");
            offset += PAGE;
        }
        assert!(
            offset > 2 * PAGE,
            "the store must have pages past the two header slots"
        );

        // `Observer` is the mode whose retry budget turns this into four
        // attempts on the corrupted page; `open_observer` on defaults is what a
        // reader on a live store does.
        let outcome: pagedb::Result<()> = async {
            let db = Db::open_observer(vfs, KEK, PAGE, REALM, OpenOptions::default()).await?;
            let txn = db.begin_read().await?;
            txn.get(b"k").await.map(|_| ())
        }
        .await;

        let err = outcome.expect_err("a corrupted page must not read cleanly");
        assert!(
            matches!(err, PagedbError::Corruption(_)),
            "a corrupted page must be reported as Corruption, got {err:?}"
        );
    });
}
