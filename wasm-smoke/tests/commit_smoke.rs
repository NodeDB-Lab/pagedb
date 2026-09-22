//! wasm32 commit smoke tests: a write must not need a wall clock.
//!
//! `wasm32-unknown-unknown` has no std clock. `WriteTxn::commit` reads the
//! clock for the commit-history entry, and the age-based retention policy
//! reads it for the pruning threshold. Before the fix both called
//! `SystemTime::now()` directly, so every commit panicked with
//! "time not implemented on this platform" and an embedded wasm build could
//! not write at all.
//!
//! Run with `wasm-pack test --node wasm-smoke` or the CI job's
//! `wasm-bindgen-test-runner` invocation.

#![cfg(all(target_arch = "wasm32", target_os = "unknown"))]

use pagedb::vfs::memory::MemVfs;
use pagedb::{Db, OpenOptions, RealmId, RetainPolicy};
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_node_experimental);

const PAGE: usize = 4096;
const KEK: [u8; 32] = [7u8; 32];
const REALM: RealmId = RealmId::new([1u8; 16]);

/// A current-thread runtime keeps the async plumbing identical to native.
/// The memory VFS never yields to the JS event loop, so `block_on` completes
/// without blocking a host callback.
fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("current-thread runtime")
        .block_on(future)
}

async fn commit_once(policy: RetainPolicy) {
    let opts = OpenOptions::default().with_commit_history_retain(policy);
    let db = Db::open(MemVfs::new(), KEK, PAGE, REALM, opts)
        .await
        .expect("open");
    let mut w = db.begin_write().await.expect("begin_write");
    w.put(b"k", b"v").await.expect("put");
    w.commit().await.expect("commit");
}

/// The commit-history entry carries a timestamp; writing it must not panic.
#[wasm_bindgen_test]
fn commit_writes_a_history_entry() {
    block_on(commit_once(RetainPolicy::Unbounded));
}

/// The age-based retention policy computes a threshold from the clock on
/// every commit; pruning must not panic either.
#[wasm_bindgen_test]
fn commit_under_age_retention_prunes_without_a_panic() {
    block_on(commit_once(RetainPolicy::Age(
        std::time::Duration::from_secs(60),
    )));
}
