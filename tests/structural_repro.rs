//! Structural-integrity stress: sustained commits mixing appends, rewrites,
//! and overflow values, verifying every committed key remains readable with
//! its last-written value. Exercises the interaction between the dirty-leaf
//! cache, in-txn splits, spine CoW at flush, and durable free-list recycling.
//!
//! Every scenario is generic over the VFS and runs against both `MemVfs` and
//! the real-file backends (`TokioVfs`, and `IouringVfs` on Linux): the memory
//! backend gives deterministic logic coverage, the disk backends cover write
//! submission/completion ordering, handle lifecycle across drop/reopen, and
//! fsync behaviour that an in-memory file cannot model.

use std::collections::BTreeMap;

use pagedb::options::{OpenOptions, RetainPolicy};
use pagedb::vfs::Vfs;
use pagedb::vfs::memory::MemVfs;
use pagedb::vfs::tokio_backend::TokioVfs;
use pagedb::{Db, RealmId, run_deep_walk};

const PAGE: usize = 4096;
const KEK: [u8; 32] = [9u8; 32];
const REALM: RealmId = RealmId::new([1; 16]);

fn opts() -> OpenOptions {
    OpenOptions::default().with_commit_history_retain(RetainPolicy::Disabled)
}

/// Unique on-disk root for a real-file backend run.
fn disk_root(tag: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    p.push(format!(
        "pagedb-structural-{}-{}-{}",
        tag,
        std::process::id(),
        nanos
    ));
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn key(i: u64) -> Vec<u8> {
    format!("key{i:08}").into_bytes()
}

/// Deterministic value for key `i` at rewrite generation `generation`.
/// Every 10th key gets an overflow-sized value (> page_size / 4); the rest
/// stay inline but large enough that leaves hold only a handful of records,
/// forcing frequent leaf and internal splits. The overflow decision also
/// depends on `generation`, so rewrites flip records between inline and
/// overflow representations, churning overflow-chain allocation and release.
fn value(i: u64, generation: u64) -> Vec<u8> {
    let len = if (i + generation) % 10 == 0 { 3000 } else { 300 };
    let seed = (i.wrapping_mul(31)).wrapping_add(generation) as u8;
    vec![seed; len]
}

/// Read back every key in `expected` through a fresh read txn and assert the
/// stored value matches the last write. Surfaces both lost updates (stale
/// value) and structural corruption (AEAD/MAC failure on a recycled page).
async fn verify_all<V: Vfs + Clone>(db: &Db<V>, expected: &BTreeMap<u64, u64>) {
    let r = db.begin_read().await.unwrap();
    for (&i, &generation) in expected {
        let got = r
            .get(&key(i))
            .await
            .unwrap_or_else(|e| panic!("get key {i} failed: {e:?}"));
        let want = value(i, generation);
        match got {
            None => panic!("key {i} missing (generation {generation})"),
            Some(v) => assert_eq!(
                v, want,
                "key {i} wrong value: got len {}, want generation {generation} len {}",
                v.len(),
                want.len()
            ),
        }
    }
}

/// Poll a future once, returning `Some(output)` if it completed.
async fn futures_poll_once<F: std::future::Future + Unpin>(fut: F) -> Option<F::Output> {
    let mut fut = fut;
    std::future::poll_fn(move |cx| {
        std::task::Poll::Ready(match std::pin::Pin::new(&mut fut).poll(cx) {
            std::task::Poll::Ready(v) => Some(v),
            std::task::Poll::Pending => None,
        })
    })
    .await
}

// ------------------------------------------------------------------------ //
// Scenario bodies, generic over the VFS.
// ------------------------------------------------------------------------ //

/// Monotonic inserts plus scattered rewrites, committed in small batches, with
/// a full read-back after every commit. A few thousand puts drive the tree
/// through multiple leaf splits, root growth, and internal splits while other
/// leaves sit dirty in the same txn — and drive freed pages through the
/// durable free-list back into circulation.
async fn sustained_impl<V: Vfs + Clone>(vfs: V) {
    let db = Db::open_internal_with_options(vfs, KEK, PAGE, REALM, opts())
        .await
        .unwrap();
    // expected: key index -> last-written generation.
    let mut expected: BTreeMap<u64, u64> = BTreeMap::new();
    let mut next_key: u64 = 0;
    // Simple deterministic LCG for choosing rewrite targets.
    let mut rng: u64 = 0x243F_6A88_85A3_08D3;
    let mut lcg = move || {
        rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        rng
    };

    for batch in 0..80u64 {
        let mut w = db.begin_write().await.unwrap();
        // (a) 20 rewrites of existing keys scattered across the keyspace,
        // dirtying leaves far from the append edge — recorded in the txn
        // BEFORE the appends below trigger any splits.
        if next_key > 100 {
            for _ in 0..20 {
                let i = lcg() % next_key;
                let generation = expected.get(&i).copied().unwrap_or(0) + 1;
                w.put(&key(i), &value(i, generation)).await.unwrap();
                expected.insert(i, generation);
            }
        }
        // (b) 50 monotonically increasing fresh keys, splitting the rightmost
        // leaf (and periodically the spine) as the last writes of the txn.
        for _ in 0..50 {
            let i = next_key;
            next_key += 1;
            w.put(&key(i), &value(i, 0)).await.unwrap();
            expected.insert(i, 0);
        }
        w.commit()
            .await
            .unwrap_or_else(|e| panic!("commit of batch {batch} failed: {e:?}"));
        verify_all(&db, &expected).await;
    }
}

/// The same mixed workload driven across repeated close/reopen cycles on a
/// shared VFS. A reopen discards the buffer pool, so every page referenced by
/// the durable header must decode from disk — a page that was freed and
/// recycled while a durable structure still referenced it stays hidden behind
/// the warm cache in a single-handle run and only surfaces here as an
/// AEAD/MAC failure or stale value on the cold read-back.
async fn reopen_cycle_impl<V: Vfs + Clone>(vfs: V) {
    let mut expected: BTreeMap<u64, u64> = BTreeMap::new();
    let mut next_key: u64 = 0;
    let mut rng: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut lcg = move || {
        rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        rng
    };

    for cycle in 0..12u64 {
        let db = if cycle == 0 {
            Db::open_internal_with_options(vfs.clone(), KEK, PAGE, REALM, opts())
                .await
                .unwrap()
        } else {
            Db::open_existing_with_options(vfs.clone(), KEK, PAGE, REALM, opts())
                .await
                .unwrap_or_else(|e| panic!("reopen before cycle {cycle} failed: {e:?}"))
        };
        // Cold read-back straight after reopen: every key must decode from
        // disk before any new write warms or repairs the cache.
        verify_all(&db, &expected).await;

        for _txn in 0..6u64 {
            let mut w = db.begin_write().await.unwrap();
            // Scattered rewrites first, then appends, so splits triggered by
            // the appends are the txn's final structural mutations.
            if next_key > 100 {
                for _ in 0..20 {
                    let i = lcg() % next_key;
                    let generation = expected.get(&i).copied().unwrap_or(0) + 1;
                    w.put(&key(i), &value(i, generation)).await.unwrap();
                    expected.insert(i, generation);
                }
                // A few scattered deletes, so leaves shrink and freed
                // overflow chains flow through the free-list.
                for _ in 0..5 {
                    let i = lcg() % next_key;
                    if expected.remove(&i).is_some() {
                        assert!(w.delete(&key(i)).await.unwrap(), "delete key {i}");
                    }
                }
            }
            // Monotonic tail extension via the append fast path (cached
            // rightmost descent), the pattern an op-log embedder produces.
            for _ in 0..40 {
                let i = next_key;
                next_key += 1;
                w.put_append(&key(i), &value(i, 0)).await.unwrap();
                expected.insert(i, 0);
            }
            // A catalog write per txn, so both trees allocate pages in the
            // shared id space every commit.
            w.counter("txn-seq").unwrap().increment_by(1).await.unwrap();
            w.commit()
                .await
                .unwrap_or_else(|e| panic!("commit in cycle {cycle} failed: {e:?}"));
            // Structural integrity must hold after every commit: no page may
            // be simultaneously reachable from a live root and named free,
            // and every referenced page must decode. This catches a lost
            // reference at the commit that created it, long before the page
            // is recycled and the damage becomes an AEAD failure.
            let report = run_deep_walk(&db).await.unwrap();
            assert!(
                report.is_clean(),
                "deep walk found issues after a commit in cycle {cycle}: {:?}",
                report.page_issues
            );
        }
        verify_all(&db, &expected).await;
        // Drop without compaction or graceful drain, as an embedder that is
        // terminated right after a commit would.
        drop(db);
    }
}

/// Commit cancellation at every await point. A commit future dropped mid-way
/// (as an embedder shutting down mid-commit produces) must leave the store
/// openable and atomic: after reopen the visible state is exactly the
/// pre-commit state or exactly the post-commit state, never a blend, and a
/// deep walk stays clean. Iterates the cancellation point across the whole
/// commit sequence by polling the future a bounded number of times before
/// dropping it. On a real-file backend a dropped commit also abandons queued
/// write submissions mid-io, which the memory backend cannot model.
async fn cancelled_commit_impl<V: Vfs + Clone>(vfs: V) {
    let mut db = Db::open_internal_with_options(vfs.clone(), KEK, PAGE, REALM, opts())
        .await
        .unwrap();
    let mut committed: BTreeMap<u64, u64> = BTreeMap::new();
    let mut next_key: u64 = 0;

    // Seed a base commit so every later batch mixes rewrites with appends.
    {
        let mut w = db.begin_write().await.unwrap();
        for _ in 0..120 {
            let i = next_key;
            next_key += 1;
            w.put(&key(i), &value(i, 0)).await.unwrap();
            committed.insert(i, 0);
        }
        w.commit().await.unwrap();
    }

    for k in 0..60usize {
        // Build a batch on top of the committed state.
        let mut staged = committed.clone();
        let mut w = db.begin_write().await.unwrap();
        for _ in 0..10 {
            let i = (next_key.wrapping_mul(7) + k as u64) % next_key;
            let generation = staged.get(&i).copied().unwrap_or(0) + 1;
            w.put(&key(i), &value(i, generation)).await.unwrap();
            staged.insert(i, generation);
        }
        for _ in 0..20 {
            let i = next_key;
            next_key += 1;
            w.put(&key(i), &value(i, 0)).await.unwrap();
            staged.insert(i, 0);
        }
        // Poll the commit future exactly `k` times, then drop it, modelling a
        // shutdown that cancels the in-flight commit at that await point.
        let completed = {
            let mut fut = Box::pin(w.commit());
            let mut completed = None;
            for _ in 0..k {
                let poll = futures_poll_once(fut.as_mut()).await;
                if let Some(result) = poll {
                    completed = Some(result.expect("commit that ran to completion succeeds"));
                    break;
                }
            }
            completed
            // Dropping `fut` here drops the write txn mid-commit when it
            // never completed.
        };

        // Reopen cold and demand atomicity: the surviving state is exactly
        // `staged` (commit landed) or exactly `committed` (commit lost).
        drop(db);
        db = Db::open_existing_with_options(vfs.clone(), KEK, PAGE, REALM, opts())
            .await
            .unwrap_or_else(|e| panic!("reopen after cancellation at poll {k} failed: {e:?}"));
        let r = db.begin_read().await.unwrap();
        let landed = match completed {
            Some(_) => true,
            None => {
                // Probe with a key unique to the staged batch.
                let probe = next_key - 1;
                r.get(&key(probe))
                    .await
                    .unwrap_or_else(|e| panic!("probe read after cancel at {k}: {e:?}"))
                    .is_some()
            }
        };
        let want = if landed { &staged } else { &committed };
        for (&i, &generation) in want {
            let got = r
                .get(&key(i))
                .await
                .unwrap_or_else(|e| panic!("get key {i} after cancel at {k}: {e:?}"));
            assert_eq!(
                got.as_deref(),
                Some(value(i, generation).as_slice()),
                "key {i} inconsistent after commit cancelled at poll {k} (landed={landed})"
            );
        }
        drop(r);
        let report = run_deep_walk(&db).await.unwrap();
        assert!(
            report.is_clean(),
            "deep walk issues after commit cancelled at poll {k}: {:?}",
            report.page_issues
        );
        if landed {
            committed = staged;
        } else {
            // The lost batch's keys were never durable; rewind the key cursor
            // so bookkeeping matches the store.
            next_key -= 20;
        }
    }
}

/// Concurrent readers against a committing writer on a multi-thread runtime,
/// followed by a reopen and cold verification. Reader pins move the
/// reclamation floor while commits recycle pages, so this exercises the
/// begin-time floor scan, the shared allocator cache, and pager cache
/// concurrency under real parallelism.
async fn concurrent_impl<V: Vfs + Clone + Send + Sync + 'static>(vfs: V) {
    let db = std::sync::Arc::new(
        Db::open_internal_with_options(vfs.clone(), KEK, PAGE, REALM, opts())
            .await
            .unwrap(),
    );

    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut readers = Vec::new();
    for r in 0..3u64 {
        let db = db.clone();
        let stop = stop.clone();
        readers.push(tokio::spawn(async move {
            let mut i: u64 = r;
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                let snap = db.begin_read().await.unwrap();
                for _ in 0..20 {
                    // Reads may race ahead of the writer; only decode
                    // errors matter, absence is fine.
                    let _ = snap.get(&key(i % 4000)).await.unwrap();
                    i = i.wrapping_add(13);
                }
                tokio::task::yield_now().await;
            }
        }));
    }

    let mut expected: BTreeMap<u64, u64> = BTreeMap::new();
    let mut next_key: u64 = 0;
    let mut rng: u64 = 0xDEAD_BEEF_CAFE_F00D;
    let mut lcg = move || {
        rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        rng
    };
    for _batch in 0..60u64 {
        let mut w = db.begin_write().await.unwrap();
        if next_key > 100 {
            for _ in 0..15 {
                let i = lcg() % next_key;
                let generation = expected.get(&i).copied().unwrap_or(0) + 1;
                w.put(&key(i), &value(i, generation)).await.unwrap();
                expected.insert(i, generation);
            }
        }
        for _ in 0..30 {
            let i = next_key;
            next_key += 1;
            w.put_append(&key(i), &value(i, 0)).await.unwrap();
            expected.insert(i, 0);
        }
        w.commit().await.unwrap();
    }
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    for r in readers {
        r.await.unwrap();
    }

    let report = run_deep_walk(&db).await.unwrap();
    assert!(report.is_clean(), "deep walk issues: {:?}", report.page_issues);
    verify_all(&db, &expected).await;
    drop(db);

    let db = Db::open_existing_with_options(vfs, KEK, PAGE, REALM, opts())
        .await
        .unwrap();
    verify_all(&db, &expected).await;
    let report = run_deep_walk(&db).await.unwrap();
    assert!(report.is_clean(), "post-reopen issues: {:?}", report.page_issues);
}

/// Randomized structural stress across many seeds: variable-length keys
/// (long separators force frequent multi-level internal splits), values
/// spanning inline through multi-page overflow chains, same-key rewrite
/// churn, deletes, range deletes, aborted txns, and reopen cycles. Runs a
/// deep-walk integrity check after every commit so a lost reference is
/// caught at the commit that created it, and a cold full read-back after
/// every reopen.
async fn randomized_impl<V: Vfs + Clone>(seeds: u64, mut make_vfs: impl FnMut(u64) -> V) {
    for seed in 0..seeds {
        let vfs = make_vfs(seed);
        let mut rng: u64 = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
        let mut next = move || {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            rng
        };
        // Keys: index -> byte key. Length varies with the index so separator
        // keys differ in size across the tree.
        let skey = |i: u64| -> Vec<u8> {
            let pad = (i % 5) as usize * 20;
            format!("{:0width$}", i, width = 12 + pad).into_bytes()
        };
        let sval = |i: u64, generation: u64| -> Vec<u8> {
            // Value length cycles through inline, single-page overflow, and
            // multi-page overflow chains as the generation advances.
            let len = match (i + generation) % 4 {
                0 => 64,
                1 => 700,
                2 => 2500,
                _ => 9000,
            };
            vec![(i.wrapping_mul(37).wrapping_add(generation)) as u8; len]
        };

        let mut expected: BTreeMap<u64, u64> = BTreeMap::new();
        let mut next_key: u64 = 0;

        let db = Db::open_internal_with_options(vfs.clone(), KEK, PAGE, REALM, opts())
            .await
            .unwrap();
        let mut db = db;
        for round in 0..14u64 {
            let mut w = db.begin_write().await.unwrap();
            let ops = 30 + (next() % 40);
            let mut staged = expected.clone();
            for _ in 0..ops {
                match next() % 10 {
                    // Append new keys.
                    0..=3 => {
                        let i = next_key;
                        next_key += 1;
                        w.put(&skey(i), &sval(i, 0)).await.unwrap();
                        staged.insert(i, 0);
                    }
                    // Rewrite an existing key (value class may flip).
                    4..=6 => {
                        if next_key > 0 {
                            let i = next() % next_key;
                            let generation = staged.get(&i).copied().unwrap_or(0) + 1;
                            w.put(&skey(i), &sval(i, generation)).await.unwrap();
                            staged.insert(i, generation);
                        }
                    }
                    // Delete a key.
                    7..=8 => {
                        if next_key > 0 {
                            let i = next() % next_key;
                            if staged.remove(&i).is_some() {
                                assert!(w.delete(&skey(i)).await.unwrap());
                            }
                        }
                    }
                    // Delete a small index window.
                    _ => {
                        if next_key > 20 {
                            let lo = next() % (next_key - 10);
                            let hi = lo + 1 + next() % 8;
                            // Keys are not ordered by index (lengths vary), so
                            // delete by explicit key list for exact bookkeeping.
                            for i in lo..hi.min(next_key) {
                                if staged.remove(&i).is_some() {
                                    assert!(w.delete(&skey(i)).await.unwrap());
                                }
                            }
                        }
                    }
                }
            }
            // One in five txns aborts: its staged mutations must vanish.
            if next() % 5 == 0 {
                w.abort().await;
            } else {
                w.commit()
                    .await
                    .unwrap_or_else(|e| panic!("seed {seed} round {round} commit: {e:?}"));
                expected = staged;
                let report = run_deep_walk(&db).await.unwrap();
                assert!(
                    report.is_clean(),
                    "seed {seed} round {round}: deep walk issues: {:?}",
                    report.page_issues
                );
            }
            // Reopen every few rounds: cold-verify everything.
            if next() % 3 == 0 {
                drop(db);
                db = Db::open_existing_with_options(vfs.clone(), KEK, PAGE, REALM, opts())
                    .await
                    .unwrap_or_else(|e| panic!("seed {seed} round {round} reopen: {e:?}"));
                let r = db.begin_read().await.unwrap();
                for (&i, &generation) in &expected {
                    let got = r.get(&skey(i)).await.unwrap_or_else(|e| {
                        panic!("seed {seed} round {round} get {i}: {e:?}")
                    });
                    assert_eq!(
                        got.as_deref(),
                        Some(sval(i, generation).as_slice()),
                        "seed {seed} round {round} key {i} stale/missing"
                    );
                }
            }
        }
        drop(db);
    }
}

// ------------------------------------------------------------------------ //
// MemVfs runs.
// ------------------------------------------------------------------------ //

#[tokio::test(flavor = "current_thread")]
async fn sustained_put_rewrite_overflow_all_keys_survive() {
    sustained_impl(MemVfs::new()).await;
}

#[tokio::test(flavor = "current_thread")]
async fn reopen_cycle_all_keys_survive() {
    reopen_cycle_impl(MemVfs::new()).await;
}

#[tokio::test(flavor = "current_thread")]
async fn cancelled_commit_leaves_consistent_store() {
    cancelled_commit_impl(MemVfs::new()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_readers_writer_reopen() {
    concurrent_impl(MemVfs::new()).await;
}

#[tokio::test(flavor = "current_thread")]
async fn randomized_structural_stress() {
    randomized_impl(16, |_| MemVfs::new()).await;
}

// ------------------------------------------------------------------------ //
// TokioVfs (real files) runs.
// ------------------------------------------------------------------------ //

#[tokio::test(flavor = "current_thread")]
async fn sustained_all_keys_survive_tokio_disk() {
    let root = disk_root("sustained");
    sustained_impl(TokioVfs::new(&root)).await;
    std::fs::remove_dir_all(&root).ok();
}

#[tokio::test(flavor = "current_thread")]
async fn reopen_cycle_all_keys_survive_tokio_disk() {
    let root = disk_root("reopen");
    reopen_cycle_impl(TokioVfs::new(&root)).await;
    std::fs::remove_dir_all(&root).ok();
}

#[tokio::test(flavor = "current_thread")]
async fn cancelled_commit_consistent_tokio_disk() {
    let root = disk_root("cancel");
    cancelled_commit_impl(TokioVfs::new(&root)).await;
    std::fs::remove_dir_all(&root).ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_readers_writer_reopen_tokio_disk() {
    let root = disk_root("concurrent");
    concurrent_impl(TokioVfs::new(&root)).await;
    std::fs::remove_dir_all(&root).ok();
}

#[tokio::test(flavor = "current_thread")]
async fn randomized_structural_stress_tokio_disk() {
    let root = disk_root("randomized");
    let base = root.clone();
    randomized_impl(6, move |seed| {
        let dir = base.join(format!("seed{seed}"));
        std::fs::create_dir_all(&dir).unwrap();
        TokioVfs::new(dir)
    })
    .await;
    std::fs::remove_dir_all(&root).ok();
}

// ------------------------------------------------------------------------ //
// IouringVfs (Linux default backend) runs.
// ------------------------------------------------------------------------ //

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "current_thread")]
async fn reopen_cycle_all_keys_survive_iouring_disk() {
    let root = disk_root("reopen-uring");
    reopen_cycle_impl(pagedb::vfs::IouringVfs::new(&root).unwrap()).await;
    std::fs::remove_dir_all(&root).ok();
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "current_thread")]
async fn cancelled_commit_consistent_iouring_disk() {
    let root = disk_root("cancel-uring");
    cancelled_commit_impl(pagedb::vfs::IouringVfs::new(&root).unwrap()).await;
    std::fs::remove_dir_all(&root).ok();
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "current_thread")]
async fn randomized_structural_stress_iouring_disk() {
    let root = disk_root("randomized-uring");
    let base = root.clone();
    randomized_impl(6, move |seed| {
        let dir = base.join(format!("seed{seed}"));
        std::fs::create_dir_all(&dir).unwrap();
        pagedb::vfs::IouringVfs::new(dir).unwrap()
    })
    .await;
    std::fs::remove_dir_all(&root).ok();
}
