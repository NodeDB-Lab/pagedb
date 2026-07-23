//! Reproduction target: a live B+ tree page freed (and later recycled) while a
//! parent internal node still references it — a use-after-free that leaves a
//! dangling internal→freed child pointer and bricks the store on the next read
//! of any key under that pointer (the exact shape that bricked a real
//! nodedb-lite store: identity KV leaf freed, parent still pointing at it,
//! page reused as a free-list chain host).
//!
//! Shape mirrors nodedb-lite: **two-tree commits** — each commit materializes
//! BOTH the data B+ tree (KV puts, overflow values) AND the catalog B+ tree
//! (segment link/unlink), sharing one page allocator. Heavy overwrite churn +
//! segment churn under a held read snapshot, one op per commit. If any commit
//! frees a page still referenced by either tree's committed spine, the strict
//! structural deep-walk flags it.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use pagedb::options::RetainPolicy;
use pagedb::recovery::run_deep_walk;
use pagedb::segment::types::SegmentPageKind;
use pagedb::vfs::memory::MemVfs;
use pagedb::{Db, OpenOptions, RealmId, SegmentKind};

const KEK: [u8; 32] = [0x2Au8; 32];
const REALM: RealmId = RealmId::new([0x5Cu8; 16]);
const PAGE: usize = 4096;

fn lite_like_opts() -> OpenOptions {
    OpenOptions::default().with_commit_history_retain(RetainPolicy::Disabled)
}

fn key(i: u32) -> Vec<u8> {
    format!("k:{i:08}").into_bytes()
}

fn value(i: u32, generation: u32) -> Vec<u8> {
    let bucket = (i.wrapping_mul(3).wrapping_add(generation) % 10) as usize;
    let len = match bucket {
        0..=4 => 60 + bucket * 40,
        5..=7 => 300 + bucket * 120,
        _ => 1300 + bucket * 700, // > page/4 → overflow chain
    };
    let mut v = vec![0u8; len];
    v[0..4].copy_from_slice(&i.to_le_bytes());
    if len >= 8 {
        v[4..8].copy_from_slice(&generation.to_le_bytes());
    }
    for (j, b) in v.iter_mut().enumerate().skip(8) {
        *b = (i as usize)
            .wrapping_mul(31)
            .wrapping_add((generation as usize).wrapping_mul(131))
            .wrapping_add(j) as u8;
    }
    v
}

fn lcg(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    *state >> 16
}

/// Seal a small segment and return its meta (grows the catalog tree when linked).
async fn make_segment(db: &Db<MemVfs>, gn: u32) -> pagedb::catalog::codec::SegmentMeta {
    let mut w = db
        .create_segment(REALM, SegmentKind::Unspecified)
        .await
        .unwrap();
    let mut content = [0u8; 256];
    content[0..4].copy_from_slice(&gn.to_le_bytes());
    w.append_page(SegmentPageKind::Data, &content)
        .await
        .unwrap();
    w.seal().await.unwrap()
}

async fn assert_clean(db: &Db<MemVfs>, ctx: &str) {
    let report = run_deep_walk(db).await.unwrap();
    assert!(
        report.is_clean(),
        "{ctx}: deep-walk found {} issue(s): {:?}",
        report.page_issues.len(),
        report.page_issues,
    );
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "slow free/reparent stress; run with --run-ignored all"]
async fn two_tree_churn_never_frees_a_live_page() {
    const N: u32 = 1500;
    const ROUNDS: u32 = 300;

    let db = Db::open(MemVfs::new(), KEK, PAGE, REALM, lite_like_opts())
        .await
        .unwrap();

    for i in 0..N {
        let mut w = db.begin_write().await.unwrap();
        w.put(&key(i), &value(i, 0)).await.unwrap();
        w.commit().await.unwrap();
    }
    assert_clean(&db, "after seed").await;

    let mut rng = 0x1234_5678_9abc_def0u64;
    let mut generation = 1u32;
    let mut linked: Vec<String> = Vec::new();
    let mut seg_ctr = 0u32;

    for round in 0..ROUNDS {
        let pin = db.begin_read().await.unwrap();

        for _ in 0..150 {
            let i = (lcg(&mut rng) % u64::from(N)) as u32;
            // Two-tree commit: data put + a catalog op sharing one allocator.
            let mut w = db.begin_write().await.unwrap();
            w.put(&key(i), &value(i, generation)).await.unwrap();
            match lcg(&mut rng) % 3 {
                0 => {
                    // Link a fresh segment (grows catalog).
                    seg_ctr += 1;
                    let name = format!("seg-{seg_ctr:06}");
                    let meta = make_segment(&db, generation).await;
                    w.link_segment(&name, &meta).await.unwrap();
                    linked.push(name);
                }
                1 if !linked.is_empty() => {
                    // Unlink an old segment (frees catalog pages → reparent).
                    let idx = (lcg(&mut rng) as usize) % linked.len();
                    let name = linked.swap_remove(idx);
                    w.unlink_segment(&name).await.unwrap();
                }
                _ => {}
            }
            w.commit().await.unwrap();
        }

        // Contiguous delete run → catalog+data merges, then reinsert.
        let base = (lcg(&mut rng) % u64::from(N.saturating_sub(80))) as u32;
        for d in 0..60 {
            let mut w = db.begin_write().await.unwrap();
            w.delete(&key(base + d)).await.unwrap();
            w.commit().await.unwrap();
        }
        for d in 0..60 {
            let mut w = db.begin_write().await.unwrap();
            w.put(&key(base + d), &value(base + d, generation))
                .await
                .unwrap();
            w.commit().await.unwrap();
        }

        drop(pin);
        generation = generation.wrapping_add(1);

        if round % 15 == 0 {
            assert_clean(&db, &format!("round {round}")).await;
            let r = db.begin_read().await.unwrap();
            for i in 0..N {
                r.get(&key(i))
                    .await
                    .unwrap_or_else(|e| panic!("round {round}: get key {i} failed: {e}"));
            }
            drop(r);
        }
    }

    assert_clean(&db, "final").await;
}

/// Multi-threaded: reader tasks run get-loops on other OS threads genuinely
/// concurrent with the writer's commit / free-list manipulation — the one
/// dimension the daemon has that a current_thread test cannot express.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "slow free/reparent stress; run with --run-ignored all"]
async fn concurrent_readers_during_churn_never_free_a_live_page() {
    const N: u32 = 1200;
    const ROUNDS: u32 = 200;

    let db = Arc::new(
        Db::open(MemVfs::new(), KEK, PAGE, REALM, lite_like_opts())
            .await
            .unwrap(),
    );
    for i in 0..N {
        let mut w = db.begin_write().await.unwrap();
        w.put(&key(i), &value(i, 0)).await.unwrap();
        w.commit().await.unwrap();
    }

    let stop = Arc::new(AtomicBool::new(false));
    let mut readers = Vec::new();
    for _ in 0..3 {
        let db = db.clone();
        let stop = stop.clone();
        readers.push(tokio::spawn(async move {
            let mut i = 0u32;
            while !stop.load(Ordering::Relaxed) {
                if let Ok(r) = db.begin_read().await {
                    let _ = r.get(&key(i % N)).await; // ignore transient errors; final walk is the judge
                }
                i = i.wrapping_add(7);
            }
        }));
    }

    let mut rng = 0xdead_beef_1234_5678u64;
    let mut generation = 1u32;
    for round in 0..ROUNDS {
        for _ in 0..200 {
            let i = (lcg(&mut rng) % u64::from(N)) as u32;
            let mut w = db.begin_write().await.unwrap();
            w.put(&key(i), &value(i, generation)).await.unwrap();
            w.commit().await.unwrap();
        }
        let base = (lcg(&mut rng) % u64::from(N.saturating_sub(80))) as u32;
        for d in 0..60 {
            let mut w = db.begin_write().await.unwrap();
            w.delete(&key(base + d)).await.unwrap();
            w.commit().await.unwrap();
        }
        for d in 0..60 {
            let mut w = db.begin_write().await.unwrap();
            w.put(&key(base + d), &value(base + d, generation))
                .await
                .unwrap();
            w.commit().await.unwrap();
        }
        generation = generation.wrapping_add(1);
        if round % 20 == 0 {
            assert_clean(&db, &format!("concurrent round {round}")).await;
        }
    }

    stop.store(true, Ordering::Relaxed);
    for r in readers {
        let _ = r.await;
    }
    assert_clean(&db, "concurrent final").await;
}
