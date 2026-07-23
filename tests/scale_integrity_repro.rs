//! Regression: data integrity + bounded growth under a growing, distinct-key
//! workload with one commit per key — the shape a document store (e.g.
//! nodedb-lite indexing a codebase) produces — while a **long-lived reader**
//! pins an old snapshot. The existing deferred-free tests rewrite a *constant*
//! 20-key set (tiny tree, no readers); this exercises a large tree while a
//! reader holds the reclamation floor.
//!
//! Guards the free-list-chain feedback loop: rewriting the chain frees its own
//! old pages, and if those metadata pages are floor-gated like reader-visible
//! data they cannot be reclaimed under a pin, so they re-enter the chain as
//! entries and it grows by its own size every commit — eventually one commit
//! exceeds the per-commit AEAD nonce budget and aborts (and, short of that, is
//! severe write amplification). A failure shows up as a commit `Aborted`, a
//! wrong/absent value on read-back, an AEAD/MAC verification error, or an
//! unbounded `next_page_id`.

use pagedb::options::{OpenOptions, RetainPolicy};
use pagedb::recovery::run_deep_walk;
use pagedb::vfs::memory::MemVfs;
use pagedb::{Db, RealmId};

const KEK: [u8; 32] = [0x2Au8; 32];
const REALM: RealmId = RealmId::new([0x5Cu8; 16]);
const PAGE: usize = 4096;

/// nodedb-lite opens with commit history disabled — mirror that here so the
/// freelist reclaim behaviour matches the real store.
fn lite_like_opts() -> OpenOptions {
    OpenOptions::default().with_commit_history_retain(RetainPolicy::Disabled)
}

fn key(i: u32) -> Vec<u8> {
    format!("entry:{i:08}").into_bytes()
}

/// ~1 KiB value, content keyed by `i` so read-back can verify the exact bytes.
fn value(i: u32) -> Vec<u8> {
    let mut v = vec![0u8; 1024];
    v[0..4].copy_from_slice(&i.to_le_bytes());
    for (j, b) in v.iter_mut().enumerate().skip(4) {
        *b = ((i as usize).wrapping_mul(31).wrapping_add(j)) as u8;
    }
    v
}

/// Insert `n` distinct keys, one commit per key, and read every key back within
/// the same session. No readers held. Verifies exact bytes + structural walk.
#[tokio::test(flavor = "current_thread")]
async fn growing_keys_one_commit_each_stay_intact() {
    let n: u32 = 5000;
    let db = Db::open_internal_with_options(MemVfs::new(), KEK, PAGE, REALM, lite_like_opts())
        .await
        .unwrap();

    for i in 0..n {
        let mut w = db.begin_write().await.unwrap();
        w.put(&key(i), &value(i)).await.unwrap();
        w.commit().await.unwrap();
    }

    // Read every key back and verify exact bytes.
    let r = db.begin_read().await.unwrap();
    for i in 0..n {
        let got = r
            .get(&key(i))
            .await
            .unwrap_or_else(|e| panic!("read key {i} errored (corruption?): {e}"));
        assert_eq!(
            got.as_deref(),
            Some(value(i).as_slice()),
            "key {i} did not read back intact"
        );
    }
    drop(r);

    let report = run_deep_walk(&db).await.unwrap();
    assert!(
        report.is_clean(),
        "deep walk found structural corruption: {} page, {} segment, {} drift issue(s): {:?}",
        report.page_issues.len(),
        report.segment_issues.len(),
        report.drift_issues.len(),
        report.page_issues,
    );
}

/// Same growing workload, but a long-lived reader snapshot is opened early and
/// held across all writes — pinning an old commit and exercising the freelist
/// reclamation floor's reader accounting while the tree grows and splits.
#[tokio::test(flavor = "current_thread")]
async fn growing_keys_with_interleaved_readers_stay_intact() {
    let n: u32 = 5000;
    let db = Db::open_internal_with_options(MemVfs::new(), KEK, PAGE, REALM, lite_like_opts())
        .await
        .unwrap();

    // Seed a few keys, then open a long-lived reader pinning this early commit.
    for i in 0..16 {
        let mut w = db.begin_write().await.unwrap();
        w.put(&key(i), &value(i)).await.unwrap();
        w.commit().await.unwrap();
    }
    let pinned = db.begin_read().await.unwrap();

    for i in 16..n {
        let mut w = db.begin_write().await.unwrap();
        w.put(&key(i), &value(i)).await.unwrap();
        w.commit()
            .await
            .unwrap_or_else(|e| panic!("commit aborted at i={i} (free-list feedback loop?): {e:?}"));
    }

    // Bounded growth: the file must not explode. Before the fix, the chain fed
    // itself and `next_page_id` ran to ~250k for 5000 one-key commits under the
    // pin; a healthy store stays a small multiple of the live page count.
    let next_page_id = db.stats().await.unwrap().main_db_next_page_id;
    assert!(
        next_page_id < 50_000,
        "next_page_id exploded to {next_page_id} for {n} keys — free-list feedback loop"
    );

    // The pinned reader must still see its early snapshot intact (its pages must
    // not have been recycled out from under it).
    for i in 0..16 {
        let got = pinned
            .get(&key(i))
            .await
            .unwrap_or_else(|e| panic!("pinned reader key {i} errored (corruption?): {e}"));
        assert_eq!(
            got.as_deref(),
            Some(value(i).as_slice()),
            "pinned reader: key {i} not intact"
        );
    }
    drop(pinned);

    // And the current state has every key.
    let r = db.begin_read().await.unwrap();
    for i in 0..n {
        let got = r
            .get(&key(i))
            .await
            .unwrap_or_else(|e| panic!("current read key {i} errored (corruption?): {e}"));
        assert_eq!(
            got.as_deref(),
            Some(value(i).as_slice()),
            "current: key {i} not intact"
        );
    }
    drop(r);

    let report = run_deep_walk(&db).await.unwrap();
    assert!(report.is_clean(), "deep walk found corruption: {:?}", report.page_issues);
}
