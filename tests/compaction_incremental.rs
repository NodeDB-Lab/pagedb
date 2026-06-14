//! Integration tests for incremental compaction: watermark persistence,
//! progress reporting, batched compaction, crash-resume semantics, and
//! interleaving of writes between compaction steps.

use pagedb::vfs::memory::MemVfs;
use pagedb::{CompactBudget, Db, RealmId};

const PAGE: usize = 4096;
const REALM: RealmId = RealmId::new([0x55; 16]);
const KEK: [u8; 32] = [0x22; 32];

async fn fresh_db() -> Db<MemVfs> {
    Db::open_internal(MemVfs::new(), KEK, PAGE, REALM)
        .await
        .unwrap()
}

// ─── Test 1: compact_step returns more_work=false on empty db ────────────────

#[tokio::test(flavor = "current_thread")]
async fn compact_step_empty_db() {
    let db = fresh_db().await;
    let prog = db.compact_step(CompactBudget::default()).await.unwrap();
    assert!(!prog.more_work, "empty db should have no more work");
    assert_eq!(prog.pages_relocated, 0);
    assert!(prog.watermark.is_none());
}

// ─── Test 2: compact_now finishes a db with no deleted keys ──────────────────

#[tokio::test(flavor = "current_thread")]
async fn compact_now_no_free_pages() {
    let db = fresh_db().await;

    // Write 20 keys.
    {
        let mut txn = db.begin_write().await.unwrap();
        for i in 0u32..20 {
            let key = format!("key-{i:04}");
            txn.put(key.as_bytes(), b"value").await.unwrap();
        }
        txn.commit().await.unwrap();
    }

    let stats = db.compact_now().await.unwrap();
    // No pages should be reclaimed (no deletions).
    let _ = stats; // stats are informational; just verify it completes
}

// ─── Test 3: compact_step advances watermark in each call ────────────────────

#[tokio::test(flavor = "current_thread")]
async fn compact_step_watermark_advances() {
    let db = fresh_db().await;

    // Write 100 keys and delete half to create free pages.
    {
        let mut txn = db.begin_write().await.unwrap();
        for i in 0u32..100 {
            let key = format!("wm-{i:04}");
            txn.put(key.as_bytes(), b"watermark-test-value")
                .await
                .unwrap();
        }
        txn.commit().await.unwrap();
    }
    {
        let mut txn = db.begin_write().await.unwrap();
        for i in (0u32..100).step_by(2) {
            let key = format!("wm-{i:04}");
            txn.delete(key.as_bytes()).await.unwrap();
        }
        txn.commit().await.unwrap();
    }

    // Run compaction in tiny batches of 5 and verify watermark is monotonically
    // non-decreasing until completion.
    let budget = CompactBudget::new(5, 10_000);

    let mut prev_watermark: Option<u64> = None;
    let mut iterations = 0usize;
    loop {
        let prog = db.compact_step(budget).await.unwrap();
        iterations += 1;

        if let Some(wm) = prog.watermark {
            if let Some(prev) = prev_watermark {
                assert!(
                    wm >= prev,
                    "watermark must not decrease: prev={prev} current={wm}"
                );
            }
            prev_watermark = Some(wm);
        } else {
            // Watermark cleared = session complete.
            assert!(!prog.more_work);
            break;
        }

        if !prog.more_work {
            break;
        }

        assert!(iterations < 10_000, "compaction did not converge");
    }
}

// ─── Test 4: Writes between steps do not corrupt data ────────────────────────

#[tokio::test(flavor = "current_thread")]
async fn writes_between_steps_do_not_corrupt() {
    let db = fresh_db().await;

    // Write 60 keys.
    {
        let mut txn = db.begin_write().await.unwrap();
        for i in 0u32..60 {
            let key = format!("interleave-{i:04}");
            txn.put(key.as_bytes(), b"initial-value").await.unwrap();
        }
        txn.commit().await.unwrap();
    }
    // Delete half.
    {
        let mut txn = db.begin_write().await.unwrap();
        for i in (0u32..60).step_by(2) {
            let key = format!("interleave-{i:04}");
            txn.delete(key.as_bytes()).await.unwrap();
        }
        txn.commit().await.unwrap();
    }

    let budget = CompactBudget::new(3, 10_000);

    // Alternate: one compaction step, then a normal write.
    let mut extra_writes = 0u32;
    let mut iters = 0usize;
    loop {
        let prog = db.compact_step(budget).await.unwrap();
        iters += 1;

        // Write a new key between compaction steps.
        {
            let mut txn = db.begin_write().await.unwrap();
            let key = format!("new-{extra_writes:04}");
            txn.put(key.as_bytes(), b"new-value").await.unwrap();
            txn.commit().await.unwrap();
        }
        extra_writes += 1;

        if !prog.more_work {
            break;
        }
        assert!(iters < 10_000, "compaction did not converge");
    }

    // Verify all surviving original keys are intact.
    let txn = db.begin_read().await.unwrap();
    for i in 0u32..60 {
        let key = format!("interleave-{i:04}");
        let got = txn.get(key.as_bytes()).await.unwrap();
        if i % 2 == 0 {
            assert!(got.is_none(), "{key} should be deleted");
        } else {
            assert_eq!(
                got.unwrap().as_slice(),
                b"initial-value",
                "{key} value mismatch"
            );
        }
    }
    // Verify newly written keys are readable.
    for j in 0..extra_writes {
        let key = format!("new-{j:04}");
        let got = txn.get(key.as_bytes()).await.unwrap();
        assert_eq!(got.unwrap().as_slice(), b"new-value", "{key} missing");
    }
}

// ─── Test 5: compact_now loops until more_work = false ───────────────────────

#[tokio::test(flavor = "current_thread")]
async fn compact_now_completes_fully() {
    let db = fresh_db().await;

    {
        let mut txn = db.begin_write().await.unwrap();
        for i in 0u32..80 {
            let key = format!("full-{i:04}");
            txn.put(key.as_bytes(), b"full-value").await.unwrap();
        }
        txn.commit().await.unwrap();
    }
    {
        let mut txn = db.begin_write().await.unwrap();
        for i in 0u32..40 {
            let key = format!("full-{i:04}");
            txn.delete(key.as_bytes()).await.unwrap();
        }
        txn.commit().await.unwrap();
    }

    db.compact_now().await.unwrap();

    // After full compaction, a single compact_step should report more_work=false.
    let prog = db.compact_step(CompactBudget::default()).await.unwrap();
    assert!(
        !prog.more_work,
        "after compact_now, compact_step should have no more work"
    );
    assert!(prog.watermark.is_none());

    // All surviving keys must still be readable.
    let txn = db.begin_read().await.unwrap();
    for i in 40u32..80 {
        let key = format!("full-{i:04}");
        let got = txn.get(key.as_bytes()).await.unwrap();
        assert_eq!(
            got.unwrap().as_slice(),
            b"full-value",
            "{key} missing after compact_now"
        );
    }
}

// ─── Test: history is consistently discarded across compact_step (no dangling
//     commit-history root in the durable header) ────────────────────────────
#[tokio::test(flavor = "current_thread")]
async fn compact_step_reopen_history_consistent() {
    let vfs = MemVfs::new();
    {
        // Default options retain commit history (Count(1024)). Build several
        // commits so a history tree exists, then incrementally compact through
        // intermediate steps and a final dense repack.
        let db = Db::open_internal(vfs.clone(), KEK, PAGE, REALM)
            .await
            .unwrap();
        for round in 0u32..15 {
            let mut w = db.begin_write().await.unwrap();
            for i in 0u32..30 {
                w.put(format!("k{round:02}_{i:04}").as_bytes(), &[round as u8; 64])
                    .await
                    .unwrap();
            }
            w.commit().await.unwrap();
        }
        let budget = CompactBudget::new(5, 10_000); // small → intermediate steps + final
        let mut iters = 0;
        loop {
            let p = db.compact_step(budget).await.unwrap();
            iters += 1;
            assert!(iters < 10_000, "compaction did not converge");
            if !p.more_work {
                break;
            }
        }
        // Db drops here.
    }

    // Reopen. Before the fix, the header still pointed at the pre-repack
    // commit-history root (overwritten/truncated by the dense repack), so the
    // next write — which opens the history tree at that root — corrupted or
    // errored. It must now be a clean reset (root = 0).
    let db = Db::open_existing(vfs.clone(), KEK, PAGE, REALM)
        .await
        .unwrap();
    {
        let mut w = db.begin_write().await.unwrap();
        w.put(b"after-reopen", b"v").await.unwrap();
        w.commit().await.unwrap();
    }
    let r = db.begin_read().await.unwrap();
    assert_eq!(
        r.get(b"after-reopen").await.unwrap().as_deref(),
        Some(&b"v"[..])
    );
    // Pre-compaction data survived the repack.
    assert!(
        r.get(b"k00_0000").await.unwrap().is_some(),
        "data written before compaction must survive"
    );
}

// ─── Test: an intermediate compact_step preserves the durable free-list ──────
#[tokio::test(flavor = "current_thread")]
async fn compact_step_preserves_free_list() {
    // No commit history, so freed pages are immediately reclaimable and tracked
    // in the durable free-list with no reader/history pinning them.
    let opts = pagedb::options::OpenOptions::default()
        .with_commit_history_retain(pagedb::options::RetainPolicy::Disabled);
    let db = Db::open_internal_with_options(MemVfs::new(), KEK, PAGE, REALM, opts)
        .await
        .unwrap();

    // Build a working set, then delete most of it to populate the free-list.
    {
        let mut w = db.begin_write().await.unwrap();
        for i in 0u32..300 {
            w.put(format!("k{i:05}").as_bytes(), &[1u8; 128])
                .await
                .unwrap();
        }
        w.commit().await.unwrap();
    }
    {
        let mut w = db.begin_write().await.unwrap();
        for i in 0u32..250 {
            w.delete(format!("k{i:05}").as_bytes()).await.unwrap();
        }
        w.commit().await.unwrap();
    }
    let pending_before = db.stats().await.unwrap().free_list_pending_entries;
    assert!(
        pending_before > 0,
        "setup should have populated the free-list; got {pending_before}"
    );

    // One intermediate step (small budget so it is NOT the final batch).
    let prog = db
        .compact_step(CompactBudget::new(5, 10_000))
        .await
        .unwrap();
    assert!(prog.more_work, "small budget should leave more work");

    // The pre-existing free-list must survive the intermediate step, not be
    // wiped — those pages are still reusable by ordinary writes.
    let pending_after = db.stats().await.unwrap().free_list_pending_entries;
    assert!(
        pending_after >= pending_before,
        "intermediate compact_step wiped the durable free-list: {pending_before} -> {pending_after}"
    );
}
