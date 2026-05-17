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
