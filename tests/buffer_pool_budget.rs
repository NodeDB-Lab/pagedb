//! `buffer_pool_pages` is a budget the pool returns to.
//!
//! Dirty and pinned pages can hold the pool over budget, but only until they are
//! flushed, discarded, or released. An idle handle has neither, so every entry
//! is evictable and the pool holds at most `buffer_pool_pages`.

use pagedb::vfs::memory::MemVfs;
use pagedb::{Db, OpenOptions, RealmId};

const PAGE: usize = 4096;
const KEK: [u8; 32] = [0x71u8; 32];
const REALM: RealmId = RealmId::new([0xD2u8; 16]);
const BUDGET: usize = 256;

async fn open_db() -> Db<MemVfs> {
    let options = OpenOptions::default().with_buffer_pool_pages(BUDGET);
    Db::open(MemVfs::new(), KEK, PAGE, REALM, options)
        .await
        .unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn idle_handle_after_large_commit_reports_resident_pages_within_budget() {
    let db = open_db().await;
    let value = [0x5Au8; 64];

    let mut txn = db.begin_write().await.unwrap();
    for i in 0..20_000u32 {
        txn.put(format!("k-{i:06}").as_bytes(), &value)
            .await
            .unwrap();
    }
    txn.commit().await.unwrap();

    let stats = db.stats().await.unwrap();
    assert!(
        stats.main_db_next_page_id > BUDGET as u64,
        "the commit must write more pages than the budget, wrote {}",
        stats.main_db_next_page_id
    );
    assert_eq!(stats.dirty_pages, 0);
    assert!(
        stats.buffer_pool_pages <= BUDGET as u64,
        "{} pages resident on an idle handle with a budget of {BUDGET}",
        stats.buffer_pool_pages
    );

    // A full read pass keeps the bound, and the data survives the evictions.
    let reader = db.begin_read().await.unwrap();
    for i in 0..20_000u32 {
        let found = reader.get(format!("k-{i:06}").as_bytes()).await.unwrap();
        assert_eq!(found.as_deref(), Some(value.as_slice()), "row {i}");
    }
    drop(reader);
    let stats = db.stats().await.unwrap();
    assert!(stats.buffer_pool_pages <= BUDGET as u64);
}

/// Each value exceeds a quarter page, so `put` writes an overflow page through
/// the pager at once, with no flush until commit. The pool therefore overgrows
/// before the abort, and the test asserts that it does.
#[tokio::test(flavor = "current_thread")]
async fn aborted_large_transaction_returns_pool_to_budget() {
    let db = open_db().await;
    let value = vec![0x3Cu8; 3000];

    let mut txn = db.begin_write().await.unwrap();
    for i in 0..2_000u32 {
        txn.put(format!("k-{i:06}").as_bytes(), &value)
            .await
            .unwrap();
    }
    let during = db.stats().await.unwrap();
    assert!(
        during.buffer_pool_pages > BUDGET as u64,
        "the transaction must overgrow the pool, holds {} pages",
        during.buffer_pool_pages
    );

    txn.abort().await;

    let after = db.stats().await.unwrap();
    assert_eq!(after.dirty_pages, 0);
    assert!(
        after.buffer_pool_pages <= BUDGET as u64,
        "{} pages resident after an abort with a budget of {BUDGET}",
        after.buffer_pool_pages
    );
    let reader = db.begin_read().await.unwrap();
    assert!(reader.get(b"k-000000").await.unwrap().is_none());
}
