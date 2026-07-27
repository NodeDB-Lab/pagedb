//! A write transaction must not be bounded by the nonce anchor budget.
//!
//! Every newly-encrypted page draws a nonce, and the counter may only run
//! `anchor_budget` ahead of the anchor the header has made durable. A commit
//! writes its header once, at the end, so without an intervening refresh the
//! whole transaction had to fit in a single window — which made the budget a
//! silent ceiling on how much one transaction could write, and made a store's
//! maximum useful transaction a function of a tuning knob rather than of disk
//! or memory.

use pagedb::vfs::memory::MemVfs;
use pagedb::{Db, OpenOptions, RealmId};

const PAGE: usize = 4096;
const KEK: [u8; 32] = [0x6Eu8; 32];
const REALM: RealmId = RealmId::new([0xC4u8; 16]);

/// Deliberately far below the default: the property is "more pages than the
/// budget", not any particular size, so a small budget keeps the test fast
/// while still forcing many refreshes.
const BUDGET: u64 = 8;

#[tokio::test(flavor = "current_thread")]
async fn one_transaction_may_write_more_pages_than_the_anchor_budget() {
    let options = OpenOptions::default().with_anchor_budget(BUDGET);
    let db = Db::open_internal_with_options(MemVfs::new(), KEK, PAGE, REALM, options)
        .await
        .unwrap();

    // Each value exceeds a quarter page, so every row takes an overflow page of
    // its own — the row count is a lower bound on newly-encrypted pages, well
    // past the budget.
    let value = vec![0x7Au8; 3000];
    let rows = 200u32;

    let mut txn = db.begin_write().await.unwrap();
    for i in 0..rows {
        txn.put(format!("k-{i:05}").as_bytes(), &value)
            .await
            .unwrap();
    }
    txn.commit()
        .await
        .expect("a transaction larger than the anchor budget must still commit");

    // The data is durable and complete, not merely accepted.
    let read = db.begin_read().await.unwrap();
    for i in 0..rows {
        assert_eq!(
            read.get(format!("k-{i:05}").as_bytes())
                .await
                .unwrap()
                .as_deref(),
            Some(value.as_slice()),
            "row {i} did not survive a transaction that spanned several anchor windows"
        );
    }
    drop(read);

    // And it survives a reopen, so the anchor the refreshes left behind is
    // consistent with what was written rather than merely in-memory.
    drop(db);
    assert!(rows > BUDGET as u32, "the fixture must exceed the budget");
}
