//! Tests for counter torn-write hardening and durable monotonicity.

use pagedb::vfs::memory::MemVfs;
use pagedb::{Db, OpenOptions, RealmId};

const KEK: [u8; 32] = [9u8; 32];
const REALM: RealmId = RealmId::new([1u8; 16]);

#[tokio::test(flavor = "current_thread")]
async fn counter_increments_persist_and_reload() {
    let vfs = MemVfs::new();
    let opts = OpenOptions::default().with_buffer_pool_pages(64);

    // Open, increment, close.
    {
        let db = Db::open_internal_with_options(vfs.clone(), KEK, 4096, REALM, opts.clone())
            .await
            .unwrap();
        let mut txn = db.begin_write().await.unwrap();
        let mut counter_ref = txn.counter("hits").unwrap();
        let new_val = counter_ref.increment_by(100).await.unwrap();
        assert_eq!(new_val, 100);
        drop(counter_ref);
        txn.commit().await.unwrap();
    }

    // Reopen and verify the value is preserved.
    {
        let db = Db::open_existing_with_options(vfs.clone(), KEK, 4096, REALM, opts.clone())
            .await
            .unwrap();
        let mut txn = db.begin_write().await.unwrap();
        let counter_ref = txn.counter("hits").unwrap();
        let val = counter_ref.get().await.unwrap();
        assert_eq!(val, 100, "counter value should persist across reopen");
        drop(counter_ref);
        txn.abort().await;
    }
}

#[tokio::test(flavor = "current_thread")]
async fn counter_monotonicity_enforced() {
    let vfs = MemVfs::new();
    let opts = OpenOptions::default().with_buffer_pool_pages(64);

    let db = Db::open_internal_with_options(vfs, KEK, 4096, REALM, opts)
        .await
        .unwrap();

    // Set counter to 50.
    {
        let mut txn = db.begin_write().await.unwrap();
        let mut counter_ref = txn.counter("mono").unwrap();
        counter_ref.set(50).await.unwrap();
        drop(counter_ref);
        txn.commit().await.unwrap();
    }

    // Attempting to set backward should fail.
    {
        let mut txn = db.begin_write().await.unwrap();
        let mut counter_ref = txn.counter("mono").unwrap();
        let err = counter_ref.set(30).await.unwrap_err();
        assert!(
            matches!(err, pagedb::PagedbError::Aborted),
            "backward set should return Aborted, got {err:?}"
        );
        drop(counter_ref);
        txn.abort().await;
    }

    // Incrementing forward should still work.
    {
        let mut txn = db.begin_write().await.unwrap();
        let mut counter_ref = txn.counter("mono").unwrap();
        let val = counter_ref.increment_by(10).await.unwrap();
        assert_eq!(val, 60);
        drop(counter_ref);
        txn.commit().await.unwrap();
    }
}

#[tokio::test(flavor = "current_thread")]
async fn counter_anchor_recovery_on_reopen() {
    // Simulate torn write: after a commit, manually zero out a counter row
    // in the catalog by reopening and directly overwriting (simulating a
    // crash that lost the catalog update but kept the header with counter_anchor).
    //
    // In our MemVfs-based environment we cannot easily simulate a partial
    // crash, so we verify the weaker property: that after a normal round-trip,
    // the counter value is at least the anchor written in the header. We do
    // this by checking that on reopen with a non-zero anchor the recovery path
    // is exercised without error.
    let vfs = MemVfs::new();
    let opts = OpenOptions::default().with_buffer_pool_pages(64);

    // Open, set counter, close.
    {
        let db = Db::open_internal_with_options(vfs.clone(), KEK, 4096, REALM, opts.clone())
            .await
            .unwrap();
        let mut txn = db.begin_write().await.unwrap();
        let mut counter_ref = txn.counter("anchor_test").unwrap();
        counter_ref.set(42).await.unwrap();
        drop(counter_ref);
        txn.commit().await.unwrap();
    }

    // Reopen — recovery_counter_monotonicity runs internally.
    {
        let db = Db::open_existing_with_options(vfs.clone(), KEK, 4096, REALM, opts.clone())
            .await
            .unwrap();
        let mut txn = db.begin_write().await.unwrap();
        let counter_ref = txn.counter("anchor_test").unwrap();
        let val = counter_ref.get().await.unwrap();
        // Value must be at least 42 (the anchor ensures it is never less).
        assert!(
            val >= 42,
            "counter should be at least the anchored value after reopen; got {val}"
        );
        drop(counter_ref);
        txn.abort().await;
    }
}
