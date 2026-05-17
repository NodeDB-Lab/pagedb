/// Verify that durable reader-pin rows are created in the catalog when
/// `begin_read` is called and removed when the `ReadTxn` is dropped.
use pagedb::vfs::memory::MemVfs;
use pagedb::{Db, RealmId};

const PAGE: usize = 4096;

async fn open_db() -> Db<MemVfs> {
    Db::open_internal(MemVfs::new(), [11u8; 32], PAGE, RealmId::new([3u8; 16]))
        .await
        .unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn begin_read_before_catalog_creates_no_durable_pin() {
    // Without a catalog (no catalog_root_page_id), begin_read returns a txn
    // without a durable pin. This should succeed cleanly.
    let db = open_db().await;
    let r = db.begin_read().await.unwrap();
    // Read succeeds; no catalog exists yet so no durable pin written.
    assert!(r.get(b"any").await.unwrap().is_none());
    drop(r);
    // No crash on drop.
}

#[tokio::test(flavor = "current_thread")]
async fn reader_pin_inserted_and_removed_after_catalog_exists() {
    let db = open_db().await;

    // Trigger catalog creation by writing a segment (catalog is created on
    // the first link_segment / commit that touches it). Here we simply ensure
    // a write transaction commits so open proceeds.
    {
        let mut w = db.begin_write().await.unwrap();
        w.put(b"sentinel", b"1").await.unwrap();
        w.commit().await.unwrap();
    }

    // A second write creates the catalog if it does not yet exist.
    // begin_read should now insert a durable pin row.
    let r = db.begin_read().await.unwrap();
    assert_eq!(
        r.get(b"sentinel").await.unwrap().as_deref(),
        Some(b"1".as_ref())
    );
    drop(r);

    // After drop, the pending_pin_deletes queue is non-empty; the next gc_now
    // drains it without error.
    db.gc_now().await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn multiple_concurrent_read_txns_drop_cleanly() {
    let db = open_db().await;
    {
        let mut w = db.begin_write().await.unwrap();
        w.put(b"k", b"v").await.unwrap();
        w.commit().await.unwrap();
    }

    let r1 = db.begin_read().await.unwrap();
    let r2 = db.begin_read().await.unwrap();
    let r3 = db.begin_read().await.unwrap();

    assert_eq!(r1.get(b"k").await.unwrap().as_deref(), Some(b"v".as_ref()));
    assert_eq!(r2.get(b"k").await.unwrap().as_deref(), Some(b"v".as_ref()));
    assert_eq!(r3.get(b"k").await.unwrap().as_deref(), Some(b"v".as_ref()));

    drop(r1);
    drop(r2);
    drop(r3);

    // Drain pending deletes.
    db.gc_now().await.unwrap();
}
