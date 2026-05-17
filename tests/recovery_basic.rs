use pagedb::catalog::codec::SegmentKind;
use pagedb::errors::PagedbError;
use pagedb::segment::types::SegmentPageKind;
use pagedb::vfs::memory::MemVfs;
use pagedb::{Db, RealmId};

const PAGE: usize = 4096;

#[tokio::test(flavor = "current_thread")]
async fn open_existing_reconciles_clean_catalog() {
    let vfs = MemVfs::new();
    {
        let db = Db::open_internal(vfs.clone(), [9u8; 32], PAGE, RealmId::new([1; 16]))
            .await
            .unwrap();
        let realm = RealmId::new([1; 16]);
        let mut w = db
            .create_segment(realm, SegmentKind::Unspecified)
            .await
            .unwrap();
        w.append_page(SegmentPageKind::Data, b"x").await.unwrap();
        let m = w.seal().await.unwrap();
        let mut t = db.begin_write().await.unwrap();
        t.link_segment("ok", &m).await.unwrap();
        t.commit().await.unwrap();
    }
    // Reopen: reconciliation should succeed.
    let db = Db::open_existing(vfs, [9u8; 32], PAGE, RealmId::new([1; 16]))
        .await
        .unwrap();
    let r = db.open_segment(RealmId::new([1; 16]), "ok").await.unwrap();
    let page = r.read_page(1).await.unwrap();
    assert!(page.starts_with(b"x"));
}

#[tokio::test(flavor = "current_thread")]
async fn deferred_tombstone_pins_under_reader() {
    let db = Db::open_internal(MemVfs::new(), [9u8; 32], PAGE, RealmId::new([1; 16]))
        .await
        .unwrap();
    let realm = RealmId::new([1; 16]);
    let mut w = db
        .create_segment(realm, SegmentKind::Unspecified)
        .await
        .unwrap();
    w.append_page(SegmentPageKind::Data, b"pinned")
        .await
        .unwrap();
    let m = w.seal().await.unwrap();
    {
        let mut t = db.begin_write().await.unwrap();
        t.link_segment("name", &m).await.unwrap();
        t.commit().await.unwrap();
    }
    let snapshot = db.begin_read().await.unwrap();
    {
        let mut t = db.begin_write().await.unwrap();
        t.unlink_segment("name").await.unwrap();
        t.commit().await.unwrap();
    }
    // Reader-pinned: the segment is still accessible via the snapshot.
    let r = snapshot.open_segment("name").await.unwrap();
    let page = r.read_page(1).await.unwrap();
    assert!(page.starts_with(b"pinned"));
    drop(r);
    drop(snapshot);
    // After dropping the reader, gc_now should rename + delete.
    let stats = db.gc_now().await.unwrap();
    assert!(stats.reclaimed_segments >= 1);
}

#[tokio::test(flavor = "current_thread")]
async fn gc_now_deletes_tombstones() {
    let db = Db::open_internal(MemVfs::new(), [9u8; 32], PAGE, RealmId::new([1; 16]))
        .await
        .unwrap();
    let realm = RealmId::new([1; 16]);
    let mut w = db
        .create_segment(realm, SegmentKind::Unspecified)
        .await
        .unwrap();
    w.append_page(SegmentPageKind::Data, b"x").await.unwrap();
    let m = w.seal().await.unwrap();
    {
        let mut t = db.begin_write().await.unwrap();
        t.link_segment("dead", &m).await.unwrap();
        t.commit().await.unwrap();
    }
    {
        let mut t = db.begin_write().await.unwrap();
        t.unlink_segment("dead").await.unwrap();
        t.commit().await.unwrap();
    }
    let stats = db.gc_now().await.unwrap();
    assert!(stats.reclaimed_segments >= 1);
    // open_segment now returns NotFound.
    let err = db.open_segment(realm, "dead").await.err().unwrap();
    assert!(matches!(err, PagedbError::NotFound));
}
