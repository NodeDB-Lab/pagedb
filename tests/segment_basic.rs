use pagedb::vfs::memory::MemVfs;
use pagedb::{Db, PagedbError, RealmId, SegmentKind, SegmentPageKind};

const PAGE: usize = 4096;

async fn open() -> Db<MemVfs> {
    Db::open_internal(MemVfs::new(), [9u8; 32], PAGE, RealmId::new([1; 16]))
        .await
        .unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn create_append_seal_link_read_round_trip() {
    let db = open().await;
    let realm = RealmId::new([1; 16]);
    let mut w = db
        .create_segment(realm, SegmentKind::Unspecified)
        .await
        .unwrap();
    let pid1 = w
        .append_page(SegmentPageKind::Data, b"page-one")
        .await
        .unwrap();
    let pid2 = w
        .append_page(SegmentPageKind::Data, b"page-two")
        .await
        .unwrap();
    assert_eq!(pid1, 1);
    assert_eq!(pid2, 2);
    w.set_manifest(b"manifest-bytes").unwrap();
    let meta = w.seal().await.unwrap();
    // page_count = header(1) + 2 data pages + footer(1) = 4
    assert_eq!(meta.page_count, 4);
    {
        let mut t = db.begin_write().await.unwrap();
        t.link_segment("engine.idx", &meta).await.unwrap();
        t.commit().await.unwrap();
    }
    let reader = db.open_segment(realm, "engine.idx").await.unwrap();
    let page1 = reader.read_page(1).await.unwrap();
    assert!(page1.starts_with(b"page-one"));
    let page2 = reader.read_page(2).await.unwrap();
    assert!(page2.starts_with(b"page-two"));
    assert_eq!(reader.meta().page_count, 4);
}

#[tokio::test(flavor = "current_thread")]
async fn concurrent_writers_on_distinct_segments() {
    let db = open().await;
    let realm = RealmId::new([1; 16]);
    let mut w1 = db
        .create_segment(realm, SegmentKind::Unspecified)
        .await
        .unwrap();
    let mut w2 = db
        .create_segment(realm, SegmentKind::Unspecified)
        .await
        .unwrap();
    assert_ne!(w1.segment_id(), w2.segment_id());
    w1.append_page(SegmentPageKind::Data, b"w1").await.unwrap();
    w2.append_page(SegmentPageKind::Data, b"w2").await.unwrap();
    let m1 = w1.seal().await.unwrap();
    let m2 = w2.seal().await.unwrap();
    {
        let mut t = db.begin_write().await.unwrap();
        t.link_segment("seg1", &m1).await.unwrap();
        t.commit().await.unwrap();
    }
    {
        let mut t = db.begin_write().await.unwrap();
        t.link_segment("seg2", &m2).await.unwrap();
        t.commit().await.unwrap();
    }
    let r1 = db.open_segment(realm, "seg1").await.unwrap();
    let r2 = db.open_segment(realm, "seg2").await.unwrap();
    assert!(r1.read_page(1).await.unwrap().starts_with(b"w1"));
    assert!(r2.read_page(1).await.unwrap().starts_with(b"w2"));
}

#[tokio::test(flavor = "current_thread")]
async fn manifest_too_large_rejected() {
    let db = open().await;
    let mut w = db
        .create_segment(RealmId::new([1; 16]), SegmentKind::Unspecified)
        .await
        .unwrap();
    let too_big = vec![0u8; PAGE];
    let err = w.set_manifest(&too_big).err().unwrap();
    assert!(matches!(err, PagedbError::ManifestTooLarge));
}

#[tokio::test(flavor = "current_thread")]
async fn payload_too_large_rejected() {
    let db = open().await;
    let mut w = db
        .create_segment(RealmId::new([1; 16]), SegmentKind::Unspecified)
        .await
        .unwrap();
    let too_big = vec![0u8; PAGE];
    let err = w
        .append_page(SegmentPageKind::Data, &too_big)
        .await
        .err()
        .unwrap();
    assert!(matches!(err, PagedbError::PayloadTooLarge));
}

#[tokio::test(flavor = "current_thread")]
async fn list_segments_returns_prefix_match() {
    let db = open().await;
    let realm = RealmId::new([1; 16]);
    for name in ["alpha", "alpine", "beta"] {
        let mut w = db
            .create_segment(realm, SegmentKind::Unspecified)
            .await
            .unwrap();
        w.append_page(SegmentPageKind::Data, name.as_bytes())
            .await
            .unwrap();
        let meta = w.seal().await.unwrap();
        let mut t = db.begin_write().await.unwrap();
        t.link_segment(name, &meta).await.unwrap();
        t.commit().await.unwrap();
    }
    let listed = db.list_segments(realm, "alp").await.unwrap();
    assert_eq!(listed.len(), 2);
}

#[tokio::test(flavor = "current_thread")]
async fn open_segment_not_found() {
    let db = open().await;
    let err = db
        .open_segment(RealmId::new([1; 16]), "missing")
        .await
        .err()
        .unwrap();
    assert!(matches!(err, PagedbError::NotFound));
}

#[tokio::test(flavor = "current_thread")]
async fn gc_now_stub_is_zero() {
    let db = open().await;
    let stats = db.gc_now().await.unwrap();
    assert_eq!(stats.reclaimed_segments, 0);
    assert_eq!(stats.reclaimed_bytes, 0);
}

#[tokio::test(flavor = "current_thread")]
async fn link_segment_already_linked() {
    let db = open().await;
    let realm = RealmId::new([1; 16]);
    let mut w = db
        .create_segment(realm, SegmentKind::Unspecified)
        .await
        .unwrap();
    w.append_page(SegmentPageKind::Data, b"x").await.unwrap();
    let meta = w.seal().await.unwrap();
    {
        let mut t = db.begin_write().await.unwrap();
        t.link_segment("dup", &meta).await.unwrap();
        t.commit().await.unwrap();
    }
    // Second link with same name must fail; use a fresh segment.
    let mut w2 = db
        .create_segment(realm, SegmentKind::Unspecified)
        .await
        .unwrap();
    w2.append_page(SegmentPageKind::Data, b"y").await.unwrap();
    let meta2 = w2.seal().await.unwrap();
    let mut t = db.begin_write().await.unwrap();
    let err = t.link_segment("dup", &meta2).await.err().unwrap();
    assert!(matches!(err, PagedbError::AlreadyLinked));
}

#[tokio::test(flavor = "current_thread")]
async fn unlink_segment_removes_from_catalog() {
    let db = open().await;
    let realm = RealmId::new([1; 16]);
    let mut w = db
        .create_segment(realm, SegmentKind::Unspecified)
        .await
        .unwrap();
    w.append_page(SegmentPageKind::Data, b"x").await.unwrap();
    let meta = w.seal().await.unwrap();
    {
        let mut t = db.begin_write().await.unwrap();
        t.link_segment("toremove", &meta).await.unwrap();
        t.commit().await.unwrap();
    }
    {
        let mut t = db.begin_write().await.unwrap();
        t.unlink_segment("toremove").await.unwrap();
        t.commit().await.unwrap();
    }
    let err = db.open_segment(realm, "toremove").await.err().unwrap();
    assert!(matches!(err, PagedbError::NotFound));
}

#[tokio::test(flavor = "current_thread")]
async fn unlink_segment_not_linked() {
    let db = open().await;
    let mut t = db.begin_write().await.unwrap();
    let err = t.unlink_segment("never-linked").await.err().unwrap();
    assert!(matches!(err, PagedbError::NotLinked));
}

#[tokio::test(flavor = "current_thread")]
async fn replace_segment_swap() {
    let db = open().await;
    let realm = RealmId::new([1; 16]);
    let mut w1 = db
        .create_segment(realm, SegmentKind::Unspecified)
        .await
        .unwrap();
    w1.append_page(SegmentPageKind::Data, b"first")
        .await
        .unwrap();
    let m1 = w1.seal().await.unwrap();
    {
        let mut t = db.begin_write().await.unwrap();
        t.link_segment("name", &m1).await.unwrap();
        t.commit().await.unwrap();
    }
    let mut w2 = db
        .create_segment(realm, SegmentKind::Unspecified)
        .await
        .unwrap();
    w2.append_page(SegmentPageKind::Data, b"second")
        .await
        .unwrap();
    let m2 = w2.seal().await.unwrap();
    {
        let mut t = db.begin_write().await.unwrap();
        t.replace_segment("name", &m2).await.unwrap();
        t.commit().await.unwrap();
    }
    let reader = db.open_segment(realm, "name").await.unwrap();
    let page = reader.read_page(1).await.unwrap();
    assert!(page.starts_with(b"second"));
}

#[tokio::test(flavor = "current_thread")]
async fn read_txn_pins_catalog_snapshot() {
    let db = open().await;
    let realm = RealmId::new([1; 16]);
    let mut w = db
        .create_segment(realm, SegmentKind::Unspecified)
        .await
        .unwrap();
    w.append_page(SegmentPageKind::Data, b"v1").await.unwrap();
    let m1 = w.seal().await.unwrap();
    {
        let mut t = db.begin_write().await.unwrap();
        t.link_segment("pinned", &m1).await.unwrap();
        t.commit().await.unwrap();
    }
    // Pin a read snapshot before unlinking.
    let snapshot = db.begin_read().await.unwrap();
    {
        let mut t = db.begin_write().await.unwrap();
        t.unlink_segment("pinned").await.unwrap();
        t.commit().await.unwrap();
    }
    // The pinned snapshot still sees the segment.
    let reader = snapshot.open_segment("pinned").await.unwrap();
    let page = reader.read_page(1).await.unwrap();
    assert!(page.starts_with(b"v1"));
}
