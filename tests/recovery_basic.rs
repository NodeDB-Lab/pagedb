use pagedb::vfs::memory::MemVfs;
use pagedb::vfs::{OpenMode, Vfs};
use pagedb::{Db, OpenOptions, PagedbError, RealmId, SegmentKind, SegmentPageKind};

const PAGE: usize = 4096;

#[tokio::test(flavor = "current_thread")]
async fn reopen_reconciles_clean_catalog() {
    let vfs = MemVfs::new();
    {
        let db = Db::open(
            vfs.clone(),
            [9u8; 32],
            PAGE,
            RealmId::new([1; 16]),
            OpenOptions::default(),
        )
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
    let db = Db::open(
        vfs,
        [9u8; 32],
        PAGE,
        RealmId::new([1; 16]),
        OpenOptions::default(),
    )
    .await
    .unwrap();
    let r = db.open_segment(RealmId::new([1; 16]), "ok").await.unwrap();
    let page = r.read_page(1).await.unwrap();
    assert!(page.starts_with(b"x"));
}

#[tokio::test(flavor = "current_thread")]
async fn deferred_tombstone_pins_under_reader() {
    let db = Db::open(
        MemVfs::new(),
        [9u8; 32],
        PAGE,
        RealmId::new([1; 16]),
        OpenOptions::default(),
    )
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

/// Retiring a segment reclaims its file as part of the commit that retires it,
/// so on-disk size is bounded without anyone scheduling GC. This is the property
/// that keeps an embedder which never calls `gc_now` from filling its disk.
#[tokio::test(flavor = "current_thread")]
async fn unlink_reclaims_the_segment_file_at_commit() {
    let vfs = MemVfs::new();
    let db = Db::open(
        vfs.clone(),
        [9u8; 32],
        PAGE,
        RealmId::new([1; 16]),
        OpenOptions::default(),
    )
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

    let live = format!(
        "seg/{}",
        m.segment_id.iter().fold(String::new(), |mut s, b| {
            use std::fmt::Write as _;
            let _ = write!(s, "{b:02x}");
            s
        })
    );
    assert!(
        vfs.open(&live, OpenMode::Read).await.is_ok(),
        "the linked segment must be on disk before the unlink"
    );

    {
        let mut t = db.begin_write().await.unwrap();
        t.unlink_segment("dead").await.unwrap();
        t.commit().await.unwrap();
    }

    assert!(
        vfs.open(&live, OpenMode::Read).await.is_err(),
        "the unlink commit must reclaim the segment file, not leave it for a sweep"
    );
    assert_eq!(
        db.gc_now().await.unwrap().reclaimed_segments,
        0,
        "nothing should be left for GC to reclaim"
    );

    let err = db.open_segment(realm, "dead").await.err().unwrap();
    assert!(matches!(err, PagedbError::NotFound));
}
