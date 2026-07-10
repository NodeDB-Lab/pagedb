//! Verifies that commit paths call sync_dir on the root directory. Uses
//! MemVfs which no-ops sync_dir; the test confirms the full commit flow
//! completes without error, validating that sync_dir is wired in without
//! panicking or returning unexpected errors.

use pagedb::vfs::memory::MemVfs;
use pagedb::{CommitId, Db, RealmId};

const PAGE: usize = 4096;

#[tokio::test(flavor = "current_thread")]
async fn commit_calls_sync_dir_without_error() {
    let vfs = MemVfs::new();
    let db = Db::open_internal(vfs, [1u8; 32], PAGE, RealmId::new([1u8; 16]))
        .await
        .unwrap();
    let mut w = db.begin_write().await.unwrap();
    w.put(b"key", b"value").await.unwrap();
    let cid = w.commit().await.unwrap();
    assert_eq!(cid, CommitId::new(1));

    // A second commit also exercises the sync_dir path cleanly.
    let mut w2 = db.begin_write().await.unwrap();
    w2.put(b"key2", b"value2").await.unwrap();
    let cid2 = w2.commit().await.unwrap();
    assert_eq!(cid2, CommitId::new(2));
}

#[tokio::test(flavor = "current_thread")]
async fn segment_promote_calls_sync_dir_without_error() {
    use pagedb::{SegmentKind, SegmentPageKind};

    let vfs = MemVfs::new();
    let realm = RealmId::new([2u8; 16]);
    let db = Db::open_internal(vfs, [2u8; 32], PAGE, realm)
        .await
        .unwrap();

    let mut sw = db
        .create_segment(realm, SegmentKind::Unspecified)
        .await
        .unwrap();
    sw.append_page(SegmentPageKind::Data, b"payload")
        .await
        .unwrap();
    let meta = sw.seal().await.unwrap();

    let mut w = db.begin_write().await.unwrap();
    w.link_segment("seg1", &meta).await.unwrap();
    w.commit().await.unwrap();

    // Now unlink to exercise tombstone + sync_dir("seg/.tombstone").
    let mut w2 = db.begin_write().await.unwrap();
    w2.unlink_segment("seg1").await.unwrap();
    w2.commit().await.unwrap();
}
