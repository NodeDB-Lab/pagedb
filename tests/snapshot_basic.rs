//! Integration tests for snapshot_to / restore_from / promote_to_follower /
//! apply_incremental / snapshot_incremental_to.

use pagedb::vfs::tokio_backend::TokioVfs;
use pagedb::{
    ApplyStats, Db, DbMode, OpenOptions, PagedbError, RealmId, SegmentKind, SegmentPageKind,
    SnapshotStats,
};

const PAGE: usize = 4096;
const KEK: [u8; 32] = [7u8; 32];
const REALM: RealmId = RealmId::new([1u8; 16]);

fn tempdir() -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    p.push(format!("pagedb-snap-{}-{}", std::process::id(), nanos));
    std::fs::create_dir_all(&p).unwrap();
    p
}

async fn make_db(root: &std::path::Path) -> Db<TokioVfs> {
    let vfs = TokioVfs::new(root);
    Db::open(vfs, KEK, PAGE, REALM, OpenOptions::default())
        .await
        .unwrap()
}

// ---------------------------------------------------------------------------
// Test 1: full snapshot then restore reads data back.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "current_thread")]
async fn full_snapshot_then_restore_reads_data() {
    let src_dir = tempdir();
    let snap_dir = tempdir();
    let dst_dir = tempdir();

    let db = make_db(&src_dir).await;
    {
        let mut t = db.begin_write().await.unwrap();
        t.put(b"key1", b"value1").await.unwrap();
        t.put(b"key2", b"value2").await.unwrap();
        t.commit().await.unwrap();
    }

    let stats = db.snapshot_to(&snap_dir).await.unwrap();
    assert!(stats.bytes > 0);

    drop(db);

    let restored = Db::<TokioVfs>::restore_from(&snap_dir, &dst_dir, OpenOptions::default(), KEK)
        .await
        .unwrap();
    assert_eq!(restored.mode(), DbMode::ReadOnly);

    let rtxn = restored.begin_read().await.unwrap();
    let v1 = rtxn.get(b"key1").await.unwrap();
    let v2 = rtxn.get(b"key2").await.unwrap();
    assert_eq!(v1.as_deref(), Some(b"value1" as &[u8]));
    assert_eq!(v2.as_deref(), Some(b"value2" as &[u8]));

    std::fs::remove_dir_all(&src_dir).ok();
    std::fs::remove_dir_all(&snap_dir).ok();
    std::fs::remove_dir_all(&dst_dir).ok();
}

// ---------------------------------------------------------------------------
// Test 2: restore yields a ReadOnly Db; begin_write returns ReadOnly error.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "current_thread")]
async fn restore_yields_readonly_db() {
    let src_dir = tempdir();
    let snap_dir = tempdir();
    let dst_dir = tempdir();

    let db = make_db(&src_dir).await;
    db.snapshot_to(&snap_dir).await.unwrap();
    drop(db);

    let restored = Db::<TokioVfs>::restore_from(&snap_dir, &dst_dir, OpenOptions::default(), KEK)
        .await
        .unwrap();
    assert_eq!(restored.mode(), DbMode::ReadOnly);

    // begin_write must fail with ReadOnly.
    let err = restored.begin_write().await.err().unwrap();
    assert!(
        matches!(err, PagedbError::ReadOnly),
        "expected ReadOnly, got {err:?}"
    );

    std::fs::remove_dir_all(&src_dir).ok();
    std::fs::remove_dir_all(&snap_dir).ok();
    std::fs::remove_dir_all(&dst_dir).ok();
}

// ---------------------------------------------------------------------------
// Test 3: promote_to_follower allows apply_incremental (empty delta succeeds).
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "current_thread")]
async fn promote_to_follower_allows_apply() {
    let src_dir = tempdir();
    let snap_dir = tempdir();
    let dst_dir = tempdir();
    let delta_dir = tempdir();

    let db = make_db(&src_dir).await;
    let c1 = db.latest_commit();
    db.snapshot_to(&snap_dir).await.unwrap();

    // Create an empty incremental from c1 to c1 (nothing changed).
    db.snapshot_incremental_to(c1, &delta_dir).await.unwrap();
    drop(db);

    let restored = Db::<TokioVfs>::restore_from(&snap_dir, &dst_dir, OpenOptions::default(), KEK)
        .await
        .unwrap();

    let follower = restored.promote_to_follower().await.unwrap();
    assert_eq!(follower.mode(), DbMode::Follower);
    assert!(follower.can_apply_incremental());

    let stats = follower.apply_incremental(&delta_dir).await.unwrap();
    assert_eq!(stats.pages_applied, 0); // empty delta

    std::fs::remove_dir_all(&src_dir).ok();
    std::fs::remove_dir_all(&snap_dir).ok();
    std::fs::remove_dir_all(&dst_dir).ok();
    std::fs::remove_dir_all(&delta_dir).ok();
}

// ---------------------------------------------------------------------------
// Test 4: incremental carries only changed pages.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "current_thread")]
async fn incremental_carries_only_changed_pages() {
    let src_dir = tempdir();
    let snap1_dir = tempdir();
    let snap2_dir = tempdir();

    let db = make_db(&src_dir).await;
    // Write some initial data.
    {
        let mut t = db.begin_write().await.unwrap();
        for i in 0u32..50 {
            let k = format!("key{i:03}");
            t.put(k.as_bytes(), b"init").await.unwrap();
        }
        t.commit().await.unwrap();
    }
    let c1 = db.latest_commit();
    let full_stats: SnapshotStats = db.snapshot_to(&snap1_dir).await.unwrap();

    // Write more data to advance the commit.
    {
        let mut t = db.begin_write().await.unwrap();
        for i in 0u32..10 {
            let k = format!("new{i:03}");
            t.put(k.as_bytes(), b"added").await.unwrap();
        }
        t.commit().await.unwrap();
    }

    let inc_stats: SnapshotStats = db.snapshot_incremental_to(c1, &snap2_dir).await.unwrap();

    // Incremental should have fewer pages than the full snapshot.
    assert!(
        inc_stats.pages_written < full_stats.pages_written,
        "incremental pages {} should be < full pages {}",
        inc_stats.pages_written,
        full_stats.pages_written
    );

    std::fs::remove_dir_all(&src_dir).ok();
    std::fs::remove_dir_all(&snap1_dir).ok();
    std::fs::remove_dir_all(&snap2_dir).ok();
}

// ---------------------------------------------------------------------------
// Test 5: apply_incremental advances commit and data matches.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "current_thread")]
async fn apply_incremental_advances_commit() {
    let src_dir = tempdir();
    let snap_dir = tempdir();
    let delta_dir = tempdir();
    let dst_dir = tempdir();

    let db = make_db(&src_dir).await;
    // Write initial data.
    {
        let mut t = db.begin_write().await.unwrap();
        t.put(b"base", b"data").await.unwrap();
        t.commit().await.unwrap();
    }
    let c1 = db.latest_commit();
    db.snapshot_to(&snap_dir).await.unwrap();

    // Write more data after c1.
    {
        let mut t = db.begin_write().await.unwrap();
        t.put(b"new_key", b"new_val").await.unwrap();
        t.commit().await.unwrap();
    }
    let c2 = db.latest_commit();

    // Incremental from c1 to c2.
    db.snapshot_incremental_to(c1, &delta_dir).await.unwrap();
    drop(db);

    // Restore and promote.
    let restored = Db::<TokioVfs>::restore_from(&snap_dir, &dst_dir, OpenOptions::default(), KEK)
        .await
        .unwrap();
    let follower = restored.promote_to_follower().await.unwrap();

    // Apply incremental.
    let _stats: ApplyStats = follower.apply_incremental(&delta_dir).await.unwrap();

    // The follower's latest_commit should equal c2 after applying.
    let follower_commit = follower.latest_commit();
    assert_eq!(follower_commit, c2, "follower commit should match c2");

    std::fs::remove_dir_all(&src_dir).ok();
    std::fs::remove_dir_all(&snap_dir).ok();
    std::fs::remove_dir_all(&delta_dir).ok();
    std::fs::remove_dir_all(&dst_dir).ok();
}

// ---------------------------------------------------------------------------
// Test 6: standalone db calling apply_incremental returns IdentityForked.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "current_thread")]
async fn apply_incremental_rejects_on_standalone() {
    let src_dir = tempdir();
    let snap_dir = tempdir();

    let db = make_db(&src_dir).await;
    db.snapshot_to(&snap_dir).await.unwrap();

    let err = db.apply_incremental(&snap_dir).await.err().unwrap();
    assert!(
        matches!(err, PagedbError::IdentityForked),
        "expected IdentityForked, got {err:?}"
    );

    std::fs::remove_dir_all(&src_dir).ok();
    std::fs::remove_dir_all(&snap_dir).ok();
}

// ---------------------------------------------------------------------------
// Test 7: snapshot includes segments; restored db can read segment.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "current_thread")]
async fn snapshot_includes_segments() {
    let src_dir = tempdir();
    let snap_dir = tempdir();
    let dst_dir = tempdir();

    let db = make_db(&src_dir).await;
    {
        let mut w = db
            .create_segment(REALM, SegmentKind::Unspecified)
            .await
            .unwrap();
        w.append_page(SegmentPageKind::Data, b"seg-content")
            .await
            .unwrap();
        w.set_manifest(b"mf").unwrap();
        let meta = w.seal().await.unwrap();
        let mut t = db.begin_write().await.unwrap();
        t.link_segment("my.seg", &meta).await.unwrap();
        t.commit().await.unwrap();
    }

    let stats = db.snapshot_to(&snap_dir).await.unwrap();
    assert_eq!(stats.segments_written, 1);
    drop(db);

    let restored = Db::<TokioVfs>::restore_from(&snap_dir, &dst_dir, OpenOptions::default(), KEK)
        .await
        .unwrap();
    let rtxn = restored.begin_read().await.unwrap();
    let reader = rtxn.open_segment("my.seg").await.unwrap();
    let page = reader.read_page(1).await.unwrap();
    assert!(page.starts_with(b"seg-content"));

    std::fs::remove_dir_all(&src_dir).ok();
    std::fs::remove_dir_all(&snap_dir).ok();
    std::fs::remove_dir_all(&dst_dir).ok();
}

// ---------------------------------------------------------------------------
// Test 8: manifest corruption detected.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "current_thread")]
async fn manifest_corruption_detected() {
    let src_dir = tempdir();
    let snap_dir = tempdir();
    let dst_dir = tempdir();

    let db = make_db(&src_dir).await;
    db.snapshot_to(&snap_dir).await.unwrap();
    drop(db);

    // Corrupt the last byte of the manifest (the HK-MAC).
    let manifest_path = snap_dir.join("manifest");
    let mut bytes = std::fs::read(&manifest_path).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xFF;
    std::fs::write(&manifest_path, &bytes).unwrap();

    let err = Db::<TokioVfs>::restore_from(&snap_dir, &dst_dir, OpenOptions::default(), KEK)
        .await
        .err()
        .unwrap();
    assert!(
        matches!(err, PagedbError::Corruption(_)),
        "expected Corruption, got {err:?}"
    );

    std::fs::remove_dir_all(&src_dir).ok();
    std::fs::remove_dir_all(&snap_dir).ok();
    std::fs::remove_dir_all(&dst_dir).ok();
}
