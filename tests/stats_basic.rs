//! Basic tests for `Db::stats()` and related observability surface.

use pagedb::vfs::memory::MemVfs;
use pagedb::{Db, DbMode, OpenOptions, RealmId, SegmentKind, SegmentPageKind};

fn realm() -> RealmId {
    RealmId::new([0x42u8; 16])
}

fn kek() -> [u8; 32] {
    [0xABu8; 32]
}

async fn fresh_db() -> Db<MemVfs> {
    let vfs = MemVfs::new();
    Db::open(vfs, kek(), 4096, realm(), OpenOptions::default())
        .await
        .unwrap()
}

/// Write `n` transactions each inserting one key.
async fn write_n(db: &Db<MemVfs>, n: u64) {
    for i in 0..n {
        let mut txn = db.begin_write().await.unwrap();
        txn.put(&[i as u8], &[i as u8]).await.unwrap();
        txn.commit().await.unwrap();
    }
}

#[tokio::test]
async fn stats_reports_commits() {
    let db = fresh_db().await;
    write_n(&db, 3).await;
    let s = db.stats().await.unwrap();
    assert_eq!(
        s.latest_commit_id, 3,
        "expected 3 commits, got {}",
        s.latest_commit_id
    );
}

#[tokio::test]
async fn stats_reports_segments() {
    let db = fresh_db().await;

    // Create and seal two segments.
    {
        let mut w = db
            .create_segment(realm(), SegmentKind::Unspecified)
            .await
            .unwrap();
        w.append_page(SegmentPageKind::Data, &[1u8; 32])
            .await
            .unwrap();
        let meta = w.seal().await.unwrap();
        let mut txn = db.begin_write().await.unwrap();
        txn.link_segment("seg1", &meta).await.unwrap();
        txn.commit().await.unwrap();
    }

    {
        let mut w = db
            .create_segment(realm(), SegmentKind::Unspecified)
            .await
            .unwrap();
        w.append_page(SegmentPageKind::Data, &[2u8; 32])
            .await
            .unwrap();
        let meta = w.seal().await.unwrap();
        let mut txn = db.begin_write().await.unwrap();
        txn.link_segment("seg2", &meta).await.unwrap();
        txn.commit().await.unwrap();
    }

    let s = db.stats().await.unwrap();
    assert_eq!(
        s.segments_live, 2,
        "expected 2 live segments, got {}",
        s.segments_live
    );
    assert!(
        s.segments_total_bytes > 0,
        "segments_total_bytes should be > 0"
    );
}

#[tokio::test]
async fn stats_reports_buffer_pool() {
    let db = fresh_db().await;

    // Write a key so there is something to read.
    {
        let mut txn = db.begin_write().await.unwrap();
        txn.put(b"hello", b"world").await.unwrap();
        txn.commit().await.unwrap();
    }

    // Read the same key twice within a read txn (second access should hit cache).
    {
        let rtxn = db.begin_read().await.unwrap();
        let _ = rtxn.get(b"hello").await.unwrap();
        let _ = rtxn.get(b"hello").await.unwrap();
    }

    let s = db.stats().await.unwrap();
    // At least one cache access must have been recorded.
    assert!(
        s.buffer_pool_hits + s.buffer_pool_misses > 0,
        "expected at least one cache access, hits={} misses={}",
        s.buffer_pool_hits,
        s.buffer_pool_misses,
    );
    // The second read of the same key within the same txn should be a hit.
    assert!(
        s.buffer_pool_hits > 0,
        "expected at least one cache hit after repeated read"
    );
}

#[tokio::test]
async fn stats_reports_mode() {
    let vfs = MemVfs::new();
    // Bootstrap first so ReadOnly open can find main.db.
    {
        let db = Db::open(vfs.clone(), kek(), 4096, realm(), OpenOptions::default())
            .await
            .unwrap();
        drop(db);
    }
    let db = Db::<MemVfs>::open_read_only(vfs, kek(), 4096, realm(), OpenOptions::default())
        .await
        .unwrap();
    let s = db.stats().await.unwrap();
    assert_eq!(
        s.mode,
        DbMode::ReadOnly,
        "expected ReadOnly mode, got {:?}",
        s.mode
    );
}

#[tokio::test]
async fn stats_reports_reader_census() {
    let db = fresh_db().await;
    write_n(&db, 1).await;

    let idle = db.stats().await.unwrap();
    assert_eq!(idle.oldest_reader_commit_id, None);
    assert_eq!(idle.oldest_reader_age_ms, None);
    assert_eq!(idle.tracked_readers_non_abortable, 0);

    let reader = db.begin_read().await.unwrap();
    let pinned = reader.commit_id().value();
    write_n(&db, 3).await;
    // Only the older reader can be 10 ms old when the first census runs, so
    // the age assertion below fails if the census reports the newest reader.
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    let internal = db.begin_read_non_abortable().await.unwrap();
    assert!(internal.commit_id().value() > pinned);
    write_n(&db, 3).await;

    let first = db.stats().await.unwrap();
    assert_eq!(first.oldest_reader_commit_id, Some(pinned));
    assert_eq!(first.tracked_readers_non_abortable, 1);
    let first_age = first.oldest_reader_age_ms.expect("reader is pinned");
    assert!(
        first_age >= 10,
        "age is the older reader's, at least the 10 ms sleep: {first_age}"
    );

    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    write_n(&db, 1).await;

    let second = db.stats().await.unwrap();
    assert_eq!(second.oldest_reader_commit_id, Some(pinned));
    let second_age = second.oldest_reader_age_ms.expect("reader is pinned");
    assert!(
        second_age >= first_age + 10,
        "age grew less than the 10 ms sleep: {first_age} -> {second_age}"
    );

    drop(reader);
    drop(internal);
    let drained = db.stats().await.unwrap();
    assert_eq!(drained.oldest_reader_commit_id, None);
    assert_eq!(drained.oldest_reader_age_ms, None);
    assert_eq!(drained.tracked_readers_non_abortable, 0);
}

#[tokio::test]
async fn stats_reader_census_fields_can_describe_different_readers() {
    let db = fresh_db().await;
    write_n(&db, 1).await;
    let old_commit = db.begin_read().await.unwrap().commit_id();
    write_n(&db, 3).await;

    let longest_lived = db.begin_read().await.unwrap();
    assert!(longest_lived.commit_id().value() > old_commit.value());
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    // Opened later, but pinned to an older commit.
    let _historical = db.begin_read_at(old_commit).await.unwrap();

    let s = db.stats().await.unwrap();
    assert_eq!(s.tracked_readers, 2);
    assert_eq!(s.oldest_reader_commit_id, Some(old_commit.value()));
    let age = s.oldest_reader_age_ms.expect("readers are registered");
    assert!(
        age >= 10,
        "age is the longest-lived reader's, not the oldest-commit reader's: {age}"
    );
}
