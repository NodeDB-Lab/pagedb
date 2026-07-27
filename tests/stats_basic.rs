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
async fn evict_main_pages_forces_next_read_to_miss_cache() {
    let db = fresh_db().await;
    {
        let mut txn = db.begin_write().await.unwrap();
        txn.put(b"hello", b"world").await.unwrap();
        txn.commit().await.unwrap();
    }

    {
        let reader = db.begin_read().await.unwrap();
        assert_eq!(
            reader.get(b"hello").await.unwrap().as_deref(),
            Some(b"world".as_slice())
        );
    }
    let before = db.stats().await.unwrap();

    db.evict_main_pages(realm());

    let reader = db.begin_read().await.unwrap();
    assert_eq!(
        reader.get(b"hello").await.unwrap().as_deref(),
        Some(b"world".as_slice())
    );
    let after = db.stats().await.unwrap();
    assert!(
        after.buffer_pool_misses > before.buffer_pool_misses,
        "eviction must force a VFS-backed cache miss: before={before:?}, after={after:?}"
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
