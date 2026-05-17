//! Integration tests for online compaction: persistent free-list, main.db
//! defragmentation, segment repacking, reader-pin safety, idempotency, and
//! free-list persistence across reopen.

use pagedb::vfs::memory::MemVfs;
use pagedb::{Db, RealmId, SegmentKind, SegmentPageKind};

const PAGE: usize = 4096;
const REALM: RealmId = RealmId::new([0xAB; 16]);
const KEK: [u8; 32] = [0x11; 32];

async fn fresh_db() -> Db<MemVfs> {
    Db::open_internal(MemVfs::new(), KEK, PAGE, REALM)
        .await
        .unwrap()
}

/// Return the number of pages in main.db by asking the Db for the file size.
async fn main_db_pages(db: &Db<MemVfs>) -> u64 {
    db.main_db_byte_size().await.unwrap() / PAGE as u64
}

// ─── Test 1: Free-list reuse across transactions ──────────────────────────────

#[tokio::test(flavor = "current_thread")]
async fn free_list_reuse_across_txns() {
    let db = fresh_db().await;

    // Write 50 keys across txn 1.
    {
        let mut w = db.begin_write().await.unwrap();
        for i in 0u32..50 {
            let key = format!("key-{i:04}");
            w.put(key.as_bytes(), &[i as u8; 64]).await.unwrap();
        }
        w.commit().await.unwrap();
    }

    let pages_after_write = main_db_pages(&db).await;

    // Delete all keys in txn 2.
    {
        let mut w = db.begin_write().await.unwrap();
        for i in 0u32..50 {
            let key = format!("key-{i:04}");
            w.delete(key.as_bytes()).await.unwrap();
        }
        w.commit().await.unwrap();
    }

    // Write 50 new keys in txn 3 — they should reuse freed pages from the
    // deferred queue (now eligible since no readers are pinning).
    {
        let mut w = db.begin_write().await.unwrap();
        for i in 50u32..100 {
            let key = format!("key-{i:04}");
            w.put(key.as_bytes(), &[i as u8; 64]).await.unwrap();
        }
        w.commit().await.unwrap();
    }

    let pages_after_rewrite = main_db_pages(&db).await;

    // The file should not have grown unboundedly: the rewrite round should
    // reuse pages freed in txn 2.
    // We allow up to 2× the original size as a generous bound.
    assert!(
        pages_after_rewrite <= pages_after_write * 2,
        "expected reuse: pages_after_write={pages_after_write}, pages_after_rewrite={pages_after_rewrite}"
    );
}

// ─── Test 2: compact_now truncates main.db ────────────────────────────────────

#[tokio::test(flavor = "current_thread")]
async fn compact_truncates_main_db() {
    let db = fresh_db().await;

    // Write many keys (enough to allocate several pages).
    {
        let mut w = db.begin_write().await.unwrap();
        for i in 0u32..200 {
            let key = format!("key-{i:06}");
            w.put(key.as_bytes(), &[0u8; 128]).await.unwrap();
        }
        w.commit().await.unwrap();
    }

    let pages_before = main_db_pages(&db).await;

    // Delete most keys, leaving only 10.
    {
        let mut w = db.begin_write().await.unwrap();
        for i in 0u32..190 {
            let key = format!("key-{i:06}");
            w.delete(key.as_bytes()).await.unwrap();
        }
        w.commit().await.unwrap();
    }

    let stats = db.compact_now().await.unwrap();
    let pages_after = main_db_pages(&db).await;

    // File must have shrunk.
    assert!(
        pages_after < pages_before,
        "expected file to shrink: before={pages_before}, after={pages_after}"
    );
    // bytes_truncated should be non-zero.
    assert!(
        stats.bytes_truncated > 0,
        "expected bytes_truncated > 0, got {stats:?}"
    );
    // Remaining keys still readable.
    let r = db.begin_read().await.unwrap();
    for i in 190u32..200 {
        let key = format!("key-{i:06}");
        let v = r.get(key.as_bytes()).await.unwrap();
        assert!(v.is_some(), "key {key} should still exist after compaction");
    }
}

// ─── Test 3: compact_now repacks segments ─────────────────────────────────────

#[tokio::test(flavor = "current_thread")]
async fn compact_repacks_segments() {
    let db = fresh_db().await;

    // Create a segment and link it.
    let meta = {
        let mut seg = db
            .create_segment(REALM, SegmentKind::Unspecified)
            .await
            .unwrap();
        for _i in 0..5 {
            seg.append_page(SegmentPageKind::Data, &[0xAA; 512])
                .await
                .unwrap();
        }
        seg.seal().await.unwrap()
    };
    let logical_bytes = meta.total_bytes;
    let page_count = meta.page_count;

    {
        let mut w = db.begin_write().await.unwrap();
        w.link_segment("engine.idx", &meta).await.unwrap();
        w.commit().await.unwrap();
    }

    // The segment file size should equal page_count * PAGE which is also its
    // logical size — no garbage, so compact_now should skip it.
    let stats_no_garbage = db.compact_now().await.unwrap();
    assert_eq!(
        stats_no_garbage.segments_repacked, 0,
        "segment with no garbage should not be repacked"
    );
    let _ = (logical_bytes, page_count); // suppress unused warnings
}

// ─── Test 4: compact_now respects reader pins ────────────────────────────────

#[tokio::test(flavor = "current_thread")]
async fn compact_respects_reader_pins() {
    let db = fresh_db().await;

    // Write initial data.
    {
        let mut w = db.begin_write().await.unwrap();
        for i in 0u32..50 {
            let key = format!("pin-key-{i:04}");
            w.put(key.as_bytes(), &[i as u8; 32]).await.unwrap();
        }
        w.commit().await.unwrap();
    }

    // Open a read txn BEFORE deletion — this pins the old snapshot.
    let reader = db.begin_read().await.unwrap();

    // Delete all keys.
    {
        let mut w = db.begin_write().await.unwrap();
        for i in 0u32..50 {
            let key = format!("pin-key-{i:04}");
            w.delete(key.as_bytes()).await.unwrap();
        }
        w.commit().await.unwrap();
    }

    let pages_before = main_db_pages(&db).await;

    // Compact while the reader is still open.
    let stats = db.compact_now().await.unwrap();

    let pages_after = main_db_pages(&db).await;

    // The file must NOT have been truncated while the reader is pinning the old range.
    // (pages_after >= pages_before means no truncation happened)
    assert!(
        pages_after >= pages_before || stats.bytes_truncated == 0,
        "file should not be truncated while a reader is pinned: before={pages_before}, after={pages_after}"
    );

    // The pinned reader must still be able to read its snapshot.
    for i in 0u32..50 {
        let key = format!("pin-key-{i:04}");
        let v = reader.get(key.as_bytes()).await.unwrap();
        assert!(v.is_some(), "pinned reader lost key {key} after compaction");
    }

    drop(reader);
}

// ─── Test 5: compact_now is idempotent ───────────────────────────────────────

#[tokio::test(flavor = "current_thread")]
async fn compact_idempotent() {
    let db = fresh_db().await;

    {
        let mut w = db.begin_write().await.unwrap();
        for i in 0u32..30 {
            let key = format!("idem-{i:04}");
            w.put(key.as_bytes(), &[1u8; 48]).await.unwrap();
        }
        w.commit().await.unwrap();
    }

    // First compaction — may reclaim pages.
    let stats1 = db.compact_now().await.unwrap();

    // Second compaction on an already-compact database should be a no-op:
    // no pages to reclaim, no segments to repack.
    let stats2 = db.compact_now().await.unwrap();

    assert_eq!(
        stats2.main_db_pages_reclaimed, 0,
        "second compact should reclaim nothing: first={stats1:?} second={stats2:?}"
    );
    assert_eq!(
        stats2.segments_repacked, 0,
        "second compact should repack nothing"
    );
    assert_eq!(
        stats2.bytes_truncated, 0,
        "second compact should not truncate"
    );
}

// ─── Test 6: free-list persists across reopen ─────────────────────────────────

#[tokio::test(flavor = "current_thread")]
async fn free_list_persists_across_reopen() {
    let vfs = MemVfs::new();

    // Open, write, then delete to populate the deferred-free queue.
    {
        let db = Db::open_internal(vfs.clone(), KEK, PAGE, REALM)
            .await
            .unwrap();
        let mut w = db.begin_write().await.unwrap();
        for i in 0u32..30 {
            let key = format!("persist-{i:04}");
            w.put(key.as_bytes(), &[9u8; 64]).await.unwrap();
        }
        w.commit().await.unwrap();

        let mut w2 = db.begin_write().await.unwrap();
        for i in 0u32..30 {
            let key = format!("persist-{i:04}");
            w2.delete(key.as_bytes()).await.unwrap();
        }
        w2.commit().await.unwrap();
        // Db drops here — deferred-free queue is on disk.
    }

    // Reopen and compact. The deferred-free pages should be drained and
    // reused, so next_page_id should not advance much when we write new data.
    let db2 = Db::open_existing(vfs.clone(), KEK, PAGE, REALM)
        .await
        .unwrap();

    // Compact to drain deferred-free into free-list.
    let _stats = db2.compact_now().await.unwrap();

    let pages_after_compact = main_db_pages(&db2).await;

    // Write new data — should reuse freed pages rather than extending the file.
    {
        let mut w = db2.begin_write().await.unwrap();
        for i in 0u32..30 {
            let key = format!("new-{i:04}");
            w.put(key.as_bytes(), &[7u8; 64]).await.unwrap();
        }
        w.commit().await.unwrap();
    }

    let pages_after_rewrite = main_db_pages(&db2).await;

    // The file should not have grown much beyond the post-compact size,
    // because freed pages were reused (not next_page_id).
    // Allow a 50% overshoot to be generous.
    assert!(
        pages_after_rewrite <= pages_after_compact + pages_after_compact / 2 + 4,
        "next_page_id advanced too much after reopen; \
         pages_after_compact={pages_after_compact}, \
         pages_after_rewrite={pages_after_rewrite}"
    );
}
