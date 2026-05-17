//! Integration tests for v2 segment extent index: lazy loading via `OnceCell`,
//! binary-search lookup, and backward compatibility with v1-style segments.

use pagedb::vfs::memory::MemVfs;
use pagedb::{Db, RealmId, SegmentKind, SegmentPageKind};

const PAGE: usize = 4096;
const REALM: RealmId = RealmId::new([0xCC; 16]);
const KEK: [u8; 32] = [0x77; 32];

async fn fresh_db() -> Db<MemVfs> {
    Db::open_internal(MemVfs::new(), KEK, PAGE, REALM)
        .await
        .unwrap()
}

// ─── Test 1: Single extent — write and find by start_page_id ─────────────────

#[tokio::test(flavor = "current_thread")]
async fn single_extent_find_round_trip() {
    let db = fresh_db().await;

    let mut w = db
        .create_segment(REALM, SegmentKind::Unspecified)
        .await
        .unwrap();
    let ext = w
        .append_extent(&[b"data-page-0".as_ref(), b"data-page-1".as_ref()])
        .await
        .unwrap();
    let meta = w.seal().await.unwrap();

    let mut txn = db.begin_write().await.unwrap();
    txn.link_segment("idx.test", &meta).await.unwrap();
    txn.commit().await.unwrap();

    let reader = db.open_segment(REALM, "idx.test").await.unwrap();
    let pages = reader.find_extent(ext.start_page_id).await.unwrap();
    assert_eq!(pages.len(), 2);
    assert!(pages[0].starts_with(b"data-page-0"));
    assert!(pages[1].starts_with(b"data-page-1"));
}

// ─── Test 2: Many extents — binary search finds only the requested extent ──

#[tokio::test(flavor = "current_thread")]
async fn many_extents_binary_search() {
    let db = fresh_db().await;

    const NUM_EXTENTS: usize = 100;

    let mut w = db
        .create_segment(REALM, SegmentKind::Unspecified)
        .await
        .unwrap();

    let mut start_ids = Vec::with_capacity(NUM_EXTENTS);
    for i in 0..NUM_EXTENTS {
        let payload = format!("extent-{i:04}");
        let ext = w.append_extent(&[payload.as_bytes()]).await.unwrap();
        start_ids.push(ext.start_page_id);
    }
    let meta = w.seal().await.unwrap();

    let mut txn = db.begin_write().await.unwrap();
    txn.link_segment("many.idx", &meta).await.unwrap();
    txn.commit().await.unwrap();

    let reader = db.open_segment(REALM, "many.idx").await.unwrap();

    // Verify binary search finds every extent correctly.
    for (i, &sid) in start_ids.iter().enumerate() {
        let pages = reader.find_extent(sid).await.unwrap();
        assert_eq!(pages.len(), 1, "extent {i} should have 1 page");
        let expected = format!("extent-{i:04}");
        assert!(
            pages[0].starts_with(expected.as_bytes()),
            "extent {i} content mismatch"
        );
    }
}

// ─── Test 3: find_extent on a missing start_page_id returns NotFound ─────────

#[tokio::test(flavor = "current_thread")]
async fn find_extent_missing_returns_not_found() {
    let db = fresh_db().await;

    let mut w = db
        .create_segment(REALM, SegmentKind::Unspecified)
        .await
        .unwrap();
    w.append_extent(&[b"only-extent"]).await.unwrap();
    let meta = w.seal().await.unwrap();

    let mut txn = db.begin_write().await.unwrap();
    txn.link_segment("sparse.idx", &meta).await.unwrap();
    txn.commit().await.unwrap();

    let reader = db.open_segment(REALM, "sparse.idx").await.unwrap();
    // page_id 999 was never the start of an extent.
    let result = reader.find_extent(999).await;
    assert!(
        matches!(result, Err(pagedb::PagedbError::NotFound)),
        "expected NotFound, got {result:?}"
    );
}

// ─── Test 4: Segment with no append_extent has index_page_count = 0 ──────────

#[tokio::test(flavor = "current_thread")]
async fn no_extents_find_returns_not_found() {
    let db = fresh_db().await;

    let mut w = db
        .create_segment(REALM, SegmentKind::Unspecified)
        .await
        .unwrap();
    // Only append_page calls; no append_extent.
    w.append_page(SegmentPageKind::Data, b"raw-page")
        .await
        .unwrap();
    let meta = w.seal().await.unwrap();

    let mut txn = db.begin_write().await.unwrap();
    txn.link_segment("noext.idx", &meta).await.unwrap();
    txn.commit().await.unwrap();

    let reader = db.open_segment(REALM, "noext.idx").await.unwrap();
    assert_eq!(reader.index_page_count(), 0);
    let result = reader.find_extent(1).await;
    assert!(
        matches!(result, Err(pagedb::PagedbError::NotFound)),
        "expected NotFound for segment without extent index"
    );
}

// ─── Test 5: Large value extents — multiple pages per extent ─────────────────

#[tokio::test(flavor = "current_thread")]
async fn multi_page_extent_round_trip() {
    let db = fresh_db().await;

    let mut w = db
        .create_segment(REALM, SegmentKind::Unspecified)
        .await
        .unwrap();

    // Append an extent with 5 pages.
    let payloads: Vec<Vec<u8>> = (0..5u32)
        .map(|i| format!("page-{i:03}-data").into_bytes())
        .collect();
    let payload_refs: Vec<&[u8]> = payloads.iter().map(|v| v.as_slice()).collect();
    let ext = w.append_extent(&payload_refs).await.unwrap();
    assert_eq!(ext.count, 5);

    let meta = w.seal().await.unwrap();
    let mut txn = db.begin_write().await.unwrap();
    txn.link_segment("multi.idx", &meta).await.unwrap();
    txn.commit().await.unwrap();

    let reader = db.open_segment(REALM, "multi.idx").await.unwrap();
    let pages = reader.find_extent(ext.start_page_id).await.unwrap();
    assert_eq!(pages.len(), 5);
    for (i, page) in pages.iter().enumerate() {
        let expected = format!("page-{i:03}-data");
        assert!(page.starts_with(expected.as_bytes()), "page {i} mismatch");
    }
}

// ─── Test 6: Index spans multiple index pages (many extents) ─────────────────

#[tokio::test(flavor = "current_thread")]
async fn index_spans_multiple_pages() {
    let db = fresh_db().await;

    // With PAGE=4096 and ENVELOPE_OVERHEAD=40, body = 4056 bytes.
    // Each index entry = 32 bytes, so entries_per_page = 4056 / 32 = 126.
    // Writing 300 extents forces ceil(300/126) = 3 index pages.
    const NUM_EXTENTS: usize = 300;

    let mut w = db
        .create_segment(REALM, SegmentKind::Unspecified)
        .await
        .unwrap();

    let mut start_ids = Vec::with_capacity(NUM_EXTENTS);
    for i in 0..NUM_EXTENTS {
        let payload = format!("e{i:05}");
        let ext = w.append_extent(&[payload.as_bytes()]).await.unwrap();
        start_ids.push(ext.start_page_id);
    }
    let meta = w.seal().await.unwrap();

    let mut txn = db.begin_write().await.unwrap();
    txn.link_segment("big.idx", &meta).await.unwrap();
    txn.commit().await.unwrap();

    let reader = db.open_segment(REALM, "big.idx").await.unwrap();
    assert!(
        reader.index_page_count() >= 3,
        "expected at least 3 index pages, got {}",
        reader.index_page_count()
    );

    // Spot-check a few extents.
    for &i in &[0usize, 99, 200, 299] {
        let pages = reader.find_extent(start_ids[i]).await.unwrap();
        assert_eq!(pages.len(), 1);
        let expected = format!("e{i:05}");
        assert!(pages[0].starts_with(expected.as_bytes()));
    }
}
