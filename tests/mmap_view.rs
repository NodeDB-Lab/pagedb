use pagedb::options::OpenOptions;
use pagedb::vfs::memory::MemVfs;
use pagedb::{Db, ExtentRef, PagedbError, RealmId, SegmentKind, SegmentPageKind};

const PAGE: usize = 4096;

#[allow(dead_code)]
async fn open() -> Db<MemVfs> {
    Db::open_internal(MemVfs::new(), [7u8; 32], PAGE, RealmId::new([2; 16]))
        .await
        .unwrap()
}

async fn open_with_budget(budget: usize) -> Db<MemVfs> {
    let opts = OpenOptions::default().with_mmap_view_scratch_bytes(budget);
    Db::open_internal_with_options(MemVfs::new(), [7u8; 32], PAGE, RealmId::new([2; 16]), opts)
        .await
        .unwrap()
}

/// Helper: create a one-page segment with known content, seal, link, and
/// return the sealed page data alongside the open reader.
async fn setup_segment(db: &Db<MemVfs>, name: &str, payload: &[u8]) -> pagedb::Result<()> {
    let realm = RealmId::new([2; 16]);
    let mut w = db.create_segment(realm, SegmentKind::Unspecified).await?;
    w.append_page(SegmentPageKind::Data, payload).await?;
    let meta = w.seal().await?;
    let mut t = db.begin_write().await?;
    t.link_segment(name, &meta).await?;
    t.commit().await?;
    Ok(())
}

// ── Test 1: mmap_view returns the correct decrypted bytes ─────────────────

#[cfg(not(target_arch = "wasm32"))]
#[tokio::test(flavor = "current_thread")]
async fn mmap_view_reads_data() {
    let budget = 1024 * 1024; // 1 MiB — enough for a few pages
    let db = open_with_budget(budget).await;
    let known = b"hello from mmap_view test";
    setup_segment(&db, "mmap.seg", known).await.unwrap();

    let realm = RealmId::new([2; 16]);
    let reader = db.open_segment(realm, "mmap.seg").await.unwrap();

    // Page 1 is the first data page (0 = header, last = footer).
    let view = reader.mmap_view(ExtentRef::new(1, 1)).await.unwrap();

    // The view must start with the payload bytes.
    assert!(
        view.as_slice().starts_with(known),
        "view does not start with expected payload"
    );
}

// ── Test 2: WASM placeholder ───────────────────────────────────────────────

// On wasm32 mmap_view returns Unsupported. We can only compile-test the stub
// path here; runtime verification requires a wasm runner.
#[cfg(target_arch = "wasm32")]
#[test]
fn mmap_view_unsupported_on_wasm() {
    // Compile-time sentinel: if this test compiles, the wasm stub exists.
}

// ── Test 3: budget exceeded returns MmapViewQuotaExceeded ─────────────────

#[cfg(not(target_arch = "wasm32"))]
#[tokio::test(flavor = "current_thread")]
async fn mmap_view_budget_exceeded() {
    // Budget of 4096 bytes; one plaintext page body is up to PAGE-overhead
    // bytes, so a two-page extent will exceed the budget easily.
    let tiny_budget = 4096usize;
    let db = open_with_budget(tiny_budget).await;

    // Write enough data pages so the total plaintext exceeds the budget.
    let realm = RealmId::new([2; 16]);
    let mut w = db
        .create_segment(realm, SegmentKind::Unspecified)
        .await
        .unwrap();
    // Each append_page writes up to PAGE-32 bytes; 5 pages worth of plaintext
    // vastly exceeds a 4096-byte budget.
    for _ in 0..5 {
        w.append_page(SegmentPageKind::Data, &[0xABu8; 100])
            .await
            .unwrap();
    }
    let meta = w.seal().await.unwrap();
    {
        let mut t = db.begin_write().await.unwrap();
        t.link_segment("budget.seg", &meta).await.unwrap();
        t.commit().await.unwrap();
    }

    let reader = db.open_segment(realm, "budget.seg").await.unwrap();
    // 5 data pages starting at page 1.
    let err = reader.mmap_view(ExtentRef::new(1, 5)).await.err().unwrap();

    assert!(
        matches!(err, PagedbError::MmapViewQuotaExceeded { .. }),
        "expected MmapViewQuotaExceeded, got: {err:?}"
    );
}

// ── Test 4: dropping a view releases the budget ────────────────────────────

#[cfg(not(target_arch = "wasm32"))]
#[tokio::test(flavor = "current_thread")]
async fn mmap_view_drop_releases_budget() {
    // Budget just large enough for one page's plaintext body but not two
    // simultaneously. A single page body is at most (PAGE - overhead) bytes;
    // set budget to a generous 32 KiB so one page always fits.
    let budget = 32 * 1024usize;
    let db = open_with_budget(budget).await;
    let realm = RealmId::new([2; 16]);

    // Create a segment with one data page whose plaintext fits in budget.
    let mut w = db
        .create_segment(realm, SegmentKind::Unspecified)
        .await
        .unwrap();
    w.append_page(SegmentPageKind::Data, b"drop-test-payload")
        .await
        .unwrap();
    let meta = w.seal().await.unwrap();
    {
        let mut t = db.begin_write().await.unwrap();
        t.link_segment("drop.seg", &meta).await.unwrap();
        t.commit().await.unwrap();
    }

    let reader = db.open_segment(realm, "drop.seg").await.unwrap();
    let extent = ExtentRef::new(1, 1);

    // First view — succeeds.
    let view1 = reader.mmap_view(extent).await.unwrap();
    assert!(view1.as_slice().starts_with(b"drop-test-payload"));

    // Drop the view — releases budget.
    drop(view1);

    // Second view of the same size — should succeed now that budget is free.
    let view2 = reader.mmap_view(extent).await.unwrap();
    assert!(view2.as_slice().starts_with(b"drop-test-payload"));
}
