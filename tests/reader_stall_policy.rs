//! Tests for reader stall policy enforcement.

use pagedb::vfs::memory::MemVfs;
use pagedb::{Db, OpenOptions, PagedbError, ReaderStallPolicy, RealmId};

const KEK: [u8; 32] = [7u8; 32];
const REALM: RealmId = RealmId::new([1u8; 16]);
/// Low threshold makes it easy to trigger in unit tests.
const LOW_THRESHOLD: u64 = 5;

fn opts_low_threshold() -> OpenOptions {
    let mut opts = OpenOptions::default().with_buffer_pool_pages(256);
    opts.reader_stall_threshold_pages = LOW_THRESHOLD;
    opts
}

/// Write `n` key-value pairs, then overwrite them all, to accumulate freed
/// pages in the deferred-free queue. Returns the error from the commit that
/// triggers the stall policy, or `None` if no error was produced.
async fn fill_until_stall(db: &Db<MemVfs>) -> Option<PagedbError> {
    for round in 0..30u32 {
        let prefix = format!("k{round:04}");
        // Write fresh keys.
        let mut w = db.begin_write().await.unwrap();
        for i in 0u64..8 {
            let key = format!("{prefix}_{i:04}");
            w.put(key.as_bytes(), &[0u8; 200]).await.unwrap();
        }
        if let Err(e) = w.commit().await {
            return Some(e);
        }
        // Overwrite to free the old pages.
        let mut w2 = db.begin_write().await.unwrap();
        for i in 0u64..8 {
            let key = format!("{prefix}_{i:04}");
            w2.put(key.as_bytes(), b"x").await.unwrap();
        }
        if let Err(e) = w2.commit().await {
            return Some(e);
        }
    }
    None
}

#[tokio::test(flavor = "current_thread")]
async fn unbounded_never_aborts() {
    let vfs = MemVfs::new();
    let opts = opts_low_threshold();
    let db = Db::open_internal_with_options(vfs, KEK, 4096, REALM, opts)
        .await
        .unwrap();
    db.set_reader_stall_policy(ReaderStallPolicy::Unbounded);

    // Open a reader that pins old pages.
    let reader = db.begin_read().await.unwrap();

    // Build backlog — should never get an error with Unbounded.
    let err = fill_until_stall(&db).await;
    assert!(
        err.is_none(),
        "Unbounded should not produce errors; got {err:?}"
    );

    // Reader still works.
    let result = reader.get(b"anything").await;
    assert!(result.is_ok(), "reader should still be alive: {result:?}");
    drop(reader);
}

#[tokio::test(flavor = "current_thread")]
async fn reject_returns_backlog_error() {
    let vfs = MemVfs::new();
    let opts = opts_low_threshold();
    let db = Db::open_internal_with_options(vfs, KEK, 4096, REALM, opts)
        .await
        .unwrap();
    db.set_reader_stall_policy(ReaderStallPolicy::Reject);

    // Non-abortable reader blocks draining.
    let _reader = db.begin_read_non_abortable().await.unwrap();

    let err = fill_until_stall(&db).await;
    assert!(
        matches!(err, Some(PagedbError::DeferredFreeBacklog { .. })),
        "expected DeferredFreeBacklog, got: {err:?}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn abort_oldest_aborts_old_reader() {
    let vfs = MemVfs::new();
    let opts = opts_low_threshold();
    let db = Db::open_internal_with_options(vfs, KEK, 4096, REALM, opts)
        .await
        .unwrap();
    db.set_reader_stall_policy(ReaderStallPolicy::AbortOldest);

    // Write initial data so the reader has something to read.
    {
        let mut txn = db.begin_write().await.unwrap();
        txn.put(b"hello", b"world").await.unwrap();
        txn.commit().await.unwrap();
    }

    // Open old reader R1 first, then newer reader R2.
    let r1 = db.begin_read().await.unwrap();
    let r2 = db.begin_read().await.unwrap();

    // Build backlog until AbortOldest fires and marks R1 as aborted.
    fill_until_stall(&db).await;

    // R1 should now return Aborted on its next read.
    let r1_result = r1.get(b"hello").await;
    assert!(
        matches!(r1_result, Err(PagedbError::Aborted)),
        "R1 should be aborted, got: {r1_result:?}"
    );

    // R2 should still work.
    let r2_result = r2.get(b"hello").await;
    assert!(r2_result.is_ok(), "R2 should still work: {r2_result:?}");

    drop(r1);
    drop(r2);
}

#[tokio::test(flavor = "current_thread")]
async fn non_abortable_reader_survives_abort_oldest() {
    let vfs = MemVfs::new();
    let opts = opts_low_threshold();
    let db = Db::open_internal_with_options(vfs, KEK, 4096, REALM, opts)
        .await
        .unwrap();
    db.set_reader_stall_policy(ReaderStallPolicy::AbortOldest);

    // Only a non-abortable reader is blocking.
    let r_non_abortable = db.begin_read_non_abortable().await.unwrap();

    // Write initial data.
    {
        let mut txn = db.begin_write().await.unwrap();
        txn.put(b"key", b"val").await.unwrap();
        txn.commit().await.unwrap();
    }

    // Fill until stall: since only non-abortable readers block, the policy
    // falls through to Reject semantics.
    let err = fill_until_stall(&db).await;
    assert!(
        matches!(err, Some(PagedbError::DeferredFreeBacklog { .. })),
        "should get DeferredFreeBacklog when only non-abortable readers are blocking; got {err:?}"
    );

    // Non-abortable reader should still work.
    let result = r_non_abortable.get(b"key").await;
    assert!(
        result.is_ok(),
        "non-abortable reader should not be aborted: {result:?}"
    );
}
