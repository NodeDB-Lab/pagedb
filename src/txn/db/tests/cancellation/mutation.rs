//! `WriteTxn` mutations dropped mid-tree-walk, and what the transaction then does.

use std::sync::Arc;

use bytes::Bytes;

use crate::options::OpenOptions;
use crate::pager::core::FileKey;
use crate::recovery::deep_walk::run_deep_walk;
use crate::vfs::gated::{Gate, GatedVfs, bounded, cancel_when};
use crate::{Db, PagedbError};

use super::support::{KEK, PAGE, REALM};

// A counter or segment call reads its catalog root first and then writes. The
// read caches the root, so a read gate cannot park the write that follows. These
// tests therefore drop `put`, `delete`, and a read. Those other calls use the same
// marker, and one test below checks that the marker refuses them.

async fn store_with_base_row() -> (GatedVfs, Db<GatedVfs>) {
    let vfs = GatedVfs::new();
    let db = Db::open(vfs.clone(), KEK, PAGE, REALM, OpenOptions::default())
        .await
        .unwrap();
    let mut txn = db.begin_write().await.unwrap();
    txn.put(b"base", b"before").await.unwrap();
    txn.commit().await.unwrap();
    (vfs, db)
}

/// Arm a gate on the data root read, and empty the cache so a tree walk misses.
fn park_next_root_read(vfs: &GatedVfs, db: &Db<GatedVfs>) -> Arc<Gate> {
    db.pager.evict_clean_main_pages().unwrap();
    let root = db.snapshot.read().root_page_id;
    vfs.park_next_read(&db.main_db_path, root * PAGE as u64)
}

fn assert_interrupted<T>(outcome: crate::Result<T>) {
    assert!(
        matches!(outcome, Err(PagedbError::WriteTxnInterrupted)),
        "expected WriteTxnInterrupted"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn commit_after_a_dropped_put_returns_the_typed_error_and_publishes_nothing() {
    let (vfs, db) = store_with_base_row().await;
    let base = db.latest_commit();

    let mut txn = db.begin_write().await.unwrap();
    let read = park_next_root_read(&vfs, &db);
    cancel_when(
        Box::pin(txn.put(b"dropped", b"value")),
        read.wait_until_parked(),
    )
    .await;

    assert_interrupted(txn.commit().await);
    assert_eq!(db.latest_commit(), base);
    db.ensure_usable().unwrap();
    let reader = db.begin_read().await.unwrap();
    assert!(reader.get(b"dropped").await.unwrap().is_none());
}

#[tokio::test(flavor = "current_thread")]
async fn commit_after_a_dropped_delete_returns_the_typed_error_and_keeps_the_row() {
    let (vfs, db) = store_with_base_row().await;

    let mut txn = db.begin_write().await.unwrap();
    let read = park_next_root_read(&vfs, &db);
    cancel_when(Box::pin(txn.delete(b"base")), read.wait_until_parked()).await;

    assert_interrupted(txn.commit().await);
    let reader = db.begin_read().await.unwrap();
    assert_eq!(
        reader.get(b"base").await.unwrap().as_deref(),
        Some(b"before".as_slice())
    );
}

#[tokio::test(flavor = "current_thread")]
async fn every_read_after_a_dropped_put_returns_the_typed_error() {
    let (vfs, db) = store_with_base_row().await;

    let mut txn = db.begin_write().await.unwrap();
    let read = park_next_root_read(&vfs, &db);
    cancel_when(
        Box::pin(txn.put(b"dropped", b"value")),
        read.wait_until_parked(),
    )
    .await;

    assert_interrupted(txn.get(b"base").await);
    assert_interrupted(txn.get_range(b"base", 0, 1).await);
    assert_interrupted(txn.scan(b"a", b"z").await);
    assert_interrupted(txn.scan_from(b"a", 1).await);
    assert_interrupted(txn.scan_prefix(b"b").await);
    assert_interrupted(txn.scan_prefix_from(b"b", b"b", 1).await);
    assert_interrupted(txn.scan_rev(b"a", b"z").await);
    assert_interrupted(txn.scan_rev_from(None, 1).await);
    assert_interrupted(txn.first_key().await);
    assert_interrupted(txn.last_key().await);
}

#[tokio::test(flavor = "current_thread")]
async fn every_mutation_after_a_dropped_put_returns_the_typed_error() {
    let (vfs, db) = store_with_base_row().await;

    let mut txn = db.begin_write().await.unwrap();
    let read = park_next_root_read(&vfs, &db);
    cancel_when(
        Box::pin(txn.put(b"dropped", b"value")),
        read.wait_until_parked(),
    )
    .await;

    assert_interrupted(txn.put(b"k", b"v").await);
    assert_interrupted(txn.put_append(b"k", b"v").await);
    assert_interrupted(txn.delete(b"k").await);
    assert_interrupted(
        txn.put_batch(vec![(Bytes::from_static(b"k"), Bytes::from_static(b"v"))])
            .await,
    );
    assert_interrupted(txn.delete_batch(vec![b"k".to_vec()]).await);
    assert_interrupted(txn.delete_range(b"a", b"z").await);
    assert_interrupted(txn.unlink_segment("absent").await);
    assert_interrupted(txn.counter("c").map(|_| ()));
}

/// The transaction itself still aborts cleanly, and the writer slot comes back.
#[tokio::test(flavor = "current_thread")]
async fn dropping_a_transaction_after_a_dropped_put_stays_a_clean_abort() {
    let (vfs, db) = store_with_base_row().await;
    let base = db.latest_commit();

    let mut txn = db.begin_write().await.unwrap();
    let read = park_next_root_read(&vfs, &db);
    cancel_when(
        Box::pin(txn.put(b"dropped", b"value")),
        read.wait_until_parked(),
    )
    .await;
    drop(txn);

    db.ensure_usable().unwrap();
    assert_eq!(db.latest_commit(), base);
    let dirty = db
        .pager
        .inner
        .buffer_pool
        .lock()
        .dirty_for_file(FileKey::Main);
    assert_eq!(dirty, Vec::<u64>::new(), "dirty pages survived the drop");

    let mut txn = db.begin_write().await.unwrap();
    txn.put(b"next", b"writer").await.unwrap();
    txn.commit().await.unwrap();
    let reader = db.begin_read().await.unwrap();
    assert!(reader.get(b"dropped").await.unwrap().is_none());
    assert_eq!(
        reader.get(b"next").await.unwrap().as_deref(),
        Some(b"writer".as_slice())
    );
    drop(reader);
    let report = run_deep_walk(&db).await.unwrap();
    assert!(report.is_clean(), "the store after the abort: {report:?}");
}

#[tokio::test(flavor = "current_thread")]
async fn abort_after_a_dropped_put_leaves_the_store_writable() {
    let (vfs, db) = store_with_base_row().await;

    let mut txn = db.begin_write().await.unwrap();
    let read = park_next_root_read(&vfs, &db);
    cancel_when(
        Box::pin(txn.put(b"dropped", b"value")),
        read.wait_until_parked(),
    )
    .await;
    txn.abort().await;

    let mut txn = db.begin_write().await.unwrap();
    txn.put(b"next", b"writer").await.unwrap();
    txn.commit().await.unwrap();
}

/// A validation error changes no tree. The transaction stays usable, and every
/// earlier write in it still commits.
#[tokio::test(flavor = "current_thread")]
async fn an_error_from_a_mutation_does_not_mark_the_transaction_interrupted() {
    let (_vfs, db) = store_with_base_row().await;

    let mut txn = db.begin_write().await.unwrap();
    txn.put_append(b"m", b"1").await.unwrap();
    assert!(matches!(
        txn.put_append(b"l", b"2").await,
        Err(PagedbError::AppendNotMonotonic)
    ));
    let too_long = vec![b'k'; PAGE];
    assert!(matches!(
        txn.put(&too_long, b"v").await,
        Err(PagedbError::PayloadTooLarge)
    ));
    assert!(matches!(
        txn.unlink_segment("absent").await,
        Err(PagedbError::NotLinked)
    ));
    assert!(txn.get(b"m").await.unwrap().is_some());
    txn.put(b"n", b"3").await.unwrap();
    txn.commit().await.unwrap();

    let reader = db.begin_read().await.unwrap();
    assert!(reader.get(b"m").await.unwrap().is_some());
    assert!(reader.get(b"n").await.unwrap().is_some());
}

#[tokio::test(flavor = "current_thread")]
async fn a_batch_with_a_rejected_record_applies_nothing_and_stays_usable() {
    let (_vfs, db) = store_with_base_row().await;

    let mut txn = db.begin_write().await.unwrap();
    let pairs = vec![
        (Bytes::from_static(b"first"), Bytes::from_static(b"v")),
        (Bytes::from(vec![b'k'; PAGE]), Bytes::from_static(b"v")),
    ];
    assert!(matches!(
        txn.put_batch(pairs).await,
        Err(PagedbError::PayloadTooLarge)
    ));
    assert!(txn.get(b"first").await.unwrap().is_none());
    txn.commit().await.unwrap();
}

/// Rows of the largest inline size. A leaf holds three of them, because four alone
/// exceed a page, so a fourth in a full leaf must split it.
const WIDE_ROWS: u32 = 40;
const WIDE_VALUE_LEN: usize = PAGE / 4;

fn wide_key(row: u32) -> Vec<u8> {
    format!("row-{row:05}").into_bytes()
}

async fn store_with_a_two_level_tree() -> (GatedVfs, Db<GatedVfs>) {
    let vfs = GatedVfs::new();
    let db = Db::open(vfs.clone(), KEK, PAGE, REALM, OpenOptions::default())
        .await
        .unwrap();
    let mut txn = db.begin_write().await.unwrap();
    for row in 0..WIDE_ROWS {
        txn.put(&wide_key(row), &[0xA5; WIDE_VALUE_LEN])
            .await
            .unwrap();
    }
    txn.commit().await.unwrap();
    (vfs, db)
}

async fn assert_every_wide_row_reads_back(db: &Db<GatedVfs>) {
    let reader = db.begin_read().await.unwrap();
    for row in 0..WIDE_ROWS {
        assert_eq!(
            reader.get(&wide_key(row)).await.unwrap().as_deref(),
            Some([0xA5; WIDE_VALUE_LEN].as_slice()),
            "row {row}"
        );
    }
}

/// The split has freed the old leaf and moved its records when the spine read
/// fails. The tree then names a freed leaf. Committing it publishes a free list
/// that holds a live page, so the error must end the transaction.
#[tokio::test(flavor = "current_thread")]
async fn a_read_error_during_a_split_ends_the_transaction_and_leaves_the_store_clean() {
    let (vfs, db) = store_with_a_two_level_tree().await;
    let base = db.latest_commit();
    let root_offset = db.snapshot.read().root_page_id * PAGE as u64;
    let inserted = b"row-00001-inserted";

    let mut txn = db.begin_write().await.unwrap();
    db.pager.evict_clean_main_pages().unwrap();
    let below_root = vfs.park_next_read_other_than(&db.main_db_path, root_offset);
    let mut put = Box::pin(txn.put(inserted, &[0xB6; WIDE_VALUE_LEN]));
    bounded(async {
        tokio::select! {
            biased;
            () = below_root.wait_until_parked() => {}
            _ = &mut put => panic!("the put finished before it read below the root"),
        }
    })
    .await;
    // The descent has read the root. Its next read is the split's spine update.
    db.pager.evict_clean_main_pages().unwrap();
    vfs.fail_next_read_at(&db.main_db_path, root_offset);
    below_root.release();
    assert!(
        matches!(bounded(put).await, Err(PagedbError::Io(_))),
        "the injected spine read error did not reach the caller"
    );

    assert_interrupted(txn.get(b"row-00000").await);
    assert_interrupted(txn.commit().await);
    db.ensure_usable().unwrap();
    assert_eq!(db.latest_commit(), base);
    assert_every_wide_row_reads_back(&db).await;
    let report = run_deep_walk(&db).await.unwrap();
    assert!(report.is_clean(), "the store after the error: {report:?}");

    let mut txn = db.begin_write().await.unwrap();
    txn.put(inserted, &[0xB6; WIDE_VALUE_LEN]).await.unwrap();
    txn.commit().await.unwrap();
    assert_every_wide_row_reads_back(&db).await;
    let report = run_deep_walk(&db).await.unwrap();
    assert!(report.is_clean(), "the store after the retry: {report:?}");
}

/// A descent error changes no tree, but a caller of `put` cannot tell it from a
/// split error. It ends the transaction in the same way.
#[tokio::test(flavor = "current_thread")]
async fn a_read_error_during_a_descent_ends_the_transaction() {
    let (vfs, db) = store_with_base_row().await;
    let root_offset = db.snapshot.read().root_page_id * PAGE as u64;

    let mut txn = db.begin_write().await.unwrap();
    db.pager.evict_clean_main_pages().unwrap();
    vfs.fail_next_read_at(&db.main_db_path, root_offset);
    assert!(matches!(
        txn.put(b"lost", b"value").await,
        Err(PagedbError::Io(_))
    ));

    assert_interrupted(txn.commit().await);
    db.ensure_usable().unwrap();
    let reader = db.begin_read().await.unwrap();
    assert!(reader.get(b"lost").await.unwrap().is_none());
    assert_eq!(
        reader.get(b"base").await.unwrap().as_deref(),
        Some(b"before".as_slice())
    );
}

/// A dropped read changes no tree, so it must not end the transaction.
#[tokio::test(flavor = "current_thread")]
async fn a_dropped_read_does_not_mark_the_transaction_interrupted() {
    let (vfs, db) = store_with_base_row().await;

    let mut txn = db.begin_write().await.unwrap();
    let read = park_next_root_read(&vfs, &db);
    cancel_when(Box::pin(txn.get(b"base")), read.wait_until_parked()).await;
    txn.put(b"after", b"read").await.unwrap();
    txn.commit().await.unwrap();

    let reader = db.begin_read().await.unwrap();
    assert_eq!(
        reader.get(b"after").await.unwrap().as_deref(),
        Some(b"read".as_slice())
    );
}
