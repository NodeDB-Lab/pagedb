//! `WriteTxn::commit` dropped before, inside, and after its durable window.

use std::time::Duration;

use tokio::time::timeout;

use crate::options::OpenOptions;
use crate::pager::core::FileKey;
use crate::recovery::deep_walk::run_deep_walk;
use crate::vfs::gated::{GatedVfs, cancel_when};
use crate::vfs::{OpenMode, Vfs};
use crate::{CommitId, Db};

use super::support::{KEK, PAGE, REALM, next_commit, next_header_offset, poisoned_commit};

/// How long a commit runs while the test holds the gate it needs. It cannot
/// finish in any time, and the first poll takes it to the gate.
const GATE_PATIENCE: Duration = Duration::from_millis(50);

async fn store_with_base_commit(options: OpenOptions) -> (GatedVfs, Db<GatedVfs>) {
    let vfs = GatedVfs::new();
    let db = Db::open(vfs.clone(), KEK, PAGE, REALM, options)
        .await
        .unwrap();
    let mut txn = db.begin_write().await.unwrap();
    txn.put(b"base", b"before").await.unwrap();
    txn.commit().await.unwrap();
    (vfs, db)
}

/// The header bytes landed and the future is still pending. Without poison the
/// next commit overwrites pages that durable header names.
#[tokio::test(flavor = "current_thread")]
async fn commit_dropped_after_its_header_write_poisons_and_keeps_the_commit_after_reopen() {
    let (vfs, db) = store_with_base_commit(OpenOptions::default()).await;
    let base = db.latest_commit();
    let expected = next_commit(&db);
    let existing = db.begin_read().await.unwrap();

    let mut txn = db.begin_write().await.unwrap();
    txn.put(b"landed", b"after").await.unwrap();
    let header = vfs.park_next_write_at(&db.main_db_path, next_header_offset(&db));
    cancel_when(Box::pin(txn.commit()), header.wait_until_parked()).await;

    assert_eq!(poisoned_commit(db.begin_read().await), expected);
    assert_eq!(poisoned_commit(db.begin_write().await), expected);
    assert_eq!(db.latest_commit(), base);
    assert_eq!(
        existing.get(b"base").await.unwrap().as_deref(),
        Some(b"before".as_slice()),
        "a reader of published data keeps working"
    );
    assert!(existing.get(b"landed").await.unwrap().is_none());
    drop(existing);
    drop(db);

    let reopened = Db::open(vfs, KEK, PAGE, REALM, OpenOptions::default())
        .await
        .unwrap();
    assert_eq!(reopened.latest_commit(), expected);
    let reader = reopened.begin_read().await.unwrap();
    assert_eq!(
        reader.get(b"landed").await.unwrap().as_deref(),
        Some(b"after".as_slice())
    );
    drop(reader);
    let report = run_deep_walk(&reopened).await.unwrap();
    assert!(report.is_clean(), "the reopened store: {report:?}");
}

/// The header is durable and `state` has advanced. Publication waits on the gate
/// a metadata walk holds.
#[tokio::test(flavor = "current_thread")]
async fn commit_dropped_while_waiting_to_publish_poisons_the_handle() {
    let (vfs, db) = store_with_base_commit(OpenOptions::default()).await;
    let expected = next_commit(&db);

    let hold = db.visibility_gate.read().await;
    let mut txn = db.begin_write().await.unwrap();
    txn.put(b"landed", b"after").await.unwrap();
    assert!(
        timeout(GATE_PATIENCE, Box::pin(txn.commit()))
            .await
            .is_err(),
        "the commit finished while the test held the visibility gate"
    );
    drop(hold);

    assert_eq!(poisoned_commit(db.begin_read().await), expected);
    drop(db);

    let reopened = Db::open(vfs, KEK, PAGE, REALM, OpenOptions::default())
        .await
        .unwrap();
    let reader = reopened.begin_read().await.unwrap();
    assert_eq!(
        reader.get(b"landed").await.unwrap().as_deref(),
        Some(b"after".as_slice())
    );
}

/// The page flush writes only pages no durable header names. A drop there is a
/// plain abort, so it must not poison.
#[tokio::test(flavor = "current_thread")]
async fn commit_dropped_before_any_durable_step_stays_a_plain_abort() {
    let (vfs, db) = store_with_base_commit(OpenOptions::default()).await;
    let base = db.latest_commit();

    let mut txn = db.begin_write().await.unwrap();
    txn.put(b"aborted", b"never").await.unwrap();
    let flush_sync = vfs.park_next_sync(&db.main_db_path);
    cancel_when(Box::pin(txn.commit()), flush_sync.wait_until_parked()).await;

    db.ensure_usable().unwrap();
    assert_eq!(db.latest_commit(), base);
    let dirty = db
        .pager
        .inner
        .buffer_pool
        .lock()
        .dirty_for_file(FileKey::Main);
    assert_eq!(dirty, Vec::<u64>::new(), "dirty pages survived the drop");
    {
        let reader = db.begin_read().await.unwrap();
        assert_eq!(
            reader.get(b"base").await.unwrap().as_deref(),
            Some(b"before".as_slice())
        );
        assert!(reader.get(b"aborted").await.unwrap().is_none());
    }

    let mut txn = db.begin_write().await.unwrap();
    txn.put(b"next", b"writer").await.unwrap();
    assert_eq!(txn.commit().await.unwrap(), CommitId::new(base.value() + 1));
    drop(db);

    let reopened = Db::open(vfs, KEK, PAGE, REALM, OpenOptions::default())
        .await
        .unwrap();
    let reader = reopened.begin_read().await.unwrap();
    assert_eq!(
        reader.get(b"next").await.unwrap().as_deref(),
        Some(b"writer".as_slice())
    );
    assert!(reader.get(b"aborted").await.unwrap().is_none());
}

/// Publication has run, so a drop during the spill cleanup leaves the commit
/// visible. `Drop` still owns the gauge and the path.
#[tokio::test(flavor = "current_thread")]
async fn commit_dropped_during_spill_cleanup_stays_published_and_clears_the_spill() {
    let options = OpenOptions::default().with_scratch_bytes(1024 * 1024);
    let (vfs, db) = store_with_base_commit(options).await;

    let mut txn = db.begin_write().await.unwrap();
    txn.put(b"landed", b"after").await.unwrap();
    txn.spill_scope().append(b"spilled").await.unwrap();
    let spill_path = format!("tmp/scratch-{}", txn.txn_seq);
    let cleanup = vfs.park_next_remove(&spill_path);
    cancel_when(Box::pin(txn.commit()), cleanup.wait_until_parked()).await;

    db.ensure_usable().unwrap();
    assert_eq!(
        db.stats().await.unwrap().spill_bytes_in_use,
        0,
        "the gauge reports a transaction that no longer exists"
    );
    {
        let reader = db.begin_read().await.unwrap();
        assert_eq!(
            reader.get(b"landed").await.unwrap().as_deref(),
            Some(b"after".as_slice())
        );
    }

    db.begin_write().await.unwrap().abort().await;
    assert!(
        vfs.open(&spill_path, OpenMode::Read).await.is_err(),
        "the next begin_write removes the spill file the dropped commit left"
    );
}
