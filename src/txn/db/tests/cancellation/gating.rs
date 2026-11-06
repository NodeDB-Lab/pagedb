//! Every entry point reports poison, including a call already waiting on a lock
//! when the poison lands.

use std::time::Duration;

use tokio::time::timeout;

use crate::catalog::codec::{RealmQuotas, SegmentKind};
use crate::options::OpenOptions;
use crate::recovery::deep_walk::run_deep_walk;
use crate::vfs::gated::{GatedVfs, bounded};
use crate::{CommitId, CompactBudget, Db};

use super::support::{KEK, PAGE, REALM, next_commit, poisoned_commit, store_with_free_pages};

#[tokio::test(flavor = "current_thread")]
async fn every_entry_point_reports_poison() {
    let db = Db::open(GatedVfs::new(), KEK, PAGE, REALM, OpenOptions::default())
        .await
        .unwrap();
    let mut txn = db.begin_write().await.unwrap();
    txn.put(b"base", b"before").await.unwrap();
    let first = txn.commit().await.unwrap();

    let commit = CommitId::new(99);
    db.poison(commit);

    assert_eq!(poisoned_commit(db.begin_read().await), commit);
    assert_eq!(poisoned_commit(db.begin_read_non_abortable().await), commit);
    assert_eq!(poisoned_commit(db.begin_read_at(first).await), commit);
    assert_eq!(poisoned_commit(db.begin_write().await), commit);
    assert_eq!(poisoned_commit(db.compact_now().await), commit);
    assert_eq!(
        poisoned_commit(db.compact_step(CompactBudget::default()).await),
        commit
    );
    assert_eq!(poisoned_commit(db.gc_now().await), commit);
    assert_eq!(poisoned_commit(db.rekey_db(KEK, 1).await), commit);
    assert_eq!(poisoned_commit(db.stats().await), commit);
    assert_eq!(poisoned_commit(db.main_db_byte_size().await), commit);
    assert_eq!(poisoned_commit(db.page_provenance(4).await), commit);
    assert_eq!(poisoned_commit(run_deep_walk(&db).await), commit);
    assert_eq!(
        poisoned_commit(db.create_segment(REALM, SegmentKind::Unspecified).await),
        commit
    );
    assert_eq!(poisoned_commit(db.open_segment(REALM, "x").await), commit);
    assert_eq!(poisoned_commit(db.list_segments(REALM, "").await), commit);
    assert_eq!(poisoned_commit(db.realm_quotas(REALM).await), commit);
    assert_eq!(
        poisoned_commit(db.set_realm_quotas(REALM, RealmQuotas::default()).await),
        commit
    );
    #[cfg(not(target_arch = "wasm32"))]
    {
        let unused = std::path::Path::new("/unused");
        assert_eq!(poisoned_commit(db.snapshot_to(unused).await), commit);
        assert_eq!(
            poisoned_commit(db.snapshot_incremental_to(first, unused).await),
            commit
        );
    }
}

/// A reader checks poison, then waits on the gate a repack holds. The repack is
/// dropped after its rename. The reader must not pin old roots over the new file.
#[tokio::test(flavor = "current_thread")]
async fn a_reader_waiting_on_the_gate_reports_poison_when_the_holder_is_dropped() {
    let (vfs, db) = store_with_free_pages().await;
    let expected = next_commit(&db);
    let dir_sync = vfs.park_next_sync_dir("/");

    let mut compaction = Box::pin(db.compact_now());
    bounded(async {
        tokio::select! {
            biased;
            () = dir_sync.wait_until_parked() => {}
            _ = &mut compaction => panic!("the compaction finished before its directory sync"),
        }
    })
    .await;

    let mut reader = Box::pin(db.begin_read());
    assert!(
        timeout(Duration::from_millis(50), &mut reader)
            .await
            .is_err(),
        "the reader was admitted while the repack held the gate"
    );

    drop(compaction);
    assert_eq!(poisoned_commit(reader.await), expected);
}
