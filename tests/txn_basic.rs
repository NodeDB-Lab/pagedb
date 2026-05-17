use pagedb::vfs::memory::MemVfs;
use pagedb::{CommitId, Db, PagedbError, ReaderStallPolicy, RealmId};

const PAGE: usize = 4096;

async fn open_db() -> Db<MemVfs> {
    Db::open_internal(MemVfs::new(), [9u8; 32], PAGE, RealmId::new([1; 16]))
        .await
        .unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn empty_db_begin_read_then_read_returns_none() {
    let db = open_db().await;
    let r = db.begin_read().await.unwrap();
    assert!(r.get(b"missing").await.unwrap().is_none());
}

#[tokio::test(flavor = "current_thread")]
async fn write_commit_then_read() {
    let db = open_db().await;
    {
        let mut w = db.begin_write().await.unwrap();
        w.put(b"k", b"v").await.unwrap();
        let cid = w.commit().await.unwrap();
        assert_eq!(cid, CommitId::new(1));
    }
    let r = db.begin_read().await.unwrap();
    assert_eq!(r.get(b"k").await.unwrap().as_deref(), Some(b"v".as_ref()));
}

#[tokio::test(flavor = "current_thread")]
async fn abort_discards_changes() {
    let db = open_db().await;
    {
        let mut w = db.begin_write().await.unwrap();
        w.put(b"k", b"v").await.unwrap();
        w.abort().await;
    }
    let r = db.begin_read().await.unwrap();
    assert!(r.get(b"k").await.unwrap().is_none());
}

#[tokio::test(flavor = "current_thread")]
async fn snapshot_isolation_pin_survives_concurrent_writer() {
    let db = open_db().await;
    // commit 1: k=v1
    {
        let mut w = db.begin_write().await.unwrap();
        w.put(b"k", b"v1").await.unwrap();
        w.commit().await.unwrap();
    }
    // open a reader at commit 1
    let r = db.begin_read().await.unwrap();
    assert_eq!(r.commit_id(), CommitId::new(1));
    // commit 2: k=v2
    {
        let mut w = db.begin_write().await.unwrap();
        w.put(b"k", b"v2").await.unwrap();
        w.commit().await.unwrap();
    }
    // The pre-existing reader's view depends on the snapshot pin —
    // because the BTree CoW path leaves the old root in place (just
    // unreferenced from the new header), the reader at commit_id=1
    // continues to see "v1" by descending from its pinned root.
    assert_eq!(r.get(b"k").await.unwrap().as_deref(), Some(b"v1".as_ref()));
}

#[tokio::test(flavor = "current_thread")]
async fn latest_commit_advances_on_commit() {
    let db = open_db().await;
    assert_eq!(db.latest_commit(), CommitId::new(0));
    {
        let mut w = db.begin_write().await.unwrap();
        w.put(b"a", b"1").await.unwrap();
        w.commit().await.unwrap();
    }
    assert_eq!(db.latest_commit(), CommitId::new(1));
    {
        let mut w = db.begin_write().await.unwrap();
        w.put(b"b", b"2").await.unwrap();
        w.commit().await.unwrap();
    }
    assert_eq!(db.latest_commit(), CommitId::new(2));
}

#[tokio::test(flavor = "current_thread")]
async fn begin_read_at_current_succeeds() {
    let db = open_db().await;
    {
        let mut w = db.begin_write().await.unwrap();
        w.put(b"k", b"v").await.unwrap();
        w.commit().await.unwrap();
    }
    let r = db.begin_read_at(CommitId::new(1)).await.unwrap();
    assert_eq!(r.get(b"k").await.unwrap().as_deref(), Some(b"v".as_ref()));
}

#[tokio::test(flavor = "current_thread")]
async fn begin_read_at_past_returns_commit_gone() {
    // With Count(2), writing 3 commits prunes commit 1; begin_read_at(1) must
    // return CommitGone.
    use pagedb::options::{OpenOptions, RetainPolicy};
    use pagedb::vfs::memory::MemVfs;
    let opts = OpenOptions::default().with_commit_history_retain(RetainPolicy::Count(2));
    let db =
        Db::open_internal_with_options(MemVfs::new(), [9u8; 32], PAGE, RealmId::new([1; 16]), opts)
            .await
            .unwrap();
    for _ in 0..3u32 {
        let mut w = db.begin_write().await.unwrap();
        w.put(b"k", b"v").await.unwrap();
        w.commit().await.unwrap();
    }
    let result = db.begin_read_at(CommitId::new(1)).await;
    match result {
        Err(PagedbError::CommitGone { .. }) => {}
        Err(e) => panic!("expected CommitGone, got error {e:?}"),
        Ok(_) => panic!("expected CommitGone but got Ok"),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn begin_read_at_future_returns_commit_gone() {
    let db = open_db().await;
    let err = db.begin_read_at(CommitId::new(99)).await.err().unwrap();
    assert!(matches!(err, PagedbError::CommitGone { .. }));
}

#[tokio::test(flavor = "current_thread")]
async fn write_txn_serializes() {
    use std::sync::Arc;
    use tokio::task::LocalSet;

    let local = LocalSet::new();
    local
        .run_until(async {
            let db = Arc::new(open_db().await);
            let db2 = db.clone();
            // First writer holds the slot; second writer must wait.
            let mut w1 = db.begin_write().await.unwrap();
            w1.put(b"k", b"v").await.unwrap();
            // Spawn a second begin_write using spawn_local.
            let handle = tokio::task::spawn_local(async move {
                let mut w2 = db2.begin_write().await.unwrap();
                w2.put(b"k2", b"v2").await.unwrap();
                w2.commit().await.unwrap()
            });
            // Yield a few times to let the spawned task try (and block) on the lock.
            for _ in 0..5 {
                tokio::task::yield_now().await;
            }
            assert!(!handle.is_finished(), "second writer should be blocked");
            w1.commit().await.unwrap();
            let cid2 = handle.await.unwrap();
            assert_eq!(cid2, CommitId::new(2));
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn reader_registration_drops_clean() {
    let db = open_db().await;
    {
        let _r1 = db.begin_read().await.unwrap();
        let _r2 = db.begin_read().await.unwrap();
        let _r3 = db.begin_read().await.unwrap();
        // 3 readers registered
    }
    // After scope, all unregistered; opening a writer should not contend.
    let mut w = db.begin_write().await.unwrap();
    w.put(b"a", b"b").await.unwrap();
    w.commit().await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn reader_stall_policy_settable() {
    let db = open_db().await;
    assert_eq!(db.reader_stall_policy(), ReaderStallPolicy::AbortOldest);
    db.set_reader_stall_policy(ReaderStallPolicy::Reject);
    assert_eq!(db.reader_stall_policy(), ReaderStallPolicy::Reject);
    db.set_reader_stall_policy(ReaderStallPolicy::Unbounded);
    assert_eq!(db.reader_stall_policy(), ReaderStallPolicy::Unbounded);
}
