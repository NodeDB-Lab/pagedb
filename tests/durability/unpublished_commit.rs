//! A failed post-header segment reconciliation poisons only the active handle.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use pagedb::vfs::memory::{MemFile, MemLockHandle, MemVfs};
use pagedb::vfs::{OpenMode, Vfs};
use pagedb::{Db, PagedbError, RealmId, SegmentKind, run_deep_walk};

const PAGE: usize = 4096;
const KEK: [u8; 32] = [12u8; 32];
const REALM: RealmId = RealmId::new([4u8; 16]);

#[derive(Clone)]
struct RenameFaultVfs {
    inner: MemVfs,
    fail_renames: Arc<AtomicBool>,
    fail_sync_dirs: Arc<AtomicBool>,
    failures_remaining: Arc<AtomicUsize>,
}

impl RenameFaultVfs {
    fn new() -> Self {
        Self {
            inner: MemVfs::new(),
            fail_renames: Arc::new(AtomicBool::new(false)),
            fail_sync_dirs: Arc::new(AtomicBool::new(false)),
            failures_remaining: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn fail_renames(&self, fail: bool) {
        self.fail_renames.store(fail, Ordering::SeqCst);
    }

    fn fail_next_rename(&self) {
        self.failures_remaining.store(1, Ordering::SeqCst);
    }

    fn fail_sync_dirs(&self, fail: bool) {
        self.fail_sync_dirs.store(fail, Ordering::SeqCst);
    }
}

impl Vfs for RenameFaultVfs {
    type File = MemFile;
    type LockHandle = MemLockHandle;

    async fn open(&self, path: &str, mode: OpenMode) -> pagedb::Result<Self::File> {
        self.inner.open(path, mode).await
    }

    async fn remove(&self, path: &str) -> pagedb::Result<()> {
        self.inner.remove(path).await
    }

    async fn rename(&self, from: &str, to: &str) -> pagedb::Result<()> {
        let fail_once = self
            .failures_remaining
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok();
        if self.fail_renames.load(Ordering::SeqCst) || fail_once {
            return Err(PagedbError::Io(std::io::Error::other(
                "injected segment reconciliation failure",
            )));
        }
        self.inner.rename(from, to).await
    }

    async fn list_dir(&self, path: &str) -> pagedb::Result<Vec<String>> {
        self.inner.list_dir(path).await
    }

    async fn mkdir_all(&self, path: &str) -> pagedb::Result<()> {
        self.inner.mkdir_all(path).await
    }

    async fn sync_dir(&self, path: &str) -> pagedb::Result<()> {
        if self.fail_sync_dirs.load(Ordering::SeqCst) {
            return Err(PagedbError::Io(std::io::Error::other(
                "injected post-durable directory sync failure",
            )));
        }
        self.inner.sync_dir(path).await
    }

    async fn lock_exclusive(&self, path: &str) -> pagedb::Result<Self::LockHandle> {
        self.inner.lock_exclusive(path).await
    }

    async fn lock_shared(&self, path: &str) -> pagedb::Result<Self::LockHandle> {
        self.inner.lock_shared(path).await
    }
}

#[tokio::test(flavor = "current_thread")]
async fn one_segment_reconciliation_retry_publishes_once() {
    let vfs = RenameFaultVfs::new();
    let db = Db::open_internal(vfs.clone(), KEK, PAGE, REALM)
        .await
        .unwrap();
    let writer = db
        .create_segment(REALM, SegmentKind::Unspecified)
        .await
        .unwrap();
    let meta = writer.seal().await.unwrap();
    let mut txn = db.begin_write().await.unwrap();
    txn.link_segment("retry", &meta).await.unwrap();

    vfs.fail_next_rename();
    let commit = txn.commit().await.unwrap();
    assert_eq!(commit.value(), 1);
    assert_eq!(db.latest_commit(), commit);
    assert!(db.open_segment(REALM, "retry").await.is_ok());
}

#[tokio::test(flavor = "current_thread")]
async fn failed_segment_reconciliation_poisoned_handle_keeps_existing_snapshot_usable() {
    let vfs = RenameFaultVfs::new();
    let db = Db::open_internal(vfs.clone(), KEK, PAGE, REALM)
        .await
        .unwrap();
    let existing = db.begin_read().await.unwrap();

    let writer = db
        .create_segment(REALM, SegmentKind::Unspecified)
        .await
        .unwrap();
    let meta = writer.seal().await.unwrap();
    let mut txn = db.begin_write().await.unwrap();
    txn.link_segment("replacement", &meta).await.unwrap();

    vfs.fail_renames(true);
    let result = txn.commit().await;
    let durable_commit = match result {
        Err(PagedbError::DurablyCommittedButUnpublished { commit }) => commit,
        other => panic!("expected poisoned-handle error, got {other:?}"),
    };

    assert_eq!(db.latest_commit().value(), 0);
    assert!(existing.get(b"absent").await.unwrap().is_none());
    assert!(matches!(
        db.begin_read().await,
        Err(PagedbError::DurablyCommittedButUnpublished { commit }) if commit == durable_commit
    ));
    assert!(matches!(
        db.begin_write().await,
        Err(PagedbError::DurablyCommittedButUnpublished { commit }) if commit == durable_commit
    ));
    assert!(matches!(
        db.open_segment(REALM, "replacement").await,
        Err(PagedbError::DurablyCommittedButUnpublished { commit }) if commit == durable_commit
    ));
    assert!(matches!(
        db.list_segments(REALM, "").await,
        Err(PagedbError::DurablyCommittedButUnpublished { commit }) if commit == durable_commit
    ));
    assert!(matches!(
        db.create_segment(REALM, SegmentKind::Unspecified).await,
        Err(PagedbError::DurablyCommittedButUnpublished { commit }) if commit == durable_commit
    ));
    assert!(matches!(
        db.gc_now().await,
        Err(PagedbError::DurablyCommittedButUnpublished { commit }) if commit == durable_commit
    ));
    assert!(matches!(
        db.rekey_db(KEK, 1).await,
        Err(PagedbError::DurablyCommittedButUnpublished { commit }) if commit == durable_commit
    ));
    assert!(matches!(
        db.compact_now().await,
        Err(PagedbError::DurablyCommittedButUnpublished { commit }) if commit == durable_commit
    ));
    assert!(matches!(
        db.snapshot_to(std::path::Path::new("/unused")).await,
        Err(PagedbError::DurablyCommittedButUnpublished { commit }) if commit == durable_commit
    ));
    assert!(matches!(
        run_deep_walk(&db).await,
        Err(PagedbError::DurablyCommittedButUnpublished { commit }) if commit == durable_commit
    ));
    assert_eq!(db.mode(), pagedb::DbMode::Standalone);
    assert_eq!(db.stats().await.unwrap().latest_commit_id, 0);

    vfs.fail_renames(false);
    drop(existing);
    drop(db);

    let reopened = Db::open_existing(vfs, KEK, PAGE, REALM).await.unwrap();
    let segment = reopened.open_segment(REALM, "replacement").await;
    assert!(
        segment.is_ok(),
        "reopen must reconcile the durable catalog state"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn rekey_segment_reconciliation_failure_poisoned_handle_reopens_with_readable_segment() {
    let vfs = RenameFaultVfs::new();
    let db = Db::open_internal(vfs.clone(), KEK, PAGE, REALM)
        .await
        .unwrap();
    let writer = db
        .create_segment(REALM, SegmentKind::Unspecified)
        .await
        .unwrap();
    let meta = writer.seal().await.unwrap();
    let mut txn = db.begin_write().await.unwrap();
    txn.link_segment("rekeyed", &meta).await.unwrap();
    txn.commit().await.unwrap();

    vfs.fail_renames(true);
    assert!(matches!(
        db.rekey_db(KEK, 1).await,
        Err(PagedbError::DurablyCommittedButUnpublished { .. })
    ));
    assert!(matches!(
        db.list_segments(REALM, "").await,
        Err(PagedbError::DurablyCommittedButUnpublished { .. })
    ));

    vfs.fail_renames(false);
    drop(db);
    let reopened = Db::open_existing(vfs, KEK, PAGE, REALM).await.unwrap();
    assert!(reopened.open_segment(REALM, "rekeyed").await.is_ok());
}

#[tokio::test(flavor = "current_thread")]
async fn compaction_swap_failure_poisoned_handle_reopens_at_durable_snapshot() {
    let vfs = RenameFaultVfs::new();
    let db = Db::open_internal(vfs.clone(), KEK, PAGE, REALM)
        .await
        .unwrap();
    {
        let mut txn = db.begin_write().await.unwrap();
        for i in 0u32..200 {
            let key = format!("k-{i:04}");
            txn.put(key.as_bytes(), &[0xAC; 128]).await.unwrap();
        }
        txn.commit().await.unwrap();
    }
    {
        let mut txn = db.begin_write().await.unwrap();
        for i in 0u32..190 {
            let key = format!("k-{i:04}");
            txn.delete(key.as_bytes()).await.unwrap();
        }
        txn.commit().await.unwrap();
    }

    vfs.fail_sync_dirs(true);
    assert!(matches!(
        db.compact_now().await,
        Err(PagedbError::DurablyCommittedButUnpublished { .. })
    ));
    assert!(matches!(
        db.create_segment(REALM, SegmentKind::Unspecified).await,
        Err(PagedbError::DurablyCommittedButUnpublished { .. })
    ));

    vfs.fail_sync_dirs(false);
    drop(db);
    let reopened = Db::open_existing(vfs, KEK, PAGE, REALM).await.unwrap();
    let read = reopened.begin_read().await.unwrap();
    assert_eq!(
        read.get(b"k-0199").await.unwrap().as_deref(),
        Some(&[0xAC; 128][..])
    );
}
