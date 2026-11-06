//! A full export walks the free chain while commits wait.
//!
//! `snapshot_to` takes the writer lock before it reads anything and keeps it until it returns.
//! Every commit takes the same lock in `begin_write`, so no commit runs during the walk.
//! This test parks the walk on a chain page and asserts that hold.
//! A commit that reuses the chain page during the walk is therefore not reachable.
//!
//! `GatedVfs` sits on `MemVfs`, which has no root path, and `snapshot_to` refuses such a backend.
//! This file therefore parks a read on a `TokioVfs` with the same one-shot latch shape.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use tokio::sync::Notify;

use crate::options::{OpenOptions, RetainPolicy};
use crate::pager::freelist::{CHAIN_METADATA_CID, read_chain};
use crate::vfs::gated::bounded;
use crate::vfs::tokio_backend::{TokioFile, TokioLockHandle, TokioVfs};
use crate::vfs::{OpenMode, ReadReq, Vfs, VfsFile, WriteReq};
use crate::{CommitId, Db, RealmId, run_deep_walk};

const PAGE: usize = 4096;
const KEK: [u8; 32] = [0x3E; 32];
const REALM: RealmId = RealmId::new([0x3F; 16]);
/// One overwrite frees one overflow page per row, which fills more than one chain page.
const ROWS: u32 = 400;
/// A value past the inline threshold that fits in one overflow page.
const VALUE_LEN: usize = 3000;
const DISARMED: u64 = u64::MAX;
/// Polls the queued commit gets while the walk stays parked. The walk stays parked for any count.
const QUEUE_POLLS: usize = 16;
/// Overwrites allowed before the scenario reports that no commit reused the chain page.
const MAX_REUSE_COMMITS: u8 = 8;

/// Parks one read of `main.db` at the armed offset, after it copies the bytes out.
struct ReadGate {
    armed_offset: AtomicU64,
    parked: Notify,
    released: Notify,
}

#[derive(Clone)]
struct ParkedReadVfs {
    inner: TokioVfs,
    gate: Arc<ReadGate>,
}

impl ParkedReadVfs {
    fn new(root: &Path) -> Self {
        Self {
            inner: TokioVfs::new(root),
            gate: Arc::new(ReadGate {
                armed_offset: AtomicU64::new(DISARMED),
                parked: Notify::new(),
                released: Notify::new(),
            }),
        }
    }
}

struct ParkedReadFile {
    inner: TokioFile,
    is_main_db: bool,
    gate: Arc<ReadGate>,
}

impl Vfs for ParkedReadVfs {
    type File = ParkedReadFile;
    type LockHandle = TokioLockHandle;

    async fn open(&self, path: &str, mode: OpenMode) -> crate::Result<Self::File> {
        Ok(ParkedReadFile {
            inner: self.inner.open(path, mode).await?,
            is_main_db: path.trim_start_matches('/') == "main.db",
            gate: self.gate.clone(),
        })
    }

    async fn remove(&self, path: &str) -> crate::Result<()> {
        self.inner.remove(path).await
    }

    async fn rename(&self, from: &str, to: &str) -> crate::Result<()> {
        self.inner.rename(from, to).await
    }

    async fn list_dir(&self, path: &str) -> crate::Result<Vec<String>> {
        self.inner.list_dir(path).await
    }

    async fn mkdir_all(&self, path: &str) -> crate::Result<()> {
        self.inner.mkdir_all(path).await
    }

    async fn sync_dir(&self, path: &str) -> crate::Result<()> {
        self.inner.sync_dir(path).await
    }

    async fn lock_exclusive(&self, path: &str) -> crate::Result<Self::LockHandle> {
        self.inner.lock_exclusive(path).await
    }

    async fn lock_shared(&self, path: &str) -> crate::Result<Self::LockHandle> {
        self.inner.lock_shared(path).await
    }

    fn root_path(&self) -> Option<&Path> {
        Some(self.inner.root_path())
    }
}

impl VfsFile for ParkedReadFile {
    async fn read_at(&self, offset: u64, buf: &mut [u8]) -> crate::Result<usize> {
        let read = self.inner.read_at(offset, buf).await?;
        if self.is_main_db
            && self
                .gate
                .armed_offset
                .compare_exchange(offset, DISARMED, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
        {
            self.gate.parked.notify_one();
            self.gate.released.notified().await;
        }
        Ok(read)
    }

    async fn read_at_vectored(&self, reqs: &mut [ReadReq<'_>]) -> crate::Result<()> {
        self.inner.read_at_vectored(reqs).await
    }

    async fn write_at(&mut self, offset: u64, buf: &[u8]) -> crate::Result<usize> {
        self.inner.write_at(offset, buf).await
    }

    async fn write_at_vectored(&mut self, reqs: &[WriteReq<'_>]) -> crate::Result<()> {
        self.inner.write_at_vectored(reqs).await
    }

    async fn sync(&mut self) -> crate::Result<()> {
        self.inner.sync().await
    }

    async fn truncate(&mut self, len: u64) -> crate::Result<()> {
        self.inner.truncate(len).await
    }

    async fn len(&self) -> crate::Result<u64> {
        self.inner.len().await
    }

    async fn is_empty(&self) -> crate::Result<bool> {
        self.inner.is_empty().await
    }

    fn supports_direct_io(&self) -> bool {
        self.inner.supports_direct_io()
    }
}

fn options() -> OpenOptions {
    OpenOptions::default().with_commit_history_retain(RetainPolicy::Count(2))
}

fn row_key(row: u32) -> Vec<u8> {
    format!("row-{row:05}").into_bytes()
}

fn row_value(row: u32, generation: u8) -> Vec<u8> {
    let mut value = vec![generation; VALUE_LEN];
    value[..4].copy_from_slice(&row.to_le_bytes());
    value
}

async fn overwrite_every_row<V: Vfs + Clone>(db: &Db<V>, generation: u8) -> CommitId {
    let mut txn = db.begin_write().await.unwrap();
    for row in 0..ROWS {
        txn.put(&row_key(row), &row_value(row, generation))
            .await
            .unwrap();
    }
    txn.commit().await.unwrap()
}

async fn free_chain_of<V: Vfs + Clone>(db: &Db<V>) -> (Vec<(u64, u64)>, Vec<u64>) {
    let head = db.writer.lock().await.free_list_root_page_id;
    read_chain(&db.pager, REALM, head).await.unwrap()
}

/// An open detaches a chain with a torn page, in memory only, so its header still
/// names that chain. The export must neither read the torn page nor name the chain.
#[tokio::test(flavor = "current_thread")]
async fn export_after_a_detached_chain_skips_the_torn_page_and_restores_without_the_chain() {
    for torn_index in [0_usize, 1] {
        let dir = tempfile::tempdir().unwrap();
        let snapshot_dir = dir.path().join("snapshot");
        let restored_dir = dir.path().join("restored");
        let vfs = ParkedReadVfs::new(&dir.path().join("source"));
        let gate = vfs.gate.clone();
        let db = Db::open(vfs.clone(), KEK, PAGE, REALM, options())
            .await
            .unwrap();
        overwrite_every_row(&db, 0).await;
        let target = overwrite_every_row(&db, 1).await;
        let (_entries, chain_pages) = free_chain_of(&db).await;
        assert!(
            chain_pages.len() >= 2,
            "setup error: the free chain has {} pages",
            chain_pages.len()
        );
        let torn_offset = chain_pages[torn_index] * PAGE as u64;
        drop(db);

        let mut file = vfs.open("/main.db", OpenMode::ReadWrite).await.unwrap();
        file.write_at(torn_offset + (PAGE / 2) as u64, &[0xEE; PAGE / 2])
            .await
            .unwrap();
        file.sync().await.unwrap();
        drop(file);

        let db = Db::open(vfs, KEK, PAGE, REALM, options()).await.unwrap();
        assert_eq!(db.latest_commit(), target);
        // The open read the torn page to detach the chain. Only later reads count.
        gate.armed_offset.store(torn_offset, Ordering::SeqCst);
        let exported = tokio::select! {
            outcome = db.snapshot_to(&snapshot_dir) => outcome,
            () = gate.parked.notified() => {
                panic!("chain page {torn_index}: the export read the torn page");
            }
        };
        exported.expect("the export ignores a detached chain");

        let restored = Db::<TokioVfs>::restore_from(&snapshot_dir, &restored_dir, options(), KEK)
            .await
            .expect("the exported image restores");
        assert_eq!(restored.latest_commit(), target);
        let (entries, restored_chain_pages) = free_chain_of(&restored).await;
        assert!(
            entries.is_empty() && restored_chain_pages.is_empty(),
            "chain page {torn_index}: the exported header still names a chain"
        );
        assert_eq!(restored.stats().await.unwrap().free_list_pending_entries, 0);
        let reader = restored.begin_read().await.unwrap();
        for row in 0..ROWS {
            assert_eq!(
                reader.get(&row_key(row)).await.unwrap().as_deref(),
                Some(row_value(row, 1).as_slice()),
                "row {row} has the wrong value in the restored copy"
            );
        }
    }
}

/// The walk parks on the free-chain head, and a commit queues behind the export.
/// The export succeeds, and the restored copy holds the target values and the same chain.
/// Later commits reuse that chain page, so the writer hold is what protects the walk.
#[tokio::test(flavor = "current_thread")]
async fn export_during_commits_reads_a_consistent_free_chain() {
    let dir = tempfile::tempdir().unwrap();
    let snapshot_dir = dir.path().join("snapshot");
    let restored_dir = dir.path().join("restored");
    let vfs = ParkedReadVfs::new(&dir.path().join("source"));
    let gate = vfs.gate.clone();
    let db = Db::open(vfs, KEK, PAGE, REALM, options()).await.unwrap();

    overwrite_every_row(&db, 0).await;
    let target = overwrite_every_row(&db, 1).await;
    let (target_entries, target_chain_pages) = free_chain_of(&db).await;
    assert!(
        target_chain_pages.len() >= 2,
        "setup error: the free chain has {} pages, so the walk has no later link",
        target_chain_pages.len()
    );
    let chain_head = target_chain_pages[0];

    // The walk reads the head from the file only when the cache does not hold it.
    db.pager.evict_clean_main_pages().unwrap();
    gate.armed_offset
        .store(chain_head * PAGE as u64, Ordering::SeqCst);

    let export_finished = Notify::new();
    let commit_may_start = Notify::new();
    let commit_finished = AtomicBool::new(false);
    let export = async {
        let outcome = db.snapshot_to(&snapshot_dir).await;
        export_finished.notify_one();
        outcome
    };
    let queued_commit = async {
        commit_may_start.notified().await;
        let commit = overwrite_every_row(&db, 2).await;
        commit_finished.store(true, Ordering::SeqCst);
        commit
    };
    let driver = async {
        tokio::select! {
            () = gate.parked.notified() => {}
            () = export_finished.notified() => {
                panic!("setup error: the export never read free-chain head {chain_head} from the file");
            }
        }
        // A free writer lock here makes chain reuse during the walk reachable.
        assert!(
            db.writer.try_lock().is_err(),
            "the export released the writer lock during its free-chain walk"
        );
        commit_may_start.notify_one();
        for _ in 0..QUEUE_POLLS {
            tokio::task::yield_now().await;
        }
        assert!(
            !commit_finished.load(Ordering::SeqCst),
            "a commit finished during the free-chain walk"
        );
        assert_eq!(
            db.latest_commit(),
            target,
            "a commit published during the free-chain walk"
        );
        gate.released.notify_one();
    };
    let (exported, queued_commit_id, ()) =
        bounded(async { tokio::join!(export, queued_commit, driver) }).await;
    exported.expect("the export succeeds with a commit queued behind it");
    assert!(queued_commit_id > target);

    let restored = Db::<TokioVfs>::restore_from(&snapshot_dir, &restored_dir, options(), KEK)
        .await
        .expect("the exported image restores");
    assert_eq!(restored.latest_commit(), target);
    {
        let reader = restored.begin_read().await.unwrap();
        for row in 0..ROWS {
            assert_eq!(
                reader.get(&row_key(row)).await.unwrap().as_deref(),
                Some(row_value(row, 1).as_slice()),
                "row {row} has the wrong value in the restored copy"
            );
        }
    }
    let (restored_entries, restored_chain_pages) = free_chain_of(&restored).await;
    assert_eq!(restored_entries, target_entries);
    assert_eq!(restored_chain_pages, target_chain_pages);
    let report = run_deep_walk(&restored).await.unwrap();
    assert!(report.is_clean(), "deep walk report: {report:?}");

    // A superseded chain page carries the sentinel tag until a commit draws it.
    let mut superseded = free_chain_of(&db)
        .await
        .0
        .contains(&(CHAIN_METADATA_CID, chain_head));
    let mut reused = false;
    for offset in 0..MAX_REUSE_COMMITS {
        overwrite_every_row(&db, 3 + offset).await;
        let tagged = free_chain_of(&db)
            .await
            .0
            .contains(&(CHAIN_METADATA_CID, chain_head));
        if superseded && !tagged {
            reused = true;
            break;
        }
        superseded |= tagged;
    }
    assert!(
        reused,
        "setup error: no commit reused free-chain head {chain_head}, so nothing threatened the walk"
    );
}
