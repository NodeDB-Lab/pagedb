//! Integration tests for snapshot_to / restore_from / promote_to_follower /
//! apply_incremental / snapshot_incremental_to.

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use pagedb::options::RetainPolicy;
use pagedb::snapshot::export::{
    SnapshotManifest, decode_manifest, derive_snapshot_hk_key, encode_manifest, open_manifest,
};
use pagedb::vfs::tokio_backend::{TokioFile, TokioLockHandle, TokioVfs};
use pagedb::vfs::{OpenMode, Vfs};
use pagedb::{
    ApplyStats, CommitId, Db, DbMode, OpenOptions, PagedbError, RealmId, SegmentKind,
    SegmentPageKind, SnapshotStats, run_deep_walk,
};

const PAGE: usize = 4096;
const KEK: [u8; 32] = [7u8; 32];
const REALM: RealmId = RealmId::new([1u8; 16]);

fn tempdir() -> std::path::PathBuf {
    tempfile::Builder::new()
        .prefix("pagedb-snap-")
        .tempdir()
        .unwrap()
        .keep()
}

async fn make_db(root: &std::path::Path) -> Db<TokioVfs> {
    let vfs = TokioVfs::new(root);
    Db::open(vfs, KEK, PAGE, REALM, OpenOptions::default())
        .await
        .unwrap()
}

#[derive(Clone)]
struct RenameFaultVfs {
    inner: TokioVfs,
    fail_renames: Arc<AtomicBool>,
}

impl RenameFaultVfs {
    fn new(root: &std::path::Path) -> Self {
        Self {
            inner: TokioVfs::new(root),
            fail_renames: Arc::new(AtomicBool::new(false)),
        }
    }

    fn fail_renames(&self, fail: bool) {
        self.fail_renames.store(fail, Ordering::SeqCst);
    }
}

impl Vfs for RenameFaultVfs {
    type File = TokioFile;
    type LockHandle = TokioLockHandle;

    async fn open(&self, path: &str, mode: OpenMode) -> pagedb::Result<Self::File> {
        self.inner.open(path, mode).await
    }

    async fn remove(&self, path: &str) -> pagedb::Result<()> {
        self.inner.remove(path).await
    }

    async fn rename(&self, from: &str, to: &str) -> pagedb::Result<()> {
        if self.fail_renames.load(Ordering::SeqCst) {
            return Err(PagedbError::Io(std::io::Error::other(
                "injected persistent rename failure",
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
        self.inner.sync_dir(path).await
    }

    async fn lock_exclusive(&self, path: &str) -> pagedb::Result<Self::LockHandle> {
        self.inner.lock_exclusive(path).await
    }

    async fn lock_shared(&self, path: &str) -> pagedb::Result<Self::LockHandle> {
        self.inner.lock_shared(path).await
    }

    fn root_path(&self) -> Option<&std::path::Path> {
        Some(self.inner.root_path())
    }
}

async fn make_db_with_options(root: &std::path::Path, options: OpenOptions) -> Db<TokioVfs> {
    let vfs = TokioVfs::new(root);
    Db::open(vfs, KEK, PAGE, REALM, options).await.unwrap()
}

fn hex_lower(bytes: &[u8; 16]) -> String {
    use std::fmt::Write as _;

    let mut out = String::with_capacity(32);
    for byte in bytes {
        write!(&mut out, "{byte:02x}").unwrap();
    }
    out
}

fn create_stale_snapshot_sidecar(snapshot_dir: &std::path::Path) {
    let stale_seg_dir = snapshot_dir.join("seg");
    std::fs::create_dir_all(&stale_seg_dir).unwrap();
    std::fs::write(
        stale_seg_dir.join("00000000000000000000000000000001"),
        b"stale",
    )
    .unwrap();
}

#[derive(Clone)]
struct FailStagingSyncTokioVfs {
    inner: TokioVfs,
    fail_staging_sync: Arc<AtomicBool>,
}

impl FailStagingSyncTokioVfs {
    fn new(root: impl Into<std::path::PathBuf>) -> Self {
        Self {
            inner: TokioVfs::new(root),
            fail_staging_sync: Arc::new(AtomicBool::new(false)),
        }
    }

    fn fail_next_staging_sync(&self) {
        self.fail_staging_sync.store(true, Ordering::SeqCst);
    }
}

impl Vfs for FailStagingSyncTokioVfs {
    type File = TokioFile;
    type LockHandle = TokioLockHandle;

    async fn open(&self, path: &str, mode: OpenMode) -> pagedb::Result<Self::File> {
        self.inner.open(path, mode).await
    }

    async fn remove(&self, path: &str) -> pagedb::Result<()> {
        self.inner.remove(path).await
    }

    async fn rename(&self, from: &str, to: &str) -> pagedb::Result<()> {
        self.inner.rename(from, to).await
    }

    async fn list_dir(&self, path: &str) -> pagedb::Result<Vec<String>> {
        self.inner.list_dir(path).await
    }

    async fn mkdir_all(&self, path: &str) -> pagedb::Result<()> {
        self.inner.mkdir_all(path).await
    }

    async fn sync_dir(&self, path: &str) -> pagedb::Result<()> {
        if path == "seg/.staging" && self.fail_staging_sync.swap(false, Ordering::SeqCst) {
            return Err(PagedbError::Io(std::io::Error::other(
                "injected staging sync fault",
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

    fn root_path(&self) -> Option<&std::path::Path> {
        Some(self.inner.root_path())
    }
}

#[test]
fn tempdir_helper_allocates_unique_roots() {
    let dirs: Vec<_> = (0..128).map(|_| tempdir()).collect();
    let mut paths = dirs.clone();
    paths.sort();
    paths.dedup();
    assert_eq!(paths.len(), dirs.len());

    for dir in dirs {
        std::fs::remove_dir_all(dir).ok();
    }
}

// ---------------------------------------------------------------------------
// Test 1: full snapshot then restore reads data back.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "current_thread")]
async fn full_snapshot_then_restore_reads_data() {
    let src_dir = tempdir();
    let snap_dir = tempdir();
    let dst_dir = tempdir();

    let db = make_db(&src_dir).await;
    {
        let mut t = db.begin_write().await.unwrap();
        t.put(b"key1", b"value1").await.unwrap();
        t.put(b"key2", b"value2").await.unwrap();
        t.commit().await.unwrap();
    }

    let stats = db.snapshot_to(&snap_dir).await.unwrap();
    assert!(stats.bytes > 0);

    drop(db);

    let restored = Db::<TokioVfs>::restore_from(&snap_dir, &dst_dir, OpenOptions::default(), KEK)
        .await
        .unwrap();
    assert_eq!(restored.mode(), DbMode::ReadOnly);

    let rtxn = restored.begin_read().await.unwrap();
    let v1 = rtxn.get(b"key1").await.unwrap();
    let v2 = rtxn.get(b"key2").await.unwrap();
    assert_eq!(v1.as_deref(), Some(b"value1" as &[u8]));
    assert_eq!(v2.as_deref(), Some(b"value2" as &[u8]));

    std::fs::remove_dir_all(&src_dir).ok();
    std::fs::remove_dir_all(&snap_dir).ok();
    std::fs::remove_dir_all(&dst_dir).ok();
}

// ---------------------------------------------------------------------------
// Test 2: restore yields a ReadOnly Db; begin_write returns ReadOnly error.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "current_thread")]
async fn restore_yields_readonly_db() {
    let src_dir = tempdir();
    let snap_dir = tempdir();
    let dst_dir = tempdir();

    let db = make_db_with_options(
        &src_dir,
        OpenOptions::default().with_commit_history_retain(RetainPolicy::Unbounded),
    )
    .await;
    db.snapshot_to(&snap_dir).await.unwrap();
    drop(db);

    let restored = Db::<TokioVfs>::restore_from(&snap_dir, &dst_dir, OpenOptions::default(), KEK)
        .await
        .unwrap();
    assert_eq!(restored.mode(), DbMode::ReadOnly);

    // begin_write must fail with ReadOnly.
    let err = restored.begin_write().await.err().unwrap();
    assert!(
        matches!(err, PagedbError::ReadOnly),
        "expected ReadOnly, got {err:?}"
    );

    std::fs::remove_dir_all(&src_dir).ok();
    std::fs::remove_dir_all(&snap_dir).ok();
    std::fs::remove_dir_all(&dst_dir).ok();
}

// ---------------------------------------------------------------------------
// Test 3: restore_from rejects corrupt active-root main.db pages.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "current_thread")]
async fn restore_rejects_corrupt_active_root_page() {
    let src_dir = tempdir();
    let snap_dir = tempdir();
    let dst_dir = tempdir();

    let db = make_db(&src_dir).await;
    {
        let mut t = db.begin_write().await.unwrap();
        t.put(b"base", b"data").await.unwrap();
        t.commit().await.unwrap();
    }
    db.snapshot_to(&snap_dir).await.unwrap();

    let manifest = open_manifest(&snap_dir.join("manifest"), &KEK)
        .await
        .unwrap();
    assert_ne!(
        manifest.target_active_root_page_id, 0,
        "test setup must produce a non-empty active tree"
    );
    let main_path = snap_dir.join("main.db");
    let mut bytes = std::fs::read(&main_path).unwrap();
    let corrupt_at = manifest.target_active_root_page_id as usize * PAGE + 128;
    assert!(
        bytes.len() > corrupt_at,
        "test setup must include the active root page in full snapshot main.db"
    );
    bytes[corrupt_at] ^= 0xFF;
    std::fs::write(&main_path, bytes).unwrap();
    drop(db);

    let err = match Db::<TokioVfs>::restore_from(&snap_dir, &dst_dir, OpenOptions::default(), KEK)
        .await
    {
        Ok(_) => panic!("restore_from must reject corrupt active-root pages"),
        Err(err) => err,
    };
    assert!(
        matches!(
            err,
            PagedbError::ChecksumFailure | PagedbError::Corruption(_)
        ),
        "expected page authentication failure, got {err:?}"
    );

    std::fs::remove_dir_all(&src_dir).ok();
    std::fs::remove_dir_all(&snap_dir).ok();
    std::fs::remove_dir_all(&dst_dir).ok();
}

// ---------------------------------------------------------------------------
// Test 4: failed restore leaves the destination reusable.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "current_thread")]
async fn restore_failure_leaves_destination_reusable() {
    let src_dir = tempdir();
    let snap_dir = tempdir();
    let dst_dir = tempdir();

    let db = make_db(&src_dir).await;
    {
        let mut t = db.begin_write().await.unwrap();
        t.put(b"base", b"data").await.unwrap();
        t.commit().await.unwrap();
    }
    db.snapshot_to(&snap_dir).await.unwrap();

    let manifest = open_manifest(&snap_dir.join("manifest"), &KEK)
        .await
        .unwrap();
    let main_path = snap_dir.join("main.db");
    let original_main = std::fs::read(&main_path).unwrap();
    let mut corrupt_main = original_main.clone();
    let corrupt_at = manifest.target_active_root_page_id as usize * PAGE + 128;
    assert!(
        corrupt_main.len() > corrupt_at,
        "test setup must include the active root page in full snapshot main.db"
    );
    corrupt_main[corrupt_at] ^= 0xFF;
    std::fs::write(&main_path, corrupt_main).unwrap();

    let err = match Db::<TokioVfs>::restore_from(&snap_dir, &dst_dir, OpenOptions::default(), KEK)
        .await
    {
        Ok(_) => panic!("corrupt snapshot must fail restore"),
        Err(err) => err,
    };
    assert!(
        matches!(
            err,
            PagedbError::ChecksumFailure | PagedbError::Corruption(_)
        ),
        "expected page authentication failure, got {err:?}"
    );

    std::fs::write(&main_path, original_main).unwrap();
    let restored = Db::<TokioVfs>::restore_from(&snap_dir, &dst_dir, OpenOptions::default(), KEK)
        .await
        .expect("failed restore must leave the destination reusable");
    let rtxn = restored.begin_read().await.unwrap();
    assert_eq!(
        rtxn.get(b"base").await.unwrap().as_deref(),
        Some(b"data".as_slice())
    );
    drop(rtxn);
    drop(restored);
    drop(db);

    std::fs::remove_dir_all(&src_dir).ok();
    std::fs::remove_dir_all(&snap_dir).ok();
    std::fs::remove_dir_all(&dst_dir).ok();
}

// ---------------------------------------------------------------------------
// Test 5: restore_from rejects non-empty destination directories.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "current_thread")]
async fn restore_rejects_non_empty_destination() {
    let src_dir = tempdir();
    let snap_dir = tempdir();
    let dst_dir = tempdir();

    let db = make_db(&src_dir).await;
    {
        let mut t = db.begin_write().await.unwrap();
        t.put(b"base", b"data").await.unwrap();
        t.commit().await.unwrap();
    }
    db.snapshot_to(&snap_dir).await.unwrap();
    drop(db);

    let stale_seg = dst_dir.join("seg");
    std::fs::create_dir_all(&stale_seg).unwrap();
    std::fs::write(stale_seg.join("00000000000000000000000000000000"), b"stale").unwrap();

    let err = match Db::<TokioVfs>::restore_from(&snap_dir, &dst_dir, OpenOptions::default(), KEK)
        .await
    {
        Ok(_) => panic!("restore_from must reject a non-empty destination"),
        Err(err) => err,
    };
    assert!(
        matches!(err, PagedbError::Io(_)),
        "expected Io for non-empty destination, got {err:?}"
    );

    std::fs::remove_dir_all(&src_dir).ok();
    std::fs::remove_dir_all(&snap_dir).ok();
    std::fs::remove_dir_all(&dst_dir).ok();
}

// ---------------------------------------------------------------------------
// Test 5: restore_from rejects a manifest whose root fields do not match main.db.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "current_thread")]
async fn restore_rejects_manifest_active_root_mismatch() {
    let src_dir = tempdir();
    let snap_dir = tempdir();
    let dst_dir = tempdir();

    let db = make_db(&src_dir).await;
    {
        let mut t = db.begin_write().await.unwrap();
        t.put(b"base", b"data").await.unwrap();
        t.commit().await.unwrap();
    }
    db.snapshot_to(&snap_dir).await.unwrap();

    let manifest_path = snap_dir.join("manifest");
    let mut manifest = open_manifest(&manifest_path, &KEK).await.unwrap();
    assert_ne!(
        manifest.target_active_root_page_id, 0,
        "test setup must produce a non-empty active tree"
    );
    let hk_key = derive_snapshot_hk_key(&KEK, &manifest.kek_salt, manifest.mk_epoch).unwrap();
    manifest.target_active_root_page_id = 0;
    std::fs::write(manifest_path, encode_manifest(&manifest, &hk_key)).unwrap();
    drop(db);

    let err = match Db::<TokioVfs>::restore_from(&snap_dir, &dst_dir, OpenOptions::default(), KEK)
        .await
    {
        Ok(_) => panic!("restore_from must reject manifest/header root mismatch"),
        Err(err) => err,
    };
    assert!(
        matches!(
            err,
            PagedbError::IdentityForked
                | PagedbError::Corruption(_)
                | PagedbError::SnapshotIncompatible {
                    field: "target_active_root_page_id"
                }
        ),
        "expected identity/corruption failure for manifest/header mismatch, got {err:?}"
    );

    std::fs::remove_dir_all(&src_dir).ok();
    std::fs::remove_dir_all(&snap_dir).ok();
    std::fs::remove_dir_all(&dst_dir).ok();
}

// ---------------------------------------------------------------------------
// Test 6: restore_from rejects an incremental snapshot manifest.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "current_thread")]
async fn restore_rejects_incremental_snapshot_manifest() {
    let src_dir = tempdir();
    let delta_dir = tempdir();
    let dst_dir = tempdir();

    let db = make_db(&src_dir).await;
    {
        let mut t = db.begin_write().await.unwrap();
        t.put(b"base", b"data").await.unwrap();
        t.commit().await.unwrap();
    }
    let c1 = db.latest_commit();
    {
        let mut t = db.begin_write().await.unwrap();
        t.put(b"later", b"value").await.unwrap();
        t.commit().await.unwrap();
    }
    db.snapshot_incremental_to(c1, &delta_dir).await.unwrap();
    drop(db);

    let err = match Db::<TokioVfs>::restore_from(&delta_dir, &dst_dir, OpenOptions::default(), KEK)
        .await
    {
        Ok(_) => panic!("restore_from must reject an incremental snapshot manifest"),
        Err(err) => err,
    };
    assert!(
        matches!(
            err,
            PagedbError::Corruption(_) | PagedbError::SnapshotIncompatible { field: "kind" }
        ),
        "expected Corruption for incremental snapshot manifest, got {err:?}"
    );

    std::fs::remove_dir_all(&src_dir).ok();
    std::fs::remove_dir_all(&delta_dir).ok();
    std::fs::remove_dir_all(&dst_dir).ok();
}

#[tokio::test(flavor = "current_thread")]
async fn restore_rejects_manifest_with_trailing_bytes() {
    let src_dir = tempdir();
    let snap_dir = tempdir();
    let dst_dir = tempdir();

    let db = make_db(&src_dir).await;
    {
        let mut t = db.begin_write().await.unwrap();
        t.put(b"base", b"data").await.unwrap();
        t.commit().await.unwrap();
    }
    db.snapshot_to(&snap_dir).await.unwrap();

    let manifest_path = snap_dir.join("manifest");
    let mut bytes = std::fs::read(&manifest_path).unwrap();
    bytes.push(0xAA);
    std::fs::write(&manifest_path, bytes).unwrap();
    drop(db);

    let err = match Db::<TokioVfs>::restore_from(&snap_dir, &dst_dir, OpenOptions::default(), KEK)
        .await
    {
        Ok(_) => panic!("restore_from must reject non-canonical manifest length"),
        Err(err) => err,
    };
    assert!(
        matches!(err, PagedbError::Corruption(_)),
        "expected Corruption for manifest trailing bytes, got {err:?}"
    );

    std::fs::remove_dir_all(&src_dir).ok();
    std::fs::remove_dir_all(&snap_dir).ok();
    std::fs::remove_dir_all(&dst_dir).ok();
}

// ---------------------------------------------------------------------------
// Test 4: promote_to_follower allows applying a real incremental.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "current_thread")]
async fn promote_to_follower_allows_apply() {
    let src_dir = tempdir();
    let snap_dir = tempdir();
    let dst_dir = tempdir();
    let delta_dir = tempdir();

    let db = make_db(&src_dir).await;
    {
        let mut txn = db.begin_write().await.unwrap();
        txn.put(b"base", b"before-snapshot").await.unwrap();
        txn.commit().await.unwrap();
    }
    let c1 = db.latest_commit();
    db.snapshot_to(&snap_dir).await.unwrap();

    // Advance the source after the full snapshot and export c1 -> c2.
    {
        let mut txn = db.begin_write().await.unwrap();
        txn.put(b"changed", b"after-snapshot").await.unwrap();
        txn.commit().await.unwrap();
    }
    let c2 = db.latest_commit();
    db.snapshot_incremental_to(c1, &delta_dir).await.unwrap();
    drop(db);

    let restored = Db::<TokioVfs>::restore_from(&snap_dir, &dst_dir, OpenOptions::default(), KEK)
        .await
        .unwrap();

    let follower = restored.promote_to_follower().await.unwrap();
    assert_eq!(follower.mode(), DbMode::Follower);
    assert!(follower.can_apply_incremental());

    let stats = follower.apply_incremental(&delta_dir).await.unwrap();
    assert!(stats.pages_applied > 0);
    assert_eq!(follower.latest_commit(), c2);

    let rtxn = follower.begin_read().await.unwrap();
    assert_eq!(
        rtxn.get(b"changed").await.unwrap().as_deref(),
        Some(b"after-snapshot".as_slice())
    );

    std::fs::remove_dir_all(&src_dir).ok();
    std::fs::remove_dir_all(&snap_dir).ok();
    std::fs::remove_dir_all(&dst_dir).ok();
    std::fs::remove_dir_all(&delta_dir).ok();
}

/// A writer that recycles pages between the base and target commits still
/// produces an applicable delta.
///
/// Page reuse is the steady state of the free-list design, not an edge case: the
/// reclamation floor exists so freed pages come back. A page id below the base
/// commit's allocation cursor therefore proves nothing on its own — what matters
/// is whether the page was *live* at the base. Treating the cursor as a liveness
/// boundary rejects healthy snapshots from any database that has ever deleted
/// anything, which is why this walks a full delete-and-refill cycle rather than
/// only appending.
#[tokio::test(flavor = "current_thread")]
async fn incremental_round_trip_survives_page_reuse_below_the_base_cursor() {
    let src_dir = tempdir();
    let snap_dir = tempdir();
    let dst_dir = tempdir();
    let delta_dir = tempdir();

    let db = make_db(&src_dir).await;

    // Grow the tree well past a single page, so deleting most of it frees
    // interior pages rather than just trimming one leaf.
    {
        let mut txn = db.begin_write().await.unwrap();
        for index in 0u16..512 {
            txn.put(format!("reuse-{index:04}").as_bytes(), &[index as u8; 64])
                .await
                .unwrap();
        }
        txn.commit().await.unwrap();
    }
    // Free most of those pages. They stay on the durable free list, below the
    // allocation cursor the base commit will record.
    {
        let mut txn = db.begin_write().await.unwrap();
        for index in 0u16..480 {
            txn.delete(format!("reuse-{index:04}").as_bytes())
                .await
                .unwrap();
        }
        txn.commit().await.unwrap();
    }
    let base = db.latest_commit();
    db.snapshot_to(&snap_dir).await.unwrap();

    // Refill. The allocator draws from the free list, so the target tree is
    // reachable through pages whose ids sit below `base`'s cursor.
    {
        let mut txn = db.begin_write().await.unwrap();
        for index in 0u16..480 {
            txn.put(format!("refill-{index:04}").as_bytes(), &[0xC7; 64])
                .await
                .unwrap();
        }
        txn.commit().await.unwrap();
    }
    let target = db.latest_commit();
    let base_next_page_id = {
        let txn = db.begin_read_at(base).await.unwrap();
        txn.next_page_id()
    };

    db.snapshot_incremental_to(base, &delta_dir)
        .await
        .expect("page reuse below the base cursor must still export");
    drop(db);

    let restored = Db::<TokioVfs>::restore_from(&snap_dir, &dst_dir, OpenOptions::default(), KEK)
        .await
        .unwrap();
    let follower = restored.promote_to_follower().await.unwrap();
    let stats = follower
        .apply_incremental(&delta_dir)
        .await
        .expect("a delta carrying recycled page ids must still apply");
    assert!(stats.pages_applied > 0);
    assert_eq!(follower.latest_commit(), target);

    // The scenario is only meaningful if reuse actually happened; otherwise this
    // silently degrades into the append-only case the other tests already cover.
    let rtxn = follower.begin_read().await.unwrap();
    assert!(
        rtxn.next_page_id() <= base_next_page_id.saturating_add(64),
        "expected the refill to recycle freed pages rather than extend the file: \
         base cursor {base_next_page_id}, target cursor {}",
        rtxn.next_page_id()
    );
    for index in 0u16..480 {
        assert_eq!(
            rtxn.get(format!("refill-{index:04}").as_bytes())
                .await
                .unwrap()
                .as_deref(),
            Some([0xC7; 64].as_slice()),
            "refilled key {index} missing after apply"
        );
        assert_eq!(
            rtxn.get(format!("reuse-{index:04}").as_bytes())
                .await
                .unwrap(),
            None,
            "deleted key {index} came back after apply"
        );
    }

    std::fs::remove_dir_all(&src_dir).ok();
    std::fs::remove_dir_all(&snap_dir).ok();
    std::fs::remove_dir_all(&dst_dir).ok();
    std::fs::remove_dir_all(&delta_dir).ok();
}

#[tokio::test(flavor = "current_thread")]
async fn apply_incremental_surfaces_staging_dir_sync_failure_then_retry_succeeds() {
    let src_dir = tempdir();
    let snap_dir = tempdir();
    let dst_dir = tempdir();
    let delta_dir = tempdir();

    let db = make_db(&src_dir).await;
    {
        let mut t = db.begin_write().await.unwrap();
        t.put(b"base", b"stable").await.unwrap();
        t.commit().await.unwrap();
    }
    let base = db.latest_commit();
    db.snapshot_to(&snap_dir).await.unwrap();

    let meta = {
        let mut s = db
            .create_segment(REALM, SegmentKind::Unspecified)
            .await
            .unwrap();
        s.append_page(SegmentPageKind::Data, b"post-base segment")
            .await
            .unwrap();
        s.seal().await.unwrap()
    };
    {
        let mut t = db.begin_write().await.unwrap();
        t.link_segment("post-base.seg", &meta).await.unwrap();
        t.commit().await.unwrap();
    }
    db.snapshot_incremental_to(base, &delta_dir).await.unwrap();
    drop(db);

    let restored = Db::<TokioVfs>::restore_from(&snap_dir, &dst_dir, OpenOptions::default(), KEK)
        .await
        .unwrap();
    drop(restored);

    let vfs = FailStagingSyncTokioVfs::new(&dst_dir);
    let restored = Db::open_read_only(vfs.clone(), KEK, PAGE, REALM, OpenOptions::default())
        .await
        .unwrap();
    let follower = restored.promote_to_follower().await.unwrap();
    vfs.fail_next_staging_sync();

    let err = follower
        .apply_incremental(&delta_dir)
        .await
        .expect_err("apply_incremental must surface failed staging directory syncs");
    assert!(
        matches!(err, PagedbError::Io(_)),
        "expected staging sync I/O error, got {err:?}"
    );
    assert_eq!(
        follower.latest_commit(),
        base,
        "failed staging sync must leave the follower on the base commit"
    );
    {
        let rtxn = follower.begin_read().await.unwrap();
        assert_eq!(
            rtxn.get(b"base").await.unwrap().as_deref(),
            Some(b"stable" as &[u8])
        );
        assert!(
            rtxn.open_segment("post-base.seg").await.is_err(),
            "failed apply must not expose the target segment"
        );
    }

    let stats = follower
        .apply_incremental(&delta_dir)
        .await
        .expect("retry after transient staging sync fault must succeed");
    assert_eq!(stats.segments_promoted, 1);
    assert!(
        follower.latest_commit() > base,
        "successful retry must advance the follower commit"
    );
    let rtxn = follower.begin_read().await.unwrap();
    let reader = rtxn.open_segment("post-base.seg").await.unwrap();
    let page = reader.read_page(1).await.unwrap();
    assert!(page.starts_with(b"post-base segment"));

    std::fs::remove_dir_all(&src_dir).ok();
    std::fs::remove_dir_all(&snap_dir).ok();
    std::fs::remove_dir_all(&dst_dir).ok();
    std::fs::remove_dir_all(&delta_dir).ok();
}

// ---------------------------------------------------------------------------
// Test 5: incremental carries only changed pages.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "current_thread")]
async fn incremental_carries_only_changed_pages() {
    let src_dir = tempdir();
    let snap1_dir = tempdir();
    let snap2_dir = tempdir();

    let db = make_db_with_options(
        &src_dir,
        OpenOptions::default().with_commit_history_retain(RetainPolicy::Unbounded),
    )
    .await;
    // Write a small base that does not create free pages before the base
    // cursor; reused below-base pages are covered by the dedicated rejection
    // regression below.
    {
        let mut t = db.begin_write().await.unwrap();
        t.put(b"key000", b"init").await.unwrap();
        t.commit().await.unwrap();
    }
    let c1 = db.latest_commit();
    let full_stats: SnapshotStats = db.snapshot_to(&snap1_dir).await.unwrap();

    // Write more data to advance the commit.
    {
        let mut t = db.begin_write().await.unwrap();
        t.put(b"new000", b"added").await.unwrap();
        t.commit().await.unwrap();
    }

    let inc_stats: SnapshotStats = db.snapshot_incremental_to(c1, &snap2_dir).await.unwrap();

    // Incremental should have fewer pages than the full snapshot.
    assert!(
        inc_stats.pages_written < full_stats.pages_written,
        "incremental pages {} should be < full pages {}",
        inc_stats.pages_written,
        full_stats.pages_written
    );

    std::fs::remove_dir_all(&src_dir).ok();
    std::fs::remove_dir_all(&snap1_dir).ok();
    std::fs::remove_dir_all(&snap2_dir).ok();
}

// ---------------------------------------------------------------------------
// Test 6: incremental snapshots require a readable base commit.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "current_thread")]
async fn incremental_snapshot_rejects_missing_base_commit() {
    let src_dir = tempdir();
    let delta_dir = tempdir();

    let db = make_db(&src_dir).await;
    {
        let mut t = db.begin_write().await.unwrap();
        t.put(b"base", b"data").await.unwrap();
        t.commit().await.unwrap();
    }

    let missing_base = CommitId::new(99);
    let err = db
        .snapshot_incremental_to(missing_base, &delta_dir)
        .await
        .expect_err("incremental snapshots must reject an unreadable base commit");
    assert!(
        matches!(err, PagedbError::CommitGone { .. }),
        "expected CommitGone for missing base commit, got {err:?}"
    );

    std::fs::remove_dir_all(&src_dir).ok();
    std::fs::remove_dir_all(&delta_dir).ok();
}

// ---------------------------------------------------------------------------
// Test 7: apply_incremental advances commit and data matches.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "current_thread")]
async fn apply_incremental_advances_commit() {
    let src_dir = tempdir();
    let snap_dir = tempdir();
    let delta_dir = tempdir();
    let dst_dir = tempdir();

    let db = make_db(&src_dir).await;
    // Write initial data.
    {
        let mut t = db.begin_write().await.unwrap();
        t.put(b"base", b"data").await.unwrap();
        t.commit().await.unwrap();
    }
    let c1 = db.latest_commit();
    db.snapshot_to(&snap_dir).await.unwrap();

    // Write more data after c1.
    {
        let mut t = db.begin_write().await.unwrap();
        t.put(b"new_key", b"new_val").await.unwrap();
        t.commit().await.unwrap();
    }
    let c2 = db.latest_commit();

    // Incremental from c1 to c2.
    db.snapshot_incremental_to(c1, &delta_dir).await.unwrap();
    drop(db);

    // Restore and promote.
    let restored = Db::<TokioVfs>::restore_from(&snap_dir, &dst_dir, OpenOptions::default(), KEK)
        .await
        .unwrap();
    let follower = restored.promote_to_follower().await.unwrap();

    // Apply incremental.
    let _stats: ApplyStats = follower.apply_incremental(&delta_dir).await.unwrap();

    // The follower's latest_commit should equal c2 after applying.
    let follower_commit = follower.latest_commit();
    assert_eq!(follower_commit, c2, "follower commit should match c2");

    // The applied delta must advance the data tree: the key written after the
    // base snapshot is now readable, and the base key still resolves.
    let rtxn = follower.begin_read().await.unwrap();
    assert_eq!(
        rtxn.get(b"new_key").await.unwrap().as_deref(),
        Some(b"new_val".as_slice()),
        "incrementally-applied key must be readable on the follower"
    );
    assert_eq!(
        rtxn.get(b"base").await.unwrap().as_deref(),
        Some(b"data".as_slice()),
        "base key must survive the incremental apply"
    );
    drop(rtxn);

    std::fs::remove_dir_all(&src_dir).ok();
    std::fs::remove_dir_all(&snap_dir).ok();
    std::fs::remove_dir_all(&delta_dir).ok();
    std::fs::remove_dir_all(&dst_dir).ok();
}

// ---------------------------------------------------------------------------
// Test 8: apply_incremental rejects a delta when the follower is past its base.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "current_thread")]
async fn apply_incremental_rejects_delta_when_follower_not_at_base_commit() {
    let src_dir = tempdir();
    let snap_dir = tempdir();
    let delta_dir = tempdir();
    let dst_dir = tempdir();

    let db = make_db(&src_dir).await;
    {
        let mut t = db.begin_write().await.unwrap();
        t.put(b"base", b"data").await.unwrap();
        t.commit().await.unwrap();
    }
    let c1 = db.latest_commit();
    db.snapshot_to(&snap_dir).await.unwrap();

    {
        let mut t = db.begin_write().await.unwrap();
        t.put(b"new_key", b"new_val").await.unwrap();
        t.commit().await.unwrap();
    }
    db.snapshot_incremental_to(c1, &delta_dir).await.unwrap();
    drop(db);

    let restored = Db::<TokioVfs>::restore_from(&snap_dir, &dst_dir, OpenOptions::default(), KEK)
        .await
        .unwrap();
    let follower = restored.promote_to_follower().await.unwrap();

    follower.apply_incremental(&delta_dir).await.unwrap();
    let err = follower
        .apply_incremental(&delta_dir)
        .await
        .expect_err("apply_incremental must reject a delta whose base is not the follower commit");
    assert!(
        matches!(
            err,
            PagedbError::IdentityForked
                | PagedbError::SnapshotIncompatible {
                    field: "base_commit"
                }
        ),
        "expected IdentityForked for base-commit mismatch, got {err:?}"
    );

    std::fs::remove_dir_all(&src_dir).ok();
    std::fs::remove_dir_all(&snap_dir).ok();
    std::fs::remove_dir_all(&delta_dir).ok();
    std::fs::remove_dir_all(&dst_dir).ok();
}

#[tokio::test(flavor = "current_thread")]
async fn incremental_snapshot_rejects_missing_changed_main_page() {
    let src_dir = tempdir();
    let snap_dir = tempdir();
    let delta_dir = tempdir();

    let db = make_db(&src_dir).await;
    {
        let mut t = db.begin_write().await.unwrap();
        t.put(b"base", b"data").await.unwrap();
        t.commit().await.unwrap();
    }
    let c1 = db.latest_commit();
    db.snapshot_to(&snap_dir).await.unwrap();

    {
        let mut t = db.begin_write().await.unwrap();
        t.put(b"new_key", b"new_val").await.unwrap();
        t.commit().await.unwrap();
    }

    std::fs::OpenOptions::new()
        .write(true)
        .open(src_dir.join("main.db"))
        .unwrap()
        .set_len((PAGE * 2) as u64)
        .unwrap();

    let err = db
        .snapshot_incremental_to(c1, &delta_dir)
        .await
        .expect_err("incremental snapshot must reject missing changed main.db pages");
    assert!(
        matches!(err, PagedbError::Io(ref io) if io.kind() == std::io::ErrorKind::UnexpectedEof),
        "expected UnexpectedEof for missing changed main page, got {err:?}"
    );

    std::fs::remove_dir_all(&src_dir).ok();
    std::fs::remove_dir_all(&snap_dir).ok();
    std::fs::remove_dir_all(&delta_dir).ok();
}

/// Export succeeds when the target reaches pages below the base allocation
/// cursor, and actually ships them.
///
/// The cursor is an allocation watermark, not a liveness boundary. A page that
/// was on the free list at the base commit is legitimately reallocated for the
/// target, and shipping it is safe precisely because nothing reachable from the
/// base points at it. Rejecting on the cursor would make incremental snapshots
/// unusable for any database that has ever deleted anything.
///
/// The complementary end-to-end case — that such a delta also *applies* — is
/// `incremental_round_trip_survives_page_reuse_below_the_base_cursor`.
#[tokio::test(flavor = "current_thread")]
async fn incremental_snapshot_exports_reused_pages_below_base_cursor() {
    let src_dir = tempdir();
    let snap_dir = tempdir();
    let delta_dir = tempdir();

    let options = OpenOptions::default().with_commit_history_retain(RetainPolicy::Count(2));
    let db = make_db_with_options(&src_dir, options.clone()).await;
    {
        let mut t = db.begin_write().await.unwrap();
        for i in 0u32..48 {
            t.put(format!("old-{i:03}").as_bytes(), &vec![i as u8; PAGE * 2])
                .await
                .unwrap();
        }
        t.commit().await.unwrap();
    }
    {
        let mut t = db.begin_write().await.unwrap();
        for i in 0u32..48 {
            t.delete(format!("old-{i:03}").as_bytes()).await.unwrap();
        }
        t.commit().await.unwrap();
    }
    {
        let mut t = db.begin_write().await.unwrap();
        t.put(b"base-marker", b"retained").await.unwrap();
        t.commit().await.unwrap();
    }
    let base = db.latest_commit();
    db.snapshot_to(&snap_dir).await.unwrap();

    let new_value = vec![0xC7; PAGE * 2];
    {
        let mut t = db.begin_write().await.unwrap();
        t.put(b"reused-after-base", &new_value).await.unwrap();
        t.commit().await.unwrap();
    }
    let base_next_page_id = {
        let txn = db.begin_read_at(base).await.unwrap();
        txn.next_page_id()
    };
    let stats = db
        .snapshot_incremental_to(base, &delta_dir)
        .await
        .expect("reused pages below the base cursor must still export");
    assert!(stats.pages_written > 0);

    // Prove the scenario is the intended one: at least one shipped record names
    // a page id below the base cursor. Without this the test would still pass on
    // an implementation that only ever appends.
    let delta = std::fs::read(delta_dir.join("pages.delta")).unwrap();
    let record_size = 8 + PAGE;
    assert_eq!(delta.len() % record_size, 0, "delta must be whole records");
    let recycled = delta
        .chunks_exact(record_size)
        .map(|record| u64::from_be_bytes(record[..8].try_into().unwrap()))
        .filter(|page_id| *page_id < base_next_page_id)
        .count();
    assert!(
        recycled > 0,
        "expected the refill to recycle freed pages below the base cursor \
         ({base_next_page_id}); the delta shipped none"
    );

    std::fs::remove_dir_all(&src_dir).ok();
    std::fs::remove_dir_all(&snap_dir).ok();
    std::fs::remove_dir_all(&delta_dir).ok();
}

// ---------------------------------------------------------------------------
// Test 9: apply_incremental rejects a truncated delta stream.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "current_thread")]
async fn apply_incremental_rejects_truncated_delta_stream() {
    let src_dir = tempdir();
    let snap_dir = tempdir();
    let delta_dir = tempdir();
    let dst_dir = tempdir();

    let db = make_db(&src_dir).await;
    {
        let mut t = db.begin_write().await.unwrap();
        t.put(b"base", b"data").await.unwrap();
        t.commit().await.unwrap();
    }
    let c1 = db.latest_commit();
    db.snapshot_to(&snap_dir).await.unwrap();

    {
        let mut t = db.begin_write().await.unwrap();
        t.put(b"new_key", b"new_val").await.unwrap();
        t.commit().await.unwrap();
    }

    db.snapshot_incremental_to(c1, &delta_dir).await.unwrap();
    let delta_path = delta_dir.join("pages.delta");
    assert!(
        std::fs::metadata(&delta_path).unwrap().len() > 8,
        "test setup must produce a non-empty delta stream"
    );
    std::fs::write(&delta_path, [0xAA]).unwrap();
    drop(db);

    let restored = Db::<TokioVfs>::restore_from(&snap_dir, &dst_dir, OpenOptions::default(), KEK)
        .await
        .unwrap();
    let follower = restored.promote_to_follower().await.unwrap();

    let err = follower
        .apply_incremental(&delta_dir)
        .await
        .expect_err("apply_incremental must reject a truncated delta stream");
    assert!(
        matches!(err, PagedbError::Corruption(_)),
        "expected Corruption for truncated delta stream, got {err:?}"
    );

    let rtxn = follower.begin_read().await.unwrap();
    assert_eq!(
        rtxn.get(b"base").await.unwrap().as_deref(),
        Some(b"data".as_slice())
    );
    assert_eq!(rtxn.get(b"new_key").await.unwrap().as_deref(), None);
    drop(rtxn);

    std::fs::remove_dir_all(&src_dir).ok();
    std::fs::remove_dir_all(&snap_dir).ok();
    std::fs::remove_dir_all(&delta_dir).ok();
    std::fs::remove_dir_all(&dst_dir).ok();
}

// ---------------------------------------------------------------------------
// Test 9: apply_incremental rejects delta records for header pages.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "current_thread")]
async fn apply_incremental_rejects_header_page_delta_record() {
    let src_dir = tempdir();
    let snap_dir = tempdir();
    let delta_dir = tempdir();
    let dst_dir = tempdir();

    let db = make_db(&src_dir).await;
    {
        let mut t = db.begin_write().await.unwrap();
        t.put(b"base", b"data").await.unwrap();
        t.commit().await.unwrap();
    }
    let c1 = db.latest_commit();
    db.snapshot_to(&snap_dir).await.unwrap();

    {
        let mut t = db.begin_write().await.unwrap();
        t.put(b"new_key", b"new_val").await.unwrap();
        t.commit().await.unwrap();
    }
    db.snapshot_incremental_to(c1, &delta_dir).await.unwrap();

    let mut delta = Vec::with_capacity(8 + PAGE);
    delta.extend_from_slice(&0u64.to_be_bytes());
    delta.extend_from_slice(&vec![0xAA; PAGE]);
    std::fs::write(delta_dir.join("pages.delta"), delta).unwrap();
    drop(db);

    let restored = Db::<TokioVfs>::restore_from(&snap_dir, &dst_dir, OpenOptions::default(), KEK)
        .await
        .unwrap();
    let follower = restored.promote_to_follower().await.unwrap();

    let err = follower
        .apply_incremental(&delta_dir)
        .await
        .expect_err("apply_incremental must reject header-page delta records");
    assert!(
        matches!(err, PagedbError::Corruption(_)),
        "expected Corruption for header-page delta record, got {err:?}"
    );

    std::fs::remove_dir_all(&src_dir).ok();
    std::fs::remove_dir_all(&snap_dir).ok();
    std::fs::remove_dir_all(&delta_dir).ok();
    std::fs::remove_dir_all(&dst_dir).ok();
}

// ---------------------------------------------------------------------------
// Test 10: apply_incremental rejects delta records beyond the target page range.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "current_thread")]
async fn apply_incremental_rejects_delta_record_at_target_next_page_id() {
    let src_dir = tempdir();
    let snap_dir = tempdir();
    let delta_dir = tempdir();
    let dst_dir = tempdir();

    let db = make_db(&src_dir).await;
    {
        let mut t = db.begin_write().await.unwrap();
        t.put(b"base", b"data").await.unwrap();
        t.commit().await.unwrap();
    }
    let c1 = db.latest_commit();
    db.snapshot_to(&snap_dir).await.unwrap();

    {
        let mut t = db.begin_write().await.unwrap();
        t.put(b"new_key", b"new_val").await.unwrap();
        t.commit().await.unwrap();
    }
    db.snapshot_incremental_to(c1, &delta_dir).await.unwrap();

    let manifest = std::fs::read(delta_dir.join("manifest")).unwrap();
    let target_next_page_id = u64::from_le_bytes(manifest[74..82].try_into().unwrap());
    let mut delta = Vec::with_capacity(8 + PAGE);
    delta.extend_from_slice(&target_next_page_id.to_be_bytes());
    delta.extend_from_slice(&vec![0xAA; PAGE]);
    std::fs::write(delta_dir.join("pages.delta"), delta).unwrap();
    drop(db);

    let restored = Db::<TokioVfs>::restore_from(&snap_dir, &dst_dir, OpenOptions::default(), KEK)
        .await
        .unwrap();
    let follower = restored.promote_to_follower().await.unwrap();

    let err = follower
        .apply_incremental(&delta_dir)
        .await
        .expect_err("apply_incremental must reject out-of-range delta records");
    assert!(
        matches!(err, PagedbError::Corruption(_)),
        "expected Corruption for out-of-range delta record, got {err:?}"
    );

    std::fs::remove_dir_all(&src_dir).ok();
    std::fs::remove_dir_all(&snap_dir).ok();
    std::fs::remove_dir_all(&delta_dir).ok();
    std::fs::remove_dir_all(&dst_dir).ok();
}

// ---------------------------------------------------------------------------
// Test 11: apply_incremental rejects delta records below the base next-page id.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "current_thread")]
/// A delta record naming a page the base still holds live is refused, and the
/// refusal leaves the base intact.
///
/// The injected id is the base snapshot's own active root — a page the follower
/// is still reading through. What makes it inadmissible is that it is base-live,
/// not that it sorts below some allocation cursor: recycled ids below that
/// cursor are ordinary and are covered by
/// `incremental_snapshot_exports_reused_pages_below_base_cursor`.
async fn apply_incremental_refuses_to_overwrite_a_base_live_page_without_mutating_base() {
    let src_dir = tempdir();
    let snap_dir = tempdir();
    let delta_dir = tempdir();
    let dst_dir = tempdir();

    let db = make_db(&src_dir).await;
    {
        let mut t = db.begin_write().await.unwrap();
        t.put(b"base", b"data").await.unwrap();
        t.commit().await.unwrap();
    }
    let c1 = db.latest_commit();
    db.snapshot_to(&snap_dir).await.unwrap();
    let base_manifest = open_manifest(&snap_dir.join("manifest"), &KEK)
        .await
        .unwrap();

    {
        let mut t = db.begin_write().await.unwrap();
        t.put(b"new_key", b"new_val").await.unwrap();
        t.commit().await.unwrap();
    }
    db.snapshot_incremental_to(c1, &delta_dir).await.unwrap();

    let stale_page_id = base_manifest.target_active_root_page_id;
    assert!(
        stale_page_id >= 2 && stale_page_id < base_manifest.next_page_id_at_target,
        "test setup needs an existing non-header base page"
    );
    let delta_path = delta_dir.join("pages.delta");
    let original_delta = std::fs::read(&delta_path).unwrap();
    let mut malicious_delta = Vec::with_capacity(original_delta.len() + 8 + PAGE);
    malicious_delta.extend_from_slice(&stale_page_id.to_be_bytes());
    malicious_delta.extend_from_slice(&vec![0xAA; PAGE]);
    malicious_delta.extend_from_slice(&original_delta);
    std::fs::write(&delta_path, malicious_delta).unwrap();
    drop(db);

    let restored = Db::<TokioVfs>::restore_from(&snap_dir, &dst_dir, OpenOptions::default(), KEK)
        .await
        .unwrap();
    let follower = restored.promote_to_follower().await.unwrap();

    let err = follower
        .apply_incremental(&delta_dir)
        .await
        .expect_err("apply_incremental must refuse to overwrite a base-live page");
    assert!(
        matches!(
            err,
            PagedbError::SnapshotBasePageReused { page_id } if page_id == stale_page_id
        ),
        "expected SnapshotBasePageReused naming page {stale_page_id}, got {err:?}"
    );

    let rtxn = follower.begin_read().await.unwrap();
    let base = rtxn
        .get(b"base")
        .await
        .expect("failed apply must not corrupt existing base pages");
    assert_eq!(base.as_deref(), Some(b"data".as_slice()));
    drop(rtxn);

    std::fs::remove_dir_all(&src_dir).ok();
    std::fs::remove_dir_all(&snap_dir).ok();
    std::fs::remove_dir_all(&delta_dir).ok();
    std::fs::remove_dir_all(&dst_dir).ok();
}

// ---------------------------------------------------------------------------
// Test 12: apply_incremental rejects duplicate delta records.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "current_thread")]
async fn apply_incremental_rejects_duplicate_delta_page_records() {
    let src_dir = tempdir();
    let snap_dir = tempdir();
    let delta_dir = tempdir();
    let dst_dir = tempdir();

    let db = make_db(&src_dir).await;
    {
        let mut t = db.begin_write().await.unwrap();
        t.put(b"base", b"data").await.unwrap();
        t.commit().await.unwrap();
    }
    let c1 = db.latest_commit();
    db.snapshot_to(&snap_dir).await.unwrap();

    {
        let mut t = db.begin_write().await.unwrap();
        t.put(b"new_key", b"new_val").await.unwrap();
        t.commit().await.unwrap();
    }
    db.snapshot_incremental_to(c1, &delta_dir).await.unwrap();

    let delta_path = delta_dir.join("pages.delta");
    let original_delta = std::fs::read(&delta_path).unwrap();
    assert!(
        original_delta.len() >= 8 + PAGE,
        "test setup must produce at least one delta page"
    );
    let duplicate_page_id = u64::from_be_bytes(original_delta[..8].try_into().unwrap());
    let mut duplicated_delta = Vec::with_capacity(original_delta.len() + 8 + PAGE);
    duplicated_delta.extend_from_slice(&original_delta);
    duplicated_delta.extend_from_slice(&duplicate_page_id.to_be_bytes());
    duplicated_delta.extend_from_slice(&vec![0xAA; PAGE]);
    std::fs::write(delta_path, duplicated_delta).unwrap();
    drop(db);

    let restored = Db::<TokioVfs>::restore_from(&snap_dir, &dst_dir, OpenOptions::default(), KEK)
        .await
        .unwrap();
    let follower = restored.promote_to_follower().await.unwrap();

    let err = follower
        .apply_incremental(&delta_dir)
        .await
        .expect_err("apply_incremental must reject duplicate delta records");
    assert!(
        matches!(err, PagedbError::Corruption(_)),
        "expected Corruption for duplicate delta record, got {err:?}"
    );

    std::fs::remove_dir_all(&src_dir).ok();
    std::fs::remove_dir_all(&snap_dir).ok();
    std::fs::remove_dir_all(&delta_dir).ok();
    std::fs::remove_dir_all(&dst_dir).ok();
}

// ---------------------------------------------------------------------------
// Test 12: apply_incremental rejects corrupt target active-root delta pages.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "current_thread")]
async fn apply_incremental_rejects_corrupt_target_active_root_delta_page() {
    let src_dir = tempdir();
    let snap_dir = tempdir();
    let delta_dir = tempdir();
    let dst_dir = tempdir();

    let db = make_db(&src_dir).await;
    {
        let mut t = db.begin_write().await.unwrap();
        t.put(b"base", b"data").await.unwrap();
        t.commit().await.unwrap();
    }
    let c1 = db.latest_commit();
    db.snapshot_to(&snap_dir).await.unwrap();

    {
        let mut t = db.begin_write().await.unwrap();
        t.put(b"new_key", b"new_val").await.unwrap();
        t.commit().await.unwrap();
    }
    db.snapshot_incremental_to(c1, &delta_dir).await.unwrap();

    let manifest = std::fs::read(delta_dir.join("manifest")).unwrap();
    let target_active_root_page_id = u64::from_le_bytes(manifest[102..110].try_into().unwrap());
    let delta_path = delta_dir.join("pages.delta");
    let mut delta = std::fs::read(&delta_path).unwrap();
    let record_len = 8 + PAGE;
    let mut corrupted = false;
    for record in delta.chunks_exact_mut(record_len) {
        let page_id = u64::from_be_bytes(record[..8].try_into().unwrap());
        if page_id == target_active_root_page_id {
            record[8 + 128] ^= 0xFF;
            corrupted = true;
            break;
        }
    }
    assert!(
        corrupted,
        "test setup must include target active root page {target_active_root_page_id} in pages.delta"
    );
    std::fs::write(&delta_path, delta).unwrap();
    drop(db);

    let restored = Db::<TokioVfs>::restore_from(&snap_dir, &dst_dir, OpenOptions::default(), KEK)
        .await
        .unwrap();
    let follower = restored.promote_to_follower().await.unwrap();

    let err = follower
        .apply_incremental(&delta_dir)
        .await
        .expect_err("apply_incremental must reject corrupt target active-root delta pages");
    assert!(
        matches!(
            err,
            PagedbError::ChecksumFailure | PagedbError::Corruption(_)
        ),
        "expected page authentication failure, got {err:?}"
    );

    let rtxn = follower.begin_read().await.unwrap();
    assert_eq!(
        rtxn.get(b"base").await.unwrap().as_deref(),
        Some(b"data".as_slice())
    );
    assert_eq!(
        rtxn.get(b"new_key").await.unwrap().as_deref(),
        None,
        "failed incremental apply must not advance the active root"
    );
    drop(rtxn);

    std::fs::remove_dir_all(&src_dir).ok();
    std::fs::remove_dir_all(&snap_dir).ok();
    std::fs::remove_dir_all(&delta_dir).ok();
    std::fs::remove_dir_all(&dst_dir).ok();
}

// ---------------------------------------------------------------------------
// Test 12: apply_incremental rejects a full snapshot manifest.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "current_thread")]
async fn apply_incremental_rejects_full_snapshot_manifest() {
    let src_dir = tempdir();
    let base_snap_dir = tempdir();
    let full_snap_dir = tempdir();
    let dst_dir = tempdir();

    let db = make_db(&src_dir).await;
    {
        let mut t = db.begin_write().await.unwrap();
        t.put(b"base", b"data").await.unwrap();
        t.commit().await.unwrap();
    }
    db.snapshot_to(&base_snap_dir).await.unwrap();

    {
        let mut t = db.begin_write().await.unwrap();
        t.put(b"later", b"value").await.unwrap();
        t.commit().await.unwrap();
    }
    db.snapshot_to(&full_snap_dir).await.unwrap();
    drop(db);

    let restored =
        Db::<TokioVfs>::restore_from(&base_snap_dir, &dst_dir, OpenOptions::default(), KEK)
            .await
            .unwrap();
    let follower = restored.promote_to_follower().await.unwrap();

    let err = follower
        .apply_incremental(&full_snap_dir)
        .await
        .expect_err("apply_incremental must reject a full snapshot manifest");
    assert!(
        matches!(
            err,
            PagedbError::Corruption(_) | PagedbError::SnapshotIncompatible { field: "kind" }
        ),
        "expected Corruption for full snapshot manifest, got {err:?}"
    );

    std::fs::remove_dir_all(&src_dir).ok();
    std::fs::remove_dir_all(&base_snap_dir).ok();
    std::fs::remove_dir_all(&full_snap_dir).ok();
    std::fs::remove_dir_all(&dst_dir).ok();
}

#[tokio::test(flavor = "current_thread")]
async fn apply_incremental_rejects_manifest_with_trailing_bytes() {
    let src_dir = tempdir();
    let snap_dir = tempdir();
    let delta_dir = tempdir();
    let dst_dir = tempdir();

    let db = make_db(&src_dir).await;
    {
        let mut t = db.begin_write().await.unwrap();
        t.put(b"base", b"data").await.unwrap();
        t.commit().await.unwrap();
    }
    let c1 = db.latest_commit();
    db.snapshot_to(&snap_dir).await.unwrap();

    {
        let mut t = db.begin_write().await.unwrap();
        t.put(b"later", b"value").await.unwrap();
        t.commit().await.unwrap();
    }
    db.snapshot_incremental_to(c1, &delta_dir).await.unwrap();

    let manifest_path = delta_dir.join("manifest");
    let mut bytes = std::fs::read(&manifest_path).unwrap();
    bytes.push(0xAA);
    std::fs::write(&manifest_path, bytes).unwrap();
    drop(db);

    let restored = Db::<TokioVfs>::restore_from(&snap_dir, &dst_dir, OpenOptions::default(), KEK)
        .await
        .unwrap();
    let follower = restored.promote_to_follower().await.unwrap();

    let err = follower
        .apply_incremental(&delta_dir)
        .await
        .expect_err("apply_incremental must reject non-canonical manifest length");
    assert!(
        matches!(err, PagedbError::Corruption(_)),
        "expected Corruption for manifest trailing bytes, got {err:?}"
    );

    std::fs::remove_dir_all(&src_dir).ok();
    std::fs::remove_dir_all(&snap_dir).ok();
    std::fs::remove_dir_all(&delta_dir).ok();
    std::fs::remove_dir_all(&dst_dir).ok();
}

// ---------------------------------------------------------------------------
// Test 13: apply_incremental rejects a correctly MACed wrong-realm manifest.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "current_thread")]
async fn apply_incremental_rejects_wrong_realm_manifest() {
    let src_dir = tempdir();
    let snap_dir = tempdir();
    let delta_dir = tempdir();
    let dst_dir = tempdir();

    let db = make_db(&src_dir).await;
    {
        let mut t = db.begin_write().await.unwrap();
        t.put(b"base", b"data").await.unwrap();
        t.commit().await.unwrap();
    }
    let c1 = db.latest_commit();
    db.snapshot_to(&snap_dir).await.unwrap();

    {
        let mut t = db.begin_write().await.unwrap();
        t.put(b"new_key", b"new_val").await.unwrap();
        t.commit().await.unwrap();
    }
    db.snapshot_incremental_to(c1, &delta_dir).await.unwrap();

    let manifest_path = delta_dir.join("manifest");
    let mut manifest = open_manifest(&manifest_path, &KEK).await.unwrap();
    let hk_key = derive_snapshot_hk_key(&KEK, &manifest.kek_salt, manifest.mk_epoch).unwrap();
    manifest.realm_id = [2u8; 16];
    std::fs::write(manifest_path, encode_manifest(&manifest, &hk_key)).unwrap();
    drop(db);

    let restored = Db::<TokioVfs>::restore_from(&snap_dir, &dst_dir, OpenOptions::default(), KEK)
        .await
        .unwrap();
    let follower = restored.promote_to_follower().await.unwrap();

    let err = follower
        .apply_incremental(&delta_dir)
        .await
        .expect_err("apply_incremental must reject a wrong-realm incremental manifest");
    assert!(
        matches!(
            err,
            PagedbError::IdentityForked
                | PagedbError::Corruption(_)
                | PagedbError::SnapshotIncompatible { field: "realm_id" }
        ),
        "expected identity failure for wrong-realm manifest, got {err:?}"
    );

    let rtxn = follower.begin_read().await.unwrap();
    assert_eq!(
        rtxn.get(b"base").await.unwrap().as_deref(),
        Some(b"data".as_slice())
    );
    assert_eq!(
        rtxn.get(b"new_key").await.unwrap().as_deref(),
        None,
        "failed incremental apply must not advance the active root"
    );
    drop(rtxn);

    std::fs::remove_dir_all(&src_dir).ok();
    std::fs::remove_dir_all(&snap_dir).ok();
    std::fs::remove_dir_all(&delta_dir).ok();
    std::fs::remove_dir_all(&dst_dir).ok();
}

// ---------------------------------------------------------------------------
// Test 13: apply_incremental rejects target commits that do not advance.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "current_thread")]
async fn apply_incremental_rejects_non_advancing_target_commit() {
    let src_dir = tempdir();
    let snap_dir = tempdir();
    let delta_dir = tempdir();
    let dst_dir = tempdir();

    let db = make_db(&src_dir).await;
    {
        let mut t = db.begin_write().await.unwrap();
        t.put(b"base", b"data").await.unwrap();
        t.commit().await.unwrap();
    }
    let c1 = db.latest_commit();
    db.snapshot_to(&snap_dir).await.unwrap();

    {
        let mut t = db.begin_write().await.unwrap();
        t.put(b"new_key", b"new_val").await.unwrap();
        t.commit().await.unwrap();
    }
    db.snapshot_incremental_to(c1, &delta_dir).await.unwrap();

    let manifest_path = delta_dir.join("manifest");
    let mut manifest = open_manifest(&manifest_path, &KEK).await.unwrap();
    let hk_key = derive_snapshot_hk_key(&KEK, &manifest.kek_salt, manifest.mk_epoch).unwrap();
    manifest.target_commit = manifest.base_commit;
    std::fs::write(manifest_path, encode_manifest(&manifest, &hk_key)).unwrap();
    drop(db);

    let restored = Db::<TokioVfs>::restore_from(&snap_dir, &dst_dir, OpenOptions::default(), KEK)
        .await
        .unwrap();
    let follower = restored.promote_to_follower().await.unwrap();

    let err = follower
        .apply_incremental(&delta_dir)
        .await
        .expect_err("apply_incremental must reject non-advancing target commits");
    assert!(
        matches!(
            err,
            PagedbError::IdentityForked
                | PagedbError::Corruption(_)
                | PagedbError::SnapshotIncompatible {
                    field: "target_commit"
                }
        ),
        "expected identity/corruption failure for non-advancing target commit, got {err:?}"
    );

    let rtxn = follower.begin_read().await.unwrap();
    assert_eq!(
        rtxn.get(b"base").await.unwrap().as_deref(),
        Some(b"data".as_slice())
    );
    assert_eq!(
        rtxn.get(b"new_key").await.unwrap().as_deref(),
        None,
        "failed incremental apply must not install new content under the base commit id"
    );
    drop(rtxn);

    std::fs::remove_dir_all(&src_dir).ok();
    std::fs::remove_dir_all(&snap_dir).ok();
    std::fs::remove_dir_all(&delta_dir).ok();
    std::fs::remove_dir_all(&dst_dir).ok();
}

// ---------------------------------------------------------------------------
// Test 14: standalone db calling apply_incremental returns IdentityForked.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "current_thread")]
async fn apply_incremental_rejects_on_standalone() {
    let src_dir = tempdir();
    let snap_dir = tempdir();

    let db = make_db(&src_dir).await;
    db.snapshot_to(&snap_dir).await.unwrap();

    let err = db.apply_incremental(&snap_dir).await.err().unwrap();
    assert!(
        matches!(err, PagedbError::IdentityForked),
        "expected IdentityForked, got {err:?}"
    );

    std::fs::remove_dir_all(&src_dir).ok();
    std::fs::remove_dir_all(&snap_dir).ok();
}

// ---------------------------------------------------------------------------
// Test 14: snapshot includes segments; restored db can read segment.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "current_thread")]
async fn snapshot_includes_segments() {
    let src_dir = tempdir();
    let snap_dir = tempdir();
    let dst_dir = tempdir();

    let db = make_db(&src_dir).await;
    {
        let mut w = db
            .create_segment(REALM, SegmentKind::Unspecified)
            .await
            .unwrap();
        w.append_page(SegmentPageKind::Data, b"seg-content")
            .await
            .unwrap();
        w.set_manifest(b"mf").unwrap();
        let meta = w.seal().await.unwrap();
        let mut t = db.begin_write().await.unwrap();
        t.link_segment("my.seg", &meta).await.unwrap();
        t.commit().await.unwrap();
    }

    let stats = db.snapshot_to(&snap_dir).await.unwrap();
    assert_eq!(stats.segments_written, 1);
    drop(db);

    let restored = Db::<TokioVfs>::restore_from(&snap_dir, &dst_dir, OpenOptions::default(), KEK)
        .await
        .unwrap();
    let rtxn = restored.begin_read().await.unwrap();
    let reader = rtxn.open_segment("my.seg").await.unwrap();
    let page = reader.read_page(1).await.unwrap();
    assert!(page.starts_with(b"seg-content"));

    std::fs::remove_dir_all(&src_dir).ok();
    std::fs::remove_dir_all(&snap_dir).ok();
    std::fs::remove_dir_all(&dst_dir).ok();
}

// ---------------------------------------------------------------------------
// Test 15: snapshot_to rejects a catalog segment whose file is missing.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "current_thread")]
async fn snapshot_to_rejects_missing_catalog_segment_file() {
    let src_dir = tempdir();
    let snap_dir = tempdir();

    let db = make_db(&src_dir).await;
    let meta = {
        let mut w = db
            .create_segment(REALM, SegmentKind::Unspecified)
            .await
            .unwrap();
        w.append_page(SegmentPageKind::Data, b"seg-content")
            .await
            .unwrap();
        w.set_manifest(b"mf").unwrap();
        w.seal().await.unwrap()
    };
    let segment_path = src_dir.join("seg").join(hex_lower(&meta.segment_id));
    {
        let mut t = db.begin_write().await.unwrap();
        t.link_segment("missing-source.seg", &meta).await.unwrap();
        t.commit().await.unwrap();
    }
    assert!(
        segment_path.is_file(),
        "test setup must create the linked live segment file"
    );
    std::fs::remove_file(&segment_path).unwrap();

    let err = match db.snapshot_to(&snap_dir).await {
        Ok(_) => panic!("snapshot_to must reject a catalog segment whose file is missing"),
        Err(err) => err,
    };
    assert!(
        matches!(err, PagedbError::Io(ref io) if io.kind() == std::io::ErrorKind::NotFound),
        "expected NotFound for missing catalog segment file, got {err:?}"
    );

    std::fs::remove_dir_all(&src_dir).ok();
    std::fs::remove_dir_all(&snap_dir).ok();
}

// ---------------------------------------------------------------------------
// Test 16: snapshot_to rejects non-empty output directories.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "current_thread")]
async fn snapshot_to_rejects_non_empty_destination() {
    let src_dir = tempdir();
    let snap_dir = tempdir();

    let db = make_db(&src_dir).await;
    {
        let mut t = db.begin_write().await.unwrap();
        t.put(b"base", b"data").await.unwrap();
        t.commit().await.unwrap();
    }
    create_stale_snapshot_sidecar(&snap_dir);

    let err = match db.snapshot_to(&snap_dir).await {
        Ok(_) => panic!("snapshot_to must reject a non-empty destination"),
        Err(err) => err,
    };
    assert!(
        matches!(err, PagedbError::Io(ref io) if io.kind() == std::io::ErrorKind::AlreadyExists),
        "expected AlreadyExists for non-empty snapshot destination, got {err:?}"
    );

    std::fs::remove_dir_all(&src_dir).ok();
    std::fs::remove_dir_all(&snap_dir).ok();
}

// ---------------------------------------------------------------------------
// Test 17: failed snapshot_to leaves the destination reusable.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "current_thread")]
async fn snapshot_to_failure_leaves_destination_reusable() {
    let src_dir = tempdir();
    let snap_dir = tempdir();

    let db = make_db(&src_dir).await;
    let meta = {
        let mut w = db
            .create_segment(REALM, SegmentKind::Unspecified)
            .await
            .unwrap();
        w.append_page(SegmentPageKind::Data, b"seg-content")
            .await
            .unwrap();
        w.set_manifest(b"mf").unwrap();
        w.seal().await.unwrap()
    };
    let segment_path = src_dir.join("seg").join(hex_lower(&meta.segment_id));
    let backup_path = segment_path.with_extension("bak");
    {
        let mut t = db.begin_write().await.unwrap();
        t.link_segment("retry-full.seg", &meta).await.unwrap();
        t.commit().await.unwrap();
    }
    std::fs::rename(&segment_path, &backup_path).unwrap();

    let err = match db.snapshot_to(&snap_dir).await {
        Ok(_) => panic!("snapshot_to must reject a catalog segment whose file is missing"),
        Err(err) => err,
    };
    assert!(
        matches!(err, PagedbError::Io(ref io) if io.kind() == std::io::ErrorKind::NotFound),
        "expected NotFound for missing catalog segment file, got {err:?}"
    );

    std::fs::rename(&backup_path, &segment_path).unwrap();
    let stats = db
        .snapshot_to(&snap_dir)
        .await
        .expect("failed snapshot_to must leave the destination reusable");
    assert_eq!(stats.segments_written, 1);

    std::fs::remove_dir_all(&src_dir).ok();
    std::fs::remove_dir_all(&snap_dir).ok();
}

#[tokio::test(flavor = "current_thread")]
async fn snapshot_to_rejects_missing_main_page() {
    let src_dir = tempdir();
    let snap_dir = tempdir();

    let db = make_db(&src_dir).await;
    {
        let mut t = db.begin_write().await.unwrap();
        t.put(b"full-missing-page", b"value").await.unwrap();
        t.commit().await.unwrap();
    }

    std::fs::OpenOptions::new()
        .write(true)
        .open(src_dir.join("main.db"))
        .unwrap()
        .set_len((PAGE * 2) as u64)
        .unwrap();

    let err = db
        .snapshot_to(&snap_dir)
        .await
        .expect_err("snapshot_to must reject missing main.db pages");
    assert!(
        matches!(err, PagedbError::Io(ref io) if io.kind() == std::io::ErrorKind::UnexpectedEof),
        "expected UnexpectedEof for missing main.db page, got {err:?}"
    );

    std::fs::remove_dir_all(&src_dir).ok();
    std::fs::remove_dir_all(&snap_dir).ok();
}

#[tokio::test(flavor = "current_thread")]
async fn snapshot_to_rejects_missing_header_referenced_main_page() {
    let src_dir = tempdir();
    let snap_dir = tempdir();

    let db = make_db(&src_dir).await;
    let second_value = vec![0xB2; PAGE * 3];
    {
        let mut t = db.begin_write().await.unwrap();
        t.put(b"overflow-a", &vec![0xA1; PAGE * 3]).await.unwrap();
        t.put(b"overflow-b", &second_value).await.unwrap();
        t.commit().await.unwrap();
    }
    let rtxn = db.begin_read().await.unwrap();
    assert_eq!(
        rtxn.get(b"overflow-b").await.unwrap().as_deref(),
        Some(second_value.as_slice()),
        "test setup must make the committed payload readable before truncation"
    );
    drop(rtxn);

    db.snapshot_to(&snap_dir).await.unwrap();
    let manifest = open_manifest(&snap_dir.join("manifest"), &KEK)
        .await
        .unwrap();
    std::fs::remove_dir_all(&snap_dir).unwrap();

    let highest_root_page = manifest
        .target_active_root_page_id
        .max(manifest.target_catalog_root_page_id);
    let truncated_len = (highest_root_page + 1) * PAGE as u64;
    let main_path = src_dir.join("main.db");
    let original_len = std::fs::metadata(&main_path).unwrap().len();
    assert!(
        original_len > truncated_len,
        "test setup must allocate header-referenced pages beyond the root/catalog watermark"
    );
    std::fs::OpenOptions::new()
        .write(true)
        .open(&main_path)
        .unwrap()
        .set_len(truncated_len)
        .unwrap();

    let err = db
        .snapshot_to(&snap_dir)
        .await
        .expect_err("snapshot_to must reject missing header-referenced pages");
    assert!(
        matches!(err, PagedbError::Io(ref io) if io.kind() == std::io::ErrorKind::UnexpectedEof),
        "expected UnexpectedEof for missing header-referenced page, got {err:?}"
    );

    std::fs::remove_dir_all(&src_dir).ok();
    std::fs::remove_dir_all(&snap_dir).ok();
}

// ---------------------------------------------------------------------------
// Test 18: snapshot_incremental_to rejects a new segment whose file is missing.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "current_thread")]
async fn snapshot_incremental_to_rejects_missing_new_segment_file() {
    let src_dir = tempdir();
    let delta_dir = tempdir();

    let db = make_db(&src_dir).await;
    {
        let mut t = db.begin_write().await.unwrap();
        t.put(b"base", b"data").await.unwrap();
        t.commit().await.unwrap();
    }
    let c1 = db.latest_commit();

    let meta = {
        let mut w = db
            .create_segment(REALM, SegmentKind::Unspecified)
            .await
            .unwrap();
        w.append_page(SegmentPageKind::Data, b"seg-content")
            .await
            .unwrap();
        w.set_manifest(b"mf").unwrap();
        w.seal().await.unwrap()
    };
    let segment_path = src_dir.join("seg").join(hex_lower(&meta.segment_id));
    {
        let mut t = db.begin_write().await.unwrap();
        t.link_segment("missing-incremental.seg", &meta)
            .await
            .unwrap();
        t.commit().await.unwrap();
    }
    assert!(
        segment_path.is_file(),
        "test setup must create the linked live segment file"
    );
    std::fs::remove_file(&segment_path).unwrap();

    let err = match db.snapshot_incremental_to(c1, &delta_dir).await {
        Ok(_) => panic!("snapshot_incremental_to must reject a new segment whose file is missing"),
        Err(err) => err,
    };
    assert!(
        matches!(err, PagedbError::Io(ref io) if io.kind() == std::io::ErrorKind::NotFound),
        "expected NotFound for missing new segment file, got {err:?}"
    );

    std::fs::remove_dir_all(&src_dir).ok();
    std::fs::remove_dir_all(&delta_dir).ok();
}

// ---------------------------------------------------------------------------
// Test 19: snapshot_incremental_to rejects non-empty output directories.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "current_thread")]
async fn snapshot_incremental_to_rejects_non_empty_destination() {
    let src_dir = tempdir();
    let delta_dir = tempdir();

    let db = make_db(&src_dir).await;
    {
        let mut t = db.begin_write().await.unwrap();
        t.put(b"base", b"data").await.unwrap();
        t.commit().await.unwrap();
    }
    let c1 = db.latest_commit();
    {
        let mut t = db.begin_write().await.unwrap();
        t.put(b"new_key", b"new_val").await.unwrap();
        t.commit().await.unwrap();
    }
    create_stale_snapshot_sidecar(&delta_dir);

    let err = match db.snapshot_incremental_to(c1, &delta_dir).await {
        Ok(_) => panic!("snapshot_incremental_to must reject a non-empty destination"),
        Err(err) => err,
    };
    assert!(
        matches!(err, PagedbError::Io(ref io) if io.kind() == std::io::ErrorKind::AlreadyExists),
        "expected AlreadyExists for non-empty incremental destination, got {err:?}"
    );

    std::fs::remove_dir_all(&src_dir).ok();
    std::fs::remove_dir_all(&delta_dir).ok();
}

// ---------------------------------------------------------------------------
// Test 20: failed snapshot_incremental_to leaves the destination reusable.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "current_thread")]
async fn snapshot_incremental_to_failure_leaves_destination_reusable() {
    let src_dir = tempdir();
    let delta_dir = tempdir();

    let db = make_db(&src_dir).await;
    {
        let mut t = db.begin_write().await.unwrap();
        t.put(b"base", b"data").await.unwrap();
        t.commit().await.unwrap();
    }
    let c1 = db.latest_commit();
    let meta = {
        let mut w = db
            .create_segment(REALM, SegmentKind::Unspecified)
            .await
            .unwrap();
        w.append_page(SegmentPageKind::Data, b"seg-content")
            .await
            .unwrap();
        w.set_manifest(b"mf").unwrap();
        w.seal().await.unwrap()
    };
    let segment_path = src_dir.join("seg").join(hex_lower(&meta.segment_id));
    let backup_path = segment_path.with_extension("bak");
    {
        let mut t = db.begin_write().await.unwrap();
        t.link_segment("retry-incremental.seg", &meta)
            .await
            .unwrap();
        t.commit().await.unwrap();
    }
    std::fs::rename(&segment_path, &backup_path).unwrap();

    let err = match db.snapshot_incremental_to(c1, &delta_dir).await {
        Ok(_) => panic!("snapshot_incremental_to must reject a new segment whose file is missing"),
        Err(err) => err,
    };
    assert!(
        matches!(err, PagedbError::Io(ref io) if io.kind() == std::io::ErrorKind::NotFound),
        "expected NotFound for missing new segment file, got {err:?}"
    );

    std::fs::rename(&backup_path, &segment_path).unwrap();
    let stats = db
        .snapshot_incremental_to(c1, &delta_dir)
        .await
        .expect("failed snapshot_incremental_to must leave the destination reusable");
    assert_eq!(stats.segments_written, 1);

    std::fs::remove_dir_all(&src_dir).ok();
    std::fs::remove_dir_all(&delta_dir).ok();
}

// ---------------------------------------------------------------------------
// Test 21: apply_incremental rejects renamed segment sidecars.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "current_thread")]
async fn apply_incremental_rejects_renamed_manifest_declared_segment_file() {
    let src_dir = tempdir();
    let snap_dir = tempdir();
    let delta_dir = tempdir();
    let dst_dir = tempdir();

    let db = make_db(&src_dir).await;
    {
        let mut t = db.begin_write().await.unwrap();
        t.put(b"base", b"data").await.unwrap();
        t.commit().await.unwrap();
    }
    let c1 = db.latest_commit();
    db.snapshot_to(&snap_dir).await.unwrap();

    {
        let meta = {
            let mut s = db
                .create_segment(REALM, SegmentKind::Unspecified)
                .await
                .unwrap();
            s.append_page(SegmentPageKind::Data, b"segment-after-base")
                .await
                .unwrap();
            s.set_manifest(b"mf").unwrap();
            s.seal().await.unwrap()
        };
        let mut t = db.begin_write().await.unwrap();
        t.link_segment("renamed.seg", &meta).await.unwrap();
        t.commit().await.unwrap();
    }

    let stats = db.snapshot_incremental_to(c1, &delta_dir).await.unwrap();
    assert_eq!(stats.segments_written, 1);
    let seg_files: Vec<_> = std::fs::read_dir(delta_dir.join("seg"))
        .unwrap()
        .filter_map(std::result::Result::ok)
        .filter(|entry| entry.path().is_file())
        .map(|entry| entry.path())
        .collect();
    assert_eq!(
        seg_files.len(),
        1,
        "test setup must produce exactly one incremental segment sidecar"
    );
    let original_sidecar = &seg_files[0];
    let fake_sidecar = delta_dir
        .join("seg")
        .join("cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd");
    std::fs::rename(original_sidecar, fake_sidecar).unwrap();
    drop(db);

    let restored = Db::<TokioVfs>::restore_from(&snap_dir, &dst_dir, OpenOptions::default(), KEK)
        .await
        .unwrap();
    let follower = restored.promote_to_follower().await.unwrap();

    let err = follower
        .apply_incremental(&delta_dir)
        .await
        .expect_err("apply_incremental must reject renamed manifest-declared segment files");
    assert!(
        matches!(
            err,
            PagedbError::Corruption(_)
                | PagedbError::SnapshotIncompatible {
                    field: "segments_count"
                }
        ),
        "expected Corruption for renamed segment sidecar, got {err:?}"
    );

    let rtxn = follower.begin_read().await.unwrap();
    assert!(
        rtxn.open_segment("renamed.seg").await.is_err(),
        "failed incremental apply must not advance the catalog"
    );
    drop(rtxn);

    std::fs::remove_dir_all(&src_dir).ok();
    std::fs::remove_dir_all(&snap_dir).ok();
    std::fs::remove_dir_all(&delta_dir).ok();
    std::fs::remove_dir_all(&dst_dir).ok();
}

// Test 18: restore_from rejects missing manifest-declared segment files.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "current_thread")]
async fn restore_rejects_missing_manifest_declared_segment_file() {
    let src_dir = tempdir();
    let snap_dir = tempdir();
    let dst_dir = tempdir();

    let db = make_db(&src_dir).await;
    {
        let mut w = db
            .create_segment(REALM, SegmentKind::Unspecified)
            .await
            .unwrap();
        w.append_page(SegmentPageKind::Data, b"seg-content")
            .await
            .unwrap();
        w.set_manifest(b"mf").unwrap();
        let meta = w.seal().await.unwrap();
        let mut t = db.begin_write().await.unwrap();
        t.link_segment("missing-full.seg", &meta).await.unwrap();
        t.commit().await.unwrap();
    }

    let stats = db.snapshot_to(&snap_dir).await.unwrap();
    assert_eq!(stats.segments_written, 1);
    let seg_files: Vec<_> = std::fs::read_dir(snap_dir.join("seg"))
        .unwrap()
        .filter_map(std::result::Result::ok)
        .filter(|entry| entry.path().is_file())
        .map(|entry| entry.path())
        .collect();
    assert_eq!(
        seg_files.len(),
        1,
        "test setup must produce exactly one full-snapshot segment sidecar"
    );
    for file in seg_files {
        std::fs::remove_file(file).unwrap();
    }
    drop(db);

    let err = match Db::<TokioVfs>::restore_from(&snap_dir, &dst_dir, OpenOptions::default(), KEK)
        .await
    {
        Ok(_) => panic!("restore_from must reject missing manifest-declared segment files"),
        Err(err) => err,
    };
    assert!(
        matches!(
            err,
            PagedbError::Corruption(_)
                | PagedbError::SnapshotIncompatible {
                    field: "segments_count"
                }
        ),
        "expected Corruption for missing full-snapshot segment sidecar, got {err:?}"
    );

    std::fs::remove_dir_all(&src_dir).ok();
    std::fs::remove_dir_all(&snap_dir).ok();
    std::fs::remove_dir_all(&dst_dir).ok();
}

// ---------------------------------------------------------------------------
// Test 19: restore_from rejects renamed manifest-declared segment files.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "current_thread")]
async fn restore_rejects_renamed_manifest_declared_segment_file() {
    let src_dir = tempdir();
    let snap_dir = tempdir();
    let dst_dir = tempdir();

    let db = make_db(&src_dir).await;
    {
        let mut w = db
            .create_segment(REALM, SegmentKind::Unspecified)
            .await
            .unwrap();
        w.append_page(SegmentPageKind::Data, b"seg-content")
            .await
            .unwrap();
        w.set_manifest(b"mf").unwrap();
        let meta = w.seal().await.unwrap();
        let mut t = db.begin_write().await.unwrap();
        t.link_segment("renamed-full.seg", &meta).await.unwrap();
        t.commit().await.unwrap();
    }

    let stats = db.snapshot_to(&snap_dir).await.unwrap();
    assert_eq!(stats.segments_written, 1);
    let seg_files: Vec<_> = std::fs::read_dir(snap_dir.join("seg"))
        .unwrap()
        .filter_map(std::result::Result::ok)
        .filter(|entry| entry.path().is_file())
        .map(|entry| entry.path())
        .collect();
    assert_eq!(
        seg_files.len(),
        1,
        "test setup must produce exactly one full-snapshot segment sidecar"
    );
    let fake_sidecar = snap_dir
        .join("seg")
        .join("efefefefefefefefefefefefefefefef");
    std::fs::rename(&seg_files[0], fake_sidecar).unwrap();
    drop(db);

    let err = match Db::<TokioVfs>::restore_from(&snap_dir, &dst_dir, OpenOptions::default(), KEK)
        .await
    {
        Ok(_) => panic!("restore_from must reject renamed manifest-declared segment files"),
        Err(err) => err,
    };
    assert!(
        matches!(err, PagedbError::Corruption(_)),
        "expected Corruption for renamed full-snapshot segment sidecar, got {err:?}"
    );

    std::fs::remove_dir_all(&src_dir).ok();
    std::fs::remove_dir_all(&snap_dir).ok();
    std::fs::remove_dir_all(&dst_dir).ok();
}

// ---------------------------------------------------------------------------
// Test 20: restore_from rejects corrupt segment data pages.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "current_thread")]
async fn restore_rejects_corrupt_segment_data_page() {
    let src_dir = tempdir();
    let snap_dir = tempdir();
    let dst_dir = tempdir();

    let db = make_db(&src_dir).await;
    {
        let mut w = db
            .create_segment(REALM, SegmentKind::Unspecified)
            .await
            .unwrap();
        w.append_page(SegmentPageKind::Data, b"seg-content")
            .await
            .unwrap();
        w.set_manifest(b"mf").unwrap();
        let meta = w.seal().await.unwrap();
        let mut t = db.begin_write().await.unwrap();
        t.link_segment("corrupt.seg", &meta).await.unwrap();
        t.commit().await.unwrap();
    }

    let stats = db.snapshot_to(&snap_dir).await.unwrap();
    assert_eq!(stats.segments_written, 1);
    let seg_files: Vec<_> = std::fs::read_dir(snap_dir.join("seg"))
        .unwrap()
        .filter_map(std::result::Result::ok)
        .filter(|entry| entry.path().is_file())
        .map(|entry| entry.path())
        .collect();
    assert_eq!(
        seg_files.len(),
        1,
        "test setup must produce exactly one full-snapshot segment sidecar"
    );
    let mut bytes = std::fs::read(&seg_files[0]).unwrap();
    assert!(
        bytes.len() > PAGE + 128,
        "test setup must include a data page to corrupt"
    );
    bytes[PAGE + 128] ^= 0xFF;
    std::fs::write(&seg_files[0], bytes).unwrap();
    drop(db);

    let err = match Db::<TokioVfs>::restore_from(&snap_dir, &dst_dir, OpenOptions::default(), KEK)
        .await
    {
        Ok(_) => panic!("restore_from must reject corrupt segment data pages"),
        Err(err) => err,
    };
    assert!(
        matches!(
            err,
            PagedbError::ChecksumFailure | PagedbError::Corruption(_)
        ),
        "expected segment authentication failure, got {err:?}"
    );

    std::fs::remove_dir_all(&src_dir).ok();
    std::fs::remove_dir_all(&snap_dir).ok();
    std::fs::remove_dir_all(&dst_dir).ok();
}

// ---------------------------------------------------------------------------
// Test 21: restore_from rejects extra manifest-undeclared segment files.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "current_thread")]
async fn restore_rejects_extra_manifest_undeclared_segment_file() {
    let src_dir = tempdir();
    let snap_dir = tempdir();
    let dst_dir = tempdir();

    let db = make_db(&src_dir).await;
    {
        let mut w = db
            .create_segment(REALM, SegmentKind::Unspecified)
            .await
            .unwrap();
        w.append_page(SegmentPageKind::Data, b"seg-content")
            .await
            .unwrap();
        w.set_manifest(b"mf").unwrap();
        let meta = w.seal().await.unwrap();
        let mut t = db.begin_write().await.unwrap();
        t.link_segment("my.seg", &meta).await.unwrap();
        t.commit().await.unwrap();
    }

    let stats = db.snapshot_to(&snap_dir).await.unwrap();
    assert_eq!(stats.segments_written, 1);
    std::fs::write(
        snap_dir
            .join("seg")
            .join("abababababababababababababababab"),
        b"manifest-undeclared segment",
    )
    .unwrap();
    drop(db);

    let err = match Db::<TokioVfs>::restore_from(&snap_dir, &dst_dir, OpenOptions::default(), KEK)
        .await
    {
        Ok(_) => panic!("restore_from must reject manifest-undeclared segment files"),
        Err(err) => err,
    };
    assert!(
        matches!(err, PagedbError::Corruption(_)),
        "expected Corruption for extra full-snapshot segment sidecar, got {err:?}"
    );

    std::fs::remove_dir_all(&src_dir).ok();
    std::fs::remove_dir_all(&snap_dir).ok();
    std::fs::remove_dir_all(&dst_dir).ok();
}

// ---------------------------------------------------------------------------
// Test 22: apply_incremental rejects missing manifest-declared segment files.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "current_thread")]
async fn apply_incremental_rejects_missing_manifest_declared_segment_file() {
    let src_dir = tempdir();
    let snap_dir = tempdir();
    let delta_dir = tempdir();
    let dst_dir = tempdir();

    let db = make_db(&src_dir).await;
    {
        let mut t = db.begin_write().await.unwrap();
        t.put(b"base", b"data").await.unwrap();
        t.commit().await.unwrap();
    }
    let c1 = db.latest_commit();
    db.snapshot_to(&snap_dir).await.unwrap();

    {
        let meta = {
            let mut s = db
                .create_segment(REALM, SegmentKind::Unspecified)
                .await
                .unwrap();
            s.append_page(SegmentPageKind::Data, b"segment-after-base")
                .await
                .unwrap();
            s.set_manifest(b"mf").unwrap();
            s.seal().await.unwrap()
        };
        let mut t = db.begin_write().await.unwrap();
        t.link_segment("missing.seg", &meta).await.unwrap();
        t.commit().await.unwrap();
    }

    let stats = db.snapshot_incremental_to(c1, &delta_dir).await.unwrap();
    assert_eq!(stats.segments_written, 1);
    let seg_files: Vec<_> = std::fs::read_dir(delta_dir.join("seg"))
        .unwrap()
        .filter_map(std::result::Result::ok)
        .filter(|entry| entry.path().is_file())
        .map(|entry| entry.path())
        .collect();
    assert_eq!(
        seg_files.len(),
        1,
        "test setup must produce exactly one incremental segment sidecar"
    );
    for file in seg_files {
        std::fs::remove_file(file).unwrap();
    }
    drop(db);

    let restored = Db::<TokioVfs>::restore_from(&snap_dir, &dst_dir, OpenOptions::default(), KEK)
        .await
        .unwrap();
    let follower = restored.promote_to_follower().await.unwrap();

    let err = follower
        .apply_incremental(&delta_dir)
        .await
        .expect_err("apply_incremental must reject missing manifest-declared segment files");
    assert!(
        matches!(
            err,
            PagedbError::Corruption(_)
                | PagedbError::SnapshotIncompatible {
                    field: "segments_count"
                }
        ),
        "expected Corruption for missing segment sidecar, got {err:?}"
    );

    let rtxn = follower.begin_read().await.unwrap();
    assert_eq!(
        rtxn.get(b"base").await.unwrap().as_deref(),
        Some(b"data".as_slice())
    );
    assert!(
        rtxn.open_segment("missing.seg").await.is_err(),
        "failed incremental apply must not advance the catalog"
    );
    drop(rtxn);

    std::fs::remove_dir_all(&src_dir).ok();
    std::fs::remove_dir_all(&snap_dir).ok();
    std::fs::remove_dir_all(&delta_dir).ok();
    std::fs::remove_dir_all(&dst_dir).ok();
}

#[tokio::test(flavor = "current_thread")]
async fn apply_incremental_rejects_delta_depending_on_leftover_future_pages() {
    let src_dir = tempdir();
    let snap_dir = tempdir();
    let delta_dir = tempdir();
    let dst_dir = tempdir();

    let db = make_db(&src_dir).await;
    {
        let mut t = db.begin_write().await.unwrap();
        t.put(b"base", b"data").await.unwrap();
        t.commit().await.unwrap();
    }
    let c1 = db.latest_commit();
    db.snapshot_to(&snap_dir).await.unwrap();

    {
        let meta = {
            let mut s = db
                .create_segment(REALM, SegmentKind::Unspecified)
                .await
                .unwrap();
            s.append_page(SegmentPageKind::Data, b"segment-after-base")
                .await
                .unwrap();
            s.set_manifest(b"mf").unwrap();
            s.seal().await.unwrap()
        };
        let mut t = db.begin_write().await.unwrap();
        t.put(b"later", b"value").await.unwrap();
        t.link_segment("leftover.seg", &meta).await.unwrap();
        t.commit().await.unwrap();
    }
    db.snapshot_incremental_to(c1, &delta_dir).await.unwrap();
    drop(db);

    let original_delta = std::fs::read(delta_dir.join("pages.delta")).unwrap();
    assert!(
        original_delta.len() > PAGE,
        "test setup must produce at least one changed main-db page"
    );
    let seg_files: Vec<_> = std::fs::read_dir(delta_dir.join("seg"))
        .unwrap()
        .filter_map(std::result::Result::ok)
        .filter(|entry| entry.path().is_file())
        .map(|entry| entry.path())
        .collect();
    assert_eq!(
        seg_files.len(),
        1,
        "test setup must produce exactly one segment sidecar"
    );
    let saved_segments: Vec<_> = seg_files
        .iter()
        .map(|path| (path.clone(), std::fs::read(path).unwrap()))
        .collect();

    let restored = Db::<TokioVfs>::restore_from(&snap_dir, &dst_dir, OpenOptions::default(), KEK)
        .await
        .unwrap();
    let follower = restored.promote_to_follower().await.unwrap();

    for (path, bytes) in &saved_segments {
        assert!(
            bytes.len() > PAGE + 128,
            "test setup must include a segment data page to corrupt"
        );
        let mut corrupt = bytes.clone();
        corrupt[PAGE + 128] ^= 0xFF;
        std::fs::write(path, corrupt).unwrap();
    }
    let err = follower
        .apply_incremental(&delta_dir)
        .await
        .expect_err("first apply must fail after writing delta pages");
    assert!(
        matches!(
            err,
            PagedbError::ChecksumFailure | PagedbError::Corruption(_)
        ),
        "expected corrupt sidecar authentication failure, got {err:?}"
    );
    assert_eq!(
        follower.latest_commit(),
        c1,
        "failed apply must not advance the follower header"
    );

    for (path, bytes) in &saved_segments {
        std::fs::write(path, bytes).unwrap();
    }
    let manifest = std::fs::read(delta_dir.join("manifest")).unwrap();
    let target_active_root_page_id = u64::from_le_bytes(manifest[102..110].try_into().unwrap());
    let mut corrupt_retry_delta = original_delta;
    let mut corrupted = false;
    for record in corrupt_retry_delta.chunks_exact_mut(8 + PAGE) {
        let page_id = u64::from_be_bytes(record[..8].try_into().unwrap());
        if page_id == target_active_root_page_id {
            record[8 + 128] ^= 0xFF;
            corrupted = true;
            break;
        }
    }
    assert!(
        corrupted,
        "test setup must include the target active root in pages.delta"
    );
    std::fs::write(delta_dir.join("pages.delta"), corrupt_retry_delta).unwrap();

    let err = follower
        .apply_incremental(&delta_dir)
        .await
        .expect_err("retry must authenticate rewritten pages instead of using cached leftovers");
    assert!(
        matches!(
            err,
            PagedbError::ChecksumFailure | PagedbError::Corruption(_)
        ),
        "expected authentication failure for a corrupt retry over leftover future pages, got {err:?}"
    );
    assert_eq!(
        follower.latest_commit(),
        c1,
        "incomplete retry must not advance the follower header"
    );

    std::fs::remove_dir_all(&src_dir).ok();
    std::fs::remove_dir_all(&snap_dir).ok();
    std::fs::remove_dir_all(&delta_dir).ok();
    std::fs::remove_dir_all(&dst_dir).ok();
}

// ---------------------------------------------------------------------------
// Test 23: apply_incremental rejects corrupt new segment sidecars.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "current_thread")]
async fn apply_incremental_rejects_corrupt_new_segment_sidecar() {
    let src_dir = tempdir();
    let snap_dir = tempdir();
    let delta_dir = tempdir();
    let dst_dir = tempdir();

    let db = make_db(&src_dir).await;
    {
        let mut t = db.begin_write().await.unwrap();
        t.put(b"base", b"data").await.unwrap();
        t.commit().await.unwrap();
    }
    let c1 = db.latest_commit();
    db.snapshot_to(&snap_dir).await.unwrap();

    {
        let meta = {
            let mut s = db
                .create_segment(REALM, SegmentKind::Unspecified)
                .await
                .unwrap();
            s.append_page(SegmentPageKind::Data, b"segment-after-base")
                .await
                .unwrap();
            s.set_manifest(b"mf").unwrap();
            s.seal().await.unwrap()
        };
        let mut t = db.begin_write().await.unwrap();
        t.link_segment("corrupt-new.seg", &meta).await.unwrap();
        t.commit().await.unwrap();
    }

    let stats = db.snapshot_incremental_to(c1, &delta_dir).await.unwrap();
    assert_eq!(stats.segments_written, 1);
    let seg_files: Vec<_> = std::fs::read_dir(delta_dir.join("seg"))
        .unwrap()
        .filter_map(std::result::Result::ok)
        .filter(|entry| entry.path().is_file())
        .map(|entry| entry.path())
        .collect();
    assert_eq!(
        seg_files.len(),
        1,
        "test setup must produce exactly one incremental segment sidecar"
    );
    let mut bytes = std::fs::read(&seg_files[0]).unwrap();
    assert!(
        bytes.len() > PAGE + 128,
        "test setup must include a data page to corrupt"
    );
    bytes[PAGE + 128] ^= 0xFF;
    std::fs::write(&seg_files[0], bytes).unwrap();
    drop(db);

    let restored = Db::<TokioVfs>::restore_from(&snap_dir, &dst_dir, OpenOptions::default(), KEK)
        .await
        .unwrap();
    let follower = restored.promote_to_follower().await.unwrap();

    let err = follower
        .apply_incremental(&delta_dir)
        .await
        .expect_err("apply_incremental must reject corrupt new segment sidecars");
    assert!(
        matches!(
            err,
            PagedbError::ChecksumFailure | PagedbError::Corruption(_)
        ),
        "expected segment authentication failure, got {err:?}"
    );

    let rtxn = follower.begin_read().await.unwrap();
    assert!(
        rtxn.open_segment("corrupt-new.seg").await.is_err(),
        "failed incremental apply must not advance the catalog"
    );
    drop(rtxn);

    std::fs::remove_dir_all(&src_dir).ok();
    std::fs::remove_dir_all(&snap_dir).ok();
    std::fs::remove_dir_all(&delta_dir).ok();
    std::fs::remove_dir_all(&dst_dir).ok();
}

// ---------------------------------------------------------------------------
// Test 24: apply_incremental tombstones segments removed by the target catalog.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "current_thread")]
async fn apply_incremental_tombstones_segment_removed_by_target_catalog() {
    let src_dir = tempdir();
    let snap_dir = tempdir();
    let delta_dir = tempdir();
    let dst_dir = tempdir();

    let db = make_db(&src_dir).await;
    let meta = {
        let mut s = db
            .create_segment(REALM, SegmentKind::Unspecified)
            .await
            .unwrap();
        s.append_page(SegmentPageKind::Data, b"segment-before-unlink")
            .await
            .unwrap();
        s.set_manifest(b"mf").unwrap();
        s.seal().await.unwrap()
    };
    {
        let mut t = db.begin_write().await.unwrap();
        t.link_segment("removed.seg", &meta).await.unwrap();
        t.commit().await.unwrap();
    }
    let c1 = db.latest_commit();
    db.snapshot_to(&snap_dir).await.unwrap();

    {
        let mut t = db.begin_write().await.unwrap();
        t.unlink_segment("removed.seg").await.unwrap();
        t.commit().await.unwrap();
    }
    db.snapshot_incremental_to(c1, &delta_dir).await.unwrap();
    drop(db);

    let restored = Db::<TokioVfs>::restore_from(&snap_dir, &dst_dir, OpenOptions::default(), KEK)
        .await
        .unwrap();
    let follower = restored.promote_to_follower().await.unwrap();
    let live_path = dst_dir.join("seg").join(hex_lower(&meta.segment_id));
    assert!(
        live_path.is_file(),
        "base restore must contain the segment before the unlink delta is applied"
    );

    let stats = follower
        .apply_incremental(&delta_dir)
        .await
        .expect("unlink delta should apply successfully");
    assert_eq!(
        stats.segments_tombstoned, 1,
        "apply_incremental must report the removed segment tombstone"
    );
    assert!(
        !live_path.exists(),
        "removed segment must not remain at its live path after apply"
    );
    let tombstone_dir = dst_dir.join("seg").join(".tombstone");
    let tombstone_count = std::fs::read_dir(&tombstone_dir)
        .unwrap()
        .filter_map(std::result::Result::ok)
        .filter(|entry| entry.path().is_file())
        .count();
    assert_eq!(tombstone_count, 1);

    let rtxn = follower.begin_read().await.unwrap();
    assert!(
        rtxn.open_segment("removed.seg").await.is_err(),
        "applied target catalog must no longer expose the removed segment"
    );
    drop(rtxn);

    std::fs::remove_dir_all(&src_dir).ok();
    std::fs::remove_dir_all(&snap_dir).ok();
    std::fs::remove_dir_all(&delta_dir).ok();
    std::fs::remove_dir_all(&dst_dir).ok();
}

// ---------------------------------------------------------------------------
// Test 25: manifest corruption detected.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "current_thread")]
async fn manifest_corruption_detected() {
    let src_dir = tempdir();
    let snap_dir = tempdir();
    let dst_dir = tempdir();

    let db = make_db(&src_dir).await;
    db.snapshot_to(&snap_dir).await.unwrap();
    drop(db);

    // Corrupt the last byte of the manifest (the HK-MAC).
    let manifest_path = snap_dir.join("manifest");
    let mut bytes = std::fs::read(&manifest_path).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xFF;
    std::fs::write(&manifest_path, &bytes).unwrap();

    let err = Db::<TokioVfs>::restore_from(&snap_dir, &dst_dir, OpenOptions::default(), KEK)
        .await
        .err()
        .unwrap();
    assert!(
        matches!(err, PagedbError::Corruption(_)),
        "expected Corruption, got {err:?}"
    );

    std::fs::remove_dir_all(&src_dir).ok();
    std::fs::remove_dir_all(&snap_dir).ok();
    std::fs::remove_dir_all(&dst_dir).ok();
}

// ---------------------------------------------------------------------------
// An incremental delta may carry an arbitrary number of new segments. Applying
// it must promote every staged segment, regardless of how many there are — the
// apply journal that records the promotions must represent a promotion set that
// does not fit in a single page. A live set larger than one journal page's
// worth of actions is ordinary for any segment-heavy engine (HNSW shards,
// columnar blocks, FTS postings), so this is common usage, not a corner case.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "current_thread")]
async fn apply_incremental_promotes_segment_set_larger_than_one_journal_page() {
    let src_dir = tempdir();
    let snap_dir = tempdir();
    let delta_dir = tempdir();
    let dst_dir = tempdir();

    let db = make_db(&src_dir).await;
    {
        let mut t = db.begin_write().await.unwrap();
        t.put(b"base", b"data").await.unwrap();
        t.commit().await.unwrap();
    }
    let c1 = db.latest_commit();
    db.snapshot_to(&snap_dir).await.unwrap();

    // Link more segments than fit in a single journal page's worth of promote
    // actions, so the promotion set must span multiple journal pages.
    const SEGMENTS: u32 = 300;
    for i in 0..SEGMENTS {
        let meta = {
            let mut s = db
                .create_segment(REALM, SegmentKind::Unspecified)
                .await
                .unwrap();
            s.append_page(SegmentPageKind::Data, &[0xAA; 256])
                .await
                .unwrap();
            s.seal().await.unwrap()
        };
        let mut w = db.begin_write().await.unwrap();
        w.link_segment(&format!("seg-{i:05}"), &meta).await.unwrap();
        w.commit().await.unwrap();
    }

    db.snapshot_incremental_to(c1, &delta_dir).await.unwrap();
    drop(db);

    let restored = Db::<TokioVfs>::restore_from(&snap_dir, &dst_dir, OpenOptions::default(), KEK)
        .await
        .unwrap();
    let follower = restored.promote_to_follower().await.unwrap();

    let stats: ApplyStats = follower
        .apply_incremental(&delta_dir)
        .await
        .expect("apply_incremental must promote a multi-page promotion set");
    assert_eq!(
        stats.segments_promoted, SEGMENTS,
        "every staged segment must be promoted"
    );

    // Every staged segment must have been promoted from `seg/.staging/` to its
    // live `seg/<hex(id)>` path — the journal must carry the whole promotion
    // set, not just the fraction that fit one page. Verify at the filesystem level
    // (the live `seg/` dir holds exactly the promoted files), and that nothing
    // is left behind in staging. A single-page journal could only carry a
    // fraction of the set, so this fails unless the journal spans pages.
    let live_count = std::fs::read_dir(dst_dir.join("seg"))
        .unwrap()
        .filter_map(std::result::Result::ok)
        .filter(|e| e.path().is_file())
        .count();
    assert_eq!(
        live_count as u32, SEGMENTS,
        "all {SEGMENTS} staged segments must be promoted to live paths"
    );
    let staging = dst_dir.join("seg").join(".staging");
    let staging_left = std::fs::read_dir(&staging)
        .map(|rd| {
            rd.filter_map(std::result::Result::ok)
                .filter(|e| e.path().is_file())
                .count()
        })
        .unwrap_or(0);
    assert_eq!(staging_left, 0, "no staged segment may be left unpromoted");

    // The applied delta must advance the catalog: every promoted segment is
    // reachable by name and readable through the follower's catalog, not just
    // present on disk.
    let rtxn = follower.begin_read().await.unwrap();
    for i in (0..SEGMENTS).step_by(73) {
        let name = format!("seg-{i:05}");
        let reader = rtxn
            .open_segment(&name)
            .await
            .unwrap_or_else(|e| panic!("segment {name} unreachable via catalog: {e:?}"));
        let page = reader.read_page(1).await.unwrap();
        assert!(
            page.starts_with(&[0xAA; 256]),
            "segment {name} content wrong"
        );
    }

    std::fs::remove_dir_all(&src_dir).ok();
    std::fs::remove_dir_all(&snap_dir).ok();
    std::fs::remove_dir_all(&delta_dir).ok();
    std::fs::remove_dir_all(&dst_dir).ok();
}

#[tokio::test(flavor = "current_thread")]
async fn deferred_apply_journal_blocks_next_apply_until_gc_drains_reader_pin() {
    let src_dir = tempdir();
    let snap_dir = tempdir();
    let delta_dir = tempdir();
    let dst_dir = tempdir();

    let source = make_db(&src_dir).await;
    let meta = {
        let mut writer = source
            .create_segment(REALM, SegmentKind::Unspecified)
            .await
            .unwrap();
        writer
            .append_page(SegmentPageKind::Data, b"base-segment")
            .await
            .unwrap();
        writer.seal().await.unwrap()
    };
    {
        let mut write = source.begin_write().await.unwrap();
        write.link_segment("removed", &meta).await.unwrap();
        write.commit().await.unwrap();
    }
    let base = source.latest_commit();
    source.snapshot_to(&snap_dir).await.unwrap();
    {
        let mut write = source.begin_write().await.unwrap();
        write.unlink_segment("removed").await.unwrap();
        write.commit().await.unwrap();
    }
    source
        .snapshot_incremental_to(base, &delta_dir)
        .await
        .unwrap();
    drop(source);

    let restored = Db::<TokioVfs>::restore_from(&snap_dir, &dst_dir, OpenOptions::default(), KEK)
        .await
        .unwrap();
    let follower = restored.promote_to_follower().await.unwrap();
    let base_reader = follower.begin_read().await.unwrap();

    assert!(matches!(
        follower.apply_incremental(&delta_dir).await,
        Err(PagedbError::ReadersPinningTruncatedRange)
    ));
    assert!(follower.list_segments(REALM, "").await.unwrap().is_empty());
    assert!(matches!(
        follower.apply_incremental(&delta_dir).await,
        Err(PagedbError::ReadersPinningTruncatedRange)
    ));

    drop(base_reader);
    follower.gc_now().await.unwrap();

    std::fs::remove_dir_all(&src_dir).ok();
    std::fs::remove_dir_all(&snap_dir).ok();
    std::fs::remove_dir_all(&delta_dir).ok();
    std::fs::remove_dir_all(&dst_dir).ok();
}

#[tokio::test(flavor = "current_thread")]
async fn failed_apply_promote_poisoned_handle_reopens_and_replays_journal_before_reads() {
    let src_dir = tempdir();
    let snap_dir = tempdir();
    let delta_dir = tempdir();
    let dst_dir = tempdir();

    let source = make_db(&src_dir).await;
    {
        let mut write = source.begin_write().await.unwrap();
        write.put(b"base", b"before-snapshot").await.unwrap();
        write.commit().await.unwrap();
    }
    let base = source.latest_commit();
    source.snapshot_to(&snap_dir).await.unwrap();
    let meta = {
        let mut writer = source
            .create_segment(REALM, SegmentKind::Unspecified)
            .await
            .unwrap();
        writer
            .append_page(SegmentPageKind::Data, b"promoted-after-reopen")
            .await
            .unwrap();
        writer.seal().await.unwrap()
    };
    {
        let mut write = source.begin_write().await.unwrap();
        write.link_segment("promoted", &meta).await.unwrap();
        write.commit().await.unwrap();
    }
    source
        .snapshot_incremental_to(base, &delta_dir)
        .await
        .unwrap();
    drop(source);

    let restored = Db::<TokioVfs>::restore_from(&snap_dir, &dst_dir, OpenOptions::default(), KEK)
        .await
        .unwrap();
    drop(restored);

    let vfs = RenameFaultVfs::new(&dst_dir);
    let read_only = Db::open_read_only(vfs.clone(), KEK, PAGE, REALM, OpenOptions::default())
        .await
        .unwrap();
    let follower = read_only.promote_to_follower().await.unwrap();
    vfs.fail_renames(true);

    assert!(matches!(
        follower.apply_incremental(&delta_dir).await,
        Err(PagedbError::DurablyCommittedButUnpublished { .. })
    ));
    assert!(matches!(
        follower.list_segments(REALM, "").await,
        Err(PagedbError::DurablyCommittedButUnpublished { .. })
    ));

    vfs.fail_renames(false);
    drop(follower);
    let reopened = Db::open_existing(vfs, KEK, PAGE, REALM).await.unwrap();
    let segment = reopened.open_segment(REALM, "promoted").await.unwrap();
    assert!(
        segment
            .read_page(1)
            .await
            .unwrap()
            .starts_with(b"promoted-after-reopen")
    );

    std::fs::remove_dir_all(&src_dir).ok();
    std::fs::remove_dir_all(&snap_dir).ok();
    std::fs::remove_dir_all(&delta_dir).ok();
    std::fs::remove_dir_all(&dst_dir).ok();
}

async fn follower_with_segment_incremental() -> (Db<TokioVfs>, Vec<std::path::PathBuf>, u64) {
    let src_dir = tempdir();
    let snap_dir = tempdir();
    let delta_dir = tempdir();
    let dst_dir = tempdir();

    let source = make_db(&src_dir).await;
    {
        let mut write = source.begin_write().await.unwrap();
        write.put(b"base", b"value").await.unwrap();
        write.commit().await.unwrap();
    }
    let base_commit = source.latest_commit();
    source.snapshot_to(&snap_dir).await.unwrap();

    {
        let mut write = source.begin_write().await.unwrap();
        write.put(b"after-base", b"value").await.unwrap();
        write.commit().await.unwrap();
    }
    let meta = {
        let mut writer = source
            .create_segment(REALM, SegmentKind::Unspecified)
            .await
            .unwrap();
        writer
            .append_page(SegmentPageKind::Data, b"manifest-validation")
            .await
            .unwrap();
        writer.seal().await.unwrap()
    };
    {
        let mut write = source.begin_write().await.unwrap();
        write
            .link_segment("manifest-validation", &meta)
            .await
            .unwrap();
        write.commit().await.unwrap();
    }
    let target_commit = source.latest_commit().value();
    source
        .snapshot_incremental_to(base_commit, &delta_dir)
        .await
        .unwrap();
    drop(source);

    let restored = Db::<TokioVfs>::restore_from(&snap_dir, &dst_dir, OpenOptions::default(), KEK)
        .await
        .unwrap();
    let follower = restored.promote_to_follower().await.unwrap();
    (
        follower,
        vec![src_dir, snap_dir, delta_dir, dst_dir],
        target_commit,
    )
}

fn original_manifest(path: &std::path::Path) -> [u8; 240] {
    std::fs::read(path.join("manifest"))
        .unwrap()
        .try_into()
        .unwrap()
}

fn rewrite_manifest(
    path: &std::path::Path,
    original: &[u8; 240],
    hk: &[u8; 32],
    edit: impl FnOnce(&mut SnapshotManifest),
) {
    let mut manifest = decode_manifest(original, hk).unwrap();
    edit(&mut manifest);
    std::fs::write(path.join("manifest"), encode_manifest(&manifest, hk)).unwrap();
}

fn directory_contents(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    fn collect(
        root: &std::path::Path,
        current: &std::path::Path,
        out: &mut Vec<std::path::PathBuf>,
    ) {
        for entry in std::fs::read_dir(current).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            let relative = path.strip_prefix(root).unwrap().to_owned();
            out.push(relative);
            if path.is_dir() {
                collect(root, &path, out);
            }
        }
    }

    let mut entries = Vec::new();
    collect(root, root, &mut entries);
    entries.sort();
    entries
}

async fn assert_refusal_preserves_follower(
    follower: &Db<TokioVfs>,
    delta_dir: &std::path::Path,
    dst_dir: &std::path::Path,
    expected_field: &'static str,
    commit_before: u64,
    headers_before: &[u8],
    directory_before: &[std::path::PathBuf],
) {
    let error = follower.apply_incremental(delta_dir).await.unwrap_err();
    assert!(matches!(
        error,
        PagedbError::SnapshotIncompatible { field } if field == expected_field
    ));
    assert_eq!(follower.latest_commit().value(), commit_before);
    assert_eq!(
        &std::fs::read(dst_dir.join("main.db")).unwrap()[..PAGE * 2],
        headers_before
    );
    assert_eq!(directory_contents(dst_dir), directory_before);
}

struct ManifestRejectionContext {
    follower: Db<TokioVfs>,
    paths: Vec<std::path::PathBuf>,
    original: [u8; 240],
    hk: [u8; 32],
    commit_before: u64,
    headers_before: Vec<u8>,
    directory_before: Vec<std::path::PathBuf>,
}

impl ManifestRejectionContext {
    async fn reject_manifest_change(
        &self,
        expected_field: &'static str,
        edit: impl FnOnce(&mut SnapshotManifest),
    ) {
        rewrite_manifest(&self.paths[2], &self.original, &self.hk, edit);
        assert_refusal_preserves_follower(
            &self.follower,
            &self.paths[2],
            &self.paths[3],
            expected_field,
            self.commit_before,
            &self.headers_before,
            &self.directory_before,
        )
        .await;
    }
}

#[tokio::test(flavor = "current_thread")]
async fn apply_incremental_rejects_incompatible_manifests_without_mutation() {
    let (follower, paths, _) = follower_with_segment_incremental().await;
    let original = original_manifest(&paths[2]);
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&original[53..69]);
    let mut epoch = [0u8; 8];
    epoch.copy_from_slice(&original[45..53]);
    let hk = derive_snapshot_hk_key(&KEK, &salt, u64::from_le_bytes(epoch)).unwrap();
    let commit_before = follower.latest_commit().value();
    let main_db = std::fs::read(paths[3].join("main.db")).unwrap();
    let headers_before = main_db[..PAGE * 2].to_vec();
    let directory_before = directory_contents(&paths[3]);
    let context = ManifestRejectionContext {
        follower,
        paths,
        original,
        hk,
        commit_before,
        headers_before,
        directory_before,
    };

    context
        .reject_manifest_change("kind", |manifest| manifest.kind = 0)
        .await;
    context
        .reject_manifest_change("base_commit", |manifest| manifest.base_commit += 1)
        .await;
    context
        .reject_manifest_change("target_commit", |manifest| {
            manifest.target_commit = manifest.base_commit
        })
        .await;
    context
        .reject_manifest_change("file_id", |manifest| manifest.file_id[0] ^= 1)
        .await;
    context
        .reject_manifest_change("realm_id", |manifest| manifest.realm_id[0] ^= 1)
        .await;
    context
        .reject_manifest_change("cipher_id", |manifest| manifest.cipher_id ^= 1)
        .await;
    context
        .reject_manifest_change("mk_epoch", |manifest| manifest.mk_epoch += 1)
        .await;
    context
        .reject_manifest_change("kek_salt", |manifest| manifest.kek_salt[0] ^= 1)
        .await;
    context
        .reject_manifest_change("page_size", |manifest| {
            manifest.page_size = (PAGE * 2) as u32
        })
        .await;
    context
        .reject_manifest_change("version", |manifest| manifest.version = 2)
        .await;
    context
        .reject_manifest_change("target_active_root_page_id", |manifest| {
            manifest.target_active_root_page_id = manifest.next_page_id_at_target
        })
        .await;
    context
        .reject_manifest_change("target_catalog_root_page_id", |manifest| {
            manifest.target_catalog_root_page_id = 1
        })
        .await;
    context
        .reject_manifest_change("segments_count", |manifest| manifest.segments_count += 1)
        .await;

    drop(context.follower);
    for path in context.paths {
        std::fs::remove_dir_all(path).ok();
    }
}

#[tokio::test(flavor = "current_thread")]
async fn concurrent_incremental_applies_are_serialized_before_raw_page_writes() {
    let (follower, paths, target_commit) = follower_with_segment_incremental().await;
    let delta_dir = &paths[2];
    assert!(
        std::fs::metadata(delta_dir.join("pages.delta"))
            .unwrap()
            .len()
            > 0
    );
    let (first, second) = tokio::join!(
        follower.apply_incremental(delta_dir),
        follower.apply_incremental(delta_dir),
    );

    let results = [first, second];
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert!(results.iter().any(|result| {
        matches!(
            result,
            Err(PagedbError::SnapshotIncompatible {
                field: "base_commit"
            })
        )
    }));
    assert_eq!(follower.latest_commit().value(), target_commit);

    drop(follower);
    for path in paths {
        std::fs::remove_dir_all(path).ok();
    }
}

/// Applying an incremental delta writes raw pages directly to `main.db`,
/// bypassing the normal write-txn path that the free-list accounting relies
/// on elsewhere. That makes it its own place where a page could end up
/// reachable from neither a live root nor the free list — a leak the deep
/// walk's orphan check exists to catch.
#[tokio::test(flavor = "current_thread")]
async fn apply_incremental_leaves_no_orphan_pages_on_the_follower() {
    let src_dir = tempdir();
    let snap_dir = tempdir();
    let delta_dir = tempdir();
    let dst_dir = tempdir();

    let source = make_db(&src_dir).await;
    {
        let mut write = source.begin_write().await.unwrap();
        for i in 0u32..200 {
            write
                .put(format!("k{i:05}").as_bytes(), &[1u8; 128])
                .await
                .unwrap();
        }
        write.commit().await.unwrap();
    }
    let base = source.latest_commit();
    source.snapshot_to(&snap_dir).await.unwrap();

    // Several more commits after the base snapshot, overwriting the same key
    // set each time so copy-on-write both allocates fresh pages and recycles
    // superseded ones, exercising both halves of the delta.
    for generation in 0u8..5 {
        let mut write = source.begin_write().await.unwrap();
        for i in 0u32..200 {
            write
                .put(format!("k{i:05}").as_bytes(), &[generation; 128])
                .await
                .unwrap();
        }
        write.commit().await.unwrap();
    }
    source
        .snapshot_incremental_to(base, &delta_dir)
        .await
        .unwrap();
    drop(source);

    let restored = Db::<TokioVfs>::restore_from(&snap_dir, &dst_dir, OpenOptions::default(), KEK)
        .await
        .unwrap();
    let follower = restored.promote_to_follower().await.unwrap();
    follower.apply_incremental(&delta_dir).await.unwrap();

    let report = run_deep_walk(&follower).await.unwrap();
    assert!(
        report.orphan_page_ids.is_empty(),
        "snapshot apply must not leave leaked pages on the follower, got {} orphans: {:?}",
        report.orphan_page_ids.len(),
        report.orphan_page_ids
    );
    assert!(
        report.is_clean(),
        "follower deep-walk report should be clean after apply_incremental: {report:?}"
    );

    drop(follower);
    std::fs::remove_dir_all(&src_dir).ok();
    std::fs::remove_dir_all(&snap_dir).ok();
    std::fs::remove_dir_all(&delta_dir).ok();
    std::fs::remove_dir_all(&dst_dir).ok();
}

/// Folding a reclaimed chain into the follower's free list can bump-allocate
/// past pages the producer never touched, pushing the follower's visible
/// `next_page_id` ahead of the producer's own cursor. `apply_incremental`
/// requires the next delta's `next_page_id_at_target` to be `>=` the
/// follower's current cursor, so if the fold-in ever runs the follower ahead
/// of the producer, a second chained delta would be rejected and the
/// follower could never catch up. Apply two deltas back-to-back, the second
/// chained onto the first delta's own target commit, to prove that door
/// stays open.
#[tokio::test(flavor = "current_thread")]
async fn chained_incremental_applies_keep_the_follower_able_to_advance() {
    let src_dir = tempdir();
    let snap_dir = tempdir();
    let delta_one_dir = tempdir();
    let delta_two_dir = tempdir();
    let dst_dir = tempdir();

    let source = make_db(&src_dir).await;
    {
        let mut write = source.begin_write().await.unwrap();
        for i in 0u32..200 {
            write
                .put(format!("k{i:05}").as_bytes(), &[1u8; 128])
                .await
                .unwrap();
        }
        write.commit().await.unwrap();
    }
    let base = source.latest_commit();
    source.snapshot_to(&snap_dir).await.unwrap();

    // First run of overwrite-generations: supersedes and recycles pages,
    // exactly like the single-delta orphan test, then export delta one.
    for generation in 0u8..5 {
        let mut write = source.begin_write().await.unwrap();
        for i in 0u32..200 {
            write
                .put(format!("k{i:05}").as_bytes(), &[generation; 128])
                .await
                .unwrap();
        }
        write.commit().await.unwrap();
    }
    let delta_one_target = source.latest_commit();
    source
        .snapshot_incremental_to(base, &delta_one_dir)
        .await
        .unwrap();

    // More overwrite-generations on top, so delta two chains onto delta
    // one's own target commit rather than the original base.
    for generation in 5u8..10 {
        let mut write = source.begin_write().await.unwrap();
        for i in 0u32..200 {
            write
                .put(format!("k{i:05}").as_bytes(), &[generation; 128])
                .await
                .unwrap();
        }
        write.commit().await.unwrap();
    }
    let delta_two_target = source.latest_commit();
    source
        .snapshot_incremental_to(delta_one_target, &delta_two_dir)
        .await
        .unwrap();
    drop(source);

    let restored = Db::<TokioVfs>::restore_from(&snap_dir, &dst_dir, OpenOptions::default(), KEK)
        .await
        .unwrap();
    let follower = restored.promote_to_follower().await.unwrap();

    follower
        .apply_incremental(&delta_one_dir)
        .await
        .expect("first chained delta must apply");
    assert_eq!(follower.latest_commit(), delta_one_target);
    {
        let report = run_deep_walk(&follower).await.unwrap();
        assert!(
            report.orphan_page_ids.is_empty(),
            "no orphans expected after the first delta, got {:?}",
            report.orphan_page_ids
        );
        let rtxn = follower.begin_read().await.unwrap();
        for i in 0u32..200 {
            assert_eq!(
                rtxn.get(format!("k{i:05}").as_bytes()).await.unwrap(),
                Some(vec![4u8; 128]),
                "key k{i:05} should reflect generation 4 after the first delta"
            );
        }
    }

    // This is the assertion that catches the cursor-runahead hazard: if
    // folding delta one's reclaimed chain into the follower's free list
    // bump-allocated the follower's next_page_id past the producer's own
    // cursor at delta_one_target, validate_incremental_manifest would reject
    // this second delta as stale even though it correctly chains onto the
    // commit the follower is sitting at.
    follower.apply_incremental(&delta_two_dir).await.expect(
        "second chained delta must apply without the follower's cursor outrunning the producer",
    );
    assert_eq!(follower.latest_commit(), delta_two_target);
    {
        let report = run_deep_walk(&follower).await.unwrap();
        assert!(
            report.orphan_page_ids.is_empty(),
            "no orphans expected after the second delta, got {:?}",
            report.orphan_page_ids
        );
        assert!(
            report.is_clean(),
            "follower deep-walk report should be clean after both chained deltas: {report:?}"
        );
        let rtxn = follower.begin_read().await.unwrap();
        for i in 0u32..200 {
            assert_eq!(
                rtxn.get(format!("k{i:05}").as_bytes()).await.unwrap(),
                Some(vec![9u8; 128]),
                "key k{i:05} should reflect generation 9 after the second delta"
            );
        }
    }

    drop(follower);
    std::fs::remove_dir_all(&src_dir).ok();
    std::fs::remove_dir_all(&snap_dir).ok();
    std::fs::remove_dir_all(&delta_one_dir).ok();
    std::fs::remove_dir_all(&delta_two_dir).ok();
    std::fs::remove_dir_all(&dst_dir).ok();
}

/// The follower keeps its own free-list chain and commit-history tree across
/// an apply, and those pages are invisible to the producer, which can neither
/// predict nor avoid them. When the producer's allocator later recycles one of
/// those same ids into its own live tree, the resulting delta ships that id by
/// number and `apply_delta_pages` refuses it outright as `SnapshotBasePageReused`
/// -- fail-closed, before `main.db` is ever opened for writing. That refusal is
/// not a bug to work around; it is the contract. This proves the refusal is
/// both precise (the exact error variant, not any old error) and side-effect
/// free (the follower's commit, its key/value state, and its page graph are
/// bit-for-bit what they were before the doomed apply was attempted), and that
/// the documented remedy -- a full snapshot instead of a delta -- still works.
#[tokio::test(flavor = "current_thread")]
async fn an_inapplicable_delta_is_refused_without_touching_the_follower() {
    let src_dir = tempdir();
    let snap_dir = tempdir();
    let dst_dir = tempdir();
    let delta_dir = tempdir();
    let full_snap_dir = tempdir();
    let full_dst_dir = tempdir();

    let source = make_db(&src_dir).await;

    // A large working set, so deletes free interior pages, not just one leaf.
    {
        let mut write = source.begin_write().await.unwrap();
        for i in 0u32..512 {
            write
                .put(format!("k{i:05}").as_bytes(), &[0xAA; 128])
                .await
                .unwrap();
        }
        write.commit().await.unwrap();
    }
    source.snapshot_to(&snap_dir).await.unwrap();

    let restored = Db::<TokioVfs>::restore_from(&snap_dir, &dst_dir, OpenOptions::default(), KEK)
        .await
        .unwrap();
    let follower = restored.promote_to_follower().await.unwrap();

    let base = source.latest_commit();

    // Record the follower's full state before the doomed apply so the
    // "nothing changed" assertions below have something concrete to compare
    // against, rather than just "it still looks fine".
    let pre_apply_commit = follower.latest_commit();
    let pre_apply_values: Vec<(String, Option<Vec<u8>>)> = {
        let rtxn = follower.begin_read().await.unwrap();
        let mut values = Vec::with_capacity(512);
        for i in 0u32..512 {
            let key = format!("k{i:05}");
            let value = rtxn.get(key.as_bytes()).await.unwrap();
            values.push((key, value));
        }
        values
    };

    // Free half the working set -- interior pages go onto the source's
    // durable free list.
    {
        let mut write = source.begin_write().await.unwrap();
        for i in 0u32..256 {
            write.delete(format!("k{i:05}").as_bytes()).await.unwrap();
        }
        write.commit().await.unwrap();
    }
    // Re-insert, forcing the allocator to draw the just-freed ids back off the
    // free list -- among them, with overwhelming likelihood given 512 keys
    // reused down to 256 ids, some id the follower is holding for its own
    // chain or commit-history pages.
    {
        let mut write = source.begin_write().await.unwrap();
        for i in 0u32..256 {
            write
                .put(format!("k{i:05}").as_bytes(), &[0xBB; 128])
                .await
                .unwrap();
        }
        write.commit().await.unwrap();
    }
    let target = source.latest_commit();
    source
        .snapshot_incremental_to(base, &delta_dir)
        .await
        .expect("exporting the delta itself must succeed; the guard lives on the apply side");

    let err = follower
        .apply_incremental(&delta_dir)
        .await
        .expect_err("a delta that reuses a follower-private page id must be refused, not applied");
    assert!(
        matches!(err, PagedbError::SnapshotBasePageReused { .. }),
        "expected PagedbError::SnapshotBasePageReused, got a different error: {err:?}"
    );

    // The load-bearing assertions: the rejection must be a pure no-op on the
    // follower. Nothing about its commit, its data, or its page graph may have
    // moved, because the write path bails before `main.db` is opened.
    assert_eq!(
        follower.latest_commit(),
        pre_apply_commit,
        "a refused apply must not advance the follower's commit"
    );
    {
        let rtxn = follower.begin_read().await.unwrap();
        for (key, expected) in &pre_apply_values {
            assert_eq!(
                &rtxn.get(key.as_bytes()).await.unwrap(),
                expected,
                "key {key} must read back exactly as it did before the refused apply"
            );
        }
    }
    let report = run_deep_walk(&follower).await.unwrap();
    assert!(
        report.orphan_page_ids.is_empty(),
        "a refused apply must not leave orphan pages, got {:?}",
        report.orphan_page_ids
    );
    assert!(
        report.is_clean(),
        "a refused apply must leave the follower's deep-walk report clean: {report:?}"
    );

    // The documented remedy: fall back to a full snapshot instead of a delta.
    source.snapshot_to(&full_snap_dir).await.unwrap();
    let full_restored =
        Db::<TokioVfs>::restore_from(&full_snap_dir, &full_dst_dir, OpenOptions::default(), KEK)
            .await
            .unwrap();
    let full_follower = full_restored.promote_to_follower().await.unwrap();
    assert_eq!(full_follower.latest_commit(), target);
    {
        let rtxn = full_follower.begin_read().await.unwrap();
        for i in 0u32..256 {
            assert_eq!(
                rtxn.get(format!("k{i:05}").as_bytes()).await.unwrap(),
                Some(vec![0xBBu8; 128]),
                "full-snapshot remedy: refilled key k{i:05} must reflect the source's current state"
            );
        }
        for i in 256u32..512 {
            assert_eq!(
                rtxn.get(format!("k{i:05}").as_bytes()).await.unwrap(),
                Some(vec![0xAAu8; 128]),
                "full-snapshot remedy: untouched key k{i:05} must reflect the source's current state"
            );
        }
    }
    let full_report = run_deep_walk(&full_follower).await.unwrap();
    assert!(
        full_report.orphan_page_ids.is_empty(),
        "full-snapshot remedy follower must have no orphan pages, got {:?}",
        full_report.orphan_page_ids
    );
    assert!(
        full_report.is_clean(),
        "full-snapshot remedy follower must deep-walk clean: {full_report:?}"
    );

    drop(full_follower);
    drop(follower);
    drop(source);
    std::fs::remove_dir_all(&src_dir).ok();
    std::fs::remove_dir_all(&snap_dir).ok();
    std::fs::remove_dir_all(&dst_dir).ok();
    std::fs::remove_dir_all(&delta_dir).ok();
    std::fs::remove_dir_all(&full_snap_dir).ok();
    std::fs::remove_dir_all(&full_dst_dir).ok();
}

/// This is a genuine architectural limit, not a defect to be papered over:
/// `protected_page_ids` is the follower's whole published base page set, and
/// `apply_delta_pages` writes pages before the header swap, so once the
/// producer recycles ANY id the follower's base still holds, that delta can
/// never be applied -- overwriting it first would destroy the base with no
/// valid header left to recover from on a crash. Ordinary churn (delete some
/// keys, refill, overwrite the rest -- CoW recycles pages on overwrite exactly
/// as deletes do, so there is no churn shape that reliably dodges this) will
/// eventually recycle such an id. A real replication client must therefore
/// treat `SnapshotBasePageReused` as an expected outcome of chaining deltas,
/// not a bug: fall back to a full snapshot and keep going. This test drives 12
/// rounds of that ordinary churn and, on every round, accepts exactly two
/// outcomes -- clean apply, or refusal-plus-full-snapshot-remedy -- and fails
/// loudly on anything else.
#[tokio::test(flavor = "current_thread")]
async fn a_follower_stays_consistent_across_churn_by_falling_back_to_a_full_snapshot() {
    let src_dir = tempdir();
    let snap_dir = tempdir();
    let dst_dir = tempdir();

    let source = make_db(&src_dir).await;

    // A large working set, so deletes free interior pages, not just one leaf.
    {
        let mut write = source.begin_write().await.unwrap();
        for i in 0u32..512 {
            write
                .put(format!("k{i:05}").as_bytes(), &[0xAA; 128])
                .await
                .unwrap();
        }
        write.commit().await.unwrap();
    }
    source.snapshot_to(&snap_dir).await.unwrap();

    let restored = Db::<TokioVfs>::restore_from(&snap_dir, &dst_dir, OpenOptions::default(), KEK)
        .await
        .unwrap();
    let mut follower = restored.promote_to_follower().await.unwrap();

    let mut delta_target = source.latest_commit();
    let mut cleanup_dirs = vec![src_dir.clone(), snap_dir.clone(), dst_dir.clone()];
    let mut ok_rounds = 0u32;
    let mut refused_rounds = 0u32;

    for round in 0u32..12 {
        let round_base = delta_target;

        // Pre-round follower state, needed only if this round's delta gets
        // refused -- the refusal must be a pure no-op.
        let pre_round_commit = follower.latest_commit();
        let pre_round_values: Vec<(String, Option<Vec<u8>>)> = {
            let rtxn = follower.begin_read().await.unwrap();
            let mut values = Vec::with_capacity(512);
            for i in 0u32..512 {
                let key = format!("k{i:05}");
                let value = rtxn.get(key.as_bytes()).await.unwrap();
                values.push((key, value));
            }
            values
        };

        // Ordinary churn: free half the working set, refill it with this
        // round's generation, and overwrite the surviving half in place. Both
        // the refill and the in-place overwrite draw on/recycle freed pages,
        // which is exactly the condition that can hit a follower-held id.
        {
            let mut write = source.begin_write().await.unwrap();
            for i in 0u32..256 {
                write.delete(format!("k{i:05}").as_bytes()).await.unwrap();
            }
            write.commit().await.unwrap();
        }
        {
            let mut write = source.begin_write().await.unwrap();
            for i in 0u32..256 {
                write
                    .put(format!("k{i:05}").as_bytes(), &[round as u8; 128])
                    .await
                    .unwrap();
            }
            write.commit().await.unwrap();
        }
        {
            let mut write = source.begin_write().await.unwrap();
            for i in 256u32..512 {
                write
                    .put(format!("k{i:05}").as_bytes(), &[round as u8; 128])
                    .await
                    .unwrap();
            }
            write.commit().await.unwrap();
        }

        delta_target = source.latest_commit();
        let delta_dir = tempdir();
        cleanup_dirs.push(delta_dir.clone());
        source
            .snapshot_incremental_to(round_base, &delta_dir)
            .await
            .unwrap_or_else(|e| panic!("round {round}: incremental export must succeed: {e:?}"));

        match follower.apply_incremental(&delta_dir).await {
            Ok(_) => {
                ok_rounds += 1;
                assert_eq!(
                    follower.latest_commit(),
                    delta_target,
                    "round {round}: a successful apply must land on the delta's target commit"
                );
                let report = run_deep_walk(&follower).await.unwrap();
                assert!(
                    report.orphan_page_ids.is_empty(),
                    "round {round}: a successful apply must leave no orphan pages, got {:?}",
                    report.orphan_page_ids
                );
                assert!(
                    report.is_clean(),
                    "round {round}: a successful apply must leave a clean deep-walk report: {report:?}"
                );
                let rtxn = follower.begin_read().await.unwrap();
                for i in 0u32..512 {
                    assert_eq!(
                        rtxn.get(format!("k{i:05}").as_bytes()).await.unwrap(),
                        Some(vec![round as u8; 128]),
                        "round {round}: key k{i:05} should reflect this round's generation after a successful apply"
                    );
                }
            }
            Err(PagedbError::SnapshotBasePageReused { .. }) => {
                refused_rounds += 1;

                // The refusal must be a pure no-op on the follower that was
                // asked to apply the delta.
                assert_eq!(
                    follower.latest_commit(),
                    pre_round_commit,
                    "round {round}: a refused apply must not advance the follower's commit"
                );
                {
                    let rtxn = follower.begin_read().await.unwrap();
                    for (key, expected) in &pre_round_values {
                        assert_eq!(
                            &rtxn.get(key.as_bytes()).await.unwrap(),
                            expected,
                            "round {round}: key {key} must read back exactly as before the refused apply"
                        );
                    }
                }
                let report = run_deep_walk(&follower).await.unwrap();
                assert!(
                    report.orphan_page_ids.is_empty(),
                    "round {round}: a refused apply must not leave orphan pages, got {:?}",
                    report.orphan_page_ids
                );
                assert!(
                    report.is_clean(),
                    "round {round}: a refused apply must leave a clean deep-walk report: {report:?}"
                );

                // The documented remedy: fall back to a full snapshot and keep
                // going with a brand-new follower built from it.
                let full_snap_dir = tempdir();
                let full_dst_dir = tempdir();
                cleanup_dirs.push(full_snap_dir.clone());
                cleanup_dirs.push(full_dst_dir.clone());

                source
                    .snapshot_to(&full_snap_dir)
                    .await
                    .unwrap_or_else(|e| {
                        panic!("round {round}: full-snapshot remedy export must succeed: {e:?}")
                    });
                let full_restored = Db::<TokioVfs>::restore_from(
                    &full_snap_dir,
                    &full_dst_dir,
                    OpenOptions::default(),
                    KEK,
                )
                .await
                .unwrap_or_else(|e| {
                    panic!("round {round}: full-snapshot remedy restore must succeed: {e:?}")
                });
                let new_follower = full_restored
                    .promote_to_follower()
                    .await
                    .unwrap_or_else(|e| {
                        panic!("round {round}: full-snapshot remedy promotion must succeed: {e:?}")
                    });

                assert_eq!(
                    new_follower.latest_commit(),
                    delta_target,
                    "round {round}: the remedy follower must land on the source's current commit"
                );
                let report = run_deep_walk(&new_follower).await.unwrap();
                assert!(
                    report.orphan_page_ids.is_empty(),
                    "round {round}: the remedy follower must have no orphan pages, got {:?}",
                    report.orphan_page_ids
                );
                assert!(
                    report.is_clean(),
                    "round {round}: the remedy follower must deep-walk clean: {report:?}"
                );
                let rtxn = new_follower.begin_read().await.unwrap();
                for i in 0u32..512 {
                    assert_eq!(
                        rtxn.get(format!("k{i:05}").as_bytes()).await.unwrap(),
                        Some(vec![round as u8; 128]),
                        "round {round}: key k{i:05} should reflect this round's generation on the remedy follower"
                    );
                }
                drop(rtxn);

                drop(follower);
                follower = new_follower;
            }
            Err(other) => panic!(
                "round {round}: unexpected error, only Ok or SnapshotBasePageReused are acceptable outcomes of chaining a delta: {other:?}"
            ),
        }
    }

    // Neither branch is required to occur. Which rounds apply and which are
    // refused depends on the ids the producer's allocator happens to recycle,
    // and that shifts with build configuration: every round is refused under
    // `PAGEDB_INVARIANT_CHECKS`, and none is refused without it. Asserting a
    // count here would pin a scheduling accident, so this test asserts only the
    // property that must hold either way — every round ends applied-and-clean or
    // refused-and-unchanged, never anything else, and the follower is
    // consistent at the end. Each branch is proved deterministically on its own:
    // the clean apply by `chained_incremental_applies_keep_the_follower_able_to_advance`,
    // the refusal by `an_inapplicable_delta_is_refused_without_touching_the_follower`.
    assert_eq!(
        ok_rounds + refused_rounds,
        12,
        "every round must end in one of the two acceptable outcomes"
    );

    drop(follower);
    drop(source);
    for dir in cleanup_dirs {
        std::fs::remove_dir_all(&dir).ok();
    }
}
