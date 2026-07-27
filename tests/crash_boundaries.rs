// SPDX-License-Identifier: MIT OR Apache-2.0
//! Interruption at the durable boundaries of the commit, segment publication,
//! segment tombstone, and compaction protocols.
//!
//! Each test drives the store to one boundary, fails exactly the operation that
//! defines it, reopens, and then holds the reopened store to the protocol's own
//! invariants rather than to "it opened again": the deep walk must come back
//! clean — which includes leaked pages, since the reopened handle owns the
//! allocator — and the committed data must be entirely the old state or
//! entirely the new one, never a mixture of the two.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use pagedb::vfs::memory::{MemFile, MemLockHandle, MemVfs};
use pagedb::vfs::{OpenMode, ReadReq, Vfs, VfsFile, WriteReq};
use pagedb::{Db, OpenOptions, PagedbError, RealmId, SegmentKind, SegmentPageKind, run_deep_walk};

const PAGE: usize = 4096;
const KEK: [u8; 32] = [0x3B; 32];
const REALM: RealmId = RealmId::new([0x1D; 16]);
const MAIN_DB: &str = "/main.db";

/// A `MemVfs` that can be stopped at one durable boundary.
///
/// `fail_header_writes` rejects writes into the two A/B header slots of
/// `main.db` and nothing else, so a commit that has already flushed its data
/// pages stops exactly at the header swap — the commit point. `fail_renames`
/// stops the segment publish and tombstone protocols at their rename, after the
/// catalog is durable. `fail_sync_dirs` stops compaction between its scratch
/// rename — the point at which the compacted image becomes the durable one —
/// and the directory sync that follows it.
#[derive(Clone)]
struct BoundaryVfs {
    inner: MemVfs,
    fail_header_writes: Arc<AtomicBool>,
    fail_renames: Arc<AtomicBool>,
    fail_sync_dirs: Arc<AtomicBool>,
}

impl BoundaryVfs {
    fn new() -> Self {
        Self {
            inner: MemVfs::new(),
            fail_header_writes: Arc::new(AtomicBool::new(false)),
            fail_renames: Arc::new(AtomicBool::new(false)),
            fail_sync_dirs: Arc::new(AtomicBool::new(false)),
        }
    }

    fn fail_header_writes(&self, fail: bool) {
        self.fail_header_writes.store(fail, Ordering::SeqCst);
    }

    fn fail_renames(&self, fail: bool) {
        self.fail_renames.store(fail, Ordering::SeqCst);
    }

    fn fail_sync_dirs(&self, fail: bool) {
        self.fail_sync_dirs.store(fail, Ordering::SeqCst);
    }

    fn injected() -> PagedbError {
        PagedbError::Io(std::io::Error::other("injected boundary interruption"))
    }
}

impl Vfs for BoundaryVfs {
    type File = BoundaryFile;
    type LockHandle = MemLockHandle;

    async fn open(&self, path: &str, mode: OpenMode) -> pagedb::Result<Self::File> {
        Ok(BoundaryFile {
            inner: self.inner.open(path, mode).await?,
            is_main_db: path == MAIN_DB,
            fail_header_writes: self.fail_header_writes.clone(),
        })
    }

    async fn remove(&self, path: &str) -> pagedb::Result<()> {
        self.inner.remove(path).await
    }

    async fn rename(&self, from: &str, to: &str) -> pagedb::Result<()> {
        if self.fail_renames.load(Ordering::SeqCst) {
            return Err(Self::injected());
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
            return Err(Self::injected());
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

struct BoundaryFile {
    inner: MemFile,
    is_main_db: bool,
    fail_header_writes: Arc<AtomicBool>,
}

impl BoundaryFile {
    /// The A/B header slots are pages 0 and 1 of `main.db`; every data page
    /// lives at or above page 4, so this discriminates the header swap from the
    /// page flush that precedes it.
    fn rejects(&self, offset: u64) -> bool {
        self.is_main_db
            && self.fail_header_writes.load(Ordering::SeqCst)
            && offset < 2 * PAGE as u64
    }
}

impl VfsFile for BoundaryFile {
    async fn read_at(&self, offset: u64, buf: &mut [u8]) -> pagedb::Result<usize> {
        self.inner.read_at(offset, buf).await
    }

    async fn read_at_vectored(&self, reqs: &mut [ReadReq<'_>]) -> pagedb::Result<()> {
        self.inner.read_at_vectored(reqs).await
    }

    async fn write_at(&mut self, offset: u64, buf: &[u8]) -> pagedb::Result<usize> {
        if self.rejects(offset) {
            return Err(BoundaryVfs::injected());
        }
        self.inner.write_at(offset, buf).await
    }

    async fn write_at_vectored(&mut self, reqs: &[WriteReq<'_>]) -> pagedb::Result<()> {
        if reqs.iter().any(|req| self.rejects(req.offset)) {
            return Err(BoundaryVfs::injected());
        }
        self.inner.write_at_vectored(reqs).await
    }

    async fn sync(&mut self) -> pagedb::Result<()> {
        self.inner.sync().await
    }

    async fn truncate(&mut self, len: u64) -> pagedb::Result<()> {
        self.inner.truncate(len).await
    }

    async fn len(&self) -> pagedb::Result<u64> {
        self.inner.len().await
    }

    async fn is_empty(&self) -> pagedb::Result<bool> {
        self.inner.is_empty().await
    }

    fn supports_direct_io(&self) -> bool {
        self.inner.supports_direct_io()
    }
}

fn hex_lower(bytes: &[u8; 16]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(32);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn key(index: u32) -> String {
    format!("k-{index:04}")
}

async fn assert_clean(db: &Db<BoundaryVfs>, context: &str) {
    let report = run_deep_walk(db).await.unwrap();
    assert!(
        report.is_clean(),
        "{context}: the reopened store must satisfy its own invariants: {report:?}"
    );
}

/// A commit stopped at the header swap leaves the whole previous commit in
/// place: no key advances, and the pages the abandoned attempt already flushed
/// are neither reachable nor lost — the deep walk sees no leak.
#[tokio::test(flavor = "current_thread")]
async fn commit_interrupted_at_the_header_swap_reopens_wholly_at_the_previous_commit() {
    let vfs = BoundaryVfs::new();
    let db = Db::open(vfs.clone(), KEK, PAGE, REALM, OpenOptions::default())
        .await
        .unwrap();

    {
        let mut txn = db.begin_write().await.unwrap();
        for index in 0..200u32 {
            txn.put(key(index).as_bytes(), b"first").await.unwrap();
        }
        txn.commit().await.unwrap();
    }
    let durable_commit = db.latest_commit();

    // Overwrite every key and add new ones, then fail the header swap. Every
    // data page of the candidate commit is already flushed at that point.
    {
        let mut txn = db.begin_write().await.unwrap();
        for index in 0..200u32 {
            txn.put(key(index).as_bytes(), b"second").await.unwrap();
        }
        for index in 200..260u32 {
            txn.put(key(index).as_bytes(), b"second").await.unwrap();
        }
        vfs.fail_header_writes(true);
        assert!(
            txn.commit().await.is_err(),
            "a rejected header swap must fail the commit"
        );
    }
    vfs.fail_header_writes(false);
    drop(db);

    let reopened = Db::open(vfs, KEK, PAGE, REALM, OpenOptions::default())
        .await
        .unwrap();
    assert_eq!(reopened.latest_commit(), durable_commit);
    let read = reopened.begin_read().await.unwrap();
    for index in 0..200u32 {
        assert_eq!(
            read.get(key(index).as_bytes()).await.unwrap().as_deref(),
            Some(b"first".as_slice()),
            "no key may carry the interrupted commit's value"
        );
    }
    for index in 200..260u32 {
        assert!(
            read.get(key(index).as_bytes()).await.unwrap().is_none(),
            "no key of the interrupted commit may become visible"
        );
    }
    drop(read);
    assert_clean(&reopened, "commit interrupted at the header swap").await;
}

/// A commit stopped at the header swap must not consume the store: the reopened
/// handle writes the state through and stays within its own invariants, so the
/// page range the abandoned attempt touched is reused rather than stranded.
#[tokio::test(flavor = "current_thread")]
async fn a_store_reopened_after_an_interrupted_header_swap_commits_again_cleanly() {
    let vfs = BoundaryVfs::new();
    let db = Db::open(vfs.clone(), KEK, PAGE, REALM, OpenOptions::default())
        .await
        .unwrap();

    {
        let mut txn = db.begin_write().await.unwrap();
        for index in 0..120u32 {
            txn.put(key(index).as_bytes(), b"first").await.unwrap();
        }
        txn.commit().await.unwrap();
    }

    {
        let mut txn = db.begin_write().await.unwrap();
        for index in 0..120u32 {
            txn.put(key(index).as_bytes(), b"abandoned").await.unwrap();
        }
        vfs.fail_header_writes(true);
        assert!(txn.commit().await.is_err());
    }
    vfs.fail_header_writes(false);
    drop(db);

    let reopened = Db::open(vfs, KEK, PAGE, REALM, OpenOptions::default())
        .await
        .unwrap();
    assert_clean(&reopened, "reopen after an interrupted header swap").await;
    {
        let mut txn = reopened.begin_write().await.unwrap();
        for index in 0..120u32 {
            txn.put(key(index).as_bytes(), b"second").await.unwrap();
        }
        txn.commit().await.unwrap();
    }

    let read = reopened.begin_read().await.unwrap();
    for index in 0..120u32 {
        assert_eq!(
            read.get(key(index).as_bytes()).await.unwrap().as_deref(),
            Some(b"second".as_slice())
        );
    }
    drop(read);
    assert_clean(&reopened, "commit after an interrupted header swap").await;
}

/// A link whose catalog row is durable but whose staging-to-live rename never
/// ran must reopen with the segment published and readable — the catalog row is
/// the commit point, and the rename is completed by recovery.
#[tokio::test(flavor = "current_thread")]
async fn link_interrupted_before_the_promote_rename_reopens_with_a_readable_segment() {
    let vfs = BoundaryVfs::new();
    let db = Db::open(vfs.clone(), KEK, PAGE, REALM, OpenOptions::default())
        .await
        .unwrap();

    let mut writer = db
        .create_segment(REALM, SegmentKind::Unspecified)
        .await
        .unwrap();
    writer
        .append_page(SegmentPageKind::Data, b"promoted-by-recovery")
        .await
        .unwrap();
    let meta = writer.seal().await.unwrap();
    let segment_hex = hex_lower(&meta.segment_id);

    let mut txn = db.begin_write().await.unwrap();
    txn.put(b"row", b"value").await.unwrap();
    txn.link_segment("published", &meta).await.unwrap();
    vfs.fail_renames(true);
    assert!(
        txn.commit().await.is_err(),
        "a rejected promote rename must report the commit as unpublished"
    );
    vfs.fail_renames(false);
    drop(db);

    let reopened = Db::open(vfs.clone(), KEK, PAGE, REALM, OpenOptions::default())
        .await
        .unwrap();
    let reader = reopened.open_segment(REALM, "published").await.unwrap();
    assert!(
        reader
            .read_page(1)
            .await
            .unwrap()
            .starts_with(b"promoted-by-recovery")
    );
    let read = reopened.begin_read().await.unwrap();
    assert_eq!(
        read.get(b"row").await.unwrap().as_deref(),
        Some(b"value".as_slice()),
        "the durable catalog commit carries its data rows with it"
    );
    drop(read);
    assert!(
        vfs.open(&format!("seg/.staging/{segment_hex}"), OpenMode::Read)
            .await
            .is_err(),
        "the staged copy must not survive its own promotion"
    );
    assert_clean(&reopened, "link interrupted before the promote rename").await;
}

/// An unlink whose catalog row is durable but whose live-to-tombstone rename
/// never ran must reopen with the segment gone from both the catalog and the
/// live directory: recovery sweeps the file the catalog no longer names.
#[tokio::test(flavor = "current_thread")]
async fn unlink_interrupted_before_the_tombstone_rename_reopens_without_the_segment() {
    let vfs = BoundaryVfs::new();
    let db = Db::open(vfs.clone(), KEK, PAGE, REALM, OpenOptions::default())
        .await
        .unwrap();

    let mut writer = db
        .create_segment(REALM, SegmentKind::Unspecified)
        .await
        .unwrap();
    writer
        .append_page(SegmentPageKind::Data, b"unlinked")
        .await
        .unwrap();
    let meta = writer.seal().await.unwrap();
    let segment_hex = hex_lower(&meta.segment_id);
    {
        let mut txn = db.begin_write().await.unwrap();
        txn.put(b"survivor", b"value").await.unwrap();
        txn.link_segment("dropped", &meta).await.unwrap();
        txn.commit().await.unwrap();
    }
    assert!(
        vfs.open(&format!("seg/{segment_hex}"), OpenMode::Read)
            .await
            .is_ok()
    );

    {
        let mut txn = db.begin_write().await.unwrap();
        txn.unlink_segment("dropped").await.unwrap();
        vfs.fail_renames(true);
        assert!(
            txn.commit().await.is_err(),
            "a rejected tombstone rename must report the commit as unpublished"
        );
    }
    vfs.fail_renames(false);
    drop(db);

    let reopened = Db::open(vfs.clone(), KEK, PAGE, REALM, OpenOptions::default())
        .await
        .unwrap();
    assert!(
        matches!(
            reopened.open_segment(REALM, "dropped").await,
            Err(PagedbError::NotFound)
        ),
        "the durable unlink must not be undone by recovery"
    );
    assert!(
        vfs.open(&format!("seg/{segment_hex}"), OpenMode::Read)
            .await
            .is_err(),
        "the file the catalog no longer names must be swept out of the live directory"
    );
    let read = reopened.begin_read().await.unwrap();
    assert_eq!(
        read.get(b"survivor").await.unwrap().as_deref(),
        Some(b"value".as_slice())
    );
    drop(read);
    assert_clean(&reopened, "unlink interrupted before the tombstone rename").await;

    // The swept file is reclaimable through the ordinary tombstone path.
    reopened.gc_now().await.unwrap();
    assert_clean(&reopened, "tombstone sweep followed by collection").await;
}

/// Compaction interrupted after the scratch rename — its single commit point —
/// must reopen wholly compacted, with every surviving key intact, every deleted
/// key gone, and no page stranded by the relocation.
#[tokio::test(flavor = "current_thread")]
async fn compaction_interrupted_after_the_scratch_rename_reopens_wholly_compacted() {
    let vfs = BoundaryVfs::new();
    let db = Db::open(vfs.clone(), KEK, PAGE, REALM, OpenOptions::default())
        .await
        .unwrap();

    {
        let mut txn = db.begin_write().await.unwrap();
        for index in 0..200u32 {
            txn.put(key(index).as_bytes(), &[0xAC; 128]).await.unwrap();
        }
        txn.commit().await.unwrap();
    }
    {
        let mut txn = db.begin_write().await.unwrap();
        for index in 0..190u32 {
            txn.delete(key(index).as_bytes()).await.unwrap();
        }
        txn.commit().await.unwrap();
    }

    // The rename succeeds and the directory sync that follows it does not, so
    // the compacted image is durable while the handle never publishes it.
    vfs.fail_sync_dirs(true);
    assert!(
        matches!(
            db.compact_now().await,
            Err(PagedbError::DurablyCommittedButUnpublished { .. })
        ),
        "an unsynced post-rename compaction must report the commit as unpublished"
    );
    vfs.fail_sync_dirs(false);
    drop(db);

    let reopened = Db::open(vfs.clone(), KEK, PAGE, REALM, OpenOptions::default())
        .await
        .unwrap();
    let read = reopened.begin_read().await.unwrap();
    for index in 0..190u32 {
        assert!(
            read.get(key(index).as_bytes()).await.unwrap().is_none(),
            "compaction must not resurrect a deleted key"
        );
    }
    for index in 190..200u32 {
        assert_eq!(
            read.get(key(index).as_bytes()).await.unwrap().as_deref(),
            Some(&[0xAC; 128][..]),
            "compaction must not lose a live key"
        );
    }
    drop(read);
    assert!(
        vfs.open("/main.db.compact", OpenMode::Read).await.is_err(),
        "no compaction scratch may survive the reopen"
    );
    assert_clean(&reopened, "compaction interrupted after the scratch rename").await;

    // The reopened store still takes writes, and the next commit stays clean.
    {
        let mut txn = reopened.begin_write().await.unwrap();
        txn.put(b"after-compaction", b"value").await.unwrap();
        txn.commit().await.unwrap();
    }
    assert_clean(&reopened, "commit after an interrupted compaction").await;
}
