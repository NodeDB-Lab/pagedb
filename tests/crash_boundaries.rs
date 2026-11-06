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

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

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
///
/// [`PowerLog`] also records what a power cut leaves: only bytes a file sync covered,
/// and only directory changes a directory sync covered.
#[derive(Clone)]
struct BoundaryVfs {
    inner: MemVfs,
    fail_header_writes: Arc<AtomicBool>,
    fail_renames: Arc<AtomicBool>,
    fail_sync_dirs: Arc<AtomicBool>,
    power: Arc<Mutex<PowerLog>>,
}

/// A file's durable bytes outlive its name, as an inode's do. The durable names and
/// the live names differ until a directory sync.
#[derive(Default)]
struct PowerLog {
    next_inode: u64,
    durable_bytes: BTreeMap<u64, Vec<u8>>,
    live_names: BTreeMap<String, u64>,
    durable_names: BTreeMap<String, u64>,
    directories: BTreeSet<String>,
    /// Durable events left before the power cut. `None` never cuts.
    events_left: Option<u64>,
    cut: Option<PowerCut>,
    renames_seen: u64,
}

/// The two images a power cut can leave. A file system can make a rename durable
/// before its directory sync, or lose it. Data never outruns its file sync in either.
struct PowerCut {
    renames_lost: BTreeMap<String, Vec<u8>>,
    renames_kept: BTreeMap<String, Vec<u8>>,
    directories: BTreeSet<String>,
}

fn normalized(path: &str) -> String {
    path.trim_start_matches('/').to_string()
}

fn parent_of(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(parent, _)| parent)
}

impl PowerLog {
    fn image(&self, names: &BTreeMap<String, u64>) -> BTreeMap<String, Vec<u8>> {
        names
            .iter()
            .map(|(name, inode)| {
                let bytes = self.durable_bytes.get(inode).cloned().unwrap_or_default();
                (name.clone(), bytes)
            })
            .collect()
    }

    /// Count one durable event. Returns whether the power is off from here on.
    fn event(&mut self) -> bool {
        if self.cut.is_some() {
            return true;
        }
        match self.events_left {
            Some(0) => {
                self.cut = Some(PowerCut {
                    renames_lost: self.image(&self.durable_names),
                    renames_kept: self.image(&self.live_names),
                    directories: self.directories.clone(),
                });
                true
            }
            Some(left) => {
                self.events_left = Some(left - 1);
                false
            }
            None => false,
        }
    }

    fn inode_for(&mut self, path: &str) -> u64 {
        if let Some(inode) = self.live_names.get(path) {
            return *inode;
        }
        self.next_inode += 1;
        self.live_names.insert(path.to_string(), self.next_inode);
        self.next_inode
    }
}

impl BoundaryVfs {
    fn new() -> Self {
        Self {
            inner: MemVfs::new(),
            fail_header_writes: Arc::new(AtomicBool::new(false)),
            fail_renames: Arc::new(AtomicBool::new(false)),
            fail_sync_dirs: Arc::new(AtomicBool::new(false)),
            power: Arc::new(Mutex::new(PowerLog::default())),
        }
    }

    /// Cut the power at the durable event `events` events from now.
    fn cut_power_after(&self, events: u64) {
        self.power.lock().unwrap().events_left = Some(events);
    }

    fn take_power_cut(&self) -> Option<PowerCut> {
        self.power.lock().unwrap().cut.take()
    }

    fn renames_seen(&self) -> u64 {
        self.power.lock().unwrap().renames_seen
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
        let inner = self.inner.open(path, mode).await?;
        let inode = self.power.lock().unwrap().inode_for(&normalized(path));
        Ok(BoundaryFile {
            inner,
            is_main_db: path == MAIN_DB,
            fail_header_writes: self.fail_header_writes.clone(),
            inode,
            power: self.power.clone(),
        })
    }

    async fn remove(&self, path: &str) -> pagedb::Result<()> {
        {
            let mut power = self.power.lock().unwrap();
            if power.cut.is_some() {
                return Err(Self::injected());
            }
            power.live_names.remove(&normalized(path));
        }
        self.inner.remove(path).await
    }

    async fn rename(&self, from: &str, to: &str) -> pagedb::Result<()> {
        if self.fail_renames.load(Ordering::SeqCst) {
            return Err(Self::injected());
        }
        {
            let mut power = self.power.lock().unwrap();
            if power.event() {
                return Err(Self::injected());
            }
            power.renames_seen += 1;
            if let Some(inode) = power.live_names.remove(&normalized(from)) {
                power.live_names.insert(normalized(to), inode);
            }
        }
        self.inner.rename(from, to).await
    }

    async fn list_dir(&self, path: &str) -> pagedb::Result<Vec<String>> {
        self.inner.list_dir(path).await
    }

    async fn mkdir_all(&self, path: &str) -> pagedb::Result<()> {
        self.power
            .lock()
            .unwrap()
            .directories
            .insert(normalized(path));
        self.inner.mkdir_all(path).await
    }

    async fn sync_dir(&self, path: &str) -> pagedb::Result<()> {
        if self.fail_sync_dirs.load(Ordering::SeqCst) {
            return Err(Self::injected());
        }
        {
            let mut power = self.power.lock().unwrap();
            if power.event() {
                return Err(Self::injected());
            }
            let dir = normalized(path);
            let dir = if dir == "." { String::new() } else { dir };
            let mut durable: BTreeMap<String, u64> = power
                .durable_names
                .iter()
                .filter(|(name, _)| parent_of(name) != dir)
                .map(|(name, inode)| (name.clone(), *inode))
                .collect();
            durable.extend(
                power
                    .live_names
                    .iter()
                    .filter(|(name, _)| parent_of(name) == dir)
                    .map(|(name, inode)| (name.clone(), *inode)),
            );
            power.durable_names = durable;
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
    inode: u64,
    power: Arc<Mutex<PowerLog>>,
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

    fn power_is_off(&self) -> bool {
        self.power.lock().unwrap().cut.is_some()
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
        if self.rejects(offset) || self.power_is_off() {
            return Err(BoundaryVfs::injected());
        }
        self.inner.write_at(offset, buf).await
    }

    async fn write_at_vectored(&mut self, reqs: &[WriteReq<'_>]) -> pagedb::Result<()> {
        if reqs.iter().any(|req| self.rejects(req.offset)) || self.power_is_off() {
            return Err(BoundaryVfs::injected());
        }
        self.inner.write_at_vectored(reqs).await
    }

    async fn sync(&mut self) -> pagedb::Result<()> {
        if self.power.lock().unwrap().event() {
            return Err(BoundaryVfs::injected());
        }
        self.inner.sync().await?;
        let mut bytes = vec![0u8; usize::try_from(self.inner.len().await?).unwrap()];
        let read = self.inner.read_at(0, &mut bytes).await?;
        bytes.truncate(read);
        self.power
            .lock()
            .unwrap()
            .durable_bytes
            .insert(self.inode, bytes);
        Ok(())
    }

    async fn truncate(&mut self, len: u64) -> pagedb::Result<()> {
        if self.power_is_off() {
            return Err(BoundaryVfs::injected());
        }
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

const REKEY_ROWS: u32 = 40;
const REKEY_TARGET_KEK: [u8; 32] = [0x3C; 32];

/// How a rekey changes keys, and so what a reopen after a power cut holds.
#[derive(Clone, Copy, Debug)]
enum RekeyKeys {
    SameKek,
    NewKek,
}

impl RekeyKeys {
    fn target(self) -> [u8; 32] {
        match self {
            Self::SameKek => KEK,
            Self::NewKek => REKEY_TARGET_KEK,
        }
    }
}

/// A store with free pages, retained rows, and a linked segment.
async fn store_ready_to_rekey(vfs: &BoundaryVfs) -> Db<BoundaryVfs> {
    let db = Db::open(vfs.clone(), KEK, PAGE, REALM, OpenOptions::default())
        .await
        .unwrap();
    for generation in 0..2u8 {
        let mut txn = db.begin_write().await.unwrap();
        for index in 0..REKEY_ROWS {
            txn.put(key(index).as_bytes(), &[generation; 3000])
                .await
                .unwrap();
        }
        txn.commit().await.unwrap();
    }
    let mut writer = db
        .create_segment(REALM, SegmentKind::Unspecified)
        .await
        .unwrap();
    writer
        .append_page(SegmentPageKind::Data, b"crash-segment")
        .await
        .unwrap();
    let meta = writer.seal().await.unwrap();
    let mut txn = db.begin_write().await.unwrap();
    txn.link_segment("crash-segment", &meta).await.unwrap();
    txn.commit().await.unwrap();
    db
}

async fn store_from_image(image: &BTreeMap<String, Vec<u8>>, dirs: &BTreeSet<String>) -> MemVfs {
    let vfs = MemVfs::new();
    for dir in dirs {
        vfs.mkdir_all(dir).await.unwrap();
    }
    for (name, bytes) in image {
        let parent = parent_of(name);
        if !parent.is_empty() {
            vfs.mkdir_all(parent).await.unwrap();
        }
        let mut file = vfs.open(name, OpenMode::CreateNew).await.unwrap();
        file.write_at(0, bytes).await.unwrap();
        file.sync().await.unwrap();
    }
    vfs
}

async fn assert_image_reopens_whole(
    image: &BTreeMap<String, Vec<u8>>,
    dirs: &BTreeSet<String>,
    keys: RekeyKeys,
    context: &str,
) {
    let vfs = store_from_image(image, dirs).await;
    let db = match keys {
        RekeyKeys::SameKek => Db::open(vfs, KEK, PAGE, REALM, OpenOptions::default()).await,
        RekeyKeys::NewKek => {
            Db::open_existing_with_counterpart_kek(
                vfs,
                KEK,
                REKEY_TARGET_KEK,
                PAGE,
                REALM,
                OpenOptions::default(),
            )
            .await
        }
    }
    .unwrap_or_else(|error| panic!("{context}: the reopen failed: {error:?}"));

    let reader = db.begin_read().await.unwrap();
    for index in [0, REKEY_ROWS - 1] {
        assert_eq!(
            reader.get(key(index).as_bytes()).await.unwrap().as_deref(),
            Some([1u8; 3000].as_slice()),
            "{context}: row {index}"
        );
    }
    drop(reader);
    let segment = db.open_segment(REALM, "crash-segment").await.unwrap();
    assert!(
        segment
            .read_page(1)
            .await
            .unwrap()
            .starts_with(b"crash-segment"),
        "{context}"
    );
    drop(segment);
    let report = run_deep_walk(&db).await.unwrap();
    assert!(report.is_clean(), "{context}: {report:?}");
}

/// Cut the power at every sync, rename, and directory sync of a rekey. Each cut
/// leaves two images: one that lost every rename no directory sync covered, and one
/// that kept them. In both, a file holds only what its sync covered, so a rename
/// that ran ahead of its data would show here as a torn `main.db`.
///
/// This covers each boundary: the intent's header, every scratch flush, the scratch
/// header, the rename with its directory sync still to come, and the stages after it.
#[tokio::test(flavor = "current_thread")]
async fn a_power_cut_at_every_durable_event_of_a_rekey_reopens_with_all_data() {
    for keys in [RekeyKeys::SameKek, RekeyKeys::NewKek] {
        let mut event = 0;
        let mut main_swap_cuts = 0;
        loop {
            let vfs = BoundaryVfs::new();
            let db = store_ready_to_rekey(&vfs).await;
            let renames_before = vfs.renames_seen();
            vfs.cut_power_after(event);
            let outcome = db.rekey_db(keys.target(), 1).await;
            let renames_during = vfs.renames_seen() - renames_before;
            drop(db);

            let Some(cut) = vfs.take_power_cut() else {
                outcome.unwrap();
                break;
            };
            if renames_during > 0 && cut.renames_lost != cut.renames_kept {
                main_swap_cuts += 1;
            }
            for (image, kind) in [
                (&cut.renames_lost, "renames lost"),
                (&cut.renames_kept, "renames kept"),
            ] {
                let context = format!("{keys:?} cut at event {event}, {kind}");
                assert_image_reopens_whole(image, &cut.directories, keys, &context).await;
            }
            event += 1;
        }
        assert!(event > 8, "{keys:?}: only {event} durable events ran");
        assert!(
            main_swap_cuts > 0,
            "{keys:?}: no cut landed between a rename and its directory sync"
        );
    }
}
