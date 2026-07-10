//! Integration tests for snapshot_to / restore_from / promote_to_follower /
//! apply_incremental / snapshot_incremental_to.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use pagedb::snapshot::export::{
    SnapshotManifest, decode_manifest, derive_snapshot_hk_key, encode_manifest,
};
use pagedb::vfs::tokio_backend::{TokioFile, TokioLockHandle, TokioVfs};
use pagedb::vfs::{OpenMode, Vfs};
use pagedb::{
    ApplyStats, Db, DbMode, OpenOptions, PagedbError, RealmId, SegmentKind, SegmentPageKind,
    SnapshotStats,
};

const PAGE: usize = 4096;
const KEK: [u8; 32] = [7u8; 32];
const REALM: RealmId = RealmId::new([1u8; 16]);

fn tempdir() -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    p.push(format!("pagedb-snap-{}-{}", std::process::id(), nanos));
    std::fs::create_dir_all(&p).unwrap();
    p
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

    let db = make_db(&src_dir).await;
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
// Test 3: promote_to_follower allows applying a real incremental.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "current_thread")]
async fn promote_to_follower_allows_apply() {
    let src_dir = tempdir();
    let snap_dir = tempdir();
    let dst_dir = tempdir();
    let delta_dir = tempdir();

    let db = make_db(&src_dir).await;
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

// ---------------------------------------------------------------------------
// Test 4: incremental carries only changed pages.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "current_thread")]
async fn incremental_carries_only_changed_pages() {
    let src_dir = tempdir();
    let snap1_dir = tempdir();
    let snap2_dir = tempdir();

    let db = make_db(&src_dir).await;
    // Write some initial data.
    {
        let mut t = db.begin_write().await.unwrap();
        for i in 0u32..50 {
            let k = format!("key{i:03}");
            t.put(k.as_bytes(), b"init").await.unwrap();
        }
        t.commit().await.unwrap();
    }
    let c1 = db.latest_commit();
    let full_stats: SnapshotStats = db.snapshot_to(&snap1_dir).await.unwrap();

    // Write more data to advance the commit.
    {
        let mut t = db.begin_write().await.unwrap();
        for i in 0u32..10 {
            let k = format!("new{i:03}");
            t.put(k.as_bytes(), b"added").await.unwrap();
        }
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
// Test 5: apply_incremental advances commit and data matches.
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
// Test 6: standalone db calling apply_incremental returns IdentityForked.
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
// Test 7: snapshot includes segments; restored db can read segment.
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
// Test 8: manifest corruption detected.
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
