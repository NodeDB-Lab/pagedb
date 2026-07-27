//! Tests for the deep-walk integrity checker.

use std::sync::{Arc, Mutex};

use pagedb::options::RetainPolicy;
use pagedb::vfs::memory::MemVfs;
use pagedb::vfs::{OpenMode, ReadReq, Vfs, VfsFile, WriteReq};
use pagedb::{Db, OpenOptions, PagedbError, RealmId, run_deep_walk};

const KEK: [u8; 32] = [3u8; 32];
const REALM: RealmId = RealmId::new([1u8; 16]);
const PAGE: usize = 4096;

async fn open_db() -> Db<MemVfs> {
    let opts = OpenOptions::default().with_buffer_pool_pages(64);
    Db::open(MemVfs::new(), KEK, 4096, REALM, opts)
        .await
        .unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn clean_db_reports_clean() {
    let db = open_db().await;

    // Write some data.
    let mut txn = db.begin_write().await.unwrap();
    for i in 0u64..20 {
        let key = format!("key{i:04}");
        txn.put(key.as_bytes(), &[i as u8; 128]).await.unwrap();
    }
    txn.commit().await.unwrap();

    let report = run_deep_walk(&db).await.unwrap();
    assert!(
        report.page_issues.is_empty(),
        "expected no page issues, got: {:?}",
        report.page_issues
    );
    assert!(
        report.segment_issues.is_empty(),
        "expected no segment issues"
    );
    assert!(report.drift_issues.is_empty(), "expected no drift issues");
    assert!(
        report.pages_examined > 0,
        "should have examined at least some pages"
    );
    assert!(report.is_clean(), "report should be clean");
}

#[tokio::test(flavor = "current_thread")]
async fn empty_db_reports_clean() {
    let db = open_db().await;
    let report = run_deep_walk(&db).await.unwrap();
    // An empty db has no data pages (next_page_id == 4, pages 4..4 is empty).
    assert!(report.is_clean(), "empty db should be clean");
}

#[tokio::test(flavor = "current_thread")]
async fn corrupt_page_detected() {
    let vfs = MemVfs::new();
    let opts = OpenOptions::default().with_buffer_pool_pages(64);
    let db = Db::open(vfs.clone(), KEK, 4096, REALM, opts.clone())
        .await
        .unwrap();

    // Write data to create some pages.
    let mut txn = db.begin_write().await.unwrap();
    for i in 0u64..10 {
        let key = format!("ck{i:04}");
        txn.put(key.as_bytes(), &[0xABu8; 64]).await.unwrap();
    }
    txn.commit().await.unwrap();

    // Page 4 is the first data page (pages 0-3 are reserved), so the writes
    // above must have allocated it for the corruption below to land on a real
    // page rather than past the end of the file.
    let next_pid = db.stats().await.unwrap().main_db_next_page_id;
    assert!(
        next_pid > 4,
        "the seed writes must have allocated at least one data page; got {next_pid}"
    );
    // Close the store before touching its bytes underneath it, the way a
    // crash-then-fsck sequence does.
    drop(db);

    // Corrupt a data page by flipping bytes directly in the MemVfs.
    {
        use pagedb::vfs::OpenMode;
        use pagedb::vfs::{Vfs, VfsFile};
        let mut f = vfs.open("/main.db", OpenMode::ReadWrite).await.unwrap();
        // Flip bytes in the AEAD tag of page 4 (last 16 bytes of the page).
        let corrupt_offset = 4 * 4096 + 4096 - 16;
        let mut corrupt_buf = [0u8; 16];
        f.read_at(corrupt_offset, &mut corrupt_buf).await.unwrap();
        for b in &mut corrupt_buf {
            *b ^= 0xFF;
        }
        f.write_at(corrupt_offset, &corrupt_buf).await.unwrap();
        f.sync().await.unwrap();
    }

    // A fresh handle starts with a cold buffer pool, so the deep walk reads the
    // corrupted bytes from disk instead of the page the writer left warm.
    let db = Db::open(vfs.clone(), KEK, 4096, REALM, opts).await.unwrap();
    let report = run_deep_walk(&db).await.unwrap();
    assert!(
        !report.page_issues.is_empty(),
        "should detect corrupted page"
    );
    assert!(
        report.page_issues.iter().any(|i| i.page_id == 4),
        "page 4 should be reported as corrupted; issues: {:?}",
        report.page_issues
    );
}

#[tokio::test(flavor = "current_thread")]
async fn free_list_pages_are_accounted_not_orphans() {
    // Disable history so deleted pages enter the durable free-list immediately
    // (no retained snapshot pins them).
    let opts = OpenOptions::default()
        .with_buffer_pool_pages(64)
        .with_commit_history_retain(pagedb::options::RetainPolicy::Disabled);
    let db = Db::open(MemVfs::new(), KEK, 4096, REALM, opts)
        .await
        .unwrap();

    {
        let mut w = db.begin_write().await.unwrap();
        for i in 0u32..300 {
            w.put(format!("k{i:05}").as_bytes(), &[7u8; 128])
                .await
                .unwrap();
        }
        w.commit().await.unwrap();
    }
    {
        let mut w = db.begin_write().await.unwrap();
        for i in 0u32..250 {
            w.delete(format!("k{i:05}").as_bytes()).await.unwrap();
        }
        w.commit().await.unwrap();
    }
    assert!(
        db.stats().await.unwrap().free_list_pending_entries > 0,
        "setup should have populated the durable free-list"
    );

    let report = run_deep_walk(&db).await.unwrap();
    assert!(
        report.page_issues.is_empty(),
        "free-listed/chain pages must verify cleanly, got: {:?}",
        report.page_issues
    );
    // The free-list chain pages and the pages they track are accounted for, so
    // none should be reported as orphans.
    assert!(
        report.orphan_page_ids.is_empty(),
        "free-list pages must not be reported as orphans, got: {:?}",
        report.orphan_page_ids
    );
    assert!(report.is_clean(), "report should be clean");
}

/// With commit-history retention enabled, superseded-but-retained tree
/// versions are still reachable through the commit-history index used by
/// `begin_read_at`. A healthy store with several retained generations must
/// not report those pages as orphans, and a retained generation must still
/// be genuinely readable back.
#[tokio::test(flavor = "current_thread")]
async fn retained_history_pages_are_not_reported_as_orphans() {
    let opts = OpenOptions::default()
        .with_buffer_pool_pages(64)
        .with_commit_history_retain(RetainPolicy::Count(1024));
    let db = Db::open(MemVfs::new(), KEK, 4096, REALM, opts)
        .await
        .unwrap();

    // Repeatedly overwrite the same key set across several generations so
    // copy-on-write genuinely supersedes earlier pages instead of only
    // appending new ones. Enough keys/bytes to span multiple B+ tree pages.
    let mut commits = Vec::new();
    for generation in 0u8..24 {
        let mut txn = db.begin_write().await.unwrap();
        for i in 0u32..300 {
            let key = format!("hkey{i:05}");
            txn.put(key.as_bytes(), &[generation; 128]).await.unwrap();
        }
        let commit_id = txn.commit().await.unwrap();
        commits.push(commit_id);
    }

    let report = run_deep_walk(&db).await.unwrap();
    assert!(
        report.orphan_page_ids.is_empty(),
        "pages held for retained history are accounted by the deferred-free \
         chain, not leaked, got {} orphans: {:?}",
        report.orphan_page_ids.len(),
        report.orphan_page_ids
    );

    // The pages the walk just declined to call orphans are genuinely live: an
    // earlier retained commit still opens and reads back its own generation.
    let earliest = commits[0];
    let historical = db.begin_read_at(earliest).await.unwrap();
    assert_eq!(
        historical.get(b"hkey00000").await.unwrap().as_deref(),
        Some([0u8; 128].as_slice()),
        "retained historical commit must still read back its own generation's value"
    );
    drop(historical);

    // Compaction is the pass that actually reclaims superseded pages. It
    // retires retained history rather than preserving it, so the reachable set
    // shrinks to the live roots — and must still balance exactly.
    db.compact_now().await.unwrap();
    assert!(
        matches!(
            db.begin_read_at(earliest).await,
            Err(PagedbError::CommitGone { .. })
        ),
        "compaction retires retained history instead of pinning it forever"
    );

    let report = run_deep_walk(&db).await.unwrap();
    assert!(
        report.orphan_page_ids.is_empty(),
        "compaction must return every superseded page to the free list, got {} \
         orphans: {:?}",
        report.orphan_page_ids.len(),
        report.orphan_page_ids
    );
}

/// A `MemVfs` that shortens exactly one positional read by one byte, then
/// behaves normally.
///
/// Every PageDB VFS is allowed to satisfy a request across several `read_at`
/// calls, so a positive short read is a legal step in a transfer, not evidence
/// about the file. The wrapper leaves the missing byte available to the next
/// call, which is what makes the resulting report a statement about deep walk
/// rather than about the mock: a clean report is only reachable by completing
/// the same legal byte stream.
#[derive(Clone)]
struct ShortReadVfs {
    inner: MemVfs,
    short_read_at: Arc<Mutex<Option<(String, u64)>>>,
}

impl ShortReadVfs {
    fn new() -> Self {
        Self {
            inner: MemVfs::new(),
            short_read_at: Arc::new(Mutex::new(None)),
        }
    }

    fn short_once_at(&self, path: impl Into<String>, offset: u64) {
        *self.short_read_at.lock().unwrap() = Some((path.into(), offset));
    }

    /// Whether the armed short read has been consumed. A test that never fires
    /// it proves nothing, so the assertion belongs next to the report.
    fn fired(&self) -> bool {
        self.short_read_at.lock().unwrap().is_none()
    }
}

struct ShortReadFile<F> {
    inner: F,
    path: String,
    short_read_at: Arc<Mutex<Option<(String, u64)>>>,
}

impl Vfs for ShortReadVfs {
    type File = ShortReadFile<<MemVfs as Vfs>::File>;
    type LockHandle = <MemVfs as Vfs>::LockHandle;

    async fn open(&self, path: &str, mode: OpenMode) -> pagedb::Result<Self::File> {
        Ok(ShortReadFile {
            inner: self.inner.open(path, mode).await?,
            path: path.to_string(),
            short_read_at: self.short_read_at.clone(),
        })
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
        self.inner.sync_dir(path).await
    }

    async fn lock_exclusive(&self, path: &str) -> pagedb::Result<Self::LockHandle> {
        self.inner.lock_exclusive(path).await
    }

    async fn lock_shared(&self, path: &str) -> pagedb::Result<Self::LockHandle> {
        self.inner.lock_shared(path).await
    }
}

impl<F: VfsFile + Sync> VfsFile for ShortReadFile<F> {
    async fn read_at(&self, offset: u64, buf: &mut [u8]) -> pagedb::Result<usize> {
        let should_shorten = {
            let mut armed = self.short_read_at.lock().unwrap();
            let matches_here = armed
                .as_ref()
                .is_some_and(|(path, at)| path == &self.path && *at == offset);
            if matches_here {
                armed.take();
            }
            matches_here
        };
        if should_shorten && buf.len() > 1 {
            let short_len = buf.len() - 1;
            return self.inner.read_at(offset, &mut buf[..short_len]).await;
        }
        self.inner.read_at(offset, buf).await
    }

    async fn read_at_vectored(&self, reqs: &mut [ReadReq<'_>]) -> pagedb::Result<()> {
        self.inner.read_at_vectored(reqs).await
    }

    async fn write_at(&mut self, offset: u64, buf: &[u8]) -> pagedb::Result<usize> {
        self.inner.write_at(offset, buf).await
    }

    async fn write_at_vectored(&mut self, reqs: &[WriteReq<'_>]) -> pagedb::Result<()> {
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

#[tokio::test(flavor = "current_thread")]
async fn deep_walk_completes_a_short_main_data_page_read() {
    let vfs = ShortReadVfs::new();
    let opts = OpenOptions::default().with_buffer_pool_pages(64);
    let db = Db::open(vfs.clone(), KEK, PAGE, REALM, opts).await.unwrap();

    let mut txn = db.begin_write().await.unwrap();
    for i in 0u64..10 {
        let key = format!("short-main-{i:04}");
        txn.put(key.as_bytes(), &[0xCC; 128]).await.unwrap();
    }
    txn.commit().await.unwrap();

    vfs.short_once_at("/main.db", (PAGE * 4) as u64);
    let report = run_deep_walk(&db).await.unwrap();

    assert!(vfs.fired(), "the armed short read never reached deep walk");
    assert!(
        report.page_issues.is_empty(),
        "a legal short main.db read must be completed, not reported: {:?}",
        report.page_issues
    );
    assert!(report.is_clean(), "report should be clean: {report:?}");
}

#[tokio::test(flavor = "current_thread")]
async fn deep_walk_completes_a_short_segment_data_page_read() {
    let vfs = ShortReadVfs::new();
    let opts = OpenOptions::default().with_buffer_pool_pages(64);
    let db = Db::open(vfs.clone(), KEK, PAGE, REALM, opts).await.unwrap();

    let mut segment = db
        .create_segment(REALM, pagedb::SegmentKind::Unspecified)
        .await
        .unwrap();
    segment
        .append_page(pagedb::SegmentPageKind::Data, b"deep-walk-short-segment")
        .await
        .unwrap();
    let meta = segment.seal().await.unwrap();
    let mut txn = db.begin_write().await.unwrap();
    txn.link_segment("short-segment", &meta).await.unwrap();
    txn.commit().await.unwrap();

    let segment_path = format!("seg/{}", hex_lower(&meta.segment_id));
    vfs.short_once_at(segment_path, PAGE as u64);

    let report = run_deep_walk(&db).await.unwrap();

    assert!(vfs.fired(), "the armed short read never reached deep walk");
    assert!(
        report.segment_issues.is_empty(),
        "a legal short segment read must be completed, not reported: {:?}",
        report.segment_issues
    );
    assert!(report.is_clean(), "report should be clean: {report:?}");
}

fn hex_lower(bytes: &[u8; 16]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A genuinely short file must still be reported, and the report must carry the
/// numbers. `read_exact_at` completes legal short reads and surfaces real
/// truncation as a bare end-of-file, so the walk restores the offset and the
/// file length an operator needs to size the damage.
#[tokio::test(flavor = "current_thread")]
async fn deep_walk_reports_a_truncated_main_db_with_its_extent() {
    let vfs = MemVfs::new();
    let opts = OpenOptions::default().with_buffer_pool_pages(64);
    let db = Db::open(vfs.clone(), KEK, PAGE, REALM, opts).await.unwrap();

    let mut txn = db.begin_write().await.unwrap();
    for i in 0u64..400 {
        let key = format!("truncated-{i:04}");
        txn.put(key.as_bytes(), &[0xAB; 128]).await.unwrap();
    }
    txn.commit().await.unwrap();

    let kept_bytes = (PAGE * 5) as u64;
    {
        let mut main = vfs.open("/main.db", OpenMode::CreateOrOpen).await.unwrap();
        main.truncate(kept_bytes).await.unwrap();
        main.sync().await.unwrap();
    }

    let report = run_deep_walk(&db).await.unwrap();
    assert!(
        report.page_issues.iter().any(|issue| {
            issue.description.contains("truncated:")
                && issue
                    .description
                    .contains(&format!("file is {kept_bytes} bytes"))
        }),
        "a truncated main.db must be reported with its extent: {:?}",
        report.page_issues
    );
}
