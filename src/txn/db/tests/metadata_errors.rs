//! Durable metadata error propagation and positional-I/O completion.
//!
//! Metadata publication depends on `rename`/`sync_dir`, while authenticated
//! pages may be transferred by backends that legally complete positional I/O
//! in several calls. These tests verify that transient failures are surfaced,
//! partial transfers finish before success is reported, and retries preserve
//! usable state.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use crate::options::{OpenOptions, RetainPolicy};
use crate::recovery::journal::{JournalAction, execute_journal_actions};
use crate::vfs::memory::MemVfs;
use crate::vfs::traits::{Vfs, VfsFile};
use crate::vfs::types::{OpenMode, ReadReq, WriteReq};
use crate::{Db, PagedbError, RealmId, Result, SegmentKind, SegmentPageKind};

const PAGE: usize = 4096;
const REALM: RealmId = RealmId::new([1u8; 16]);

/// MemVfs wrapper that injects one-shot metadata and main.db I/O failures.
#[derive(Clone)]
struct FailOnceVfs {
    inner: MemVfs,
    fail_live_segment_open_path: Arc<Mutex<Option<String>>>,
    fail_main_db_read_at: Arc<AtomicBool>,
    fail_main_db_read_open: Arc<AtomicBool>,
    fail_main_db_write_at: Arc<AtomicBool>,
    fail_rename: Arc<AtomicBool>,
    fail_sync_dir: Arc<AtomicBool>,
    fail_tombstone_list_dir: Arc<AtomicBool>,
    fail_tombstone_len: Arc<AtomicBool>,
    fail_tombstone_remove: Arc<AtomicBool>,
    fail_writer_lock: Arc<AtomicBool>,
    main_db_write_at_count: Arc<AtomicUsize>,
    short_write_at: Arc<Mutex<Option<(String, u64)>>>,
    short_read_at: Arc<Mutex<Option<(String, u64)>>>,
    short_main_db_read_at_or_after: Arc<Mutex<Option<u64>>>,
}

impl FailOnceVfs {
    fn new(inner: MemVfs) -> Self {
        FailOnceVfs {
            inner,
            fail_live_segment_open_path: Arc::new(Mutex::new(None)),
            fail_main_db_read_at: Arc::new(AtomicBool::new(false)),
            fail_main_db_read_open: Arc::new(AtomicBool::new(false)),
            fail_main_db_write_at: Arc::new(AtomicBool::new(false)),
            fail_rename: Arc::new(AtomicBool::new(false)),
            fail_sync_dir: Arc::new(AtomicBool::new(false)),
            fail_tombstone_list_dir: Arc::new(AtomicBool::new(false)),
            fail_tombstone_len: Arc::new(AtomicBool::new(false)),
            fail_tombstone_remove: Arc::new(AtomicBool::new(false)),
            fail_writer_lock: Arc::new(AtomicBool::new(false)),
            main_db_write_at_count: Arc::new(AtomicUsize::new(0)),
            short_write_at: Arc::new(Mutex::new(None)),
            short_read_at: Arc::new(Mutex::new(None)),
            short_main_db_read_at_or_after: Arc::new(Mutex::new(None)),
        }
    }

    fn injected() -> PagedbError {
        PagedbError::Io(std::io::Error::other("injected metadata fault"))
    }
}

struct FailFile<F> {
    inner: F,
    path: String,
    fail_main_db_read_at: Arc<AtomicBool>,
    fail_main_db_write_at: Arc<AtomicBool>,
    fail_tombstone_len: Arc<AtomicBool>,
    main_db_write_at_count: Arc<AtomicUsize>,
    short_write_at: Arc<Mutex<Option<(String, u64)>>>,
    short_read_at: Arc<Mutex<Option<(String, u64)>>>,
    short_main_db_read_at_or_after: Arc<Mutex<Option<u64>>>,
}

impl Vfs for FailOnceVfs {
    type File = FailFile<<MemVfs as Vfs>::File>;
    type LockHandle = <MemVfs as Vfs>::LockHandle;

    async fn open(&self, path: &str, mode: OpenMode) -> Result<Self::File> {
        let fail_live_segment_open = if matches!(mode, OpenMode::Read) {
            let mut guard = self.fail_live_segment_open_path.lock().unwrap();
            if guard.as_deref() == Some(path) {
                guard.take();
                true
            } else {
                false
            }
        } else {
            false
        };
        if fail_live_segment_open {
            return Err(PagedbError::Io(std::io::Error::from(
                std::io::ErrorKind::PermissionDenied,
            )));
        }
        if self.fail_main_db_read_open.swap(false, Ordering::SeqCst)
            && matches!(mode, OpenMode::Read)
            && path == "/main.db"
        {
            return Err(PagedbError::Io(std::io::Error::from(
                std::io::ErrorKind::PermissionDenied,
            )));
        }
        Ok(FailFile {
            inner: self.inner.open(path, mode).await?,
            path: path.to_string(),
            fail_main_db_read_at: self.fail_main_db_read_at.clone(),
            fail_main_db_write_at: self.fail_main_db_write_at.clone(),
            fail_tombstone_len: self.fail_tombstone_len.clone(),
            main_db_write_at_count: self.main_db_write_at_count.clone(),
            short_write_at: self.short_write_at.clone(),
            short_read_at: self.short_read_at.clone(),
            short_main_db_read_at_or_after: self.short_main_db_read_at_or_after.clone(),
        })
    }
    async fn remove(&self, path: &str) -> Result<()> {
        if self.fail_tombstone_remove.swap(false, Ordering::SeqCst)
            && path.starts_with("seg/.tombstone/")
        {
            return Err(PagedbError::Io(std::io::Error::from(
                std::io::ErrorKind::PermissionDenied,
            )));
        }
        self.inner.remove(path).await
    }
    async fn rename(&self, from: &str, to: &str) -> Result<()> {
        if self.fail_rename.swap(false, Ordering::SeqCst) {
            return Err(Self::injected());
        }
        self.inner.rename(from, to).await
    }
    async fn list_dir(&self, path: &str) -> Result<Vec<String>> {
        if self.fail_tombstone_list_dir.swap(false, Ordering::SeqCst) && path == "seg/.tombstone" {
            return Err(PagedbError::Io(std::io::Error::from(
                std::io::ErrorKind::PermissionDenied,
            )));
        }
        self.inner.list_dir(path).await
    }
    async fn mkdir_all(&self, path: &str) -> Result<()> {
        self.inner.mkdir_all(path).await
    }
    async fn sync_dir(&self, path: &str) -> Result<()> {
        if self.fail_sync_dir.swap(false, Ordering::SeqCst) {
            return Err(Self::injected());
        }
        self.inner.sync_dir(path).await
    }
    async fn lock_exclusive(&self, path: &str) -> Result<Self::LockHandle> {
        if path == ".writer.lock" && self.fail_writer_lock.swap(false, Ordering::SeqCst) {
            return Err(PagedbError::Io(std::io::Error::from(
                std::io::ErrorKind::PermissionDenied,
            )));
        }
        self.inner.lock_exclusive(path).await
    }
    async fn lock_shared(&self, path: &str) -> Result<Self::LockHandle> {
        self.inner.lock_shared(path).await
    }
}

impl<F: VfsFile + Sync> VfsFile for FailFile<F> {
    async fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        if self.fail_main_db_read_at.swap(false, Ordering::SeqCst) && self.path == "/main.db" {
            return Err(PagedbError::Io(std::io::Error::from(
                std::io::ErrorKind::PermissionDenied,
            )));
        }
        let short_read = {
            let mut guard = self.short_read_at.lock().unwrap();
            if guard.as_ref() == Some(&(self.path.clone(), offset)) {
                guard.take();
                true
            } else {
                false
            }
        };
        let short_main_db_read = {
            let mut guard = self.short_main_db_read_at_or_after.lock().unwrap();
            if self.path == "/main.db" && guard.is_some_and(|min_offset| offset >= min_offset) {
                guard.take();
                true
            } else {
                false
            }
        };
        if short_read || short_main_db_read {
            let n = buf.len().saturating_sub(1);
            if n == 0 {
                return Ok(0);
            }
            return self.inner.read_at(offset, &mut buf[..n]).await;
        }
        self.inner.read_at(offset, buf).await
    }
    async fn read_at_vectored(&self, reqs: &mut [ReadReq<'_>]) -> Result<()> {
        self.inner.read_at_vectored(reqs).await
    }
    async fn write_at(&mut self, offset: u64, buf: &[u8]) -> Result<usize> {
        if self.path == "/main.db" {
            self.main_db_write_at_count.fetch_add(1, Ordering::SeqCst);
        }
        if self.fail_main_db_write_at.swap(false, Ordering::SeqCst) && self.path == "/main.db" {
            return Err(PagedbError::Io(std::io::Error::from(
                std::io::ErrorKind::PermissionDenied,
            )));
        }
        let short_write = {
            let mut guard = self.short_write_at.lock().unwrap();
            if guard.as_ref() == Some(&(self.path.clone(), offset)) {
                guard.take();
                true
            } else {
                false
            }
        };
        if short_write {
            let n = buf.len().saturating_sub(1);
            if n == 0 {
                return Ok(0);
            }
            return self.inner.write_at(offset, &buf[..n]).await;
        }
        self.inner.write_at(offset, buf).await
    }
    async fn write_at_vectored(&mut self, reqs: &[WriteReq<'_>]) -> Result<()> {
        self.inner.write_at_vectored(reqs).await
    }
    async fn sync(&mut self) -> Result<()> {
        self.inner.sync().await
    }
    async fn truncate(&mut self, len: u64) -> Result<()> {
        self.inner.truncate(len).await
    }
    async fn len(&self) -> Result<u64> {
        if self.fail_tombstone_len.swap(false, Ordering::SeqCst)
            && self.path.starts_with("seg/.tombstone/")
        {
            return Err(PagedbError::Io(std::io::Error::from(
                std::io::ErrorKind::PermissionDenied,
            )));
        }
        self.inner.len().await
    }
    async fn is_empty(&self) -> Result<bool> {
        self.inner.is_empty().await
    }
    fn supports_direct_io(&self) -> bool {
        self.inner.supports_direct_io()
    }
}

#[tokio::test(flavor = "current_thread")]
async fn journal_actions_surface_rename_error_then_retry_succeeds() {
    let mem = MemVfs::new();
    mem.mkdir_all("seg/.staging").await.unwrap();
    let id = [7u8; 16];
    let staging = format!("seg/.staging/{}", hex(&id));
    let mut f = mem.open(&staging, OpenMode::CreateNew).await.unwrap();
    f.write_at(0, b"payload").await.unwrap();
    drop(f);

    let vfs = FailOnceVfs::new(mem.clone());
    let actions = vec![JournalAction::Promote { segment_id: id }];

    vfs.fail_rename.store(true, Ordering::SeqCst);
    let err = execute_journal_actions(&vfs, &actions)
        .await
        .expect_err("failed rename must surface, not be swallowed");
    assert!(matches!(err, PagedbError::Io(_)));

    // Retry (fault cleared) completes the action.
    execute_journal_actions(&vfs, &actions).await.unwrap();
    let live = format!("seg/{}", hex(&id));
    assert!(mem.open(&live, OpenMode::Read).await.is_ok());
}

#[tokio::test(flavor = "current_thread")]
async fn journal_actions_tolerate_already_completed_rename() {
    // Source missing = action already ran; replay must be a no-op success.
    let mem = MemVfs::new();
    mem.mkdir_all("seg").await.unwrap();
    let id = [8u8; 16];
    let live = format!("seg/{}", hex(&id));
    mem.open(&live, OpenMode::CreateNew).await.unwrap();

    let actions = vec![JournalAction::Promote { segment_id: id }];
    execute_journal_actions(&mem, &actions).await.unwrap();
    assert!(mem.open(&live, OpenMode::Read).await.is_ok());
}

#[tokio::test(flavor = "current_thread")]
async fn gc_sync_dir_error_surfaces_then_retry_succeeds() {
    let vfs = FailOnceVfs::new(MemVfs::new());
    let options = OpenOptions::default().with_commit_history_retain(RetainPolicy::Disabled);
    let db = Db::open_internal_with_options(vfs.clone(), [9u8; 32], PAGE, REALM, options)
        .await
        .unwrap();
    let mut w = db
        .create_segment(REALM, SegmentKind::Unspecified)
        .await
        .unwrap();
    w.append_page(SegmentPageKind::Data, b"x").await.unwrap();
    let m = w.seal().await.unwrap();
    {
        let mut t = db.begin_write().await.unwrap();
        t.link_segment("dead", &m).await.unwrap();
        t.commit().await.unwrap();
    }
    {
        let mut t = db.begin_write().await.unwrap();
        t.unlink_segment("dead").await.unwrap();
        t.commit().await.unwrap();
    }

    // First gc_now hits the injected sync_dir failure and must SURFACE it.
    vfs.fail_sync_dir.store(true, Ordering::SeqCst);
    let err = db
        .gc_now()
        .await
        .expect_err("gc sync_dir failure must surface");
    assert!(matches!(err, PagedbError::Io(_)));

    // Retry succeeds and the segment is gone.
    db.gc_now().await.unwrap();
    let err = db.open_segment(REALM, "dead").await.err().unwrap();
    assert!(matches!(err, PagedbError::NotFound));
}

#[tokio::test(flavor = "current_thread")]
async fn journal_actions_surface_sync_dir_error_then_retry_succeeds() {
    let mem = MemVfs::new();
    mem.mkdir_all("seg/.staging").await.unwrap();
    let id = [9u8; 16];
    let staging = format!("seg/.staging/{}", hex(&id));
    let mut f = mem.open(&staging, OpenMode::CreateNew).await.unwrap();
    f.write_at(0, b"payload").await.unwrap();
    drop(f);

    let vfs = FailOnceVfs::new(mem.clone());
    let actions = vec![JournalAction::Promote { segment_id: id }];

    vfs.fail_sync_dir.store(true, Ordering::SeqCst);
    let err = execute_journal_actions(&vfs, &actions)
        .await
        .expect_err("journal action sync_dir failures must surface before the journal is cleared");
    assert!(matches!(err, PagedbError::Io(_)));

    // Retry must complete even if the prior attempt already performed the
    // rename but failed before making the directory entry durable.
    execute_journal_actions(&vfs, &actions).await.unwrap();
    let live = format!("seg/{}", hex(&id));
    assert!(mem.open(&live, OpenMode::Read).await.is_ok());
}

#[tokio::test(flavor = "current_thread")]
async fn reconcile_surfaces_live_segment_open_error_then_retry_succeeds() {
    let vfs = FailOnceVfs::new(MemVfs::new());
    {
        let db = Db::open_internal(vfs.clone(), [9u8; 32], PAGE, REALM)
            .await
            .unwrap();
        let mut w = db
            .create_segment(REALM, SegmentKind::Unspecified)
            .await
            .unwrap();
        w.append_page(SegmentPageKind::Data, b"recoverable")
            .await
            .unwrap();
        let m = w.seal().await.unwrap();
        let live_path = format!("seg/{}", hex(&m.segment_id));
        let mut t = db.begin_write().await.unwrap();
        t.link_segment("open-error", &m).await.unwrap();
        t.commit().await.unwrap();
        *vfs.fail_live_segment_open_path.lock().unwrap() = Some(live_path);
    }

    let err = match Db::open_existing(vfs.clone(), [9u8; 32], PAGE, REALM).await {
        Ok(_) => panic!("reconcile must surface live segment open I/O errors"),
        Err(err) => err,
    };
    assert!(
        matches!(err, PagedbError::Io(ref io) if io.kind() == std::io::ErrorKind::PermissionDenied),
        "expected live segment PermissionDenied to surface, got {err:?}"
    );

    let db = Db::open_existing(vfs, [9u8; 32], PAGE, REALM)
        .await
        .expect("retry after transient open fault must succeed");
    let reader = db.open_segment(REALM, "open-error").await.unwrap();
    let page = reader.read_page(1).await.unwrap();
    assert!(page.starts_with(b"recoverable"));
}

#[tokio::test(flavor = "current_thread")]
async fn reconcile_retries_short_live_segment_footer_read() {
    let vfs = FailOnceVfs::new(MemVfs::new());
    {
        let db = Db::open_internal(vfs.clone(), [9u8; 32], PAGE, REALM)
            .await
            .unwrap();
        let mut w = db
            .create_segment(REALM, SegmentKind::Unspecified)
            .await
            .unwrap();
        w.append_page(SegmentPageKind::Data, b"reconcile-short-footer")
            .await
            .unwrap();
        let m = w.seal().await.unwrap();
        let live_path = format!("seg/{}", hex(&m.segment_id));
        let footer_offset = (m.page_count - 1) * PAGE as u64;
        let mut t = db.begin_write().await.unwrap();
        t.link_segment("reconcile-short-footer", &m).await.unwrap();
        t.commit().await.unwrap();
        *vfs.short_read_at.lock().unwrap() = Some((live_path, footer_offset));
    }

    let db = Db::open_existing(vfs, [9u8; 32], PAGE, REALM)
        .await
        .expect("reconcile must retry transient short live segment footer reads");
    let reader = db
        .open_segment(REALM, "reconcile-short-footer")
        .await
        .unwrap();
    let page = reader.read_page(1).await.unwrap();
    assert!(page.starts_with(b"reconcile-short-footer"));
}

#[tokio::test(flavor = "current_thread")]
async fn reconcile_surfaces_promote_sync_dir_error_then_retry_succeeds() {
    let vfs = FailOnceVfs::new(MemVfs::new());
    {
        let db = Db::open_internal(vfs.clone(), [9u8; 32], PAGE, REALM)
            .await
            .unwrap();
        let mut w = db
            .create_segment(REALM, SegmentKind::Unspecified)
            .await
            .unwrap();
        w.append_page(SegmentPageKind::Data, b"staged-promote")
            .await
            .unwrap();
        let m = w.seal().await.unwrap();
        let live_path = format!("seg/{}", hex(&m.segment_id));
        let staging_path = format!("seg/.staging/{}", hex(&m.segment_id));
        let mut t = db.begin_write().await.unwrap();
        t.link_segment("staged-promote", &m).await.unwrap();
        t.commit().await.unwrap();

        vfs.inner.rename(&live_path, &staging_path).await.unwrap();
    }

    vfs.fail_sync_dir.store(true, Ordering::SeqCst);
    let err = match Db::open_existing(vfs.clone(), [9u8; 32], PAGE, REALM).await {
        Ok(db) => {
            drop(db);
            panic!("reconcile promote sync_dir errors must not be swallowed during open");
        }
        Err(err) => err,
    };
    assert!(
        matches!(err, PagedbError::Io(_)),
        "expected staged-promote sync_dir error to surface, got {err:?}"
    );

    let db = Db::open_existing(vfs, [9u8; 32], PAGE, REALM)
        .await
        .expect("retry after transient reconcile sync fault must succeed");
    let reader = db.open_segment(REALM, "staged-promote").await.unwrap();
    let page = reader.read_page(1).await.unwrap();
    assert!(page.starts_with(b"staged-promote"));
}

#[tokio::test(flavor = "current_thread")]
async fn open_segment_surfaces_live_segment_open_error_then_retry_succeeds() {
    let vfs = FailOnceVfs::new(MemVfs::new());
    let db = Db::open_internal(vfs.clone(), [9u8; 32], PAGE, REALM)
        .await
        .unwrap();
    let mut w = db
        .create_segment(REALM, SegmentKind::Unspecified)
        .await
        .unwrap();
    w.append_page(SegmentPageKind::Data, b"reader")
        .await
        .unwrap();
    let m = w.seal().await.unwrap();
    let live_path = format!("seg/{}", hex(&m.segment_id));
    let mut t = db.begin_write().await.unwrap();
    t.link_segment("reader-open", &m).await.unwrap();
    t.commit().await.unwrap();

    *vfs.fail_live_segment_open_path.lock().unwrap() = Some(live_path);
    let err = match db.open_segment(REALM, "reader-open").await {
        Ok(_) => panic!("live segment open I/O errors must not be swallowed"),
        Err(err) => err,
    };
    assert!(
        matches!(err, PagedbError::Io(ref io) if io.kind() == std::io::ErrorKind::PermissionDenied),
        "expected live segment PermissionDenied to surface, got {err:?}"
    );

    let reader = db
        .open_segment(REALM, "reader-open")
        .await
        .expect("retry after transient open fault must succeed");
    let page = reader.read_page(1).await.unwrap();
    assert!(page.starts_with(b"reader"));
}

#[tokio::test(flavor = "current_thread")]
async fn open_segment_retries_short_header_read() {
    let vfs = FailOnceVfs::new(MemVfs::new());
    let db = Db::open_internal(vfs.clone(), [9u8; 32], PAGE, REALM)
        .await
        .unwrap();
    let mut w = db
        .create_segment(REALM, SegmentKind::Unspecified)
        .await
        .unwrap();
    w.append_page(SegmentPageKind::Data, b"short-header")
        .await
        .unwrap();
    let m = w.seal().await.unwrap();
    let live_path = format!("seg/{}", hex(&m.segment_id));
    let mut t = db.begin_write().await.unwrap();
    t.link_segment("short-header", &m).await.unwrap();
    t.commit().await.unwrap();

    *vfs.short_read_at.lock().unwrap() = Some((live_path, 0));
    let reader = db
        .open_segment(REALM, "short-header")
        .await
        .expect("open_segment must retry transient short header reads");
    let page = reader.read_page(1).await.unwrap();
    assert!(page.starts_with(b"short-header"));
}

#[tokio::test(flavor = "current_thread")]
async fn segment_read_retries_short_data_page_read() {
    let vfs = FailOnceVfs::new(MemVfs::new());
    let db = Db::open_internal(vfs.clone(), [9u8; 32], PAGE, REALM)
        .await
        .unwrap();
    let mut w = db
        .create_segment(REALM, SegmentKind::Unspecified)
        .await
        .unwrap();
    w.append_page(SegmentPageKind::Data, b"short-read")
        .await
        .unwrap();
    let m = w.seal().await.unwrap();
    let live_path = format!("seg/{}", hex(&m.segment_id));
    let mut t = db.begin_write().await.unwrap();
    t.link_segment("short-read", &m).await.unwrap();
    t.commit().await.unwrap();

    let reader = db.open_segment(REALM, "short-read").await.unwrap();
    *vfs.short_read_at.lock().unwrap() = Some((live_path, PAGE as u64));
    let page = reader
        .read_page(1)
        .await
        .expect("segment page reads must retry transient short reads");
    assert!(page.starts_with(b"short-read"));
}

#[tokio::test(flavor = "current_thread")]
async fn open_segment_retries_short_footer_read() {
    let vfs = FailOnceVfs::new(MemVfs::new());
    let db = Db::open_internal(vfs.clone(), [9u8; 32], PAGE, REALM)
        .await
        .unwrap();
    let mut w = db
        .create_segment(REALM, SegmentKind::Unspecified)
        .await
        .unwrap();
    w.append_page(SegmentPageKind::Data, b"short-footer")
        .await
        .unwrap();
    let m = w.seal().await.unwrap();
    let live_path = format!("seg/{}", hex(&m.segment_id));
    let footer_offset = (m.page_count - 1) * PAGE as u64;
    let mut t = db.begin_write().await.unwrap();
    t.link_segment("short-footer", &m).await.unwrap();
    t.commit().await.unwrap();

    *vfs.short_read_at.lock().unwrap() = Some((live_path, footer_offset));
    let reader = db
        .open_segment(REALM, "short-footer")
        .await
        .expect("open_segment must retry transient short footer reads");
    let page = reader.read_page(1).await.unwrap();
    assert!(page.starts_with(b"short-footer"));
}

#[tokio::test(flavor = "current_thread")]
async fn find_extent_retries_short_index_page_read() {
    let vfs = FailOnceVfs::new(MemVfs::new());
    let db = Db::open_internal(vfs.clone(), [9u8; 32], PAGE, REALM)
        .await
        .unwrap();
    let mut w = db
        .create_segment(REALM, SegmentKind::Unspecified)
        .await
        .unwrap();
    let extent = w.append_extent(&[b"indexed-page"]).await.unwrap();
    let m = w.seal().await.unwrap();
    let live_path = format!("seg/{}", hex(&m.segment_id));
    let index_offset = 2 * PAGE as u64;
    let mut t = db.begin_write().await.unwrap();
    t.link_segment("short-index", &m).await.unwrap();
    t.commit().await.unwrap();

    let reader = db.open_segment(REALM, "short-index").await.unwrap();
    assert_eq!(extent.start_page_id, 1);
    *vfs.short_read_at.lock().unwrap() = Some((live_path, index_offset));
    let pages = reader
        .find_extent(extent.start_page_id)
        .await
        .expect("extent index load must retry transient short index-page reads");
    assert_eq!(pages.len(), 1);
    assert!(pages[0].starts_with(b"indexed-page"));
}

#[tokio::test(flavor = "current_thread")]
async fn segment_writer_retries_short_data_page_write_before_publish() {
    let vfs = FailOnceVfs::new(MemVfs::new());
    let db = Db::open_internal(vfs.clone(), [9u8; 32], PAGE, REALM)
        .await
        .unwrap();
    let mut w = db
        .create_segment(REALM, SegmentKind::Unspecified)
        .await
        .unwrap();
    let staging_entries = vfs.inner.list_dir("seg/.staging").await.unwrap();
    assert_eq!(staging_entries.len(), 1);
    let staging_path = format!("seg/.staging/{}", staging_entries[0]);
    *vfs.short_write_at.lock().unwrap() = Some((staging_path, PAGE as u64));

    w.append_page(SegmentPageKind::Data, b"short-write")
        .await
        .expect("segment writer must retry short data page writes");
    let m = w.seal().await.unwrap();
    let mut t = db.begin_write().await.unwrap();
    t.link_segment("short-write", &m).await.unwrap();
    t.commit().await.unwrap();

    let reader = db.open_segment(REALM, "short-write").await.unwrap();
    let page = reader.read_page(1).await.unwrap();
    assert!(page.starts_with(b"short-write"));
}

#[tokio::test(flavor = "current_thread")]
async fn spill_append_retries_short_body_write_before_returning_handle() {
    let vfs = FailOnceVfs::new(MemVfs::new());
    let opts = OpenOptions::default().with_scratch_bytes(1024 * 1024);
    let db = Db::open_internal_with_options(vfs.clone(), [9u8; 32], PAGE, REALM, opts)
        .await
        .unwrap();
    let mut t = db.begin_write().await.unwrap();

    *vfs.short_write_at.lock().unwrap() = Some(("tmp/scratch-1".to_string(), 0));
    let got = {
        let mut spill = t.spill_scope();
        let handle = spill
            .append(b"spill-short-write")
            .await
            .expect("spill append must retry short ciphertext body writes");

        spill
            .read(handle)
            .await
            .expect("spill handle must decrypt after a transient short write")
    };
    assert_eq!(got, b"spill-short-write");

    t.abort().await;
}

#[tokio::test(flavor = "current_thread")]
async fn spill_read_retries_short_body_read_before_decrypting() {
    let vfs = FailOnceVfs::new(MemVfs::new());
    let opts = OpenOptions::default().with_scratch_bytes(1024 * 1024);
    let db = Db::open_internal_with_options(vfs.clone(), [9u8; 32], PAGE, REALM, opts)
        .await
        .unwrap();
    let mut t = db.begin_write().await.unwrap();

    let got = {
        let mut spill = t.spill_scope();
        let handle = spill.append(b"spill-short-read").await.unwrap();

        *vfs.short_read_at.lock().unwrap() = Some(("tmp/scratch-1".to_string(), 0));
        spill
            .read(handle)
            .await
            .expect("spill reads must retry partial ciphertext body reads before decrypting")
    };
    assert_eq!(got, b"spill-short-read");

    t.abort().await;
}

#[tokio::test(flavor = "current_thread")]
async fn commit_retries_short_header_slot_write_before_reporting_success() {
    let vfs = FailOnceVfs::new(MemVfs::new());
    {
        let db = Db::open_internal(vfs.clone(), [9u8; 32], PAGE, REALM)
            .await
            .unwrap();
        let mut t = db.begin_write().await.unwrap();
        t.put(b"header-short-write", b"durable").await.unwrap();
        *vfs.short_write_at.lock().unwrap() = Some(("/main.db".to_string(), PAGE as u64));
        t.commit()
            .await
            .expect("header commit must retry short inactive-slot writes");
    }

    let reopened = Db::open_existing(vfs, [9u8; 32], PAGE, REALM)
        .await
        .expect("database should reopen after committed header short write retry");
    let r = reopened.begin_read().await.unwrap();
    assert_eq!(
        r.get(b"header-short-write").await.unwrap().as_deref(),
        Some(&b"durable"[..])
    );
}

#[tokio::test(flavor = "current_thread")]
async fn open_existing_retries_short_latest_header_slot_read() {
    let vfs = FailOnceVfs::new(MemVfs::new());
    {
        let db = Db::open_internal(vfs.clone(), [9u8; 32], PAGE, REALM)
            .await
            .unwrap();
        let mut t = db.begin_write().await.unwrap();
        t.put(b"header-short-read", b"latest").await.unwrap();
        t.commit().await.unwrap();
    }

    *vfs.short_read_at.lock().unwrap() = Some(("/main.db".to_string(), PAGE as u64));
    let reopened = Db::open_existing(vfs, [9u8; 32], PAGE, REALM)
        .await
        .expect("open_existing must retry transient short header-slot reads");
    let r = reopened.begin_read().await.unwrap();
    assert_eq!(
        r.get(b"header-short-read").await.unwrap().as_deref(),
        Some(&b"latest"[..])
    );
}

#[tokio::test(flavor = "current_thread")]
async fn read_retries_short_main_data_page_read() {
    let vfs = FailOnceVfs::new(MemVfs::new());
    {
        let db = Db::open_internal(vfs.clone(), [9u8; 32], PAGE, REALM)
            .await
            .unwrap();
        let mut t = db.begin_write().await.unwrap();
        t.put(b"main-short-read", b"value").await.unwrap();
        t.commit().await.unwrap();
    }

    let reopened = Db::open_read_only(vfs.clone(), [9u8; 32], PAGE, REALM, OpenOptions::default())
        .await
        .unwrap();

    *vfs.short_main_db_read_at_or_after.lock().unwrap() = Some((PAGE * 2) as u64);
    let r = reopened.begin_read().await.unwrap();
    assert_eq!(
        r.get(b"main-short-read").await.unwrap().as_deref(),
        Some(&b"value"[..])
    );
}

#[tokio::test(flavor = "current_thread")]
async fn compact_now_surfaces_live_segment_open_error_then_retry_succeeds() {
    let vfs = FailOnceVfs::new(MemVfs::new());
    let db = Db::open_internal(vfs.clone(), [9u8; 32], PAGE, REALM)
        .await
        .unwrap();
    let mut w = db
        .create_segment(REALM, SegmentKind::Unspecified)
        .await
        .unwrap();
    w.append_page(SegmentPageKind::Data, b"compact-reader")
        .await
        .unwrap();
    let m = w.seal().await.unwrap();
    let live_path = format!("seg/{}", hex(&m.segment_id));
    let mut t = db.begin_write().await.unwrap();
    t.link_segment("compact-open", &m).await.unwrap();
    t.commit().await.unwrap();

    *vfs.fail_live_segment_open_path.lock().unwrap() = Some(live_path);
    let err = match db.compact_now().await {
        Ok(_) => panic!("compact_now must not skip live segment open I/O errors"),
        Err(err) => err,
    };
    assert!(
        matches!(err, PagedbError::Io(ref io) if io.kind() == std::io::ErrorKind::PermissionDenied),
        "expected compact live segment PermissionDenied to surface, got {err:?}"
    );

    db.compact_now()
        .await
        .expect("retry after transient compact segment-open fault must succeed");
    let reader = db.open_segment(REALM, "compact-open").await.unwrap();
    let page = reader.read_page(1).await.unwrap();
    assert!(page.starts_with(b"compact-reader"));
}

#[tokio::test(flavor = "current_thread")]
async fn compact_now_surfaces_dense_repack_sync_dir_error_then_reopen_succeeds() {
    let vfs = FailOnceVfs::new(MemVfs::new());
    {
        let db = Db::open_internal(vfs.clone(), [9u8; 32], PAGE, REALM)
            .await
            .unwrap();
        {
            let mut t = db.begin_write().await.unwrap();
            t.put(b"sentinel", b"kept").await.unwrap();
            for i in 0..80u32 {
                let key = format!("dead-{i:04}");
                t.put(key.as_bytes(), &[i as u8; 96]).await.unwrap();
            }
            t.commit().await.unwrap();
        }
        {
            let mut t = db.begin_write().await.unwrap();
            for i in 0..80u32 {
                let key = format!("dead-{i:04}");
                t.delete(key.as_bytes()).await.unwrap();
            }
            t.commit().await.unwrap();
        }

        vfs.fail_sync_dir.store(true, Ordering::SeqCst);
        let err = db
            .compact_now()
            .await
            .expect_err("dense repack root sync_dir failures must surface");
        assert!(
            matches!(err, PagedbError::DurablyCommittedButUnpublished { .. }),
            "post-rename sync failure must report unknown publication state, got {err:?}"
        );
    }

    let reopened = Db::open_existing(vfs, [9u8; 32], PAGE, REALM)
        .await
        .expect("reopen after transient dense-repack sync fault must succeed");
    let r = reopened.begin_read().await.unwrap();
    assert_eq!(
        r.get(b"sentinel").await.unwrap().as_deref(),
        Some(&b"kept"[..])
    );
}

#[tokio::test(flavor = "current_thread")]
async fn gc_now_surfaces_tombstone_list_dir_error_then_retry_succeeds() {
    let vfs = FailOnceVfs::new(MemVfs::new());
    let options = OpenOptions::default().with_commit_history_retain(RetainPolicy::Disabled);
    let db = Db::open_internal_with_options(vfs.clone(), [9u8; 32], PAGE, REALM, options)
        .await
        .unwrap();
    let mut w = db
        .create_segment(REALM, SegmentKind::Unspecified)
        .await
        .unwrap();
    w.append_page(SegmentPageKind::Data, b"gc-list")
        .await
        .unwrap();
    let m = w.seal().await.unwrap();
    {
        let mut t = db.begin_write().await.unwrap();
        t.link_segment("gc-list", &m).await.unwrap();
        t.commit().await.unwrap();
    }
    {
        let mut t = db.begin_write().await.unwrap();
        t.unlink_segment("gc-list").await.unwrap();
        t.commit().await.unwrap();
    }

    vfs.fail_tombstone_list_dir.store(true, Ordering::SeqCst);
    let err = db
        .gc_now()
        .await
        .expect_err("tombstone list_dir I/O errors must surface");
    assert!(
        matches!(err, PagedbError::Io(ref io) if io.kind() == std::io::ErrorKind::PermissionDenied),
        "expected tombstone list_dir PermissionDenied to surface, got {err:?}"
    );

    let stats = db.gc_now().await.unwrap();
    assert!(stats.reclaimed_segments >= 1);
}

#[tokio::test(flavor = "current_thread")]
async fn stats_surfaces_main_db_open_error_then_retry_succeeds() {
    let vfs = FailOnceVfs::new(MemVfs::new());
    let db = Db::open_internal(vfs.clone(), [9u8; 32], PAGE, REALM)
        .await
        .unwrap();

    vfs.fail_main_db_read_open.store(true, Ordering::SeqCst);
    let err = db
        .stats()
        .await
        .expect_err("main.db read errors must not be reported as zero bytes");
    assert!(
        matches!(err, PagedbError::Io(ref io) if io.kind() == std::io::ErrorKind::PermissionDenied),
        "expected stats PermissionDenied to surface, got {err:?}"
    );

    let stats = db.stats().await.unwrap();
    assert!(stats.main_db_bytes > 0);
}

#[tokio::test(flavor = "current_thread")]
async fn stats_surfaces_free_list_read_error_then_retry_succeeds() {
    let vfs = FailOnceVfs::new(MemVfs::new());
    let opts = OpenOptions::default().with_commit_history_retain(RetainPolicy::Disabled);
    let value = [0xABu8; 256];
    {
        let db = Db::open_internal_with_options(vfs.clone(), [9u8; 32], PAGE, REALM, opts.clone())
            .await
            .unwrap();
        {
            let mut w = db.begin_write().await.unwrap();
            for i in 0u32..400 {
                w.put(format!("k{i:05}").as_bytes(), &value).await.unwrap();
            }
            w.commit().await.unwrap();
        }
        {
            let mut w = db.begin_write().await.unwrap();
            for i in 0u32..400 {
                w.delete(format!("k{i:05}").as_bytes()).await.unwrap();
            }
            w.commit().await.unwrap();
        }
        assert!(
            db.stats().await.unwrap().free_list_pending_entries > 20,
            "test setup must create durable free-list entries"
        );
    }

    let db = Db::open_existing_with_options(vfs.clone(), [9u8; 32], PAGE, REALM, opts)
        .await
        .unwrap();
    vfs.fail_main_db_read_at.store(true, Ordering::SeqCst);
    let err = db
        .stats()
        .await
        .expect_err("free-list read errors must not be reported as zero pending entries");
    assert!(
        matches!(err, PagedbError::Io(ref io) if io.kind() == std::io::ErrorKind::PermissionDenied),
        "expected stats free-list PermissionDenied to surface, got {err:?}"
    );

    let stats = db.stats().await.unwrap();
    assert!(stats.free_list_pending_entries > 20);
}

#[tokio::test(flavor = "current_thread")]
async fn open_surfaces_writer_lock_io_error_then_retry_succeeds() {
    let vfs = FailOnceVfs::new(MemVfs::new());

    vfs.fail_writer_lock.store(true, Ordering::SeqCst);
    let err = match Db::open(vfs.clone(), [9u8; 32], PAGE, REALM, Default::default()).await {
        Ok(_) => panic!("writer lock I/O errors must not be collapsed to AlreadyOpen"),
        Err(err) => err,
    };
    assert!(
        matches!(err, PagedbError::Io(ref io) if io.kind() == std::io::ErrorKind::PermissionDenied),
        "expected writer lock PermissionDenied to surface, got {err:?}"
    );

    Db::open(vfs, [9u8; 32], PAGE, REALM, Default::default())
        .await
        .expect("retry after transient writer lock fault must succeed");
}

#[tokio::test(flavor = "current_thread")]
async fn open_surfaces_main_db_probe_error_then_retry_succeeds() {
    let vfs = FailOnceVfs::new(MemVfs::new());
    let existing = Db::open_internal(vfs.clone(), [9u8; 32], PAGE, REALM)
        .await
        .unwrap();
    drop(existing);

    vfs.fail_main_db_read_open.store(true, Ordering::SeqCst);
    let err = match Db::open(vfs.clone(), [9u8; 32], PAGE, REALM, Default::default()).await {
        Ok(_) => panic!("main.db probe I/O errors must not be discarded"),
        Err(err) => err,
    };
    assert!(
        matches!(err, PagedbError::Io(ref io) if io.kind() == std::io::ErrorKind::PermissionDenied),
        "expected main.db probe PermissionDenied to surface, got {err:?}"
    );

    Db::open(vfs, [9u8; 32], PAGE, REALM, Default::default())
        .await
        .expect("retry after transient main.db probe fault must succeed");
}

#[tokio::test(flavor = "current_thread")]
async fn open_preserves_named_counter_when_nonce_anchor_is_higher() {
    let vfs = FailOnceVfs::new(MemVfs::new());
    let opts = OpenOptions::default().with_buffer_pool_pages(64);
    {
        let db = Db::open_internal_with_options(vfs.clone(), [9u8; 32], PAGE, REALM, opts.clone())
            .await
            .unwrap();
        let mut txn = db.begin_write().await.unwrap();
        let mut counter = txn.counter("recovery-write").unwrap();
        counter.set(1).await.unwrap();
        drop(counter);
        txn.commit().await.unwrap();
    }

    vfs.fail_main_db_write_at.store(true, Ordering::SeqCst);
    let db = Db::open_existing_with_options(vfs.clone(), [9u8; 32], PAGE, REALM, opts)
        .await
        .expect("open must not rewrite named counters from the page-nonce anchor");
    assert!(
        vfs.fail_main_db_write_at.load(Ordering::SeqCst),
        "the injected main.db write fault must remain unused during open"
    );
    let mut txn = db.begin_write().await.unwrap();
    let counter = txn.counter("recovery-write").unwrap();
    assert_eq!(counter.get().await.unwrap(), 1);
    drop(counter);
    txn.abort().await;
}

#[tokio::test(flavor = "current_thread")]
async fn open_read_only_does_not_rewrite_named_counters() {
    let vfs = FailOnceVfs::new(MemVfs::new());
    let opts = OpenOptions::default().with_buffer_pool_pages(64);
    {
        let db = Db::open_internal_with_options(vfs.clone(), [9u8; 32], PAGE, REALM, opts.clone())
            .await
            .unwrap();
        let mut txn = db.begin_write().await.unwrap();
        let mut counter = txn.counter("read-only-recovery").unwrap();
        counter.set(1).await.unwrap();
        drop(counter);
        txn.commit().await.unwrap();
    }

    let writes_before = vfs.main_db_write_at_count.load(Ordering::SeqCst);
    let db = Db::open_read_only(vfs.clone(), [9u8; 32], PAGE, REALM, opts)
        .await
        .expect("read-only open should not need recovery writes");
    assert!(!db.is_writer());
    drop(db);
    let writes_after = vfs.main_db_write_at_count.load(Ordering::SeqCst);
    assert_eq!(
        writes_after, writes_before,
        "read-only open must not mutate main.db while recovering counters"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn gc_now_surfaces_tombstone_len_error_then_retry_succeeds() {
    let vfs = FailOnceVfs::new(MemVfs::new());
    let options = OpenOptions::default().with_commit_history_retain(RetainPolicy::Disabled);
    let db = Db::open_internal_with_options(vfs.clone(), [9u8; 32], PAGE, REALM, options)
        .await
        .unwrap();
    let mut w = db
        .create_segment(REALM, SegmentKind::Unspecified)
        .await
        .unwrap();
    w.append_page(SegmentPageKind::Data, b"gc-len")
        .await
        .unwrap();
    let m = w.seal().await.unwrap();
    {
        let mut t = db.begin_write().await.unwrap();
        t.link_segment("gc-len", &m).await.unwrap();
        t.commit().await.unwrap();
    }
    {
        let mut t = db.begin_write().await.unwrap();
        t.unlink_segment("gc-len").await.unwrap();
        t.commit().await.unwrap();
    }

    vfs.fail_tombstone_len.store(true, Ordering::SeqCst);
    let err = db
        .gc_now()
        .await
        .expect_err("tombstone len I/O errors must surface before delete");
    assert!(
        matches!(err, PagedbError::Io(ref io) if io.kind() == std::io::ErrorKind::PermissionDenied),
        "expected tombstone len PermissionDenied to surface, got {err:?}"
    );

    let stats = db.gc_now().await.unwrap();
    assert!(stats.reclaimed_segments >= 1);
    assert!(stats.reclaimed_bytes > 0);
}

#[tokio::test(flavor = "current_thread")]
async fn gc_now_surfaces_tombstone_remove_error_then_retry_succeeds() {
    let vfs = FailOnceVfs::new(MemVfs::new());
    let options = OpenOptions::default().with_commit_history_retain(RetainPolicy::Disabled);
    let db = Db::open_internal_with_options(vfs.clone(), [9u8; 32], PAGE, REALM, options)
        .await
        .unwrap();
    let mut segment = db
        .create_segment(REALM, SegmentKind::Unspecified)
        .await
        .unwrap();
    segment
        .append_page(SegmentPageKind::Data, b"gc-remove")
        .await
        .unwrap();
    let meta = segment.seal().await.unwrap();
    {
        let mut txn = db.begin_write().await.unwrap();
        txn.link_segment("gc-remove", &meta).await.unwrap();
        txn.commit().await.unwrap();
    }
    {
        let mut txn = db.begin_write().await.unwrap();
        txn.unlink_segment("gc-remove").await.unwrap();
        txn.commit().await.unwrap();
    }

    vfs.fail_tombstone_remove.store(true, Ordering::SeqCst);
    let err = db
        .gc_now()
        .await
        .expect_err("tombstone remove I/O errors must surface");
    assert!(
        matches!(err, PagedbError::Io(ref io) if io.kind() == std::io::ErrorKind::PermissionDenied),
        "expected tombstone remove PermissionDenied to surface, got {err:?}"
    );

    let stats = db.gc_now().await.unwrap();
    assert!(stats.reclaimed_segments >= 1);
    assert!(stats.reclaimed_bytes > 0);
}

fn hex(bytes: &[u8; 16]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
