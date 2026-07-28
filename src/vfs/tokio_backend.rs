//! Cross-platform native VFS backed by `tokio::fs`. Advisory locking is the
//! shared two-layer protocol behind [`TokioLockHandle`], so this backend and every
//! other native backend exclude each other over the same directory. The trait
//! contract from `traits.rs` is the durable surface.

use std::path::PathBuf;
use std::sync::Arc;

use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

use crate::Result;
use crate::errors::PagedbError;

use super::blocking::offload;
use super::oslock::{LockKind, LockTable};
use super::traits::{Vfs, VfsFile, canonical_native_path, resolve_native_path};
use super::types::{OpenMode, ReadReq, WriteReq};

/// RAII advisory lock handle returned by `TokioVfs::lock_exclusive` /
/// `lock_shared`. The one native handle type, shared with every other
/// filesystem-backed backend.
pub use super::oslock::NativeLockHandle as TokioLockHandle;

// ---------------------------------------------------------------------------
// TokioVfs
// ---------------------------------------------------------------------------

/// VFS rooted at a directory. Paths supplied to all methods are resolved
/// relative to this root; a leading `/` is stripped. Cloning shares the same
/// root and lock table.
#[derive(Clone)]
pub struct TokioVfs {
    inner: Arc<TokioInner>,
}

struct TokioInner {
    root: PathBuf,
    locks: LockTable,
}

impl TokioVfs {
    /// Create a new `TokioVfs` rooted at `root`. The directory must already
    /// exist or be created before the first `open` call.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            inner: Arc::new(TokioInner {
                root: root.into(),
                locks: LockTable::new(),
            }),
        }
    }

    fn canonical_logical_path(path: &str) -> Result<String> {
        canonical_native_path(path)
    }

    fn resolve(&self, path: &str) -> Result<PathBuf> {
        resolve_native_path(&self.inner.root, path)
    }

    /// Return the filesystem root directory of this VFS instance.
    #[must_use]
    pub fn root_path(&self) -> &std::path::Path {
        &self.inner.root
    }

    async fn do_lock(&self, path: &str, kind: LockKind) -> Result<TokioLockHandle> {
        let logical_path = Self::canonical_logical_path(path)?;
        let lock_path = self.resolve(&logical_path)?;
        super::oslock::acquire(&self.inner.locks, &logical_path, lock_path, kind).await
    }
}

// ---------------------------------------------------------------------------
// TokioFile
// ---------------------------------------------------------------------------

/// Handle to an open file. Wraps `tokio::fs::File` behind a `tokio::sync::Mutex`
/// so that `read_at(&self, …)` can seek and read without requiring `&mut self`.
/// All I/O is serialized per file handle; concurrent access across cloned
/// handles is not supported (matches `MemVfs` semantics).
pub struct TokioFile {
    inner: tokio::sync::Mutex<fs::File>,
    writable: bool,
}

// ---------------------------------------------------------------------------
// Vfs impl for TokioVfs
// ---------------------------------------------------------------------------

impl Vfs for TokioVfs {
    type File = TokioFile;
    type LockHandle = TokioLockHandle;

    async fn open(&self, path: &str, mode: OpenMode) -> Result<Self::File> {
        let p = self.resolve(path)?;
        // Ensure parent directories exist for create modes.
        if matches!(mode, OpenMode::CreateNew | OpenMode::CreateOrOpen) {
            if let Some(parent) = p.parent() {
                fs::create_dir_all(parent).await.map_err(PagedbError::Io)?;
            }
        }
        let (file, writable) = match mode {
            OpenMode::Read => {
                let f = fs::OpenOptions::new()
                    .read(true)
                    .open(&p)
                    .await
                    .map_err(PagedbError::Io)?;
                (f, false)
            }
            OpenMode::ReadWrite => {
                let f = fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&p)
                    .await
                    .map_err(PagedbError::Io)?;
                (f, true)
            }
            OpenMode::CreateNew => {
                let f = fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create_new(true)
                    .open(&p)
                    .await
                    .map_err(PagedbError::Io)?;
                (f, true)
            }
            OpenMode::CreateOrOpen => {
                let f = fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .truncate(false)
                    .open(&p)
                    .await
                    .map_err(PagedbError::Io)?;
                (f, true)
            }
        };
        Ok(TokioFile {
            inner: tokio::sync::Mutex::new(file),
            writable,
        })
    }

    async fn remove(&self, path: &str) -> Result<()> {
        let p = self.resolve(path)?;
        match fs::remove_file(&p).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(PagedbError::Io(e)),
        }
    }

    async fn rename(&self, from: &str, to: &str) -> Result<()> {
        let f = self.resolve(from)?;
        let t = self.resolve(to)?;
        if let Some(parent) = t.parent() {
            fs::create_dir_all(parent).await.map_err(PagedbError::Io)?;
        }
        fs::rename(&f, &t).await.map_err(PagedbError::Io)
    }

    async fn list_dir(&self, path: &str) -> Result<Vec<String>> {
        let p = self.resolve(path)?;
        let mut entries = match fs::read_dir(&p).await {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(PagedbError::Io(e)),
        };
        let mut out = Vec::new();
        while let Some(entry) = entries.next_entry().await.map_err(PagedbError::Io)? {
            if let Some(name) = entry.file_name().to_str() {
                out.push(name.to_string());
            }
        }
        out.sort();
        Ok(out)
    }

    async fn mkdir_all(&self, path: &str) -> Result<()> {
        let p = self.resolve(path)?;
        fs::create_dir_all(&p).await.map_err(PagedbError::Io)
    }

    async fn sync_dir(&self, path: &str) -> Result<()> {
        let p = self.resolve(path)?;
        // `tokio::fs` has no directory-sync form, so this is the one place the
        // backend reaches for `std::fs` — on the blocking pool, because the
        // sync waits on the device.
        //
        // On platforms where opening a directory handle is unsupported or
        // syncing it returns Unsupported/PermissionDenied (e.g., some Windows
        // filesystems), treat as a no-op — the rename durability guarantee is
        // best-effort in those environments.
        offload(move || {
            let dir = match std::fs::File::open(&p) {
                Ok(d) => d,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                // Opening a directory as a file handle is unsupported on some
                // platforms — notably Windows, where it fails with
                // PermissionDenied ("Access is denied") at open, before
                // sync_all is ever reached. Directory fsync is best-effort
                // there, so treat it as a no-op.
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::Unsupported | std::io::ErrorKind::PermissionDenied
                    ) =>
                {
                    return Ok(());
                }
                Err(e) => return Err(PagedbError::Io(e)),
            };
            match dir.sync_all() {
                Ok(()) => Ok(()),
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::Unsupported | std::io::ErrorKind::PermissionDenied
                    ) =>
                {
                    Ok(())
                }
                Err(e) => Err(PagedbError::Io(e)),
            }
        })
        .await
    }

    async fn lock_exclusive(&self, path: &str) -> Result<Self::LockHandle> {
        self.do_lock(path, LockKind::Exclusive).await
    }

    fn root_path(&self) -> Option<&std::path::Path> {
        Some(&self.inner.root)
    }

    async fn lock_shared(&self, path: &str) -> Result<Self::LockHandle> {
        self.do_lock(path, LockKind::Shared).await
    }
}

// ---------------------------------------------------------------------------
// VfsFile impl for TokioFile
// ---------------------------------------------------------------------------

impl VfsFile for TokioFile {
    async fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let mut f = self.inner.lock().await;
        f.seek(std::io::SeekFrom::Start(offset))
            .await
            .map_err(PagedbError::Io)?;
        let mut total = 0;
        while total < buf.len() {
            let n = f.read(&mut buf[total..]).await.map_err(PagedbError::Io)?;
            if n == 0 {
                break;
            }
            total += n;
        }
        Ok(total)
    }

    async fn read_at_vectored(&self, reqs: &mut [ReadReq<'_>]) -> Result<()> {
        let mut f = self.inner.lock().await;
        for req in reqs.iter_mut() {
            f.seek(std::io::SeekFrom::Start(req.offset))
                .await
                .map_err(PagedbError::Io)?;
            let mut total = 0;
            while total < req.buf.len() {
                let n = f
                    .read(&mut req.buf[total..])
                    .await
                    .map_err(PagedbError::Io)?;
                if n == 0 {
                    break;
                }
                total += n;
            }
            // Zero the tail past EOF, matching vectored contract: callers see
            // a deterministic buffer state (mirrors MemVfs behaviour).
            for b in &mut req.buf[total..] {
                *b = 0;
            }
        }
        Ok(())
    }

    async fn write_at(&mut self, offset: u64, buf: &[u8]) -> Result<usize> {
        if !self.writable {
            return Err(PagedbError::ReadOnly);
        }
        let buf_len = u64::try_from(buf.len())
            .map_err(|_| PagedbError::Io(std::io::Error::from(std::io::ErrorKind::InvalidInput)))?;
        offset.checked_add(buf_len).ok_or_else(|| {
            PagedbError::Io(std::io::Error::from(std::io::ErrorKind::InvalidInput))
        })?;
        let mut f = self.inner.lock().await;
        f.seek(std::io::SeekFrom::Start(offset))
            .await
            .map_err(PagedbError::Io)?;
        f.write_all(buf).await.map_err(PagedbError::Io)?;
        Ok(buf.len())
    }

    async fn write_at_vectored(&mut self, reqs: &[WriteReq<'_>]) -> Result<()> {
        if !self.writable {
            return Err(PagedbError::ReadOnly);
        }
        for req in reqs {
            let buf_len = u64::try_from(req.buf.len()).map_err(|_| {
                PagedbError::Io(std::io::Error::from(std::io::ErrorKind::InvalidInput))
            })?;
            req.offset.checked_add(buf_len).ok_or_else(|| {
                PagedbError::Io(std::io::Error::from(std::io::ErrorKind::InvalidInput))
            })?;
        }
        let mut f = self.inner.lock().await;
        for req in reqs {
            f.seek(std::io::SeekFrom::Start(req.offset))
                .await
                .map_err(PagedbError::Io)?;
            f.write_all(req.buf).await.map_err(PagedbError::Io)?;
        }
        Ok(())
    }

    async fn sync(&mut self) -> Result<()> {
        let f = self.inner.lock().await;
        f.sync_all().await.map_err(PagedbError::Io)
    }

    async fn truncate(&mut self, len: u64) -> Result<()> {
        if !self.writable {
            return Err(PagedbError::ReadOnly);
        }
        let f = self.inner.lock().await;
        f.set_len(len).await.map_err(PagedbError::Io)
    }

    async fn len(&self) -> Result<u64> {
        let mut f = self.inner.lock().await;
        // `metadata` is the one file operation that does not wait for a write
        // already submitted to the runtime's background pool, so on a loaded
        // pool it can observe the pre-write length even though `write_at` has
        // returned. Flush first so the reported length reflects every
        // completed write. On a read-only handle this is a no-op.
        f.flush().await.map_err(PagedbError::Io)?;
        Ok(f.metadata().await.map_err(PagedbError::Io)?.len())
    }

    async fn is_empty(&self) -> Result<bool> {
        Ok(self.len().await? == 0)
    }

    fn supports_direct_io(&self) -> bool {
        false
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn tempdir() -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};

        static NEXT: AtomicU64 = AtomicU64::new(0);
        let mut p = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
        p.push(format!(
            "pagedb-tokio-unit-{}-{nanos}-{sequence}",
            std::process::id()
        ));
        std::fs::create_dir(&p).unwrap();
        p
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

    #[test]
    fn canonical_logical_paths_have_one_spelling() {
        assert_eq!(
            TokioVfs::canonical_logical_path("/main.db").unwrap(),
            "/main.db"
        );
        assert_eq!(
            TokioVfs::canonical_logical_path("main.db").unwrap(),
            "/main.db"
        );
        assert_eq!(
            TokioVfs::canonical_logical_path("/seg/file/").unwrap(),
            "/seg/file"
        );
        assert_eq!(
            TokioVfs::canonical_logical_path(r"seg\file").unwrap(),
            "/seg/file"
        );
        assert_eq!(TokioVfs::canonical_logical_path("/").unwrap(), "/");
    }

    #[test]
    fn rejects_parent_current_and_empty_path_components() {
        let vfs = TokioVfs::new("/tmp/pagedb-root");

        for path in [
            "../escape",
            "/seg/../escape",
            "./main.db",
            "seg/./x",
            "seg//x",
        ] {
            let error = vfs.resolve(path).unwrap_err();
            match error {
                PagedbError::Io(error) => {
                    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
                }
                other => panic!("expected InvalidInput, got {other:?}"),
            }
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn write_and_read_round_trip() {
        let dir = tempdir();
        let vfs = TokioVfs::new(&dir);

        let mut f = vfs.open("/hello", OpenMode::CreateNew).await.unwrap();
        f.write_at(0, b"pagedb").await.unwrap();
        f.sync().await.unwrap();
        drop(f);

        let g = vfs.open("/hello", OpenMode::Read).await.unwrap();
        let mut buf = vec![0u8; 6];
        let n = g.read_at(0, &mut buf).await.unwrap();
        assert_eq!(n, 6);
        assert_eq!(&buf, b"pagedb");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn vectored_read_write() {
        let dir = tempdir();
        let vfs = TokioVfs::new(&dir);

        let mut f = vfs.open("/vec", OpenMode::CreateNew).await.unwrap();
        f.write_at_vectored(&[
            WriteReq {
                offset: 0,
                buf: b"foo",
            },
            WriteReq {
                offset: 10,
                buf: b"bar",
            },
        ])
        .await
        .unwrap();
        drop(f);

        let g = vfs.open("/vec", OpenMode::Read).await.unwrap();
        let mut a = [0u8; 3];
        let mut b = [0u8; 3];
        g.read_at_vectored(&mut [
            ReadReq {
                offset: 0,
                buf: &mut a,
            },
            ReadReq {
                offset: 10,
                buf: &mut b,
            },
        ])
        .await
        .unwrap();
        assert_eq!(&a, b"foo");
        assert_eq!(&b, b"bar");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn exclusive_lock_conflicts() {
        let dir = tempdir();
        let vfs = TokioVfs::new(&dir);

        let _h = vfs.lock_exclusive("/db").await.unwrap();
        assert!(vfs.lock_exclusive("/db").await.is_err());
        assert!(vfs.lock_shared("/db").await.is_err());

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Two independent `TokioVfs` instances over the same directory have
    /// separate in-process lock tables, so only the OS-level lock can stop them
    /// double-opening the same store. On Linux the OFD lock conflicts even
    /// within one process; classic `F_SETLK` would not (it is process-owned and
    /// self-non-conflicting). This is the defense-in-depth that keeps a single
    /// buggy process from concurrently opening one store's writer twice.
    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "current_thread")]
    async fn exclusive_lock_conflicts_across_vfs_instances_same_process() {
        let dir = tempdir();
        let vfs_a = TokioVfs::new(&dir);
        let vfs_b = TokioVfs::new(&dir);

        let _h = vfs_a.lock_exclusive("/db").await.unwrap();
        // Different instance, same process, same path: the in-proc guard cannot
        // see across instances, so the OFD lock must reject this.
        assert!(matches!(
            vfs_b.lock_exclusive("/db").await,
            Err(PagedbError::AlreadyLocked)
        ));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn shared_locks_coexist() {
        let dir = tempdir();
        let vfs = TokioVfs::new(&dir);

        let h1 = vfs.lock_shared("/db").await.unwrap();
        let h2 = vfs.lock_shared("/db").await.unwrap();
        assert!(vfs.lock_exclusive("/db").await.is_err());

        drop(h1);
        drop(h2);
        // After releasing both shared locks, exclusive should succeed.
        let h3 = vfs.lock_exclusive("/db").await.unwrap();
        drop(h3);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn list_dir_and_mkdir_all() {
        let dir = tempdir();
        let vfs = TokioVfs::new(&dir);

        vfs.mkdir_all("/sub/nested").await.unwrap();
        let mut f = vfs
            .open("/sub/nested/a", OpenMode::CreateNew)
            .await
            .unwrap();
        f.write_at(0, b"x").await.unwrap();
        drop(f);

        let entries = vfs.list_dir("/sub/nested").await.unwrap();
        assert!(entries.contains(&"a".to_string()));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn truncate_and_len() {
        let dir = tempdir();
        let vfs = TokioVfs::new(&dir);

        let mut f = vfs.open("/trunc", OpenMode::CreateNew).await.unwrap();
        f.write_at(0, b"abcdefgh").await.unwrap();
        assert_eq!(f.len().await.unwrap(), 8);
        f.truncate(4).await.unwrap();
        assert_eq!(f.len().await.unwrap(), 4);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn read_only_rejects_writes() {
        let dir = tempdir();
        let vfs = TokioVfs::new(&dir);

        {
            let mut f = vfs.open("/ro", OpenMode::CreateNew).await.unwrap();
            f.write_at(0, b"data").await.unwrap();
        }

        let mut g = vfs.open("/ro", OpenMode::Read).await.unwrap();
        assert!(matches!(
            g.write_at(0, b"x").await,
            Err(PagedbError::ReadOnly)
        ));

        std::fs::remove_dir_all(&dir).ok();
    }
}
