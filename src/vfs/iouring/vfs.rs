//! `IouringVfs`: Linux io_uring-backed VFS rooted at a directory.
//! Advisory path locking is the shared two-layer protocol from
//! [`crate::vfs::NativeLockHandle`] — the identical code `TokioVfs` runs, so a process on
//! this backend and one that fell back to the thread pool still exclude each
//! other over the same store.
//!
//! The ring covers file I/O only. Path operations and directory sync are plain
//! blocking syscalls, so they run on the blocking pool; only path validation
//! and the in-process lock table stay on the executor.

use std::path::PathBuf;
use std::sync::Arc;

use crate::Result;
use crate::errors::PagedbError;

use super::file::IouringFile;
use super::ring::Ring;
use crate::vfs::blocking::offload;
use crate::vfs::oslock::{LockKind, LockTable};
use crate::vfs::traits::{Vfs, canonical_native_path, resolve_native_path};
use crate::vfs::types::OpenMode;

/// RAII advisory lock handle returned by `IouringVfs::lock_exclusive` /
/// `lock_shared`. The one native handle type, shared with every other
/// filesystem-backed backend.
pub use crate::vfs::oslock::NativeLockHandle as IouringLockHandle;

// ---------------------------------------------------------------------------
// IouringVfs
// ---------------------------------------------------------------------------

struct IouringInner {
    root: PathBuf,
    ring: Ring,
    locks: LockTable,
}

/// VFS rooted at a directory, using `io_uring` for file I/O and `std::fs` /
/// libc syscalls for path-level operations. Cloning shares the same root,
/// ring, and lock table.
#[derive(Clone)]
pub struct IouringVfs {
    inner: Arc<IouringInner>,
}

impl IouringVfs {
    /// Create a new `IouringVfs` rooted at `root`. The directory must already
    /// exist before the first `open` call, or callers must invoke `mkdir_all`
    /// first.
    pub fn new(root: impl Into<PathBuf>) -> Result<Self> {
        let ring = Ring::new()?;
        Ok(Self {
            inner: Arc::new(IouringInner {
                root: root.into(),
                ring,
                locks: LockTable::new(),
            }),
        })
    }

    fn resolve(&self, path: &str) -> Result<PathBuf> {
        resolve_native_path(&self.inner.root, path)
    }

    async fn do_lock(&self, path: &str, kind: LockKind) -> Result<IouringLockHandle> {
        let logical_path = canonical_native_path(path)?;
        let lock_path = self.resolve(&logical_path)?;
        crate::vfs::oslock::acquire(&self.inner.locks, &logical_path, lock_path, kind).await
    }
}

impl Vfs for IouringVfs {
    type File = IouringFile;
    type LockHandle = IouringLockHandle;

    async fn open(&self, path: &str, mode: OpenMode) -> Result<Self::File> {
        let p = self.resolve(path)?;
        let (file, writable) = offload(move || {
            if matches!(mode, OpenMode::CreateNew | OpenMode::CreateOrOpen) {
                if let Some(parent) = p.parent() {
                    std::fs::create_dir_all(parent).map_err(PagedbError::Io)?;
                }
            }
            let opened = match mode {
                OpenMode::Read => {
                    let f = std::fs::OpenOptions::new()
                        .read(true)
                        .open(&p)
                        .map_err(PagedbError::Io)?;
                    (f, false)
                }
                OpenMode::ReadWrite => {
                    let f = std::fs::OpenOptions::new()
                        .read(true)
                        .write(true)
                        .open(&p)
                        .map_err(PagedbError::Io)?;
                    (f, true)
                }
                OpenMode::CreateNew => {
                    let f = std::fs::OpenOptions::new()
                        .read(true)
                        .write(true)
                        .create_new(true)
                        .open(&p)
                        .map_err(PagedbError::Io)?;
                    (f, true)
                }
                OpenMode::CreateOrOpen => {
                    let f = std::fs::OpenOptions::new()
                        .read(true)
                        .write(true)
                        .create(true)
                        .truncate(false)
                        .open(&p)
                        .map_err(PagedbError::Io)?;
                    (f, true)
                }
            };
            Ok(opened)
        })
        .await?;
        Ok(IouringFile::new(
            file,
            writable,
            Arc::clone(&self.inner.ring.inner),
        ))
    }

    async fn remove(&self, path: &str) -> Result<()> {
        let p = self.resolve(path)?;
        offload(move || match std::fs::remove_file(&p) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(PagedbError::Io(e)),
        })
        .await
    }

    async fn rename(&self, from: &str, to: &str) -> Result<()> {
        let f = self.resolve(from)?;
        let t = self.resolve(to)?;
        offload(move || {
            if let Some(parent) = t.parent() {
                std::fs::create_dir_all(parent).map_err(PagedbError::Io)?;
            }
            std::fs::rename(&f, &t).map_err(PagedbError::Io)
        })
        .await
    }

    async fn list_dir(&self, path: &str) -> Result<Vec<String>> {
        let p = self.resolve(path)?;
        offload(move || {
            let iter = match std::fs::read_dir(&p) {
                Ok(it) => it,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
                Err(e) => return Err(PagedbError::Io(e)),
            };
            let mut out = Vec::new();
            for entry in iter {
                let entry = entry.map_err(PagedbError::Io)?;
                if let Some(name) = entry.file_name().to_str() {
                    out.push(name.to_string());
                }
            }
            out.sort();
            Ok(out)
        })
        .await
    }

    async fn mkdir_all(&self, path: &str) -> Result<()> {
        let p = self.resolve(path)?;
        offload(move || std::fs::create_dir_all(&p).map_err(PagedbError::Io)).await
    }

    async fn sync_dir(&self, path: &str) -> Result<()> {
        let p = self.resolve(path)?;
        // Open the directory with O_RDONLY|O_DIRECTORY and fsync the fd.
        // Waiting on the device is the point of the call, so it runs on the
        // pool rather than on the executor.
        offload(move || {
            let dir = match std::fs::File::open(&p) {
                Ok(d) => d,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
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

    async fn lock_shared(&self, path: &str) -> Result<Self::LockHandle> {
        self.do_lock(path, LockKind::Shared).await
    }

    fn root_path(&self) -> Option<&std::path::Path> {
        Some(&self.inner.root)
    }
}
