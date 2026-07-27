//! `GcdVfs`: macOS / iOS / iPadOS VFS rooted at a directory, using Grand
//! Central Dispatch I/O for per-file reads and writes. Advisory path locking
//! uses the same in-process state machine + POSIX `flock` protocol as the
//! Tokio fallback.
//!
//! `dispatch_io` covers reads and writes only. Path operations and directory
//! sync are plain blocking syscalls, so they run on the blocking pool; only
//! path validation and the in-process lock table stay on the executor.
#![allow(unsafe_code)]

use std::collections::BTreeMap;
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;
use std::sync::Arc;

use parking_lot::Mutex;

use dispatch2::{DispatchQoS, DispatchQueue, DispatchRetained, GlobalQueueIdentifier};

use crate::Result;
use crate::errors::PagedbError;

use super::file::GcdFile;
use crate::vfs::blocking::offload;
use crate::vfs::traits::{Vfs, canonical_native_path, resolve_native_path};
use crate::vfs::types::OpenMode;

#[derive(Debug, Clone, Copy)]
enum LockState {
    Free,
    Exclusive,
    Shared(u32),
}

#[derive(Debug, Clone, Copy)]
enum LockKind {
    Exclusive,
    Shared,
}

struct InProcLockEntry {
    state: Mutex<LockState>,
}

struct OsFcntlHandle {
    _file: std::fs::File,
}

impl OsFcntlHandle {
    fn try_acquire(path: &std::path::Path, kind: LockKind) -> Result<Self> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(path)
            .map_err(PagedbError::Io)?;

        let fd = file.as_raw_fd();
        #[allow(clippy::cast_possible_truncation)]
        let l_type = match kind {
            LockKind::Exclusive => libc::F_WRLCK as libc::c_short,
            LockKind::Shared => libc::F_RDLCK as libc::c_short,
        };
        #[allow(clippy::cast_possible_truncation)]
        let flock = libc::flock {
            l_type,
            l_whence: libc::SEEK_SET as libc::c_short,
            l_start: 0,
            l_len: 0,
            l_pid: 0,
        };
        // SAFETY: `fd` valid (owned by `file`); `flock` fully initialised;
        // F_SETLK is non-blocking.
        let rc = unsafe { libc::fcntl(fd, libc::F_SETLK, &flock) };
        if rc == -1 {
            let err = std::io::Error::last_os_error();
            let raw = err.raw_os_error().unwrap_or(0);
            if raw == libc::EAGAIN || raw == libc::EACCES {
                return Err(PagedbError::AlreadyLocked);
            }
            return Err(PagedbError::Io(err));
        }
        Ok(Self { _file: file })
    }
}

// SAFETY: fd is owned exclusively; struct moves whole-cloth.
unsafe impl Send for OsFcntlHandle {}

pub struct GcdLockHandle {
    lock_ref: Arc<InProcLockEntry>,
    kind: LockKind,
    _os_lock: OsFcntlHandle,
}

impl Drop for GcdLockHandle {
    fn drop(&mut self) {
        let mut s = self.lock_ref.state.lock();
        match (self.kind, *s) {
            (LockKind::Exclusive, LockState::Exclusive)
            | (LockKind::Shared, LockState::Shared(1)) => *s = LockState::Free,
            (LockKind::Shared, LockState::Shared(n)) if n > 1 => {
                *s = LockState::Shared(n - 1);
            }
            _ => {}
        }
    }
}

struct GcdInner {
    root: PathBuf,
    queue: DispatchRetained<DispatchQueue>,
    locks: Mutex<BTreeMap<String, Arc<InProcLockEntry>>>,
}

#[derive(Clone)]
pub struct GcdVfs {
    inner: Arc<GcdInner>,
}

impl GcdVfs {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        let queue = DispatchQueue::global_queue(GlobalQueueIdentifier::QualityOfService(
            DispatchQoS::Default,
        ));
        Self {
            inner: Arc::new(GcdInner {
                root: root.into(),
                queue,
                locks: Mutex::new(BTreeMap::new()),
            }),
        }
    }

    fn resolve(&self, path: &str) -> Result<PathBuf> {
        resolve_native_path(&self.inner.root, path)
    }

    fn lookup_or_create_entry(&self, path: &str) -> Arc<InProcLockEntry> {
        let mut locks = self.inner.locks.lock();
        locks
            .entry(path.to_string())
            .or_insert_with(|| {
                Arc::new(InProcLockEntry {
                    state: Mutex::new(LockState::Free),
                })
            })
            .clone()
    }

    async fn do_lock(&self, path: &str, kind: LockKind) -> Result<GcdLockHandle> {
        let logical_path = canonical_native_path(path)?;
        let entry = self.lookup_or_create_entry(&logical_path);
        {
            let mut s = entry.state.lock();
            match (kind, *s) {
                (LockKind::Exclusive, LockState::Free) => *s = LockState::Exclusive,
                (LockKind::Shared, LockState::Free) => *s = LockState::Shared(1),
                (LockKind::Shared, LockState::Shared(n)) => *s = LockState::Shared(n + 1),
                _ => return Err(PagedbError::AlreadyLocked),
            }
        }
        let lock_path = self.resolve(&logical_path)?;
        // `F_SETLK` never waits on a conflict, but creating the sentinel file
        // can still stall on the filesystem, so the pair goes to the pool.
        let acquired = offload(move || {
            if let Some(parent) = lock_path.parent() {
                std::fs::create_dir_all(parent).map_err(PagedbError::Io)?;
            }
            OsFcntlHandle::try_acquire(&lock_path, kind)
        })
        .await;
        match acquired {
            Ok(os_lock) => Ok(GcdLockHandle {
                lock_ref: entry,
                kind,
                _os_lock: os_lock,
            }),
            Err(e) => {
                let mut s = entry.state.lock();
                match (kind, *s) {
                    (LockKind::Exclusive, LockState::Exclusive)
                    | (LockKind::Shared, LockState::Shared(1)) => *s = LockState::Free,
                    (LockKind::Shared, LockState::Shared(n)) => *s = LockState::Shared(n - 1),
                    _ => {}
                }
                Err(e)
            }
        }
    }
}

impl Vfs for GcdVfs {
    type File = GcdFile;
    type LockHandle = GcdLockHandle;

    async fn open(&self, path: &str, mode: OpenMode) -> Result<Self::File> {
        let p = self.resolve(path)?;
        let (file, writable) = offload(move || {
            if matches!(mode, OpenMode::CreateNew | OpenMode::CreateOrOpen) {
                if let Some(parent) = p.parent() {
                    std::fs::create_dir_all(parent).map_err(PagedbError::Io)?;
                }
            }
            let opened = match mode {
                OpenMode::Read => (
                    std::fs::OpenOptions::new()
                        .read(true)
                        .open(&p)
                        .map_err(PagedbError::Io)?,
                    false,
                ),
                OpenMode::ReadWrite => (
                    std::fs::OpenOptions::new()
                        .read(true)
                        .write(true)
                        .open(&p)
                        .map_err(PagedbError::Io)?,
                    true,
                ),
                OpenMode::CreateNew => (
                    std::fs::OpenOptions::new()
                        .read(true)
                        .write(true)
                        .create_new(true)
                        .open(&p)
                        .map_err(PagedbError::Io)?,
                    true,
                ),
                OpenMode::CreateOrOpen => (
                    std::fs::OpenOptions::new()
                        .read(true)
                        .write(true)
                        .create(true)
                        .truncate(false)
                        .open(&p)
                        .map_err(PagedbError::Io)?,
                    true,
                ),
            };
            Ok(opened)
        })
        .await?;
        // Creating the channel only registers the descriptor with libdispatch;
        // it performs no I/O, so it stays on the executor. Clone the queue
        // retain so the file holds its own reference.
        GcdFile::new(file, writable, self.inner.queue.clone())
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
        // POSIX fsync on the directory fd; HFS+/APFS honor it. Waiting on the
        // device is the whole point of the call, so it runs on the pool.
        let p = self.resolve(path)?;
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
