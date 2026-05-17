//! `IouringVfs`: Linux io_uring-backed VFS rooted at a directory.
//! Advisory path locking uses a two-layer protocol: an in-process state
//! machine for single-process exclusion and `fcntl(F_SETLK)` for
//! cross-process exclusion, exactly mirroring `TokioVfs`.
#![allow(unsafe_code)]

use std::collections::BTreeMap;
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;
use std::sync::Arc;

use parking_lot::Mutex;

use crate::Result;
use crate::errors::PagedbError;

use super::file::IouringFile;
use super::ring::Ring;
use crate::vfs::traits::Vfs;
use crate::vfs::types::OpenMode;

// ---------------------------------------------------------------------------
// In-process lock state machine
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// OS-level cross-process lock via fcntl(F_SETLK)
// ---------------------------------------------------------------------------

/// Holds an open file descriptor whose `F_SETLK` advisory lock is released
/// when this struct is dropped (fd close releases the lock on Linux).
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
        // SAFETY: F_WRLCK and F_RDLCK are small positive constants defined by
        // libc that always fit in i16 on all Linux targets.
        #[allow(clippy::cast_possible_truncation)]
        let l_type = match kind {
            LockKind::Exclusive => libc::F_WRLCK as libc::c_short,
            LockKind::Shared => libc::F_RDLCK as libc::c_short,
        };
        // SAFETY: SEEK_SET == 0, always fits in i16.
        #[allow(clippy::cast_possible_truncation)]
        let flock = libc::flock {
            l_type,
            l_whence: libc::SEEK_SET as libc::c_short,
            l_start: 0,
            l_len: 0,
            l_pid: 0,
        };
        // SAFETY: `fd` is valid and owned by `file` which lives past this call;
        // `flock` is a plain C struct fully initialised above. F_SETLK is
        // non-blocking: EAGAIN/EACCES signals another process holds a
        // conflicting lock.
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

// SAFETY: The raw fd is valid across threads; the struct is moved as a whole
// and is never shared between threads simultaneously.
unsafe impl Send for OsFcntlHandle {}

// ---------------------------------------------------------------------------
// Public lock handle
// ---------------------------------------------------------------------------

/// RAII advisory lock handle returned by `IouringVfs::lock_exclusive` /
/// `lock_shared`. Holds both an in-process state guard and an OS-level
/// `fcntl` lock.
pub struct IouringLockHandle {
    lock_ref: Arc<InProcLockEntry>,
    kind: LockKind,
    _os_lock: OsFcntlHandle,
}

impl Drop for IouringLockHandle {
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
        // `_os_lock` is dropped automatically after this, releasing the fcntl lock.
    }
}

// ---------------------------------------------------------------------------
// IouringVfs
// ---------------------------------------------------------------------------

struct IouringInner {
    root: PathBuf,
    ring: Ring,
    locks: Mutex<BTreeMap<String, Arc<InProcLockEntry>>>,
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
                locks: Mutex::new(BTreeMap::new()),
            }),
        })
    }

    fn resolve(&self, p: &str) -> PathBuf {
        self.inner.root.join(p.trim_start_matches('/'))
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

    fn do_lock(&self, path: &str, kind: LockKind) -> Result<IouringLockHandle> {
        let entry = self.lookup_or_create_entry(path);
        // In-process guard first.
        {
            let mut s = entry.state.lock();
            match (kind, *s) {
                (LockKind::Exclusive, LockState::Free) => *s = LockState::Exclusive,
                (LockKind::Shared, LockState::Free) => *s = LockState::Shared(1),
                (LockKind::Shared, LockState::Shared(n)) => *s = LockState::Shared(n + 1),
                _ => return Err(PagedbError::AlreadyLocked),
            }
        }
        let lock_path = self.resolve(path);
        if let Some(parent) = lock_path.parent() {
            std::fs::create_dir_all(parent).map_err(PagedbError::Io)?;
        }
        match OsFcntlHandle::try_acquire(&lock_path, kind) {
            Ok(os_lock) => Ok(IouringLockHandle {
                lock_ref: entry,
                kind,
                _os_lock: os_lock,
            }),
            Err(e) => {
                // Roll back the in-process guard.
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

impl Vfs for IouringVfs {
    type File = IouringFile;
    type LockHandle = IouringLockHandle;

    async fn open(&self, path: &str, mode: OpenMode) -> Result<Self::File> {
        let p = self.resolve(path);
        if matches!(mode, OpenMode::CreateNew | OpenMode::CreateOrOpen) {
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).map_err(PagedbError::Io)?;
            }
        }
        let (file, writable) = match mode {
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
        Ok(IouringFile::new(
            file,
            writable,
            Arc::clone(&self.inner.ring.inner),
        ))
    }

    async fn remove(&self, path: &str) -> Result<()> {
        let p = self.resolve(path);
        match std::fs::remove_file(&p) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(PagedbError::Io(e)),
        }
    }

    async fn rename(&self, from: &str, to: &str) -> Result<()> {
        let f = self.resolve(from);
        let t = self.resolve(to);
        if let Some(parent) = t.parent() {
            std::fs::create_dir_all(parent).map_err(PagedbError::Io)?;
        }
        std::fs::rename(&f, &t).map_err(PagedbError::Io)
    }

    async fn list_dir(&self, path: &str) -> Result<Vec<String>> {
        let p = self.resolve(path);
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
    }

    async fn mkdir_all(&self, path: &str) -> Result<()> {
        let p = self.resolve(path);
        std::fs::create_dir_all(&p).map_err(PagedbError::Io)
    }

    async fn sync_dir(&self, path: &str) -> Result<()> {
        let p = self.resolve(path);
        // Open the directory with O_RDONLY|O_DIRECTORY and fsync the fd.
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
    }

    async fn lock_exclusive(&self, path: &str) -> Result<Self::LockHandle> {
        self.do_lock(path, LockKind::Exclusive)
    }

    async fn lock_shared(&self, path: &str) -> Result<Self::LockHandle> {
        self.do_lock(path, LockKind::Shared)
    }

    fn root_path(&self) -> Option<&std::path::Path> {
        Some(&self.inner.root)
    }
}
