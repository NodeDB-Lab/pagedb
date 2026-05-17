//! `IocpVfs`: Windows IOCP-backed VFS rooted at a directory. Advisory path
//! locking uses an in-process state machine backed by `LockFileEx` for
//! cross-process exclusion — same protocol as the Tokio fallback. Segment
//! files open with `FILE_SHARE_DELETE` so tombstone-rename protocols succeed
//! against held handles.
#![allow(unsafe_code)]

use std::collections::BTreeMap;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use parking_lot::Mutex;

use crate::Result;
use crate::errors::PagedbError;

use super::file::IocpFile;
use super::port::Port;
use crate::vfs::traits::Vfs;
use crate::vfs::types::OpenMode;

use windows_sys::Win32::Foundation::{
    ERROR_IO_PENDING, ERROR_LOCK_VIOLATION, GetLastError, HANDLE,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_FLAG_OVERLAPPED, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY, LockFileEx,
    UnlockFileEx,
};
use windows_sys::Win32::System::IO::OVERLAPPED;

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
// Cross-process lock via LockFileEx
// ---------------------------------------------------------------------------

struct OsLockFileExHandle {
    file: std::fs::File,
}

impl OsLockFileExHandle {
    fn try_acquire(path: &std::path::Path, kind: LockKind) -> Result<Self> {
        // FILE_SHARE_READ | FILE_SHARE_WRITE: multiple processes must be able
        // to open the sentinel file and contend on the lock.
        const FILE_SHARE_READ_WRITE: u32 = 0x0000_0003;

        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .share_mode(FILE_SHARE_READ_WRITE)
            .open(path)
            .map_err(PagedbError::Io)?;

        let handle = file.as_raw_handle() as HANDLE;
        let flags = match kind {
            LockKind::Exclusive => LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
            LockKind::Shared => LOCKFILE_FAIL_IMMEDIATELY,
        };

        // SAFETY: `handle` is valid for the duration of this call (owned by
        // `file` which is alive). Zero-initialised OVERLAPPED is the
        // documented input for synchronous `LockFileEx` use. We lock the
        // whole [0, u64::MAX) byte range.
        let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
        let rc = unsafe { LockFileEx(handle, flags, 0, u32::MAX, u32::MAX, &mut overlapped) };

        if rc == 0 {
            // SAFETY: documented pattern.
            let err = unsafe { GetLastError() };
            if err == ERROR_LOCK_VIOLATION || err == ERROR_IO_PENDING {
                return Err(PagedbError::AlreadyLocked);
            }
            return Err(PagedbError::Io(std::io::Error::last_os_error()));
        }

        Ok(Self { file })
    }
}

impl Drop for OsLockFileExHandle {
    fn drop(&mut self) {
        let handle = self.file.as_raw_handle() as HANDLE;
        // SAFETY: `handle` valid until `file` drops at end of this method.
        // Errors are ignored in Drop; closing the handle releases the lock
        // regardless.
        let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
        let _ = unsafe { UnlockFileEx(handle, 0, u32::MAX, u32::MAX, &mut overlapped) };
    }
}

// SAFETY: HANDLE is process-owned and not aliased between threads — the
// struct moves as a whole.
unsafe impl Send for OsLockFileExHandle {}

// ---------------------------------------------------------------------------
// Public lock handle
// ---------------------------------------------------------------------------

pub struct IocpLockHandle {
    lock_ref: Arc<InProcLockEntry>,
    kind: LockKind,
    _os_lock: OsLockFileExHandle,
}

impl Drop for IocpLockHandle {
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

// ---------------------------------------------------------------------------
// IocpVfs
// ---------------------------------------------------------------------------

struct IocpInner {
    root: PathBuf,
    port: Port,
    /// Monotonic counter for per-file `CompletionKey`s. The mutex on the port
    /// means keys are not strictly required to disambiguate completions, but
    /// they are useful for diagnostics and future relaxation of serialisation.
    next_key: AtomicUsize,
    locks: Mutex<BTreeMap<String, Arc<InProcLockEntry>>>,
}

#[derive(Clone)]
pub struct IocpVfs {
    inner: Arc<IocpInner>,
}

impl IocpVfs {
    pub fn new(root: impl Into<PathBuf>) -> Result<Self> {
        let port = Port::new()?;
        Ok(Self {
            inner: Arc::new(IocpInner {
                root: root.into(),
                port,
                next_key: AtomicUsize::new(1),
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

    fn do_lock(&self, path: &str, kind: LockKind) -> Result<IocpLockHandle> {
        let entry = self.lookup_or_create_entry(path);
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
        match OsLockFileExHandle::try_acquire(&lock_path, kind) {
            Ok(os_lock) => Ok(IocpLockHandle {
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

impl Vfs for IocpVfs {
    type File = IocpFile;
    type LockHandle = IocpLockHandle;

    async fn open(&self, path: &str, mode: OpenMode) -> Result<Self::File> {
        let p = self.resolve(path);
        if matches!(mode, OpenMode::CreateNew | OpenMode::CreateOrOpen) {
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).map_err(PagedbError::Io)?;
            }
        }
        // FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE.
        // FILE_SHARE_DELETE is required so tombstone-rename protocols succeed
        // while readers hold handles open.
        const FILE_SHARE_RWD: u32 = 0x0000_0007;
        let (file, writable) = match mode {
            OpenMode::Read => {
                let f = std::fs::OpenOptions::new()
                    .read(true)
                    .share_mode(FILE_SHARE_RWD)
                    .custom_flags(FILE_FLAG_OVERLAPPED)
                    .open(&p)
                    .map_err(PagedbError::Io)?;
                (f, false)
            }
            OpenMode::ReadWrite => {
                let f = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .share_mode(FILE_SHARE_RWD)
                    .custom_flags(FILE_FLAG_OVERLAPPED)
                    .open(&p)
                    .map_err(PagedbError::Io)?;
                (f, true)
            }
            OpenMode::CreateNew => {
                let f = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create_new(true)
                    .share_mode(FILE_SHARE_RWD)
                    .custom_flags(FILE_FLAG_OVERLAPPED)
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
                    .share_mode(FILE_SHARE_RWD)
                    .custom_flags(FILE_FLAG_OVERLAPPED)
                    .open(&p)
                    .map_err(PagedbError::Io)?;
                (f, true)
            }
        };
        let key = self.inner.next_key.fetch_add(1, Ordering::Relaxed);
        let handle = file.as_raw_handle() as HANDLE;
        self.inner.port.associate(handle, key)?;
        Ok(IocpFile::new(
            file,
            writable,
            key,
            Arc::clone(&self.inner.port.inner),
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
        // `std::fs::rename` on Windows is `MoveFileExW(MOVEFILE_REPLACE_EXISTING)`,
        // which is the primitive the architecture's tombstone protocol relies on.
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

    async fn sync_dir(&self, _path: &str) -> Result<()> {
        // NTFS folds rename durability into its metadata journal, and
        // `FlushFileBuffers` on a directory handle is not generally available
        // through `std::fs`. Best-effort no-op on Windows; rename + the
        // subsequent `sync` on the affected file produces a durable transition.
        Ok(())
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
