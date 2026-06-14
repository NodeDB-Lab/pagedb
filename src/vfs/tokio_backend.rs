//! Cross-platform native VFS backed by `tokio::fs`. Advisory locks use a
//! two-layer protocol: an in-process state machine provides fast single-process
//! exclusion, and `fcntl(F_SETLK)` on Unix and `LockFileEx` on Windows back
//! each lock with a real OS-level exclusive/shared mutex for cross-process
//! exclusion. On other targets only the in-process layer is used. The trait
//! contract from `traits.rs` is the durable surface.
//!
//! `unsafe` is permitted here for platform lock primitives (fcntl on Unix,
//! `LockFileEx` on Windows).
#![allow(unsafe_code)]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use parking_lot::Mutex;
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

use crate::Result;
use crate::errors::PagedbError;

use super::traits::{Vfs, VfsFile};
use super::types::{OpenMode, ReadReq, WriteReq};

// ---------------------------------------------------------------------------
// In-process lock state machine (guards single-process re-entry for all
// targets, and is the only guard on non-Unix targets).
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
// Unix cross-process lock via fcntl(F_SETLK).
// ---------------------------------------------------------------------------

/// On Unix, holds an open file descriptor whose advisory lock (`F_SETLK`) is
/// released when this struct is dropped (fd close triggers lock release).
#[cfg(unix)]
struct OsFcntlHandle {
    _file: std::fs::File,
}

#[cfg(unix)]
impl OsFcntlHandle {
    fn try_acquire(path: &std::path::Path, kind: LockKind) -> Result<Self> {
        use std::os::unix::io::AsRawFd;

        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(path)
            .map_err(PagedbError::Io)?;

        let fd = file.as_raw_fd();
        // SAFETY: F_WRLCK and F_RDLCK are small positive constants that fit
        // in i16 on every platform where libc defines them.
        #[allow(clippy::cast_possible_truncation)]
        let l_type = match kind {
            LockKind::Exclusive => libc::F_WRLCK as libc::c_short,
            LockKind::Shared => libc::F_RDLCK as libc::c_short,
        };

        // SAFETY: SEEK_SET == 0, which always fits in i16.
        #[allow(clippy::cast_possible_truncation)]
        let flock = libc::flock {
            l_type,
            l_whence: libc::SEEK_SET as libc::c_short,
            l_start: 0,
            l_len: 0,
            l_pid: 0,
        };

        // SAFETY: `fd` is valid (owned by `file` above which stays alive past
        // this call); `flock` is a plain C struct fully initialised above.
        // F_SETLK is non-blocking: EAGAIN/EACCES means another process holds
        // a conflicting lock.
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

// SAFETY: The raw fd is valid across threads; we do not share it between
// threads — the struct is moved as a whole.
#[cfg(unix)]
unsafe impl Send for OsFcntlHandle {}

// ---------------------------------------------------------------------------
// Windows cross-process lock via LockFileEx.
// ---------------------------------------------------------------------------

/// On Windows, holds an open file whose byte-range advisory lock (`LockFileEx`)
/// is explicitly released on drop via `UnlockFileEx`, then the file is closed.
#[cfg(windows)]
struct OsLockFileExHandle {
    file: std::fs::File,
}

#[cfg(windows)]
impl OsLockFileExHandle {
    fn try_acquire(path: &std::path::Path, kind: LockKind) -> Result<Self> {
        use std::os::windows::fs::OpenOptionsExt;
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Foundation::{ERROR_IO_PENDING, ERROR_LOCK_VIOLATION};
        use windows_sys::Win32::Storage::FileSystem::LockFileEx;
        use windows_sys::Win32::Storage::FileSystem::{
            LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY,
        };
        use windows_sys::Win32::System::IO::OVERLAPPED;

        // FILE_SHARE_READ | FILE_SHARE_WRITE (0x1 | 0x2 = 0x3): multiple
        // processes must be able to open the same lock file simultaneously so
        // they can all call LockFileEx and contend against each other.
        const FILE_SHARE_READ_WRITE: u32 = 0x0000_0003;

        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .share_mode(FILE_SHARE_READ_WRITE)
            .open(path)
            .map_err(PagedbError::Io)?;

        let handle = file.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE;

        let flags = match kind {
            LockKind::Exclusive => LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
            LockKind::Shared => LOCKFILE_FAIL_IMMEDIATELY,
        };

        // SAFETY: `handle` is valid and owned by `file` which is alive for the
        // duration of this call. `overlapped` is zero-initialised — LockFileEx
        // requires a pointer to OVERLAPPED even when LOCKFILE_FAIL_IMMEDIATELY
        // is set (the call completes synchronously in that mode); zeroing all
        // fields is the correct initialisation for a synchronous, non-event
        // OVERLAPPED. We cover bytes [0, u64::MAX) which is the conventional
        // "whole file" range. `dwreserved` must be 0 per MSDN.
        let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
        let rc = unsafe { LockFileEx(handle, flags, 0, u32::MAX, u32::MAX, &mut overlapped) };

        if rc == 0 {
            // SAFETY: Calling GetLastError immediately after a failed Win32
            // call is the documented pattern; no other OS calls intervene.
            let err_code = unsafe { windows_sys::Win32::Foundation::GetLastError() };
            if err_code == ERROR_LOCK_VIOLATION || err_code == ERROR_IO_PENDING {
                return Err(PagedbError::AlreadyLocked);
            }
            return Err(PagedbError::Io(std::io::Error::last_os_error()));
        }

        Ok(Self { file })
    }
}

#[cfg(windows)]
impl Drop for OsLockFileExHandle {
    fn drop(&mut self) {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::UnlockFileEx;
        use windows_sys::Win32::System::IO::OVERLAPPED;

        let handle = self.file.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE;
        // SAFETY: `handle` is valid (file is still open at drop time — the
        // file field is dropped after this impl returns). Zero-initialised
        // OVERLAPPED is required by UnlockFileEx for a synchronous call.
        // Unlocking the full [0, u64::MAX) byte range matches what LockFileEx
        // locked. Ignoring the return value on Drop is intentional: we cannot
        // propagate errors from Drop, and a failed unlock during process exit
        // is harmless because Windows releases all file locks when the handle
        // is closed.
        let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
        let _ = unsafe { UnlockFileEx(handle, 0, u32::MAX, u32::MAX, &mut overlapped) };
        // `self.file` is dropped here, closing the handle.
    }
}

// SAFETY: The raw HANDLE is valid across threads; we do not share it between
// threads — the struct is moved as a whole.
#[cfg(windows)]
unsafe impl Send for OsLockFileExHandle {}

// ---------------------------------------------------------------------------
// Public lock handle.
// ---------------------------------------------------------------------------

/// RAII advisory lock handle returned by `TokioVfs::lock_exclusive` /
/// `lock_shared`. On Unix the handle holds both an in-process state guard and
/// an OS-level fcntl lock; on Windows it holds an OS-level `LockFileEx` lock;
/// on other targets only the in-process guard is used.
pub struct TokioLockHandle {
    /// Shared in-process lock entry; released on drop.
    lock_ref: Arc<InProcLockEntry>,
    kind: LockKind,
    /// On Unix: holds the fcntl-locked file open. Dropped (and thus unlocked)
    /// together with this handle.
    #[cfg(unix)]
    _os_lock: OsFcntlHandle,
    /// On Windows: holds the LockFileEx-locked file open. Explicitly unlocked
    /// and closed when dropped.
    #[cfg(windows)]
    _os_lock: OsLockFileExHandle,
}

impl Drop for TokioLockHandle {
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
        // _os_lock (unix only) is dropped automatically after this.
    }
}

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
    locks: Mutex<BTreeMap<String, Arc<InProcLockEntry>>>,
}

impl TokioVfs {
    /// Create a new `TokioVfs` rooted at `root`. The directory must already
    /// exist or be created before the first `open` call.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            inner: Arc::new(TokioInner {
                root: root.into(),
                locks: Mutex::new(BTreeMap::new()),
            }),
        }
    }

    fn resolve(&self, p: &str) -> PathBuf {
        self.inner.root.join(p.trim_start_matches('/'))
    }

    /// Return the filesystem root directory of this VFS instance.
    #[must_use]
    pub fn root_path(&self) -> &std::path::Path {
        &self.inner.root
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
        let p = self.resolve(path);
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
        let p = self.resolve(path);
        match fs::remove_file(&p).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(PagedbError::Io(e)),
        }
    }

    async fn rename(&self, from: &str, to: &str) -> Result<()> {
        let f = self.resolve(from);
        let t = self.resolve(to);
        if let Some(parent) = t.parent() {
            fs::create_dir_all(parent).await.map_err(PagedbError::Io)?;
        }
        fs::rename(&f, &t).await.map_err(PagedbError::Io)
    }

    async fn list_dir(&self, path: &str) -> Result<Vec<String>> {
        let p = self.resolve(path);
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
        let p = self.resolve(path);
        fs::create_dir_all(&p).await.map_err(PagedbError::Io)
    }

    async fn sync_dir(&self, path: &str) -> Result<()> {
        let p = self.resolve(path);
        // Open the directory with std::fs (synchronous) to call sync_all.
        // On platforms where opening a directory handle is unsupported or
        // syncing it returns Unsupported/PermissionDenied (e.g., some Windows
        // filesystems), treat as a no-op — the rename durability guarantee is
        // best-effort in those environments.
        let dir = match std::fs::File::open(&p) {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            // Opening a directory as a file handle is unsupported on some
            // platforms — notably Windows, where it fails with PermissionDenied
            // ("Access is denied") at open, before sync_all is ever reached.
            // Directory fsync is best-effort there, so treat it as a no-op.
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
    }

    async fn lock_exclusive(&self, path: &str) -> Result<Self::LockHandle> {
        let entry = self.lookup_or_create_entry(path);
        // In-process guard first: fast fail if the same process already holds
        // any lock on this path.
        {
            let mut s = entry.state.lock();
            match *s {
                LockState::Free => *s = LockState::Exclusive,
                _ => return Err(PagedbError::AlreadyLocked),
            }
        }
        // On Unix, back the in-process guard with a real OS-level fcntl lock
        // so another process opening the same directory is also excluded.
        #[cfg(unix)]
        {
            let lock_path = self.resolve(path);
            if let Some(parent) = lock_path.parent() {
                std::fs::create_dir_all(parent).map_err(PagedbError::Io)?;
            }
            match OsFcntlHandle::try_acquire(&lock_path, LockKind::Exclusive) {
                Ok(os_lock) => Ok(TokioLockHandle {
                    lock_ref: entry,
                    kind: LockKind::Exclusive,
                    _os_lock: os_lock,
                }),
                Err(e) => {
                    // Roll back in-process guard since OS lock failed.
                    let mut s = entry.state.lock();
                    *s = LockState::Free;
                    Err(e)
                }
            }
        }
        // On Windows, back the in-process guard with a LockFileEx advisory
        // lock so another process is also excluded.
        #[cfg(windows)]
        {
            let lock_path = self.resolve(path);
            if let Some(parent) = lock_path.parent() {
                std::fs::create_dir_all(parent).map_err(PagedbError::Io)?;
            }
            match OsLockFileExHandle::try_acquire(&lock_path, LockKind::Exclusive) {
                Ok(os_lock) => Ok(TokioLockHandle {
                    lock_ref: entry,
                    kind: LockKind::Exclusive,
                    _os_lock: os_lock,
                }),
                Err(e) => {
                    // Roll back in-process guard since OS lock failed.
                    let mut s = entry.state.lock();
                    *s = LockState::Free;
                    Err(e)
                }
            }
        }
        #[cfg(not(any(unix, windows)))]
        {
            Ok(TokioLockHandle {
                lock_ref: entry,
                kind: LockKind::Exclusive,
            })
        }
    }

    fn root_path(&self) -> Option<&std::path::Path> {
        Some(&self.inner.root)
    }

    async fn lock_shared(&self, path: &str) -> Result<Self::LockHandle> {
        let entry = self.lookup_or_create_entry(path);
        {
            let mut s = entry.state.lock();
            match *s {
                LockState::Free => *s = LockState::Shared(1),
                LockState::Shared(n) => *s = LockState::Shared(n + 1),
                LockState::Exclusive => return Err(PagedbError::AlreadyLocked),
            }
        }
        #[cfg(unix)]
        {
            let lock_path = self.resolve(path);
            if let Some(parent) = lock_path.parent() {
                std::fs::create_dir_all(parent).map_err(PagedbError::Io)?;
            }
            match OsFcntlHandle::try_acquire(&lock_path, LockKind::Shared) {
                Ok(os_lock) => Ok(TokioLockHandle {
                    lock_ref: entry,
                    kind: LockKind::Shared,
                    _os_lock: os_lock,
                }),
                Err(e) => {
                    let mut s = entry.state.lock();
                    match *s {
                        LockState::Shared(1) => *s = LockState::Free,
                        LockState::Shared(n) => *s = LockState::Shared(n - 1),
                        _ => {}
                    }
                    Err(e)
                }
            }
        }
        #[cfg(windows)]
        {
            let lock_path = self.resolve(path);
            if let Some(parent) = lock_path.parent() {
                std::fs::create_dir_all(parent).map_err(PagedbError::Io)?;
            }
            match OsLockFileExHandle::try_acquire(&lock_path, LockKind::Shared) {
                Ok(os_lock) => Ok(TokioLockHandle {
                    lock_ref: entry,
                    kind: LockKind::Shared,
                    _os_lock: os_lock,
                }),
                Err(e) => {
                    let mut s = entry.state.lock();
                    match *s {
                        LockState::Shared(1) => *s = LockState::Free,
                        LockState::Shared(n) => *s = LockState::Shared(n - 1),
                        _ => {}
                    }
                    Err(e)
                }
            }
        }
        #[cfg(not(any(unix, windows)))]
        {
            Ok(TokioLockHandle {
                lock_ref: entry,
                kind: LockKind::Shared,
            })
        }
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
        let f = self.inner.lock().await;
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
        let mut p = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        p.push(format!(
            "pagedb-tokio-unit-{}-{}",
            std::process::id(),
            nanos
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
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
