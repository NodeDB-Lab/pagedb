//! Advisory path locking shared by every filesystem-backed native VFS.
//!
//! One protocol, one implementation. A lock is two layers: an in-process state
//! machine that gives fast single-process exclusion, and an OS-level lock that
//! excludes other processes — `fcntl` OFD locks (`F_OFD_SETLK`) on Linux,
//! classic `F_SETLK` on other Unix, and `LockFileEx` on Windows. On targets
//! with neither, only the in-process layer applies.
//!
//! Both layers live here rather than in each backend deliberately. The store's
//! single-writer guarantee rests on the `.writer.lock` sentinel, and two
//! backends may hold that sentinel at the same time — a process that got an
//! `io_uring` ring and one that fell back to the thread pool are running
//! different `Vfs` implementations over the same directory. If they locked by
//! different rules, the two would not exclude each other and both could write
//! the same store. Sharing the code makes that class of divergence impossible.
//!
//! `unsafe` is permitted here for the platform lock primitives (fcntl on Unix,
//! `LockFileEx` on Windows).
#![allow(unsafe_code)]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use parking_lot::Mutex;

use crate::Result;
use crate::errors::PagedbError;

#[cfg(any(unix, windows))]
use super::blocking::offload;

// ---------------------------------------------------------------------------
// In-process lock state machine (guards single-process re-entry on all
// targets, and is the only guard where the OS offers no advisory lock).
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
enum LockState {
    Free,
    Exclusive,
    Shared(u32),
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum LockKind {
    Exclusive,
    Shared,
}

struct InProcLockEntry {
    state: Mutex<LockState>,
}

impl InProcLockEntry {
    /// Take the in-process layer, or report the conflict without touching it.
    fn try_enter(&self, kind: LockKind) -> Result<()> {
        let mut state = self.state.lock();
        match (kind, *state) {
            (LockKind::Exclusive, LockState::Free) => *state = LockState::Exclusive,
            (LockKind::Shared, LockState::Free) => *state = LockState::Shared(1),
            (LockKind::Shared, LockState::Shared(n)) => *state = LockState::Shared(n + 1),
            _ => return Err(PagedbError::AlreadyLocked),
        }
        Ok(())
    }

    /// Give the in-process layer back. Used both when a handle drops and to
    /// roll back after the OS layer refused, so a failed acquisition leaves no
    /// trace.
    fn leave(&self, kind: LockKind) {
        let mut state = self.state.lock();
        match (kind, *state) {
            (LockKind::Exclusive, LockState::Exclusive)
            | (LockKind::Shared, LockState::Shared(1)) => *state = LockState::Free,
            (LockKind::Shared, LockState::Shared(n)) if n > 1 => *state = LockState::Shared(n - 1),
            _ => {}
        }
    }
}

/// Per-VFS table of in-process lock entries, keyed by canonical logical path.
///
/// Each distinct canonical path is its own lock domain. The table only ever
/// grows an entry per path that has been locked at least once; entries are
/// cheap and keeping them avoids racing a concurrent acquirer against removal.
pub(crate) struct LockTable {
    entries: Mutex<BTreeMap<String, Arc<InProcLockEntry>>>,
}

impl LockTable {
    pub(crate) fn new() -> Self {
        Self {
            entries: Mutex::new(BTreeMap::new()),
        }
    }

    fn entry(&self, path: &str) -> Arc<InProcLockEntry> {
        let mut entries = self.entries.lock();
        entries
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
// Unix cross-process lock via fcntl.
// ---------------------------------------------------------------------------

/// On Unix, holds an open file descriptor whose advisory lock is released when
/// this struct is dropped (fd close triggers lock release).
///
/// On Linux the lock is an **OFD** (open file description) lock
/// (`F_OFD_SETLK`), which is owned by the open file description rather than the
/// process. This avoids two notorious `F_SETLK` (process-associated) footguns
/// that can drop or defeat a writer lock and let a second opener corrupt the
/// store:
///
/// 1. *Release-on-any-close*: a process `F_SETLK` lock is dropped the moment
///    the process closes **any** fd to that inode, not just the locking fd — an
///    unrelated open/close of the lock path silently frees the lock.
/// 2. *Self-non-conflict*: a second `F_SETLK` request from the **same** process
///    succeeds instead of conflicting, so two VFS instances (with independent
///    in-process lock tables) can both "acquire" and double-open.
///
/// OFD locks are per-description: closing other fds does not release them, and
/// two open descriptions conflict even within one process. They also conflict
/// with traditional `F_SETLK` record locks, so a mixed deployment still
/// excludes correctly.
///
/// Non-Linux Unix (e.g. macOS, which lacks OFD locks) falls back to `F_SETLK`.
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

        // Prefer OFD locks on Linux (see the type doc); fall back to classic
        // process locks elsewhere. Both use the identical `flock` payload and
        // the same non-blocking `*_SETLK` semantics (EAGAIN/EACCES == conflict).
        #[cfg(target_os = "linux")]
        let cmd = libc::F_OFD_SETLK;
        #[cfg(not(target_os = "linux"))]
        let cmd = libc::F_SETLK;

        // SAFETY: `fd` is valid (owned by `file` above which stays alive past
        // this call); `flock` is a plain C struct fully initialised above.
        // The command is non-blocking: EAGAIN/EACCES means another open
        // description (OFD) or process (F_SETLK) holds a conflicting lock.
        let rc = unsafe { libc::fcntl(fd, cmd, &flock) };
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

/// The OS lock primitive for this target. Unix and Windows are mutually
/// exclusive cfgs, so this names exactly one type wherever it exists.
#[cfg(unix)]
type OsLock = OsFcntlHandle;
#[cfg(windows)]
type OsLock = OsLockFileExHandle;

// ---------------------------------------------------------------------------
// Public lock handle.
// ---------------------------------------------------------------------------

/// RAII advisory lock handle returned by every native backend's
/// `lock_exclusive` / `lock_shared`. Holds the in-process state guard and, on
/// targets that have one, the OS-level lock. Dropping it releases both.
pub struct NativeLockHandle {
    entry: Arc<InProcLockEntry>,
    kind: LockKind,
    /// On Unix: holds the fcntl-locked file open (an OFD lock on Linux, a
    /// process `F_SETLK` lock elsewhere). On Windows: holds the
    /// `LockFileEx`-locked file open. Dropped together with this handle.
    #[cfg(any(unix, windows))]
    _os_lock: OsLock,
}

impl Drop for NativeLockHandle {
    fn drop(&mut self) {
        self.entry.leave(self.kind);
        // `_os_lock` is dropped automatically after this, releasing the OS lock.
    }
}

/// Acquire an advisory lock on one canonical logical path.
///
/// `logical_path` names the lock domain in the in-process table;
/// `lock_path` is the sentinel file on disk that carries the OS-level lock.
pub(crate) async fn acquire(
    table: &LockTable,
    logical_path: &str,
    lock_path: PathBuf,
    kind: LockKind,
) -> Result<NativeLockHandle> {
    let entry = table.entry(logical_path);
    // In-process guard first: fast fail if this process already holds a
    // conflicting lock on the path, without touching the filesystem.
    entry.try_enter(kind)?;

    #[cfg(any(unix, windows))]
    {
        // Neither `*_SETLK` nor `LOCKFILE_FAIL_IMMEDIATELY` waits on a
        // conflict, but creating the sentinel file can still stall on the
        // filesystem, so the pair goes to the blocking pool together.
        let acquired = offload(move || {
            if let Some(parent) = lock_path.parent() {
                std::fs::create_dir_all(parent).map_err(PagedbError::Io)?;
            }
            OsLock::try_acquire(&lock_path, kind)
        })
        .await;
        match acquired {
            Ok(os_lock) => Ok(NativeLockHandle {
                entry,
                kind,
                _os_lock: os_lock,
            }),
            Err(error) => {
                // The OS layer refused, so the in-process layer must not stay
                // taken — a rejected acquisition leaves no trace.
                entry.leave(kind);
                Err(error)
            }
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = lock_path;
        Ok(NativeLockHandle { entry, kind })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_exclusive_entry_excludes_every_other_kind() {
        let table = LockTable::new();
        let entry = table.entry("/db");
        entry.try_enter(LockKind::Exclusive).unwrap();
        assert!(matches!(
            entry.try_enter(LockKind::Exclusive),
            Err(PagedbError::AlreadyLocked)
        ));
        assert!(matches!(
            entry.try_enter(LockKind::Shared),
            Err(PagedbError::AlreadyLocked)
        ));
    }

    #[test]
    fn shared_entries_stack_and_only_the_last_release_frees_the_domain() {
        let table = LockTable::new();
        let entry = table.entry("/db");
        entry.try_enter(LockKind::Shared).unwrap();
        entry.try_enter(LockKind::Shared).unwrap();

        entry.leave(LockKind::Shared);
        assert!(
            matches!(
                entry.try_enter(LockKind::Exclusive),
                Err(PagedbError::AlreadyLocked)
            ),
            "one shared holder remains, so exclusive must still be refused"
        );

        entry.leave(LockKind::Shared);
        entry.try_enter(LockKind::Exclusive).unwrap();
    }

    #[test]
    fn the_same_logical_path_always_maps_to_one_entry() {
        let table = LockTable::new();
        let first = table.entry("/db");
        let second = table.entry("/db");
        assert!(Arc::ptr_eq(&first, &second));
        assert!(!Arc::ptr_eq(&first, &table.entry("/other")));
    }
}
