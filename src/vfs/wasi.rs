//! WASI preview1 VFS backend for pagedb.
//!
//! # Compile gating
//!
//! The full implementation is compiled only for `cfg(target_os = "wasi")`.
//! On every other target a thin shim is compiled instead; the constructor
//! returns [`PagedbError::Unsupported`] and every method is unreachable.
//!
//! # Locking
//!
//! WASI preview1 has no `flock` equivalent. Advisory locking falls back to an
//! in-process `BTreeMap` state machine — the same pattern used by `MemVfs` and
//! the non-Unix path of `TokioVfs`. In practice each WASI component runs in its
//! own sandbox (one instance per runtime invocation), so in-process exclusion is
//! sufficient. The limitation is documented here: if two WASI components happen
//! to share the same host directory via separate mounts, cross-component locking
//! is not enforced.
//!
//! # Directory sync
//!
//! WASI preview1 does not have a dedicated directory-sync syscall. `sync_dir`
//! opens the directory as a file descriptor and calls `fd_sync`. Some sandboxed
//! runtimes stub `fd_sync` out with `ENOTSUP`; that error is treated as a
//! no-op (best-effort durability, with a `tracing::debug!` trace emitted so the
//! caller has observability).

// ── Real WASI implementation ──────────────────────────────────────────────────

#[cfg(target_os = "wasi")]
pub use real::WasiVfs;

#[cfg(target_os = "wasi")]
mod real {
    use std::collections::BTreeMap;
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::path::PathBuf;
    use std::sync::Arc;

    use parking_lot::Mutex;

    use crate::Result;
    use crate::errors::PagedbError;
    use crate::vfs::traits::{Vfs, VfsFile};
    use crate::vfs::types::{OpenMode, ReadReq, WriteReq};

    // ── In-process lock state machine ─────────────────────────────────────────

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

    struct LockEntry {
        state: Mutex<LockState>,
    }

    /// RAII advisory lock handle. Releases the in-process lock on drop.
    pub struct WasiLockHandle {
        lock_ref: Arc<LockEntry>,
        kind: LockKind,
    }

    impl Drop for WasiLockHandle {
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

    // ── WasiVfs ───────────────────────────────────────────────────────────────

    struct WasiInner {
        root: PathBuf,
        locks: Mutex<BTreeMap<String, Arc<LockEntry>>>,
    }

    /// VFS rooted at a directory, backed by WASI preview1 synchronous syscalls.
    ///
    /// All `async fn`s wrap synchronous `std::fs` / `wasi`-crate calls. They
    /// do not yield. This is intentional: the WASI preview1 execution model is
    /// single-threaded and blocking. A future preview2 / component-model VFS
    /// backend would use native async I/O; this one targets preview1 runtimes
    /// (wasmtime, wasmer, wazero, etc.) as they exist today.
    ///
    /// Cloning shares the root directory and lock table.
    #[derive(Clone)]
    pub struct WasiVfs {
        inner: Arc<WasiInner>,
    }

    impl WasiVfs {
        /// Create a new `WasiVfs` rooted at `root`.
        ///
        /// The directory does not need to exist yet; the first `mkdir_all` or
        /// `open` with a create mode will create it.
        pub fn new(root: impl Into<PathBuf>) -> Self {
            Self {
                inner: Arc::new(WasiInner {
                    root: root.into(),
                    locks: Mutex::new(BTreeMap::new()),
                }),
            }
        }

        fn resolve(&self, p: &str) -> PathBuf {
            self.inner.root.join(p.trim_start_matches('/'))
        }

        fn lookup_or_create_entry(&self, path: &str) -> Arc<LockEntry> {
            let mut locks = self.inner.locks.lock();
            locks
                .entry(path.to_string())
                .or_insert_with(|| {
                    Arc::new(LockEntry {
                        state: Mutex::new(LockState::Free),
                    })
                })
                .clone()
        }
    }

    // ── WasiFile ──────────────────────────────────────────────────────────────

    /// Handle to an open file on a WASI target.
    ///
    /// Uses `std::fs::File`, which maps directly onto WASI preview1 `fd_*`
    /// syscalls. Positional reads and writes loop over `std::os::wasi::fs::FileExt`
    /// `read_at` / `write_at` which correspond to `fd_pread` / `fd_pwrite`.
    pub struct WasiFile {
        /// Mutex so that `read_at(&self, …)` can seek without requiring `&mut`.
        /// On WASI every seek+read pair is already synchronous so this adds no
        /// overhead beyond the lock word itself.
        inner: Mutex<std::fs::File>,
        writable: bool,
    }

    impl Vfs for WasiVfs {
        type File = WasiFile;
        type LockHandle = WasiLockHandle;

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
            Ok(WasiFile {
                inner: Mutex::new(file),
                writable,
            })
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
            let entries = match std::fs::read_dir(&p) {
                Ok(e) => e,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
                Err(e) => return Err(PagedbError::Io(e)),
            };
            let mut out = Vec::new();
            for entry in entries {
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

        /// Make directory metadata changes durable.
        ///
        /// WASI preview1 has no dedicated directory-sync syscall. This
        /// implementation opens the directory as a file descriptor and calls
        /// `wasi::fd_sync` on it. Runtimes that stub out `fd_sync` with
        /// `ENOTSUP` / `ENOSYS` are treated as a no-op so that pagedb still
        /// operates in those environments; a `tracing::debug!` message is
        /// emitted for observability.
        async fn sync_dir(&self, path: &str) -> Result<()> {
            use std::os::wasi::io::AsRawFd;

            let p = self.resolve(path);
            let dir = match std::fs::File::open(&p) {
                Ok(d) => d,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(e) => return Err(PagedbError::Io(e)),
            };

            // SAFETY: `dir.as_raw_fd()` is a valid, open file descriptor for
            // the duration of this call. `wasi::fd_sync` is a pure I/O syscall
            // that does not move or alias memory.
            let rc = unsafe { wasi::fd_sync(dir.as_raw_fd()) };
            match rc {
                Ok(()) => Ok(()),
                Err(e) if e == wasi::ERRNO_NOTSUP || e == wasi::ERRNO_NOSYS => {
                    tracing::debug!(
                        path = %p.display(),
                        "sync_dir: fd_sync returned {:?}; treating as no-op \
                         (runtime does not support directory sync)",
                        e
                    );
                    Ok(())
                }
                Err(e) => Err(PagedbError::Io(std::io::Error::from_raw_os_error(
                    e.raw() as i32
                ))),
            }
        }

        async fn lock_exclusive(&self, path: &str) -> Result<Self::LockHandle> {
            let entry = self.lookup_or_create_entry(path);
            let mut s = entry.state.lock();
            match *s {
                LockState::Free => {
                    *s = LockState::Exclusive;
                    drop(s);
                    Ok(WasiLockHandle {
                        lock_ref: entry,
                        kind: LockKind::Exclusive,
                    })
                }
                _ => Err(PagedbError::AlreadyLocked),
            }
        }

        async fn lock_shared(&self, path: &str) -> Result<Self::LockHandle> {
            let entry = self.lookup_or_create_entry(path);
            let mut s = entry.state.lock();
            let next = match *s {
                LockState::Free => LockState::Shared(1),
                LockState::Shared(n) => LockState::Shared(n + 1),
                LockState::Exclusive => return Err(PagedbError::AlreadyLocked),
            };
            *s = next;
            drop(s);
            Ok(WasiLockHandle {
                lock_ref: entry,
                kind: LockKind::Shared,
            })
        }

        fn root_path(&self) -> Option<&std::path::Path> {
            Some(&self.inner.root)
        }
    }

    impl VfsFile for WasiFile {
        async fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
            use std::os::wasi::fs::FileExt;
            let f = self.inner.lock();
            let mut total = 0usize;
            while total < buf.len() {
                match f.read_at(&mut buf[total..], offset + total as u64) {
                    Ok(0) => break,
                    Ok(n) => total += n,
                    Err(e) => return Err(PagedbError::Io(e)),
                }
            }
            Ok(total)
        }

        async fn read_at_vectored(&self, reqs: &mut [ReadReq<'_>]) -> Result<()> {
            use std::os::wasi::fs::FileExt;
            let f = self.inner.lock();
            for req in reqs.iter_mut() {
                let mut total = 0usize;
                loop {
                    if total == req.buf.len() {
                        break;
                    }
                    match f.read_at(&mut req.buf[total..], req.offset + total as u64) {
                        Ok(0) => break,
                        Ok(n) => total += n,
                        Err(e) => return Err(PagedbError::Io(e)),
                    }
                }
                // Zero the tail past EOF, matching the vectored contract:
                // callers see a deterministic buffer state.
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
            use std::os::wasi::fs::FileExt;
            let f = self.inner.lock();
            let mut total = 0usize;
            while total < buf.len() {
                match f.write_at(&buf[total..], offset + total as u64) {
                    Ok(0) => {
                        return Err(PagedbError::Io(std::io::Error::from(
                            std::io::ErrorKind::WriteZero,
                        )));
                    }
                    Ok(n) => total += n,
                    Err(e) => return Err(PagedbError::Io(e)),
                }
            }
            Ok(total)
        }

        async fn write_at_vectored(&mut self, reqs: &[WriteReq<'_>]) -> Result<()> {
            if !self.writable {
                return Err(PagedbError::ReadOnly);
            }
            use std::os::wasi::fs::FileExt;
            let f = self.inner.lock();
            for req in reqs {
                let mut total = 0usize;
                while total < req.buf.len() {
                    match f.write_at(&req.buf[total..], req.offset + total as u64) {
                        Ok(0) => {
                            return Err(PagedbError::Io(std::io::Error::from(
                                std::io::ErrorKind::WriteZero,
                            )));
                        }
                        Ok(n) => total += n,
                        Err(e) => return Err(PagedbError::Io(e)),
                    }
                }
            }
            Ok(())
        }

        async fn sync(&mut self) -> Result<()> {
            let f = self.inner.lock();
            f.sync_all().map_err(PagedbError::Io)
        }

        async fn truncate(&mut self, len: u64) -> Result<()> {
            if !self.writable {
                return Err(PagedbError::ReadOnly);
            }
            let f = self.inner.lock();
            f.set_len(len).map_err(PagedbError::Io)
        }

        async fn len(&self) -> Result<u64> {
            let f = self.inner.lock();
            Ok(f.metadata().map_err(PagedbError::Io)?.len())
        }

        async fn is_empty(&self) -> Result<bool> {
            Ok(self.len().await? == 0)
        }

        fn supports_direct_io(&self) -> bool {
            false
        }
    }
}

// ── Non-WASI shim ─────────────────────────────────────────────────────────────

#[cfg(not(target_os = "wasi"))]
pub use shim::WasiVfs;

#[cfg(not(target_os = "wasi"))]
mod shim {
    use crate::Result;
    use crate::errors::PagedbError;
    use crate::vfs::traits::{Vfs, VfsFile};
    use crate::vfs::types::{OpenMode, ReadReq, WriteReq};

    /// Placeholder compiled on non-WASI targets. Every method returns
    /// [`PagedbError::Unsupported`]; the constructor does too.
    pub struct WasiVfs {
        _private: (),
    }

    impl WasiVfs {
        /// Always returns `Err(PagedbError::Unsupported)` on non-WASI targets.
        pub fn new() -> Result<Self> {
            Err(PagedbError::Unsupported)
        }
    }

    pub struct WasiFileShim;

    impl VfsFile for WasiFileShim {
        async fn read_at(&self, _offset: u64, _buf: &mut [u8]) -> Result<usize> {
            Err(PagedbError::Unsupported)
        }
        async fn read_at_vectored(&self, _reqs: &mut [ReadReq<'_>]) -> Result<()> {
            Err(PagedbError::Unsupported)
        }
        async fn write_at(&mut self, _offset: u64, _buf: &[u8]) -> Result<usize> {
            Err(PagedbError::Unsupported)
        }
        async fn write_at_vectored(&mut self, _reqs: &[WriteReq<'_>]) -> Result<()> {
            Err(PagedbError::Unsupported)
        }
        async fn sync(&mut self) -> Result<()> {
            Err(PagedbError::Unsupported)
        }
        async fn truncate(&mut self, _len: u64) -> Result<()> {
            Err(PagedbError::Unsupported)
        }
        async fn len(&self) -> Result<u64> {
            Err(PagedbError::Unsupported)
        }
        async fn is_empty(&self) -> Result<bool> {
            Err(PagedbError::Unsupported)
        }
        fn supports_direct_io(&self) -> bool {
            false
        }
    }

    /// Unreachable lock handle for the non-WASI shim.
    pub struct WasiLockHandleShim(());

    impl Vfs for WasiVfs {
        type File = WasiFileShim;
        type LockHandle = WasiLockHandleShim;

        async fn open(&self, _path: &str, _mode: OpenMode) -> Result<Self::File> {
            Err(PagedbError::Unsupported)
        }
        async fn remove(&self, _path: &str) -> Result<()> {
            Err(PagedbError::Unsupported)
        }
        async fn rename(&self, _from: &str, _to: &str) -> Result<()> {
            Err(PagedbError::Unsupported)
        }
        async fn list_dir(&self, _path: &str) -> Result<Vec<String>> {
            Err(PagedbError::Unsupported)
        }
        async fn mkdir_all(&self, _path: &str) -> Result<()> {
            Err(PagedbError::Unsupported)
        }
        async fn sync_dir(&self, _path: &str) -> Result<()> {
            Err(PagedbError::Unsupported)
        }
        async fn lock_exclusive(&self, _path: &str) -> Result<Self::LockHandle> {
            Err(PagedbError::Unsupported)
        }
        async fn lock_shared(&self, _path: &str) -> Result<Self::LockHandle> {
            Err(PagedbError::Unsupported)
        }
    }
}
