//! `IocpVfs`: Windows IOCP-backed VFS rooted at a directory. Advisory path
//! locking is the shared `oslock` implementation. Segment
//! files open with `FILE_SHARE_DELETE` so tombstone-rename protocols succeed
//! against held handles.
//!
//! Path operations have no overlapped form: `CreateFile`, `MoveFileEx`,
//! directory enumeration and friends all park the calling thread. They run on
//! the blocking pool.

use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::Result;
use crate::errors::PagedbError;

use super::file::IocpFile;
use super::port::Port;
use crate::vfs::blocking::offload;
use crate::vfs::oslock::LockKind;
use crate::vfs::traits::{Vfs, canonical_native_path, resolve_native_path};
use crate::vfs::types::OpenMode;
use crate::vfs::write_order::WriteOrder;

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OVERLAPPED;

pub use crate::vfs::oslock::NativeLockHandle as IocpLockHandle;

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
            }),
        })
    }

    fn resolve(&self, path: &str) -> Result<PathBuf> {
        resolve_native_path(&self.inner.root, path)
    }

    async fn do_lock(&self, path: &str, kind: LockKind) -> Result<IocpLockHandle> {
        let lock_path = self.resolve(&canonical_native_path(path)?)?;
        crate::vfs::oslock::acquire(lock_path, kind).await
    }
}

impl Vfs for IocpVfs {
    type File = IocpFile;
    type LockHandle = IocpLockHandle;

    async fn open(&self, path: &str, mode: OpenMode) -> Result<Self::File> {
        let p = self.resolve(path)?;
        let (file, writable, order) = offload(move || {
            if matches!(mode, OpenMode::CreateNew | OpenMode::CreateOrOpen) {
                if let Some(parent) = p.parent() {
                    std::fs::create_dir_all(parent).map_err(PagedbError::Io)?;
                }
            }
            // FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE.
            // FILE_SHARE_DELETE is required so tombstone-rename protocols
            // succeed while readers hold handles open.
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
            let order = WriteOrder::for_file(&file)?;
            Ok((file, writable, order))
        })
        .await?;
        order.settled().await;
        let key = self.inner.next_key.fetch_add(1, Ordering::Relaxed);
        let handle = file.as_raw_handle() as HANDLE;
        // `CreateIoCompletionPort` only registers the handle with the port; it
        // returns without waiting on anything, so it stays on the executor.
        self.inner.port.associate(handle, key)?;
        Ok(IocpFile::new(
            file,
            writable,
            key,
            Arc::clone(&self.inner.port.inner),
            order,
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
            // `std::fs::rename` on Windows is
            // `MoveFileExW(MOVEFILE_REPLACE_EXISTING)`, which is the primitive
            // the tombstone protocol relies on.
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
        canonical_native_path(path)?;
        // NTFS folds rename durability into its metadata journal, and
        // `FlushFileBuffers` on a directory handle is not generally available
        // through `std::fs`. Best-effort no-op on Windows; rename + the
        // subsequent `sync` on the affected file produces a durable transition.
        Ok(())
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
