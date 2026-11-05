//! `GcdVfs`: macOS / iOS / iPadOS VFS rooted at a directory, using Grand
//! Central Dispatch I/O for per-file reads and writes. Advisory path locking
//! is the shared `oslock` implementation.
//!
//! `dispatch_io` covers reads and writes only. Path operations and directory
//! sync are plain blocking syscalls, so they run on the blocking pool.
use std::path::PathBuf;
use std::sync::Arc;

use dispatch2::{DispatchQoS, DispatchQueue, DispatchRetained, GlobalQueueIdentifier};

use crate::Result;
use crate::errors::PagedbError;

use super::file::GcdFile;
use crate::vfs::blocking::offload;
use crate::vfs::oslock::LockKind;
use crate::vfs::traits::{Vfs, canonical_native_path, resolve_native_path};
use crate::vfs::types::OpenMode;
use crate::vfs::write_order::WriteOrder;

pub use crate::vfs::oslock::NativeLockHandle as GcdLockHandle;

struct GcdInner {
    root: PathBuf,
    queue: DispatchRetained<DispatchQueue>,
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
            }),
        }
    }

    fn resolve(&self, path: &str) -> Result<PathBuf> {
        resolve_native_path(&self.inner.root, path)
    }

    async fn do_lock(&self, path: &str, kind: LockKind) -> Result<GcdLockHandle> {
        let lock_path = self.resolve(&canonical_native_path(path)?)?;
        crate::vfs::oslock::acquire(lock_path, kind).await
    }
}

impl Vfs for GcdVfs {
    type File = GcdFile;
    type LockHandle = GcdLockHandle;

    async fn open(&self, path: &str, mode: OpenMode) -> Result<Self::File> {
        let p = self.resolve(path)?;
        let (file, writable, order) = offload(move || {
            if matches!(mode, OpenMode::CreateNew | OpenMode::CreateOrOpen) {
                if let Some(parent) = p.parent() {
                    std::fs::create_dir_all(parent).map_err(PagedbError::Io)?;
                }
            }
            let (file, writable) = match mode {
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
            let order = WriteOrder::for_file(&file)?;
            Ok((file, writable, order))
        })
        .await?;
        order.settled().await;
        // Creating the channel only registers the descriptor with libdispatch;
        // it performs no I/O, so it stays on the executor. Clone the queue
        // retain so the file holds its own reference.
        GcdFile::new(file, writable, self.inner.queue.clone(), order)
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
