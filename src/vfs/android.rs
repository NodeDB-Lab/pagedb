//! `AndroidVfs`: thread-pool-backed VFS for Android targets that cannot use
//! `io_uring` (Android < 12, `armv7-linux-androideabi`).
//!
//! The Android backend's primitive is a thread-pool — exactly what
//! [`super::tokio_backend::TokioVfs`] provides. Rather than duplicate the
//! file/lock/sync machinery, this module wraps the Tokio backend under a
//! distinct platform name so the backend matrix maps 1:1 to a real module
//! path; callers select via [`super::open_default`] without seeing the alias.
//!
//! Selection cfg: `target_os = "android"` together with `target_arch = "arm"`
//! (the 32-bit `armv7` ABI). Modern 64-bit Android (`aarch64`) uses
//! `IouringVfs`.

pub use super::tokio_backend::{TokioFile as AndroidFile, TokioLockHandle as AndroidLockHandle};

use super::tokio_backend::TokioVfs;
use std::path::PathBuf;

/// VFS rooted at a directory, using Tokio's thread-pool for blocking syscalls.
/// Identical in behavior to [`TokioVfs`]; carries a distinct name only so the
/// per-target backend matrix maps to a real module path.
#[derive(Clone)]
pub struct AndroidVfs {
    inner: TokioVfs,
}

impl AndroidVfs {
    /// Create a new `AndroidVfs` rooted at `root`.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            inner: TokioVfs::new(root),
        }
    }

    /// Return the filesystem root directory of this VFS instance.
    #[must_use]
    pub fn root_path(&self) -> &std::path::Path {
        self.inner.root_path()
    }
}

impl std::ops::Deref for AndroidVfs {
    type Target = TokioVfs;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl super::traits::Vfs for AndroidVfs {
    type File = AndroidFile;
    type LockHandle = AndroidLockHandle;

    async fn open(&self, path: &str, mode: super::types::OpenMode) -> crate::Result<Self::File> {
        self.inner.open(path, mode).await
    }
    async fn remove(&self, path: &str) -> crate::Result<()> {
        self.inner.remove(path).await
    }
    async fn rename(&self, from: &str, to: &str) -> crate::Result<()> {
        self.inner.rename(from, to).await
    }
    async fn list_dir(&self, path: &str) -> crate::Result<Vec<String>> {
        self.inner.list_dir(path).await
    }
    async fn mkdir_all(&self, path: &str) -> crate::Result<()> {
        self.inner.mkdir_all(path).await
    }
    async fn sync_dir(&self, path: &str) -> crate::Result<()> {
        self.inner.sync_dir(path).await
    }
    async fn lock_exclusive(&self, path: &str) -> crate::Result<Self::LockHandle> {
        self.inner.lock_exclusive(path).await
    }
    async fn lock_shared(&self, path: &str) -> crate::Result<Self::LockHandle> {
        self.inner.lock_shared(path).await
    }
    fn root_path(&self) -> Option<&std::path::Path> {
        Some(self.inner.root_path())
    }
}
