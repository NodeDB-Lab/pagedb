//! `NativeVfs`: the Linux/Android backend selection, made at run time.
//!
//! `io_uring` is a performance choice, never a correctness one — [`TokioVfs`]
//! implements the same [`Vfs`] contract with the same durability and the same
//! locking. But a ring can fail to exist for reasons that have nothing to do
//! with the store: rings are charged against `RLIMIT_MEMLOCK` (commonly 8 MB,
//! exhausted by a handful of concurrent opens), Docker's default seccomp
//! profile blocks `io_uring_setup` outright, and kernels before 5.1 have no
//! such syscall. Failing the open in those environments would mean an embedder
//! simply cannot use its database, to buy nothing.
//!
//! So the selection is a run-time enum rather than a compile-time alias:
//! [`open_native`] takes a ring when one is available and drops to the thread
//! pool when it is not, loudly.
//!
//! The two backends share one lock implementation (see [`NativeLockHandle`]), so
//! a process that got a ring and a process that fell back still exclude each
//! other on the same `.writer.lock` sentinel. That is what makes degrading
//! safe rather than a way to double-open a store.

use std::path::Path;

use crate::Result;

use super::iouring::{IouringFile, IouringVfs};
use super::oslock::NativeLockHandle;
use super::tokio_backend::{TokioFile, TokioVfs};
use super::traits::{Vfs, VfsFile};
use super::types::{OpenMode, ReadReq, WriteReq};

/// The native VFS for Linux and 64-bit Android: `io_uring` when the kernel
/// grants a ring, the Tokio thread pool when it does not.
#[derive(Clone)]
pub enum NativeVfs {
    /// `io_uring` submission/completion queues — the fast path.
    Iouring(IouringVfs),
    /// Tokio's blocking pool — same behaviour, lower I/O throughput.
    Tokio(TokioVfs),
}

/// An open file belonging to whichever backend [`NativeVfs`] selected.
pub enum NativeFile {
    /// A file driven through the `io_uring` instance.
    Iouring(IouringFile),
    /// A file driven through the Tokio thread pool.
    Tokio(TokioFile),
}

/// Construct the native VFS rooted at `root`, preferring `io_uring`.
///
/// Never fails: the thread-pool backend needs nothing from the kernel beyond
/// ordinary file syscalls, so there is always a backend to return.
#[must_use]
pub fn open_native(root: &Path) -> NativeVfs {
    match IouringVfs::new(root) {
        Ok(vfs) => NativeVfs::Iouring(vfs),
        Err(error) => {
            // Degrading silently would be its own bug: the store keeps working,
            // but I/O throughput drops for a reason nothing in the process
            // reports. Name the situation and the causes worth checking.
            tracing::warn!(
                root = %root.display(),
                error = %error,
                "io_uring is unavailable, so pagedb is continuing on the thread-pool \
                 backend: identical behaviour and durability, reduced I/O performance. \
                 Worth checking: RLIMIT_MEMLOCK (every ring is charged against it, and \
                 the default 8 MB is exhausted by a handful of concurrent stores), a \
                 seccomp profile blocking io_uring_setup (Docker's default profile \
                 does), or a kernel older than 5.1."
            );
            NativeVfs::Tokio(TokioVfs::new(root))
        }
    }
}

impl NativeVfs {
    /// Whether this VFS is running on `io_uring` rather than the thread-pool
    /// fallback. Diagnostics and benchmarks report the backend actually in use;
    /// correctness never depends on which one it is.
    #[must_use]
    pub fn uses_iouring(&self) -> bool {
        matches!(self, Self::Iouring(_))
    }
}

impl Vfs for NativeVfs {
    type File = NativeFile;
    // One handle type for both arms: the lock protocol is shared, so there is
    // nothing backend-specific left to wrap.
    type LockHandle = NativeLockHandle;

    async fn open(&self, path: &str, mode: OpenMode) -> Result<Self::File> {
        match self {
            Self::Iouring(vfs) => Ok(NativeFile::Iouring(vfs.open(path, mode).await?)),
            Self::Tokio(vfs) => Ok(NativeFile::Tokio(vfs.open(path, mode).await?)),
        }
    }

    async fn remove(&self, path: &str) -> Result<()> {
        match self {
            Self::Iouring(vfs) => vfs.remove(path).await,
            Self::Tokio(vfs) => vfs.remove(path).await,
        }
    }

    async fn rename(&self, from: &str, to: &str) -> Result<()> {
        match self {
            Self::Iouring(vfs) => vfs.rename(from, to).await,
            Self::Tokio(vfs) => vfs.rename(from, to).await,
        }
    }

    async fn list_dir(&self, path: &str) -> Result<Vec<String>> {
        match self {
            Self::Iouring(vfs) => vfs.list_dir(path).await,
            Self::Tokio(vfs) => vfs.list_dir(path).await,
        }
    }

    async fn mkdir_all(&self, path: &str) -> Result<()> {
        match self {
            Self::Iouring(vfs) => vfs.mkdir_all(path).await,
            Self::Tokio(vfs) => vfs.mkdir_all(path).await,
        }
    }

    async fn sync_dir(&self, path: &str) -> Result<()> {
        match self {
            Self::Iouring(vfs) => vfs.sync_dir(path).await,
            Self::Tokio(vfs) => vfs.sync_dir(path).await,
        }
    }

    async fn lock_exclusive(&self, path: &str) -> Result<Self::LockHandle> {
        match self {
            Self::Iouring(vfs) => vfs.lock_exclusive(path).await,
            Self::Tokio(vfs) => vfs.lock_exclusive(path).await,
        }
    }

    async fn lock_shared(&self, path: &str) -> Result<Self::LockHandle> {
        match self {
            Self::Iouring(vfs) => vfs.lock_shared(path).await,
            Self::Tokio(vfs) => vfs.lock_shared(path).await,
        }
    }

    fn root_path(&self) -> Option<&Path> {
        match self {
            Self::Iouring(vfs) => vfs.root_path(),
            Self::Tokio(vfs) => Vfs::root_path(vfs),
        }
    }
}

impl VfsFile for NativeFile {
    async fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        match self {
            Self::Iouring(file) => file.read_at(offset, buf).await,
            Self::Tokio(file) => file.read_at(offset, buf).await,
        }
    }

    async fn read_at_vectored(&self, reqs: &mut [ReadReq<'_>]) -> Result<()> {
        match self {
            Self::Iouring(file) => file.read_at_vectored(reqs).await,
            Self::Tokio(file) => file.read_at_vectored(reqs).await,
        }
    }

    async fn write_at(&mut self, offset: u64, buf: &[u8]) -> Result<usize> {
        match self {
            Self::Iouring(file) => file.write_at(offset, buf).await,
            Self::Tokio(file) => file.write_at(offset, buf).await,
        }
    }

    async fn write_at_vectored(&mut self, reqs: &[WriteReq<'_>]) -> Result<()> {
        match self {
            Self::Iouring(file) => file.write_at_vectored(reqs).await,
            Self::Tokio(file) => file.write_at_vectored(reqs).await,
        }
    }

    async fn sync(&mut self) -> Result<()> {
        match self {
            Self::Iouring(file) => file.sync().await,
            Self::Tokio(file) => file.sync().await,
        }
    }

    async fn truncate(&mut self, len: u64) -> Result<()> {
        match self {
            Self::Iouring(file) => file.truncate(len).await,
            Self::Tokio(file) => file.truncate(len).await,
        }
    }

    /// Delegated rather than left to the trait default so a backend that ever
    /// gives `set_len` its own implementation keeps it through the wrapper.
    async fn set_len(&mut self, len: u64) -> Result<()> {
        match self {
            Self::Iouring(file) => file.set_len(len).await,
            Self::Tokio(file) => file.set_len(len).await,
        }
    }

    async fn len(&self) -> Result<u64> {
        match self {
            Self::Iouring(file) => file.len().await,
            Self::Tokio(file) => file.len().await,
        }
    }

    async fn is_empty(&self) -> Result<bool> {
        match self {
            Self::Iouring(file) => file.is_empty().await,
            Self::Tokio(file) => file.is_empty().await,
        }
    }

    fn supports_direct_io(&self) -> bool {
        match self {
            Self::Iouring(file) => file.supports_direct_io(),
            Self::Tokio(file) => file.supports_direct_io(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tempdir() -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};

        static NEXT: AtomicU64 = AtomicU64::new(0);
        let mut path = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
        path.push(format!(
            "pagedb-native-unit-{}-{nanos}-{sequence}",
            std::process::id()
        ));
        std::fs::create_dir(&path).unwrap();
        path
    }

    /// The fallback arm has to be a working VFS in its own right, not just a
    /// value that constructs. Drive the whole trait surface through it.
    #[tokio::test(flavor = "current_thread")]
    async fn the_fallback_arm_delegates_every_file_operation() {
        let dir = tempdir();
        let vfs = NativeVfs::Tokio(TokioVfs::new(&dir));
        assert!(!vfs.uses_iouring());
        assert_eq!(vfs.root_path(), Some(dir.as_path()));

        vfs.mkdir_all("/seg").await.unwrap();
        let mut file = vfs.open("/seg/page", OpenMode::CreateNew).await.unwrap();
        file.write_at(0, b"pagedb").await.unwrap();
        file.sync().await.unwrap();
        assert_eq!(file.len().await.unwrap(), 6);
        assert!(!file.is_empty().await.unwrap());

        file.write_at_vectored(&[WriteReq {
            offset: 8,
            buf: b"tail",
        }])
        .await
        .unwrap();

        let mut head = [0u8; 6];
        let mut tail = [0u8; 4];
        file.read_at_vectored(&mut [
            ReadReq {
                offset: 0,
                buf: &mut head,
            },
            ReadReq {
                offset: 8,
                buf: &mut tail,
            },
        ])
        .await
        .unwrap();
        assert_eq!(&head, b"pagedb");
        assert_eq!(&tail, b"tail");

        file.set_len(6).await.unwrap();
        assert_eq!(file.len().await.unwrap(), 6);
        file.truncate(0).await.unwrap();
        assert!(file.is_empty().await.unwrap());
        assert!(!file.supports_direct_io());
        drop(file);

        vfs.rename("/seg/page", "/seg/renamed").await.unwrap();
        assert_eq!(vfs.list_dir("/seg").await.unwrap(), vec!["renamed"]);
        vfs.sync_dir("/seg").await.unwrap();
        vfs.remove("/seg/renamed").await.unwrap();
        assert!(vfs.list_dir("/seg").await.unwrap().is_empty());

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Locking must behave identically through the wrapper: the handle type is
    /// shared, so an exclusive lock taken on one arm is visible to the other.
    #[tokio::test(flavor = "current_thread")]
    async fn the_fallback_arm_locks_through_the_shared_handle() {
        let dir = tempdir();
        let vfs = NativeVfs::Tokio(TokioVfs::new(&dir));

        let held = vfs.lock_exclusive("/db").await.unwrap();
        assert!(vfs.lock_shared("/db").await.is_err());
        drop(held);

        let shared_first = vfs.lock_shared("/db").await.unwrap();
        let shared_second = vfs.lock_shared("/db").await.unwrap();
        assert!(vfs.lock_exclusive("/db").await.is_err());
        drop(shared_first);
        drop(shared_second);
        vfs.lock_exclusive("/db").await.unwrap();

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The whole point of the fallback: `open_native` yields a usable store
    /// backend whichever arm it lands on, and never fails.
    #[tokio::test(flavor = "current_thread")]
    async fn open_native_always_yields_a_working_vfs() {
        let dir = tempdir();
        let vfs = open_native(&dir);

        let mut file = vfs.open("/probe", OpenMode::CreateNew).await.unwrap();
        file.write_at(0, b"ok").await.unwrap();
        file.sync().await.unwrap();
        drop(file);

        let reopened = vfs.open("/probe", OpenMode::Read).await.unwrap();
        let mut buf = [0u8; 2];
        assert_eq!(reopened.read_at(0, &mut buf).await.unwrap(), 2);
        assert_eq!(&buf, b"ok");

        std::fs::remove_dir_all(&dir).ok();
    }

    /// An `io_uring`-backed lock and a thread-pool-backed lock over the same
    /// directory must exclude each other — otherwise the fallback would let two
    /// processes hold the same store's writer sentinel at once. Both arms take
    /// the same OFD lock, and OFD locks conflict across open file descriptions
    /// even inside one process, so this is testable without spawning.
    #[tokio::test(flavor = "current_thread")]
    async fn the_two_backends_exclude_each_other_on_the_same_path() {
        let dir = tempdir();
        let Ok(iouring) = IouringVfs::new(&dir) else {
            // No ring available here; the mixed-backend case cannot arise on
            // this machine, so there is nothing to assert.
            std::fs::remove_dir_all(&dir).ok();
            return;
        };
        let iouring = NativeVfs::Iouring(iouring);
        let tokio = NativeVfs::Tokio(TokioVfs::new(&dir));

        let held = iouring.lock_exclusive("/db").await.unwrap();
        assert!(
            matches!(
                tokio.lock_exclusive("/db").await,
                Err(crate::errors::PagedbError::AlreadyLocked)
            ),
            "the thread-pool backend must not be able to take a lock the \
             io_uring backend already holds"
        );
        drop(held);

        // And the other direction, so neither backend is the privileged one.
        let held = tokio.lock_exclusive("/db").await.unwrap();
        assert!(matches!(
            iouring.lock_exclusive("/db").await,
            Err(crate::errors::PagedbError::AlreadyLocked)
        ));
        drop(held);

        std::fs::remove_dir_all(&dir).ok();
    }
}
