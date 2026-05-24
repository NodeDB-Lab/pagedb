//! `Vfs` and `VfsFile` trait definitions.

use std::future::Future;

use crate::Result;

use super::types::{OpenMode, ReadReq, WriteReq};

/// Abstract file-system surface used by the pager. Implementations provide
/// platform-appropriate I/O and advisory path locking.
///
/// Each `path` passed to a lock method is its own lock domain — locks on
/// distinct paths never conflict.
///
/// All async methods return futures that are `Send`, matching the `Send + Sync`
/// supertrait bounds on `Vfs` itself. This allows `Db<V>` futures to be
/// safely sent across threads when `V: Vfs`.
pub trait Vfs: Send + Sync {
    type File: VfsFile;
    /// RAII handle returned by `lock_exclusive` / `lock_shared`. Dropping the
    /// handle releases the lock.
    type LockHandle: Send + Sync;

    /// Open the path according to `mode`.
    fn open(&self, path: &str, mode: OpenMode) -> impl Future<Output = Result<Self::File>> + Send;

    /// Remove the file at `path`. Does not error if the path does not exist
    /// is backend-specific; mirror POSIX `unlink` semantics where possible.
    fn remove(&self, path: &str) -> impl Future<Output = Result<()>> + Send;

    /// Rename `from` to `to`. Must succeed while a handle to `from` is still
    /// open (POSIX semantics); the handle stays bound to the same underlying
    /// data after the rename.
    fn rename(&self, from: &str, to: &str) -> impl Future<Output = Result<()>> + Send;

    /// List entries at `path`. Order is unspecified.
    fn list_dir(&self, path: &str) -> impl Future<Output = Result<Vec<String>>> + Send;

    /// Create `path` and all required parents. Idempotent.
    fn mkdir_all(&self, path: &str) -> impl Future<Output = Result<()>> + Send;

    /// Make all metadata changes (renames, creates, removes) in `path`
    /// durable on the underlying storage. Required after rename operations
    /// in the segment publish / tombstone protocols and apply-journal replay.
    fn sync_dir(&self, path: &str) -> impl Future<Output = Result<()>> + Send;

    /// Acquire an exclusive advisory lock on `path`. Fails fast with
    /// `PagedbError::AlreadyLocked` if any other holder (shared or exclusive)
    /// holds a lock on the same path.
    fn lock_exclusive(&self, path: &str) -> impl Future<Output = Result<Self::LockHandle>> + Send;

    /// Acquire a shared advisory lock on `path`. Coexists with other shared
    /// locks on the same path; conflicts with an exclusive lock on the same
    /// path.
    fn lock_shared(&self, path: &str) -> impl Future<Output = Result<Self::LockHandle>> + Send;

    /// Return the filesystem root path for VFS implementations backed by a
    /// real directory. Returns `None` for in-memory or non-filesystem backends.
    fn root_path(&self) -> Option<&std::path::Path> {
        None
    }
}

/// Per-file I/O surface. Vectored ops are all-or-nothing — either every
/// request is satisfied or the call returns an error and no partial state is
/// observable to the caller.
///
/// All async methods return `Send` futures so that `VfsFile` values can be
/// held across await points inside `Send` futures.
pub trait VfsFile: Send {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> impl Future<Output = Result<usize>> + Send;
    fn read_at_vectored(&self, reqs: &mut [ReadReq<'_>])
    -> impl Future<Output = Result<()>> + Send;
    fn write_at(&mut self, offset: u64, buf: &[u8]) -> impl Future<Output = Result<usize>> + Send;
    fn write_at_vectored(
        &mut self,
        reqs: &[WriteReq<'_>],
    ) -> impl Future<Output = Result<()>> + Send;
    fn sync(&mut self) -> impl Future<Output = Result<()>> + Send;
    fn truncate(&mut self, len: u64) -> impl Future<Output = Result<()>> + Send;
    /// Shrink or extend the file to exactly `len` bytes. Identical to
    /// `truncate`; provided as an explicit alias so callers can use the name
    /// that matches their intent (shrinking for compaction).
    fn set_len(&mut self, len: u64) -> impl Future<Output = Result<()>> + Send {
        self.truncate(len)
    }
    fn len(&self) -> impl Future<Output = Result<u64>> + Send;
    fn is_empty(&self) -> impl Future<Output = Result<bool>> + Send;
    fn supports_direct_io(&self) -> bool;
}
