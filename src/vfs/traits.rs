//! `Vfs` and `VfsFile` trait definitions.

use crate::Result;

use super::types::{OpenMode, ReadReq, WriteReq};

/// Abstract file-system surface used by the pager. Implementations provide
/// platform-appropriate I/O and advisory path locking.
///
/// Each `path` passed to a lock method is its own lock domain — locks on
/// distinct paths never conflict.
#[allow(async_fn_in_trait)]
pub trait Vfs: Send + Sync {
    type File: VfsFile;
    /// RAII handle returned by `lock_exclusive` / `lock_shared`. Dropping the
    /// handle releases the lock.
    type LockHandle: Send;

    /// Open the path according to `mode`.
    async fn open(&self, path: &str, mode: OpenMode) -> Result<Self::File>;

    /// Remove the file at `path`. Does not error if the path does not exist
    /// is backend-specific; mirror POSIX `unlink` semantics where possible.
    async fn remove(&self, path: &str) -> Result<()>;

    /// Rename `from` to `to`. Must succeed while a handle to `from` is still
    /// open (POSIX semantics); the handle stays bound to the same underlying
    /// data after the rename.
    async fn rename(&self, from: &str, to: &str) -> Result<()>;

    /// List entries at `path`. Order is unspecified.
    async fn list_dir(&self, path: &str) -> Result<Vec<String>>;

    /// Create `path` and all required parents. Idempotent.
    async fn mkdir_all(&self, path: &str) -> Result<()>;

    /// Make all metadata changes (renames, creates, removes) in `path`
    /// durable on the underlying storage. Required after rename operations
    /// in the segment publish / tombstone protocols and apply-journal replay.
    async fn sync_dir(&self, path: &str) -> Result<()>;

    /// Acquire an exclusive advisory lock on `path`. Fails fast with
    /// `PagedbError::AlreadyLocked` if any other holder (shared or exclusive)
    /// holds a lock on the same path.
    async fn lock_exclusive(&self, path: &str) -> Result<Self::LockHandle>;

    /// Acquire a shared advisory lock on `path`. Coexists with other shared
    /// locks on the same path; conflicts with an exclusive lock on the same
    /// path.
    async fn lock_shared(&self, path: &str) -> Result<Self::LockHandle>;

    /// Return the filesystem root path for VFS implementations backed by a
    /// real directory. Returns `None` for in-memory or non-filesystem backends.
    fn root_path(&self) -> Option<&std::path::Path> {
        None
    }
}

/// Per-file I/O surface. Vectored ops are all-or-nothing — either every
/// request is satisfied or the call returns an error and no partial state is
/// observable to the caller.
#[allow(async_fn_in_trait)]
pub trait VfsFile: Send {
    async fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize>;
    async fn read_at_vectored(&self, reqs: &mut [ReadReq<'_>]) -> Result<()>;
    async fn write_at(&mut self, offset: u64, buf: &[u8]) -> Result<usize>;
    async fn write_at_vectored(&mut self, reqs: &[WriteReq<'_>]) -> Result<()>;
    async fn sync(&mut self) -> Result<()>;
    async fn truncate(&mut self, len: u64) -> Result<()>;
    /// Shrink or extend the file to exactly `len` bytes. Identical to
    /// `truncate`; provided as an explicit alias so callers can use the name
    /// that matches their intent (shrinking for compaction).
    async fn set_len(&mut self, len: u64) -> Result<()> {
        self.truncate(len).await
    }
    async fn len(&self) -> Result<u64>;
    async fn is_empty(&self) -> Result<bool>;
    fn supports_direct_io(&self) -> bool;
}
