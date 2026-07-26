//! `Vfs` and `VfsFile` trait definitions.

use std::future::Future;

use crate::Result;
use crate::errors::PagedbError;

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

/// Read until `buf` is full, or fail if the backend stops making progress.
///
/// Takes `&mut F` rather than `&F` deliberately. `read_at` only needs `&self`,
/// but a future holding `&F` across an await is `Send` only when `F: Sync`,
/// and `VfsFile` does not require `Sync`. `&mut F` keeps the future `Send` for
/// every backend. Callers that own their handle use this; those that read
/// through a borrowed handle use [`read_exact_at_borrowed!`], which runs the
/// same loop in place.
#[inline]
pub(crate) async fn read_exact_at<F: VfsFile + ?Sized>(
    file: &mut F,
    mut offset: u64,
    mut buf: &mut [u8],
) -> Result<()> {
    while !buf.is_empty() {
        let read = file.read_at(offset, buf).await?;
        checked_read_progress(&mut offset, read, buf.len())?;
        buf = buf.split_at_mut(read).1;
    }
    Ok(())
}

/// Validate one positional read result and advance its offset.
///
/// A backend may legally satisfy a request in several calls, so a short read is
/// not itself failure. Zero progress is end-of-file; a count above the
/// remaining buffer is a backend contract violation, not an on-disk defect.
#[inline]
pub(crate) fn checked_read_progress(offset: &mut u64, read: usize, remaining: usize) -> Result<()> {
    if read == 0 {
        return Err(PagedbError::Io(std::io::Error::from(
            std::io::ErrorKind::UnexpectedEof,
        )));
    }
    checked_transfer_progress(offset, read, remaining, "read_at", "positional read offset")
}

/// Write until `buf` is complete, or fail if the backend reports impossible
/// progress. See [`read_exact_at`] for why this takes `&mut F`.
#[inline]
pub(crate) async fn write_all_at<F: VfsFile + ?Sized>(
    file: &mut F,
    mut offset: u64,
    mut buf: &[u8],
) -> Result<()> {
    while !buf.is_empty() {
        let written = file.write_at(offset, buf).await?;
        if written == 0 {
            return Err(PagedbError::Io(std::io::Error::from(
                std::io::ErrorKind::WriteZero,
            )));
        }
        checked_transfer_progress(
            &mut offset,
            written,
            buf.len(),
            "write_at",
            "positional write offset",
        )?;
        buf = &buf[written..];
    }
    Ok(())
}

/// Run [`read_exact_at`]'s loop over a handle the caller only borrows.
///
/// A function taking `&F` would be `Send` only under `F: Sync`, which
/// `VfsFile` does not require and which would spread as a bound through every
/// segment reader. Expanding in place keeps the borrow inside the caller's own
/// future, so the rule stays in one place without costing a trait bound.
///
/// `$buf` must be a `&mut [u8]`; the result is a `Result<()>` to be `?`-ed.
macro_rules! read_exact_at_borrowed {
    ($file:expr, $offset:expr, $buf:expr $(,)?) => {{
        let mut offset: u64 = $offset;
        let mut remaining: &mut [u8] = $buf;
        loop {
            if remaining.is_empty() {
                break Ok(());
            }
            match $file.read_at(offset, remaining).await {
                Ok(read) => {
                    if let Err(error) =
                        $crate::vfs::checked_read_progress(&mut offset, read, remaining.len())
                    {
                        break Err(error);
                    }
                    remaining = remaining.split_at_mut(read).1;
                }
                Err(error) => break Err(error),
            }
        }
    }};
}
pub(crate) use read_exact_at_borrowed;

/// Shared progress rule for both directions: reject a count the caller never
/// asked for, then advance the offset without wrapping.
#[inline]
fn checked_transfer_progress(
    offset: &mut u64,
    transferred: usize,
    remaining: usize,
    operation: &'static str,
    offset_label: &'static str,
) -> Result<()> {
    if transferred > remaining {
        return Err(PagedbError::vfs_contract_violated(
            operation,
            "reported more bytes than the caller requested",
        ));
    }
    let transferred =
        u64::try_from(transferred).map_err(|_| PagedbError::arithmetic_overflow(offset_label))?;
    *offset = offset
        .checked_add(transferred)
        .ok_or_else(|| PagedbError::arithmetic_overflow(offset_label))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_short_read_advances_by_exactly_what_was_transferred() {
        let mut offset = 4096;
        checked_read_progress(&mut offset, 100, 4096).unwrap();
        assert_eq!(offset, 4196);
    }

    #[test]
    fn zero_progress_is_end_of_file_not_a_contract_violation() {
        let mut offset = 0;
        let err = checked_read_progress(&mut offset, 0, 4096).unwrap_err();
        assert!(
            matches!(err, PagedbError::Io(ref io) if io.kind() == std::io::ErrorKind::UnexpectedEof),
            "expected UnexpectedEof, got {err:?}"
        );
        assert_eq!(offset, 0, "a failed transfer must not advance the offset");
    }

    #[test]
    fn a_count_above_the_remaining_buffer_is_a_backend_contract_violation() {
        let mut offset = 0;
        let err = checked_read_progress(&mut offset, 4097, 4096).unwrap_err();
        assert!(
            matches!(
                err,
                PagedbError::VfsContractViolated {
                    operation: "read_at",
                    ..
                }
            ),
            "expected VfsContractViolated, got {err:?}"
        );
    }

    #[test]
    fn an_offset_that_would_wrap_is_reported_as_overflow() {
        let mut offset = u64::MAX;
        let err = checked_read_progress(&mut offset, 1, 4096).unwrap_err();
        assert!(
            matches!(err, PagedbError::ArithmeticOverflow { .. }),
            "expected ArithmeticOverflow, got {err:?}"
        );
    }
}
