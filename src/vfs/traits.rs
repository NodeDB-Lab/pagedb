//! `Vfs` and `VfsFile` trait definitions.

use std::future::Future;

use crate::Result;
use crate::errors::PagedbError;

use super::types::{OpenMode, ReadReq, WriteReq};

/// Abstract file-system surface used by the pager. Implementations provide
/// platform-appropriate I/O and advisory path locking.
///
/// Root-backed implementations treat paths as logical, root-relative names.
/// Leading separators are optional, while parent/current-directory and empty
/// interior components are rejected so no operation can escape the configured
/// root or create an aliased lock domain.
///
/// Each distinct logical path passed to a lock method is its own lock domain.
/// Equivalent spellings normalize to the same domain before lookup; distinct
/// canonical paths never conflict.
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

/// Per-file I/O surface. Vectored operations validate every request before
/// performing any I/O, so invalid deterministic input cannot leave a valid
/// prefix of the batch applied. A runtime device or filesystem failure part-way
/// through is still reported as it happens — the guarantee is about request
/// validation, not rollback.
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
        let consumed = checked_write_progress(&mut offset, written, buf.len())?;
        buf = &buf[consumed..];
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

/// Canonicalize a logical VFS path and reject components that could escape the
/// configured root.
pub(crate) fn canonical_native_path(path: &str) -> Result<String> {
    let trimmed = path.trim_matches(['/', '\\']);
    if trimmed.is_empty() {
        return Ok("/".to_string());
    }

    // Split first, then judge each component on its own. Parsing the path as a
    // whole is not enough: a platform prefix is only recognised in leading
    // position, so a drive letter deeper in the path (`a/C:/b`) parses as an
    // ordinary name — and `PathBuf::push` would later let it replace the root
    // outright. Every component has to survive parsing in isolation.
    let parts: Vec<_> = trimmed.split(['/', '\\']).collect();
    for part in &parts {
        if !is_plain_path_component(part) {
            return Err(invalid_native_path(path));
        }
    }

    Ok(format!("/{}", parts.join("/")))
}

/// Whether one path component is an ordinary name that can only ever extend a
/// path — never re-root it.
///
/// A colon is rejected on every target, not just the one that gives it meaning.
/// `a/C:/b` naming a file under the root on Linux and a different drive on
/// Windows would make the same logical path resolve to two different places,
/// which is exactly the portability the store is supposed to guarantee.
fn is_plain_path_component(part: &str) -> bool {
    use std::path::Component;
    if part.contains(':') {
        return false;
    }
    let mut components = std::path::Path::new(part).components();
    let Some(Component::Normal(name)) = components.next() else {
        return false;
    };
    components.next().is_none() && name == std::ffi::OsStr::new(part)
}

/// Resolve a canonical logical path beneath a native VFS root.
#[cfg(any(test, not(target_arch = "wasm32")))]
pub(crate) fn resolve_native_path(
    root: &std::path::Path,
    path: &str,
) -> Result<std::path::PathBuf> {
    let logical = canonical_native_path(path)?;
    let mut resolved = root.to_path_buf();
    for part in logical.trim_start_matches('/').split('/') {
        if !part.is_empty() {
            resolved.push(part);
        }
    }
    Ok(resolved)
}

fn invalid_native_path(path: &str) -> PagedbError {
    PagedbError::Io(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        format!("VFS path escapes root: {path:?}"),
    ))
}

/// Validate a buffer length before passing it to Win32 `ReadFile`.
#[cfg(any(test, target_os = "windows"))]
pub(crate) fn checked_readfile_len(len: usize) -> Result<u32> {
    u32::try_from(len).map_err(|_| {
        PagedbError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "buffer too large for u32 in ReadFile",
        ))
    })
}

/// Validate one reported read completion before using it as a slice boundary.
///
/// The offset-advancing form is [`checked_read_progress`]; this is for backends
/// that already know where the read landed and only need the count checked. A
/// short read is legal here — only a count the caller never asked for is not.
#[cfg(any(
    test,
    target_os = "windows",
    target_os = "linux",
    all(target_os = "android", not(target_arch = "arm")),
))]
pub(crate) fn checked_read_count(read: usize, requested: usize) -> Result<usize> {
    if read > requested {
        return Err(PagedbError::vfs_contract_violated(
            "read_at",
            "reported more bytes than the caller requested",
        ));
    }
    Ok(read)
}

/// Record one indexed batch completion, rejecting duplicate in-range keys.
#[cfg(any(
    test,
    target_os = "linux",
    all(target_os = "android", not(target_arch = "arm")),
))]
pub(crate) fn checked_indexed_completion(
    slots: &mut [Option<i32>],
    user_data: u64,
    result: i32,
) -> Result<bool> {
    let Ok(index) = usize::try_from(user_data) else {
        return Ok(false);
    };
    let Some(slot) = slots.get_mut(index) else {
        return Ok(false);
    };
    if slot.is_some() {
        return Err(PagedbError::Io(std::io::Error::other(
            "duplicate indexed completion",
        )));
    }
    *slot = Some(result);
    Ok(true)
}

/// Reject `io_uring`'s `offset == -1` sentinel for positioned I/O.
#[cfg(any(
    test,
    target_os = "linux",
    all(target_os = "android", not(target_arch = "arm")),
))]
pub(crate) fn checked_iouring_positioned_offset(offset: u64, len: usize) -> Result<()> {
    if len > 0 && offset == u64::MAX {
        return Err(PagedbError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "io_uring offset -1 uses the current file position",
        )));
    }
    Ok(())
}

/// Largest exactly representable integer in a JavaScript `number`.
#[cfg(any(test, all(target_arch = "wasm32", feature = "opfs")))]
pub(crate) const OPFS_MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

#[cfg(any(test, all(target_arch = "wasm32", feature = "opfs")))]
const OPFS_MAX_SAFE_INTEGER_F64: f64 = 9_007_199_254_740_991.0;

/// Validate an OPFS offset and length before crossing the JavaScript number
/// boundary.
#[cfg(any(test, all(target_arch = "wasm32", feature = "opfs")))]
pub(crate) fn checked_opfs_js_range(offset: u64, len: usize) -> Result<()> {
    let len = u64::try_from(len).map_err(|_| {
        PagedbError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "OPFS length does not fit u64",
        ))
    })?;
    let end = offset.checked_add(len).ok_or_else(|| {
        PagedbError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "OPFS offset range overflow",
        ))
    })?;
    if end > OPFS_MAX_SAFE_INTEGER {
        return Err(PagedbError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("offset {offset} + len {len} exceeds JS safe integer range"),
        )));
    }
    Ok(())
}

/// Validate a byte count returned through an OPFS JavaScript `number`.
#[cfg(any(test, all(target_arch = "wasm32", feature = "opfs")))]
pub(crate) fn checked_opfs_byte_count(
    kind: &'static str,
    n: f64,
    requested: usize,
) -> Result<usize> {
    if !n.is_finite() || n < 0.0 || n.fract() != 0.0 || n > OPFS_MAX_SAFE_INTEGER_F64 {
        return Err(PagedbError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("OPFS {kind} returned an invalid byte count"),
        )));
    }
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let count = n as u64;
    let requested = u64::try_from(requested).map_err(|_| {
        PagedbError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "OPFS request length does not fit u64",
        ))
    })?;
    if count > requested {
        return Err(PagedbError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("OPFS {kind} overreported bytes"),
        )));
    }
    usize::try_from(count).map_err(|_| {
        PagedbError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("OPFS {kind} byte count does not fit usize"),
        ))
    })
}

/// Validate a file size returned through an OPFS JavaScript `number`.
#[cfg(any(test, all(target_arch = "wasm32", feature = "opfs")))]
pub(crate) fn checked_opfs_file_size(size: f64) -> Result<u64> {
    if !size.is_finite() || size < 0.0 || size.fract() != 0.0 || size > OPFS_MAX_SAFE_INTEGER_F64 {
        return Err(PagedbError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "OPFS returned an invalid file size",
        )));
    }
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    Ok(size as u64)
}

/// Validate a `u64` file length before passing it to signed native syscalls.
#[cfg(any(
    test,
    target_os = "windows",
    target_os = "linux",
    all(target_os = "android", not(target_arch = "arm")),
    target_os = "macos",
    target_os = "ios",
))]
pub(crate) fn checked_signed_file_len(len: u64, syscall: &'static str) -> Result<i64> {
    i64::try_from(len).map_err(|_| {
        PagedbError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{syscall} length does not fit signed file offset"),
        ))
    })
}

/// Classified result of starting a Windows overlapped I/O request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(any(test, target_os = "windows"))]
pub(crate) enum OverlappedStart {
    CompletionQueued,
    EmptyRead,
}

/// Decide whether a Win32 overlapped I/O call produced a completion to drain.
#[cfg(any(test, target_os = "windows"))]
pub(crate) fn checked_overlapped_start(
    rc: i32,
    last_error: u32,
    error_io_pending: u32,
) -> Result<OverlappedStart> {
    if rc != 0 || last_error == error_io_pending {
        return Ok(OverlappedStart::CompletionQueued);
    }
    let code = i32::try_from(last_error).map_err(|_| {
        PagedbError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Win32 error code does not fit i32",
        ))
    })?;
    Err(PagedbError::Io(std::io::Error::from_raw_os_error(code)))
}

/// Decide whether a Win32 overlapped read produced data, EOF, or an error.
#[cfg(any(test, target_os = "windows"))]
pub(crate) fn checked_overlapped_read_start(
    rc: i32,
    last_error: u32,
    error_io_pending: u32,
    error_handle_eof: u32,
) -> Result<OverlappedStart> {
    if rc == 0 && last_error == error_handle_eof {
        return Ok(OverlappedStart::EmptyRead);
    }
    checked_overlapped_start(rc, last_error, error_io_pending)
}

/// Validate one reported write completion, advance the positioned offset, and
/// return how many bytes the caller may consume.
///
/// The mirror of [`checked_read_progress`], and the single write-side rule:
/// [`write_all_at`] and every backend that completes a short write use it, so
/// there is one definition of what progress a backend is allowed to claim.
#[inline]
pub(crate) fn checked_write_progress(
    offset: &mut u64,
    written: usize,
    remaining: usize,
) -> Result<usize> {
    if written == 0 {
        return Err(PagedbError::Io(std::io::Error::from(
            std::io::ErrorKind::WriteZero,
        )));
    }
    checked_transfer_progress(
        offset,
        written,
        remaining,
        "write_at",
        "positional write offset",
    )?;
    Ok(written)
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

    use std::sync::{Arc, Mutex};

    use super::{
        OverlappedStart, VfsFile, checked_indexed_completion, checked_iouring_positioned_offset,
        checked_opfs_byte_count, checked_opfs_file_size, checked_opfs_js_range,
        checked_overlapped_read_start, checked_overlapped_start, checked_read_count,
        checked_readfile_len, checked_signed_file_len, checked_write_progress, write_all_at,
    };
    use crate::vfs::types::{ReadReq, WriteReq};

    #[derive(Clone, Default)]
    struct ScriptedWriteFile {
        state: Arc<Mutex<ScriptedWriteState>>,
    }

    #[derive(Default)]
    struct ScriptedWriteState {
        completions: Vec<usize>,
        calls: Vec<(u64, usize)>,
    }

    impl ScriptedWriteFile {
        fn with_completions(completions: Vec<usize>) -> Self {
            Self {
                state: Arc::new(Mutex::new(ScriptedWriteState {
                    completions,
                    calls: Vec::new(),
                })),
            }
        }

        fn calls(&self) -> Vec<(u64, usize)> {
            self.state.lock().unwrap().calls.clone()
        }
    }

    impl VfsFile for ScriptedWriteFile {
        async fn read_at(&self, _offset: u64, _buf: &mut [u8]) -> crate::Result<usize> {
            unimplemented!("read_at is not used by write_all_at tests")
        }

        async fn read_at_vectored(&self, _reqs: &mut [ReadReq<'_>]) -> crate::Result<()> {
            unimplemented!("read_at_vectored is not used by write_all_at tests")
        }

        async fn write_at(&mut self, offset: u64, buf: &[u8]) -> crate::Result<usize> {
            let mut state = self.state.lock().unwrap();
            state.calls.push((offset, buf.len()));
            Ok(state.completions.remove(0))
        }

        async fn write_at_vectored(&mut self, _reqs: &[WriteReq<'_>]) -> crate::Result<()> {
            unimplemented!("write_at_vectored is not used by write_all_at tests")
        }

        async fn sync(&mut self) -> crate::Result<()> {
            Ok(())
        }

        async fn truncate(&mut self, _len: u64) -> crate::Result<()> {
            Ok(())
        }

        async fn len(&self) -> crate::Result<u64> {
            Ok(0)
        }

        async fn is_empty(&self) -> crate::Result<bool> {
            Ok(true)
        }

        fn supports_direct_io(&self) -> bool {
            false
        }
    }

    #[test]
    fn a_logical_path_normalizes_its_separators_and_leading_slash() {
        for spelling in ["/seg/abc", "seg/abc", "seg\\abc", "/seg/abc/"] {
            assert_eq!(canonical_native_path(spelling).unwrap(), "/seg/abc");
        }
        assert_eq!(canonical_native_path("").unwrap(), "/");
        assert_eq!(canonical_native_path("/").unwrap(), "/");
    }

    #[test]
    fn a_parent_or_current_directory_component_never_resolves() {
        for escape in ["../escaped", "a/../../escaped", "./a", "a//b", "a/./b"] {
            assert!(
                canonical_native_path(escape).is_err(),
                "{escape:?} must not canonicalize"
            );
        }
    }

    #[test]
    fn a_drive_letter_component_is_rejected_wherever_it_appears() {
        // Rejected on every target, not just the one that gives it meaning.
        // A platform prefix is only recognised in leading position, so a drive
        // letter deeper in the path parses as an ordinary name — and pushing it
        // would replace the root outright rather than extend it.
        for drive in ["C:", "a/C:/b", "C:/escaped", "a/C:"] {
            assert!(
                canonical_native_path(drive).is_err(),
                "{drive:?} must not canonicalize"
            );
        }
    }

    #[test]
    fn a_resolved_path_always_stays_under_its_root() {
        let root = std::path::Path::new("/srv/pagedb");
        assert_eq!(
            resolve_native_path(root, "seg/abc").unwrap(),
            root.join("seg").join("abc")
        );
        assert!(resolve_native_path(root, "../escaped").is_err());
        assert!(resolve_native_path(root, "a/C:/b").is_err());
    }

    #[test]
    fn readfile_len_accepts_u32_max() {
        assert_eq!(checked_readfile_len(u32::MAX as usize).unwrap(), u32::MAX);
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn readfile_len_rejects_above_u32_max() {
        let err = checked_readfile_len(u32::MAX as usize + 1).unwrap_err();
        assert!(matches!(err, crate::errors::PagedbError::Io(_)));
    }

    #[test]
    fn read_count_accepts_short_completion() {
        assert_eq!(checked_read_count(3, 10).unwrap(), 3);
    }

    #[test]
    fn read_count_rejects_overreported_completion() {
        let err = checked_read_count(11, 10).unwrap_err();
        assert!(
            matches!(
                err,
                crate::errors::PagedbError::VfsContractViolated {
                    operation: "read_at",
                    ..
                }
            ),
            "expected VfsContractViolated, got {err:?}"
        );
    }

    #[test]
    fn indexed_completion_records_unique_user_data() {
        let mut slots = vec![None, None];
        assert!(checked_indexed_completion(&mut slots, 1, -5).unwrap());
        assert_eq!(slots, vec![None, Some(-5)]);
    }

    #[test]
    fn indexed_completion_ignores_out_of_range_user_data() {
        let mut slots = vec![None, None];
        assert!(!checked_indexed_completion(&mut slots, 2, 9).unwrap());
        assert_eq!(slots, vec![None, None]);
    }

    #[test]
    fn indexed_completion_rejects_duplicate_user_data() {
        let mut slots = vec![None, None];
        assert!(checked_indexed_completion(&mut slots, 0, 7).unwrap());
        let err = checked_indexed_completion(&mut slots, 0, 9).unwrap_err();
        assert!(matches!(err, crate::errors::PagedbError::Io(_)));
        assert_eq!(slots, vec![Some(7), None]);
    }

    #[test]
    fn iouring_positioned_offset_rejects_u64_max_for_non_empty_io() {
        let err = checked_iouring_positioned_offset(u64::MAX, 1).unwrap_err();
        assert!(matches!(err, crate::errors::PagedbError::Io(_)));
    }

    #[test]
    fn iouring_positioned_offset_allows_u64_max_for_empty_io() {
        checked_iouring_positioned_offset(u64::MAX, 0).unwrap();
    }

    #[test]
    fn opfs_js_range_rejects_end_above_safe_integer() {
        let err = checked_opfs_js_range(9_007_199_254_740_991, 1).unwrap_err();
        assert!(matches!(err, crate::errors::PagedbError::Io(_)));
    }

    #[test]
    fn opfs_js_range_accepts_exact_safe_integer_end() {
        checked_opfs_js_range(9_007_199_254_740_990, 1).unwrap();
    }

    #[test]
    fn opfs_byte_count_rejects_nan() {
        let err = checked_opfs_byte_count("read", f64::NAN, 8).unwrap_err();
        assert!(matches!(err, crate::errors::PagedbError::Io(_)));
    }

    #[test]
    fn opfs_byte_count_rejects_fractional_count() {
        let err = checked_opfs_byte_count("read", 1.5, 8).unwrap_err();
        assert!(matches!(err, crate::errors::PagedbError::Io(_)));
    }

    #[test]
    fn opfs_byte_count_rejects_overreported_count() {
        let err = checked_opfs_byte_count("write", 9.0, 8).unwrap_err();
        assert!(matches!(err, crate::errors::PagedbError::Io(_)));
    }

    #[test]
    fn opfs_byte_count_accepts_exact_count() {
        assert_eq!(checked_opfs_byte_count("write", 8.0, 8).unwrap(), 8);
    }

    #[test]
    fn opfs_file_size_rejects_unsafe_integer() {
        let error = checked_opfs_file_size(9_007_199_254_740_992.0).unwrap_err();
        assert!(matches!(error, crate::errors::PagedbError::Io(_)));
    }

    #[test]
    fn signed_file_len_accepts_i64_max() {
        assert_eq!(
            checked_signed_file_len(i64::MAX as u64, "truncate").unwrap(),
            i64::MAX
        );
    }

    #[test]
    fn signed_file_len_rejects_above_i64_max() {
        let err = checked_signed_file_len(i64::MAX as u64 + 1, "truncate").unwrap_err();
        assert!(matches!(err, crate::errors::PagedbError::Io(_)));
    }

    #[test]
    fn overlapped_start_treats_immediate_success_as_queued_completion() {
        assert_eq!(
            checked_overlapped_start(1, 0, 997).unwrap(),
            OverlappedStart::CompletionQueued
        );
    }

    #[test]
    fn overlapped_start_treats_pending_as_queued_completion() {
        assert_eq!(
            checked_overlapped_start(0, 997, 997).unwrap(),
            OverlappedStart::CompletionQueued
        );
    }

    #[test]
    fn overlapped_start_rejects_immediate_error_without_completion() {
        let err = checked_overlapped_start(0, 5, 997).unwrap_err();
        assert!(matches!(err, crate::errors::PagedbError::Io(_)));
    }

    #[test]
    fn overlapped_read_start_maps_immediate_eof_to_empty_read() {
        assert_eq!(
            checked_overlapped_read_start(0, 38, 997, 38).unwrap(),
            OverlappedStart::EmptyRead
        );
    }

    #[test]
    fn write_progress_advances_offset_for_short_write() {
        let mut offset = 7;
        assert_eq!(checked_write_progress(&mut offset, 3, 10).unwrap(), 3);
        assert_eq!(offset, 10);
    }

    #[test]
    fn write_progress_rejects_zero_for_non_empty_write() {
        let mut offset = 7;
        let err = checked_write_progress(&mut offset, 0, 10).unwrap_err();
        assert!(matches!(err, crate::errors::PagedbError::Io(_)));
        assert_eq!(offset, 7, "failed progress must not advance offset");
    }

    #[test]
    fn write_progress_rejects_overreported_count() {
        let mut offset = 7;
        let err = checked_write_progress(&mut offset, 11, 10).unwrap_err();
        assert!(
            matches!(
                err,
                crate::errors::PagedbError::VfsContractViolated {
                    operation: "write_at",
                    ..
                }
            ),
            "expected VfsContractViolated, got {err:?}"
        );
        assert_eq!(offset, 7, "failed progress must not advance offset");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn write_all_at_returns_after_one_full_write() {
        let mut file = ScriptedWriteFile::with_completions(vec![4]);
        write_all_at(&mut file, 11, b"page").await.unwrap();
        assert_eq!(file.calls(), vec![(11, 4)]);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn write_all_at_retries_after_short_write() {
        let mut file = ScriptedWriteFile::with_completions(vec![2, 2]);
        write_all_at(&mut file, 11, b"page").await.unwrap();
        assert_eq!(file.calls(), vec![(11, 4), (13, 2)]);
    }
}
