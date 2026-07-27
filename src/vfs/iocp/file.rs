//! `IocpFile`: per-file I/O using overlapped `ReadFile` / `WriteFile` against
//! the shared IOCP.
//!
//! Nothing here runs on the async executor. Draining a completion packet is an
//! unbounded kernel wait, and `FlushFileBuffers` / `SetEndOfFile` / `metadata`
//! are blocking Win32 syscalls, so every operation hands a self-contained
//! closure to the blocking pool. The closure owns the file handle (through an
//! `Arc`), the transfer buffer, and the `OVERLAPPED` it submits, so a caller
//! that drops the future mid-flight cannot free memory the kernel is still
//! writing into. Each cycle holds the port mutex across submit + dequeue, so
//! the completion packet it drains is unambiguously its own.
#![allow(unsafe_code)]

use std::os::windows::io::AsRawHandle;
use std::sync::Arc;

use crate::Result;
use crate::errors::PagedbError;
use crate::vfs::blocking::offload;
use crate::vfs::traits::{
    OverlappedStart, VfsFile, checked_overlapped_read_start, checked_overlapped_start,
    checked_read_count, checked_readfile_len, checked_signed_file_len, checked_write_progress,
};
use crate::vfs::types::{ReadReq, WriteReq};

use super::port::{Port, PortInner};

use windows_sys::Win32::Foundation::{ERROR_HANDLE_EOF, ERROR_IO_PENDING, HANDLE};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_BEGIN, FlushFileBuffers, ReadFile, SetEndOfFile, SetFilePointerEx, WriteFile,
};
use windows_sys::Win32::System::IO::OVERLAPPED;

pub struct IocpFile {
    /// Shared so a blocking-pool cycle can own a reference to the handle for
    /// its whole duration, independently of when this `IocpFile` is dropped.
    file: Arc<std::fs::File>,
    writable: bool,
    /// Unique completion key for this file's association with the port. We
    /// don't currently disambiguate by key (the port mutex serialises every
    /// op, so any completion we dequeue under the lock is ours) but recording
    /// it preserves the option to relax serialisation later without re-
    /// associating handles.
    _key: usize,
    port: Arc<PortInner>,
}

impl IocpFile {
    pub(crate) fn new(
        file: std::fs::File,
        writable: bool,
        key: usize,
        port: Arc<PortInner>,
    ) -> Self {
        Self {
            file: Arc::new(file),
            writable,
            _key: key,
            port,
        }
    }

    /// The two owned handles a blocking-pool cycle needs. Both are cheap `Arc`
    /// clones, and both keep their target alive for as long as the cycle runs.
    fn shared(&self) -> (Arc<std::fs::File>, Port) {
        (
            Arc::clone(&self.file),
            Port {
                inner: Arc::clone(&self.port),
            },
        )
    }

    fn writefile_len(len: usize) -> Result<u32> {
        u32::try_from(len).map_err(|_| {
            PagedbError::Io(std::io::Error::other(
                "buffer too large for u32 in WriteFile",
            ))
        })
    }

    /// Submit one overlapped read or write at `offset`. The closure performs
    /// the `ReadFile` / `WriteFile` syscall against `&mut OVERLAPPED`. Caller
    /// must hold the port mutex.
    ///
    /// # Safety
    ///
    /// The buffer referenced by the closure must outlive this call. `op`
    /// must return `0` (failure) or non-zero (immediate completion); on
    /// `ERROR_IO_PENDING` we wait via `Port::dequeue`.
    unsafe fn submit_overlapped<F>(port: &Port, offset: u64, op: F) -> std::io::Result<u32>
    where
        F: FnOnce(&mut OVERLAPPED) -> i32,
    {
        // SAFETY: caller forwards the same safety contract as
        // `submit_overlapped_impl`.
        unsafe { Self::submit_overlapped_impl(port, offset, false, op) }
    }

    /// Submit one overlapped read at `offset`; EOF is reported as zero bytes.
    ///
    /// # Safety
    ///
    /// Same contract as [`Self::submit_overlapped`].
    unsafe fn submit_read_overlapped<F>(port: &Port, offset: u64, op: F) -> std::io::Result<u32>
    where
        F: FnOnce(&mut OVERLAPPED) -> i32,
    {
        // SAFETY: caller forwards the same safety contract as
        // `submit_overlapped_impl`.
        unsafe { Self::submit_overlapped_impl(port, offset, true, op) }
    }

    unsafe fn submit_overlapped_impl<F>(
        port: &Port,
        offset: u64,
        eof_is_empty_read: bool,
        op: F,
    ) -> std::io::Result<u32>
    where
        F: FnOnce(&mut OVERLAPPED) -> i32,
    {
        // SAFETY: zero-initialised OVERLAPPED is valid; we set the file
        // offset (Offset/OffsetHigh union members) explicitly.
        let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
        // Writing union fields doesn't require unsafe — we never read the
        // union back in a way that depends on the active variant.
        #[allow(clippy::cast_possible_truncation)]
        {
            overlapped.Anonymous.Anonymous.Offset = offset as u32;
            overlapped.Anonymous.Anonymous.OffsetHigh = (offset >> 32) as u32;
        }

        let rc = op(&mut overlapped);
        let err_code = if rc == 0 {
            // SAFETY: GetLastError immediately after a failed Win32 call is
            // the documented pattern.
            unsafe { windows_sys::Win32::Foundation::GetLastError() }
        } else {
            0
        };
        let start = if eof_is_empty_read {
            checked_overlapped_read_start(rc, err_code, ERROR_IO_PENDING, ERROR_HANDLE_EOF)
        } else {
            checked_overlapped_start(rc, err_code, ERROR_IO_PENDING)
        }
        .map_err(|error| match error {
            PagedbError::Io(io) => io,
            other => std::io::Error::other(other.to_string()),
        })?;
        if start == OverlappedStart::EmptyRead {
            return Ok(0);
        }

        // Associated handles queue a completion packet even when the
        // overlapped call succeeds immediately, so every non-EOF start must
        // drain its matching packet before the stack-allocated OVERLAPPED dies.
        // SAFETY: caller holds the port lock; `overlapped` lives on this
        // stack frame and is the only outstanding request. That frame belongs
        // to a blocking-pool thread which cannot unwind out from under the
        // kernel, because the wait is not an await point.
        let (bytes, _key, completed) = unsafe { port.dequeue() }.or_else(|error| {
            // ERROR_HANDLE_EOF on read is "read past EOF" — surface as
            // 0 bytes transferred, like POSIX read() at EOF.
            if error.raw_os_error() == Some(ERROR_HANDLE_EOF as i32) {
                Ok((0u32, 0usize, std::ptr::null_mut::<OVERLAPPED>()))
            } else {
                Err(error)
            }
        })?;
        let expected = (&raw mut overlapped).cast::<OVERLAPPED>();
        if !completed.is_null() && completed != expected {
            return Err(std::io::Error::other(
                "IOCP completion did not match the submitted OVERLAPPED",
            ));
        }
        Ok(bytes)
    }

    /// Run one positional read to completion. The caller must already hold the
    /// port lock, and must be running on a blocking-pool thread.
    fn read_locked(handle: HANDLE, port: &Port, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let len = checked_readfile_len(buf.len())?;
        let buf_ptr = buf.as_mut_ptr();
        // SAFETY: `buf` outlives this call, and `submit_read_overlapped` does
        // not return until the completion packet for this request has been
        // drained, so the kernel is done with the buffer either way.
        let bytes = unsafe {
            Self::submit_read_overlapped(port, offset, |ov| {
                ReadFile(handle, buf_ptr.cast(), len, std::ptr::null_mut(), ov)
            })
        }
        .map_err(PagedbError::Io)?;
        checked_read_count(bytes as usize, buf.len())
    }

    /// Run one positional write to completion. Same preconditions as
    /// [`Self::read_locked`]. Returns the raw completion count so the caller's
    /// progress rule, not this helper, decides what counts as progress.
    fn write_locked(handle: HANDLE, port: &Port, offset: u64, buf: &[u8]) -> Result<usize> {
        let len = Self::writefile_len(buf.len())?;
        let buf_ptr = buf.as_ptr();
        // SAFETY: as `read_locked` — the buffer outlives the drained completion.
        let bytes = unsafe {
            Self::submit_overlapped(port, offset, |ov| {
                WriteFile(handle, buf_ptr, len, std::ptr::null_mut(), ov)
            })
        }
        .map_err(PagedbError::Io)?;
        usize::try_from(bytes).map_err(|_| {
            PagedbError::Io(std::io::Error::other(
                "WriteFile reported byte count that does not fit in usize",
            ))
        })
    }
}

// SAFETY: every field is already `Send` — `Arc<std::fs::File>` and
// `Arc<PortInner>` are both shared owners of thread-safe kernel objects. The
// impl is spelled out rather than derived so the reasoning stays attached to
// the type: what crosses to the blocking pool is those `Arc`s, never the
// `IocpFile`, and the port mutex serialises every op regardless of which
// thread runs it.
unsafe impl Send for IocpFile {}

impl VfsFile for IocpFile {
    async fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let len = buf.len();
        // Reject an impossible length before allocating scratch for it.
        checked_readfile_len(len)?;
        let (file, port) = self.shared();
        let (scratch, read) = offload(move || {
            let handle = file.as_raw_handle() as HANDLE;
            let mut scratch = vec![0u8; len];
            // Held across submit + dequeue so the packet drained below is ours.
            let _guard = port.lock();
            let read = IocpFile::read_locked(handle, &port, offset, &mut scratch)?;
            Ok((scratch, read))
        })
        .await?;
        buf[..read].copy_from_slice(&scratch[..read]);
        Ok(read)
    }

    async fn read_at_vectored(&self, reqs: &mut [ReadReq<'_>]) -> Result<()> {
        if reqs.is_empty() {
            return Ok(());
        }
        // Validate every length before any I/O runs, so a deterministic input
        // error cannot leave a prefix of the batch applied.
        let mut plan: Vec<(u64, usize)> = Vec::with_capacity(reqs.len());
        for req in reqs.iter() {
            checked_readfile_len(req.buf.len())?;
            plan.push((req.offset, req.buf.len()));
        }
        let (file, port) = self.shared();
        // Win32 has no native scatter/gather equivalent for arbitrary offsets
        // (`ReadFileScatter` requires page-aligned same-file contiguous I/O).
        // Issue ops sequentially under one lock acquisition so the batch is
        // observed atomically with respect to other concurrent users of the
        // port.
        let completed = offload(move || {
            let handle = file.as_raw_handle() as HANDLE;
            let mut out: Vec<(Vec<u8>, usize)> = Vec::with_capacity(plan.len());
            let _guard = port.lock();
            for (offset, len) in plan {
                let mut scratch = vec![0u8; len];
                let read = IocpFile::read_locked(handle, &port, offset, &mut scratch)?;
                out.push((scratch, read));
            }
            Ok(out)
        })
        .await?;

        for (req, (scratch, read)) in reqs.iter_mut().zip(completed) {
            req.buf[..read].copy_from_slice(&scratch[..read]);
            // Zero tail past EOF — matches MemVfs / TokioVfs / Iouring.
            for b in &mut req.buf[read..] {
                *b = 0;
            }
        }
        Ok(())
    }

    async fn write_at(&mut self, offset: u64, buf: &[u8]) -> Result<usize> {
        if !self.writable {
            return Err(PagedbError::ReadOnly);
        }
        if buf.is_empty() {
            return Ok(0);
        }
        Self::writefile_len(buf.len())?;
        let (file, port) = self.shared();
        // The pool thread outlives this future, so it writes from its own copy
        // rather than from the caller's borrow.
        let data = buf.to_vec();
        offload(move || {
            let handle = file.as_raw_handle() as HANDLE;
            let _guard = port.lock();
            IocpFile::write_locked(handle, &port, offset, &data)
        })
        .await
    }

    async fn write_at_vectored(&mut self, reqs: &[WriteReq<'_>]) -> Result<()> {
        if !self.writable {
            return Err(PagedbError::ReadOnly);
        }
        if reqs.is_empty() {
            return Ok(());
        }
        let mut batch: Vec<(u64, Vec<u8>)> = Vec::with_capacity(reqs.len());
        for req in reqs {
            Self::writefile_len(req.buf.len())?;
            batch.push((req.offset, req.buf.to_vec()));
        }
        let (file, port) = self.shared();
        offload(move || {
            let handle = file.as_raw_handle() as HANDLE;
            let _guard = port.lock();
            for (start, data) in &batch {
                let mut offset = *start;
                let mut remaining = data.as_slice();
                while !remaining.is_empty() {
                    let written = IocpFile::write_locked(handle, &port, offset, remaining)?;
                    let consumed = checked_write_progress(&mut offset, written, remaining.len())?;
                    remaining = &remaining[consumed..];
                }
            }
            Ok(())
        })
        .await
    }

    async fn sync(&mut self) -> Result<()> {
        let file = Arc::clone(&self.file);
        offload(move || {
            let handle = file.as_raw_handle() as HANDLE;
            // SAFETY: the `Arc` keeps the handle valid for the whole call;
            // `FlushFileBuffers` is self-contained.
            let rc = unsafe { FlushFileBuffers(handle) };
            if rc == 0 {
                return Err(PagedbError::Io(std::io::Error::last_os_error()));
            }
            Ok(())
        })
        .await
    }

    async fn truncate(&mut self, len: u64) -> Result<()> {
        if !self.writable {
            return Err(PagedbError::ReadOnly);
        }
        // SetFilePointerEx then SetEndOfFile. We don't care about the file
        // pointer for subsequent I/O (all our ops are positional/overlapped),
        // so we just seek to `len` and set EOF there.
        let len = checked_signed_file_len(len, "SetFilePointerEx")?;
        let file = Arc::clone(&self.file);
        offload(move || {
            let handle = file.as_raw_handle() as HANDLE;
            // SAFETY: the `Arc` keeps the handle valid; the output ptr is null
            // because we don't need the new position back, and `len` was
            // validated before the syscall.
            let rc = unsafe { SetFilePointerEx(handle, len, std::ptr::null_mut(), FILE_BEGIN) };
            if rc == 0 {
                return Err(PagedbError::Io(std::io::Error::last_os_error()));
            }
            // SAFETY: `handle` is valid for the same reason.
            let rc = unsafe { SetEndOfFile(handle) };
            if rc == 0 {
                return Err(PagedbError::Io(std::io::Error::last_os_error()));
            }
            Ok(())
        })
        .await
    }

    async fn len(&self) -> Result<u64> {
        let file = Arc::clone(&self.file);
        offload(move || Ok(file.metadata().map_err(PagedbError::Io)?.len())).await
    }

    async fn is_empty(&self) -> Result<bool> {
        Ok(self.len().await? == 0)
    }

    fn supports_direct_io(&self) -> bool {
        // `FILE_FLAG_NO_BUFFERING` is not requested by this backend (it
        // requires sector-aligned buffers, which pagedb's pager does not
        // currently guarantee). Reports false to keep the pager on its
        // buffered path.
        false
    }
}
