//! `IocpFile`: per-file I/O using overlapped `ReadFile` / `WriteFile` against
//! the shared IOCP. Each op holds the port mutex across submit + dequeue so
//! the returned completion packet is unambiguously ours. `FlushFileBuffers`
//! and `SetEndOfFile` are synchronous Win32 syscalls — no IOCP involvement.
#![allow(unsafe_code)]

use std::os::windows::io::AsRawHandle;
use std::sync::Arc;

use crate::Result;
use crate::errors::PagedbError;
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
    file: std::fs::File,
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
            file,
            writable,
            _key: key,
            port,
        }
    }

    fn handle(&self) -> HANDLE {
        self.file.as_raw_handle() as HANDLE
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
        // stack frame and is the only outstanding request.
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
}

// SAFETY: `std::fs::File` is `Send`; the `Arc<PortInner>` is shared via
// `Arc`. We never share the `IocpFile` itself across threads concurrently —
// the `VfsFile` trait contract takes `&self`/`&mut self`, and the port mutex
// serialises every op.
unsafe impl Send for IocpFile {}

impl VfsFile for IocpFile {
    async fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let handle = self.handle();
        let len = checked_readfile_len(buf.len())?;
        let port = Port {
            inner: Arc::clone(&self.port),
        };
        let _guard = port.lock();
        let buf_ptr = buf.as_mut_ptr();
        // SAFETY: `buf` slice outlives this fn frame; the closure is invoked
        // synchronously before `submit_overlapped` returns.
        let bytes = unsafe {
            IocpFile::submit_read_overlapped(&port, offset, |ov| {
                ReadFile(handle, buf_ptr.cast(), len, std::ptr::null_mut(), ov)
            })
        }
        .map_err(PagedbError::Io)?;
        checked_read_count(bytes as usize, buf.len())
    }

    async fn read_at_vectored(&self, reqs: &mut [ReadReq<'_>]) -> Result<()> {
        if reqs.is_empty() {
            return Ok(());
        }
        // Win32 has no native scatter/gather equivalent for arbitrary offsets
        // (`ReadFileScatter` requires page-aligned same-file contiguous I/O).
        // Issue ops sequentially under one lock acquisition so the batch is
        // observed atomically with respect to other concurrent users of the
        // port.
        let lengths: Vec<u32> = reqs
            .iter()
            .map(|req| checked_readfile_len(req.buf.len()))
            .collect::<Result<_>>()?;
        let handle = self.handle();
        let port = Port {
            inner: Arc::clone(&self.port),
        };
        let _guard = port.lock();
        for (req, len) in reqs.iter_mut().zip(lengths) {
            let buf_ptr = req.buf.as_mut_ptr();
            // SAFETY: `req.buf` outlives this frame; closure is synchronous
            // within `submit_overlapped`.
            let bytes = unsafe {
                IocpFile::submit_read_overlapped(&port, req.offset, |ov| {
                    ReadFile(handle, buf_ptr.cast(), len, std::ptr::null_mut(), ov)
                })
            }
            .map_err(PagedbError::Io)? as usize;
            let bytes = checked_read_count(bytes, req.buf.len())?;
            // Zero tail past EOF — matches MemVfs / TokioVfs / Iouring.
            for b in &mut req.buf[bytes..] {
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
        let handle = self.handle();
        let len = Self::writefile_len(buf.len())?;
        let port = Port {
            inner: Arc::clone(&self.port),
        };
        let _guard = port.lock();
        let buf_ptr = buf.as_ptr();
        // SAFETY: `buf` slice outlives this frame; closure runs synchronously.
        let bytes = unsafe {
            IocpFile::submit_overlapped(&port, offset, |ov| {
                WriteFile(handle, buf_ptr, len, std::ptr::null_mut(), ov)
            })
        }
        .map_err(PagedbError::Io)?;
        Ok(bytes as usize)
    }

    async fn write_at_vectored(&mut self, reqs: &[WriteReq<'_>]) -> Result<()> {
        if !self.writable {
            return Err(PagedbError::ReadOnly);
        }
        if reqs.is_empty() {
            return Ok(());
        }
        for req in reqs {
            Self::writefile_len(req.buf.len())?;
        }
        let handle = self.handle();
        let port = Port {
            inner: Arc::clone(&self.port),
        };
        let _guard = port.lock();
        for req in reqs {
            let mut offset = req.offset;
            let mut remaining = req.buf;
            while !remaining.is_empty() {
                let len = Self::writefile_len(remaining.len())?;
                let buf_ptr = remaining.as_ptr();
                // SAFETY: `remaining` is a subslice of `req.buf` and outlives
                // this synchronous submission/completion wait.
                let written = unsafe {
                    IocpFile::submit_overlapped(&port, offset, |ov| {
                        WriteFile(handle, buf_ptr, len, std::ptr::null_mut(), ov)
                    })
                }
                .map_err(PagedbError::Io)?;
                let written = usize::try_from(written).map_err(|_| {
                    PagedbError::Io(std::io::Error::other(
                        "WriteFile reported byte count that does not fit in usize",
                    ))
                })?;
                let consumed = checked_write_progress(&mut offset, written, remaining.len())?;
                remaining = &remaining[consumed..];
            }
        }
        Ok(())
    }

    async fn sync(&mut self) -> Result<()> {
        let handle = self.handle();
        // SAFETY: `handle` is valid; `FlushFileBuffers` is synchronous and
        // self-contained.
        let rc = unsafe { FlushFileBuffers(handle) };
        if rc == 0 {
            return Err(PagedbError::Io(std::io::Error::last_os_error()));
        }
        Ok(())
    }

    async fn truncate(&mut self, len: u64) -> Result<()> {
        if !self.writable {
            return Err(PagedbError::ReadOnly);
        }
        let handle = self.handle();
        // SetFilePointerEx then SetEndOfFile. We don't care about the file
        // pointer for subsequent I/O (all our ops are positional/overlapped),
        // so we just seek to `len` and set EOF there.
        let len = checked_signed_file_len(len, "SetFilePointerEx")?;
        // SAFETY: `handle` is valid; output ptr is null because we don't need
        // the new position back. `len` was validated before the syscall.
        let rc = unsafe { SetFilePointerEx(handle, len, std::ptr::null_mut(), FILE_BEGIN) };
        if rc == 0 {
            return Err(PagedbError::Io(std::io::Error::last_os_error()));
        }
        // SAFETY: `handle` is valid.
        let rc = unsafe { SetEndOfFile(handle) };
        if rc == 0 {
            return Err(PagedbError::Io(std::io::Error::last_os_error()));
        }
        Ok(())
    }

    async fn len(&self) -> Result<u64> {
        let meta = self.file.metadata().map_err(PagedbError::Io)?;
        Ok(meta.len())
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
