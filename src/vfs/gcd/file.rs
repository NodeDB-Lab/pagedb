//! `GcdFile`: per-file I/O against a `DispatchIO` channel.
//!
//! The channel is created in `DISPATCH_IO_RANDOM` mode and owns a duplicated
//! file descriptor (so `dispatch_io` can asynchronously close its own copy when
//! the channel is released, independently of the `std::fs::File` we hold).
//! Reads and writes call `dispatch_io_read` / `dispatch_io_write` with block
//! handlers; the handlers accumulate chunks and, on `done`, send the result
//! through a `tokio::sync::oneshot`. Submission returns immediately, so the
//! read/write paths never park a thread — the only wait is on the oneshot.
//!
//! `fsync`, `ftruncate` and `metadata` have no `dispatch_io` equivalent and do
//! park the caller, so those run on the blocking pool instead.
#![allow(unsafe_code)]

use std::ffi::c_void;
use std::os::unix::io::AsRawFd;
use std::sync::Arc;

use parking_lot::Mutex;

use block2::{DynBlock, RcBlock};
use dispatch2::{DispatchData, DispatchIO, DispatchIOCloseFlags, DispatchQueue, DispatchRetained};

use crate::Result;
use crate::errors::PagedbError;
use crate::vfs::blocking::offload;
use crate::vfs::traits::{VfsFile, checked_signed_file_len};
use crate::vfs::types::{ReadReq, WriteReq};

pub struct GcdFile {
    /// Shared so a blocking-pool call can own a reference to the descriptor
    /// for its whole duration, independently of when this `GcdFile` drops.
    file: Arc<std::fs::File>,
    writable: bool,
    channel: DispatchRetained<DispatchIO>,
    queue: DispatchRetained<DispatchQueue>,
}

impl GcdFile {
    pub(crate) fn new(
        file: std::fs::File,
        writable: bool,
        queue: DispatchRetained<DispatchQueue>,
    ) -> Result<Self> {
        // Duplicate the fd for dispatch_io. The kernel keeps the underlying
        // open file description alive as long as either fd is open; dispatch
        // will close its dup when the channel is released via the cleanup
        // handler. Our `std::fs::File` owns the original.
        // SAFETY: `file.as_raw_fd()` returns a valid open fd; `libc::dup`
        // returns -1 on failure (handled below) and otherwise a fresh fd.
        let dup_fd = unsafe { libc::dup(file.as_raw_fd()) };
        if dup_fd == -1 {
            return Err(PagedbError::Io(std::io::Error::last_os_error()));
        }

        // The cleanup handler is invoked by libdispatch when the channel is
        // fully released. It must close the dup'd fd (dispatch_io took
        // ownership). The block is retained by libdispatch internally; we do
        // not need to keep an Rc on the Rust side.
        let cleanup_block: RcBlock<dyn Fn(libc::c_int)> = RcBlock::new(move |_err: libc::c_int| {
            // SAFETY: dispatch_io has stopped using the fd by the time
            // the cleanup handler fires; closing it once is correct.
            unsafe {
                libc::close(dup_fd);
            }
        });

        // SAFETY: `dup_fd` is a valid fd we just acquired; queue is a valid
        // retained `DispatchQueue`; the cleanup block lives as long as the
        // channel needs it (libdispatch retains it).
        let channel = unsafe {
            DispatchIO::new(
                dispatch2::DispatchIOStreamType::DISPATCH_IO_RANDOM,
                dup_fd,
                &queue,
                &cleanup_block,
            )
        };

        Ok(Self {
            file: Arc::new(file),
            writable,
            channel,
            queue,
        })
    }

    fn checked_dispatch_offset(offset: u64, len: usize) -> Result<libc::off_t> {
        let last = if len > 0 {
            let last_delta = u64::try_from(len - 1).map_err(|_| {
                PagedbError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "buffer length does not fit in u64",
                ))
            })?;
            offset.checked_add(last_delta).ok_or_else(|| {
                PagedbError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "dispatch_io offset range overflow",
                ))
            })?
        } else {
            offset
        };
        libc::off_t::try_from(last).map_err(|_| {
            PagedbError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "dispatch_io offset range does not fit into libc::off_t",
            ))
        })?;
        offset.try_into().map_err(|_| {
            PagedbError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "dispatch_io offset does not fit into libc::off_t",
            ))
        })
    }
}

impl Drop for GcdFile {
    fn drop(&mut self) {
        // Close the channel cooperatively. Outstanding ops complete with
        // ECANCELED (the cleanup handler will then close the dup fd).
        self.channel.close(DispatchIOCloseFlags(0));
        // `self.file` drops here. A blocking-pool call still holding its own
        // `Arc` keeps the original fd open until it finishes, which is exactly
        // the guarantee that lets those calls outlive a cancelled future.
    }
}

/// Submit a `dispatch_io` read and return immediately.
///
/// `dispatch_io_read` enqueues the request and returns without waiting, so this
/// is not a blocking call despite being a plain `fn`: the only wait is the
/// caller's `await` on the oneshot the handler completes.
///
/// Kept synchronous on
/// purpose: the handler `RcBlock` and the raw block pointer derived from it are
/// `!Send`, so they must never be live across an await point in the calling
/// future (`VfsFile::read_at` must return a `Send` future). The handler
/// accumulates chunks and, on completion, sends the result through `tx`.
fn submit_read(
    channel: &DispatchIO,
    queue: &DispatchQueue,
    offset: libc::off_t,
    len: usize,
    tx: tokio::sync::oneshot::Sender<std::io::Result<Vec<u8>>>,
) {
    let accum: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::with_capacity(len)));
    let sender = Arc::new(Mutex::new(Some(tx)));

    // block2 cannot encode `bool` or `*mut DispatchData` directly (the
    // dispatch_object! types don't implement `RefEncode`). We declare the
    // closure with ABI-compatible stand-ins — `u8` for bool and `*mut c_void`
    // for DispatchData — and transmute the resulting block pointer to the
    // dispatch_io_handler_t signature. dispatch2's own `DispatchData::to_vec`
    // uses the same workaround (see data.rs:114).
    let handler: RcBlock<dyn Fn(u8, *mut c_void, libc::c_int)> =
        RcBlock::new(move |done: u8, data: *mut c_void, error: libc::c_int| {
            if !data.is_null() {
                let d: &DispatchData =
                    // SAFETY: dispatch guarantees `data` (when non-null) is a
                    // valid `DispatchData` retained for the handler's duration.
                    unsafe { &*data.cast::<DispatchData>() };
                let bytes = d.to_vec();
                accum.lock().extend_from_slice(&bytes);
            }
            if done != 0 {
                let result = if error != 0 {
                    Err(std::io::Error::from_raw_os_error(error))
                } else {
                    Ok(std::mem::take(&mut *accum.lock()))
                };
                if let Some(s) = sender.lock().take() {
                    let _ = s.send(result);
                }
            }
        });

    // SAFETY: ABI-compatible pointer cast to the typedef declared by dispatch2.
    // `bool` and `u8` are one byte, while both data arguments are pointers.
    let handler_ptr: *mut DynBlock<dyn Fn(bool, *mut DispatchData, libc::c_int)> =
        RcBlock::as_ptr(&handler).cast::<DynBlock<dyn Fn(bool, *mut DispatchData, libc::c_int)>>();

    // SAFETY: channel and queue are valid (owned by the caller's `GcdFile`);
    // the handler block is retained by libdispatch on submission.
    unsafe {
        channel.read(offset, len, queue, handler_ptr);
    }
    // libdispatch has retained the block internally; we can drop our Rc.
    drop(handler);
}

/// Submit a `dispatch_io` write and return immediately. Non-blocking and
/// synchronous for the same reasons as [`submit_read`]: `dispatch_io_write`
/// enqueues without waiting, and the handler block, its raw pointer, and the
/// `DispatchData` are all `!Send` and must not cross an await point.
fn submit_write(
    channel: &DispatchIO,
    queue: &DispatchQueue,
    offset: libc::off_t,
    buf: &[u8],
    tx: tokio::sync::oneshot::Sender<std::io::Result<()>>,
) {
    let data = DispatchData::from_bytes(buf);
    let sender = Arc::new(Mutex::new(Some(tx)));

    // Same bool→u8 / *mut DispatchData→*mut c_void workaround as `submit_read`.
    let handler: RcBlock<dyn Fn(u8, *mut c_void, libc::c_int)> = RcBlock::new(
        move |done: u8, _remaining: *mut c_void, error: libc::c_int| {
            if done != 0 {
                let result = if error != 0 {
                    Err(std::io::Error::from_raw_os_error(error))
                } else {
                    Ok(())
                };
                if let Some(s) = sender.lock().take() {
                    let _ = s.send(result);
                }
            }
        },
    );

    // SAFETY: ABI-compatible pointer cast; see `submit_read`.
    let handler_ptr: *mut DynBlock<dyn Fn(bool, *mut DispatchData, libc::c_int)> =
        RcBlock::as_ptr(&handler).cast::<DynBlock<dyn Fn(bool, *mut DispatchData, libc::c_int)>>();

    // SAFETY: channel/queue/data all valid; libdispatch retains both the data
    // object and the handler block for the operation's duration.
    unsafe {
        channel.write(offset, &data, queue, handler_ptr);
    }
    drop(handler);
    drop(data);
}

impl VfsFile for GcdFile {
    async fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let len = buf.len();
        let offset = Self::checked_dispatch_offset(offset, len)?;
        let (tx, rx) = tokio::sync::oneshot::channel::<std::io::Result<Vec<u8>>>();
        // The handler block and its raw block pointer are `!Send`; submitting
        // from a synchronous helper keeps them out of this future's state
        // machine, so the future stays `Send` as `VfsFile` requires. Once
        // submitted, libdispatch owns the operation and reports back through the
        // oneshot, which is all we await here.
        submit_read(&self.channel, &self.queue, offset, len, tx);

        let data = rx
            .await
            .map_err(|_| PagedbError::Io(std::io::Error::other("dispatch_io read cancelled")))?
            .map_err(PagedbError::Io)?;
        let n = data.len().min(len);
        buf[..n].copy_from_slice(&data[..n]);
        Ok(n)
    }

    async fn read_at_vectored(&self, reqs: &mut [ReadReq<'_>]) -> Result<()> {
        for req in reqs.iter() {
            Self::checked_dispatch_offset(req.offset, req.buf.len())?;
        }

        // dispatch_io operations are intrinsically sequential per channel
        // (the channel serialises ops in submission order); issuing them one
        // at a time matches that and keeps the bridge simple.
        for req in reqs.iter_mut() {
            let n = self.read_at(req.offset, req.buf).await?;
            for b in &mut req.buf[n..] {
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
        let len = buf.len();
        let offset = Self::checked_dispatch_offset(offset, len)?;
        let (tx, rx) = tokio::sync::oneshot::channel::<std::io::Result<()>>();
        // `!Send` handler/data confined to a synchronous helper; see `read_at`.
        submit_write(&self.channel, &self.queue, offset, buf, tx);

        rx.await
            .map_err(|_| PagedbError::Io(std::io::Error::other("dispatch_io write cancelled")))?
            .map_err(PagedbError::Io)?;
        Ok(len)
    }

    async fn write_at_vectored(&mut self, reqs: &[WriteReq<'_>]) -> Result<()> {
        if !self.writable {
            return Err(PagedbError::ReadOnly);
        }
        for req in reqs {
            Self::checked_dispatch_offset(req.offset, req.buf.len())?;
        }
        for req in reqs {
            self.write_at(req.offset, req.buf).await?;
        }
        Ok(())
    }

    async fn sync(&mut self) -> Result<()> {
        // `fsync` waits on the device — it can outlast a whole commit, so it
        // never runs on the executor.
        let file = Arc::clone(&self.file);
        offload(move || {
            // SAFETY: the `Arc` keeps the fd open for the whole call, and
            // `fsync` is a self-contained syscall with no aliasing needs.
            let rc = unsafe { libc::fsync(file.as_raw_fd()) };
            if rc != 0 {
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
        let len = checked_signed_file_len(len, "ftruncate")?;
        let file = Arc::clone(&self.file);
        offload(move || {
            // SAFETY: the `Arc` keeps the fd valid, and `len` was checked to
            // fit the signed native file-offset type before the syscall.
            let rc = unsafe { libc::ftruncate(file.as_raw_fd(), len) };
            if rc != 0 {
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
        // The pager does not request `F_NOCACHE` on Apple platforms today;
        // report false to keep it on the buffered path.
        false
    }
}
