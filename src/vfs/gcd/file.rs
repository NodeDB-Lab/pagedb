//! `GcdFile`: per-file I/O against a `DispatchIO` channel.
//!
//! The channel is created in `DISPATCH_IO_RANDOM` mode and owns a duplicated
//! file descriptor (so dispatch_io can asynchronously close its own copy when
//! the channel is released, independently of the `std::fs::File` we hold).
//! Reads and writes call `dispatch_io_read` / `dispatch_io_write` with block
//! handlers; the handlers accumulate chunks and, on `done`, send the result
//! through a `tokio::sync::oneshot`.
#![allow(unsafe_code)]

use std::ffi::c_void;
use std::os::unix::io::AsRawFd;
use std::sync::Arc;

use parking_lot::Mutex;

use block2::{Block, DynBlock, RcBlock};
use dispatch2::{DispatchData, DispatchIO, DispatchIOCloseFlags, DispatchQueue, DispatchRetained};

use crate::Result;
use crate::errors::PagedbError;
use crate::vfs::traits::VfsFile;
use crate::vfs::types::{ReadReq, WriteReq};

pub struct GcdFile {
    file: std::fs::File,
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
            file,
            writable,
            channel,
            queue,
        })
    }

    fn fd(&self) -> std::os::unix::io::RawFd {
        self.file.as_raw_fd()
    }
}

impl Drop for GcdFile {
    fn drop(&mut self) {
        // Close the channel cooperatively. Outstanding ops complete with
        // ECANCELED (the cleanup handler will then close the dup fd).
        self.channel.close(DispatchIOCloseFlags(0));
        // `self.file` drops here, closing our original fd.
    }
}

impl VfsFile for GcdFile {
    async fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let len = buf.len();
        let (tx, rx) = tokio::sync::oneshot::channel::<std::io::Result<Vec<u8>>>();
        let accum: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::with_capacity(len)));
        let sender = Arc::new(Mutex::new(Some(tx)));

        // block2 cannot encode `bool` or `*mut DispatchData` directly (the
        // dispatch_object! types don't implement `RefEncode`). We declare the
        // closure with ABI-compatible stand-ins — `u8` for bool and
        // `*mut c_void` for DispatchData — and transmute the resulting block
        // pointer to the dispatch_io_handler_t signature. dispatch2's own
        // `DispatchData::to_vec` uses the same workaround (see data.rs:114).
        let accum_for_block = Arc::clone(&accum);
        let sender_for_block = Arc::clone(&sender);
        let handler: RcBlock<dyn Fn(u8, *mut c_void, libc::c_int)> =
            RcBlock::new(move |done: u8, data: *mut c_void, error: libc::c_int| {
                if !data.is_null() {
                    let d: &DispatchData =
                        // SAFETY: dispatch guarantees `data` (when non-null)
                        // is a valid `DispatchData` retained for the
                        // handler's duration.
                        unsafe { &*data.cast::<DispatchData>() };
                    let bytes = d.to_vec();
                    accum_for_block.lock().extend_from_slice(&bytes);
                }
                if done != 0 {
                    let result = if error != 0 {
                        Err(std::io::Error::from_raw_os_error(error))
                    } else {
                        Ok(std::mem::take(&mut *accum_for_block.lock()))
                    };
                    if let Some(s) = sender_for_block.lock().take() {
                        let _ = s.send(result);
                    }
                }
            });

        // SAFETY: transmute is from the stand-in block signature to the
        // typedef declared by dispatch2 — the ABI is identical because `bool`
        // and `u8` share the same one-byte ABI, and a `*mut DispatchData` is
        // bit-identical to a `*mut c_void`.
        let handler_ptr: *mut DynBlock<dyn Fn(bool, *mut DispatchData, libc::c_int)> = unsafe {
            std::mem::transmute::<
                *mut Block<dyn Fn(u8, *mut c_void, libc::c_int)>,
                *mut DynBlock<dyn Fn(bool, *mut DispatchData, libc::c_int)>,
            >(RcBlock::as_ptr(&handler))
        };

        // SAFETY: the channel and queue are valid (held by `self`); the
        // handler block is retained by libdispatch on submission.
        unsafe {
            #[allow(clippy::cast_possible_wrap)]
            self.channel
                .read(offset as libc::off_t, len, &self.queue, handler_ptr);
        }
        // libdispatch has retained the block internally; we can drop our Rc.
        drop(handler);

        let data = rx
            .await
            .map_err(|_| PagedbError::Io(std::io::Error::other("dispatch_io read cancelled")))?
            .map_err(PagedbError::Io)?;
        let n = data.len().min(len);
        buf[..n].copy_from_slice(&data[..n]);
        Ok(n)
    }

    async fn read_at_vectored(&self, reqs: &mut [ReadReq<'_>]) -> Result<()> {
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
        let data = DispatchData::from_bytes(buf);
        let (tx, rx) = tokio::sync::oneshot::channel::<std::io::Result<()>>();
        let sender = Arc::new(Mutex::new(Some(tx)));

        // Same bool→u8 / *mut DispatchData→*mut c_void workaround as
        // `read_at`. See comments there.
        let sender_for_block = Arc::clone(&sender);
        let handler: RcBlock<dyn Fn(u8, *mut c_void, libc::c_int)> = RcBlock::new(
            move |done: u8, _remaining: *mut c_void, error: libc::c_int| {
                if done != 0 {
                    let result = if error != 0 {
                        Err(std::io::Error::from_raw_os_error(error))
                    } else {
                        Ok(())
                    };
                    if let Some(s) = sender_for_block.lock().take() {
                        let _ = s.send(result);
                    }
                }
            },
        );

        // SAFETY: ABI-compatible transmute; see `read_at`.
        let handler_ptr: *mut DynBlock<dyn Fn(bool, *mut DispatchData, libc::c_int)> = unsafe {
            std::mem::transmute::<
                *mut Block<dyn Fn(u8, *mut c_void, libc::c_int)>,
                *mut DynBlock<dyn Fn(bool, *mut DispatchData, libc::c_int)>,
            >(RcBlock::as_ptr(&handler))
        };

        // SAFETY: channel/queue/data all valid; libdispatch retains both the
        // data object and the handler block for the operation's duration.
        unsafe {
            #[allow(clippy::cast_possible_wrap)]
            self.channel
                .write(offset as libc::off_t, &data, &self.queue, handler_ptr);
        }
        drop(handler);
        drop(data);

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
            self.write_at(req.offset, req.buf).await?;
        }
        Ok(())
    }

    async fn sync(&mut self) -> Result<()> {
        // SAFETY: `fd()` returns the valid raw fd owned by `self.file`,
        // which is alive for the duration of this call. `fsync` is a
        // self-contained syscall with no aliasing requirements.
        let rc = unsafe { libc::fsync(self.fd()) };
        if rc != 0 {
            return Err(PagedbError::Io(std::io::Error::last_os_error()));
        }
        Ok(())
    }

    async fn truncate(&mut self, len: u64) -> Result<()> {
        if !self.writable {
            return Err(PagedbError::ReadOnly);
        }
        // SAFETY: `fd()` valid as above; `len` fits in `libc::off_t` on
        // 64-bit Apple targets (`off_t` is `i64` on macOS / iOS).
        #[allow(clippy::cast_possible_wrap)]
        let rc = unsafe { libc::ftruncate(self.fd(), len as libc::off_t) };
        if rc != 0 {
            return Err(PagedbError::Io(std::io::Error::last_os_error()));
        }
        Ok(())
    }

    async fn len(&self) -> Result<u64> {
        Ok(self.file.metadata().map_err(PagedbError::Io)?.len())
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
