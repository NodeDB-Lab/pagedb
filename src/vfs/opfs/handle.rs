//! `OpfsFile` — a `VfsFile` backed by an open OPFS sync-access handle on the
//! worker side.

#![cfg(all(target_arch = "wasm32", feature = "opfs"))]
// The unsafe Send impl is required to satisfy `VfsFile: Send` on wasm32.
// Safety justification is in the impl block below.
#![allow(unsafe_code)]

use std::sync::Arc;

use crate::Result;
use crate::errors::PagedbError;
use crate::vfs::traits::VfsFile;
use crate::vfs::types::{ReadReq, WriteReq};

use super::protocol::{ErrKind, OpfsOp, OpfsResult};
use super::vfs_impl::OpfsVfs;

/// A `VfsFile` handle for OPFS.
///
/// Holds the remote handle id (on the worker side) and a reference to the
/// `OpfsVfs` so it can dispatch requests.
pub struct OpfsFile {
    pub(crate) handle_id: u32,
    pub(crate) vfs: Arc<OpfsVfs>,
    pub(crate) read_only: bool,
}

// SAFETY: wasm32 is single-threaded by browser spec. The Web Worker is bound
// to its spawning thread and all access to OpfsFile happens on that thread.
// send_wrapper::SendWrapper enforces this at runtime by panicking on
// cross-thread access.
unsafe impl Send for OpfsFile {}

impl Drop for OpfsFile {
    fn drop(&mut self) {
        // Issue a fire-and-forget Close to the worker. We cannot await here,
        // so we spawn a local future.
        let vfs = Arc::clone(&self.vfs);
        let handle_id = self.handle_id;
        wasm_bindgen_futures::spawn_local(async move {
            // Ignore errors on close (fire-and-forget).
            let _ = vfs.dispatch(OpfsOp::Close { handle_id }).await;
        });
    }
}

impl VfsFile for OpfsFile {
    async fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let len = buf.len();
        let result = self
            .vfs
            .dispatch(OpfsOp::Read {
                handle_id: self.handle_id,
                offset,
                len,
            })
            .await?;
        match result {
            OpfsResult::Data { bytes } => {
                let n = bytes.len().min(buf.len());
                buf[..n].copy_from_slice(&bytes[..n]);
                Ok(n)
            }
            OpfsResult::Err { reason, kind } => Err(map_err(&reason, kind)),
            _ => Err(PagedbError::Unsupported),
        }
    }

    async fn read_at_vectored(&self, reqs: &mut [ReadReq<'_>]) -> Result<()> {
        for req in reqs.iter_mut() {
            let n = self.read_at(req.offset, req.buf).await?;
            // Zero-fill past the returned bytes (all-or-nothing contract).
            for b in &mut req.buf[n..] {
                *b = 0;
            }
        }
        Ok(())
    }

    async fn write_at(&mut self, offset: u64, buf: &[u8]) -> Result<usize> {
        if self.read_only {
            return Err(PagedbError::ReadOnly);
        }
        let data = buf.to_vec();
        let len = data.len();
        let result = self
            .vfs
            .dispatch(OpfsOp::Write {
                handle_id: self.handle_id,
                offset,
                data,
            })
            .await?;
        match result {
            OpfsResult::Ok => Ok(len),
            OpfsResult::Err { reason, kind } => Err(map_err(&reason, kind)),
            _ => Err(PagedbError::Unsupported),
        }
    }

    async fn write_at_vectored(&mut self, reqs: &[WriteReq<'_>]) -> Result<()> {
        if self.read_only {
            return Err(PagedbError::ReadOnly);
        }
        for req in reqs {
            self.write_at(req.offset, req.buf).await?;
        }
        Ok(())
    }

    async fn sync(&mut self) -> Result<()> {
        let result = self
            .vfs
            .dispatch(OpfsOp::Flush {
                handle_id: self.handle_id,
            })
            .await?;
        match result {
            OpfsResult::Ok => Ok(()),
            OpfsResult::Err { reason, kind } => Err(map_err(&reason, kind)),
            _ => Err(PagedbError::Unsupported),
        }
    }

    async fn truncate(&mut self, len: u64) -> Result<()> {
        if self.read_only {
            return Err(PagedbError::ReadOnly);
        }
        let result = self
            .vfs
            .dispatch(OpfsOp::Truncate {
                handle_id: self.handle_id,
                len,
            })
            .await?;
        match result {
            OpfsResult::Ok => Ok(()),
            OpfsResult::Err { reason, kind } => Err(map_err(&reason, kind)),
            _ => Err(PagedbError::Unsupported),
        }
    }

    async fn len(&self) -> Result<u64> {
        let result = self
            .vfs
            .dispatch(OpfsOp::GetSize {
                handle_id: self.handle_id,
            })
            .await?;
        match result {
            OpfsResult::Size { len } => Ok(len),
            OpfsResult::Err { reason, kind } => Err(map_err(&reason, kind)),
            _ => Err(PagedbError::Unsupported),
        }
    }

    async fn is_empty(&self) -> Result<bool> {
        Ok(self.len().await? == 0)
    }

    fn supports_direct_io(&self) -> bool {
        false
    }
}

/// Map a worker error to a `PagedbError` using the structured `ErrKind`.
pub(crate) fn map_err(reason: &str, kind: ErrKind) -> PagedbError {
    match kind {
        ErrKind::NotFound => PagedbError::Io(std::io::Error::from(std::io::ErrorKind::NotFound)),
        ErrKind::AlreadyExists => {
            PagedbError::Io(std::io::Error::from(std::io::ErrorKind::AlreadyExists))
        }
        ErrKind::PermissionDenied => PagedbError::ReadOnly,
        ErrKind::Io | ErrKind::Other => PagedbError::Io(std::io::Error::other(reason.to_string())),
    }
}
