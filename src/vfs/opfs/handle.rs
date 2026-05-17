//! `OpfsFile` — a `VfsFile` backed by an open OPFS sync-access handle.

#![cfg(all(target_arch = "wasm32", feature = "opfs"))]

use std::rc::Rc;

use gloo_worker::WorkerBridge;

use crate::Result;
use crate::errors::PagedbError;
use crate::vfs::traits::VfsFile;
use crate::vfs::types::{ReadReq, WriteReq};

use super::vfs_impl::BridgeRef;
use super::worker::{OpfsOp, OpfsRequest, OpfsResult};

/// A `VfsFile` handle for OPFS.
///
/// Holds the remote handle id (on the worker side) and a shared reference to
/// the worker bridge so it can issue synchronous-style async requests.
pub struct OpfsFile {
    pub(crate) handle_id: u32,
    pub(crate) bridge: BridgeRef,
    pub(crate) read_only: bool,
}

impl Drop for OpfsFile {
    fn drop(&mut self) {
        // Issue a fire-and-forget Close to the worker.  We cannot await here,
        // so we spawn it as a local future.
        let bridge = Rc::clone(&self.bridge);
        let handle_id = self.handle_id;
        wasm_bindgen_futures::spawn_local(async move {
            let b = bridge.borrow();
            // seq = 0 for fire-and-forget; we do not wait for a response.
            b.send(OpfsRequest {
                seq: 0,
                op: OpfsOp::Close { handle_id },
            });
        });
    }
}

impl VfsFile for OpfsFile {
    async fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let len = buf.len();
        let result = self
            .bridge
            .borrow()
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
            OpfsResult::Err { reason } => Err(map_worker_err(&reason)),
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
            .bridge
            .borrow()
            .dispatch(OpfsOp::Write {
                handle_id: self.handle_id,
                offset,
                data,
            })
            .await?;
        match result {
            OpfsResult::Ok => Ok(len),
            OpfsResult::Err { reason } => Err(map_worker_err(&reason)),
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
            .bridge
            .borrow()
            .dispatch(OpfsOp::Flush {
                handle_id: self.handle_id,
            })
            .await?;
        match result {
            OpfsResult::Ok => Ok(()),
            OpfsResult::Err { reason } => Err(map_worker_err(&reason)),
            _ => Err(PagedbError::Unsupported),
        }
    }

    async fn truncate(&mut self, len: u64) -> Result<()> {
        if self.read_only {
            return Err(PagedbError::ReadOnly);
        }
        let result = self
            .bridge
            .borrow()
            .dispatch(OpfsOp::Truncate {
                handle_id: self.handle_id,
                len,
            })
            .await?;
        match result {
            OpfsResult::Ok => Ok(()),
            OpfsResult::Err { reason } => Err(map_worker_err(&reason)),
            _ => Err(PagedbError::Unsupported),
        }
    }

    async fn len(&self) -> Result<u64> {
        let result = self
            .bridge
            .borrow()
            .dispatch(OpfsOp::GetSize {
                handle_id: self.handle_id,
            })
            .await?;
        match result {
            OpfsResult::Size { len } => Ok(len),
            OpfsResult::Err { reason } => Err(map_worker_err(&reason)),
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

pub(crate) fn map_worker_err(reason: &str) -> PagedbError {
    if reason.contains("not found") || reason.contains("NotFound") {
        PagedbError::Io(std::io::Error::from(std::io::ErrorKind::NotFound))
    } else if reason.contains("AlreadyExists") || reason.contains("already exists") {
        PagedbError::Io(std::io::Error::from(std::io::ErrorKind::AlreadyExists))
    } else if reason.contains("read-only") {
        PagedbError::ReadOnly
    } else {
        PagedbError::Io(std::io::Error::new(
            std::io::ErrorKind::Other,
            reason.to_string(),
        ))
    }
}
