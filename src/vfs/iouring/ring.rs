//! Shared `io_uring` instance. One ring is held per `IouringVfs`. All callers
//! acquire a `parking_lot::Mutex<IoUring>` lock, push SQE(s), call
//! `submit_and_wait`, and drain matching CQEs before releasing the lock.
//! This is intentionally simple: no background poller, no `spawn_blocking`.

use std::sync::Arc;

use io_uring::IoUring;
use parking_lot::Mutex;

use crate::Result;
use crate::errors::PagedbError;

/// Default submission queue depth. Must be a power of two. Sized large
/// enough to absorb a full B+ tree `flush` (thousands of dirty pages in
/// bulk-load workloads) in one batch without exhausting the queue.
pub(crate) const RING_DEPTH: u32 = 4096;

pub struct Ring {
    pub inner: Arc<Mutex<IoUring>>,
}

impl Ring {
    pub fn new() -> Result<Self> {
        let ring = IoUring::new(RING_DEPTH).map_err(PagedbError::Io)?;
        Ok(Self {
            inner: Arc::new(Mutex::new(ring)),
        })
    }
}
