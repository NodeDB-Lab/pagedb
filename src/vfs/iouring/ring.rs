//! Shared `io_uring` instance. One ring is held per `IouringVfs`. All callers
//! acquire a `parking_lot::Mutex<IoUring>` lock, push SQE(s), call
//! `submit_and_wait`, and drain matching CQEs before releasing the lock.
//! This is intentionally simple: no background poller, and the ring fd is not
//! registered with a reactor.
//!
//! `submit_and_wait` parks the calling thread inside `io_uring_enter` until the
//! requested completions land, and the lock is held across that wait. Both are
//! why the whole submit + drain cycle runs on the blocking pool (see
//! `file.rs`): the ring must never be locked, and `io_uring_enter` must never
//! be entered, from a future being polled on the executor.

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
        let ring = IoUring::new(RING_DEPTH).map_err(setup_failed)?;
        Ok(Self {
            inner: Arc::new(Mutex::new(ring)),
        })
    }
}

/// Explain a failed `io_uring_setup` instead of surfacing a bare errno.
///
/// The raw failure is uninformative in exactly the environments where it
/// happens: `ENOMEM` here almost never means the machine is out of memory — a
/// ring is charged against `RLIMIT_MEMLOCK`, which is commonly 8 MB and is
/// exhausted by a handful of concurrent stores. `EPERM`/`ENOSYS` usually mean a
/// sandbox blocked the syscall rather than that anything is broken. Callers who
/// see this error directly get the cause; [`crate::vfs::open_default`] does not
/// surface it at all, because it falls back to the thread-pool backend.
fn setup_failed(error: std::io::Error) -> PagedbError {
    PagedbError::Io(std::io::Error::new(
        error.kind(),
        RingSetupError { source: error },
    ))
}

/// Carries the failed `io_uring_setup` errno as its `source` so nothing about
/// the original failure is lost.
#[derive(Debug)]
struct RingSetupError {
    source: std::io::Error,
}

impl std::fmt::Display for RingSetupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "io_uring setup failed ({}); likely causes: RLIMIT_MEMLOCK too low \
             for another ring (each ring is charged against it), a seccomp \
             profile blocking io_uring_setup, or a kernel older than 5.1",
            self.source
        )
    }
}

impl std::error::Error for RingSetupError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}
