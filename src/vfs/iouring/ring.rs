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
//!
//! `unsafe` is permitted here for the submission-queue push: an SQE names its
//! transfer buffer by raw pointer, so publishing one is a promise about that
//! buffer's lifetime that the type system cannot carry. [`SubmitError`] is how
//! that promise is handed back to the caller.
#![allow(unsafe_code)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use io_uring::IoUring;
use parking_lot::Mutex;

use crate::Result;
use crate::errors::PagedbError;
use crate::vfs::traits::checked_indexed_completion;

/// Default submission queue depth. Must be a power of two. Sized large
/// enough to absorb a full B+ tree `flush` (thousands of dirty pages in
/// bulk-load workloads) in one batch without exhausting the queue.
pub(crate) const RING_DEPTH: u32 = 4096;

/// Why a submit cycle produced no results.
///
/// The distinction is a memory-safety contract, not a diagnostic nicety.
/// `io_uring` SQEs name the transfer buffer by raw pointer, and the
/// `io-uring` crate publishes the submission tail when the `SubmissionQueue`
/// guard drops — so the moment an entry is pushed, the kernel may read or
/// write that buffer until its completion is observed. A caller that frees
/// the buffer while an entry is still outstanding hands the kernel a dangling
/// pointer.
pub(crate) enum SubmitError {
    /// Nothing reached the kernel, or everything that did was accounted for.
    /// No entry can still be referencing a transfer buffer, so the caller may
    /// drop its buffers normally.
    Settled(std::io::Error),
    /// Entries were published that could not be accounted for. The kernel may
    /// still write into their buffers at any time, so the caller **must not**
    /// free them — leak them with [`std::mem::forget`] instead. The ring is
    /// poisoned; every later submission on it fails immediately.
    Abandoned(std::io::Error),
}

impl SubmitError {
    /// The underlying I/O failure, for reporting.
    pub(crate) fn into_io(self) -> std::io::Error {
        match self {
            Self::Settled(error) | Self::Abandoned(error) => error,
        }
    }
}

/// The shared `io_uring` instance, plus the poison flag that fences it off
/// once a cycle has abandoned entries to the kernel.
pub(crate) struct SharedRing {
    ring: Mutex<IoUring>,
    /// Set once a submit cycle returned [`SubmitError::Abandoned`]. Matching
    /// completions by `user_data` is only sound while every prior cycle
    /// drained its own CQEs: an abandoned cycle leaves completions in the
    /// queue that a later cycle would mistake for its own and report as that
    /// cycle's byte count. Refusing every later submission is what keeps a
    /// stale CQE from ever being read as a fresh result.
    poisoned: AtomicBool,
}

impl SharedRing {
    fn poison(&self) {
        self.poisoned.store(true, Ordering::Release);
    }

    /// Submit `entries` and return their results in submission order.
    ///
    /// # Safety
    ///
    /// Every buffer referenced by `entries` must stay valid until this returns
    /// — and, if it returns [`SubmitError::Abandoned`], for the rest of the
    /// process's life.
    pub(crate) unsafe fn submit_and_collect(
        &self,
        entries: &[io_uring::squeue::Entry],
    ) -> std::result::Result<Vec<i32>, SubmitError> {
        if entries.is_empty() {
            return Ok(Vec::new());
        }
        if self.poisoned.load(Ordering::Acquire) {
            return Err(SubmitError::Settled(poisoned_error()));
        }

        let total = entries.len();
        // Cap each submission at the ring's SQ depth; larger callers (a full
        // B+ tree flush) are chunked across several round-trips. Each chunk
        // re-tags `user_data` with the index within the chunk so the drain has
        // a stable 0..chunk_len keyspace.
        let chunk_size = RING_DEPTH as usize;
        let mut results = vec![0i32; total];
        let mut guard = self.ring.lock();

        let mut base = 0usize;
        while base < total {
            let end = (base + chunk_size).min(total);
            let chunk_len = end - base;

            // Push as much of the chunk as the queue accepts. A short push is
            // not an error yet: the entries that did go in are published when
            // the guard drops, so they have to be drained before anything is
            // reported. Only the entries that were never pushed are free of
            // the kernel.
            let pushed = {
                let mut sq = guard.submission();
                let mut pushed = 0usize;
                for (index, entry) in entries[base..end].iter().enumerate() {
                    let tagged = entry.clone().user_data(index as u64);
                    // SAFETY: the caller guarantees the buffers referenced by
                    // `entries` outlive this call.
                    if unsafe { sq.push(&tagged) }.is_err() {
                        break;
                    }
                    pushed += 1;
                }
                pushed
            };

            let drained = match drain_exact(&mut guard, pushed) {
                Ok(drained) => drained,
                Err(error) => {
                    // Entries are outstanding and we no longer know which. The
                    // caller's buffers must outlive the process from here.
                    self.poison();
                    return Err(SubmitError::Abandoned(error));
                }
            };

            for (index, result) in drained.into_iter().enumerate() {
                results[base + index] = result;
            }

            if pushed < chunk_len {
                // Everything published has now been drained, so the buffers are
                // safe — but the queue could not take the whole chunk, which
                // means the ring is smaller than advertised or was left with
                // stale entries. Report rather than spin.
                return Err(SubmitError::Settled(std::io::Error::other(
                    "io_uring submission queue full",
                )));
            }
            base = end;
        }
        Ok(results)
    }
}

/// Wait until exactly `want` completions tagged `0..want` have been observed,
/// and return their results in tag order.
///
/// Returning `Ok` is the promise that no entry from this cycle is still
/// outstanding. Every path that cannot make that promise returns `Err`, which
/// the caller turns into a poisoned ring — including `EINTR`, which is retried
/// here rather than propagated precisely because a signal must not be able to
/// strand a buffer.
fn drain_exact(ring: &mut IoUring, want: usize) -> std::io::Result<Vec<i32>> {
    if want == 0 {
        return Ok(Vec::new());
    }
    let mut slots: Vec<Option<i32>> = vec![None; want];
    let mut found = 0usize;
    while found < want {
        match ring.submit_and_wait(want - found) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
        let mut completion = ring.completion();
        completion.sync();
        for cqe in completion.by_ref() {
            match checked_indexed_completion(&mut slots, cqe.user_data(), cqe.result()) {
                Ok(true) => found += 1,
                Ok(false) => {}
                // A duplicate tag means the queue holds a completion this
                // cycle cannot own. Accounting is broken; fail into poison.
                Err(error) => return Err(std::io::Error::other(error.to_string())),
            }
            if found == want {
                break;
            }
        }
    }
    slots
        .into_iter()
        .map(|slot| {
            slot.ok_or_else(|| std::io::Error::other("io_uring: missing indexed CQE result"))
        })
        .collect()
}

fn poisoned_error() -> std::io::Error {
    std::io::Error::other(
        "io_uring ring poisoned: an earlier operation left submissions unaccounted for; \
         reopen the store to get a fresh ring",
    )
}

pub struct Ring {
    pub inner: Arc<SharedRing>,
}

impl Ring {
    pub fn new() -> Result<Self> {
        let ring = IoUring::new(RING_DEPTH).map_err(setup_failed)?;
        Ok(Self {
            inner: Arc::new(SharedRing {
                ring: Mutex::new(ring),
                poisoned: AtomicBool::new(false),
            }),
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
