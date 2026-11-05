//! Test-only `Vfs` wrapper that parks a chosen operation until the test releases
//! it, or drops it there.
//!
//! A gate turns an async interleaving into a fixed order, so a test never relies
//! on timing. Each gate fires once, and gates on one trigger fire in arming order.
//!
//! The pager holds the per-file handle mutex across `read_at`. A parked read
//! therefore blocks every other read through that handle until its release.

use std::future::Future;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::sync::Semaphore;

use crate::Result;

use super::memory::MemVfs;
use super::traits::{Vfs, VfsFile, canonical_native_path};
use super::types::{OpenMode, ReadReq, WriteReq};

/// How long a gated interleaving runs before the test reports a stall.
const STALL_LIMIT: Duration = Duration::from_secs(120);

/// Fail the test when `future` stalls, instead of hanging the run.
///
/// A stall means the code under test never reached the operation a gate waits on.
pub(crate) async fn bounded<F: Future>(future: F) -> F::Output {
    tokio::time::timeout(STALL_LIMIT, future)
        .await
        .expect("the gated interleaving stalled before reaching its gate")
}

/// Run `future` and drop it the moment `until` completes.
///
/// This is what a caller's `tokio::select!` does to a losing branch. The test
/// fails when `future` finishes first, because the cancellation point never ran.
pub(crate) async fn cancel_when<F: Future, U: Future<Output = ()>>(future: F, until: U) {
    bounded(async {
        let mut future = std::pin::pin!(future);
        let mut until = std::pin::pin!(until);
        tokio::select! {
            biased;
            () = &mut until => {}
            _ = &mut future => panic!("the future finished before its cancellation point"),
        }
    })
    .await;
}

/// One parked operation. Both semaphores hold no permits, so closing one is a
/// one-shot latch that wakes every waiter.
pub(crate) struct Gate {
    parked: Semaphore,
    released: Semaphore,
}

impl Gate {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            parked: Semaphore::new(0),
            released: Semaphore::new(0),
        })
    }

    async fn park(&self) {
        self.parked.close();
        let _ = self.released.acquire().await;
    }

    /// Wait until the operation reaches this gate.
    pub(crate) async fn wait_until_parked(&self) {
        let _ = self.parked.acquire().await;
    }

    /// Let the parked operation continue.
    pub(crate) fn release(&self) {
        self.released.close();
    }
}

enum Trigger {
    /// Parks a read of `offset` after it copies the bytes out of the file.
    Read { path: String, offset: u64 },
    /// Parks an open after it binds the handle to the current inode.
    Open { path: String },
    /// Parks a rename onto `to` before the rename happens.
    Rename { to: String },
    /// Parks a truncate to a length above `min_len` before it happens.
    TruncateAbove { path: String, min_len: u64 },
    /// Parks a directory sync before it happens. The rename it follows has landed.
    SyncDir { path: String },
    /// Parks a write at `offset` after its bytes land and before its file sync.
    WriteAt { path: String, offset: u64 },
    /// Parks a file sync before it happens. The writes it follows have landed.
    Sync { path: String },
    /// Parks a remove before it happens.
    Remove { path: String },
}

type Armed = Arc<Mutex<Vec<(Trigger, Arc<Gate>)>>>;

fn take_gate(armed: &Armed, matches: impl Fn(&Trigger) -> bool) -> Option<Arc<Gate>> {
    let mut armed = armed.lock();
    let position = armed.iter().position(|(trigger, _)| matches(trigger))?;
    Some(armed.remove(position).1)
}

fn canonical(path: &str) -> String {
    canonical_native_path(path).expect("a gate names a legal path")
}

/// A `Vfs` with one-shot gates. Clones share storage and gates.
#[derive(Clone, Default)]
pub(crate) struct Gated<I> {
    inner: I,
    armed: Armed,
}

/// The in-memory form, for every test that needs no real directory.
pub(crate) type GatedVfs = Gated<MemVfs>;

impl GatedVfs {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}

impl<I> Gated<I> {
    /// Wrap a backend. An apply needs one with a root path, which `MemVfs` lacks.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn over(inner: I) -> Self {
        Self {
            inner,
            armed: Armed::default(),
        }
    }

    fn arm(&self, trigger: Trigger) -> Arc<Gate> {
        let gate = Gate::new();
        self.armed.lock().push((trigger, gate.clone()));
        gate
    }

    pub(crate) fn park_next_read(&self, path: &str, offset: u64) -> Arc<Gate> {
        self.arm(Trigger::Read {
            path: canonical(path),
            offset,
        })
    }

    pub(crate) fn park_next_open(&self, path: &str) -> Arc<Gate> {
        self.arm(Trigger::Open {
            path: canonical(path),
        })
    }

    pub(crate) fn park_next_rename(&self, to: &str) -> Arc<Gate> {
        self.arm(Trigger::Rename { to: canonical(to) })
    }

    pub(crate) fn park_next_truncate_above(&self, path: &str, min_len: u64) -> Arc<Gate> {
        self.arm(Trigger::TruncateAbove {
            path: canonical(path),
            min_len,
        })
    }

    /// `/` names the root, which is the parent of a root-level `main.db`.
    pub(crate) fn park_next_sync_dir(&self, path: &str) -> Arc<Gate> {
        self.arm(Trigger::SyncDir {
            path: canonical(path),
        })
    }

    /// The bytes land before the park. A drop there models a header that reached
    /// storage while its future was still pending.
    pub(crate) fn park_next_write_at(&self, path: &str, offset: u64) -> Arc<Gate> {
        self.arm(Trigger::WriteAt {
            path: canonical(path),
            offset,
        })
    }

    pub(crate) fn park_next_sync(&self, path: &str) -> Arc<Gate> {
        self.arm(Trigger::Sync {
            path: canonical(path),
        })
    }

    pub(crate) fn park_next_remove(&self, path: &str) -> Arc<Gate> {
        self.arm(Trigger::Remove {
            path: canonical(path),
        })
    }
}

pub(crate) struct GatedFile<F> {
    inner: F,
    path: String,
    armed: Armed,
}

#[allow(clippy::unused_async_trait_impl)]
impl<I: Vfs> Vfs for Gated<I>
where
    I::File: Sync,
{
    type File = GatedFile<I::File>;
    type LockHandle = I::LockHandle;

    async fn open(&self, path: &str, mode: OpenMode) -> Result<Self::File> {
        let inner = self.inner.open(path, mode).await?;
        let path = canonical_native_path(path)?;
        let gate = take_gate(
            &self.armed,
            |trigger| matches!(trigger, Trigger::Open { path: armed } if *armed == path),
        );
        if let Some(gate) = gate {
            gate.park().await;
        }
        Ok(GatedFile {
            inner,
            path,
            armed: self.armed.clone(),
        })
    }

    async fn remove(&self, path: &str) -> Result<()> {
        let target = canonical_native_path(path)?;
        let gate = take_gate(
            &self.armed,
            |trigger| matches!(trigger, Trigger::Remove { path: armed } if *armed == target),
        );
        if let Some(gate) = gate {
            gate.park().await;
        }
        self.inner.remove(path).await
    }

    async fn rename(&self, from: &str, to: &str) -> Result<()> {
        let target = canonical_native_path(to)?;
        let gate = take_gate(
            &self.armed,
            |trigger| matches!(trigger, Trigger::Rename { to: armed } if *armed == target),
        );
        if let Some(gate) = gate {
            gate.park().await;
        }
        self.inner.rename(from, to).await
    }

    async fn list_dir(&self, path: &str) -> Result<Vec<String>> {
        self.inner.list_dir(path).await
    }

    async fn mkdir_all(&self, path: &str) -> Result<()> {
        self.inner.mkdir_all(path).await
    }

    async fn sync_dir(&self, path: &str) -> Result<()> {
        let target = canonical_native_path(path)?;
        let gate = take_gate(
            &self.armed,
            |trigger| matches!(trigger, Trigger::SyncDir { path: armed } if *armed == target),
        );
        if let Some(gate) = gate {
            gate.park().await;
        }
        self.inner.sync_dir(path).await
    }

    async fn lock_exclusive(&self, path: &str) -> Result<Self::LockHandle> {
        self.inner.lock_exclusive(path).await
    }

    async fn lock_shared(&self, path: &str) -> Result<Self::LockHandle> {
        self.inner.lock_shared(path).await
    }

    fn root_path(&self) -> Option<&Path> {
        self.inner.root_path()
    }
}

#[allow(clippy::unused_async_trait_impl)]
impl<F: VfsFile + Sync> VfsFile for GatedFile<F> {
    async fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let read = self.inner.read_at(offset, buf).await?;
        let gate = take_gate(&self.armed, |trigger| {
            matches!(
                trigger,
                Trigger::Read { path, offset: armed } if *path == self.path && *armed == offset
            )
        });
        if let Some(gate) = gate {
            gate.park().await;
        }
        Ok(read)
    }

    async fn read_at_vectored(&self, reqs: &mut [ReadReq<'_>]) -> Result<()> {
        self.inner.read_at_vectored(reqs).await
    }

    async fn write_at(&mut self, offset: u64, buf: &[u8]) -> Result<usize> {
        let written = self.inner.write_at(offset, buf).await?;
        let gate = take_gate(&self.armed, |trigger| {
            matches!(
                trigger,
                Trigger::WriteAt { path, offset: armed } if *path == self.path && *armed == offset
            )
        });
        if let Some(gate) = gate {
            gate.park().await;
        }
        Ok(written)
    }

    async fn write_at_vectored(&mut self, reqs: &[WriteReq<'_>]) -> Result<()> {
        self.inner.write_at_vectored(reqs).await
    }

    async fn sync(&mut self) -> Result<()> {
        let gate = take_gate(
            &self.armed,
            |trigger| matches!(trigger, Trigger::Sync { path } if *path == self.path),
        );
        if let Some(gate) = gate {
            gate.park().await;
        }
        self.inner.sync().await
    }

    async fn truncate(&mut self, len: u64) -> Result<()> {
        let gate = take_gate(&self.armed, |trigger| {
            matches!(
                trigger,
                Trigger::TruncateAbove { path, min_len } if *path == self.path && len > *min_len
            )
        });
        if let Some(gate) = gate {
            gate.park().await;
        }
        self.inner.truncate(len).await
    }

    async fn len(&self) -> Result<u64> {
        self.inner.len().await
    }

    async fn is_empty(&self) -> Result<bool> {
        self.inner.is_empty().await
    }

    fn supports_direct_io(&self) -> bool {
        self.inner.supports_direct_io()
    }
}
