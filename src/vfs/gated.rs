//! Test-only `MemVfs` wrapper that parks a chosen operation until the test
//! releases it.
//!
//! A gate turns an async interleaving into a fixed order, so a test never relies
//! on timing. Each gate fires once, and gates on one trigger fire in arming order.
//!
//! The pager holds the per-file handle mutex across `read_at`. A parked read
//! therefore blocks every other read through that handle until its release.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::sync::Semaphore;

use crate::Result;

use super::memory::{MemFile, MemLockHandle, MemVfs};
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

/// `MemVfs` with one-shot gates. Clones share storage and gates.
#[derive(Clone, Default)]
pub(crate) struct GatedVfs {
    inner: MemVfs,
    armed: Armed,
}

impl GatedVfs {
    pub(crate) fn new() -> Self {
        Self::default()
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
}

pub(crate) struct GatedFile {
    inner: MemFile,
    path: String,
    armed: Armed,
}

#[allow(clippy::unused_async_trait_impl)]
impl Vfs for GatedVfs {
    type File = GatedFile;
    type LockHandle = MemLockHandle;

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
        self.inner.sync_dir(path).await
    }

    async fn lock_exclusive(&self, path: &str) -> Result<Self::LockHandle> {
        self.inner.lock_exclusive(path).await
    }

    async fn lock_shared(&self, path: &str) -> Result<Self::LockHandle> {
        self.inner.lock_shared(path).await
    }
}

#[allow(clippy::unused_async_trait_impl)]
impl VfsFile for GatedFile {
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
        self.inner.write_at(offset, buf).await
    }

    async fn write_at_vectored(&mut self, reqs: &[WriteReq<'_>]) -> Result<()> {
        self.inner.write_at_vectored(reqs).await
    }

    async fn sync(&mut self) -> Result<()> {
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
