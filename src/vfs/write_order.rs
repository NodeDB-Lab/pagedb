//! Per-file ordering of operations that can outlive their future.
//!
//! A blocking-pool call or a `dispatch_io` submission keeps running after the
//! caller drops its future. Without an order, a write from a dropped commit can
//! land after the next writer's write at the same offset. A truncate can also
//! run before that write and lose to it, and a sync can return before it.
//!
//! Each write, sync, and truncate therefore holds this file's turn until the
//! backend finishes it. The turn moves into the work itself, so it survives the
//! dropped future. The next operation on the file waits for that release.
//!
//! The gate belongs to the file, not to the handle. `commit_header` opens its own
//! handle, and a reopen after a poisoned handle opens another one. Handles of one
//! file in this process therefore share one gate, found by device and inode.
//!
//! Reads take no turn. A dropped write only targets pages no published root names
//! or the inactive header slot. An `open` waits for the writes already in flight,
//! so a new handle reads the settled file.
#![cfg_attr(windows, allow(unsafe_code))]

use std::collections::HashMap;
use std::sync::{Arc, OnceLock, Weak};

use parking_lot::Mutex;
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};

use crate::Result;
#[cfg(any(unix, windows))]
use crate::errors::PagedbError;

/// Names one file independently of its path, so a rename keeps its gate.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct FileIdentity {
    volume: u64,
    index: u64,
}

impl FileIdentity {
    #[cfg(unix)]
    fn of(file: &std::fs::File) -> Result<Self> {
        use std::os::unix::fs::MetadataExt;

        let metadata = file.metadata().map_err(PagedbError::Io)?;
        Ok(Self {
            volume: metadata.dev(),
            index: metadata.ino(),
        })
    }

    #[cfg(windows)]
    fn of(file: &std::fs::File) -> Result<Self> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Foundation::HANDLE;
        use windows_sys::Win32::Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
        };

        let handle = file.as_raw_handle() as HANDLE;
        // SAFETY: a zeroed value is valid for this plain-data struct, and the call
        // below only writes into it.
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: `file` keeps `handle` open for the call, and `info` is a live
        // exclusive reference.
        if unsafe { GetFileInformationByHandle(handle, &mut info) } == 0 {
            return Err(PagedbError::Io(std::io::Error::last_os_error()));
        }
        Ok(Self {
            volume: u64::from(info.dwVolumeSerialNumber),
            index: (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
        })
    }

    /// No file identity exists here, so each handle orders only its own work.
    #[cfg(not(any(unix, windows)))]
    fn of(_file: &std::fs::File) -> Result<Self> {
        use std::sync::atomic::{AtomicU64, Ordering};

        static NEXT_HANDLE: AtomicU64 = AtomicU64::new(0);
        Ok(Self {
            volume: 0,
            index: NEXT_HANDLE.fetch_add(1, Ordering::Relaxed),
        })
    }
}

/// The lock's value. Its drop runs when the last handle and the last in-flight
/// operation of the file are gone, and removes the file from the registry.
struct FileGate {
    identity: FileIdentity,
}

impl Drop for FileGate {
    fn drop(&mut self) {
        let mut gates = gates().lock();
        // A racing open can already have installed a live gate for this file.
        let dead = gates
            .get(&self.identity)
            .is_some_and(|gate| gate.strong_count() == 0);
        if dead {
            gates.remove(&self.identity);
        }
    }
}

type Gates = Mutex<HashMap<FileIdentity, Weak<AsyncMutex<FileGate>>>>;

fn gates() -> &'static Gates {
    static GATES: OnceLock<Gates> = OnceLock::new();
    GATES.get_or_init(Gates::default)
}

/// One handle's view of its file's gate.
pub(crate) struct WriteOrder {
    gate: Arc<AsyncMutex<FileGate>>,
}

impl WriteOrder {
    /// The gate for `file`, shared with every other live handle of that file.
    ///
    /// This reads file metadata, so call it on the blocking pool.
    pub(crate) fn for_file(file: &std::fs::File) -> Result<Self> {
        let identity = FileIdentity::of(file)?;
        let mut gates = gates().lock();
        if let Some(gate) = gates.get(&identity).and_then(Weak::upgrade) {
            return Ok(Self { gate });
        }
        let gate = Arc::new(AsyncMutex::new(FileGate { identity }));
        gates.insert(identity, Arc::downgrade(&gate));
        Ok(Self { gate })
    }

    /// Wait for every earlier operation on this file, then take the next turn.
    ///
    /// Tickets are served first come, first served. An uncontended entry costs an
    /// `Arc` clone and a semaphore acquire, with no allocation.
    pub(crate) async fn enter(&self) -> FileTurn {
        FileTurn {
            _turn: Arc::clone(&self.gate).lock_owned().await,
        }
    }

    /// Wait for every operation on this file that is already in flight.
    pub(crate) async fn settled(&self) {
        drop(self.gate.lock().await);
    }
}

/// Permission to run one operation. Move it into the work that outlives the
/// future, and drop it only when the backend has finished.
#[must_use = "dropping the turn lets the next operation on this file start"]
pub(crate) struct FileTurn {
    _turn: OwnedMutexGuard<FileGate>,
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::time::timeout;

    use super::*;

    const PATIENCE: Duration = Duration::from_millis(50);

    fn file_named(dir: &tempfile::TempDir, name: &str) -> std::fs::File {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(dir.path().join(name))
            .unwrap()
    }

    #[tokio::test(flavor = "current_thread")]
    async fn two_handles_of_one_file_share_a_gate() {
        let dir = tempfile::tempdir().unwrap();
        let first = WriteOrder::for_file(&file_named(&dir, "shared")).unwrap();
        let second = WriteOrder::for_file(&file_named(&dir, "shared")).unwrap();

        let turn = first.enter().await;
        assert!(timeout(PATIENCE, second.enter()).await.is_err());
        drop(turn);
        drop(second.enter().await);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handles_of_two_files_do_not_wait_on_each_other() {
        let dir = tempfile::tempdir().unwrap();
        let first = WriteOrder::for_file(&file_named(&dir, "one")).unwrap();
        let second = WriteOrder::for_file(&file_named(&dir, "two")).unwrap();

        let _turn = first.enter().await;
        drop(timeout(PATIENCE, second.enter()).await.unwrap());
    }

    /// A dropped write can run past the close of its handle. A handle opened in
    /// that window must still wait for it.
    #[tokio::test(flavor = "current_thread")]
    async fn a_turn_keeps_the_gate_alive_after_its_handle_closes() {
        let dir = tempfile::tempdir().unwrap();
        let file = file_named(&dir, "reopened");
        let closed = WriteOrder::for_file(&file).unwrap();
        let turn = closed.enter().await;
        drop(closed);

        let reopened = WriteOrder::for_file(&file).unwrap();
        assert!(timeout(PATIENCE, reopened.settled()).await.is_err());
        drop(turn);
        reopened.settled().await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn the_registry_forgets_a_file_with_no_handle_and_no_turn() {
        let dir = tempfile::tempdir().unwrap();
        let file = file_named(&dir, "forgotten");
        let identity = FileIdentity::of(&file).unwrap();
        let order = WriteOrder::for_file(&file).unwrap();
        let turn = order.enter().await;
        drop(order);
        assert!(gates().lock().contains_key(&identity));

        drop(turn);
        assert!(!gates().lock().contains_key(&identity));
    }
}
