//! `OpfsVfs` — the main-thread async `Vfs` implementation backed by a
//! dedicated OPFS worker.

#![cfg(all(target_arch = "wasm32", feature = "opfs"))]

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use gloo_worker::{Spawnable, WorkerBridge};
use wasm_bindgen_futures::spawn_local;

use crate::Result;
use crate::errors::PagedbError;
use crate::vfs::traits::Vfs;
use crate::vfs::types::OpenMode;

use super::handle::{OpfsFile, map_worker_err};
use super::worker::{OpfsOp, OpfsRequest, OpfsResponse, OpfsResult, OpfsWorker};

// ── Bridge wrapper ─────────────────────────────────────────────────────────────

/// Pending oneshot channel: `waker` is signalled when the response arrives.
struct Pending {
    waker: std::task::Waker,
    result: Option<OpfsResult>,
}

/// Shared state for correlating in-flight requests.
struct BridgeInner {
    bridge: WorkerBridge<OpfsWorker>,
    pending: HashMap<u32, Pending>,
    next_seq: u32,
}

/// `Rc<RefCell<BridgeInner>>` — shared between `OpfsVfs`, `OpfsFile`, and the
/// message callback.  Single-threaded wasm32 makes `Rc<RefCell<_>>` safe.
pub(crate) type BridgeRef = Rc<RefCell<BridgeInner>>;

impl BridgeInner {
    /// Send a request and return a future that resolves to the `OpfsResult`.
    fn dispatch_impl(
        this: &BridgeRef,
        op: OpfsOp,
    ) -> impl std::future::Future<Output = Result<OpfsResult>> {
        let seq = {
            let mut inner = this.borrow_mut();
            let seq = inner.next_seq;
            inner.next_seq = inner.next_seq.wrapping_add(1).max(1); // never 0
            inner.bridge.send(OpfsRequest { seq, op });
            seq
        };
        let this = Rc::clone(this);
        DispatchFuture { seq, bridge: this }
    }
}

/// Extension helper called by `OpfsFile` so it can issue a fire-and-forget
/// close without holding a borrow across an await.
pub(crate) trait BridgeExt {
    fn send(&self, req: OpfsRequest);
    fn dispatch(&self, op: OpfsOp) -> impl std::future::Future<Output = Result<OpfsResult>>;
}

impl BridgeExt for BridgeInner {
    fn send(&self, req: OpfsRequest) {
        self.bridge.send(req);
    }
    fn dispatch(&self, _op: OpfsOp) -> impl std::future::Future<Output = Result<OpfsResult>> {
        // This variant is used for fire-and-forget only; for real awaits use
        // the free function below.
        std::future::ready(Err(PagedbError::Unsupported))
    }
}

/// A future that resolves when the worker sends back `OpfsResponse { seq, .. }`.
struct DispatchFuture {
    seq: u32,
    bridge: BridgeRef,
}

impl std::future::Future for DispatchFuture {
    type Output = Result<OpfsResult>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let mut inner = self.bridge.borrow_mut();
        if let Some(p) = inner.pending.get_mut(&self.seq) {
            if let Some(result) = p.result.take() {
                inner.pending.remove(&self.seq);
                return std::task::Poll::Ready(Ok(result));
            }
            // Update the waker in case the executor changed it.
            p.waker = cx.waker().clone();
            std::task::Poll::Pending
        } else {
            // First poll: register the pending entry.
            inner.pending.insert(
                self.seq,
                Pending {
                    waker: cx.waker().clone(),
                    result: None,
                },
            );
            std::task::Poll::Pending
        }
    }
}

impl Drop for DispatchFuture {
    fn drop(&mut self) {
        // Clean up pending entry if the future is dropped before completing.
        self.bridge.borrow_mut().pending.remove(&self.seq);
    }
}

// ── Lock handle ───────────────────────────────────────────────────────────────

/// Advisory lock handle for OPFS.
///
/// OPFS itself has no advisory lock API; exclusivity is maintained in-process
/// via this map.  Since wasm32 is single-threaded, a `Rc<RefCell<_>>` map is
/// sufficient.
pub struct OpfsLockHandle {
    path: String,
    locks: Rc<RefCell<LockMap>>,
}

impl Drop for OpfsLockHandle {
    fn drop(&mut self) {
        self.locks.borrow_mut().release(&self.path);
    }
}

#[derive(Debug, Clone, Copy)]
enum LockKind {
    Exclusive,
    Shared,
}

#[derive(Default)]
struct LockMap {
    /// Maps path → (kind, shared_count).
    entries: HashMap<String, (LockKind, u32)>,
}

impl LockMap {
    fn try_exclusive(&mut self, path: &str) -> bool {
        match self.entries.get(path) {
            None => {
                self.entries
                    .insert(path.to_string(), (LockKind::Exclusive, 1));
                true
            }
            Some(_) => false,
        }
    }

    fn try_shared(&mut self, path: &str) -> bool {
        match self.entries.get_mut(path) {
            None => {
                self.entries.insert(path.to_string(), (LockKind::Shared, 1));
                true
            }
            Some((LockKind::Shared, n)) => {
                *n += 1;
                true
            }
            Some((LockKind::Exclusive, _)) => false,
        }
    }

    fn release(&mut self, path: &str) {
        let remove = match self.entries.get_mut(path) {
            Some((_, n)) if *n <= 1 => true,
            Some((_, n)) => {
                *n -= 1;
                false
            }
            None => false,
        };
        if remove {
            self.entries.remove(path);
        }
    }
}

// ── OpfsVfs ───────────────────────────────────────────────────────────────────

/// Async `Vfs` backed by a dedicated OPFS worker.
///
/// Construct via [`OpfsVfs::new`], which spawns the worker and establishes
/// the message bridge.
pub struct OpfsVfs {
    bridge: BridgeRef,
    locks: Rc<RefCell<LockMap>>,
}

impl OpfsVfs {
    /// Spawn the OPFS worker and return a ready `OpfsVfs`.
    ///
    /// `worker_url` must point to the JS bootstrap script that calls
    /// `OpfsWorker::registrar().register()` (see module-level doc comment).
    pub fn new(worker_url: &str) -> Result<Self> {
        let bridge_rc: BridgeRef = Rc::new(RefCell::new(BridgeInner {
            bridge: unsafe { std::mem::zeroed() }, // placeholder; replaced below
            pending: HashMap::new(),
            next_seq: 1,
        }));

        let callback_ref = Rc::clone(&bridge_rc);
        let bridge = OpfsWorker::spawner()
            .callback(move |resp: OpfsResponse| {
                let mut inner = callback_ref.borrow_mut();
                if let Some(p) = inner.pending.get_mut(&resp.seq) {
                    p.result = Some(resp.result);
                    p.waker.wake_by_ref();
                }
            })
            .spawn(worker_url)
            .map_err(|_| PagedbError::Unsupported)?;

        bridge_rc.borrow_mut().bridge = bridge;

        Ok(Self {
            bridge: bridge_rc,
            locks: Rc::new(RefCell::new(LockMap::default())),
        })
    }

    async fn dispatch(&self, op: OpfsOp) -> Result<OpfsResult> {
        BridgeInner::dispatch_impl(&self.bridge, op).await
    }
}

impl Vfs for OpfsVfs {
    type File = OpfsFile;
    type LockHandle = OpfsLockHandle;

    async fn open(&self, path: &str, mode: OpenMode) -> Result<Self::File> {
        let (create, create_new, read_only) = match mode {
            OpenMode::Read => (false, false, true),
            OpenMode::ReadWrite => (false, false, false),
            OpenMode::CreateNew => (true, true, false),
            OpenMode::CreateOrOpen => (true, false, false),
        };

        let result = self
            .dispatch(OpfsOp::Open {
                path: path.to_string(),
                create,
                create_new,
                read_only,
            })
            .await?;

        match result {
            OpfsResult::Opened { handle_id } => Ok(OpfsFile {
                handle_id,
                bridge: Rc::clone(&self.bridge),
                read_only,
            }),
            OpfsResult::Err { reason } => Err(map_worker_err(&reason)),
            _ => Err(PagedbError::Unsupported),
        }
    }

    async fn remove(&self, path: &str) -> Result<()> {
        let result = self
            .dispatch(OpfsOp::Remove {
                path: path.to_string(),
            })
            .await?;
        match result {
            OpfsResult::Ok => Ok(()),
            OpfsResult::Err { reason } => Err(map_worker_err(&reason)),
            _ => Err(PagedbError::Unsupported),
        }
    }

    async fn rename(&self, from: &str, to: &str) -> Result<()> {
        let result = self
            .dispatch(OpfsOp::Rename {
                from: from.to_string(),
                to: to.to_string(),
            })
            .await?;
        match result {
            OpfsResult::Ok => Ok(()),
            OpfsResult::Err { reason } => Err(map_worker_err(&reason)),
            _ => Err(PagedbError::Unsupported),
        }
    }

    async fn list_dir(&self, path: &str) -> Result<Vec<String>> {
        let result = self
            .dispatch(OpfsOp::ListDir {
                path: path.to_string(),
            })
            .await?;
        match result {
            OpfsResult::Entries { names } => Ok(names),
            OpfsResult::Err { reason } => Err(map_worker_err(&reason)),
            _ => Err(PagedbError::Unsupported),
        }
    }

    async fn mkdir_all(&self, path: &str) -> Result<()> {
        let result = self
            .dispatch(OpfsOp::MkdirAll {
                path: path.to_string(),
            })
            .await?;
        match result {
            OpfsResult::Ok => Ok(()),
            OpfsResult::Err { reason } => Err(map_worker_err(&reason)),
            _ => Err(PagedbError::Unsupported),
        }
    }

    async fn sync_dir(&self, _path: &str) -> Result<()> {
        // OPFS has no directory sync primitive; durability is implicit.
        Ok(())
    }

    async fn lock_exclusive(&self, path: &str) -> Result<Self::LockHandle> {
        let acquired = self.locks.borrow_mut().try_exclusive(path);
        if acquired {
            Ok(OpfsLockHandle {
                path: path.to_string(),
                locks: Rc::clone(&self.locks),
            })
        } else {
            Err(PagedbError::AlreadyLocked)
        }
    }

    async fn lock_shared(&self, path: &str) -> Result<Self::LockHandle> {
        let acquired = self.locks.borrow_mut().try_shared(path);
        if acquired {
            Ok(OpfsLockHandle {
                path: path.to_string(),
                locks: Rc::clone(&self.locks),
            })
        } else {
            Err(PagedbError::AlreadyLocked)
        }
    }
}
