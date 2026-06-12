//! `OpfsVfs` — the main-thread async `Vfs` implementation backed by a
//! dedicated OPFS Web Worker.

#![cfg(all(target_arch = "wasm32", feature = "opfs"))]
// The unsafe Send + Sync impls are required to satisfy `Vfs: Send + Sync` on
// wasm32. Safety justification is in the impl blocks below.
#![allow(unsafe_code)]

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};

use futures::channel::oneshot;
use send_wrapper::SendWrapper;
use wasm_bindgen::prelude::*;

use crate::Result;
use crate::errors::PagedbError;
use crate::vfs::traits::Vfs;
use crate::vfs::types::OpenMode;

use super::handle::{OpfsFile, map_err};
use super::lock::{LockMap, OpfsLockHandle};
use super::protocol::{OpfsOp, OpfsRequest, OpfsResponse, OpfsResult};

// ── Request registry ──────────────────────────────────────────────────────────

/// Maps in-flight request ids to their response channels.
type Registry = Arc<Mutex<HashMap<u64, oneshot::Sender<OpfsResult>>>>;

// ── OpfsVfs internals ─────────────────────────────────────────────────────────

/// The heap allocation shared between all `Arc<OpfsVfs>` clones.
struct OpfsVfsInner {
    /// The Web Worker handle. `web_sys::Worker` is `!Send`; `SendWrapper`
    /// enforces single-thread access at runtime, panicking if accessed from
    /// another thread.
    worker: SendWrapper<web_sys::Worker>,
    /// Pending request channels keyed by request id.
    request_registry: Registry,
    /// Monotonically increasing request id generator.
    next_request_id: AtomicU64,
    /// In-process advisory lock state.
    locks: Arc<Mutex<LockMap>>,
    /// Weak reference to the Arc that owns this inner, used by `open()` to
    /// hand an `Arc<OpfsVfs>` to each `OpfsFile` without storing the Arc
    /// inside itself (which would create a reference cycle).
    weak_self: Mutex<Weak<OpfsVfsInner>>,
    /// Keeps the onmessage Closure alive for the lifetime of `OpfsVfsInner`.
    _onmessage: SendWrapper<Closure<dyn FnMut(web_sys::MessageEvent)>>,
    /// Normalised root directory that every VFS path is resolved under, e.g.
    /// `/mydb`. Empty means paths are used verbatim against the OPFS origin
    /// root (legacy behaviour). Used to isolate independent databases in the
    /// single shared OPFS sandbox.
    root: String,
}

// ── OpfsVfs (public newtype) ──────────────────────────────────────────────────

/// Async `Vfs` backed by a dedicated OPFS Web Worker.
///
/// `Clone` is cheap — it clones the inner `Arc` and both clones share the same
/// worker connection, request registry, and lock map.
///
/// # Send + Sync
///
/// `OpfsVfs` wraps `Arc<OpfsVfsInner>`. The inner type contains
/// `SendWrapper<web_sys::Worker>` (which is `!Send` by default) and a
/// `Closure` (also `!Send`). We add `unsafe impl Send + Sync` with the
/// following justification:
///
/// - wasm32 targets run in a single-threaded browser JS realm. There is no
///   OS thread scheduler; `Send` in this context is a Rust-level marker only.
/// - `SendWrapper` panics at runtime if accessed from any thread other than
///   the one that created the value, providing the same safety guarantee that
///   `!Send` would provide statically.
/// - All public APIs (`dispatch`, `Vfs` methods) must be called from the
///   thread that constructed `OpfsVfs`. `Db<OpfsVfs>` fulfils this because
///   wasm32 has exactly one JS thread.
pub struct OpfsVfs(Arc<OpfsVfsInner>);

impl Clone for OpfsVfs {
    fn clone(&self) -> Self {
        OpfsVfs(Arc::clone(&self.0))
    }
}

// SAFETY: see doc comment above — wasm32 single-thread model, SendWrapper
// runtime guard, all access on spawning thread.
unsafe impl Send for OpfsVfs {}
unsafe impl Sync for OpfsVfs {}

impl OpfsVfs {
    /// Spawn the OPFS worker and return a ready `OpfsVfs` rooted at the OPFS
    /// origin directory.
    ///
    /// `worker_url` must point to the pure-JS worker file (`opfs_worker.js`).
    /// Embedders can obtain the JS source via [`crate::vfs::opfs::OPFS_WORKER_JS`]
    /// and serve it at a URL the browser can load.
    ///
    /// All databases opened through the returned VFS share the same OPFS paths
    /// (e.g. `/main.db`). To run several independent databases in one origin,
    /// use [`OpfsVfs::with_root`] to give each a distinct sub-directory.
    pub fn new(worker_url: &str) -> Result<Self> {
        Self::with_root(worker_url, "")
    }

    /// Spawn the OPFS worker and return a `OpfsVfs` whose every path is resolved
    /// under `root`.
    ///
    /// `root` names a sub-directory of the OPFS origin sandbox under which all
    /// of this database's files (`main.db`, segments, locks, sidecars) live, so
    /// multiple databases can coexist in the same origin without colliding on
    /// the fixed `/main.db` path. It is normalised to a single leading-slash
    /// prefix: surrounding slashes are trimmed and an empty value reproduces the
    /// legacy origin-root behaviour of [`OpfsVfs::new`].
    pub fn with_root(worker_url: &str, root: &str) -> Result<Self> {
        let root = super::path::normalize_root(root);

        let registry: Registry = Arc::new(Mutex::new(HashMap::new()));

        let worker = web_sys::Worker::new(worker_url)
            .map_err(|e| PagedbError::Io(std::io::Error::other(format!("{e:?}"))))?;

        // Build the onmessage callback. The registry Arc is cloned into it.
        let registry_cb = Arc::clone(&registry);
        let onmessage: Closure<dyn FnMut(web_sys::MessageEvent)> =
            Closure::wrap(Box::new(move |event: web_sys::MessageEvent| {
                let data = event.data();
                match serde_wasm_bindgen::from_value::<OpfsResponse>(data) {
                    Ok(resp) => {
                        let sender = {
                            let mut reg = registry_cb
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner);
                            reg.remove(&resp.id)
                        };
                        if let Some(tx) = sender {
                            // Ignore send error: receiver may be dropped (future cancelled).
                            let _ = tx.send(resp.result);
                        }
                    }
                    Err(e) => {
                        tracing::warn!("OpfsVfs: failed to deserialize worker response: {:?}", e);
                    }
                }
            }));

        worker.set_onmessage(Some(onmessage.as_ref().unchecked_ref()));

        let inner = Arc::new(OpfsVfsInner {
            worker: SendWrapper::new(worker),
            request_registry: registry,
            next_request_id: AtomicU64::new(1),
            locks: Arc::new(Mutex::new(LockMap::default())),
            weak_self: Mutex::new(Weak::new()),
            _onmessage: SendWrapper::new(onmessage),
            root,
        });

        // Store the weak self-reference so open() can hand out Arc<OpfsVfsInner>.
        *inner
            .weak_self
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::downgrade(&inner);

        Ok(OpfsVfs(inner))
    }

    /// Resolve a virtual VFS path under this VFS's configured root.
    ///
    /// Thin wrapper over [`super::path::join_root`]; see it for the joining
    /// contract (separator handling, empty-root passthrough).
    fn resolve(&self, path: &str) -> String {
        super::path::join_root(&self.0.root, path)
    }

    /// Dispatch a single `OpfsOp` to the worker and await its `OpfsResult`.
    pub(crate) async fn dispatch(&self, op: OpfsOp) -> Result<OpfsResult> {
        let id = self.0.next_request_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel::<OpfsResult>();

        {
            let mut reg = self
                .0
                .request_registry
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            reg.insert(id, tx);
        }

        let req = OpfsRequest { id, op };
        let js_val = serde_wasm_bindgen::to_value(&req).map_err(|e| {
            PagedbError::Io(std::io::Error::other(format!("serialize error: {e:?}")))
        })?;

        self.0.worker.post_message(&js_val).map_err(|e| {
            // Clean up orphaned registry entry on post failure.
            let mut reg = self
                .0
                .request_registry
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            reg.remove(&id);
            PagedbError::Io(std::io::Error::other(format!("{e:?}")))
        })?;

        rx.await.map_err(|_| {
            PagedbError::Io(std::io::Error::other("worker channel closed unexpectedly"))
        })
    }

    /// Return an `Arc` pointing at the inner state.  Used by `open()` to give
    /// each `OpfsFile` a handle back to the vfs for dispatching requests.
    fn arc_inner(&self) -> Option<Arc<OpfsVfsInner>> {
        self.0
            .weak_self
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .upgrade()
    }
}

impl Drop for OpfsVfs {
    fn drop(&mut self) {
        self.0.worker.terminate();
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
                path: self.resolve(path),
                create,
                create_new,
                read_only,
            })
            .await?;

        match result {
            OpfsResult::Opened { handle_id } => {
                let inner_arc = self.arc_inner().ok_or(PagedbError::Unsupported)?;
                Ok(OpfsFile {
                    handle_id,
                    // Wrap inner Arc as OpfsVfs so OpfsFile can call dispatch.
                    vfs: Arc::new(OpfsVfs(inner_arc)),
                    read_only,
                })
            }
            OpfsResult::Err { reason, kind } => Err(map_err(&reason, kind)),
            _ => Err(PagedbError::Unsupported),
        }
    }

    async fn remove(&self, path: &str) -> Result<()> {
        match self
            .dispatch(OpfsOp::Remove {
                path: self.resolve(path),
            })
            .await?
        {
            OpfsResult::Ok => Ok(()),
            OpfsResult::Err { reason, kind } => Err(map_err(&reason, kind)),
            _ => Err(PagedbError::Unsupported),
        }
    }

    async fn rename(&self, from: &str, to: &str) -> Result<()> {
        match self
            .dispatch(OpfsOp::Rename {
                from: self.resolve(from),
                to: self.resolve(to),
            })
            .await?
        {
            OpfsResult::Ok => Ok(()),
            OpfsResult::Err { reason, kind } => Err(map_err(&reason, kind)),
            _ => Err(PagedbError::Unsupported),
        }
    }

    async fn list_dir(&self, path: &str) -> Result<Vec<String>> {
        match self
            .dispatch(OpfsOp::ListDir {
                path: self.resolve(path),
            })
            .await?
        {
            OpfsResult::Entries { names } => Ok(names),
            OpfsResult::Err { reason, kind } => Err(map_err(&reason, kind)),
            _ => Err(PagedbError::Unsupported),
        }
    }

    async fn mkdir_all(&self, path: &str) -> Result<()> {
        match self
            .dispatch(OpfsOp::MkdirAll {
                path: self.resolve(path),
            })
            .await?
        {
            OpfsResult::Ok => Ok(()),
            OpfsResult::Err { reason, kind } => Err(map_err(&reason, kind)),
            _ => Err(PagedbError::Unsupported),
        }
    }

    async fn sync_dir(&self, _path: &str) -> Result<()> {
        // OPFS has no directory sync primitive; durability is implicit after flush.
        Ok(())
    }

    async fn lock_exclusive(&self, path: &str) -> Result<Self::LockHandle> {
        let resolved = self.resolve(path);
        let acquired = self
            .0
            .locks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .try_exclusive(&resolved);
        if acquired {
            Ok(OpfsLockHandle {
                path: resolved,
                locks: Arc::clone(&self.0.locks),
            })
        } else {
            Err(PagedbError::AlreadyLocked)
        }
    }

    async fn lock_shared(&self, path: &str) -> Result<Self::LockHandle> {
        let resolved = self.resolve(path);
        let acquired = self
            .0
            .locks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .try_shared(&resolved);
        if acquired {
            Ok(OpfsLockHandle {
                path: resolved,
                locks: Arc::clone(&self.0.locks),
            })
        } else {
            Err(PagedbError::AlreadyLocked)
        }
    }
}
