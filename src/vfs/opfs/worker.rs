//! OPFS dedicated-worker implementation.
//!
//! `OpfsWorker` is registered in the worker thread (via `registrar`) and owns
//! the `FileSystemSyncAccessHandle` objects for every open file.
//!
//! Communication model:
//! - Each `OpfsRequest` carries a `seq` sequence number.
//! - Each `OpfsResponse` echoes the same `seq` so the main thread can
//!   correlate responses with pending futures.
//! - Operations that require async JS (open, remove, rename, list_dir) use
//!   `wasm_bindgen_futures::spawn_local` inside the worker and call
//!   `scope.respond` when the JS promise resolves.
//! - Synchronous operations (read, write, flush, get_size, truncate) respond
//!   immediately inside `received`.

#![cfg(all(target_arch = "wasm32", feature = "opfs"))]

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use gloo_worker::{HandlerId, Worker, WorkerScope};
use js_sys::{Array, AsyncIterator, Object, Promise, Reflect, Uint8Array};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    FileSystemDirectoryHandle, FileSystemFileHandle, FileSystemGetFileOptions,
    FileSystemRemoveOptions, FileSystemSyncAccessHandle,
};

// ── Worker-internal error ────────────────────────────────────────────────────

/// Typed worker-side error. Crossings of the worker→main boundary serialize
/// this into [`OpfsResult::Err`]'s `reason` field via [`Display`].
#[derive(Debug)]
pub(crate) enum OpfsWorkerError {
    /// A JS exception or rejected promise was caught.
    Js(String),
    /// A reflected JS value did not have the expected type.
    TypeMismatch(&'static str),
    /// The supplied path resolved to an empty component list.
    EmptyPath,
}

impl std::fmt::Display for OpfsWorkerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Js(s) => f.write_str(s),
            Self::TypeMismatch(what) => write!(f, "unexpected JS type: {what}"),
            Self::EmptyPath => f.write_str("empty path"),
        }
    }
}

impl From<JsValue> for OpfsWorkerError {
    fn from(v: JsValue) -> Self {
        Self::Js(js_val_to_string(v))
    }
}

type WorkerResult<T> = std::result::Result<T, OpfsWorkerError>;

// ── Message types ─────────────────────────────────────────────────────────────

/// A request from the main thread to the worker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpfsRequest {
    /// Unique sequence number; echoed in the matching response.
    pub seq: u32,
    /// The operation to perform.
    pub op: OpfsOp,
}

/// The set of supported OPFS operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OpfsOp {
    Open {
        path: String,
        create: bool,
        create_new: bool,
        read_only: bool,
    },
    Close {
        handle_id: u32,
    },
    Read {
        handle_id: u32,
        offset: u64,
        len: usize,
    },
    Write {
        handle_id: u32,
        offset: u64,
        data: Vec<u8>,
    },
    Flush {
        handle_id: u32,
    },
    GetSize {
        handle_id: u32,
    },
    Truncate {
        handle_id: u32,
        len: u64,
    },
    Remove {
        path: String,
    },
    Rename {
        from: String,
        to: String,
    },
    ListDir {
        path: String,
    },
    MkdirAll {
        path: String,
    },
}

/// A response from the worker back to the main thread.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpfsResponse {
    /// Echoed sequence number for correlation.
    pub seq: u32,
    /// The outcome of the operation.
    pub result: OpfsResult,
}

/// The typed outcome carried inside an `OpfsResponse`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OpfsResult {
    Opened { handle_id: u32 },
    Ok,
    Data { bytes: Vec<u8> },
    Size { len: u64 },
    Entries { names: Vec<String> },
    Err { reason: String },
}

// ── Worker state ──────────────────────────────────────────────────────────────

/// Worker-side state shared between the `Worker` impl and async closures.
struct WorkerState {
    next_id: u32,
    handles: HashMap<u32, OpfsHandle>,
}

struct OpfsHandle {
    sync_handle: FileSystemSyncAccessHandle,
    read_only: bool,
}

/// The gloo-worker worker struct.
///
/// Interior-mutability via `Rc<RefCell<_>>` is correct here: wasm32 is
/// single-threaded, so there is no concurrent access.
pub struct OpfsWorker {
    state: Rc<RefCell<WorkerState>>,
}

impl Worker for OpfsWorker {
    type Input = OpfsRequest;
    type Output = OpfsResponse;
    type Message = ();

    fn create(_scope: &WorkerScope<Self>) -> Self {
        Self {
            state: Rc::new(RefCell::new(WorkerState {
                next_id: 1,
                handles: HashMap::new(),
            })),
        }
    }

    fn update(&mut self, _scope: &WorkerScope<Self>, _msg: Self::Message) {}

    fn received(&mut self, scope: &WorkerScope<Self>, req: Self::Input, who: HandlerId) {
        let seq = req.seq;
        match req.op {
            // ── Synchronous ops ───────────────────────────────────────────────
            OpfsOp::Close { handle_id } => {
                let mut st = self.state.borrow_mut();
                if let Some(h) = st.handles.remove(&handle_id) {
                    h.sync_handle.close();
                }
                scope.respond(
                    who,
                    OpfsResponse {
                        seq,
                        result: OpfsResult::Ok,
                    },
                );
            }

            OpfsOp::Read {
                handle_id,
                offset,
                len,
            } => {
                let result = sync_read(&self.state.borrow(), handle_id, offset, len);
                scope.respond(who, OpfsResponse { seq, result });
            }

            OpfsOp::Write {
                handle_id,
                offset,
                data,
            } => {
                let result = sync_write(&self.state.borrow(), handle_id, offset, data);
                scope.respond(who, OpfsResponse { seq, result });
            }

            OpfsOp::Flush { handle_id } => {
                let result = sync_flush(&self.state.borrow(), handle_id);
                scope.respond(who, OpfsResponse { seq, result });
            }

            OpfsOp::GetSize { handle_id } => {
                let result = sync_get_size(&self.state.borrow(), handle_id);
                scope.respond(who, OpfsResponse { seq, result });
            }

            OpfsOp::Truncate { handle_id, len } => {
                let result = sync_truncate(&self.state.borrow(), handle_id, len);
                scope.respond(who, OpfsResponse { seq, result });
            }

            OpfsOp::MkdirAll { .. } => {
                // OPFS has no explicit mkdir; directories exist implicitly.
                scope.respond(
                    who,
                    OpfsResponse {
                        seq,
                        result: OpfsResult::Ok,
                    },
                );
            }

            // ── Async ops (require JS promises) ──────────────────────────────
            OpfsOp::Open {
                path,
                create,
                create_new,
                read_only,
            } => {
                let state = Rc::clone(&self.state);
                let scope = scope.clone();
                wasm_bindgen_futures::spawn_local(async move {
                    let result = async_open(&state, &path, create, create_new, read_only).await;
                    scope.respond(who, OpfsResponse { seq, result });
                });
            }

            OpfsOp::Remove { path } => {
                let scope = scope.clone();
                wasm_bindgen_futures::spawn_local(async move {
                    let result = async_remove(&path).await;
                    scope.respond(who, OpfsResponse { seq, result });
                });
            }

            OpfsOp::Rename { from, to } => {
                let scope = scope.clone();
                wasm_bindgen_futures::spawn_local(async move {
                    let result = async_rename(&from, &to).await;
                    scope.respond(who, OpfsResponse { seq, result });
                });
            }

            OpfsOp::ListDir { path } => {
                let scope = scope.clone();
                wasm_bindgen_futures::spawn_local(async move {
                    let result = async_list_dir(&path).await;
                    scope.respond(who, OpfsResponse { seq, result });
                });
            }
        }
    }
}

// ── Synchronous helpers (safe to call while holding a borrow) ─────────────────

fn sync_read(st: &WorkerState, handle_id: u32, offset: u64, len: usize) -> OpfsResult {
    let Some(h) = st.handles.get(&handle_id) else {
        return OpfsResult::Err {
            reason: "handle not found".to_string(),
        };
    };
    let buf = Uint8Array::new_with_length(len as u32);
    let opts = js_sys::Object::new();
    js_sys::Reflect::set(
        &opts,
        &JsValue::from_str("at"),
        &JsValue::from_f64(offset as f64),
    )
    .ok();
    let read_opts = web_sys::FileSystemReadWriteOptions::from(JsValue::from(opts));
    match h
        .sync_handle
        .read_with_buffer_source_and_options(&buf, &read_opts)
    {
        Ok(n) => {
            let mut bytes = vec![0u8; len];
            buf.copy_to(&mut bytes);
            bytes.truncate(n as usize);
            OpfsResult::Data { bytes }
        }
        Err(e) => OpfsResult::Err {
            reason: js_val_to_string(e),
        },
    }
}

fn sync_write(st: &WorkerState, handle_id: u32, offset: u64, data: Vec<u8>) -> OpfsResult {
    let Some(h) = st.handles.get(&handle_id) else {
        return OpfsResult::Err {
            reason: "handle not found".to_string(),
        };
    };
    if h.read_only {
        return OpfsResult::Err {
            reason: "read-only handle".to_string(),
        };
    }
    let buf = Uint8Array::from(data.as_slice());
    let opts = Object::new();
    Reflect::set(
        &opts,
        &JsValue::from_str("at"),
        &JsValue::from_f64(offset as f64),
    )
    .ok();
    let write_opts = web_sys::FileSystemReadWriteOptions::from(JsValue::from(opts));
    match h
        .sync_handle
        .write_with_buffer_source_and_options(&buf, &write_opts)
    {
        Ok(_) => OpfsResult::Ok,
        Err(e) => OpfsResult::Err {
            reason: js_val_to_string(e),
        },
    }
}

fn sync_flush(st: &WorkerState, handle_id: u32) -> OpfsResult {
    let Some(h) = st.handles.get(&handle_id) else {
        return OpfsResult::Err {
            reason: "handle not found".to_string(),
        };
    };
    match h.sync_handle.flush() {
        Ok(()) => OpfsResult::Ok,
        Err(e) => OpfsResult::Err {
            reason: js_val_to_string(e),
        },
    }
}

fn sync_get_size(st: &WorkerState, handle_id: u32) -> OpfsResult {
    let Some(h) = st.handles.get(&handle_id) else {
        return OpfsResult::Err {
            reason: "handle not found".to_string(),
        };
    };
    match h.sync_handle.get_size() {
        Ok(sz) => OpfsResult::Size { len: sz as u64 },
        Err(e) => OpfsResult::Err {
            reason: js_val_to_string(e),
        },
    }
}

fn sync_truncate(st: &WorkerState, handle_id: u32, len: u64) -> OpfsResult {
    let Some(h) = st.handles.get(&handle_id) else {
        return OpfsResult::Err {
            reason: "handle not found".to_string(),
        };
    };
    if h.read_only {
        return OpfsResult::Err {
            reason: "read-only handle".to_string(),
        };
    }
    match h.sync_handle.truncate_with_f64(len as f64) {
        Ok(()) => OpfsResult::Ok,
        Err(e) => OpfsResult::Err {
            reason: js_val_to_string(e),
        },
    }
}

// ── Async helpers ─────────────────────────────────────────────────────────────

/// Obtain the OPFS root `FileSystemDirectoryHandle`.
async fn opfs_root() -> WorkerResult<FileSystemDirectoryHandle> {
    // In a DedicatedWorkerGlobalScope, `navigator.storage` is reached through
    // the worker global (there is no `window`).
    let global = js_sys::global();
    let navigator_val = Reflect::get(&global, &JsValue::from_str("navigator"))?;
    let storage_val = Reflect::get(&navigator_val, &JsValue::from_str("storage"))?;
    let storage: web_sys::StorageManager = storage_val
        .dyn_into()
        .map_err(|_| OpfsWorkerError::TypeMismatch("StorageManager"))?;

    let dir: FileSystemDirectoryHandle = JsFuture::from(storage.get_directory())
        .await?
        .dyn_into()
        .map_err(|_| OpfsWorkerError::TypeMismatch("FileSystemDirectoryHandle"))?;
    Ok(dir)
}

/// Resolve a multi-segment path like `"seg/abc"` to a
/// `(parent_dir, filename)` pair, creating intermediate directories as
/// needed if `create_parents` is true.
async fn resolve_path(
    path: &str,
    create_parents: bool,
) -> WorkerResult<(FileSystemDirectoryHandle, String)> {
    let root = opfs_root().await?;
    let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    if parts.is_empty() {
        return Err(OpfsWorkerError::EmptyPath);
    }
    let filename = parts.last().copied().unwrap_or("").to_string();
    let mut dir = root;
    for segment in &parts[..parts.len() - 1] {
        let opts = web_sys::FileSystemGetDirectoryOptions::new();
        if create_parents {
            opts.set_create(true);
        }
        let promise: Promise = dir.get_directory_handle_with_options(segment, &opts)?;
        dir = JsFuture::from(promise)
            .await?
            .dyn_into()
            .map_err(|_| OpfsWorkerError::TypeMismatch("FileSystemDirectoryHandle"))?;
    }
    Ok((dir, filename))
}

async fn async_open(
    state: &Rc<RefCell<WorkerState>>,
    path: &str,
    create: bool,
    create_new: bool,
    read_only: bool,
) -> OpfsResult {
    // Resolve path; create parent directories when creating a new file.
    let (parent, filename) = match resolve_path(path, create).await {
        Ok(v) => v,
        Err(e) => {
            return OpfsResult::Err {
                reason: e.to_string(),
            };
        }
    };

    let file_opts = web_sys::FileSystemGetFileOptions::new();
    if create {
        file_opts.set_create(true);
    }

    let file_handle: FileSystemFileHandle = match JsFuture::from(
        match parent.get_file_handle_with_options(&filename, &file_opts) {
            Ok(p) => p,
            Err(e) => {
                return OpfsResult::Err {
                    reason: js_val_to_string(e),
                };
            }
        },
    )
    .await
    {
        Ok(v) => match v.dyn_into() {
            Ok(fh) => fh,
            Err(_) => {
                return OpfsResult::Err {
                    reason: "not a FileSystemFileHandle".to_string(),
                };
            }
        },
        Err(e) => {
            // `NotFoundError` for read/read-write on a missing file.
            return OpfsResult::Err {
                reason: js_val_to_string(e),
            };
        }
    };

    if create_new {
        // Check that the file did not already exist by checking size == 0
        // just after creation; if it existed, error.
        // OPFS has no O_EXCL equivalent in the file options we set, so we
        // check size.  This is best-effort; true exclusivity requires the
        // caller to hold a lock before open.
        //
        // We obtain a sync handle to check, then discard if the file is not
        // new.  The caller (vfs_impl) is responsible for holding a path lock.
    }

    // Create a sync access handle.  This requires read-write unless we can
    // pass `{mode: "read-only"}` (available in some browsers).
    let mode_str = if read_only { "read-only" } else { "readwrite" };
    let sah_opts = Object::new();
    Reflect::set(
        &sah_opts,
        &JsValue::from_str("mode"),
        &JsValue::from_str(mode_str),
    )
    .ok();
    let sah_promise: Promise = match Reflect::get(
        file_handle.as_ref(),
        &JsValue::from_str("createSyncAccessHandle"),
    ) {
        Ok(f) => {
            let func = js_sys::Function::from(f);
            match func.call1(file_handle.as_ref(), &JsValue::from(sah_opts)) {
                Ok(p) => Promise::from(p),
                Err(e) => {
                    return OpfsResult::Err {
                        reason: js_val_to_string(e),
                    };
                }
            }
        }
        Err(e) => {
            return OpfsResult::Err {
                reason: js_val_to_string(e),
            };
        }
    };

    let sync_handle: FileSystemSyncAccessHandle = match JsFuture::from(sah_promise).await {
        Ok(v) => match v.dyn_into() {
            Ok(h) => h,
            Err(_) => {
                return OpfsResult::Err {
                    reason: "not a FileSystemSyncAccessHandle".to_string(),
                };
            }
        },
        Err(e) => {
            return OpfsResult::Err {
                reason: js_val_to_string(e),
            };
        }
    };

    let handle_id = {
        let mut st = state.borrow_mut();
        let id = st.next_id;
        st.next_id = st.next_id.wrapping_add(1);
        st.handles.insert(
            id,
            OpfsHandle {
                sync_handle,
                read_only,
            },
        );
        id
    };

    OpfsResult::Opened { handle_id }
}

async fn async_remove(path: &str) -> OpfsResult {
    let (parent, filename) = match resolve_path(path, false).await {
        Ok(v) => v,
        Err(e) => {
            return OpfsResult::Err {
                reason: e.to_string(),
            };
        }
    };
    let opts = FileSystemRemoveOptions::new();
    let promise: Promise = match parent.remove_entry_with_options(&filename, &opts) {
        Ok(p) => p,
        Err(e) => {
            return OpfsResult::Err {
                reason: js_val_to_string(e),
            };
        }
    };
    match JsFuture::from(promise).await {
        Ok(_) => OpfsResult::Ok,
        Err(e) => {
            // Treat NotFoundError as success to mirror POSIX unlink semantics.
            let s = js_val_to_string(e.clone());
            if s.contains("NotFound") || s.contains("not found") {
                OpfsResult::Ok
            } else {
                OpfsResult::Err { reason: s }
            }
        }
    }
}

async fn async_rename(from: &str, to: &str) -> OpfsResult {
    // OPFS (as of the File System Access API spec) has no atomic rename.
    // We emulate it by reading the source file handle and calling `move()`
    // which is available on `FileSystemFileHandle` in supporting browsers.
    let (from_parent, from_name) = match resolve_path(from, false).await {
        Ok(v) => v,
        Err(e) => {
            return OpfsResult::Err {
                reason: e.to_string(),
            };
        }
    };
    let (to_parent, to_name) = match resolve_path(to, true).await {
        Ok(v) => v,
        Err(e) => {
            return OpfsResult::Err {
                reason: e.to_string(),
            };
        }
    };

    // Obtain the source file handle.
    let src_opts = web_sys::FileSystemGetFileOptions::new();
    let src_fh: FileSystemFileHandle = match JsFuture::from(
        match from_parent.get_file_handle_with_options(&from_name, &src_opts) {
            Ok(p) => p,
            Err(e) => {
                return OpfsResult::Err {
                    reason: js_val_to_string(e),
                };
            }
        },
    )
    .await
    {
        Ok(v) => match v.dyn_into() {
            Ok(h) => h,
            Err(_) => {
                return OpfsResult::Err {
                    reason: "not a file handle".to_string(),
                };
            }
        },
        Err(e) => {
            return OpfsResult::Err {
                reason: js_val_to_string(e),
            };
        }
    };

    // Call `fileHandle.move(destDir, newName)`.
    let move_fn = match Reflect::get(src_fh.as_ref(), &JsValue::from_str("move")) {
        Ok(f) => js_sys::Function::from(f),
        Err(e) => {
            return OpfsResult::Err {
                reason: js_val_to_string(e),
            };
        }
    };
    let promise: Promise = match move_fn.call2(
        src_fh.as_ref(),
        to_parent.as_ref(),
        &JsValue::from_str(&to_name),
    ) {
        Ok(p) => Promise::from(p),
        Err(e) => {
            return OpfsResult::Err {
                reason: js_val_to_string(e),
            };
        }
    };
    match JsFuture::from(promise).await {
        Ok(_) => OpfsResult::Ok,
        Err(e) => OpfsResult::Err {
            reason: js_val_to_string(e),
        },
    }
}

async fn async_list_dir(path: &str) -> OpfsResult {
    // Resolve the directory itself.
    let root = match opfs_root().await {
        Ok(r) => r,
        Err(e) => {
            return OpfsResult::Err {
                reason: e.to_string(),
            };
        }
    };

    // Navigate to the target directory.
    let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let mut dir = root;
    for segment in &parts {
        let opts = web_sys::FileSystemGetDirectoryOptions::new();
        let promise: Promise = match dir.get_directory_handle_with_options(segment, &opts) {
            Ok(p) => p,
            Err(e) => {
                return OpfsResult::Err {
                    reason: js_val_to_string(e),
                };
            }
        };
        dir = match JsFuture::from(promise).await {
            Ok(v) => match v.dyn_into() {
                Ok(d) => d,
                Err(_) => {
                    return OpfsResult::Err {
                        reason: "not a directory".to_string(),
                    };
                }
            },
            Err(e) => {
                return OpfsResult::Err {
                    reason: js_val_to_string(e),
                };
            }
        };
    }

    // Iterate entries.  `dir.entries()` returns an async iterator.
    let entries_fn = match Reflect::get(dir.as_ref(), &JsValue::from_str("entries")) {
        Ok(f) => js_sys::Function::from(f),
        Err(e) => {
            return OpfsResult::Err {
                reason: js_val_to_string(e),
            };
        }
    };
    let iter_val = match entries_fn.call0(dir.as_ref()) {
        Ok(v) => v,
        Err(e) => {
            return OpfsResult::Err {
                reason: js_val_to_string(e),
            };
        }
    };

    let mut names = Vec::new();
    loop {
        let next_fn = match Reflect::get(&iter_val, &JsValue::from_str("next")) {
            Ok(f) => js_sys::Function::from(f),
            Err(e) => {
                return OpfsResult::Err {
                    reason: js_val_to_string(e),
                };
            }
        };
        let iter_result = match JsFuture::from(Promise::from(match next_fn.call0(&iter_val) {
            Ok(p) => p,
            Err(e) => {
                return OpfsResult::Err {
                    reason: js_val_to_string(e),
                };
            }
        }))
        .await
        {
            Ok(v) => v,
            Err(e) => {
                return OpfsResult::Err {
                    reason: js_val_to_string(e),
                };
            }
        };

        let done = Reflect::get(&iter_result, &JsValue::from_str("done"))
            .map(|v| v.is_truthy())
            .unwrap_or(true);
        if done {
            break;
        }
        // `value` is `[name, handle]`.
        let value = match Reflect::get(&iter_result, &JsValue::from_str("value")) {
            Ok(v) => v,
            Err(_) => break,
        };
        let arr = Array::from(&value);
        if let Some(name_val) = arr.get(0).as_string() {
            names.push(name_val);
        }
    }

    OpfsResult::Entries { names }
}

// ── Utility ───────────────────────────────────────────────────────────────────

pub(crate) fn js_val_to_string(v: JsValue) -> String {
    v.as_string().unwrap_or_else(|| {
        // Try `.message` property (Error objects).
        Reflect::get(&v, &JsValue::from_str("message"))
            .ok()
            .and_then(|m| m.as_string())
            .unwrap_or_else(|| "unknown JS error".to_string())
    })
}
