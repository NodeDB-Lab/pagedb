//! Wire protocol for the OPFS Web Worker.
//!
//! `OpfsRequest` is sent from the main thread to the worker;
//! `OpfsResponse` is sent back.  Both are serialised via `serde-wasm-bindgen`
//! so they cross the `postMessage` boundary as plain JS objects.

#![cfg(all(target_arch = "wasm32", feature = "opfs"))]

use serde::{Deserialize, Serialize};

// ── Request ───────────────────────────────────────────────────────────────────

/// A single request sent to the OPFS worker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpfsRequest {
    /// Monotonically increasing correlation id; the response echoes it.
    pub id: u64,
    pub op: OpfsOp,
}

/// All file-system operations the worker can perform.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
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
    LockExclusive {
        path: String,
    },
    LockShared {
        path: String,
    },
    LockRelease {
        lock_id: u32,
    },
}

// ── Response ──────────────────────────────────────────────────────────────────

/// The worker's reply, correlated by `id`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpfsResponse {
    pub id: u64,
    pub result: OpfsResult,
}

/// The successful or error outcome of an `OpfsOp`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum OpfsResult {
    /// File opened; `handle_id` identifies it in subsequent ops.
    Opened { handle_id: u32 },
    /// Advisory lock acquired; `lock_id` identifies it for release.
    Locked { lock_id: u32 },
    /// Generic success (no payload).
    Ok,
    /// Byte data returned from a read.
    Data { bytes: Vec<u8> },
    /// File size in bytes.
    Size { len: u64 },
    /// Directory entries (names only, not full paths).
    Entries { names: Vec<String> },
    /// Operation failed.
    Err { reason: String, kind: ErrKind },
}

/// Structured error kind so the main thread can map to [`crate::errors::PagedbError`] variants.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ErrKind {
    NotFound,
    AlreadyExists,
    PermissionDenied,
    Io,
    Other,
}
