//! OPFS (Origin Private File System) VFS backend for `wasm32` targets.
//!
//! # Browser-side bootstrap
//!
//! The embedder must register `OpfsWorker` as a dedicated Web Worker entry
//! point before constructing any `OpfsVfs`. A minimal JS shim:
//!
//! ```js
//! // opfs_worker.js  — loaded via new Worker("opfs_worker.js")
//! import init, { run_opfs_worker } from "./pagedb.js";
//! await init();
//! run_opfs_worker();
//! ```
//!
//! `run_opfs_worker` is exported by the embedder crate (not by pagedb itself)
//! and calls `OpfsWorker::registrar().register()`.  The `OpfsVfs` in the main
//! thread opens a bridge to that worker via `OpfsWorker::spawner().spawn(url)`.
//!
//! # Compile gating
//!
//! The full implementation is compiled only for
//! `cfg(all(target_arch = "wasm32", feature = "opfs"))`.  On every other
//! target (or when the `opfs` feature is absent) a thin shim is compiled
//! instead; every method returns [`PagedbError::Unsupported`].

#[cfg(all(target_arch = "wasm32", feature = "opfs"))]
mod handle;
#[cfg(all(target_arch = "wasm32", feature = "opfs"))]
mod worker;

#[cfg(all(target_arch = "wasm32", feature = "opfs"))]
pub use handle::OpfsFile;
#[cfg(all(target_arch = "wasm32", feature = "opfs"))]
pub use worker::OpfsWorker;

#[cfg(all(target_arch = "wasm32", feature = "opfs"))]
mod vfs_impl;

#[cfg(all(target_arch = "wasm32", feature = "opfs"))]
pub use vfs_impl::OpfsVfs;

// ── Native / non-wasm32 shim ──────────────────────────────────────────────────

#[cfg(not(all(target_arch = "wasm32", feature = "opfs")))]
pub use shim::OpfsVfs;

#[cfg(not(all(target_arch = "wasm32", feature = "opfs")))]
mod shim {
    use crate::Result;
    use crate::errors::PagedbError;
    use crate::vfs::traits::{Vfs, VfsFile};
    use crate::vfs::types::{OpenMode, ReadReq, WriteReq};

    /// Placeholder that returns [`PagedbError::Unsupported`] for every call.
    /// Compiled on non-`wasm32` targets or when the `opfs` feature is absent.
    pub struct OpfsVfs {
        _private: (),
    }

    impl OpfsVfs {
        /// Always returns `Err(PagedbError::Unsupported)`.
        pub fn new() -> Result<Self> {
            Err(PagedbError::Unsupported)
        }
    }

    pub struct OpfsFileShim;

    impl VfsFile for OpfsFileShim {
        async fn read_at(&self, _offset: u64, _buf: &mut [u8]) -> Result<usize> {
            Err(PagedbError::Unsupported)
        }
        async fn read_at_vectored(&self, _reqs: &mut [ReadReq<'_>]) -> Result<()> {
            Err(PagedbError::Unsupported)
        }
        async fn write_at(&mut self, _offset: u64, _buf: &[u8]) -> Result<usize> {
            Err(PagedbError::Unsupported)
        }
        async fn write_at_vectored(&mut self, _reqs: &[WriteReq<'_>]) -> Result<()> {
            Err(PagedbError::Unsupported)
        }
        async fn sync(&mut self) -> Result<()> {
            Err(PagedbError::Unsupported)
        }
        async fn truncate(&mut self, _len: u64) -> Result<()> {
            Err(PagedbError::Unsupported)
        }
        async fn len(&self) -> Result<u64> {
            Err(PagedbError::Unsupported)
        }
        async fn is_empty(&self) -> Result<bool> {
            Err(PagedbError::Unsupported)
        }
        fn supports_direct_io(&self) -> bool {
            false
        }
    }

    /// Unreachable lock handle for the native shim.
    ///
    /// The inner `()` is `Send`; no manual `unsafe impl` needed.
    pub struct OpfsLockHandleShim(());

    // `()` is `Send`, so `OpfsLockHandleShim` is trivially `Send` — the derive
    // is implicit through the standard rules; no unsafe block required.

    impl Vfs for OpfsVfs {
        type File = OpfsFileShim;
        type LockHandle = OpfsLockHandleShim;

        async fn open(&self, _path: &str, _mode: OpenMode) -> Result<Self::File> {
            Err(PagedbError::Unsupported)
        }
        async fn remove(&self, _path: &str) -> Result<()> {
            Err(PagedbError::Unsupported)
        }
        async fn rename(&self, _from: &str, _to: &str) -> Result<()> {
            Err(PagedbError::Unsupported)
        }
        async fn list_dir(&self, _path: &str) -> Result<Vec<String>> {
            Err(PagedbError::Unsupported)
        }
        async fn mkdir_all(&self, _path: &str) -> Result<()> {
            Err(PagedbError::Unsupported)
        }
        async fn sync_dir(&self, _path: &str) -> Result<()> {
            Err(PagedbError::Unsupported)
        }
        async fn lock_exclusive(&self, _path: &str) -> Result<Self::LockHandle> {
            Err(PagedbError::Unsupported)
        }
        async fn lock_shared(&self, _path: &str) -> Result<Self::LockHandle> {
            Err(PagedbError::Unsupported)
        }
    }
}
