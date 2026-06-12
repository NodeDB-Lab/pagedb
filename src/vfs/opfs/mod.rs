//! OPFS (Origin Private File System) VFS backend for `wasm32` targets.
//!
//! # Browser-side bootstrap
//!
//! The embedder must serve `opfs_worker.js` at a URL the browser can load as
//! a dedicated Web Worker. The JS source is embedded in this crate and
//! accessible via [`OPFS_WORKER_JS`]. A minimal bootstrap:
//!
//! ```js
//! // Write OPFS_WORKER_JS to a blob URL or serve it statically, then:
//! const vfs = await openPersistent("/myapp", workerUrl);
//! ```
//!
//! The worker is pure JS — it does **not** load any wasm module.
//!
//! # Compile gating
//!
//! The full implementation is compiled only for
//! `cfg(all(target_arch = "wasm32", feature = "opfs"))`. On every other
//! target (or when the `opfs` feature is absent) a thin shim is compiled
//! instead; every method returns [`crate::errors::PagedbError::Unsupported`].

// Pure path-rooting helpers — target-independent so they are unit-testable on
// the host even though the OPFS backend itself is wasm-only.
mod path;

#[cfg(all(target_arch = "wasm32", feature = "opfs"))]
mod handle;
#[cfg(all(target_arch = "wasm32", feature = "opfs"))]
mod lock;
#[cfg(all(target_arch = "wasm32", feature = "opfs"))]
mod protocol;
#[cfg(all(target_arch = "wasm32", feature = "opfs"))]
mod vfs_impl;

#[cfg(all(target_arch = "wasm32", feature = "opfs"))]
pub use handle::OpfsFile;
#[cfg(all(target_arch = "wasm32", feature = "opfs"))]
pub use lock::OpfsLockHandle;
#[cfg(all(target_arch = "wasm32", feature = "opfs"))]
pub use vfs_impl::OpfsVfs;

/// Embedded source of the pure-JS OPFS Web Worker.
///
/// Embedders can write this to a `Blob` URL or serve it statically and pass
/// the resulting URL to [`OpfsVfs::new`].
#[cfg(all(target_arch = "wasm32", feature = "opfs"))]
pub const OPFS_WORKER_JS: &str = include_str!("opfs_worker.js");

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
        pub fn new(_worker_url: &str) -> Result<Self> {
            Err(PagedbError::Unsupported)
        }

        /// Always returns `Err(PagedbError::Unsupported)`.
        pub fn with_root(_worker_url: &str, _root: &str) -> Result<Self> {
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
    pub struct OpfsLockHandleShim(());

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
