//! Virtual file-system abstraction: File trait, lock primitives, vectored I/O.

#[cfg(target_os = "linux")]
pub mod iouring;
pub mod memory;
#[cfg(feature = "opfs")]
pub mod opfs;
pub mod tokio_backend;
pub mod traits;
pub mod types;
pub mod wasi;

#[cfg(target_os = "linux")]
pub use iouring::{IouringFile, IouringVfs};
#[cfg(feature = "opfs")]
pub use opfs::OpfsVfs;
pub use traits::{Vfs, VfsFile};
pub use types::{OpenMode, ReadReq, WriteReq};
pub use wasi::WasiVfs;

/// The default native VFS backend for the current target. Selected at
/// compile-time per platform to use the best async-I/O primitive available
/// (architecture.md §§855–866):
///
/// - Linux: `IouringVfs` — `io_uring` submission/completion.
/// - All other native targets: `TokioVfs` — thread-pool fallback.
///
/// On `wasm32` targets, embedders construct `OpfsVfs` or `WasiVfs` directly
/// — there is no kernel async primitive to choose between.
#[cfg(target_os = "linux")]
pub type DefaultVfs = IouringVfs;
#[cfg(all(not(target_os = "linux"), not(target_arch = "wasm32")))]
pub type DefaultVfs = tokio_backend::TokioVfs;

/// Construct the best native VFS for the current target. Callers that don't
/// care which backend they're using (benchmarks, CLI tools, embedders that
/// just want "the right thing") should use this — it picks the platform's
/// fastest async-I/O primitive without leaking `cfg` into call sites.
///
/// On Linux: opens an `IouringVfs` (`io_uring` submission/completion).
/// Elsewhere: opens a `TokioVfs` (thread-pool fallback).
#[cfg(not(target_arch = "wasm32"))]
pub fn open_default<P: AsRef<std::path::Path>>(path: P) -> crate::Result<DefaultVfs> {
    #[cfg(target_os = "linux")]
    {
        IouringVfs::new(path.as_ref())
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(tokio_backend::TokioVfs::new(path.as_ref()))
    }
}
