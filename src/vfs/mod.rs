//! Virtual file-system abstraction: File trait, lock primitives, vectored I/O.
//!
//! A distinct backend is selected per target so each platform uses its best
//! async-I/O primitive (see [`DefaultVfs`] for the mapping). This module wires
//! the cfg matrix; callers use [`open_default`] or the [`DefaultVfs`] alias
//! and never have to spell the cfg themselves.

#[cfg(all(target_os = "android", target_arch = "arm"))]
pub mod android;
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub mod gcd;
#[cfg(target_os = "windows")]
pub mod iocp;
#[cfg(any(
    target_os = "linux",
    all(target_os = "android", not(target_arch = "arm")),
))]
pub mod iouring;
pub mod memory;
#[cfg(feature = "opfs")]
pub mod opfs;
#[cfg(not(target_arch = "wasm32"))]
pub mod tokio_backend;
pub mod traits;
pub mod types;
pub mod wasi;

#[cfg(all(target_os = "android", target_arch = "arm"))]
pub use android::AndroidVfs;
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub use gcd::GcdVfs;
#[cfg(target_os = "windows")]
pub use iocp::{IocpFile, IocpVfs};
#[cfg(any(
    target_os = "linux",
    all(target_os = "android", not(target_arch = "arm")),
))]
pub use iouring::{IouringFile, IouringVfs};
#[cfg(feature = "opfs")]
pub use opfs::OpfsVfs;
pub use traits::{Vfs, VfsFile};
pub use types::{OpenMode, ReadReq, WriteReq};
pub use wasi::WasiVfs;

/// The default native VFS backend for the current target. Selected at
/// compile-time per platform to use the best async-I/O primitive available:
///
/// - Linux (and 64-bit Android): `IouringVfs` — `io_uring`.
/// - Windows: `IocpVfs` — IOCP overlapped I/O.
/// - macOS / iOS / iPadOS: `GcdVfs` — `dispatch_io`.
/// - Android (32-bit, legacy): `AndroidVfs` — thread-pool.
/// - Other native (BSDs etc.): `TokioVfs` — thread-pool fallback.
///
/// On `wasm32` targets, embedders construct `OpfsVfs` or `WasiVfs` directly
/// — there is no kernel async primitive to choose between.
#[cfg(any(
    target_os = "linux",
    all(target_os = "android", not(target_arch = "arm")),
))]
pub type DefaultVfs = IouringVfs;

#[cfg(target_os = "windows")]
pub type DefaultVfs = IocpVfs;

#[cfg(any(target_os = "macos", target_os = "ios"))]
pub type DefaultVfs = GcdVfs;

#[cfg(all(target_os = "android", target_arch = "arm"))]
pub type DefaultVfs = AndroidVfs;

#[cfg(all(
    not(target_arch = "wasm32"),
    not(target_os = "linux"),
    not(target_os = "windows"),
    not(target_os = "macos"),
    not(target_os = "ios"),
    not(target_os = "android"),
))]
pub type DefaultVfs = tokio_backend::TokioVfs;

/// Construct the best native VFS for the current target. Callers that don't
/// care which backend they're using (benchmarks, CLI tools, embedders that
/// just want "the right thing") should use this — it picks the platform's
/// fastest async-I/O primitive without leaking `cfg` into call sites.
#[cfg(not(target_arch = "wasm32"))]
pub fn open_default<P: AsRef<std::path::Path>>(path: P) -> crate::Result<DefaultVfs> {
    #[cfg(any(
        all(target_os = "linux", not(target_arch = "wasm32")),
        all(target_os = "android", not(target_arch = "arm")),
    ))]
    {
        IouringVfs::new(path.as_ref())
    }
    #[cfg(target_os = "windows")]
    {
        IocpVfs::new(path.as_ref())
    }
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        Ok(GcdVfs::new(path.as_ref()))
    }
    #[cfg(all(target_os = "android", target_arch = "arm"))]
    {
        Ok(AndroidVfs::new(path.as_ref()))
    }
    #[cfg(all(
        not(target_os = "linux"),
        not(target_os = "windows"),
        not(target_os = "macos"),
        not(target_os = "ios"),
        not(target_os = "android"),
    ))]
    {
        Ok(tokio_backend::TokioVfs::new(path.as_ref()))
    }
}
