//! macOS / iOS / iPadOS backend using Grand Central Dispatch I/O.
//!
//! Each open file owns a `DispatchIO` channel in `DISPATCH_IO_RANDOM` mode;
//! reads and writes go through `dispatch_io_read` / `dispatch_io_write` with
//! block handlers bridged to tokio oneshots. `fsync` and `ftruncate` use raw
//! libc — `dispatch_io` has no equivalent.

pub mod file;
pub mod vfs;

pub use file::GcdFile;
pub use vfs::{GcdLockHandle, GcdVfs};
