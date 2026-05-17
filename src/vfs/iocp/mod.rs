//! Windows IOCP backend: overlapped I/O (`ReadFile` / `WriteFile` with
//! `OVERLAPPED`, completions reaped via `GetQueuedCompletionStatus`). Segment
//! files open with `FILE_SHARE_DELETE` so tombstone-rename protocols succeed
//! against held handles.

pub mod file;
pub mod port;
pub mod vfs;

pub use file::IocpFile;
pub use vfs::{IocpLockHandle, IocpVfs};
