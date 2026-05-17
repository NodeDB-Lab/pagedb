//! Handle modes and sentinel-lock paths.

/// The operating mode of an open `Db` handle.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DbMode {
    /// Full read/write writer. Holds exclusive `.writer.lock`.
    Standalone,
    /// Apply-incremental writer (no user writes). Holds exclusive `.writer.lock`.
    Follower,
    /// Read-only on a frozen-snapshot directory. Holds shared `.frozen_readers.lock`.
    ReadOnly,
    /// Best-effort read-only on a directory where a writer may be active.
    /// Holds shared `.observers.lock`.
    Observer,
}

pub const WRITER_LOCK_PATH: &str = ".writer.lock";
pub const FROZEN_READERS_LOCK_PATH: &str = ".frozen_readers.lock";
pub const OBSERVERS_LOCK_PATH: &str = ".observers.lock";
