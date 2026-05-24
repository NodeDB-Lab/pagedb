//! Snapshot export and incremental restore: full and delta transfer across DB instances.

#[cfg(not(target_arch = "wasm32"))]
pub mod apply;
#[cfg(not(target_arch = "wasm32"))]
pub mod export;

/// Statistics returned by a full or incremental snapshot export operation.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotStats {
    /// Number of main.db pages written to the snapshot (for incremental:
    /// changed pages only; for full: all data pages).
    pub pages_written: u64,
    /// Number of segment files included in the snapshot.
    pub segments_written: u32,
    /// Total bytes written to the snapshot directory (manifest + main.db + segments).
    pub bytes: u64,
}

/// Statistics returned by `apply_incremental`.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyStats {
    /// Number of main.db pages written into the Follower.
    pub pages_applied: u64,
    /// Number of segment files promoted from the incremental snapshot.
    pub segments_promoted: u32,
    /// Number of segments tombstoned on the Follower as a result of this apply.
    pub segments_tombstoned: u32,
}
