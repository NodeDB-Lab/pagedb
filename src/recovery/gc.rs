//! Tombstone reclamation. `Db::gc_now` processes pending deferred tombstones
//! (renaming live → tombstone for segments no reader pins) and deletes
//! tombstone files from disk.

use crate::Result;
use crate::vfs::types::OpenMode;
use crate::vfs::{Vfs, VfsFile};

/// Delete all files in `seg/.tombstone/`. Returns `(count, bytes)` where
/// `count` is the number of files deleted and `bytes` is the sum of their
/// pre-deletion sizes.
pub async fn delete_tombstone_files<V: Vfs + Clone>(vfs: &V) -> Result<(u64, u64)> {
    let mut count: u64 = 0;
    let mut bytes: u64 = 0;
    let entries = vfs.list_dir("seg/.tombstone").await?;
    for name in entries {
        let path = format!("seg/.tombstone/{name}");
        let file = vfs.open(&path, OpenMode::Read).await?;
        bytes = bytes.saturating_add(file.len().await?);
        vfs.remove(&path).await?;
        count += 1;
    }
    if count > 0 {
        // Make the directory-entry removals durable so that a subsequent open
        // does not re-count deleted tombstones as live segment bytes.
        vfs.sync_dir("seg/.tombstone").await?;
    }
    Ok((count, bytes))
}
