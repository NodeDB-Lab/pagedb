//! Reclamation of write-transaction spill scratch.
//!
//! A spill file is scratch for one live write transaction and is never read
//! back by a later one: its key is scoped to the open handle that wrote it. So
//! every scratch file present at open belongs to a handle that is already gone,
//! and is reclaimable without inspection.

use crate::Result;
use crate::vfs::Vfs;

/// Directory holding per-transaction spill scratch.
const SCRATCH_DIR: &str = "tmp";

/// Prefix of a spill scratch file name, completed by the transaction sequence.
const SCRATCH_PREFIX: &str = "scratch-";

/// Delete the spill scratch left by handles that closed without cleaning up.
///
/// Callers must hold write authority over the store: this removes files, and a
/// handle that only observes must not. Returns the number of files deleted.
pub async fn delete_orphaned_scratch<V: Vfs + Clone>(vfs: &V) -> Result<u64> {
    let entries = vfs.list_dir(SCRATCH_DIR).await?;
    let mut count: u64 = 0;
    for name in entries {
        // Only the names this crate writes. `tmp/` is a shared directory in the
        // store layout, and a sweep that removed everything under it would
        // reclaim files belonging to whatever is added there next.
        if !name.starts_with(SCRATCH_PREFIX) {
            continue;
        }
        vfs.remove(&format!("{SCRATCH_DIR}/{name}")).await?;
        count += 1;
    }
    if count > 0 {
        // Durable directory entries: a crash between here and the next open
        // would otherwise present the same scratch to be swept again.
        vfs.sync_dir(SCRATCH_DIR).await?;
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vfs::VfsFile;
    use crate::vfs::memory::MemVfs;
    use crate::vfs::types::OpenMode;

    async fn write(vfs: &MemVfs, path: &str) {
        vfs.mkdir_all(SCRATCH_DIR).await.unwrap();
        let mut f = vfs.open(path, OpenMode::CreateNew).await.unwrap();
        f.write_at(0, b"scratch").await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn sweeps_scratch_and_spares_unrelated_names() {
        let vfs = MemVfs::new();
        write(&vfs, "tmp/scratch-1").await;
        write(&vfs, "tmp/scratch-9").await;
        write(&vfs, "tmp/unrelated").await;

        assert_eq!(delete_orphaned_scratch(&vfs).await.unwrap(), 2);

        assert!(vfs.open("tmp/scratch-1", OpenMode::Read).await.is_err());
        assert!(vfs.open("tmp/scratch-9", OpenMode::Read).await.is_err());
        assert!(vfs.open("tmp/unrelated", OpenMode::Read).await.is_ok());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn absent_scratch_directory_is_not_an_error() {
        let vfs = MemVfs::new();
        assert_eq!(delete_orphaned_scratch(&vfs).await.unwrap(), 0);
    }
}
