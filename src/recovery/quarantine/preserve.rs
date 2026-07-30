//! Moving a store aside so a corruption can still be diagnosed after the
//! process that met it has moved on.
//!
//! A store that will not open is the only evidence of why it will not open.
//! Recovery paths that delete it and start again — the obvious thing to do when
//! an application must come back up — destroy the one artifact that could have
//! named the fault, and every later instance of the same fault is equally
//! unanalysable. That has happened, which is why this exists.
//!
//! pagedb never deletes a store itself, and this does not either: it renames.
//! The caller decides when to invoke it, because only the caller knows whether
//! coming back up matters more than the bytes; what this removes is the excuse
//! that preserving them was inconvenient.
//!
//! Deliberately not automatic on a failed open. Moving a user's data without
//! being asked is its own surprise, and an application that wants the old
//! behaviour can still delete afterwards — having had the chance not to.

use crate::Result;
use crate::errors::PagedbError;
use crate::vfs::Vfs;

/// Where a quarantined store went, and what moved.
#[derive(Debug, Clone)]
pub struct QuarantineReport {
    /// Directory the store now occupies, relative to the VFS root.
    pub directory: String,
    /// Entries moved into it.
    pub preserved: Vec<String>,
}

/// Move every file of the store rooted at `store_dir` into
/// `<store_dir>/quarantine/<label>/`, leaving the original paths empty.
///
/// `label` distinguishes one quarantine from the next; a caller with a clock
/// should pass a timestamp, and one without should pass something else unique.
/// An existing directory of that name is an error rather than a merge: two
/// corruptions interleaved in one directory are worse evidence than either
/// alone.
///
/// Returns what was preserved so the caller can log a path a human can act on.
/// The store directory is left in place and empty, so a subsequent open creates
/// a fresh store exactly as it would have after a delete — the difference is
/// that the old bytes still exist.
pub async fn quarantine_store<V: Vfs>(
    vfs: &V,
    store_dir: &str,
    label: &str,
) -> Result<QuarantineReport> {
    if label.is_empty() || label.contains('/') {
        return Err(PagedbError::Io(std::io::Error::other(
            "quarantine label must be a single non-empty path component",
        )));
    }
    let root = store_dir.trim_end_matches('/');
    let directory = format!("{root}/quarantine/{label}");

    // A destination that already holds something means a previous quarantine
    // used this label. Merging two corruptions into one directory would leave
    // neither interpretable, so this refuses rather than choosing for the
    // caller. An empty or absent directory is fine — backends differ on
    // whether listing a missing path is an error, and neither answer means the
    // label was used.
    if vfs
        .list_dir(&directory)
        .await
        .is_ok_and(|entries| !entries.is_empty())
    {
        return Err(PagedbError::Io(std::io::Error::other(
            "quarantine label already used; choose another",
        )));
    }
    vfs.mkdir_all(&directory).await?;

    let mut preserved = Vec::new();
    for entry in vfs.list_dir(root).await? {
        // Never fold the quarantine directory into itself.
        if entry == "quarantine" {
            continue;
        }
        let from = format!("{root}/{entry}");
        let to = format!("{directory}/{entry}");
        vfs.rename(&from, &to).await?;
        preserved.push(entry);
    }

    // The moves must outlive this call: a quarantine that evaporates on power
    // loss preserves nothing, and the reason to quarantine at all is that
    // something is already wrong.
    vfs.sync_dir(&directory).await?;
    vfs.sync_dir(root).await?;

    Ok(QuarantineReport {
        directory,
        preserved,
    })
}

#[cfg(test)]
mod tests {
    use super::quarantine_store;
    use crate::vfs::memory::MemVfs;
    use crate::vfs::types::OpenMode;
    use crate::vfs::{Vfs, VfsFile};

    async fn store_with_files(names: &[&str]) -> MemVfs {
        let vfs = MemVfs::new();
        vfs.mkdir_all("store").await.unwrap();
        for name in names {
            let mut file = vfs
                .open(&format!("store/{name}"), OpenMode::CreateOrOpen)
                .await
                .unwrap();
            file.set_len(64).await.unwrap();
        }
        vfs
    }

    /// The point of the whole exercise: after quarantine the bytes still exist
    /// somewhere a human can find them.
    #[tokio::test(flavor = "current_thread")]
    async fn quarantine_preserves_the_bytes_it_moves() {
        let vfs = store_with_files(&["main.db", "seg"]).await;

        let report = quarantine_store(&vfs, "store", "first").await.unwrap();

        assert_eq!(report.directory, "store/quarantine/first");
        let moved = vfs.list_dir("store/quarantine/first").await.unwrap();
        assert!(moved.contains(&"main.db".to_owned()), "got {moved:?}");
        assert!(
            vfs.open("store/quarantine/first/main.db", OpenMode::Read)
                .await
                .is_ok(),
            "the preserved store must still be readable"
        );
    }

    /// The original paths must be clear afterwards, so an application that
    /// quarantines in order to come back up can open a fresh store — the same
    /// end state a delete would have reached, without the loss.
    #[tokio::test(flavor = "current_thread")]
    async fn the_store_directory_is_left_ready_for_a_fresh_store() {
        let vfs = store_with_files(&["main.db"]).await;

        quarantine_store(&vfs, "store", "first").await.unwrap();

        // Asserted by path rather than by listing: backends differ on whether
        // a subdirectory appears in a listing, and what matters is that nothing
        // is left at the paths a fresh open will use.
        assert!(
            vfs.open("store/main.db", OpenMode::Read).await.is_err(),
            "the original store path must be clear for a fresh store"
        );
        assert!(
            vfs.open("store/quarantine/first/main.db", OpenMode::Read)
                .await
                .is_ok(),
            "and the bytes must be where the report says they are"
        );
    }

    /// Two corruptions interleaved in one directory are worse evidence than
    /// either alone, so a reused label is refused rather than merged.
    #[tokio::test(flavor = "current_thread")]
    async fn a_reused_label_is_refused_rather_than_merged() {
        let vfs = store_with_files(&["main.db"]).await;
        quarantine_store(&vfs, "store", "first").await.unwrap();

        let mut file = vfs
            .open("store/main.db", OpenMode::CreateOrOpen)
            .await
            .unwrap();
        file.set_len(1).await.unwrap();

        assert!(
            quarantine_store(&vfs, "store", "first").await.is_err(),
            "a second quarantine under the same label must not merge into the first"
        );
    }

    /// Quarantining twice under different labels must not fold the first
    /// quarantine into the second.
    #[tokio::test(flavor = "current_thread")]
    async fn a_second_quarantine_leaves_the_first_intact() {
        let vfs = store_with_files(&["main.db"]).await;
        quarantine_store(&vfs, "store", "first").await.unwrap();

        let mut file = vfs
            .open("store/main.db", OpenMode::CreateOrOpen)
            .await
            .unwrap();
        file.set_len(1).await.unwrap();
        quarantine_store(&vfs, "store", "second").await.unwrap();

        assert!(
            vfs.open("store/quarantine/first/main.db", OpenMode::Read)
                .await
                .is_ok(),
            "the first quarantine must survive the second"
        );
    }
}
