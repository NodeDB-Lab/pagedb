//! Incremental snapshot manifest compatibility checks.

use std::sync::atomic::Ordering;

use crate::Result;
use crate::errors::PagedbError;
use crate::snapshot::export::SnapshotManifest;
use crate::vfs::Vfs;

use super::core::Db;

const SUPPORTED_SNAPSHOT_VERSION: u32 = 1;
const FIRST_ALLOCATABLE_PAGE_ID: u64 = 4;

impl<V: Vfs + Clone> Db<V> {
    /// Reject a manifest that cannot safely advance this follower's currently
    /// reader-visible snapshot. This runs before the apply path writes pages
    /// or creates staging files.
    pub(super) fn validate_incremental_manifest(
        &self,
        manifest: &SnapshotManifest,
        reserved: &[u8],
    ) -> Result<()> {
        if manifest.version != SUPPORTED_SNAPSHOT_VERSION {
            return Err(PagedbError::snapshot_incompatible("version"));
        }
        if manifest.kind != 1 {
            return Err(PagedbError::snapshot_incompatible("kind"));
        }
        if reserved.iter().any(|byte| *byte != 0) {
            return Err(PagedbError::snapshot_incompatible("reserved"));
        }
        if manifest.file_id != self.file_id {
            return Err(PagedbError::snapshot_incompatible("file_id"));
        }
        if manifest.kek_salt != self.kek_salt {
            return Err(PagedbError::snapshot_incompatible("kek_salt"));
        }
        if manifest.mk_epoch != self.mk_epoch.load(Ordering::SeqCst) {
            return Err(PagedbError::snapshot_incompatible("mk_epoch"));
        }
        if manifest.cipher_id != self.cipher_id.as_byte() {
            return Err(PagedbError::snapshot_incompatible("cipher_id"));
        }
        let expected_page_size = u32::try_from(self.page_size)
            .map_err(|_| PagedbError::snapshot_incompatible("page_size"))?;
        if manifest.page_size != expected_page_size {
            return Err(PagedbError::snapshot_incompatible("page_size"));
        }
        if manifest.realm_id != self.realm_id.0 {
            return Err(PagedbError::snapshot_incompatible("realm_id"));
        }

        let visible_snapshot = *self.snapshot.read();
        if manifest.base_commit != visible_snapshot.commit_id {
            return Err(PagedbError::snapshot_incompatible("base_commit"));
        }
        if manifest.target_commit <= manifest.base_commit {
            return Err(PagedbError::snapshot_incompatible("target_commit"));
        }
        if manifest.next_page_id_at_target < visible_snapshot.next_page_id
            || manifest.next_page_id_at_target < FIRST_ALLOCATABLE_PAGE_ID
        {
            return Err(PagedbError::snapshot_incompatible("next_page_id_at_target"));
        }
        if !valid_root_page(
            manifest.target_active_root_page_id,
            manifest.next_page_id_at_target,
        ) {
            return Err(PagedbError::snapshot_incompatible(
                "target_active_root_page_id",
            ));
        }
        if !valid_root_page(
            manifest.target_catalog_root_page_id,
            manifest.next_page_id_at_target,
        ) {
            return Err(PagedbError::snapshot_incompatible(
                "target_catalog_root_page_id",
            ));
        }

        Ok(())
    }
}

fn valid_root_page(root_page_id: u64, next_page_id: u64) -> bool {
    root_page_id == 0 || (root_page_id >= FIRST_ALLOCATABLE_PAGE_ID && root_page_id < next_page_id)
}
