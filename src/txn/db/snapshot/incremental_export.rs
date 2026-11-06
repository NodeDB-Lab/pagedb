// SPDX-License-Identifier: Apache-2.0

//! Page-diff snapshot export.

use super::super::core::Db;
use super::super::util::get_vfs_root;
use super::ownership::{claim_empty_destination, cleanup_failed_snapshot};
use super::reachability::collect_tree_page_ids;
use crate::snapshot::export::{SnapshotManifest, snapshot_incremental};
use crate::vfs::Vfs;

impl<V: Vfs + Clone> Db<V> {
    /// Page-diff snapshot since `base_commit`. Emits only pages changed since
    /// the base commit, plus segment files new/changed since that commit.
    pub async fn snapshot_incremental_to(
        &self,
        base_commit: crate::CommitId,
        dst_path: &std::path::Path,
    ) -> crate::Result<crate::snapshot::SnapshotStats> {
        self.ensure_usable()?;
        // Pin the current published state.
        let txn = self.begin_read_non_abortable().await?;

        let target_commit = txn.commit_id().0;
        let target_next_page_id = txn.next_page_id();
        let target_active_root_page_id = txn.root_page_id();
        let target_catalog_root_page_id = txn.catalog_root_page_id();
        self.refuse_export_with_pending_rekey(target_catalog_root_page_id, target_next_page_id)
            .await?;

        // A missing base is not an empty baseline: without its roots there is
        // no sound way to determine which pages the follower must preserve.
        let base_txn = self.begin_read_at(base_commit).await?;
        let base_next_page_id = base_txn.next_page_id();
        let base_catalog_root = base_txn.catalog_root_page_id();

        let target_page_ids = collect_tree_page_ids(
            &self.pager,
            self.realm_id,
            self.page_size,
            target_active_root_page_id,
            target_catalog_root_page_id,
            target_next_page_id,
        )
        .await?;
        let base_page_ids = collect_tree_page_ids(
            &self.pager,
            self.realm_id,
            self.page_size,
            base_txn.root_page_id(),
            base_catalog_root,
            base_next_page_id,
        )
        .await?;
        // Exactly the formula `apply_incremental` re-derives from the manifest.
        // Both sides must compute this the same way or a healthy snapshot fails
        // the follower's set comparison.
        let changed_page_ids: Vec<u64> = target_page_ids
            .difference(&base_page_ids)
            .copied()
            .collect();
        // Deliberately no producer-side page-reuse check. A page id below the
        // base allocation cursor proves nothing: a page that was *free* at the
        // base commit is legitimately reallocated for the target, and shipping
        // it is safe precisely because no base-reachable state points at it.
        // Rejecting on the cursor would fail every database that has ever
        // deleted anything.
        //
        // The one collision that does matter — a page the follower's own
        // free-list chain or commit-history tree still hosts — is invisible
        // from here. The follower keeps both across an apply, and the base
        // commit's recorded free-list root is superseded writer metadata whose
        // pages a later commit may already have recycled, so reading it to
        // guess would authenticate a page that is no longer a free-list page at
        // all. The follower owns that check and runs it before any byte reaches
        // `main.db`.

        // Current segments.
        let current_segments = txn.list_segments("").await?;
        // Base segments (from base catalog).
        let base_segments: Vec<crate::catalog::codec::SegmentMeta> = if base_catalog_root != 0 {
            base_txn.list_segments("").await?
        } else {
            Vec::new()
        };

        // New/changed segments: present in current but absent or different segment_id in base.
        let base_ids: std::collections::HashSet<[u8; 16]> =
            base_segments.iter().map(|m| m.segment_id).collect();
        let new_segments: Vec<[u8; 16]> = current_segments
            .iter()
            .filter(|m| !base_ids.contains(&m.segment_id))
            .map(|m| m.segment_id)
            .collect();

        let segments_count = u32::try_from(new_segments.len()).unwrap_or(u32::MAX);

        let hk_raw: [u8; 32] = {
            let hk_guard = self.hk.read();
            *hk_guard.as_bytes()
        };

        let manifest = SnapshotManifest {
            version: 1,
            kind: 1, // Incremental
            target_commit,
            base_commit: base_commit.0,
            file_id: self.file_id,
            mk_epoch: self.mk_epoch.load(std::sync::atomic::Ordering::SeqCst),
            kek_salt: self.kek_salt,
            cipher_id: self.cipher_id.as_byte(),
            page_size: self.page_size.try_into().unwrap_or(4096),
            next_page_id_at_target: target_next_page_id,
            segments_count,
            realm_id: self.realm_id.0,
            target_active_root_page_id,
            target_catalog_root_page_id,
        };

        let src_root = get_vfs_root(&*self.vfs)?;
        let ownership = claim_empty_destination(dst_path).await?;

        let stats = match snapshot_incremental(
            &src_root,
            dst_path,
            &manifest,
            &hk_raw,
            &new_segments,
            base_next_page_id,
            &changed_page_ids,
        )
        .await
        {
            Ok(stats) => stats,
            Err(error) => {
                cleanup_failed_snapshot(dst_path, ownership).await;
                return Err(error);
            }
        };

        drop(txn);
        Ok(stats)
    }
}
