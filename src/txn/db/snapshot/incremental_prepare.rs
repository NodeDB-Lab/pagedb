// SPDX-License-Identifier: Apache-2.0

//! Authenticate and stage an incremental target image.

use super::super::core::Db;
use super::super::util::get_vfs_root;
use super::reachability::collect_tree_page_ids;
use crate::recovery::journal::JournalAction;
use crate::segment::writer::STAGING_DIR;
use crate::snapshot::apply::{
    clone_base_image, plan_delta_stream, stage_snapshot_segments, validate_snapshot_segment_count,
    write_delta_into_image,
};
use crate::snapshot::export::{SnapshotManifest, decode_manifest};
use crate::vfs::Vfs;
use std::collections::BTreeSet;
use std::sync::Arc;
use tokio::fs;
use tokio::io::AsyncReadExt;

pub(super) struct PreparedIncremental {
    pub(super) manifest: SnapshotManifest,
    pub(super) page_size: usize,
    pub(super) pages_applied: u64,
    pub(super) target_page_ids: BTreeSet<u64>,
    pub(super) reclaimed_page_ids: BTreeSet<u64>,
    pub(super) delta_page_ids: BTreeSet<u64>,
    pub(super) actions: Vec<JournalAction>,
    pub(super) segments_promoted: u32,
    pub(super) segments_tombstoned: u32,
}

impl<V: Vfs + Clone> Db<V> {
    pub(super) async fn prepare_incremental_target(
        &self,
        src_path: &std::path::Path,
        staged_image: &str,
    ) -> crate::Result<PreparedIncremental> {
        let (manifest, manifest_bytes) = self.read_incremental_manifest(src_path).await?;
        // Includes `base_commit == visible_snapshot.commit_id`, which is what
        // makes an apply idempotent: replaying a delta the follower already
        // absorbed fails here, before anything is staged.
        self.validate_incremental_manifest(&manifest, &manifest_bytes[118..224])?;
        // One sample of the published base. Its page sets and its segment set
        // are compared against each other below, so drawing them from two
        // independent reads would let a concurrent `gc_now` — which Follower
        // mode permits — split the base state across the comparison and make a
        // valid delta look inconsistent.
        let base_snapshot = *self.snapshot.read();
        // Only the reader-visible set. The free-list chain and commit-history
        // tree are read where they are rewritten, and folding them in here
        // would define the delta by pages the producer cannot see.
        let base_reader_visible = collect_tree_page_ids(
            &self.pager,
            self.realm_id,
            self.page_size,
            base_snapshot.root_page_id,
            base_snapshot.catalog_root_page_id,
            base_snapshot.next_page_id,
        )
        .await?;
        let base_segment_ids = self
            .catalog_segment_ids(
                &self.pager,
                base_snapshot.catalog_root_page_id,
                base_snapshot.next_page_id,
            )
            .await?;

        let page_size = usize::try_from(manifest.page_size)
            .map_err(|_| crate::errors::PagedbError::snapshot_incompatible("page_size"))?;
        validate_snapshot_segment_count(src_path, manifest.segments_count).await?;

        // Frame and screen the whole delta stream before a byte of it is
        // copied anywhere. A malformed record late in the stream must not cost
        // a staged image, and a record naming a base-reader-visible page is
        // refused by identity here rather than being caught later as a set
        // mismatch.
        let plan = plan_delta_stream(
            src_path,
            page_size,
            &base_reader_visible,
            manifest.next_page_id_at_target,
        )
        .await?;
        // Refused here, before an image is cloned, so the refusal costs no copy.
        self.refuse_delta_reaching_pinned_reader(base_snapshot, &plan.page_ids)
            .await?;

        // Assemble the target beside the live file. `main.db` is not opened for
        // writing anywhere in this method; the rename below is the only thing
        // that changes it.
        clone_base_image(&*self.vfs, &self.main_db_path, staged_image).await?;
        let pages_applied =
            write_delta_into_image(&*self.vfs, staged_image, src_path, page_size, &plan).await?;

        // Authenticate the target through a read-only view of the staged image.
        // Clean base pages are dropped first so the view's buffer pool and the
        // live one are not both resident at their full configured budget. This
        // runs without the writer lock, so a dirty page belongs to another
        // writer and stays.
        self.pager.evict_clean_main_pages(self.realm_id)?;
        let staged_view = Arc::new(self.pager.open_main_view(staged_image.to_owned()));
        let target_page_ids = collect_tree_page_ids(
            &staged_view,
            self.realm_id,
            self.page_size,
            manifest.target_active_root_page_id,
            manifest.target_catalog_root_page_id,
            manifest.next_page_id_at_target,
        )
        .await?;
        // The same formula the producer used to build the delta:
        // target-reachable minus base-reader-visible. Subtracting the wider
        // `published` set here instead would demand a delta the producer cannot
        // construct, because it cannot see this follower's free-list or
        // commit-history pages.
        let expected_delta_page_ids: BTreeSet<u64> = target_page_ids
            .difference(&base_reader_visible)
            .copied()
            .collect();
        if plan.page_ids != expected_delta_page_ids {
            return Err(crate::errors::PagedbError::snapshot_artifact_invalid(
                "pages.delta.reachability",
            ));
        }
        let target_segments = self
            .catalog_segment_metas(
                &staged_view,
                manifest.target_catalog_root_page_id,
                manifest.next_page_id_at_target,
            )
            .await?;
        // Everything the staged image had to say has been said. Drop the view
        // so its pool is released well before the swap.
        drop(staged_view);

        // The complementary difference: pages a reader could reach at the base
        // commit that the target no longer reaches. Nothing in the delta names
        // them — their bytes never changed, only the roots moved off them — so
        // installing the target roots strands them outside both the roots and
        // this handle's free list unless they are folded in below. Derived from
        // the two sets this apply has already walked and authenticated, which
        // is why the delta itself need not carry them: the receiver is the only
        // side that can act on them, and it can already name them exactly.
        let reclaimed_page_ids: BTreeSet<u64> = base_reader_visible
            .difference(&target_page_ids)
            .copied()
            .collect();

        let (actions, segments_promoted, segments_tombstoned) = self
            .prepare_incremental_segments(src_path, &manifest, &target_segments, &base_segment_ids)
            .await?;
        Ok(PreparedIncremental {
            manifest,
            page_size,
            pages_applied,
            target_page_ids,
            reclaimed_page_ids,
            delta_page_ids: plan.page_ids,
            actions,
            segments_promoted,
            segments_tombstoned,
        })
    }

    async fn read_incremental_manifest(
        &self,
        src_path: &std::path::Path,
    ) -> crate::Result<(SnapshotManifest, [u8; 240])> {
        let manifest_path = src_path.join("manifest");
        // We need kek to verify the manifest, but Db doesn't hold it. Use the
        // HK bytes directly as the "kek" for MAC verification — since the
        // snapshot was created with the HK-raw bytes as the MAC key, we verify
        // with the same material.
        let hk_raw: [u8; 32] = {
            let hk_guard = self.hk.read();
            *hk_guard.as_bytes()
        };
        // Decode manifest using hk_raw as the key directly.
        let manifest_bytes = {
            let mut f = fs::File::open(&manifest_path)
                .await
                .map_err(crate::errors::PagedbError::Io)?;
            if f.metadata()
                .await
                .map_err(crate::errors::PagedbError::Io)?
                .len()
                != 240
            {
                return Err(crate::errors::PagedbError::snapshot_artifact_invalid(
                    "manifest.length",
                ));
            }
            let mut buf = [0u8; 240];
            let _ = f
                .read_exact(&mut buf)
                .await
                .map_err(crate::errors::PagedbError::Io)?;
            buf
        };
        let manifest = decode_manifest(&manifest_bytes, &hk_raw)?;
        Ok((manifest, manifest_bytes))
    }

    async fn prepare_incremental_segments(
        &self,
        src_path: &std::path::Path,
        manifest: &SnapshotManifest,
        target_segments: &[crate::catalog::codec::SegmentMeta],
        base_segment_ids: &BTreeSet<[u8; 16]>,
    ) -> crate::Result<(Vec<JournalAction>, u32, u32)> {
        let target_segment_ids: BTreeSet<[u8; 16]> =
            target_segments.iter().map(|meta| meta.segment_id).collect();
        let expected_promoted_segment_ids: BTreeSet<[u8; 16]> = target_segment_ids
            .difference(base_segment_ids)
            .copied()
            .collect();
        let expected_tombstoned_segment_ids: BTreeSet<[u8; 16]> = base_segment_ids
            .difference(&target_segment_ids)
            .copied()
            .collect();
        if expected_promoted_segment_ids.len() != manifest.segments_count as usize {
            return Err(crate::errors::PagedbError::snapshot_artifact_invalid(
                "segments_count",
            ));
        }

        // Stage new segment files in `.staging/` so they can be promoted
        // atomically after the header swap via the apply journal.
        let vfs_root = get_vfs_root(&*self.vfs)?;
        let dst_seg_root = vfs_root.join("seg");
        let staged_ids =
            stage_snapshot_segments(src_path, &dst_seg_root, &expected_promoted_segment_ids)
                .await?;
        if !staged_ids.is_empty() {
            self.vfs.sync_dir(STAGING_DIR).await?;
        }
        let segments_promoted = u32::try_from(staged_ids.len())
            .map_err(|_| crate::errors::PagedbError::snapshot_incompatible("segments_count"))?;
        let segments_tombstoned = u32::try_from(expected_tombstoned_segment_ids.len())
            .map_err(|_| crate::errors::PagedbError::snapshot_incompatible("segments_count"))?;
        let mmap_limit = u64::try_from(self.options.mmap_view_scratch_bytes).unwrap_or(u64::MAX);
        for meta in target_segments
            .iter()
            .filter(|meta| expected_promoted_segment_ids.contains(&meta.segment_id))
        {
            let staged_path = crate::segment::writer::staging_path(&meta.segment_id);
            let reader = crate::segment::reader::SegmentReader::open_internal_at_path(
                self.pager.clone(),
                meta.clone(),
                &staged_path,
                self.mmap_bytes_in_use.clone(),
                mmap_limit,
            )
            .await?;
            for page_id in 1..meta.page_count.saturating_sub(1) {
                let _ = reader.read_page(page_id).await?;
            }
        }

        let new_commit_id = manifest.target_commit;
        let mut actions: Vec<JournalAction> = staged_ids
            .iter()
            .map(|&segment_id| JournalAction::Promote { segment_id })
            .collect();
        actions.extend(expected_tombstoned_segment_ids.iter().map(|&segment_id| {
            JournalAction::Tombstone {
                segment_id,
                tombstone_commit_id: new_commit_id,
            }
        }));
        Ok((actions, segments_promoted, segments_tombstoned))
    }
}
