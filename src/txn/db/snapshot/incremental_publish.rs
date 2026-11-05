// SPDX-License-Identifier: Apache-2.0

//! Publish a staged incremental target under writer and visibility ownership.

use super::super::core::{Db, WriterState};
use super::super::history_carry::CarriedHistory;
use super::super::reclaim::StagedFreeList;
use super::super::util::page_size_log2;
use super::incremental_prepare::PreparedIncremental;
use crate::pager::anchor::HeaderCursor;
use crate::pager::header::commit_header;
use crate::pager::structural_header::MainDbHeaderFields;
use crate::recovery::journal::{
    ApplyJournalRecord, JournalAction, encode_journal_id, encode_journal_pages,
};
use crate::snapshot::export::SnapshotManifest;
use crate::vfs::Vfs;

struct IncrementalHeaderParams<'a> {
    manifest: &'a SnapshotManifest,
    state: &'a WriterState,
    carried: &'a CarriedHistory,
    staged_free_list: &'a StagedFreeList,
    journal_id: [u8; 16],
}

struct StagedIncrementalHeader {
    fields: MainDbHeaderFields,
    cursor: HeaderCursor,
}

impl<V: Vfs + Clone> Db<V> {
    pub(super) async fn stage_and_swap_incremental(
        &self,
        src_path: &std::path::Path,
        staged_image: &str,
    ) -> crate::Result<crate::snapshot::ApplyStats> {
        let PreparedIncremental {
            manifest,
            page_size,
            pages_applied,
            target_page_ids,
            mut reclaimed_page_ids,
            delta_page_ids,
            actions,
            segments_promoted,
            segments_tombstoned,
        } = self
            .prepare_incremental_target(src_path, staged_image)
            .await?;
        let new_commit_id = manifest.target_commit;
        let mut state = self.writer.lock().await;
        self.ensure_usable()?;
        // Close reader admission for the remainder of the apply. Writer before
        // visibility is the global destructive-operation order, the same one
        // compaction, `gc_now`, the journal retry, and `WriteTxn::begin` take.
        //
        // Everything from here on either stages target-generation bytes through
        // the Pager or replaces the file those bytes live in, and the durable
        // header does not name the target until the rename below. A reader
        // admitted anywhere in that stretch would resolve the still-published
        // base roots against a file that is being turned into the target, and
        // would race the tombstone pin scan that decides whether the segments
        // it can name survive. The guard is held through the header write, the
        // rename, the directory sync, the journal reconciliation, and the
        // published replacement snapshot — released only once the roots and
        // the bytes agree again.
        let visibility = self.visibility_gate.write().await;

        // Move this handle's own metadata out of the incoming page space. The
        // producer allocates over the ids hosting the follower's commit-history
        // tree and free-list chain because it cannot see them; the delta may
        // therefore claim any of them. Both are read here from the still-intact
        // base image and rewritten onto ids the target does not touch, and both
        // reach disk in the staged image, so the roots and the metadata they
        // name become durable together or not at all.
        let alloc_cursor = manifest.next_page_id_at_target.max(state.next_page_id);
        let carried = self
            .carry_commit_history(
                &state,
                &delta_page_ids,
                &target_page_ids,
                new_commit_id,
                alloc_cursor,
            )
            .await?;
        reclaimed_page_ids.extend(carried.released_page_ids.iter().copied());

        // Fold the reclaim set into this handle's own free-list chain, and drop
        // any entry the target has since put back into service. The rewritten
        // chain is staged through the Pager and becomes durable with the very
        // swap that installs the target roots, so the roots and the free-list
        // accounting for the pages they abandoned can never diverge: a crash
        // before that swap leaves the previous chain and the previous roots both
        // intact, and the retry redoes the fold.
        let staged_free_list = self
            .stage_reclaimed_free_list(
                &state,
                &reclaimed_page_ids,
                &target_page_ids,
                new_commit_id,
                carried.next_page_id,
            )
            .await?;
        // Back the cursor this apply is about to publish with real extent
        // before the chain pages flush into it, so no observable point has a
        // header naming pages the image does not contain.
        self.ensure_image_covers_cursor(staged_image, staged_free_list.next_page_id)
            .await?;
        // Everything this apply wrote through the Pager — the rewritten chain
        // and any relocated history — lands in the staged image, never in the
        // live file.
        self.pager
            .flush_main_to(self.realm_id, staged_image)
            .await?;

        let journal_id = self
            .stage_incremental_journal(&actions, new_commit_id, page_size)
            .await?;
        let staged_header = self
            .stage_incremental_header(
                staged_image,
                IncrementalHeaderParams {
                    manifest: &manifest,
                    state: &state,
                    carried: &carried,
                    staged_free_list: &staged_free_list,
                    journal_id,
                },
            )
            .await?;
        let counter_anchor = staged_header.fields.counter_anchor;

        self.swap_incremental_image(staged_image, new_commit_id)
            .await?;

        // The target image is durable. Advance only internal writer state;
        // prior readers remain on the old snapshot until the nonce anchor and
        // journal actions establish a safe target directory.
        // The staged image is now `main.db`, and the header just written is the
        // slot it opens from. Any anchor refresh that landed in the file this
        // rename replaced went with it, and this header's anchor is at least as
        // large, so the durable anchor never moves backwards across the swap.
        self.install_incremental_writer_state(
            &mut state,
            &manifest,
            &carried,
            &staged_free_list,
            &staged_header,
            journal_id,
        );

        if self.pager.commit_anchor(counter_anchor).is_err() {
            let commit = crate::CommitId(new_commit_id);
            self.poison(commit);
            return Err(crate::errors::PagedbError::durably_committed_but_unpublished(commit));
        }

        if actions.is_empty() {
            self.publish_snapshot(&state);
        } else {
            // Reconciled without releasing the gate. The locking entry point
            // would re-take both guards, and the instant between dropping and
            // re-taking them is the one instant where `main.db` is the target
            // image while the published snapshot still names base roots.
            self.retry_pending_apply_journal_visible(&mut state, &visibility)
                .await?;
        }
        drop(state);
        drop(visibility);

        Ok(crate::snapshot::ApplyStats {
            pages_applied,
            segments_promoted,
            segments_tombstoned,
        })
    }

    async fn stage_incremental_journal(
        &self,
        actions: &[JournalAction],
        new_commit_id: u64,
        page_size: usize,
    ) -> crate::Result<[u8; 16]> {
        // Write the journal record to a fresh apply-journal sidecar via the
        // Pager AEAD path. A fresh, never-reused `journal_id` guarantees the
        // sidecar's nonce space never collides with another file's under one
        // key. The sidecar may span any number of pages, so the promotion set
        // is unbounded — no single-page ceiling. The 16-byte id is carried in
        // the header's `apply_journal_root` fields after the swap, so a sidecar
        // written for an apply that never swaps is simply never named.
        let journal_id = if actions.is_empty() {
            [0u8; 16]
        } else {
            let id = crate::crypto::random::journal_id()?;
            let record = ApplyJournalRecord {
                target_commit_id: new_commit_id,
                actions: actions.to_vec(),
            };
            let pages = encode_journal_pages(&record, page_size)?;
            self.vfs.mkdir_all("applyjournal").await?;
            for (page_id, body) in pages.iter().enumerate() {
                self.pager
                    .stage_journal_page(id, page_id as u64, self.realm_id, body)
                    .await?;
            }
            self.pager.flush_journal(id, self.realm_id).await?;
            self.vfs.sync_dir("applyjournal").await?;
            id
        };
        Ok(journal_id)
    }

    async fn stage_incremental_header(
        &self,
        staged_image: &str,
        params: IncrementalHeaderParams<'_>,
    ) -> crate::Result<StagedIncrementalHeader> {
        let IncrementalHeaderParams {
            manifest,
            state,
            carried,
            staged_free_list,
            journal_id,
        } = params;
        let new_commit_id = manifest.target_commit;
        let (journal_root_page_id, journal_root_version) = encode_journal_id(&journal_id);

        // The target's allocation cursor, extended if relocating this handle's
        // metadata had to bump-allocate past it.
        let new_next_page_id = staged_free_list.next_page_id;

        // Staging the follower's relocated metadata into the image seals pages,
        // and sealing them may have refreshed the anchor in the live header. Read
        // the cursor after that work so this header supersedes the right slot.
        let header_cursor = self.pager.header_cursor()?;
        let new_seq = header_cursor.next_seq()?;
        let counter_anchor = self.pager.pending_anchor();

        // Install the target trees the producer shipped in the manifest. The
        // delta pages in the staged image contain these root pages; pointing
        // the header at them is what advances the data and catalog trees past
        // the base snapshot (without this, incrementally-applied rows and
        // segments are unreachable from the follower's catalog).
        let new_root_page_id = manifest.target_active_root_page_id;
        let new_catalog_root_page_id = manifest.target_catalog_root_page_id;

        let mut catalog_root_bytes = [0u8; 16];
        catalog_root_bytes[..8].copy_from_slice(&new_catalog_root_page_id.to_le_bytes());
        catalog_root_bytes[8..].copy_from_slice(&new_commit_id.to_le_bytes());

        let fields_with_journal = MainDbHeaderFields {
            format_version: crate::pager::structural_header::MAIN_FORMAT_VERSION,
            cipher_id: self.cipher_id.as_byte(),
            page_size_log2: page_size_log2(self.page_size)?,
            flags: self.header_flags,
            file_id: self.file_id,
            kek_salt: self.kek_salt,
            mk_epoch: self.mk_epoch.load(std::sync::atomic::Ordering::SeqCst),
            seq: new_seq,
            active_root_page_id: new_root_page_id,
            active_root_txn_id: new_commit_id,
            counter_anchor,
            commit_id: crate::CommitId(new_commit_id),
            free_list_root: crate::txn::db::encode_free_list_root(
                staged_free_list.free_list_root_page_id,
            ),
            catalog_root: catalog_root_bytes,
            apply_journal_root_page_id: journal_root_page_id,
            apply_journal_root_version: journal_root_version,
            commit_history_root_page_id: carried.root_page_id,
            commit_history_root_version: carried.root_version,
            restore_mode: state.restore_mode,
            next_page_id: new_next_page_id,
            commit_retain_policy_tag: state.commit_retain_policy_tag,
            commit_retain_policy_value: state.commit_retain_policy_value,
            realm_id: self.realm_id,
        };

        // The target header goes into the staged image's inactive slot. The
        // image is a copy of the base, so it still carries the base header too;
        // whichever way the swap falls, the file that ends up at `main.db` has
        // a verifiable header with the higher `seq` naming a complete state.
        let hk_clone = { self.hk.read().clone() };
        let new_slot = commit_header(
            &*self.vfs,
            staged_image,
            &hk_clone,
            &fields_with_journal,
            header_cursor.slot,
            self.page_size,
        )
        .await?;

        Ok(StagedIncrementalHeader {
            fields: fields_with_journal,
            cursor: HeaderCursor {
                slot: new_slot,
                seq: new_seq,
            },
        })
    }

    fn install_incremental_writer_state(
        &self,
        state: &mut WriterState,
        manifest: &SnapshotManifest,
        carried: &CarriedHistory,
        staged_free_list: &StagedFreeList,
        staged_header: &StagedIncrementalHeader,
        journal_id: [u8; 16],
    ) {
        let new_commit_id = manifest.target_commit;
        let new_next_page_id = staged_header.fields.next_page_id;
        let new_root_page_id = staged_header.fields.active_root_page_id;
        let new_catalog_root_page_id = manifest.target_catalog_root_page_id;
        self.pager.note_header_written(staged_header.cursor);
        state.latest_commit_id = new_commit_id;
        state.next_page_id = new_next_page_id;
        state.root_page_id = new_root_page_id;
        state.catalog_root_page_id = new_catalog_root_page_id;
        state.catalog_root_txn_id = new_commit_id;
        state.free_list_root_page_id = staged_free_list.free_list_root_page_id;
        state.commit_history_root_page_id = carried.root_page_id;
        state.commit_history_root_version = carried.root_version;
        state.commit_history_count = carried.entry_count;
        // The header is the source of truth for a pending apply. Mirror it in
        // live writer state immediately so every subsequent operation sees the
        // same retry obligation.
        state.pending_apply_journal_id = journal_id;
    }

    async fn swap_incremental_image(
        &self,
        staged_image: &str,
        new_commit_id: u64,
    ) -> crate::Result<()> {
        // ---- Commit point. Everything above is undoable by deleting a file.
        // Close the cached handle first so the rename can replace the file
        // (Windows) and the next access reopens the new inode (Unix).
        self.pager.close_main_handle().await;
        if self
            .vfs
            .rename(staged_image, &self.main_db_path)
            .await
            .is_err()
        {
            // After closing the old handle, a backend may have performed an
            // ambiguous replacement even when it reports an error. Reopen is
            // the only safe way to establish the durable image.
            let commit = crate::CommitId(new_commit_id);
            self.poison(commit);
            return Err(crate::errors::PagedbError::durably_committed_but_unpublished(commit));
        }
        // The staged image is the live image now, so every main page cached
        // from the base predates it. A failed reset leaves those pages resident,
        // so the handle poisons and reopen is the way out.
        if self.pager.reset_main_pages().is_err() {
            let commit = crate::CommitId(new_commit_id);
            self.poison(commit);
            return Err(crate::errors::PagedbError::durably_committed_but_unpublished(commit));
        }
        if self.vfs.sync_dir(self.main_db_parent_dir()).await.is_err() {
            let commit = crate::CommitId(new_commit_id);
            self.poison(commit);
            return Err(crate::errors::PagedbError::durably_committed_but_unpublished(commit));
        }

        Ok(())
    }
}
