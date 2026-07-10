//! Online rekey: re-encrypt the main tree, catalog, and every linked segment
//! under a new `mk_epoch`, with a crash-resumable catalog watermark.

use std::sync::atomic::Ordering;

use crate::Result;
use crate::btree::BTree;
use crate::catalog::codec::{Catalog, RekeyStateRow};
use crate::crypto::kdf::{derive_hk, derive_mk};
use crate::errors::PagedbError;
use crate::pager::header::commit_header;
use crate::segment::reader::SegmentReader;
use crate::segment::writer::SegmentWriter;
use crate::vfs::Vfs;

use super::core::{Db, HeaderFieldsParams, WriterState, encode_root_ref};

impl<V: Vfs + Clone> Db<V> {
    /// Online rekey: re-encrypt every main.db B+ tree page and every linked
    /// segment under a new `mk_epoch` derived from `kek` and the existing
    /// `kek_salt`. Resumes automatically if a prior rekey was interrupted.
    ///
    /// On return `Ok(())`, all on-disk data uses `new_mk_epoch` and the A/B
    /// header records the new epoch. The in-memory `Db` is updated in-place
    /// (the pager's active key and epoch are switched atomically before the
    /// final flush). No reopen is required.
    ///
    /// # Errors
    /// Returns `Unsupported` if this handle is not in Standalone mode.
    #[allow(clippy::too_many_lines)]
    pub async fn rekey_db(&self, kek: [u8; 32], new_mk_epoch: u64) -> Result<()> {
        self.ensure_usable()?;
        let _span = tracing::debug_span!("rekey.run", new_mk_epoch);
        if !matches!(self.mode, crate::txn::mode::DbMode::Standalone) {
            return Err(PagedbError::Unsupported);
        }

        let new_mk = derive_mk(&kek, &self.kek_salt, new_mk_epoch)?;
        let derived_hk = derive_hk(&new_mk)?;

        // Acquire writer lock for the entire rekey operation.
        let mut state = self.writer.lock().await;
        self.ensure_usable()?;

        // Check for an in-flight rekey from a prior crash and compute start
        // position. A rekey watermark row under key [0x03] indicates a prior
        // incomplete rekey.
        let (main_db_done, segments_start_idx) = self.load_rekey_state(&state).await?;

        if !main_db_done {
            // Write the watermark before starting the rewrite so a crash is
            // detectable on the next open.
            self.write_rekey_watermark(&mut state, new_mk_epoch, false, 0)
                .await?;

            // Walk main tree and catalog tree, marking all pages dirty.
            let main_tree = BTree::open(
                self.pager.clone(),
                self.realm_id,
                state.root_page_id,
                state.next_page_id,
                self.page_size,
            );
            main_tree.rekey_walk().await?;

            if state.catalog_root_page_id != 0 {
                let cat_tree = BTree::open(
                    self.pager.clone(),
                    self.realm_id,
                    state.catalog_root_page_id,
                    state.next_page_id,
                    self.page_size,
                );
                cat_tree.rekey_walk().await?;
            }

            // Switch the pager to the new epoch BEFORE flushing so dirty pages
            // are sealed with the new DEK.
            self.pager.set_active_mk_epoch(new_mk.clone(), new_mk_epoch);

            // Flush all dirty pages (now re-encrypted under the new epoch).
            self.pager.flush_main(self.realm_id).await?;

            // Write the new A/B header with the new mk_epoch and mark main_db_done.
            let new_seq = state.seq + 1;
            let counter_anchor = self.pager.pending_anchor();
            let catalog_root_bytes =
                encode_root_ref(state.catalog_root_page_id, state.latest_commit_id);

            let fields = self.header_fields(HeaderFieldsParams {
                mk_epoch: new_mk_epoch,
                seq: new_seq,
                active_root_page_id: state.root_page_id,
                active_root_txn_id: state.latest_commit_id,
                counter_anchor,
                commit_id: state.latest_commit_id,
                catalog_root: catalog_root_bytes,
                commit_history_root_page_id: 0,
                commit_history_root_version: 0,
                free_list_root_page_id: state.free_list_root_page_id,
                next_page_id: state.next_page_id,
            })?;
            let new_slot = commit_header(
                &*self.vfs,
                &self.main_db_path,
                &derived_hk,
                &fields,
                state.active_slot,
                self.page_size,
            )
            .await?;
            state.active_slot = new_slot;
            state.seq = new_seq;
            let _ = self
                .finish_durable_commit(
                    &state,
                    crate::CommitId(state.latest_commit_id),
                    counter_anchor,
                    &[],
                )
                .await?;

            // Update Db's mk_epoch atomically and switch the HK so subsequent
            // WriteTxn::commit() calls sign headers with the new key material.
            self.mk_epoch.store(new_mk_epoch, Ordering::SeqCst);
            *self.hk.write() = derived_hk.clone();

            // Update watermark: main_db_done = true.
            self.write_rekey_watermark_locked(&mut state, new_mk_epoch, true, 0, &derived_hk)
                .await?;
        }

        // Rekey segments starting from segments_start_idx.
        let all_segments = self.list_all_segments(&state).await?;
        for (idx, meta) in all_segments.iter().enumerate() {
            let idx_u32 = u32::try_from(idx)
                .map_err(|_| PagedbError::Io(std::io::Error::other("segment index overflow")))?;
            if idx_u32 < segments_start_idx {
                continue;
            }
            // Skip segments already on the new epoch.
            if meta.mk_epoch == new_mk_epoch {
                continue;
            }

            // Each segment carries its source epoch. Re-derive that epoch's
            // key rather than assuming the active header still names it: an
            // interrupted rekey may already have durably advanced main.db.
            let source_mk = derive_mk(&kek, &self.kek_salt, meta.mk_epoch)?;
            let mmap_limit =
                u64::try_from(self.options.mmap_view_scratch_bytes).unwrap_or(u64::MAX);
            let reader = SegmentReader::open_internal_with_mk(
                self.pager.clone(),
                meta.clone(),
                &source_mk,
                self.mmap_bytes_in_use.clone(),
                mmap_limit,
            )
            .await?;

            // Create a new segment writer under the new epoch.
            // The pager is already using the new epoch at this point.
            self.vfs.mkdir_all("seg/.staging").await?;
            let new_segment_id = crate::crypto::random::segment_id()?;
            let mut writer = SegmentWriter::create_internal(
                self.pager.clone(),
                meta.realm_id,
                new_segment_id,
                self.file_id,
                meta.segment_kind,
            )
            .await?;

            // Copy each data page from old to new segment.
            for page_id in 1..meta.page_count - 1 {
                match reader.read_page(page_id).await {
                    Ok(page_bytes) => {
                        writer
                            .append_page(crate::segment::types::SegmentPageKind::Data, &page_bytes)
                            .await?;
                    }
                    Err(PagedbError::NotFound) => {}
                    Err(e) => return Err(e),
                }
            }

            let new_meta = writer.seal().await?;

            // Link the new segment and tombstone the old one via catalog update.
            // Find the segment name in the catalog.
            let seg_name = self.find_segment_name(&state, &meta.segment_id).await?;

            // Update catalog: replace old segment with new one.
            self.replace_segment_in_catalog(
                &mut state,
                &seg_name,
                &meta.segment_id,
                &new_meta,
                &derived_hk,
                new_mk_epoch,
            )
            .await?;

            // Update watermark progress.
            let next_idx = idx_u32.saturating_add(1);
            self.write_rekey_watermark_locked(
                &mut state,
                new_mk_epoch,
                true,
                next_idx,
                &derived_hk,
            )
            .await?;
        }

        // Clear the rekey watermark.
        self.clear_rekey_watermark(&mut state, &derived_hk).await?;

        // The old epoch is now obsolete; evict its DEK entries.
        // At this point self.mk_epoch already holds new_mk_epoch (set earlier),
        // so we evict entries from any epoch < new_mk_epoch. Since we only
        // advanced by one epoch, evict new_mk_epoch - 1 specifically.
        if new_mk_epoch > 0 {
            self.pager.evict_dek_for_epoch(new_mk_epoch - 1);
        }

        Ok(())
    }

    /// Load the rekey watermark from the catalog, if present.
    /// Returns `Some(target_epoch)` if a rekey is in-flight, `None` if not.
    pub(super) async fn load_rekey_watermark(&self, state: &WriterState) -> Result<Option<u64>> {
        if state.catalog_root_page_id == 0 {
            return Ok(None);
        }
        let tree = BTree::open(
            self.pager.clone(),
            self.realm_id,
            state.catalog_root_page_id,
            state.next_page_id,
            self.page_size,
        );
        let key = Catalog::rekey_state_key();
        match tree.get(&key).await? {
            None => Ok(None),
            Some(bytes) => {
                let row = Catalog::decode_rekey_state(&bytes)?;
                Ok(Some(row.target_mk_epoch))
            }
        }
    }

    /// Load full rekey watermark state. Returns `(main_db_done, segments_remaining_idx)`.
    async fn load_rekey_state(&self, state: &WriterState) -> Result<(bool, u32)> {
        if state.catalog_root_page_id == 0 {
            return Ok((false, 0));
        }
        let tree = BTree::open(
            self.pager.clone(),
            self.realm_id,
            state.catalog_root_page_id,
            state.next_page_id,
            self.page_size,
        );
        let key = Catalog::rekey_state_key();
        match tree.get(&key).await? {
            None => Ok((false, 0)),
            Some(bytes) => {
                let row = Catalog::decode_rekey_state(&bytes)?;
                Ok((row.main_db_done, row.segments_remaining_idx))
            }
        }
    }

    /// Write a rekey watermark with `main_db_done=false` and no segments
    /// rewritten yet. Exposed for integration tests that need to simulate an
    /// interrupted rekey without accessing private fields.
    pub async fn inject_incomplete_rekey_watermark(&self, target_epoch: u64) -> Result<()> {
        self.ensure_usable()?;
        if !matches!(self.mode, crate::txn::mode::DbMode::Standalone) {
            return Err(PagedbError::Unsupported);
        }
        let mut state = self.writer.lock().await;
        self.write_rekey_watermark(&mut state, target_epoch, false, 0)
            .await
    }

    /// Write the rekey watermark into the catalog and commit the header.
    async fn write_rekey_watermark(
        &self,
        state: &mut WriterState,
        target_epoch: u64,
        main_db_done: bool,
        segments_remaining_idx: u32,
    ) -> Result<()> {
        let hk_snapshot = self.hk.read().clone();
        self.write_rekey_watermark_locked(
            state,
            target_epoch,
            main_db_done,
            segments_remaining_idx,
            &hk_snapshot,
        )
        .await
    }

    async fn write_rekey_watermark_locked(
        &self,
        state: &mut WriterState,
        target_epoch: u64,
        main_db_done: bool,
        segments_remaining_idx: u32,
        hk: &crate::crypto::keys::DerivedKey,
    ) -> Result<()> {
        let row = RekeyStateRow {
            target_mk_epoch: target_epoch,
            main_db_done,
            segments_remaining_idx,
        };
        let encoded = Catalog::encode_rekey_state(&row);

        let mut cat_tree = BTree::open(
            self.pager.clone(),
            self.realm_id,
            state.catalog_root_page_id,
            state.next_page_id,
            self.page_size,
        );
        let key = Catalog::rekey_state_key();
        cat_tree.put(&key, &encoded).await?;
        cat_tree.flush().await?;

        let new_catalog_root = cat_tree.root_page_id();
        let new_next = cat_tree.next_page_id().max(state.next_page_id);
        let new_seq = state.seq + 1;
        let counter_anchor = self.pager.pending_anchor();

        let catalog_root_bytes = encode_root_ref(new_catalog_root, state.latest_commit_id);

        let fields = self.header_fields(HeaderFieldsParams {
            mk_epoch: self.mk_epoch.load(Ordering::SeqCst),
            seq: new_seq,
            active_root_page_id: state.root_page_id,
            active_root_txn_id: state.latest_commit_id,
            counter_anchor,
            commit_id: state.latest_commit_id,
            catalog_root: catalog_root_bytes,
            commit_history_root_page_id: 0,
            commit_history_root_version: 0,
            free_list_root_page_id: state.free_list_root_page_id,
            next_page_id: new_next,
        })?;

        let new_slot = commit_header(
            &*self.vfs,
            &self.main_db_path,
            hk,
            &fields,
            state.active_slot,
            self.page_size,
        )
        .await?;

        state.catalog_root_page_id = new_catalog_root;
        state.next_page_id = new_next;
        state.active_slot = new_slot;
        state.seq = new_seq;
        let _ = self
            .finish_durable_commit(
                state,
                crate::CommitId(state.latest_commit_id),
                counter_anchor,
                &[],
            )
            .await?;

        Ok(())
    }

    /// Remove the rekey watermark row from the catalog and commit.
    async fn clear_rekey_watermark(
        &self,
        state: &mut WriterState,
        hk: &crate::crypto::keys::DerivedKey,
    ) -> Result<()> {
        if state.catalog_root_page_id == 0 {
            return Ok(());
        }
        let mut cat_tree = BTree::open(
            self.pager.clone(),
            self.realm_id,
            state.catalog_root_page_id,
            state.next_page_id,
            self.page_size,
        );
        let key = Catalog::rekey_state_key();
        // Delete returns false if the key wasn't present; ignore that.
        let _ = cat_tree.delete(&key).await?;
        cat_tree.flush().await?;

        let new_catalog_root = cat_tree.root_page_id();
        let new_next = cat_tree.next_page_id().max(state.next_page_id);
        let new_seq = state.seq + 1;
        let counter_anchor = self.pager.pending_anchor();

        let catalog_root_bytes = encode_root_ref(new_catalog_root, state.latest_commit_id);

        let fields = self.header_fields(HeaderFieldsParams {
            mk_epoch: self.mk_epoch.load(Ordering::SeqCst),
            seq: new_seq,
            active_root_page_id: state.root_page_id,
            active_root_txn_id: state.latest_commit_id,
            counter_anchor,
            commit_id: state.latest_commit_id,
            catalog_root: catalog_root_bytes,
            commit_history_root_page_id: 0,
            commit_history_root_version: 0,
            free_list_root_page_id: state.free_list_root_page_id,
            next_page_id: new_next,
        })?;

        let new_slot = commit_header(
            &*self.vfs,
            &self.main_db_path,
            hk,
            &fields,
            state.active_slot,
            self.page_size,
        )
        .await?;

        state.catalog_root_page_id = new_catalog_root;
        state.next_page_id = new_next;
        state.active_slot = new_slot;
        state.seq = new_seq;
        let _ = self
            .finish_durable_commit(
                state,
                crate::CommitId(state.latest_commit_id),
                counter_anchor,
                &[],
            )
            .await?;

        Ok(())
    }
}
