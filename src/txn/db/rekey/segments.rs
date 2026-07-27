//! Stable identity-keyed migration of immutable segment files during rekey.

use crate::Result;
use crate::btree::BTree;
use crate::catalog::codec::{
    Catalog, CatalogRowKind, RekeyIntent, RekeySegmentProgress, RekeySegmentProgressState,
    SegmentMeta,
};
use crate::crypto::DerivedKey;
use crate::errors::PagedbError;
use crate::segment::reader::SegmentReader;
use crate::segment::writer::SegmentWriter;
use crate::txn::write::SegmentSideEffect;
use crate::vfs::Vfs;

#[cfg(test)]
use super::super::core::RekeyTestFault;
use super::super::core::{Db, WriterState};
use super::main::RekeyCatalogCommit;

/// Catalog rows read per batch while rekey walks segment and progress rows. A
/// segment row is a fixed-width authenticated value plus a name capped at
/// `MAX_SEGMENT_NAME_LEN`, so one batch is a few hundred KiB resident however
/// many segments the catalog holds.
const REKEY_ROW_BATCH: usize = 256;

struct SegmentEntry {
    key: Vec<u8>,
    meta: SegmentMeta,
}

impl<V: Vfs + Clone> Db<V> {
    /// Returns whether any catalog-linked segment still requires migration.
    /// A progress row whose source is no longer catalog-linked is only stale
    /// bookkeeping: catalog replacement has already published the successor,
    /// while pending tombstone ownership retains cleanup of the old file.
    ///
    /// The walk stops at the first row that still needs migrating, so the
    /// resident cost is one batch of rows.
    pub(super) async fn rekey_segments_pending(
        &self,
        state: &WriterState,
        intent: &RekeyIntent,
    ) -> Result<bool> {
        let mut cursor: Vec<u8> = vec![CatalogRowKind::Segment as u8];
        loop {
            let batch = self.segment_batch_from(state, &cursor).await?;
            let Some(last) = batch.last() else {
                return Ok(false);
            };
            cursor.clear();
            cursor.extend_from_slice(&last.key);
            // The exact successor of the last key in the key ordering: resume
            // strictly past the row just examined.
            cursor.push(0);
            let exhausted = batch.len() < REKEY_ROW_BATCH;

            if batch
                .iter()
                .any(|entry| Self::segment_needs_rekey(&entry.meta, intent))
            {
                return Ok(true);
            }
            if exhausted {
                return Ok(false);
            }
        }
    }

    /// Migrate every catalog-linked segment to the target epoch, then drain any
    /// progress row whose source the catalog no longer names.
    ///
    /// Both passes stream the catalog in fixed-size batches, and each segment is
    /// migrated from the row that carried it. Resolving a source by identity
    /// instead — the earlier shape — cost a full catalog scan per segment, so a
    /// rekey was quadratic in segment count; here each pass reads the catalog
    /// once and holds one batch resident.
    ///
    /// Migration replaces a row's value under its own key and otherwise touches
    /// only the disjoint progress-row prefix, so key order is stable across the
    /// mutations and the cursor stays valid. The tree is reopened per batch
    /// because every catalog swap commits a new root.
    pub(super) async fn migrate_rekey_segments(
        &self,
        state: &mut WriterState,
        intent: &RekeyIntent,
        target_hk: &DerivedKey,
    ) -> Result<()> {
        let mut cursor: Vec<u8> = vec![CatalogRowKind::Segment as u8];
        loop {
            let batch = self.segment_batch_from(state, &cursor).await?;
            let Some(last) = batch.last() else {
                break;
            };
            cursor.clear();
            cursor.extend_from_slice(&last.key);
            cursor.push(0);
            let exhausted = batch.len() < REKEY_ROW_BATCH;

            for entry in batch {
                self.migrate_rekey_segment_entry(state, intent, target_hk, entry)
                    .await?;
            }
            if exhausted {
                break;
            }
        }

        self.drain_orphaned_rekey_progress(state, intent, target_hk)
            .await
    }

    /// Resolve every progress row the segment pass left behind.
    ///
    /// That pass clears the progress row of each segment it migrates, so what
    /// remains names a source the catalog no longer carries — its successor was
    /// already published by a durable swap before the interruption. The rows are
    /// streamed and deleted as they are resolved, so the resident cost is one
    /// batch.
    async fn drain_orphaned_rekey_progress(
        &self,
        state: &mut WriterState,
        intent: &RekeyIntent,
        target_hk: &DerivedKey,
    ) -> Result<()> {
        let prefix = [CatalogRowKind::RekeySegmentProgress as u8];
        let mut cursor: Vec<u8> = prefix.to_vec();
        loop {
            if state.catalog_root_page_id == 0 {
                return Ok(());
            }
            let tree = self.rekey_catalog_tree(state);
            let batch = tree
                .collect_prefix_batch_from(&prefix, &cursor, REKEY_ROW_BATCH)
                .await?;
            let Some((last_key, _)) = batch.last() else {
                return Ok(());
            };
            cursor.clear();
            cursor.extend_from_slice(last_key);
            cursor.push(0);
            let exhausted = batch.len() < REKEY_ROW_BATCH;

            for (key, value) in &batch {
                if key.len() != 17 {
                    return Err(PagedbError::rekey_state_invalid(
                        "rekey.segment_progress.key",
                    ));
                }
                let mut source_id = [0u8; 16];
                source_id.copy_from_slice(&key[1..17]);
                let progress = Catalog::decode_rekey_segment_progress(value)?;
                // A source that is somehow still catalog-linked is migrated
                // through the ordinary path; only a genuinely absent one is
                // finished as an orphan.
                match self.segment_entry_by_id(state, source_id).await? {
                    Some(entry) => {
                        self.migrate_rekey_segment_entry(state, intent, target_hk, entry)
                            .await?;
                    }
                    None => {
                        self.finish_orphaned_rekey_progress(
                            state, intent, target_hk, source_id, progress,
                        )
                        .await?;
                    }
                }
            }
            if exhausted {
                return Ok(());
            }
        }
    }

    fn segment_needs_rekey(meta: &SegmentMeta, intent: &RekeyIntent) -> bool {
        // Rekey has no target-cipher API. Segments using a different persisted
        // cipher are not silently folded into this transition; their routing is
        // a separate compatibility concern.
        meta.cipher_id == intent.source_cipher_id && meta.mk_epoch != intent.target_mk_epoch
    }

    /// Migrate one catalog segment row to the target epoch.
    ///
    /// The row is handed in by the streaming pass that read it, so this never
    /// searches the catalog for its source; the only catalog read it makes is a
    /// point lookup of the row's own progress entry. A progress row already
    /// present means a previous attempt sealed the replacement and was
    /// interrupted before the swap — resume from it rather than sealing a second
    /// copy.
    async fn migrate_rekey_segment_entry(
        &self,
        state: &mut WriterState,
        intent: &RekeyIntent,
        target_hk: &DerivedKey,
        source: SegmentEntry,
    ) -> Result<()> {
        let source_id = source.meta.segment_id;
        let progress = if let Some(progress) = self.rekey_progress_row(state, source_id).await? {
            progress
        } else {
            if !Self::segment_needs_rekey(&source.meta, intent) {
                return Ok(());
            }
            self.seal_rekey_replacement(state, intent, target_hk, &source)
                .await?
        };

        let replacement = SegmentReader::open_rekey_replacement(
            self.pager.clone(),
            &source.meta,
            progress.replacement_segment_id,
            intent.target_mk_epoch,
            intent.target_cipher_id,
            self.mmap_bytes_in_use.clone(),
            u64::try_from(self.options.mmap_view_scratch_bytes).unwrap_or(u64::MAX),
        )
        .await?;
        let replacement_meta = replacement.meta().clone();
        self.replace_rekey_segment(
            state,
            intent,
            target_hk,
            &source,
            source_id,
            &replacement_meta,
        )
        .await?;
        #[cfg(test)]
        self.interrupt_rekey_if_requested(RekeyTestFault::CatalogSwapEffects)?;
        // The catalog swap is the migration commit point. A reader may
        // defer the old-file tombstone, but that queue owns eventual GC and
        // must not keep this durable transition open.
        self.delete_rekey_progress(state, source_id, intent.target_mk_epoch, target_hk)
            .await
    }

    /// Copy one source segment into a fresh target-epoch file and record the
    /// durable progress row naming it. Returns that row.
    async fn seal_rekey_replacement(
        &self,
        state: &mut WriterState,
        intent: &RekeyIntent,
        target_hk: &DerivedKey,
        source: &SegmentEntry,
    ) -> Result<RekeySegmentProgress> {
        let replacement_id = crate::crypto::random::segment_id()?;
        let limit = u64::try_from(self.options.mmap_view_scratch_bytes).unwrap_or(u64::MAX);
        let reader = SegmentReader::open_internal(
            self.pager.clone(),
            source.meta.clone(),
            self.mmap_bytes_in_use.clone(),
            limit,
        )
        .await?;
        let footer = reader.authenticated_footer();
        let mut writer = SegmentWriter::create_rekey_internal(
            self.pager.clone(),
            &source.meta,
            replacement_id,
            footer.fields.index_start_page,
            footer.fields.index_page_count,
        )
        .await?;
        writer.set_manifest(&footer.manifest)?;
        // Pages stream one at a time through the pager's own budget; the copy
        // never holds a whole segment resident.
        for page_id in 1..source.meta.page_count.saturating_sub(1) {
            let (kind, body) = reader.read_authenticated_page(page_id).await?;
            let copied_page_id = writer.append_rekey_page(kind, &body).await?;
            if copied_page_id != page_id {
                return Err(PagedbError::rekey_state_invalid("rekey.page_id_ordering"));
            }
        }
        let replacement = writer.seal().await?;
        #[cfg(test)]
        self.interrupt_rekey_if_requested(RekeyTestFault::SegmentSeal)?;
        drop(reader);
        if replacement.page_count != source.meta.page_count
            || replacement.format_version != source.meta.format_version
            || replacement.segment_kind != source.meta.segment_kind
            || replacement.evictable != source.meta.evictable
        {
            return Err(PagedbError::rekey_state_invalid(
                "rekey.replacement_metadata",
            ));
        }
        let progress = RekeySegmentProgress {
            replacement_segment_id: replacement_id,
            state: RekeySegmentProgressState::Sealed,
        };
        self.write_rekey_progress(
            state,
            source.meta.segment_id,
            progress,
            intent.target_mk_epoch,
            target_hk,
        )
        .await?;
        Ok(progress)
    }

    async fn finish_orphaned_rekey_progress(
        &self,
        state: &mut WriterState,
        intent: &RekeyIntent,
        target_hk: &DerivedKey,
        source_id: [u8; 16],
        progress: RekeySegmentProgress,
    ) -> Result<()> {
        let replacement = self
            .segment_entry_by_id(state, progress.replacement_segment_id)
            .await?
            .ok_or(PagedbError::RekeyReplacementMissing {
                replacement_segment_id: progress.replacement_segment_id,
            })?;
        if replacement.meta.mk_epoch != intent.target_mk_epoch
            || replacement.meta.cipher_id != intent.target_cipher_id
        {
            return Err(PagedbError::RekeyReplacementMissing {
                replacement_segment_id: progress.replacement_segment_id,
            });
        }
        // The catalog swap is authoritative, but a crash can leave the
        // replacement in staging before its post-header promotion ran. Finish
        // that publication idempotently; old-source cleanup remains elsewhere.
        let effects = [SegmentSideEffect::Promote {
            segment_id: progress.replacement_segment_id,
        }];
        self.reconcile_segment_effects(&effects, state.latest_commit_id)
            .await?;
        let limit = u64::try_from(self.options.mmap_view_scratch_bytes).unwrap_or(u64::MAX);
        SegmentReader::open_internal(
            self.pager.clone(),
            replacement.meta.clone(),
            self.mmap_bytes_in_use.clone(),
            limit,
        )
        .await
        .map_err(|_| PagedbError::RekeyReplacementMissing {
            replacement_segment_id: progress.replacement_segment_id,
        })?;
        // The source disappeared from the catalog in a prior durable swap.
        // Replaying its tombstone here would turn a reader-deferred cleanup
        // into false corruption after restart; catalog reconciliation and the
        // pending tombstone queue own that unreferenced file instead.
        self.delete_rekey_progress(state, source_id, intent.target_mk_epoch, target_hk)
            .await
    }

    async fn replace_rekey_segment(
        &self,
        state: &mut WriterState,
        intent: &RekeyIntent,
        target_hk: &DerivedKey,
        source: &SegmentEntry,
        source_id: [u8; 16],
        replacement: &SegmentMeta,
    ) -> Result<()> {
        let mut tree = BTree::open(
            self.pager.clone(),
            self.realm_id,
            state.catalog_root_page_id,
            state.next_page_id,
            self.page_size,
        );
        tree.put(&source.key, &Catalog::encode_segment_meta(replacement))
            .await?;
        tree.flush().await?;
        let freed_pages = tree.drain_freed();
        let effects = [
            SegmentSideEffect::Promote {
                segment_id: replacement.segment_id,
            },
            SegmentSideEffect::Tombstone {
                segment_id: source_id,
                tombstone_commit_id: None,
            },
        ];
        self.commit_rekey_catalog_root(
            state,
            RekeyCatalogCommit {
                catalog_root_page_id: tree.root_page_id(),
                next_page_id: tree.next_page_id(),
                freed_pages: &freed_pages,
                effects: &effects,
            },
            intent.target_mk_epoch,
            target_hk,
        )
        .await
        .map(|_| ())
    }

    async fn write_rekey_progress(
        &self,
        state: &mut WriterState,
        source_id: [u8; 16],
        progress: RekeySegmentProgress,
        header_epoch: u64,
        header_hk: &DerivedKey,
    ) -> Result<()> {
        let mut tree = self.rekey_catalog_tree(state);
        tree.put(
            &Catalog::rekey_segment_progress_key(source_id),
            &Catalog::encode_rekey_segment_progress(progress),
        )
        .await?;
        tree.flush().await?;
        let freed_pages = tree.drain_freed();
        self.commit_rekey_catalog_root(
            state,
            RekeyCatalogCommit {
                catalog_root_page_id: tree.root_page_id(),
                next_page_id: tree.next_page_id(),
                freed_pages: &freed_pages,
                effects: &[],
            },
            header_epoch,
            header_hk,
        )
        .await?;
        #[cfg(test)]
        self.interrupt_rekey_if_requested(RekeyTestFault::ProgressRowCommit)?;
        Ok(())
    }

    async fn delete_rekey_progress(
        &self,
        state: &mut WriterState,
        source_id: [u8; 16],
        header_epoch: u64,
        header_hk: &DerivedKey,
    ) -> Result<()> {
        let mut tree = self.rekey_catalog_tree(state);
        let _ = tree
            .delete(&Catalog::rekey_segment_progress_key(source_id))
            .await?;
        tree.flush().await?;
        let freed_pages = tree.drain_freed();
        self.commit_rekey_catalog_root(
            state,
            RekeyCatalogCommit {
                catalog_root_page_id: tree.root_page_id(),
                next_page_id: tree.next_page_id(),
                freed_pages: &freed_pages,
                effects: &[],
            },
            header_epoch,
            header_hk,
        )
        .await?;
        #[cfg(test)]
        self.interrupt_rekey_if_requested(RekeyTestFault::ProgressDeletion)?;
        Ok(())
    }

    fn rekey_catalog_tree(&self, state: &WriterState) -> BTree<V> {
        BTree::open(
            self.pager.clone(),
            self.realm_id,
            state.catalog_root_page_id,
            state.next_page_id,
            self.page_size,
        )
    }

    /// The durable progress row for one source segment, by point lookup.
    ///
    /// The row is keyed by source identity, so this is an O(height) descent —
    /// nothing about it scales with how many segments the catalog holds.
    async fn rekey_progress_row(
        &self,
        state: &WriterState,
        source_id: [u8; 16],
    ) -> Result<Option<RekeySegmentProgress>> {
        if state.catalog_root_page_id == 0 {
            return Ok(None);
        }
        let tree = self.rekey_catalog_tree(state);
        let key = Catalog::rekey_segment_progress_key(source_id);
        let Some(bytes) = tree.get(&key).await? else {
            return Ok(None);
        };
        Ok(Some(Catalog::decode_rekey_segment_progress(&bytes)?))
    }

    /// One bounded batch of catalog segment rows at or after `cursor`.
    async fn segment_batch_from(
        &self,
        state: &WriterState,
        cursor: &[u8],
    ) -> Result<Vec<SegmentEntry>> {
        if state.catalog_root_page_id == 0 {
            return Ok(Vec::new());
        }
        let tree = self.rekey_catalog_tree(state);
        let prefix = [CatalogRowKind::Segment as u8];
        tree.collect_prefix_batch_from(&prefix, cursor, REKEY_ROW_BATCH)
            .await?
            .into_iter()
            .map(|(key, value)| {
                Ok(SegmentEntry {
                    key,
                    meta: Catalog::decode_segment_meta(&value)?,
                })
            })
            .collect()
    }

    /// Resolve a catalog segment row by segment identity.
    ///
    /// The catalog is keyed by `(realm, name)`, so identity has no index to
    /// descend and the rows must be walked. Walking them in bounded batches with
    /// an early exit keeps the resident cost at one batch. Only the
    /// orphaned-progress path needs this, and progress rows are written and
    /// cleared one segment at a time, so the number of such lookups is the
    /// number of rows a single interrupted migration left behind — not a
    /// function of catalog size.
    async fn segment_entry_by_id(
        &self,
        state: &WriterState,
        segment_id: [u8; 16],
    ) -> Result<Option<SegmentEntry>> {
        let mut cursor: Vec<u8> = vec![CatalogRowKind::Segment as u8];
        loop {
            let batch = self.segment_batch_from(state, &cursor).await?;
            let Some(last) = batch.last() else {
                return Ok(None);
            };
            cursor.clear();
            cursor.extend_from_slice(&last.key);
            cursor.push(0);
            let exhausted = batch.len() < REKEY_ROW_BATCH;

            if let Some(entry) = batch
                .into_iter()
                .find(|entry| entry.meta.segment_id == segment_id)
            {
                return Ok(Some(entry));
            }
            if exhausted {
                return Ok(None);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::segment::types::SegmentPageKind;
    use crate::vfs::memory::MemVfs;
    use crate::{RealmId, SegmentKind};

    use super::*;

    const PAGE: usize = 4096;
    const REALM: RealmId = RealmId::new([0x61; 16]);
    const KEK: [u8; 32] = [0x62; 32];

    #[tokio::test(flavor = "current_thread")]
    async fn rekey_preserves_manifest_footer_version_and_extent_index() {
        let db = Db::open_internal(MemVfs::new(), KEK, PAGE, REALM)
            .await
            .unwrap();

        let mut v1_writer = db
            .create_segment(REALM, SegmentKind::Unspecified)
            .await
            .unwrap();
        v1_writer.set_format_version_for_rekey_test(1);
        v1_writer
            .append_page(SegmentPageKind::Data, b"v1-data")
            .await
            .unwrap();
        v1_writer.set_manifest(b"v1-manifest").unwrap();
        let v1_meta = v1_writer.seal().await.unwrap();
        let mut txn = db.begin_write().await.unwrap();
        txn.link_segment("v1", &v1_meta).await.unwrap();
        txn.commit().await.unwrap();

        let mut v2_writer = db
            .create_segment(REALM, SegmentKind::Unspecified)
            .await
            .unwrap();
        let extent = v2_writer
            .append_extent(&[b"v2-extent-a", b"v2-extent-b"])
            .await
            .unwrap();
        v2_writer.set_manifest(b"v2-manifest").unwrap();
        let v2_meta = v2_writer.seal().await.unwrap();
        let mut txn = db.begin_write().await.unwrap();
        txn.link_segment("v2", &v2_meta).await.unwrap();
        txn.commit().await.unwrap();

        db.rekey_db(KEK, 1).await.unwrap();

        let v1 = db.open_segment(REALM, "v1").await.unwrap();
        assert_eq!(v1.meta().format_version, 1);
        assert_eq!(
            v1.authenticated_footer().manifest.as_slice(),
            b"v1-manifest"
        );
        let v2 = db.open_segment(REALM, "v2").await.unwrap();
        assert_eq!(v2.meta().format_version, 2);
        assert_eq!(
            v2.authenticated_footer().manifest.as_slice(),
            b"v2-manifest"
        );
        let pages = v2.find_extent(extent.start_page_id).await.unwrap();
        assert!(pages[0].starts_with(b"v2-extent-a"));
        assert!(pages[1].starts_with(b"v2-extent-b"));
    }
}
