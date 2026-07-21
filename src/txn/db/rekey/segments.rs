//! Stable identity-keyed migration of immutable segment files during rekey.

use std::collections::{BTreeMap, BTreeSet};

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

struct SegmentEntry {
    key: Vec<u8>,
    meta: SegmentMeta,
}

impl<V: Vfs + Clone> Db<V> {
    /// Returns whether any catalog-linked segment still requires migration.
    /// A progress row whose source is no longer catalog-linked is only stale
    /// bookkeeping: catalog replacement has already published the successor,
    /// while pending tombstone ownership retains cleanup of the old file.
    pub(super) async fn rekey_segments_pending(
        &self,
        state: &WriterState,
        intent: &RekeyIntent,
    ) -> Result<bool> {
        Ok(self
            .segment_entries(state)
            .await?
            .iter()
            .any(|entry| Self::segment_needs_rekey(&entry.meta, intent)))
    }

    /// Snapshot source identities, then resolve every operation against the
    /// current catalog by identity. Catalog ordering and embedder names never
    /// participate in migration progress.
    pub(super) async fn migrate_rekey_segments(
        &self,
        state: &mut WriterState,
        intent: &RekeyIntent,
        target_hk: &DerivedKey,
    ) -> Result<()> {
        let mut source_ids = BTreeSet::new();
        for entry in self.segment_entries(state).await? {
            if Self::segment_needs_rekey(&entry.meta, intent) {
                source_ids.insert(entry.meta.segment_id);
            }
        }
        for source_id in self.rekey_progress_rows(state).await?.keys() {
            source_ids.insert(*source_id);
        }

        for source_id in source_ids {
            self.migrate_rekey_segment(state, intent, target_hk, source_id)
                .await?;
        }
        Ok(())
    }

    fn segment_needs_rekey(meta: &SegmentMeta, intent: &RekeyIntent) -> bool {
        // Rekey has no target-cipher API. Segments using a different persisted
        // cipher are not silently folded into this transition; their routing is
        // a separate compatibility concern.
        meta.cipher_id == intent.source_cipher_id && meta.mk_epoch != intent.target_mk_epoch
    }

    async fn migrate_rekey_segment(
        &self,
        state: &mut WriterState,
        intent: &RekeyIntent,
        target_hk: &DerivedKey,
        source_id: [u8; 16],
    ) -> Result<()> {
        for _ in 0..2 {
            let progress = self.rekey_progress_rows(state).await?.remove(&source_id);
            let source = self.segment_entry_by_id(state, source_id).await?;

            let Some(progress) = progress else {
                let Some(source) = source else {
                    return Ok(());
                };
                if !Self::segment_needs_rekey(&source.meta, intent) {
                    return Ok(());
                }
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
                for page_id in 1..source.meta.page_count.saturating_sub(1) {
                    let (kind, body) = reader.read_authenticated_page(page_id).await?;
                    let copied_page_id = writer.append_rekey_page(kind, &body).await?;
                    if copied_page_id != page_id {
                        return Err(PagedbError::corruption(
                            crate::errors::CorruptionDetail::HeaderUnverifiable,
                        ));
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
                    return Err(PagedbError::corruption(
                        crate::errors::CorruptionDetail::HeaderUnverifiable,
                    ));
                }
                self.write_rekey_progress(
                    state,
                    source_id,
                    RekeySegmentProgress {
                        replacement_segment_id: replacement_id,
                        state: RekeySegmentProgressState::Sealed,
                    },
                    intent.target_mk_epoch,
                    target_hk,
                )
                .await?;
                continue;
            };

            let Some(source) = source else {
                return self
                    .finish_orphaned_rekey_progress(state, intent, target_hk, source_id, progress)
                    .await;
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
                .await?;
            return Ok(());
        }
        Err(PagedbError::corruption(
            crate::errors::CorruptionDetail::HeaderUnverifiable,
        ))
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
            tree.root_page_id(),
            tree.next_page_id(),
            intent.target_mk_epoch,
            target_hk,
            &effects,
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
        self.commit_rekey_catalog_root(
            state,
            tree.root_page_id(),
            tree.next_page_id(),
            header_epoch,
            header_hk,
            &[],
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
        self.commit_rekey_catalog_root(
            state,
            tree.root_page_id(),
            tree.next_page_id(),
            header_epoch,
            header_hk,
            &[],
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

    async fn rekey_progress_rows(
        &self,
        state: &WriterState,
    ) -> Result<BTreeMap<[u8; 16], RekeySegmentProgress>> {
        if state.catalog_root_page_id == 0 {
            return Ok(BTreeMap::new());
        }
        let tree = self.rekey_catalog_tree(state);
        let start = vec![CatalogRowKind::RekeySegmentProgress as u8];
        let rows = tree.scan_prefix(&start).await?;
        let mut out = BTreeMap::new();
        for (key, value) in rows {
            if key.len() != 17 {
                return Err(PagedbError::corruption(
                    crate::errors::CorruptionDetail::HeaderUnverifiable,
                ));
            }
            let mut source_id = [0u8; 16];
            source_id.copy_from_slice(&key[1..17]);
            out.insert(source_id, Catalog::decode_rekey_segment_progress(&value)?);
        }
        Ok(out)
    }

    async fn segment_entries(&self, state: &WriterState) -> Result<Vec<SegmentEntry>> {
        if state.catalog_root_page_id == 0 {
            return Ok(Vec::new());
        }
        let tree = self.rekey_catalog_tree(state);
        let start = vec![CatalogRowKind::Segment as u8];
        tree.scan_prefix(&start)
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

    async fn segment_entry_by_id(
        &self,
        state: &WriterState,
        segment_id: [u8; 16],
    ) -> Result<Option<SegmentEntry>> {
        Ok(self
            .segment_entries(state)
            .await?
            .into_iter()
            .find(|entry| entry.meta.segment_id == segment_id))
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
