//! Segment creation, lookup, listing, reader-pin checks, and catalog-level
//! segment replacement.

use crate::btree::BTree;
use crate::catalog::codec::CatalogRowKind;
use crate::catalog::codec::{Catalog, SegmentKind, SegmentMeta};
use crate::errors::PagedbError;
use crate::segment::reader::SegmentReader;
use crate::segment::writer::SegmentWriter;
use crate::txn::write::SegmentSideEffect;
use crate::vfs::Vfs;
use crate::vfs::types::OpenMode;
use crate::{RealmId, Result};

use super::core::{Db, HeaderFieldsParams, PendingTombstone, WriterState, encode_root_ref};

/// Result of reconciling post-header segment effects. A deferred tombstone is
/// safe to publish because the old live file is extra data not referenced by
/// the new catalog; its journal or pending-GC entry must remain for retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SegmentReconciliation {
    Complete,
    Deferred,
}

impl<V: Vfs + Clone> Db<V> {
    /// Create a fresh segment in the given realm. The returned writer holds a
    /// handle to `seg/.staging/<hex(segment_id)>`. Sealing the writer makes
    /// the file durable; publication requires a catalog link.
    pub async fn create_segment(
        &self,
        realm: RealmId,
        kind: SegmentKind,
    ) -> Result<SegmentWriter<V>> {
        self.ensure_usable()?;
        if !self.mode.open_capabilities().allows_user_writes() {
            return Err(PagedbError::ReadOnly);
        }
        self.vfs.mkdir_all("seg/.staging").await?;
        let segment_id = crate::crypto::random::segment_id()?;
        SegmentWriter::create_internal(self.pager.clone(), realm, segment_id, self.file_id, kind)
            .await
    }

    /// Open a segment by `(realm, name)` resolved against the live catalog.
    pub async fn open_segment(&self, realm: RealmId, name: &str) -> Result<SegmentReader<V>> {
        self.ensure_usable()?;
        let meta = self.lookup_segment(realm, name).await?;
        let limit = u64::try_from(self.options.mmap_view_scratch_bytes).unwrap_or(u64::MAX);
        SegmentReader::open_internal(
            self.pager.clone(),
            meta,
            self.mmap_bytes_in_use.clone(),
            limit,
        )
        .await
    }

    /// List segments in `realm` whose names start with `prefix`. Live catalog.
    pub async fn list_segments(&self, realm: RealmId, prefix: &str) -> Result<Vec<SegmentMeta>> {
        self.ensure_usable()?;
        let snap = *self.snapshot.read();
        let (catalog_root, next) = (snap.catalog_root_page_id, snap.next_page_id);
        if catalog_root == 0 {
            return Ok(Vec::new());
        }
        let tree = BTree::open(
            self.pager.clone(),
            self.realm_id,
            catalog_root,
            next,
            self.page_size,
        );
        let start = Catalog::segment_key(realm, prefix.as_bytes())?;
        let mut end = start.clone();
        end.push(0xFF);
        let rows = tree.collect_range(&start, &end).await?;
        let mut out = Vec::with_capacity(rows.len());
        for (_k, v) in rows {
            let meta = Catalog::decode_segment_meta(&v)?;
            out.push(meta);
        }
        Ok(out)
    }

    /// Return `true` if any currently tracked reader's catalog snapshot
    /// contains `segment_id`.
    pub(crate) async fn segment_id_is_reader_pinned(&self, segment_id: [u8; 16]) -> Result<bool> {
        let snapshots = {
            let readers = self.tracked_readers.lock();
            readers
                .iter()
                .map(|r| (r.catalog_root_page_id, r.next_page_id))
                .collect::<Vec<_>>()
        };
        for (root, next) in snapshots {
            if root == 0 {
                continue;
            }
            let tree = BTree::open(
                self.pager.clone(),
                self.realm_id,
                root,
                next,
                self.page_size,
            );
            let start = vec![0x01u8];
            let end = vec![0x02u8];
            let rows = tree.collect_range(&start, &end).await?;
            for (_, v) in rows {
                let meta = Catalog::decode_segment_meta(&v)?;
                if meta.segment_id == segment_id {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    pub(crate) async fn reconcile_segment_effects(
        &self,
        effects: &[SegmentSideEffect],
        commit_id: u64,
    ) -> Result<SegmentReconciliation> {
        match self.apply_segment_effects(effects, commit_id).await {
            Ok(outcome) => Ok(outcome),
            Err(first_error) => {
                tracing::debug!(
                    name = "segment.effects.retry",
                    error = %first_error,
                    commit_id,
                    "retrying durable segment reconciliation"
                );
                self.apply_segment_effects(effects, commit_id).await
            }
        }
    }

    /// Reconcile apply-journal actions through the same pin-aware protocol as
    /// ordinary commits. The complete action set is retried once as one unit,
    /// and journal tombstones retain their recorded commit ids.
    pub(crate) async fn reconcile_journal_actions(
        &self,
        actions: &[crate::recovery::journal::JournalAction],
    ) -> Result<SegmentReconciliation> {
        let effects: Vec<SegmentSideEffect> = actions
            .iter()
            .map(|action| match action {
                crate::recovery::journal::JournalAction::Promote { segment_id } => {
                    SegmentSideEffect::Promote {
                        segment_id: *segment_id,
                    }
                }
                crate::recovery::journal::JournalAction::Tombstone {
                    segment_id,
                    tombstone_commit_id,
                } => SegmentSideEffect::Tombstone {
                    segment_id: *segment_id,
                    tombstone_commit_id: Some(*tombstone_commit_id),
                },
            })
            .collect();
        self.reconcile_segment_effects(&effects, 0).await
    }

    async fn apply_segment_effects(
        &self,
        effects: &[SegmentSideEffect],
        commit_id: u64,
    ) -> Result<SegmentReconciliation> {
        if effects.is_empty() {
            return Ok(SegmentReconciliation::Complete);
        }
        self.vfs.mkdir_all("seg").await?;
        self.vfs.mkdir_all("seg/.staging").await?;
        self.vfs.mkdir_all("seg/.tombstone").await?;
        self.vfs.sync_dir("seg").await?;
        self.vfs.sync_dir("seg/.staging").await?;
        self.vfs.sync_dir("seg/.tombstone").await?;

        let mut deferred = false;
        for effect in effects {
            let outcome = match effect {
                SegmentSideEffect::Promote { segment_id } => {
                    self.promote_segment(*segment_id).await?;
                    SegmentReconciliation::Complete
                }
                SegmentSideEffect::Tombstone {
                    segment_id,
                    tombstone_commit_id,
                } => {
                    self.tombstone_segment(*segment_id, tombstone_commit_id.unwrap_or(commit_id))
                        .await?
                }
            };
            deferred |= matches!(outcome, SegmentReconciliation::Deferred);
        }

        self.vfs.sync_dir("seg").await?;
        self.vfs.sync_dir("seg/.staging").await?;
        self.vfs.sync_dir("seg/.tombstone").await?;
        Ok(if deferred {
            SegmentReconciliation::Deferred
        } else {
            SegmentReconciliation::Complete
        })
    }

    async fn promote_segment(&self, segment_id: [u8; 16]) -> Result<()> {
        let live = crate::segment::writer::live_path(&segment_id);
        if self.path_exists(&live).await? {
            return Ok(());
        }
        let staging = crate::segment::writer::staging_path(&segment_id);
        if !self.path_exists(&staging).await? {
            return Err(PagedbError::NotFound);
        }
        self.vfs.rename(&staging, &live).await
    }

    async fn tombstone_segment(
        &self,
        segment_id: [u8; 16],
        commit_id: u64,
    ) -> Result<SegmentReconciliation> {
        if self.segment_id_is_reader_pinned(segment_id).await? {
            self.enqueue_pending_tombstone(PendingTombstone {
                segment_id,
                commit_id,
            });
            return Ok(SegmentReconciliation::Deferred);
        }
        let tomb = format!(
            "seg/.tombstone/{}.{}",
            crate::hex::to_hex_lower(&segment_id),
            commit_id
        );
        if self.path_exists(&tomb).await? {
            return Ok(SegmentReconciliation::Complete);
        }
        let live = crate::segment::writer::live_path(&segment_id);
        if !self.path_exists(&live).await? {
            return Ok(SegmentReconciliation::Complete);
        }
        self.vfs.rename(&live, &tomb).await?;
        Ok(SegmentReconciliation::Complete)
    }

    pub(super) fn enqueue_pending_tombstone(&self, pending: PendingTombstone) {
        let mut entries = self.pending_tombstones.lock();
        if !entries.iter().any(|entry| {
            entry.segment_id == pending.segment_id && entry.commit_id == pending.commit_id
        }) {
            entries.push(pending);
        }
    }

    async fn path_exists(&self, path: &str) -> Result<bool> {
        match self.vfs.open(path, OpenMode::Read).await {
            Ok(_) => Ok(true),
            Err(PagedbError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(false)
            }
            Err(error) => Err(error),
        }
    }

    async fn lookup_segment(&self, realm: RealmId, name: &str) -> Result<SegmentMeta> {
        let snap = *self.snapshot.read();
        let (catalog_root, next) = (snap.catalog_root_page_id, snap.next_page_id);
        if catalog_root == 0 {
            return Err(PagedbError::NotFound);
        }
        let tree = BTree::open(
            self.pager.clone(),
            self.realm_id,
            catalog_root,
            next,
            self.page_size,
        );
        let key = Catalog::segment_key(realm, name.as_bytes())?;
        let value = tree.get(&key).await?.ok_or(PagedbError::NotFound)?;
        Catalog::decode_segment_meta(&value)
    }

    /// List all segment entries in the catalog.
    pub(super) async fn list_all_segments(&self, state: &WriterState) -> Result<Vec<SegmentMeta>> {
        if state.catalog_root_page_id == 0 {
            return Ok(Vec::new());
        }
        let tree = BTree::open(
            self.pager.clone(),
            self.realm_id,
            state.catalog_root_page_id,
            state.next_page_id,
            self.page_size,
        );
        let start = vec![CatalogRowKind::Segment as u8];
        let mut end = start.clone();
        end.push(0xFF);
        let rows = tree.collect_range(&start, &end).await?;
        let mut out = Vec::with_capacity(rows.len());
        for (_k, v) in rows {
            let meta = Catalog::decode_segment_meta(&v)?;
            out.push(meta);
        }
        Ok(out)
    }

    /// Find the catalog name for a segment by its `segment_id`.
    pub(super) async fn find_segment_name(
        &self,
        state: &WriterState,
        segment_id: &[u8; 16],
    ) -> Result<String> {
        if state.catalog_root_page_id == 0 {
            return Err(PagedbError::NotFound);
        }
        let tree = BTree::open(
            self.pager.clone(),
            self.realm_id,
            state.catalog_root_page_id,
            state.next_page_id,
            self.page_size,
        );
        let start = vec![CatalogRowKind::Segment as u8];
        let mut end = start.clone();
        end.push(0xFF);
        let rows = tree.collect_range(&start, &end).await?;
        for (k, v) in rows {
            let meta = Catalog::decode_segment_meta(&v)?;
            if meta.segment_id == *segment_id {
                // Key layout: [0x01] || realm_id[16] || name_bytes
                if k.len() > 17 {
                    let name = String::from_utf8_lossy(&k[17..]).into_owned();
                    return Ok(name);
                }
            }
        }
        Err(PagedbError::NotFound)
    }

    /// Replace a segment in the catalog with a new one and commit the header.
    pub(super) async fn replace_segment_in_catalog(
        &self,
        state: &mut WriterState,
        name: &str,
        old_segment_id: &[u8; 16],
        new_meta: &SegmentMeta,
        hk: &crate::crypto::keys::DerivedKey,
        new_mk_epoch: u64,
    ) -> Result<()> {
        let key = Catalog::segment_key(self.realm_id, name.as_bytes())?;
        let value = Catalog::encode_segment_meta(new_meta);

        let mut cat_tree = BTree::open(
            self.pager.clone(),
            self.realm_id,
            state.catalog_root_page_id,
            state.next_page_id,
            self.page_size,
        );
        cat_tree.put(&key, &value).await?;
        cat_tree.flush().await?;

        let new_catalog_root = cat_tree.root_page_id();
        let new_next = cat_tree.next_page_id().max(state.next_page_id);
        let new_commit_id = state.latest_commit_id + 1;
        let new_seq = state.seq + 1;
        let counter_anchor = self.pager.pending_anchor();

        let catalog_root_bytes = encode_root_ref(new_catalog_root, new_commit_id);

        let fields = self.header_fields(HeaderFieldsParams {
            mk_epoch: new_mk_epoch,
            seq: new_seq,
            active_root_page_id: state.root_page_id,
            active_root_txn_id: state.latest_commit_id,
            counter_anchor,
            commit_id: new_commit_id,
            catalog_root: catalog_root_bytes,
            commit_history_root_page_id: 0,
            commit_history_root_version: 0,
            free_list_root_page_id: state.free_list_root_page_id,
            next_page_id: new_next,
        })?;

        let new_slot = crate::pager::header::commit_header(
            &*self.vfs,
            &self.main_db_path,
            hk,
            &fields,
            state.active_slot,
            self.page_size,
        )
        .await?;
        // The header is durable. Advance the internal writer state before
        // the shared post-durability protocol, while retaining the old reader
        // snapshot until segment reconciliation succeeds.
        state.catalog_root_page_id = new_catalog_root;
        state.catalog_root_txn_id = new_commit_id;
        state.next_page_id = new_next;
        state.active_slot = new_slot;
        state.seq = new_seq;
        state.latest_commit_id = new_commit_id;

        let effects = [
            SegmentSideEffect::Tombstone {
                segment_id: *old_segment_id,
                tombstone_commit_id: None,
            },
            SegmentSideEffect::Promote {
                segment_id: new_meta.segment_id,
            },
        ];
        let _ = self
            .finish_durable_commit(
                state,
                crate::CommitId(new_commit_id),
                counter_anchor,
                &effects,
            )
            .await?;

        Ok(())
    }
}
