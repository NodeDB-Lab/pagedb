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

use super::core::{Db, PendingTombstone, WriterState};

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
}
