//! Segment creation, lookup, listing, reader-pin checks, and catalog-level
//! segment replacement.

use crate::btree::BTree;
use crate::catalog::codec::CatalogRowKind;
use crate::catalog::codec::{Catalog, SegmentKind, SegmentMeta};
use crate::errors::{CorruptionDetail, PagedbError};
use crate::segment::reader::SegmentReader;
use crate::segment::writer::SegmentWriter;
use crate::txn::write::SegmentSideEffect;
use crate::vfs::types::OpenMode;
use crate::vfs::{Vfs, VfsFile};
use crate::{RealmId, Result};

use super::super::mode::DbMode;
use super::DbModeCapabilities;
use super::core::{Db, PendingTombstone};

/// Catalog segment rows read per batch while testing a reader snapshot for a
/// pin. A row is a fixed-width authenticated value plus a name capped at
/// `MAX_SEGMENT_NAME_LEN`, so one batch is a few hundred KiB resident however
/// many segments the snapshot names.
const READER_PIN_ROW_BATCH: usize = 256;

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
        self.require_mode(
            "create_segment",
            DbMode::Standalone,
            DbModeCapabilities::allows_user_writes,
        )?;
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
        let rows = tree.scan_prefix(&start).await?;
        let mut out = Vec::with_capacity(rows.len());
        for (_k, v) in rows {
            let meta = Catalog::decode_segment_meta(&v)?;
            out.push(meta);
        }
        Ok(out)
    }

    /// Return `true` if any currently tracked reader's catalog snapshot
    /// contains `segment_id`.
    ///
    /// Each snapshot's segment rows are streamed in bounded batches and the
    /// walk stops at the first match, so the resident cost is one batch plus
    /// one root pair per live reader — never one `SegmentMeta` per catalog
    /// entry, which this runs over once per reader on every tombstone.
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
            let prefix = [CatalogRowKind::Segment as u8];
            let mut cursor: Vec<u8> = prefix.to_vec();
            loop {
                let batch = tree
                    .collect_prefix_batch_from(&prefix, &cursor, READER_PIN_ROW_BATCH)
                    .await?;
                let Some((last_key, _)) = batch.last() else {
                    break;
                };
                cursor.clear();
                cursor.extend_from_slice(last_key);
                // The exact successor of `last_key` in the key ordering: resume
                // strictly past the row just examined.
                cursor.push(0);
                let exhausted = batch.len() < READER_PIN_ROW_BATCH;

                for (_, value) in &batch {
                    if Catalog::decode_segment_meta(value)?.segment_id == segment_id {
                        return Ok(true);
                    }
                }

                if exhausted {
                    break;
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

        // Drain part of the deferred queue as a side effect of this commit, so a
        // backlog cannot survive on the assumption that someone schedules GC.
        self.drain_some_pending_tombstones().await?;

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
            // Reaching here means a durable record (a commit's side effects or
            // a replayed apply journal) says this segment is published, yet
            // neither publication location holds it. That is missing data, not
            // a lookup miss the caller can retry differently, so it must not
            // share `NotFound` with "no such segment name".
            return Err(PagedbError::corruption(CorruptionDetail::StagingMissing {
                segment_id,
            }));
        }
        self.vfs.rename(&staging, &live).await
    }

    /// Retire a segment: delete it outright when no reader pins it, otherwise
    /// defer.
    ///
    /// Reclaiming here — in the write path — rather than leaving the file for a
    /// separately-scheduled sweep is what makes disk usage bounded by
    /// construction. Every mature embedded engine works this way (`SQLite`
    /// reuses freelist pages, redb processes its freed tree inside commit). A
    /// retired file that only an explicitly-scheduled call reclaims grows
    /// without bound for any embedder that never schedules it, and segments are
    /// separate files, so the cost is disk exhaustion rather than a file that
    /// merely fails to shrink.
    ///
    /// The rename into `seg/.tombstone/` is KEPT rather than replaced by a
    /// direct unlink: it is the crash boundary the recovery protocol is built
    /// on — a commit whose rename cannot run reports itself unpublished, and a
    /// replay recognises an already-parked tombstone by its recorded commit id.
    /// Reclamation is achieved by deleting the parked file immediately
    /// afterwards, which costs one extra syscall and changes no crash semantics.
    /// A crash between the two leaves a file that the next open sweeps.
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
            // A retirement that was interrupted between the rename and the
            // removal below.
            self.vfs.remove(&tomb).await?;
            return Ok(SegmentReconciliation::Complete);
        }
        let live = crate::segment::writer::live_path(&segment_id);
        if !self.path_exists(&live).await? {
            return Ok(SegmentReconciliation::Complete);
        }
        self.vfs.rename(&live, &tomb).await?;
        self.vfs.remove(&tomb).await?;
        Ok(SegmentReconciliation::Complete)
    }

    /// Re-evaluate a bounded slice of the deferred-tombstone queue.
    ///
    /// Runs on every commit that carries segment effects, so the queue drains as
    /// a side effect of normal writes instead of waiting for an explicit GC —
    /// the same property that makes redb's freed-tree handling self-limiting.
    /// The slice is bounded so a long queue cannot turn one commit into an
    /// unbounded amount of work.
    ///
    /// Entries still pinned by a reader are put back and retried on a later
    /// commit.
    ///
    /// An entry is put back on failure too. The queue is the only record that a
    /// retired file still needs reclaiming, so an entry dropped here is a file
    /// nothing will ever delete — the unbounded growth this drain exists to
    /// prevent, reintroduced by the error path. A transient I/O failure on one
    /// entry must cost a retry, not the record.
    async fn drain_some_pending_tombstones(&self) -> Result<()> {
        const MAX_PER_COMMIT: usize = 32;

        let batch: Vec<PendingTombstone> = {
            let mut entries = self.pending_tombstones.lock();
            let take = entries.len().min(MAX_PER_COMMIT);
            entries.drain(..take).collect()
        };
        let mut batch = batch.into_iter();
        while let Some(entry) = batch.next() {
            let outcome = match self.segment_id_is_reader_pinned(entry.segment_id).await {
                Ok(true) => {
                    self.enqueue_pending_tombstone(entry);
                    continue;
                }
                Ok(false) => {
                    self.tombstone_segment(entry.segment_id, entry.commit_id)
                        .await
                }
                Err(error) => Err(error),
            };
            if let Err(error) = outcome {
                self.enqueue_pending_tombstone(entry);
                for remaining in batch {
                    self.enqueue_pending_tombstone(remaining);
                }
                return Err(error);
            }
        }
        Ok(())
    }

    /// Size of a segment's live file, or `None` if it is already gone.
    ///
    /// Measured before reclamation so callers can report bytes freed. Absence
    /// is `None` rather than zero because the two mean different things to a
    /// caller counting reclaimed segments: a file a commit-time retirement
    /// already deleted was not reclaimed by this call, and reporting it as a
    /// zero-byte reclamation inflates the count with work nobody did.
    pub(super) async fn live_segment_len(&self, segment_id: [u8; 16]) -> Result<Option<u64>> {
        let live = crate::segment::writer::live_path(&segment_id);
        match self.vfs.open(&live, OpenMode::Read).await {
            Ok(file) => file.len().await.map(Some),
            Err(PagedbError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
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
}
