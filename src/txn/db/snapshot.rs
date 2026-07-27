//! Snapshot export, restore, and incremental apply. Native-only (requires
//! filesystem access via the VFS root path).

#![cfg(not(target_arch = "wasm32"))]

use std::collections::BTreeSet;

use crate::pager::header::commit_header;
use crate::pager::structural_header::MainDbHeaderFields;
use crate::recovery::journal::{
    ApplyJournalRecord, JournalAction, encode_journal_id, encode_journal_pages,
};
use crate::snapshot::apply::{
    apply_delta_pages, stage_snapshot_segments, validate_snapshot_segment_count,
};
use crate::snapshot::export::{
    SnapshotManifest, decode_manifest, open_manifest, snapshot_full, snapshot_incremental,
};
use crate::txn::mode::DbMode;
use crate::vfs::Vfs;
use crate::vfs::tokio_backend::TokioVfs;
use tokio::fs;
use tokio::io::AsyncReadExt;

use super::core::{Db, ReaderSnapshot};
use super::util::{get_vfs_root, page_size_log2};

async fn collect_tree_page_ids<V: Vfs + Clone>(
    db: &Db<V>,
    active_root_page_id: u64,
    catalog_root_page_id: u64,
    next_page_id: u64,
) -> crate::Result<BTreeSet<u64>> {
    let mut page_ids = BTreeSet::new();
    for root_page_id in [active_root_page_id, catalog_root_page_id] {
        if root_page_id == 0 {
            continue;
        }
        let tree = crate::btree::BTree::open(
            db.pager.clone(),
            db.realm_id,
            root_page_id,
            next_page_id,
            db.page_size,
        );
        tree.collect_all_page_ids(&mut page_ids).await?;
    }
    Ok(page_ids)
}

/// The two page sets a base state contributes to an incremental apply.
///
/// They are deliberately distinct. `reader_visible` is the data and catalog
/// reachable set — the *only* set both sides of the protocol can compute, so it
/// is what defines which pages a delta must carry. `published` additionally
/// covers the free-list chain and commit-history tree, which
/// [`Db::apply_incremental`] carries over from the follower's own header rather
/// than taking from the producer; those pages stay live across the apply and
/// must never be overwritten, but the producer cannot see them, so they can only
/// ever be a write guard — never part of the delta's definition.
///
/// Conflating the two is what makes a healthy snapshot look malformed:
/// subtracting `published` when deciding *which pages a delta should contain*
/// turns every page the producer legitimately allocated over a follower-local
/// free-list page into an unexplained set mismatch.
struct BasePageSets {
    reader_visible: BTreeSet<u64>,
    published: BTreeSet<u64>,
}

async fn collect_base_page_sets<V: Vfs + Clone>(
    db: &Db<V>,
    snapshot: ReaderSnapshot,
) -> crate::Result<BasePageSets> {
    let reader_visible = collect_tree_page_ids(
        db,
        snapshot.root_page_id,
        snapshot.catalog_root_page_id,
        snapshot.next_page_id,
    )
    .await?;
    let mut published = reader_visible.clone();
    if snapshot.commit_history_root_page_id != 0 {
        let history = crate::btree::BTree::open(
            db.pager.clone(),
            db.realm_id,
            snapshot.commit_history_root_page_id,
            snapshot.next_page_id,
            db.page_size,
        );
        history.collect_all_page_ids(&mut published).await?;
    }
    if snapshot.free_list_root_page_id != 0 {
        let (_entries, chain_pages) = crate::pager::freelist::read_chain(
            &db.pager,
            db.realm_id,
            snapshot.free_list_root_page_id,
        )
        .await?;
        published.extend(chain_pages);
    }
    Ok(BasePageSets {
        reader_visible,
        published,
    })
}

/// What a failed export or restore is allowed to delete.
///
/// Cleanup must undo what the operation created and nothing else. A caller that
/// pre-created an empty output directory — `mkdir -p /backups/snap-1`, then
/// snapshot into it — still owns that directory after a failure, so the
/// distinction is recorded up front rather than inferred afterwards from an
/// `io::ErrorKind` that any number of unrelated operations also produce.
#[derive(Clone, Copy, PartialEq, Eq)]
enum DestinationOwnership {
    /// The directory did not exist; a failure removes it entirely.
    Created,
    /// The directory already existed and was empty; a failure removes only the
    /// contents written into it.
    PreExisting,
}

/// Require an empty destination and record whether it already existed.
///
/// A non-empty destination is refused rather than merged into: a snapshot
/// artifact describes one exact state, and mixing it with unrelated pre-existing
/// pages or segment files produces a directory that authenticates as neither.
async fn claim_empty_destination(
    dst_path: &std::path::Path,
) -> crate::Result<DestinationOwnership> {
    match fs::read_dir(dst_path).await {
        Ok(mut entries) => {
            if entries
                .next_entry()
                .await
                .map_err(crate::errors::PagedbError::Io)?
                .is_some()
            {
                return Err(crate::errors::PagedbError::Io(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    format!("snapshot destination is not empty: {}", dst_path.display()),
                )));
            }
            Ok(DestinationOwnership::PreExisting)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(DestinationOwnership::Created)
        }
        Err(error) => Err(crate::errors::PagedbError::Io(error)),
    }
}

/// Roll back a failed export or restore, leaving the destination reusable.
///
/// Errors are discarded deliberately: the caller is already returning the
/// failure that matters, and a cleanup error must not replace it with something
/// less diagnostic.
async fn cleanup_failed_snapshot(dst_path: &std::path::Path, ownership: DestinationOwnership) {
    match ownership {
        DestinationOwnership::Created => {
            let _ = fs::remove_dir_all(dst_path).await;
        }
        DestinationOwnership::PreExisting => {
            let Ok(mut entries) = fs::read_dir(dst_path).await else {
                return;
            };
            while let Ok(Some(entry)) = entries.next_entry().await {
                let path = entry.path();
                if entry.file_type().await.is_ok_and(|kind| kind.is_dir()) {
                    let _ = fs::remove_dir_all(&path).await;
                } else {
                    let _ = fs::remove_file(&path).await;
                }
            }
        }
    }
}

async fn validate_restored_snapshot(
    manifest: &SnapshotManifest,
    restored: &Db<TokioVfs>,
) -> crate::Result<()> {
    let snapshot = *restored.snapshot.read();
    if snapshot.commit_id != manifest.target_commit {
        return Err(crate::errors::PagedbError::snapshot_incompatible(
            "target_commit",
        ));
    }
    if snapshot.next_page_id != manifest.next_page_id_at_target {
        return Err(crate::errors::PagedbError::snapshot_incompatible(
            "next_page_id_at_target",
        ));
    }
    if snapshot.root_page_id != manifest.target_active_root_page_id {
        return Err(crate::errors::PagedbError::snapshot_incompatible(
            "target_active_root_page_id",
        ));
    }
    if snapshot.catalog_root_page_id != manifest.target_catalog_root_page_id {
        return Err(crate::errors::PagedbError::snapshot_incompatible(
            "target_catalog_root_page_id",
        ));
    }

    collect_tree_page_ids(
        restored,
        snapshot.root_page_id,
        snapshot.catalog_root_page_id,
        snapshot.next_page_id,
    )
    .await?;

    let expected_segments = restored.list_segments(restored.realm_id, "").await?;
    let expected_ids: BTreeSet<[u8; 16]> = expected_segments
        .iter()
        .map(|meta| meta.segment_id)
        .collect();
    let mut actual_ids = BTreeSet::new();
    let mut entries = fs::read_dir(restored.vfs.root_path().join("seg"))
        .await
        .map_err(crate::errors::PagedbError::Io)?;
    while let Some(entry) = entries
        .next_entry()
        .await
        .map_err(crate::errors::PagedbError::Io)?
    {
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| crate::errors::PagedbError::snapshot_artifact_invalid("segment.name"))?;
        let segment_id = crate::hex::parse_hex::<16>(&name)
            .ok_or_else(|| crate::errors::PagedbError::snapshot_artifact_invalid("segment.name"))?;
        actual_ids.insert(segment_id);
    }
    if actual_ids != expected_ids
        || u32::try_from(actual_ids.len()).ok() != Some(manifest.segments_count)
    {
        return Err(crate::errors::PagedbError::snapshot_artifact_invalid(
            "segments",
        ));
    }

    let mmap_limit = u64::try_from(restored.options.mmap_view_scratch_bytes).unwrap_or(u64::MAX);
    for meta in expected_segments {
        let reader = crate::segment::reader::SegmentReader::open_internal(
            restored.pager.clone(),
            meta.clone(),
            restored.mmap_bytes_in_use.clone(),
            mmap_limit,
        )
        .await?;
        for page_id in 1..meta.page_count.saturating_sub(1) {
            let _ = reader.read_page(page_id).await?;
        }
    }
    Ok(())
}

impl<V: Vfs + Clone> Db<V> {
    /// Segment rows of the catalog tree rooted at `catalog_root_page_id`.
    ///
    /// Reads the catalog at an explicit root rather than through a `ReadTxn`, so
    /// a caller comparing a base and a target catalog can hold both at once —
    /// and so the base side can be drawn from the same published snapshot its
    /// page sets came from.
    async fn catalog_segment_metas(
        &self,
        catalog_root_page_id: u64,
        next_page_id: u64,
    ) -> crate::Result<Vec<crate::catalog::codec::SegmentMeta>> {
        if catalog_root_page_id == 0 {
            return Ok(Vec::new());
        }
        let tree = crate::btree::BTree::open(
            self.pager.clone(),
            self.realm_id,
            catalog_root_page_id,
            next_page_id,
            self.page_size,
        );
        let rows = tree
            .scan_prefix(&[crate::catalog::codec::CatalogRowKind::Segment as u8])
            .await?;
        let mut entries = Vec::with_capacity(rows.len());
        for (_, value) in rows {
            entries.push(crate::catalog::codec::Catalog::decode_segment_meta(&value)?);
        }
        Ok(entries)
    }

    async fn catalog_segment_ids(
        &self,
        catalog_root_page_id: u64,
        next_page_id: u64,
    ) -> crate::Result<BTreeSet<[u8; 16]>> {
        Ok(self
            .catalog_segment_metas(catalog_root_page_id, next_page_id)
            .await?
            .into_iter()
            .map(|meta| meta.segment_id)
            .collect())
    }

    /// Full verbatim snapshot of the database at the current `latest_commit`.
    ///
    /// Not available on `wasm32` targets (requires native file system access).
    ///
    /// Takes a non-abortable `ReadTxn` to pin the state while files are copied,
    /// then writes `<dst_path>/manifest`, `<dst_path>/main.db`, and all live
    /// segment files under `<dst_path>/seg/<hex(id)>`.
    pub async fn snapshot_to(
        &self,
        dst_path: &std::path::Path,
    ) -> crate::Result<crate::snapshot::SnapshotStats> {
        self.ensure_usable()?;
        let _span = tracing::debug_span!("snapshot.export");

        // Pin the current published state with a non-abortable read txn.
        let txn = self.begin_read_non_abortable().await?;

        let (target_commit, next_page_id) = { (txn.commit_id().0, txn.next_page_id()) };
        let target_active_root_page_id = txn.root_page_id();
        let target_catalog_root_page_id = txn.catalog_root_page_id();

        // Collect live segment ids from the pinned catalog snapshot.
        let segments = txn.list_segments("").await?;
        let segment_ids: Vec<[u8; 16]> = segments.iter().map(|m| m.segment_id).collect();
        let segments_count = u32::try_from(segment_ids.len()).unwrap_or(u32::MAX);

        // The manifest HK-MAC key is the DB's in-memory HK bytes (first 32 bytes).
        let hk_raw: [u8; 32] = {
            let hk_guard = self.hk.read();
            *hk_guard.as_bytes()
        };

        let manifest = SnapshotManifest {
            version: 1,
            kind: 0, // Full
            target_commit,
            base_commit: 0,
            file_id: self.file_id,
            mk_epoch: self.mk_epoch.load(std::sync::atomic::Ordering::SeqCst),
            kek_salt: self.kek_salt,
            cipher_id: self.cipher_id.as_byte(),
            page_size: self.page_size.try_into().unwrap_or(4096),
            next_page_id_at_target: next_page_id,
            segments_count,
            realm_id: self.realm_id.0,
            target_active_root_page_id,
            target_catalog_root_page_id,
        };

        let src_root = get_vfs_root(&*self.vfs)?;
        let ownership = claim_empty_destination(dst_path).await?;
        // Bound before the await: the guard is a `parking_lot` read lock and
        // must not be alive across a suspension point. This is a length floor
        // for the verbatim `main.db` copy, not a set-membership claim, so the
        // currently published snapshot is the right source even though `txn`
        // pins a possibly earlier commit — any later commit only grows the file.
        let published_snapshot = *self.snapshot.read();
        let required_page_ids = collect_base_page_sets(self, published_snapshot)
            .await?
            .published;
        let highest_required_main_page = required_page_ids.iter().next_back().copied().unwrap_or(1);
        let stats = match snapshot_full(
            &src_root,
            dst_path,
            &manifest,
            &hk_raw,
            &segment_ids,
            highest_required_main_page,
        )
        .await
        {
            Ok(stats) => stats,
            Err(error) => {
                cleanup_failed_snapshot(dst_path, ownership).await;
                return Err(error);
            }
        };
        drop(txn); // unpin
        Ok(stats)
    }

    /// Associated fn. Copy snapshot from `src_path` into `dst_path` and return
    /// a `Db` in `DbMode::ReadOnly`.
    ///
    /// Verifies the manifest HK-MAC using `kek` before copying; returns
    /// `Corruption` on failure.
    pub async fn restore_from(
        src_path: &std::path::Path,
        dst_path: &std::path::Path,
        options: crate::options::OpenOptions,
        kek: impl Into<crate::crypto::SecretKey>,
    ) -> crate::Result<crate::txn::db::Db<crate::vfs::tokio_backend::TokioVfs>> {
        let kek = kek.into();
        let _span = tracing::debug_span!("snapshot.apply");

        // Verify and parse manifest.
        let manifest_src = src_path.join("manifest");
        let manifest = open_manifest(&manifest_src, kek.as_bytes()).await?;
        if manifest.kind != 0 {
            return Err(crate::errors::PagedbError::snapshot_incompatible("kind"));
        }
        let ownership = claim_empty_destination(dst_path).await?;

        let restore_result = async {
            // Create destination directory.
            fs::create_dir_all(dst_path)
                .await
                .map_err(crate::errors::PagedbError::Io)?;
            let seg_dst = dst_path.join("seg");
            fs::create_dir_all(&seg_dst)
                .await
                .map_err(crate::errors::PagedbError::Io)?;

            // Copy the already length- and MAC-validated manifest.
            fs::copy(&manifest_src, dst_path.join("manifest"))
                .await
                .map_err(crate::errors::PagedbError::Io)?;

            // Copy main.db.
            fs::copy(src_path.join("main.db"), dst_path.join("main.db"))
                .await
                .map_err(crate::errors::PagedbError::Io)?;

            // Copy segment files without collapsing directory or entry errors.
            // Names are screened here, before anything opens the destination: a
            // file that is not a segment identity is an undeclared sidecar, and
            // letting open-time recovery meet it first reports artifact
            // corruption as whatever error that recovery path happens to raise.
            let seg_src = src_path.join("seg");
            let mut copied_segments: u32 = 0;
            match fs::read_dir(&seg_src).await {
                Ok(mut entries) => {
                    while let Some(entry) = entries
                        .next_entry()
                        .await
                        .map_err(crate::errors::PagedbError::Io)?
                    {
                        let name = entry.file_name().into_string().map_err(|_| {
                            crate::errors::PagedbError::snapshot_artifact_invalid("segment.name")
                        })?;
                        if crate::hex::parse_hex::<16>(&name).is_none() {
                            return Err(crate::errors::PagedbError::snapshot_artifact_invalid(
                                "segment.name",
                            ));
                        }
                        fs::copy(entry.path(), seg_dst.join(&name))
                            .await
                            .map_err(crate::errors::PagedbError::Io)?;
                        copied_segments = copied_segments.checked_add(1).ok_or_else(|| {
                            crate::errors::PagedbError::snapshot_artifact_invalid("segments_count")
                        })?;
                    }
                }
                Err(error)
                    if error.kind() == std::io::ErrorKind::NotFound
                        && manifest.segments_count == 0 => {}
                Err(error) => return Err(crate::errors::PagedbError::Io(error)),
            }
            if copied_segments != manifest.segments_count {
                return Err(crate::errors::PagedbError::snapshot_artifact_invalid(
                    "segments",
                ));
            }

            // Open and authenticate every manifest-referenced root and segment
            // before returning a usable handle.
            let page_size = usize::try_from(manifest.page_size)
                .map_err(|_| crate::errors::PagedbError::snapshot_incompatible("page_size"))?;
            let realm_id = crate::RealmId(manifest.realm_id);
            let dst_vfs = TokioVfs::new(dst_path);
            let restored =
                Db::<TokioVfs>::open_read_only(dst_vfs, kek, page_size, realm_id, options).await?;
            validate_restored_snapshot(&manifest, &restored).await?;
            Ok(restored)
        }
        .await;
        if restore_result.is_err() {
            cleanup_failed_snapshot(dst_path, ownership).await;
        }
        restore_result
    }

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

        // A missing base is not an empty baseline: without its roots there is
        // no sound way to determine which pages the follower must preserve.
        let base_txn = self.begin_read_at(base_commit).await?;
        let base_next_page_id = base_txn.next_page_id();
        let base_catalog_root = base_txn.catalog_root_page_id();

        let target_page_ids = collect_tree_page_ids(
            self,
            target_active_root_page_id,
            target_catalog_root_page_id,
            target_next_page_id,
        )
        .await?;
        let base_page_ids = collect_tree_page_ids(
            self,
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

    /// Apply an incremental snapshot to this Follower handle.
    ///
    /// Reads `src_path/pages.delta` and writes pages directly to `main.db`,
    /// then promotes segment files, then commits the new header.
    #[allow(clippy::too_many_lines)]
    pub async fn apply_incremental(
        &self,
        src_path: &std::path::Path,
    ) -> crate::Result<crate::snapshot::ApplyStats> {
        self.ensure_usable()?;
        let _span = tracing::debug_span!("snapshot.apply");

        if !matches!(self.mode, DbMode::Follower) {
            return Err(crate::errors::PagedbError::IdentityForked);
        }
        // An apply owns the complete protocol, including recovery, validation,
        // raw page writes, staging, and post-header reconciliation. A waiting
        // caller re-checks poison state after it acquires the gate.
        let _apply_guard = self.apply_gate.lock().await;
        self.ensure_usable()?;

        // A durable target with an uncleared journal must converge before a
        // later apply can overwrite its retry pointer or staging set.
        self.retry_pending_apply_journal().await?;

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
        self.validate_incremental_manifest(&manifest, &manifest_bytes[118..224])?;
        // One sample of the published base. Its page sets and its segment set
        // are compared against each other below, so drawing them from two
        // independent reads would let a concurrent `gc_now` — which Follower
        // mode permits — split the base state across the comparison and make a
        // valid delta look inconsistent.
        let base_snapshot = *self.snapshot.read();
        let base_pages = collect_base_page_sets(self, base_snapshot).await?;
        let base_segment_ids = self
            .catalog_segment_ids(
                base_snapshot.catalog_root_page_id,
                base_snapshot.next_page_id,
            )
            .await?;

        let page_size = usize::try_from(manifest.page_size)
            .map_err(|_| crate::errors::PagedbError::snapshot_incompatible("page_size"))?;
        validate_snapshot_segment_count(src_path, manifest.segments_count).await?;

        let vfs_root = get_vfs_root(&*self.vfs)?;
        let dst_main_db = vfs_root.join("main.db");

        // Write delta pages to main.db.
        let applied_pages = apply_delta_pages(
            src_path,
            &dst_main_db,
            page_size,
            &base_pages.published,
            manifest.next_page_id_at_target,
        )
        .await?;
        // Raw delta writes bypass the Pager. Discard unpinned main-db cache
        // entries before authenticating the target so a retry cannot validate
        // stale plaintext left by an earlier failed apply.
        self.pager.reset_main_pages();

        let target_page_ids = collect_tree_page_ids(
            self,
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
            .difference(&base_pages.reader_visible)
            .copied()
            .collect();
        if applied_pages.page_ids != expected_delta_page_ids {
            return Err(crate::errors::PagedbError::snapshot_artifact_invalid(
                "pages.delta.reachability",
            ));
        }

        // The complementary difference: pages a reader could reach at the base
        // commit that the target no longer reaches. Nothing in the delta names
        // them — their bytes never changed, only the roots moved off them — so
        // installing the target roots strands them outside both the roots and
        // this handle's free list unless they are folded in below. Derived from
        // the two sets this apply has already walked and authenticated, which
        // is why the delta itself need not carry them: the receiver is the only
        // side that can act on them, and it can already name them exactly.
        let reclaimed_page_ids: BTreeSet<u64> = base_pages
            .reader_visible
            .difference(&target_page_ids)
            .copied()
            .collect();

        let target_segments = self
            .catalog_segment_metas(
                manifest.target_catalog_root_page_id,
                manifest.next_page_id_at_target,
            )
            .await?;
        let target_segment_ids: BTreeSet<[u8; 16]> =
            target_segments.iter().map(|meta| meta.segment_id).collect();
        let expected_promoted_segment_ids: BTreeSet<[u8; 16]> = target_segment_ids
            .difference(&base_segment_ids)
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
        let dst_seg_root = vfs_root.join("seg");
        let staged_ids =
            stage_snapshot_segments(src_path, &dst_seg_root, &expected_promoted_segment_ids)
                .await?;
        if !staged_ids.is_empty() {
            self.vfs.sync_dir("seg/.staging").await?;
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
        let mut state = self.writer.lock().await;
        self.ensure_usable()?;

        // Fold the reclaim set into this handle's own free-list chain, and drop
        // any entry the target has since put back into service. The rewritten
        // chain is staged through the Pager and becomes durable with the very
        // header swap that installs the target roots, so the roots and the
        // free-list accounting for the pages they abandoned can never diverge:
        // a crash before that swap leaves the previous chain and the previous
        // roots both intact, and the retry redoes the fold.
        let alloc_cursor = manifest.next_page_id_at_target.max(state.next_page_id);
        let staged_free_list = self
            .stage_reclaimed_free_list(
                &state,
                &reclaimed_page_ids,
                &target_page_ids,
                new_commit_id,
                alloc_cursor,
            )
            .await?;
        // Back the cursor this apply is about to publish with real extent
        // before the chain pages flush into it, so no observable point has a
        // header naming pages `main.db` does not contain.
        self.ensure_main_db_covers_cursor(staged_free_list.next_page_id)
            .await?;
        self.pager.flush_main(self.realm_id).await?;

        // Write the journal record to a fresh apply-journal sidecar via the
        // Pager AEAD path. A fresh, never-reused `journal_id` guarantees the
        // sidecar's nonce space never collides with another file's under one
        // key. The sidecar may span any number of pages, so the promotion set
        // is unbounded — no single-page ceiling. The 16-byte id is carried in
        // the header's `apply_journal_root` fields after the swap.
        let journal_id = if actions.is_empty() {
            [0u8; 16]
        } else {
            let id = crate::crypto::random::journal_id()?;
            let record = ApplyJournalRecord {
                target_commit_id: new_commit_id,
                actions: actions.clone(),
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
        let (journal_root_page_id, journal_root_version) = encode_journal_id(&journal_id);

        // The target's allocation cursor, extended if hosting the rewritten
        // free-list chain had to bump-allocate past it.
        let new_next_page_id = staged_free_list.next_page_id;

        // Commit the A/B header with the journal root pointing at the slot we
        // just wrote. After this commit, a crash-recovery replay can re-execute
        // the promote renames idempotently.
        let new_seq = state
            .seq
            .checked_add(1)
            .ok_or_else(|| crate::errors::PagedbError::arithmetic_overflow("apply sequence"))?;
        let counter_anchor = self.pager.pending_anchor();

        // Install the target trees the producer shipped in the manifest. The
        // delta pages just written to main.db contain these root pages; pointing
        // the header at them is what advances the data and catalog trees past the
        // base snapshot (without this, incrementally-applied rows and segments
        // are unreachable from the follower's catalog).
        let new_root_page_id = manifest.target_active_root_page_id;
        let new_catalog_root_page_id = manifest.target_catalog_root_page_id;

        let mut catalog_root_bytes = [0u8; 16];
        catalog_root_bytes[..8].copy_from_slice(&new_catalog_root_page_id.to_le_bytes());
        catalog_root_bytes[8..].copy_from_slice(&new_commit_id.to_le_bytes());

        let fields_with_journal = MainDbHeaderFields {
            format_version: 1,
            cipher_id: self.cipher_id.as_byte(),
            page_size_log2: page_size_log2(self.page_size)?,
            flags: 0,
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
            commit_history_root_page_id: state.commit_history_root_page_id,
            commit_history_root_version: state.commit_history_root_version,
            restore_mode: state.restore_mode,
            next_page_id: new_next_page_id,
            commit_retain_policy_tag: state.commit_retain_policy_tag,
            commit_retain_policy_value: state.commit_retain_policy_value,
        };

        let hk_clone = { self.hk.read().clone() };
        let new_slot = commit_header(
            &*self.vfs,
            &self.main_db_path,
            &hk_clone,
            &fields_with_journal,
            state.active_slot,
            self.page_size,
        )
        .await?;
        // The target header is durable. Advance only internal writer state;
        // prior readers remain on the old snapshot until the nonce anchor and
        // journal actions establish a safe target directory.
        state.active_slot = new_slot;
        state.seq = new_seq;
        state.latest_commit_id = new_commit_id;
        state.next_page_id = new_next_page_id;
        state.root_page_id = new_root_page_id;
        state.catalog_root_page_id = new_catalog_root_page_id;
        state.catalog_root_txn_id = new_commit_id;
        state.free_list_root_page_id = staged_free_list.free_list_root_page_id;
        // The header is the source of truth for a pending apply. Mirror it in
        // live writer state immediately so every subsequent operation sees the
        // same retry obligation.
        state.pending_apply_journal_id = journal_id;

        if self.pager.commit_anchor(counter_anchor).is_err() {
            let commit = crate::CommitId(new_commit_id);
            self.poison(commit);
            return Err(crate::errors::PagedbError::durably_committed_but_unpublished(commit));
        }

        if actions.is_empty() {
            self.publish_snapshot(&state);
            drop(state);
        } else {
            drop(state);
            self.retry_pending_apply_journal().await?;
        }

        Ok(crate::snapshot::ApplyStats {
            pages_applied: applied_pages.pages_applied,
            segments_promoted,
            segments_tombstoned,
        })
    }
}
