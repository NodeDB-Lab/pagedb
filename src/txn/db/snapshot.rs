//! Snapshot export, restore, and incremental apply. Native-only (requires
//! filesystem access via the VFS root path).

#![cfg(not(target_arch = "wasm32"))]

use crate::pager::structural_header::MainDbHeaderFields;
use crate::vfs::Vfs;

use super::core::Db;
use super::util::{get_vfs_root, page_size_log2};

impl<V: Vfs + Clone> Db<V> {
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
        use crate::snapshot::export::{SnapshotManifest, snapshot_full};

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

        let stats = snapshot_full(&src_root, dst_path, &manifest, &hk_raw, &segment_ids).await?;
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
        kek: [u8; 32],
    ) -> crate::Result<crate::txn::db::Db<crate::vfs::tokio_backend::TokioVfs>> {
        use crate::snapshot::export::open_manifest;
        use crate::vfs::tokio_backend::TokioVfs;
        use tokio::fs;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let _span = tracing::debug_span!("snapshot.apply");

        // Verify and parse manifest.
        let manifest_src = src_path.join("manifest");
        let manifest = open_manifest(&manifest_src, &kek).await?;

        // Create destination directory.
        fs::create_dir_all(dst_path)
            .await
            .map_err(crate::errors::PagedbError::Io)?;
        let seg_dst = dst_path.join("seg");
        fs::create_dir_all(&seg_dst)
            .await
            .map_err(crate::errors::PagedbError::Io)?;

        // Copy manifest.
        let mut manifest_bytes = [0u8; 240];
        {
            let mut f = fs::File::open(&manifest_src)
                .await
                .map_err(crate::errors::PagedbError::Io)?;
            f.read_exact(&mut manifest_bytes)
                .await
                .map_err(crate::errors::PagedbError::Io)?;
        }
        {
            let mut f = fs::File::create(dst_path.join("manifest"))
                .await
                .map_err(crate::errors::PagedbError::Io)?;
            f.write_all(&manifest_bytes)
                .await
                .map_err(crate::errors::PagedbError::Io)?;
        }

        // Copy main.db.
        fs::copy(src_path.join("main.db"), dst_path.join("main.db"))
            .await
            .map_err(crate::errors::PagedbError::Io)?;

        // Copy segment files.
        let seg_src = src_path.join("seg");
        if let Ok(mut rd) = fs::read_dir(&seg_src).await {
            while let Ok(Some(entry)) = rd.next_entry().await {
                let name = entry.file_name();
                let src_file = seg_src.join(&name);
                let dst_file = seg_dst.join(&name);
                fs::copy(&src_file, &dst_file)
                    .await
                    .map_err(crate::errors::PagedbError::Io)?;
            }
        }

        // Open the restored Db in ReadOnly mode.
        let page_size = manifest.page_size as usize;
        let realm_id = crate::RealmId(manifest.realm_id);
        let dst_vfs = TokioVfs::new(dst_path);
        Db::<TokioVfs>::open_read_only(dst_vfs, kek, page_size, realm_id, options).await
    }

    /// Page-diff snapshot since `base_commit`. Emits only pages changed since
    /// the base commit, plus segment files new/changed since that commit.
    pub async fn snapshot_incremental_to(
        &self,
        base_commit: crate::CommitId,
        dst_path: &std::path::Path,
    ) -> crate::Result<crate::snapshot::SnapshotStats> {
        use crate::snapshot::export::{SnapshotManifest, snapshot_incremental};

        self.ensure_usable()?;
        // Pin the current published state.
        let txn = self.begin_read_non_abortable().await?;

        let target_commit = txn.commit_id().0;
        let target_next_page_id = txn.next_page_id();
        let target_active_root_page_id = txn.root_page_id();
        let target_catalog_root_page_id = txn.catalog_root_page_id();

        // Get base snapshot's next_page_id by reading the commit history.
        let base_txn_result = self.begin_read_at(base_commit).await;
        let base_next_page_id = base_txn_result
            .as_ref()
            .map_or(0u64, crate::txn::ReadTxn::next_page_id);
        let base_catalog_root = base_txn_result
            .as_ref()
            .map_or(0u64, crate::txn::ReadTxn::catalog_root_page_id);

        // Pages changed = all pages with page_id >= base_next_page_id (allocated after base).
        // Also include all pages reachable from current root that have id >= base_next_page_id.
        let changed_page_ids: Vec<u64> = (base_next_page_id..target_next_page_id).collect();

        // Current segments.
        let current_segments = txn.list_segments("").await?;
        // Base segments (from base catalog).
        let base_segments: Vec<crate::catalog::codec::SegmentMeta> = if base_catalog_root != 0 {
            match &base_txn_result {
                Ok(bt) => bt.list_segments("").await.unwrap_or_default(),
                Err(_) => Vec::new(),
            }
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

        let stats = snapshot_incremental(
            &src_root,
            dst_path,
            &manifest,
            &hk_raw,
            &new_segments,
            base_next_page_id,
            &changed_page_ids,
        )
        .await?;

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
        use crate::pager::header::commit_header;
        use crate::recovery::journal::{
            ApplyJournalRecord, JournalAction, encode_journal_id, encode_journal_pages,
        };
        use crate::snapshot::apply::{
            apply_delta_pages, stage_snapshot_segments, validate_snapshot_segment_count,
        };
        use crate::txn::mode::DbMode;

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
            use tokio::fs;
            use tokio::io::AsyncReadExt;
            let mut f = fs::File::open(&manifest_path)
                .await
                .map_err(crate::errors::PagedbError::Io)?;
            let mut buf = [0u8; 240];
            let _ = f
                .read_exact(&mut buf)
                .await
                .map_err(crate::errors::PagedbError::Io)?;
            buf
        };
        let manifest = crate::snapshot::export::decode_manifest(&manifest_bytes, &hk_raw)?;
        self.validate_incremental_manifest(&manifest, &manifest_bytes[118..224])?;

        let page_size = usize::try_from(manifest.page_size)
            .map_err(|_| crate::errors::PagedbError::snapshot_incompatible("page_size"))?;
        validate_snapshot_segment_count(src_path, manifest.segments_count).await?;

        let vfs_root = get_vfs_root(&*self.vfs)?;
        let dst_main_db = vfs_root.join("main.db");

        // Write delta pages to main.db.
        let pages_applied = apply_delta_pages(src_path, &dst_main_db, page_size).await?;

        // Stage new segment files in `.staging/` so they can be promoted
        // atomically after the header swap via the apply journal.
        let dst_seg_root = vfs_root.join("seg");
        let staging_dir = dst_seg_root.join(".staging");
        let staging_existed = match tokio::fs::metadata(&staging_dir).await {
            Ok(_) => true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => return Err(crate::errors::PagedbError::Io(error)),
        };
        let staged_ids = stage_snapshot_segments(src_path, &dst_seg_root).await?;
        let segments_promoted = u32::try_from(staged_ids.len())
            .map_err(|_| crate::errors::PagedbError::snapshot_incompatible("segments_count"))?;
        if segments_promoted != manifest.segments_count {
            for segment_id in &staged_ids {
                let path = staging_dir.join(crate::hex::to_hex_lower(segment_id));
                tokio::fs::remove_file(path)
                    .await
                    .map_err(crate::errors::PagedbError::Io)?;
            }
            if !staging_existed {
                tokio::fs::remove_dir(&staging_dir)
                    .await
                    .map_err(crate::errors::PagedbError::Io)?;
            }
            return Err(crate::errors::PagedbError::snapshot_incompatible(
                "segments_count",
            ));
        }

        let new_commit_id = manifest.target_commit;
        let mut state = self.writer.lock().await;
        self.ensure_usable()?;

        // Reconcile the target catalog against the currently published one.
        // The target pages are already present on disk, so this comparison can
        // record both staged promotions and old live segments that must be
        // tombstoned after the header becomes durable.
        let old_segments = self.list_all_segments(&state).await?;
        let target_catalog_root = manifest.target_catalog_root_page_id;
        let target_segments = if target_catalog_root == 0 {
            Vec::new()
        } else {
            let tree = crate::btree::BTree::open(
                self.pager.clone(),
                self.realm_id,
                target_catalog_root,
                manifest.next_page_id_at_target,
                self.page_size,
            );
            let rows = tree.collect_range(&[0x01], &[0x02]).await?;
            let mut entries = Vec::with_capacity(rows.len());
            for (_, value) in rows {
                entries.push(crate::catalog::codec::Catalog::decode_segment_meta(&value)?);
            }
            entries
        };
        let target_ids: std::collections::HashSet<[u8; 16]> =
            target_segments.iter().map(|meta| meta.segment_id).collect();
        let mut actions: Vec<JournalAction> = staged_ids
            .iter()
            .map(|&segment_id| JournalAction::Promote { segment_id })
            .collect();
        actions.extend(old_segments.into_iter().filter_map(|meta| {
            (!target_ids.contains(&meta.segment_id)).then_some(JournalAction::Tombstone {
                segment_id: meta.segment_id,
                tombstone_commit_id: new_commit_id,
            })
        }));

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

        // Commit the A/B header with the journal root pointing at the slot we
        // just wrote. After this commit, a crash-recovery replay can re-execute
        // the promote renames idempotently.
        let new_next_page_id = manifest.next_page_id_at_target;
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
            free_list_root: crate::txn::db::encode_free_list_root(state.free_list_root_page_id),
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
            pages_applied,
            segments_promoted,
            segments_tombstoned: 0,
        })
    }
}
