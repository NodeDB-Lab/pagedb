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

        let _span = tracing::debug_span!("snapshot.export");

        // Pin the current state via a non-abortable read txn.
        let txn = {
            let w = self.writer.lock().await;
            let cid = crate::CommitId(w.latest_commit_id);
            let root = w.root_page_id;
            let next = w.next_page_id;
            let cat = w.catalog_root_page_id;
            drop(w);
            self.register_read(cid, root, next, cat, true)
        };

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

        // Pin current state.
        let txn = {
            let w = self.writer.lock().await;
            let cid = crate::CommitId(w.latest_commit_id);
            let root = w.root_page_id;
            let next = w.next_page_id;
            let cat = w.catalog_root_page_id;
            drop(w);
            self.register_read(cid, root, next, cat, true)
        };

        let target_commit = txn.commit_id().0;
        let target_next_page_id = txn.next_page_id();
        let target_active_root_page_id = txn.root_page_id();
        let target_catalog_root_page_id = txn.catalog_root_page_id();

        // Get base snapshot's next_page_id by reading the commit history.
        let base_txn_result = self.begin_read_at(base_commit).await;
        let base_next_page_id = match &base_txn_result {
            Ok(bt) => bt.next_page_id(),
            Err(_) => 0u64,
        };
        let base_catalog_root = match &base_txn_result {
            Ok(bt) => bt.catalog_root_page_id(),
            Err(_) => 0u64,
        };

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
            execute_journal_actions,
        };
        use crate::snapshot::apply::{apply_delta_pages, stage_snapshot_segments};
        use crate::txn::mode::DbMode;

        let _span = tracing::debug_span!("snapshot.apply");

        if !matches!(self.mode, DbMode::Follower) {
            return Err(crate::errors::PagedbError::IdentityForked);
        }

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

        let page_size = manifest.page_size as usize;
        let vfs_root = get_vfs_root(&*self.vfs)?;
        let dst_main_db = vfs_root.join("main.db");

        // Write delta pages to main.db.
        let pages_applied = apply_delta_pages(src_path, &dst_main_db, page_size).await?;

        // Stage new segment files in `.staging/` so they can be promoted
        // atomically after the header swap via the apply journal.
        let dst_seg_root = vfs_root.join("seg");
        let staged_ids = stage_snapshot_segments(src_path, &dst_seg_root).await?;
        let segments_promoted = u32::try_from(staged_ids.len()).unwrap_or(u32::MAX);

        // Build journal actions: one Promote per staged segment.
        let new_commit_id = manifest.target_commit;
        let actions: Vec<JournalAction> = staged_ids
            .iter()
            .map(|&segment_id| JournalAction::Promote { segment_id })
            .collect();

        let mut state = self.writer.lock().await;

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
            self.vfs.sync_dir("applyjournal").await.ok();
            id
        };
        let (journal_root_page_id, journal_root_version) = encode_journal_id(&journal_id);

        // Commit the A/B header with the journal root pointing at the slot we
        // just wrote. After this commit, a crash-recovery replay can re-execute
        // the promote renames idempotently.
        let new_next_page_id = manifest.next_page_id_at_target;
        let new_seq = state.seq + 1;
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
            free_list_root: [0; 16],
            catalog_root: catalog_root_bytes,
            apply_journal_root_page_id: journal_root_page_id,
            apply_journal_root_version: journal_root_version,
            commit_history_root_page_id: 0,
            commit_history_root_version: 0,
            restore_mode: 0,
            next_page_id: new_next_page_id,
            commit_retain_policy_tag: 0,
            commit_retain_policy_value: 0,
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
        self.pager.commit_anchor(counter_anchor)?;

        // The header swap is durable. Execute the journal actions (staging →
        // live renames). Each rename is idempotent; a crash here is safe
        // because replay_apply_journal will re-execute on the next open.
        if actions.is_empty() {
            state.active_slot = new_slot;
            state.seq = new_seq;
        } else {
            execute_journal_actions(&*self.vfs, &actions).await;

            // Clear the journal root by writing a second header commit with
            // apply_journal_root_page_id = 0. This marks the journal as complete.
            let new_seq2 = new_seq + 1;
            let counter_anchor2 = self.pager.pending_anchor();
            let fields_clear = MainDbHeaderFields {
                format_version: 1,
                cipher_id: self.cipher_id.as_byte(),
                page_size_log2: page_size_log2(self.page_size)?,
                flags: 0,
                file_id: self.file_id,
                kek_salt: self.kek_salt,
                mk_epoch: self.mk_epoch.load(std::sync::atomic::Ordering::SeqCst),
                seq: new_seq2,
                active_root_page_id: new_root_page_id,
                active_root_txn_id: new_commit_id,
                counter_anchor: counter_anchor2,
                commit_id: crate::CommitId(new_commit_id),
                free_list_root: [0; 16],
                catalog_root: catalog_root_bytes,
                apply_journal_root_page_id: 0,
                apply_journal_root_version: 0,
                commit_history_root_page_id: 0,
                commit_history_root_version: 0,
                restore_mode: 0,
                next_page_id: new_next_page_id,
                commit_retain_policy_tag: 0,
                commit_retain_policy_value: 0,
            };
            let new_slot2 = commit_header(
                &*self.vfs,
                &self.main_db_path,
                &hk_clone,
                &fields_clear,
                new_slot,
                self.page_size,
            )
            .await?;
            self.pager.commit_anchor(counter_anchor2)?;
            state.active_slot = new_slot2;
            state.seq = new_seq2;

            // The journal root is cleared and durable; the sidecar is no longer
            // needed. Remove it (a crash before this point leaves the sidecar,
            // which the next open's replay re-runs idempotently then removes).
            self.pager.remove_journal(journal_id).await?;
        }

        state.latest_commit_id = new_commit_id;
        state.next_page_id = new_next_page_id;
        state.root_page_id = new_root_page_id;
        state.catalog_root_page_id = new_catalog_root_page_id;
        self.latest_commit
            .store(new_commit_id, std::sync::atomic::Ordering::SeqCst);
        self.publish_snapshot(&state);

        drop(state);

        Ok(crate::snapshot::ApplyStats {
            pages_applied,
            segments_promoted,
            segments_tombstoned: 0,
        })
    }
}
