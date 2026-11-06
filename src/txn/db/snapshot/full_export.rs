// SPDX-License-Identifier: Apache-2.0

//! Full snapshots retain one writer-owned published state.

use super::super::core::Db;
use super::super::util::get_vfs_root;
use super::ownership::{claim_empty_destination, cleanup_failed_snapshot};
use super::reachability::collect_published_page_ids;
use crate::snapshot::export::{SnapshotManifest, snapshot_full};
use crate::vfs::Vfs;
use crate::vfs::tokio_backend::TokioVfs;

impl<V: Vfs + Clone> Db<V> {
    /// Full verbatim snapshot of the database at the current `latest_commit`.
    ///
    /// Not available on `wasm32` targets (requires native file system access).
    ///
    /// Takes a non-abortable `ReadTxn` to pin the state while files are copied,
    /// then writes `<dst_path>/manifest`, `<dst_path>/main.db`, and all live
    /// segment files under `<dst_path>/seg/<hex(id)>`.
    /// Source writes wait during export. Reads remain available.
    pub async fn snapshot_to(
        &self,
        dst_path: &std::path::Path,
    ) -> crate::Result<crate::snapshot::SnapshotStats> {
        self.ensure_usable()?;
        let _writer_guard = self.writer.lock().await;
        self.ensure_usable()?;
        let _span = tracing::debug_span!("snapshot.export");

        // Pin the current published state with a non-abortable read txn.
        let txn = self.begin_read_non_abortable().await?;
        #[cfg(test)]
        tests::pause_export(self.file_id).await;

        let (target_commit, next_page_id) = { (txn.commit_id().0, txn.next_page_id()) };
        let target_active_root_page_id = txn.root_page_id();
        let target_catalog_root_page_id = txn.catalog_root_page_id();
        self.refuse_export_with_pending_rekey(target_catalog_root_page_id, next_page_id)
            .await?;

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
        let main_db_extent = tokio::fs::metadata(src_root.join("main.db"))
            .await
            .map_err(crate::errors::PagedbError::Io)?
            .len();
        let ownership = claim_empty_destination(dst_path).await?;
        // Copy the published descriptor before awaiting page collection.
        let published_snapshot = *self.snapshot.read();
        let required_page_ids = collect_published_page_ids(self, published_snapshot).await?;
        let highest_required_main_page = required_page_ids.iter().next_back().copied().unwrap_or(1);
        let exported = async {
            let stats = snapshot_full(
                &src_root,
                dst_path,
                &manifest,
                &hk_raw,
                &segment_ids,
                highest_required_main_page,
                main_db_extent,
            )
            .await?;
            // The exported `main.db` shares this store's nonce space. Stamping
            // it keeps a `Db::open` of the snapshot directory from taking
            // independent writes under this store's key.
            let hk = self.hk.read().clone();
            crate::txn::db::restore_mode::stamp_exported_read_only(
                &TokioVfs::new(dst_path),
                "/main.db",
                self.page_size,
                &hk,
                published_snapshot.free_list_root_page_id,
            )
            .await?;
            Ok::<_, crate::errors::PagedbError>(stats)
        }
        .await;
        let stats = match exported {
            Ok(stats) => stats,
            Err(error) => {
                cleanup_failed_snapshot(dst_path, ownership).await;
                return Err(error);
            }
        };
        drop(txn); // unpin
        Ok(stats)
    }
}

#[cfg(test)]
mod tests {
    use crate::vfs::tokio_backend::TokioVfs;
    use crate::{Db, DbMode, OpenOptions, RealmId, RetainPolicy, SegmentKind, SegmentPageKind};
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex, OnceLock};
    use tokio::sync::Notify;

    const KEK: [u8; 32] = [7; 32];
    const REALM: RealmId = RealmId::new([1; 16]);

    struct ExportPause {
        entered: Notify,
        release: Notify,
    }
    static PAUSES: OnceLock<Mutex<HashMap<[u8; 16], Arc<ExportPause>>>> = OnceLock::new();

    fn install_pause(db: &Db<TokioVfs>) -> Arc<ExportPause> {
        let pause = Arc::new(ExportPause {
            entered: Notify::new(),
            release: Notify::new(),
        });
        PAUSES
            .get_or_init(|| Mutex::new(HashMap::new()))
            .lock()
            .unwrap()
            .insert(db.file_id, Arc::clone(&pause));
        pause
    }

    pub(super) async fn pause_export(file_id: [u8; 16]) {
        let pause = {
            let Some(pauses) = PAUSES.get() else {
                return;
            };
            pauses.lock().unwrap().remove(&file_id)
        };
        if let Some(pause) = pause {
            pause.entered.notify_one();
            pause.release.notified().await;
        }
    }

    async fn open(root: &std::path::Path) -> Arc<Db<TokioVfs>> {
        Arc::new(
            Db::open(
                TokioVfs::new(root),
                KEK,
                4096,
                REALM,
                OpenOptions::default().with_commit_history_retain(RetainPolicy::Unbounded),
            )
            .await
            .unwrap(),
        )
    }

    async fn seed_history_and_segment(db: &Db<TokioVfs>) -> (crate::CommitId, crate::CommitId) {
        let mut transaction = db.begin_write().await.unwrap();
        transaction.put(b"key", b"first").await.unwrap();
        let first = transaction.commit().await.unwrap();
        let mut segment = db
            .create_segment(REALM, SegmentKind::Unspecified)
            .await
            .unwrap();
        segment
            .append_page(SegmentPageKind::Data, b"segment data")
            .await
            .unwrap();
        let metadata = segment.seal().await.unwrap();
        let mut transaction = db.begin_write().await.unwrap();
        transaction.put(b"key", b"second").await.unwrap();
        transaction
            .link_segment("payload", &metadata)
            .await
            .unwrap();
        let target = transaction.commit().await.unwrap();
        (first, target)
    }

    #[tokio::test]
    async fn full_export_blocks_writes_and_preserves_exact_commit_history_and_segments() {
        let dir = tempfile::tempdir().unwrap();
        let db = open(&dir.path().join("source")).await;
        let (first, target) = seed_history_and_segment(&db).await;
        let pause = install_pause(&db);
        let export_db = Arc::clone(&db);
        let snapshot = dir.path().join("snapshot");
        let export_path = snapshot.clone();
        let export = tokio::spawn(async move { export_db.snapshot_to(&export_path).await });
        pause.entered.notified().await;
        assert!(db.writer.try_lock().is_err());
        let reader = db.begin_read().await.unwrap();
        assert_eq!(
            reader.get(b"key").await.unwrap().as_deref(),
            Some(b"second".as_slice())
        );
        drop(reader);
        let started = Arc::new(Notify::new());
        let writer_started = Arc::clone(&started);
        let writer_db = Arc::clone(&db);
        let writer = tokio::spawn(async move {
            writer_started.notify_one();
            let mut transaction = writer_db.begin_write().await.unwrap();
            transaction.put(b"key", b"third").await.unwrap();
            transaction.commit().await.unwrap()
        });
        started.notified().await;
        assert!(!writer.is_finished());
        pause.release.notify_one();
        let stats = export.await.unwrap().unwrap();
        assert_eq!(stats.segments_written, 1);
        let queued_commit = writer.await.unwrap();
        assert!(queued_commit > target);
        let reader = db.begin_read().await.unwrap();
        assert_eq!(
            reader.get(b"key").await.unwrap().as_deref(),
            Some(b"third".as_slice())
        );
        drop(reader);
        let restored = Db::<TokioVfs>::restore_from(
            &snapshot,
            &dir.path().join("restored"),
            OpenOptions::default().with_commit_history_retain(RetainPolicy::Unbounded),
            KEK,
        )
        .await
        .unwrap();
        assert_eq!(restored.latest_commit(), target);
        assert_eq!(restored.mode(), DbMode::ReadOnly);
        assert!(matches!(
            restored.begin_write().await,
            Err(crate::PagedbError::WrongMode {
                operation: "begin_write",
                required: DbMode::Standalone,
                actual: DbMode::ReadOnly,
            })
        ));
        let historic = restored.begin_read_at(first).await.unwrap();
        assert_eq!(
            historic.get(b"key").await.unwrap().as_deref(),
            Some(b"first".as_slice())
        );
        drop(historic);
        let reader = restored.begin_read().await.unwrap();
        assert_eq!(
            reader.get(b"key").await.unwrap().as_deref(),
            Some(b"second".as_slice())
        );
        let segment = reader.open_segment("payload").await.unwrap();
        assert!(
            segment
                .read_page(1)
                .await
                .unwrap()
                .starts_with(b"segment data")
        );
        drop(segment);
        drop(reader);
        let fork = restored.rekey_into_writer([9; 32]).await.unwrap();
        let mut transaction = fork.begin_write().await.unwrap();
        transaction.put(b"fork", b"independent").await.unwrap();
        transaction.commit().await.unwrap();
        let source = db.begin_read().await.unwrap();
        assert!(source.get(b"fork").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn export_error_and_cancellation_release_writer_ownership() {
        let dir = tempfile::tempdir().unwrap();
        let db = open(&dir.path().join("source")).await;
        let occupied = dir.path().join("occupied");
        tokio::fs::create_dir(&occupied).await.unwrap();
        tokio::fs::write(occupied.join("keep"), b"keep")
            .await
            .unwrap();
        assert!(db.snapshot_to(&occupied).await.is_err());
        assert!(db.writer.try_lock().is_ok());
        assert_eq!(
            tokio::fs::read(occupied.join("keep")).await.unwrap(),
            b"keep"
        );
        let pause = install_pause(&db);
        let export_db = Arc::clone(&db);
        let destination = dir.path().join("cancelled");
        let export = tokio::spawn(async move { export_db.snapshot_to(&destination).await });
        pause.entered.notified().await;
        assert!(db.writer.try_lock().is_err());
        export.abort();
        assert!(export.await.unwrap_err().is_cancelled());
        assert!(db.writer.try_lock().is_ok());
        let mut transaction = db.begin_write().await.unwrap();
        transaction
            .put(b"after", b"cancelled export")
            .await
            .unwrap();
        transaction.commit().await.unwrap();
    }
}
