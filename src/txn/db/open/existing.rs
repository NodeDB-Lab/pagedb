//! Authenticated reconstruction of an existing database without repair.

use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use tokio::sync::Mutex as AsyncMutex;

use crate::crypto::CipherId;
use crate::crypto::kdf::{derive_hk, derive_mk};
use crate::errors::PagedbError;
use crate::options::OpenOptions;
use crate::pager::header::ActiveSlot;
use crate::pager::structural_header::MainDbHeaderFields;
use crate::pager::{Pager, PagerConfig};
use crate::vfs::{Vfs, VfsFile};
use crate::{RealmId, Result};

use super::super::super::mode::DbMode;
use super::super::super::policy::ReaderStallPolicy;
use super::super::core::{Db, ReaderSnapshot, WriterState};
use super::recovery::recover_open_state;

impl<V: Vfs + Clone> Db<V> {
    /// Like `open_existing` but with explicit memory budgets.
    pub async fn open_existing_with_options(
        vfs: V,
        kek: [u8; 32],
        page_size: usize,
        realm: RealmId,
        options: OpenOptions,
    ) -> Result<Self> {
        Self::open_existing_inner(vfs, kek, page_size, realm, options, DbMode::Standalone).await
    }

    /// Open an existing database that was previously created with
    /// `open_internal`. Reads and verifies both A/B header slots, picks the
    /// active one, recovers the nonce generator, and restores catalog state.
    pub async fn open_existing(
        vfs: V,
        kek: [u8; 32],
        page_size: usize,
        realm: RealmId,
    ) -> Result<Self> {
        Self::open_existing_inner(
            vfs,
            kek,
            page_size,
            realm,
            OpenOptions::default(),
            DbMode::Standalone,
        )
        .await
    }

    #[allow(clippy::too_many_lines)]
    pub(super) async fn open_existing_inner(
        vfs: V,
        kek: [u8; 32],
        page_size: usize,
        realm: RealmId,
        options: OpenOptions,
        mode: DbMode,
    ) -> Result<Self> {
        let main_db_path = "/main.db".to_string();
        let capabilities = mode.open_capabilities();
        let file_mode = capabilities.main_db_open_mode();
        let read_only = capabilities.read_only_file_access();
        let f = vfs.open(&main_db_path, file_mode).await?;
        let mut buf_a = vec![0u8; page_size];
        let mut buf_b = vec![0u8; page_size];
        let _ = f.read_at(0, &mut buf_a).await?;
        let page_size_u64 = u64::try_from(page_size)
            .map_err(|_| PagedbError::Io(std::io::Error::other("page_size > u64")))?;
        let _ = f.read_at(page_size_u64, &mut buf_b).await?;
        drop(f);

        let try_decode = |buf: &[u8]| -> Option<MainDbHeaderFields> {
            if buf.len() < 56 {
                return None;
            }
            let mut salt = [0u8; 16];
            salt.copy_from_slice(&buf[32..48]);
            let mut epoch_bytes = [0u8; 8];
            epoch_bytes.copy_from_slice(&buf[48..56]);
            let epoch = u64::from_le_bytes(epoch_bytes);
            let mk = derive_mk(&kek, &salt, epoch).ok()?;
            let hk = derive_hk(&mk).ok()?;
            crate::pager::format::structural_header::decode_main_db_header(buf, &hk, page_size).ok()
        };

        let a = try_decode(&buf_a);
        let b = try_decode(&buf_b);
        let (fields, active_slot) = match (a, b) {
            (Some(a), Some(b)) => {
                if a.seq >= b.seq {
                    (a, ActiveSlot::A)
                } else {
                    (b, ActiveSlot::B)
                }
            }
            (Some(a), None) => (a, ActiveSlot::A),
            (None, Some(b)) => (b, ActiveSlot::B),
            (None, None) => {
                return Err(PagedbError::corruption(
                    crate::errors::CorruptionDetail::HeaderUnverifiable,
                ));
            }
        };

        let cipher_id = CipherId::from_byte(fields.cipher_id)?;
        let mk_epoch = fields.mk_epoch;
        let file_id = fields.file_id;
        let kek_salt = fields.kek_salt;
        let mk = derive_mk(&kek, &kek_salt, mk_epoch)?;
        let hk = derive_hk(&mk)?;

        let cfg = PagerConfig {
            page_size,
            buffer_pool_pages: options.buffer_pool_pages,
            segment_cache_pages: options.segment_cache_pages,
            cipher_id,
            mk_epoch,
            main_db_file_id: file_id,
            main_db_path: main_db_path.clone(),
            anchor_budget: options.anchor_budget,
            dek_lru_capacity: 256,
            observer_retry_count: options.observer_retry_count,
            metrics_enabled: options.metrics_enabled,
        };
        let vfs_arc = Arc::new(vfs);
        let pager = Pager::open(V::clone(&*vfs_arc), mk, cfg).await?;
        if read_only {
            pager.set_read_only();
        }
        pager.recover_main_nonce(fields.counter_anchor);

        let catalog_root_page_id = {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&fields.catalog_root[..8]);
            u64::from_le_bytes(bytes)
        };
        let catalog_root_txn_id = {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&fields.catalog_root[8..]);
            u64::from_le_bytes(bytes)
        };
        let latest_commit = fields.commit_id.0;
        let writer = WriterState {
            root_page_id: fields.active_root_page_id,
            next_page_id: fields.next_page_id,
            active_slot,
            latest_commit_id: latest_commit,
            seq: fields.seq,
            catalog_root_page_id,
            catalog_root_txn_id,
            free_list_root_page_id: super::super::core::decode_free_list_root(
                &fields.free_list_root,
            ),
            commit_history_root_page_id: fields.commit_history_root_page_id,
            commit_history_root_version: fields.commit_history_root_version,
            commit_history_count: None,
        };

        let db = Self {
            pager: Arc::new(pager),
            realm_id: realm,
            page_size,
            hk: parking_lot::RwLock::new(hk),
            main_db_path,
            vfs: vfs_arc,
            writer: Arc::new(AsyncMutex::new(writer)),
            tracked_readers: parking_lot::Mutex::new(Vec::new()),
            reader_seq: AtomicU64::new(0),
            latest_commit: AtomicU64::new(latest_commit),
            stall_policy: parking_lot::Mutex::new(ReaderStallPolicy::default()),
            cipher_id,
            mk_epoch: AtomicU64::new(mk_epoch),
            file_id,
            kek_salt,
            pending_tombstones: parking_lot::Mutex::new(Vec::new()),
            pending_pin_deletes: parking_lot::Mutex::new(Vec::new()),
            options,
            mmap_bytes_in_use: Arc::new(AtomicU64::new(0)),
            spill_bytes_in_use: AtomicU64::new(0),
            txn_seq: AtomicU64::new(0),
            mode,
            aborted_readers: parking_lot::Mutex::new(std::collections::HashSet::new()),
            sentinel_locks: Vec::new(),
            snapshot: Arc::new(parking_lot::RwLock::new(ReaderSnapshot {
                commit_id: latest_commit,
                root_page_id: fields.active_root_page_id,
                next_page_id: fields.next_page_id,
                catalog_root_page_id,
            })),
            free_page_cache: Arc::new(parking_lot::Mutex::new(Vec::new())),
            free_page_consumed: Arc::new(parking_lot::Mutex::new(Vec::new())),
        };

        recover_open_state(&db, kek, &fields).await?;
        Ok(db)
    }
}
