//! Fresh Standalone database bootstrap.

use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use tokio::sync::Mutex as AsyncMutex;

use crate::crypto::CipherId;
use crate::crypto::kdf::{derive_hk, derive_mk};
use crate::options::OpenOptions;
use crate::pager::header::{ActiveSlot, bootstrap_header};
use crate::pager::structural_header::MainDbHeaderFields;
use crate::pager::{Pager, PagerConfig};
use crate::vfs::Vfs;
use crate::{CommitId, RealmId, Result};

use super::super::super::mode::DbMode;
use super::super::super::policy::ReaderStallPolicy;
use super::super::core::{Db, ReaderSnapshot, WriterState};
use super::super::util::page_size_log2;

impl<V: Vfs + Clone> Db<V> {
    /// Bootstrap a fresh database. Creates `main.db`, writes an initial A/B
    /// header in slot A with `seq=1`.
    pub async fn open_internal(
        vfs: V,
        kek: [u8; 32],
        page_size: usize,
        realm: RealmId,
    ) -> Result<Self> {
        Self::open_internal_with_options_and_cipher(
            vfs,
            kek,
            page_size,
            realm,
            OpenOptions::default(),
            CipherId::Aes256Gcm,
        )
        .await
    }

    /// Like `open_internal` but with explicit cipher selection.
    pub async fn open_internal_with_cipher(
        vfs: V,
        kek: [u8; 32],
        page_size: usize,
        realm: RealmId,
        cipher_id: CipherId,
    ) -> Result<Self> {
        Self::open_internal_with_options_and_cipher(
            vfs,
            kek,
            page_size,
            realm,
            OpenOptions::default(),
            cipher_id,
        )
        .await
    }

    /// Like `open_internal` but with explicit memory budgets.
    pub async fn open_internal_with_options(
        vfs: V,
        kek: [u8; 32],
        page_size: usize,
        realm: RealmId,
        options: OpenOptions,
    ) -> Result<Self> {
        Self::open_internal_with_options_and_cipher(
            vfs,
            kek,
            page_size,
            realm,
            options,
            CipherId::Aes256Gcm,
        )
        .await
    }

    /// Full constructor: explicit cipher and explicit memory budgets.
    pub async fn open_internal_with_options_and_cipher(
        vfs: V,
        kek: [u8; 32],
        page_size: usize,
        realm: RealmId,
        options: OpenOptions,
        cipher_id: CipherId,
    ) -> Result<Self> {
        let main_db_path = "/main.db".to_string();
        let (file_id, kek_salt) = crate::crypto::random::database_identity()?;
        let mk_epoch = 0u64;

        let mk = derive_mk(&kek, &kek_salt, mk_epoch)?;
        let hk = derive_hk(&mk)?;

        let initial = MainDbHeaderFields {
            format_version: 1,
            cipher_id: cipher_id.as_byte(),
            page_size_log2: page_size_log2(page_size)?,
            flags: 0,
            file_id,
            kek_salt,
            mk_epoch,
            seq: 1,
            active_root_page_id: 0,
            active_root_txn_id: 0,
            counter_anchor: 0,
            commit_id: CommitId(0),
            free_list_root: [0; 16],
            catalog_root: [0; 16],
            apply_journal_root_page_id: 0,
            apply_journal_root_version: 0,
            commit_history_root_page_id: 0,
            commit_history_root_version: 0,
            restore_mode: 0,
            next_page_id: 4,
            commit_retain_policy_tag: 0,
            commit_retain_policy_value: 0,
        };
        bootstrap_header(&vfs, &main_db_path, &hk, &initial, page_size).await?;

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
            observer_retry_count: 0,
            metrics_enabled: options.metrics_enabled,
        };
        let vfs_arc = Arc::new(vfs);
        let vfs_for_pager = V::clone(&*vfs_arc);
        let pager = Pager::open(vfs_for_pager, mk, cfg).await?;

        let writer = WriterState {
            root_page_id: 0,
            next_page_id: 4,
            active_slot: ActiveSlot::A,
            latest_commit_id: 0,
            seq: 1,
            catalog_root_page_id: 0,
            catalog_root_txn_id: 0,
            free_list_root_page_id: 0,
            commit_history_root_page_id: 0,
            commit_history_root_version: 0,
            commit_history_count: Some(0),
        };

        Ok(Self {
            pager: Arc::new(pager),
            realm_id: realm,
            page_size,
            hk: parking_lot::RwLock::new(hk),
            main_db_path,
            vfs: vfs_arc,
            writer: Arc::new(AsyncMutex::new(writer)),
            tracked_readers: parking_lot::Mutex::new(Vec::new()),
            reader_seq: AtomicU64::new(0),
            latest_commit: AtomicU64::new(0),
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
            mode: DbMode::Standalone,
            aborted_readers: parking_lot::Mutex::new(std::collections::HashSet::new()),
            sentinel_locks: Vec::new(),
            snapshot: Arc::new(parking_lot::RwLock::new(ReaderSnapshot {
                commit_id: 0,
                root_page_id: 0,
                next_page_id: 4,
                catalog_root_page_id: 0,
            })),
            free_page_cache: Arc::new(parking_lot::Mutex::new(Vec::new())),
            free_page_consumed: Arc::new(parking_lot::Mutex::new(Vec::new())),
        })
    }
}
