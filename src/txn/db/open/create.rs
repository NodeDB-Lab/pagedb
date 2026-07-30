//! Fresh Standalone database bootstrap.

use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use tokio::sync::Mutex as AsyncMutex;

use crate::crypto::kdf::{derive_hk, derive_mk};
use crate::crypto::{CipherId, SecretKey};
use crate::options::OpenOptions;
use crate::pager::anchor::HeaderCursor;
use crate::pager::header::{ActiveSlot, bootstrap_header};
use crate::pager::structural_header::MainDbHeaderFields;
use crate::pager::{Pager, PagerConfig};
use crate::vfs::Vfs;
use crate::{CommitId, RealmId, Result};

use super::super::super::mode::DbMode;
// Only the test-only locking wrapper below acquires sentinels here; the
// production bootstrap already holds them by the time it reaches this module.
#[cfg(test)]
use super::super::super::mode::{ACQUISITION_LOCK_PATH, WRITER_LOCK_PATH};
use super::super::super::policy::ReaderStallPolicy;
use super::super::core::{Db, ReaderSnapshot, WriterState};
use super::super::util::page_size_log2;
#[cfg(test)]
use super::modes::acquire_interlocking_mode_lock;

struct FreshDbState<V: Vfs + Clone> {
    pager: Pager<V>,
    realm_id: RealmId,
    page_size: usize,
    hk: crate::crypto::keys::DerivedKey,
    main_db_path: String,
    vfs: Arc<V>,
    options: OpenOptions,
    cipher_id: CipherId,
    mk_epoch: u64,
    file_id: [u8; 16],
    kek_salt: [u8; 16],
    initial: MainDbHeaderFields,
}

impl<V: Vfs + Clone> Db<V> {
    fn assemble_fresh(state: FreshDbState<V>) -> Result<Self> {
        let FreshDbState {
            pager,
            realm_id,
            page_size,
            hk,
            main_db_path,
            vfs,
            options,
            cipher_id,
            mk_epoch,
            file_id,
            kek_salt,
            initial,
        } = state;
        let writer = WriterState {
            root_page_id: 0,
            next_page_id: 4,
            latest_commit_id: 0,
            catalog_root_page_id: 0,
            catalog_root_txn_id: 0,
            free_list_root_page_id: 0,
            commit_history_root_page_id: 0,
            commit_history_root_version: 0,
            commit_history_count: Some(0),
            pending_apply_journal_id: [0; 16],
            restore_mode: initial.restore_mode,
            commit_retain_policy_tag: initial.commit_retain_policy_tag,
            commit_retain_policy_value: initial.commit_retain_policy_value,
        };
        // `bootstrap_header` has just written slot A at `seq` 1, so that is where
        // the A/B protocol continues from — for ordinary commits and for the
        // pager's own anchor refreshes alike.
        let hk = Arc::new(parking_lot::RwLock::new(hk));
        pager.bind_live_header(
            hk.clone(),
            HeaderCursor {
                slot: ActiveSlot::A,
                seq: initial.seq,
            },
        );
        Ok(Self {
            pager: Arc::new(pager),
            realm_id,
            page_size,
            hk,
            main_db_path,
            vfs,
            writer: Arc::new(AsyncMutex::new(writer)),
            #[cfg(not(target_arch = "wasm32"))]
            apply_gate: AsyncMutex::new(()),
            visibility_gate: tokio::sync::RwLock::new(()),
            tracked_readers: parking_lot::Mutex::new(Vec::new()),
            reader_seq: AtomicU64::new(0),
            stall_policy: parking_lot::Mutex::new(ReaderStallPolicy::default()),
            cipher_id,
            format_version: initial.format_version,
            header_flags: initial.flags,
            mk_epoch: AtomicU64::new(mk_epoch),
            file_id,
            kek_salt,
            pending_tombstones: parking_lot::Mutex::new(Vec::new()),
            pending_key_retirements: parking_lot::Mutex::new(Vec::new()),
            options,
            mmap_bytes_in_use: Arc::new(AtomicU64::new(0)),
            spill_bytes_in_use: AtomicU64::new(0),
            txn_seq: AtomicU64::new(0),
            spill_epoch: crate::crypto::random::spill_epoch()?,
            orphaned_spill_paths: parking_lot::Mutex::new(Vec::new()),
            mode: DbMode::Standalone,
            aborted_readers: parking_lot::Mutex::new(std::collections::HashSet::new()),
            any_reader_aborted: std::sync::atomic::AtomicBool::new(false),
            sentinel_locks: Vec::new(),
            // Callers of the unlocked constructor (this fn) are responsible
            // for setting `lock_required`/`sentinel_locks` on the returned
            // handle once they've done their own locking; see `open_with_mode`
            // in modes.rs.
            lock_required: false,
            snapshot: Arc::new(parking_lot::RwLock::new(ReaderSnapshot {
                commit_id: 0,
                root_page_id: 0,
                next_page_id: 4,
                catalog_root_page_id: 0,
                free_list_root_page_id: 0,
                commit_history_root_page_id: 0,
            })),
            poisoned_commit: parking_lot::Mutex::new(None),
            free_page_cache: Arc::new(parking_lot::Mutex::new(Vec::new())),
            free_page_consumed: crate::btree::ConsumedPages::new(),
            #[cfg(test)]
            visibility_test_hook: parking_lot::Mutex::new(None),
            #[cfg(test)]
            rekey_test_fault: parking_lot::Mutex::new(None),
        })
    }

    /// Bootstrap a fresh database. Creates `main.db`, writes an initial A/B
    /// header in slot A with `seq=1`.
    ///
    /// Compiled only for the crate's own tests. Embedders reach a fresh store
    /// through [`Db::open`], which decides bootstrap-versus-reopen from what is
    /// on disk; skipping that decision is only ever what a fixture wants, so
    /// this family must not exist in a build an embedder links against.
    #[cfg(test)]
    pub(crate) async fn open_internal(
        vfs: V,
        kek: impl Into<SecretKey>,
        page_size: usize,
        realm: RealmId,
    ) -> Result<Self> {
        let kek = kek.into();
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

    /// Like `open_internal` but with explicit memory budgets. Test-only, for
    /// the same reason.
    #[cfg(test)]
    pub(crate) async fn open_internal_with_options(
        vfs: V,
        kek: impl Into<SecretKey>,
        page_size: usize,
        realm: RealmId,
        options: OpenOptions,
    ) -> Result<Self> {
        let kek = kek.into();
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
    ///
    /// Bootstraps a fresh database directly, bypassing `Db::open`'s mode
    /// dispatch — so this acquires the same writer sentinel `Db::open` would
    /// before writing the initial header. Without it, two concurrent callers
    /// of this function could race the bootstrap write unlocked. Test-only;
    /// the production bootstrap runs through `Db::open`, which already holds
    /// the sentinel and calls the `_unlocked` inner directly.
    #[cfg(test)]
    pub(crate) async fn open_internal_with_options_and_cipher(
        vfs: V,
        kek: impl Into<SecretKey>,
        page_size: usize,
        realm: RealmId,
        options: OpenOptions,
        cipher_id: CipherId,
    ) -> Result<Self> {
        let kek = kek.into();
        let acquisition = vfs.lock_exclusive(ACQUISITION_LOCK_PATH).await?;
        let mut locks = Vec::new();
        acquire_interlocking_mode_lock(&vfs, DbMode::Standalone.open_capabilities(), &mut locks)
            .await?;
        crate::diag::lock_acquired("standalone", WRITER_LOCK_PATH);
        drop(acquisition);
        let mut db = Self::open_internal_with_options_and_cipher_unlocked(
            vfs, kek, page_size, realm, options, cipher_id,
        )
        .await?;
        db.sentinel_locks = locks;
        db.lock_required = true;
        Ok(db)
    }

    /// Bootstrap logic shared by `open_internal_with_options_and_cipher` and
    /// `Db::open`'s Standalone dispatch. Callers must hold the writer
    /// sentinel (or be constructing one) before invoking this, since it
    /// writes the initial header unconditionally.
    pub(super) async fn open_internal_with_options_and_cipher_unlocked(
        vfs: V,
        kek: SecretKey,
        page_size: usize,
        realm: RealmId,
        options: OpenOptions,
        cipher_id: CipherId,
    ) -> Result<Self> {
        let main_db_path = "/main.db".to_string();
        let (file_id, kek_salt) = crate::crypto::random::database_identity()?;
        let mk_epoch = 0u64;

        let mk = derive_mk(kek.as_bytes(), &kek_salt, mk_epoch)?;
        let hk = derive_hk(&mk)?;

        let initial = MainDbHeaderFields {
            format_version: crate::pager::structural_header::MAIN_FORMAT_VERSION,
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
            realm_id: realm,
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

        Self::assemble_fresh(FreshDbState {
            pager,
            realm_id: realm,
            page_size,
            hk,
            main_db_path,
            vfs: vfs_arc,
            options,
            cipher_id,
            mk_epoch,
            file_id,
            kek_salt,
            initial,
        })
    }
}
