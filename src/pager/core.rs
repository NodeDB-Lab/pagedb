//! Pager core. Owns VFS file handles, the two cache classes, the DEK LRU,
//! and the nonce generators. Exposes read/write/flush primitives to the B+
//! tree and segment managers.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering as AtomOrd};

use bytes::Bytes;
use tokio::sync::Mutex as AsyncMutex;

use crate::crypto::aad::{AadFields, MAIN_DB_SEGMENT_ID};
use crate::crypto::key_manager::DekLru;
use crate::crypto::keys::MasterKey;
use crate::crypto::nonce::{DEFAULT_ANCHOR_BUDGET, MainDbNonceGen, SegmentNonceGen};
use crate::crypto::{Aad, CipherId, Nonce};
use crate::errors::PagedbError;
use crate::pager::cache::{Page, PageCache};
use crate::pager::format::data_page::{
    ENVELOPE_OVERHEAD, HEADER_LEN, body, extract_page_header_ids, open_data_page, seal_data_page,
};
use crate::pager::format::page_kind::PageKind;
use crate::txn::db::rekey::EpochKeyring;
use crate::vfs::types::{OpenMode, WriteReq};
use crate::vfs::{Vfs, VfsFile};
use crate::{RealmId, Result};
use rayon::prelude::*;

pub use crate::pager::cache::FileKey;

/// Static configuration for a Pager instance.
#[derive(Debug, Clone)]
pub struct PagerConfig {
    pub page_size: usize,
    pub buffer_pool_pages: usize,
    pub segment_cache_pages: usize,
    pub cipher_id: CipherId,
    pub mk_epoch: u64,
    pub main_db_file_id: [u8; 16],
    pub main_db_path: String,
    pub anchor_budget: u64,
    pub dek_lru_capacity: usize,
    /// Number of AEAD-verification retries on a cache miss before surfacing
    /// a `ChecksumFailure`. Set to > 0 only in `Observer` mode to absorb torn
    /// reads; all other modes keep this at 0 so that AEAD failures remain
    /// hard corruption signals.
    pub observer_retry_count: u32,
    /// When `false`, buffer-pool hit/miss counters are not bumped on each
    /// page read. Default in `with_defaults`: `true`.
    pub metrics_enabled: bool,
}

impl PagerConfig {
    pub fn with_defaults(
        page_size: usize,
        cipher_id: CipherId,
        mk_epoch: u64,
        main_db_file_id: [u8; 16],
        main_db_path: impl Into<String>,
    ) -> Self {
        Self {
            page_size,
            buffer_pool_pages: 1024,
            segment_cache_pages: 1024,
            cipher_id,
            mk_epoch,
            main_db_file_id,
            main_db_path: main_db_path.into(),
            anchor_budget: DEFAULT_ANCHOR_BUDGET,
            dek_lru_capacity: 256,
            observer_retry_count: 0,
            metrics_enabled: true,
        }
    }
}

/// RAII handle to a pinned cache entry. Holds a clone of the `Arc<Page>` and
/// the cache lock long enough to unpin on drop. Borrow `body()` to access the
/// decrypted plaintext bytes.
pub struct PageGuard {
    page: Arc<Page>,
    key: (FileKey, u64),
    inner: Arc<PagerInner>,
}

impl PageGuard {
    /// Decrypted body bytes (slot directory + payload area of the page,
    /// `page_size - 40` bytes), copied into an owned `Bytes`. Prefer
    /// [`body_ref`](Self::body_ref) on the read path — `body()` is kept for
    /// write/encode paths that need an owned buffer.
    #[must_use]
    pub fn body(&self) -> Bytes {
        Bytes::copy_from_slice(body(&self.page.bytes))
    }

    /// Zero-copy borrow of the decrypted body. Valid for the lifetime of the
    /// guard; the underlying cache entry stays pinned for that lifetime.
    #[must_use]
    pub fn body_ref(&self) -> &[u8] {
        body(&self.page.bytes)
    }

    #[must_use]
    pub fn page_id(&self) -> u64 {
        self.key.1
    }
}

impl Drop for PageGuard {
    fn drop(&mut self) {
        let mut cache = self.inner.cache_for_key(self.key.0).lock();
        cache.unpin(self.key);
    }
}

/// Internal shared state. Stored in an `Arc` so `PageGuard` can keep the
/// cache reachable without borrowing the Pager.
pub(crate) struct PagerInner {
    pub(crate) buffer_pool: parking_lot::Mutex<PageCache>,
    pub(crate) segment_cache: parking_lot::Mutex<PageCache>,
    /// Cumulative cache hits on the buffer pool (main.db pages only).
    pub(crate) buffer_pool_hits: AtomicU64,
    /// Cumulative cache misses on the buffer pool (main.db pages only).
    pub(crate) buffer_pool_misses: AtomicU64,
    /// When `false`, `record_hit` and `record_miss` short-circuit before any
    /// atomic op. For embedders that don't poll
    /// [`DbStats`](crate::observability::DbStats).
    pub(crate) metrics_enabled: bool,
}

impl PagerInner {
    pub(crate) fn cache_for_key(&self, file: FileKey) -> &parking_lot::Mutex<PageCache> {
        match file {
            FileKey::Main => &self.buffer_pool,
            FileKey::Segment(_) | FileKey::ApplyJournal(_) => &self.segment_cache,
        }
    }

    /// Increment the hit counter for the given file class.
    pub(crate) fn record_hit(&self, file: FileKey) {
        if self.metrics_enabled && matches!(file, FileKey::Main) {
            self.buffer_pool_hits.fetch_add(1, AtomOrd::Relaxed);
        }
    }

    /// Increment the miss counter for the given file class.
    pub(crate) fn record_miss(&self, file: FileKey) {
        if self.metrics_enabled && matches!(file, FileKey::Main) {
            self.buffer_pool_misses.fetch_add(1, AtomOrd::Relaxed);
        }
    }
}

/// The Pager. Owns one main.db handle plus N segment handles, both cache
/// classes, the DEK LRU, and the main.db nonce generator.
pub struct Pager<V: Vfs> {
    cfg: PagerConfig,
    vfs: V,
    /// Memory-only master-key leases, selected by the epoch and cipher carried
    /// by every encrypted page. The keyring is the sole decryption authority
    /// during mixed-epoch rekey state.
    keyring: EpochKeyring,
    /// Active `mk_epoch` for flush (write) operations. May differ from
    /// `cfg.mk_epoch` during an online rekey while old-epoch pages still live
    /// in the cache. Reads use per-page epoch routing; writes always use this
    /// atomic to pick the DEK.
    active_epoch: AtomicU64,
    read_only: AtomicBool,
    files: AsyncMutex<BTreeMap<FileKey, Arc<AsyncMutex<V::File>>>>,
    dek_lru: parking_lot::Mutex<DekLru>,
    main_nonce: parking_lot::Mutex<MainDbNonceGen>,
    segment_nonces: parking_lot::Mutex<BTreeMap<[u8; 16], SegmentNonceGen>>,
    /// Per-journal-sidecar nonce generators. Each apply allocates a fresh,
    /// never-reused `journal_id`, so a generator seeded from that id never
    /// collides with another journal's nonces under one key.
    journal_nonces: parking_lot::Mutex<BTreeMap<[u8; 16], SegmentNonceGen>>,
    pub(crate) inner: Arc<PagerInner>,
    /// Retries on AEAD failure before surfacing `ChecksumFailure`. Non-zero
    /// only in `Observer` mode to absorb torn reads from a concurrent writer.
    observer_retry_count: u32,
}

impl<V: Vfs> Pager<V> {
    pub(crate) fn page_size(&self) -> usize {
        self.cfg.page_size
    }

    pub(crate) fn cipher_id(&self) -> CipherId {
        self.cfg.cipher_id
    }

    pub(crate) fn mk_epoch(&self) -> u64 {
        self.active_epoch.load(AtomOrd::SeqCst)
    }

    #[allow(dead_code)]
    pub(crate) fn main_db_file_id(&self) -> [u8; 16] {
        self.cfg.main_db_file_id
    }

    /// Lease the master key selected by an on-wire epoch/cipher pair.
    pub(crate) fn mk_for(&self, epoch: u64, cipher_id: CipherId) -> Result<MasterKey> {
        self.keyring.lease(epoch, cipher_id)
    }

    /// Clone the active writer key. Read paths must call [`Self::mk_for`] with
    /// the epoch and cipher recovered from their wire format instead.
    pub(crate) fn mk(&self) -> Result<MasterKey> {
        self.mk_for(self.active_mk_epoch(), self.cfg.cipher_id)
    }

    /// Return the active `mk_epoch` used for flush (write) operations.
    #[allow(dead_code)]
    pub(crate) fn active_mk_epoch(&self) -> u64 {
        self.active_epoch.load(AtomOrd::SeqCst)
    }

    pub(crate) fn dek_lru(&self) -> &parking_lot::Mutex<crate::crypto::key_manager::DekLru> {
        &self.dek_lru
    }

    pub(crate) fn vfs(&self) -> &V {
        &self.vfs
    }

    #[allow(clippy::unused_async)]
    pub async fn open(vfs: V, mk: MasterKey, cfg: PagerConfig) -> Result<Self> {
        let inner = Arc::new(PagerInner {
            buffer_pool: parking_lot::Mutex::new(PageCache::with_capacity(cfg.buffer_pool_pages)),
            segment_cache: parking_lot::Mutex::new(PageCache::with_capacity(
                cfg.segment_cache_pages,
            )),
            buffer_pool_hits: AtomicU64::new(0),
            buffer_pool_misses: AtomicU64::new(0),
            metrics_enabled: cfg.metrics_enabled,
        });
        let main_nonce = MainDbNonceGen::new(&cfg.main_db_file_id, cfg.anchor_budget);
        let initial_epoch = cfg.mk_epoch;
        let observer_retry_count = cfg.observer_retry_count;
        Ok(Self {
            dek_lru: parking_lot::Mutex::new(DekLru::with_capacity(cfg.dek_lru_capacity)),
            main_nonce: parking_lot::Mutex::new(main_nonce),
            segment_nonces: parking_lot::Mutex::new(BTreeMap::new()),
            journal_nonces: parking_lot::Mutex::new(BTreeMap::new()),
            files: AsyncMutex::new(BTreeMap::new()),
            inner,
            active_epoch: AtomicU64::new(initial_epoch),
            read_only: AtomicBool::new(false),
            keyring: EpochKeyring::new(initial_epoch, cfg.cipher_id, mk),
            observer_retry_count,
            vfs,
            cfg,
        })
    }

    /// Restrict all lazily-opened persistent files to read access and reject
    /// pager flushes. This only changes in-memory state.
    pub(crate) fn set_read_only(&self) {
        self.read_only.store(true, AtomOrd::SeqCst);
    }

    /// Enable persistent writes after a frozen read-only handle transitions
    /// to Follower mode. Cached read-only file handles are discarded so later
    /// pager operations reopen them with read/write access.
    pub(crate) async fn enable_write_access(&self) {
        self.read_only.store(false, AtomOrd::SeqCst);
        self.files.lock().await.clear();
    }

    /// Install a leased epoch key without changing which epoch flushes use.
    pub(crate) fn install_mk_epoch(&self, mk: MasterKey, epoch: u64, cipher_id: CipherId) {
        self.keyring.install(epoch, cipher_id, mk);
    }

    /// Retire an inactive epoch and all cached derived cipher state for it.
    pub(crate) fn retire_mk_epoch(&self, epoch: u64, cipher_id: CipherId) -> Result<()> {
        if epoch == self.active_mk_epoch() && cipher_id == self.cfg.cipher_id {
            return Err(PagedbError::rekey_state_invalid("active_epoch_retirement"));
        }
        self.keyring.remove(epoch, cipher_id);
        self.dek_lru.lock().invalidate_epoch(epoch, cipher_id);
        Ok(())
    }

    /// Atomically advance the active epoch used for flush operations after its
    /// key has been installed. Existing readers continue to lease old keys.
    pub fn set_active_mk_epoch(&self, new_mk: MasterKey, new_epoch: u64) {
        self.install_mk_epoch(new_mk, new_epoch, self.cfg.cipher_id);
        self.active_epoch.store(new_epoch, AtomOrd::SeqCst);
    }

    /// Read a main.db page. Decrypts on cache miss using the epoch and cipher
    /// recorded in the on-disk page header, not from the pager's `active_epoch` or
    /// configured cipher. This makes mixed-epoch and mixed-cipher page coexistence
    /// work correctly without any global invariant on the read path.
    pub async fn read_main_page(
        &self,
        page_id: u64,
        realm_id: RealmId,
        expected_kind: PageKind,
    ) -> Result<PageGuard> {
        if !expected_kind.is_main_db() {
            return Err(PagedbError::IllegalPageKind);
        }
        tracing::trace!(name = "pager.read_page", page_id, "reading main db page");
        self.read_page(
            FileKey::Main,
            page_id,
            realm_id,
            expected_kind,
            MAIN_DB_SEGMENT_ID,
        )
        .await
    }

    /// Read a segment page. Decrypts on cache miss; pins the result.
    pub async fn read_segment_page(
        &self,
        segment_id: [u8; 16],
        page_id: u64,
        realm_id: RealmId,
        expected_kind: PageKind,
    ) -> Result<PageGuard> {
        if !expected_kind.is_segment() {
            return Err(PagedbError::IllegalPageKind);
        }
        self.read_page(
            FileKey::Segment(segment_id),
            page_id,
            realm_id,
            expected_kind,
            segment_id,
        )
        .await
    }

    /// Write (insert into cache as dirty) a main.db page. The copy-on-write caller has
    /// already chosen `page_id`. `body_plain` is the plaintext payload
    /// (length must equal `page_size - 40`).
    #[allow(clippy::unused_async)]
    pub async fn write_main_page(
        &self,
        page_id: u64,
        realm_id: RealmId,
        page_kind: PageKind,
        body_plain: &[u8],
    ) -> Result<()> {
        if !page_kind.is_main_db() {
            return Err(PagedbError::IllegalPageKind);
        }
        self.write_page(
            FileKey::Main,
            page_id,
            realm_id,
            page_kind,
            body_plain,
            MAIN_DB_SEGMENT_ID,
        )
    }

    /// Append a fresh segment page; returns the assigned `page_id` (1-based;
    /// page 0 is the segment header, allocated separately by the segment
    /// writer in a later slice).
    #[allow(clippy::unused_async)]
    pub async fn append_segment_page(
        &self,
        segment_id: [u8; 16],
        realm_id: RealmId,
        page_kind: PageKind,
        body_plain: &[u8],
    ) -> Result<u64> {
        if !page_kind.is_segment() {
            return Err(PagedbError::IllegalPageKind);
        }
        let page_id = {
            let gens = self.segment_nonces.lock();
            // peek without consuming — we need the id before writing
            gens.get(&segment_id)
                .map_or(1u64, SegmentNonceGen::peek_counter)
        };
        self.write_page(
            FileKey::Segment(segment_id),
            page_id,
            realm_id,
            page_kind,
            body_plain,
            segment_id,
        )?;
        // Consume the counter slot after successful insert.
        {
            let mut gens = self.segment_nonces.lock();
            let nonce_gen = gens
                .entry(segment_id)
                .or_insert_with(|| SegmentNonceGen::new(&segment_id));
            let _ = nonce_gen.next_nonce()?;
        }
        Ok(page_id)
    }

    /// Stage an apply-journal sidecar page into the cache as dirty. `page_id`
    /// is the 0-based page index within `applyjournal/<hex(journal_id)>`.
    #[allow(clippy::unused_async)]
    pub async fn stage_journal_page(
        &self,
        journal_id: [u8; 16],
        page_id: u64,
        realm_id: RealmId,
        body_plain: &[u8],
    ) -> Result<()> {
        self.write_page(
            FileKey::ApplyJournal(journal_id),
            page_id,
            realm_id,
            PageKind::ApplyJournal,
            body_plain,
            journal_id,
        )
    }

    /// Flush all dirty pages of an apply-journal sidecar to disk and fsync.
    pub async fn flush_journal(&self, journal_id: [u8; 16], realm_id: RealmId) -> Result<()> {
        self.flush_file(
            FileKey::ApplyJournal(journal_id),
            realm_id,
            journal_id,
            None,
        )
        .await
    }

    /// Read an apply-journal sidecar page, AEAD-verified under `realm_id`.
    pub async fn read_journal_page(
        &self,
        journal_id: [u8; 16],
        page_id: u64,
        realm_id: RealmId,
    ) -> Result<PageGuard> {
        self.read_page(
            FileKey::ApplyJournal(journal_id),
            page_id,
            realm_id,
            PageKind::ApplyJournal,
            journal_id,
        )
        .await
    }

    /// Remove an apply-journal sidecar file and drop all its in-memory state
    /// (cache pages, file handle, nonce generator). Called after the journal
    /// has been fully replayed and the header pointer cleared.
    pub async fn remove_journal(&self, journal_id: [u8; 16]) -> Result<()> {
        let key = FileKey::ApplyJournal(journal_id);
        self.files.lock().await.remove(&key);
        self.inner.cache_for_key(key).lock().clear_file(key);
        self.journal_nonces.lock().remove(&journal_id);
        let path = format!("applyjournal/{}", crate::hex::to_hex_lower(&journal_id));
        self.vfs.remove(&path).await?;
        self.vfs.sync_dir("applyjournal").await
    }

    /// Drop an apply-journal sidecar's cached pages without removing the file,
    /// forcing subsequent reads to AEAD-decrypt from disk.
    #[cfg(test)]
    pub(crate) fn drop_journal_cache(&self, journal_id: [u8; 16]) {
        let key = FileKey::ApplyJournal(journal_id);
        self.inner.cache_for_key(key).lock().clear_file(key);
    }

    /// Flush all dirty main.db pages to the VFS in physical-id order.
    pub async fn flush_main(&self, realm_id: RealmId) -> Result<()> {
        tracing::debug!(name = "pager.flush", "flushing dirty main db pages");
        self.flush_file(FileKey::Main, realm_id, MAIN_DB_SEGMENT_ID, None)
            .await
    }

    /// Flush all dirty main.db pages to an alternate file `dest_path` (rather
    /// than the live main.db), clearing their dirty flags. Pages are sealed with
    /// the same AAD as a normal main flush, so the destination is a bit-identical
    /// main.db. Used by compaction to build a compacted copy that is then
    /// atomically renamed into place.
    pub async fn flush_main_to(&self, realm_id: RealmId, dest_path: &str) -> Result<()> {
        self.flush_file(FileKey::Main, realm_id, MAIN_DB_SEGMENT_ID, Some(dest_path))
            .await
    }

    /// Drop all cached main.db pages so subsequent reads re-fetch from disk.
    /// Used after compaction replaces main.db (the cached pages no longer match
    /// the on-disk file) and on a failed compaction (to discard the partially
    /// built, never-persisted compacted pages).
    pub fn reset_main_pages(&self) {
        self.inner.buffer_pool.lock().clear_file(FileKey::Main);
    }

    /// Close the cached main.db file handle. The next access reopens the file.
    /// Required around an atomic rename over main.db: closing first lets the
    /// rename replace the file on platforms that reject replacing an open file
    /// (Windows), and reopening afterwards picks up the new inode (Unix).
    pub async fn close_main_handle(&self) {
        self.files.lock().await.remove(&FileKey::Main);
    }

    /// Flush all dirty pages for one segment to the VFS in physical-id order.
    pub async fn flush_segment(&self, segment_id: [u8; 16], realm_id: RealmId) -> Result<()> {
        self.flush_file(FileKey::Segment(segment_id), realm_id, segment_id, None)
            .await
    }

    /// Snapshot of the anchor the header writer should persist next.
    pub fn pending_anchor(&self) -> u64 {
        self.main_nonce.lock().pending_anchor()
    }

    /// Tell the Pager that the supplied anchor has been durably persisted to
    /// the A/B header. Future nonces will be issued in `(persisted_anchor,
    /// persisted_anchor + budget]`.
    pub fn commit_anchor(&self, persisted: u64) -> Result<()> {
        self.main_nonce.lock().commit_anchor(persisted)
    }

    /// Replace the main.db nonce generator with one recovered from a
    /// persisted anchor. Called by `Db::open_existing` after reading the
    /// header.
    pub fn recover_main_nonce(&self, recovered_anchor: u64) {
        let mut g = self.main_nonce.lock();
        *g = crate::crypto::nonce::MainDbNonceGen::recover(
            &self.cfg.main_db_file_id,
            recovered_anchor,
            self.cfg.anchor_budget,
        );
    }

    /// Re-encrypt a main.db page that is already in cache under its original
    /// epoch, writing fresh ciphertext under `self.active_epoch`. The page is
    /// read from cache (or disk), marked dirty, and will be flushed with the
    /// new epoch's DEK on the next `flush_main`.
    ///
    /// `read_main_page` now always routes to the on-disk epoch/cipher, so this
    /// simply reads then marks dirty.
    pub async fn rewrite_page_under_current_epoch(
        &self,
        page_id: u64,
        realm_id: RealmId,
        expected_kind: PageKind,
    ) -> Result<()> {
        let guard = self
            .read_main_page(page_id, realm_id, expected_kind)
            .await?;
        let file = FileKey::Main;
        let mut cache = self.inner.cache_for_key(file).lock();
        cache.mark_dirty((file, page_id));
        drop(cache);
        drop(guard);
        Ok(())
    }

    /// Discard all dirty main.db pages from the cache without flushing them.
    /// Used by `WriteTxn::abort` to undo in-flight `CoW` writes. Pages are
    /// removed from the dirty set; their cached plaintext remains in the
    /// buffer pool but will never be flushed (the next commit starts from the
    /// last durable root). A subsequent read that misses the cache will
    /// re-fetch the last persisted ciphertext from disk.
    pub fn discard_dirty_main(&self, _realm_id: crate::RealmId) {
        let mut cache = self.inner.buffer_pool.lock();
        let dirty_ids = cache.dirty_for_file(FileKey::Main);
        for pid in dirty_ids {
            cache.clear_dirty((FileKey::Main, pid));
        }
    }

    fn write_page(
        &self,
        file: FileKey,
        page_id: u64,
        realm_id: RealmId,
        page_kind: PageKind,
        body_plain: &[u8],
        segment_id: [u8; 16],
    ) -> Result<()> {
        let page_size = self.cfg.page_size;
        if body_plain.len() != page_size - ENVELOPE_OVERHEAD {
            return Err(PagedbError::PayloadTooLarge);
        }
        // Build the page buffer with the body plaintext. Header and tag are
        // filled at flush time when a nonce is consumed.
        let mut buf = vec![0u8; page_size];
        buf[HEADER_LEN..HEADER_LEN + body_plain.len()].copy_from_slice(body_plain);
        let page = Arc::new(Page::new_with_meta(buf, page_kind.as_byte(), realm_id.0));
        let cache_lock = self.inner.cache_for_key(file);
        let mut cache = cache_lock.lock();
        let _ = cache.insert((file, page_id), page);
        cache.mark_dirty((file, page_id));
        // Suppress unused warnings; these are used at flush time.
        let _ = realm_id;
        let _ = segment_id;
        Ok(())
    }

    /// Read a page from `file`. On a cache hit the cached plaintext is returned
    /// directly. On a miss, the on-disk page header bytes are read first;
    /// `cipher_id` (byte 0) and `mk_epoch` (bytes 4..12) are extracted and used
    /// to construct the AAD and select the DEK. This is the single read path for
    /// all pages — main.db and segment alike.
    ///
    /// AAD is constructed from on-disk header bytes, not from `Pager.active_epoch`
    /// or the configured cipher. This makes mixed-epoch and mixed-cipher coexistence
    /// work correctly without global invariants.
    #[allow(clippy::too_many_lines)]
    async fn read_page(
        &self,
        file: FileKey,
        page_id: u64,
        realm_id: RealmId,
        expected_kind: PageKind,
        segment_id: [u8; 16],
    ) -> Result<PageGuard> {
        // Cache fast-path: verify realm matches to prevent cross-realm hits.
        {
            let mut cache = self.inner.cache_for_key(file).lock();
            if let Some(page) = cache.get((file, page_id)) {
                if page.realm_id_bytes != Some(realm_id.0) {
                    return Err(PagedbError::ChecksumFailure);
                }
                // Enforce the same kind binding a cold read's AAD enforces.
                // Without this, a stale pointer reading a recycled page under
                // the wrong kind succeeds while the page is warm and only
                // starts failing after eviction — hiding structural damage
                // until long after the write that caused it.
                if page.kind_byte != 0 && page.kind_byte != expected_kind.as_byte() {
                    return Err(PagedbError::ChecksumFailure);
                }
                self.inner.record_hit(file);
                cache.pin((file, page_id));
                return Ok(PageGuard {
                    page,
                    key: (file, page_id),
                    inner: self.inner.clone(),
                });
            }
        }

        // Miss: read raw bytes from VFS, then extract on-disk cipher_id and
        // mk_epoch before constructing AAD and selecting the DEK.
        self.inner.record_miss(file);
        let page_size = self.cfg.page_size;
        let page_size_u64 =
            u64::try_from(page_size).map_err(|_| PagedbError::arithmetic_overflow("page size"))?;
        let page_offset = page_id
            .checked_mul(page_size_u64)
            .ok_or_else(|| PagedbError::arithmetic_overflow("page read offset"))?;
        let file_handle = self.open_file_handle(file).await?;

        // Observer-mode retry loop: on AEAD failure retry up to
        // `observer_retry_count` times (10 ms backoff) to absorb torn reads
        // from a concurrent writer. In non-observer mode (retry_count == 0)
        // the loop body executes exactly once and any AEAD failure is a hard
        // corruption signal.
        let max_attempts = self
            .observer_retry_count
            .checked_add(1)
            .ok_or_else(|| PagedbError::arithmetic_overflow("observer retry attempts"))?;
        let mut last_err: Option<PagedbError> = None;
        for attempt in 0..max_attempts {
            if attempt > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            let mut buf = vec![0u8; page_size];
            {
                let f = file_handle.lock().await;
                let n = f.read_at(page_offset, &mut buf).await?;
                if n < page_size {
                    for b in &mut buf[n..] {
                        *b = 0;
                    }
                }
            }

            // Extract the cipher_id and mk_epoch recorded in this specific page's
            // header. Using these on-disk values (rather than the pager's current
            // active_epoch / configured cipher) is what allows pages written under
            // different epochs or ciphers to coexist in the same file.
            let header_ids = extract_page_header_ids(&buf);
            let (on_disk_cipher_id, on_disk_epoch) = match header_ids {
                Ok(ids) => ids,
                Err(e) => {
                    last_err = Some(e);
                    continue;
                }
            };

            let aad = Aad::from_fields(AadFields {
                cipher_id: on_disk_cipher_id.as_byte(),
                page_kind: expected_kind.as_byte(),
                mk_epoch: on_disk_epoch,
                page_id,
                realm_id,
                segment_id,
            });
            let decrypt_result = {
                let mk_snapshot = self.mk_for(on_disk_epoch, on_disk_cipher_id);
                let mut lru = self.dek_lru.lock();
                let cipher_res = mk_snapshot.and_then(|mk| {
                    lru.get_or_derive(realm_id, on_disk_epoch, on_disk_cipher_id, &mk)
                });
                match cipher_res {
                    Ok(cipher) => open_data_page(&mut buf, &aad, cipher),
                    Err(e) => Err(e),
                }
            };
            match decrypt_result {
                Ok(_header) => {
                    let page = Arc::new(Page::new_with_meta(
                        buf,
                        expected_kind.as_byte(),
                        realm_id.0,
                    ));
                    let mut cache = self.inner.cache_for_key(file).lock();
                    let _ = cache.insert((file, page_id), page.clone());
                    cache.pin((file, page_id));
                    return Ok(PageGuard {
                        page,
                        key: (file, page_id),
                        inner: self.inner.clone(),
                    });
                }
                Err(e @ PagedbError::ChecksumFailure) => {
                    last_err = Some(e);
                    // Continue to retry only if we have attempts remaining.
                }
                Err(e) => return Err(e),
            }
        }
        tracing::error!(
            page_id,
            ?file,
            expected_kind = ?expected_kind,
            realm = ?realm_id.0,
            "page AEAD/MAC verification failed on read"
        );
        Err(last_err.unwrap_or(PagedbError::ChecksumFailure))
    }

    #[allow(clippy::too_many_lines)]
    async fn flush_file(
        &self,
        file: FileKey,
        realm_id: RealmId,
        segment_id: [u8; 16],
        dest_path: Option<&str>,
    ) -> Result<()> {
        if self.read_only.load(AtomOrd::SeqCst) {
            return Err(PagedbError::ReadOnly);
        }
        let dirty_ids = self.inner.cache_for_key(file).lock().dirty_for_file(file);
        if dirty_ids.is_empty() {
            return Ok(());
        }

        let page_size = self.cfg.page_size;
        let page_size_u64 =
            u64::try_from(page_size).map_err(|_| PagedbError::arithmetic_overflow("page size"))?;
        let flush_epoch = self.active_epoch.load(AtomOrd::SeqCst);

        // Serial gather: snapshot each dirty page's plaintext + kind under the
        // cache lock. Cheap memcpy; no AEAD work happens here. The gathered
        // `Arc<Page>` is retained per pid so the dirty-clear below can detect
        // pages replaced by a concurrent writer during the (slow) seal+write.
        let mut prepared: Vec<(u64, PageKind, Vec<u8>)> = Vec::with_capacity(dirty_ids.len());
        let mut gathered: Vec<(u64, Arc<Page>)> = Vec::with_capacity(dirty_ids.len());
        for pid in &dirty_ids {
            let page = self
                .inner
                .cache_for_key(file)
                .lock()
                .get((file, *pid))
                .ok_or_else(|| {
                    PagedbError::Io(std::io::Error::other("dirty page missing from cache"))
                })?;
            gathered.push((*pid, page.clone()));
            let kind = if page.kind_byte != 0 {
                PageKind::from_byte(page.kind_byte)?
            } else {
                derive_kind_for_flush(file)
            };
            // Preallocate the wire buffer at full page size; plaintext lives at
            // [HEADER_LEN .. HEADER_LEN + plaintext.len()].
            let mut wire = vec![0u8; page_size];
            let plain = body(&page.bytes);
            wire[HEADER_LEN..HEADER_LEN + plain.len()].copy_from_slice(plain);
            tracing::trace!(page_id = *pid, ?kind, ?file, "flush: writing page");
            prepared.push((*pid, kind, wire));
        }

        // Validate every physical offset before consuming any nonce.
        let offsets: Vec<u64> = prepared
            .iter()
            .map(|(pid, _, _)| {
                pid.checked_mul(page_size_u64)
                    .ok_or_else(|| PagedbError::arithmetic_overflow("page write offset"))
            })
            .collect::<Result<_>>()?;

        // Pre-allocate a nonce per page (counter increments — single-threaded
        // by design; cheap).
        let mut nonces: Vec<Nonce> = Vec::with_capacity(prepared.len());
        for _ in 0..prepared.len() {
            nonces.push(self.next_nonce_for_flush(file)?);
        }

        // Derive the per-realm DEK cipher ONCE before the parallel seal. All
        // dirty pages in this flush share the same `(realm_id, mk_epoch,
        // cipher_id)`, so they share the same cipher instance. The cipher's
        // `encrypt` method takes `&self`, so it's safe to share across rayon
        // workers.
        let cipher_id = self.cfg.cipher_id;
        let cipher: crate::crypto::Cipher = {
            let mk_snapshot = self.mk_for(flush_epoch, cipher_id)?;
            let mut lru = self.dek_lru.lock();
            let derived = lru.get_or_derive(realm_id, flush_epoch, cipher_id, &mk_snapshot)?;
            // Clone the cipher (cheap; carries a derived key) so we drop the
            // LRU lock before the parallel section.
            match derived {
                crate::crypto::Cipher::Aes256Gcm(c) => crate::crypto::Cipher::Aes256Gcm(c.clone()),
                crate::crypto::Cipher::ChaCha20Poly1305(c) => {
                    crate::crypto::Cipher::ChaCha20Poly1305(c.clone())
                }
                crate::crypto::Cipher::PlaintextMac(k) => {
                    crate::crypto::Cipher::PlaintextMac(k.clone())
                }
            }
        };

        // Parallel AEAD seal across all dirty pages. Each (`wire`, `nonce`,
        // `kind`, `page_id`) tuple is independent — no shared mutable state.
        // The cipher and `flush_epoch` are shared by reference.
        prepared
            .par_iter_mut()
            .zip(nonces.par_iter())
            .try_for_each(|((pid, kind, wire), nonce)| -> Result<()> {
                let aad = Aad::from_fields(AadFields {
                    cipher_id: cipher_id.as_byte(),
                    page_kind: kind.as_byte(),
                    mk_epoch: flush_epoch,
                    page_id: *pid,
                    realm_id,
                    segment_id,
                });
                seal_data_page(wire, *kind, 0, flush_epoch, nonce, &aad, &cipher)
            })?;

        // Issue physical-id-order vectored writes.
        let mut reqs: Vec<WriteReq<'_>> = Vec::with_capacity(prepared.len());
        for ((_, _kind, wire), offset) in prepared.iter().zip(offsets) {
            reqs.push(WriteReq { offset, buf: wire });
        }
        if let Some(path) = dest_path {
            // Alternate destination (compaction's compacted copy): open it
            // directly, never via the cached main handle.
            let mut f = self.vfs.open(path, OpenMode::CreateOrOpen).await?;
            f.write_at_vectored(&reqs).await?;
            f.sync().await?;
        } else {
            let file_handle = self.open_file_handle(file).await?;
            let mut f = file_handle.lock().await;
            f.write_at_vectored(&reqs).await?;
            f.sync().await?;
        }

        // Clear dirty flags — but ONLY for pages still holding the exact
        // `Arc<Page>` we gathered. A concurrent writer replaces the Arc on
        // every write; unconditionally clearing here would wipe its dirty
        // flag while its content never reached disk (lost update → stale
        // page on next cold read → AEAD/kind mismatch).
        // A replaced page keeps its flag and flushes on the next cycle.
        let mut cache = self.inner.cache_for_key(file).lock();
        for (pid, snapshot) in gathered {
            match cache.get((file, pid)) {
                Some(current) if Arc::ptr_eq(&current, &snapshot) => {
                    cache.clear_dirty((file, pid));
                }
                _ => {
                    tracing::debug!(
                        page_id = pid,
                        "page re-dirtied during flush; keeping dirty for next cycle"
                    );
                }
            }
        }
        Ok(())
    }

    async fn open_file_handle(&self, file: FileKey) -> Result<Arc<AsyncMutex<V::File>>> {
        let cached = {
            let files = self.files.lock().await;
            files.get(&file).cloned()
        };
        if let Some(handle) = cached {
            return Ok(handle);
        }

        let path = match file {
            FileKey::Main => self.cfg.main_db_path.clone(),
            FileKey::Segment(id) => format!("seg/{}", crate::hex::to_hex_lower(&id)),
            FileKey::ApplyJournal(id) => {
                format!("applyjournal/{}", crate::hex::to_hex_lower(&id))
            }
        };
        let mode = if self.read_only.load(AtomOrd::SeqCst) {
            OpenMode::Read
        } else {
            OpenMode::CreateOrOpen
        };
        let opened = Arc::new(AsyncMutex::new(self.vfs.open(&path, mode).await?));
        let mut files = self.files.lock().await;
        if let Some(handle) = files.get(&file) {
            return Ok(handle.clone());
        }
        files.insert(file, opened.clone());
        Ok(opened)
    }

    fn next_nonce_for_flush(&self, file: FileKey) -> Result<Nonce> {
        match file {
            FileKey::Main => {
                let mut g = self.main_nonce.lock();
                g.next_nonce()
            }
            FileKey::Segment(id) => {
                let mut gens = self.segment_nonces.lock();
                let nonce_gen = gens.entry(id).or_insert_with(|| SegmentNonceGen::new(&id));
                nonce_gen.next_nonce()
            }
            FileKey::ApplyJournal(id) => {
                let mut gens = self.journal_nonces.lock();
                let nonce_gen = gens.entry(id).or_insert_with(|| SegmentNonceGen::new(&id));
                nonce_gen.next_nonce()
            }
        }
    }
}

fn derive_kind_for_flush(file: FileKey) -> PageKind {
    // The page-kind context is supplied by the caller at write time. For this
    // slice we store it implicitly via the FileKey class: main.db dirty pages
    // are conservatively flagged BTreeLeaf and segment pages as SegmentData.
    // Real classification lives in the B+ tree / segment-manager layers where
    // page roles are explicit.
    match file {
        FileKey::Main => PageKind::BTreeLeaf,
        FileKey::Segment(_) => PageKind::SegmentData,
        FileKey::ApplyJournal(_) => PageKind::ApplyJournal,
    }
}

#[cfg(test)]
#[allow(clippy::too_many_lines)]
mod tests {
    use super::*;

    use crate::crypto::kdf::derive_mk;
    use crate::vfs::memory::MemVfs;

    const PAGE: usize = 4096;

    async fn mk_pager() -> Pager<MemVfs> {
        let mk = derive_mk(&[1u8; 32], &[0u8; 16], 0).unwrap();
        let cfg = PagerConfig {
            page_size: PAGE,
            buffer_pool_pages: 4,
            segment_cache_pages: 4,
            cipher_id: CipherId::Aes256Gcm,
            mk_epoch: 0,
            main_db_file_id: [0xAB; 16],
            main_db_path: "/main.db".into(),
            anchor_budget: 1_000_000,
            dek_lru_capacity: 16,
            observer_retry_count: 0,
            metrics_enabled: true,
        };
        Pager::open(MemVfs::new(), mk, cfg).await.unwrap()
    }

    #[tokio::test(flavor = "current_thread")]
    async fn write_flush_read_round_trip_main() {
        let pager = mk_pager().await;
        let realm = RealmId([7; 16]);
        let mut body = vec![0u8; PAGE - ENVELOPE_OVERHEAD];
        body[..5].copy_from_slice(b"hello");
        pager
            .write_main_page(10, realm, PageKind::BTreeLeaf, &body)
            .await
            .unwrap();
        pager.flush_main(realm).await.unwrap();
        // Drop cache by writing more pages than capacity.
        let blank = vec![0u8; PAGE - ENVELOPE_OVERHEAD];
        for p in 11..=20u64 {
            pager
                .write_main_page(p, realm, PageKind::BTreeLeaf, &blank)
                .await
                .unwrap();
        }
        pager.flush_main(realm).await.unwrap();

        let guard = pager
            .read_main_page(10, realm, PageKind::BTreeLeaf)
            .await
            .unwrap();
        let got = guard.body();
        assert_eq!(&got[..5], b"hello");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn write_flush_read_round_trip_segment() {
        let pager = mk_pager().await;
        let realm = RealmId([7; 16]);
        let seg_id = [0x11; 16];
        let mut body = vec![0u8; PAGE - ENVELOPE_OVERHEAD];
        body[..6].copy_from_slice(b"segdat");
        let page_id = pager
            .append_segment_page(seg_id, realm, PageKind::SegmentData, &body)
            .await
            .unwrap();
        pager.flush_segment(seg_id, realm).await.unwrap();
        // Push other pages to evict.
        let blank = vec![0u8; PAGE - ENVELOPE_OVERHEAD];
        for _ in 0..10 {
            let _ = pager
                .append_segment_page(seg_id, realm, PageKind::SegmentData, &blank)
                .await
                .unwrap();
        }
        pager.flush_segment(seg_id, realm).await.unwrap();

        let guard = pager
            .read_segment_page(seg_id, page_id, realm, PageKind::SegmentData)
            .await
            .unwrap();
        let got = guard.body();
        assert_eq!(&got[..6], b"segdat");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn wrong_realm_read_fails_with_checksum() {
        let pager = mk_pager().await;
        let realm_a = RealmId([1; 16]);
        let realm_b = RealmId([2; 16]);
        let mut body = vec![0u8; PAGE - ENVELOPE_OVERHEAD];
        body[..3].copy_from_slice(b"abc");
        pager
            .write_main_page(5, realm_a, PageKind::BTreeLeaf, &body)
            .await
            .unwrap();
        pager.flush_main(realm_a).await.unwrap();
        // Drop the cache entry.
        let blank = vec![0u8; PAGE - ENVELOPE_OVERHEAD];
        for p in 6..=20u64 {
            pager
                .write_main_page(p, realm_a, PageKind::BTreeLeaf, &blank)
                .await
                .unwrap();
        }
        pager.flush_main(realm_a).await.unwrap();
        let err = pager
            .read_main_page(5, realm_b, PageKind::BTreeLeaf)
            .await
            .err()
            .unwrap();
        assert!(matches!(err, PagedbError::ChecksumFailure));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cached_pages_require_an_exact_realm_match() {
        let pager = mk_pager().await;
        let zero_realm = RealmId([0; 16]);
        let nonzero_realm = RealmId([1; 16]);
        let body = vec![0u8; PAGE - ENVELOPE_OVERHEAD];

        pager
            .write_main_page(1, zero_realm, PageKind::BTreeLeaf, &body)
            .await
            .unwrap();
        pager
            .write_main_page(2, nonzero_realm, PageKind::BTreeLeaf, &body)
            .await
            .unwrap();

        {
            let mut cache = pager.inner.buffer_pool.lock();
            assert_eq!(
                cache
                    .get((FileKey::Main, 1))
                    .map(|page| page.realm_id_bytes),
                Some(Some(zero_realm.0))
            );
            assert_eq!(
                cache
                    .get((FileKey::Main, 2))
                    .map(|page| page.realm_id_bytes),
                Some(Some(nonzero_realm.0))
            );
        }

        for (page_id, requested_realm) in [(1, nonzero_realm), (2, zero_realm)] {
            let misses_before = pager.inner.buffer_pool_misses.load(AtomOrd::Relaxed);
            let cache_len_before = pager.inner.buffer_pool.lock().len();
            let err = pager
                .read_main_page(page_id, requested_realm, PageKind::BTreeLeaf)
                .await
                .err()
                .unwrap();

            assert!(matches!(err, PagedbError::ChecksumFailure));
            assert_eq!(
                pager.inner.buffer_pool_misses.load(AtomOrd::Relaxed),
                misses_before,
                "cached realm mismatch must not fall back to disk"
            );
            assert_eq!(pager.inner.buffer_pool.lock().len(), cache_len_before);
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn rejects_illegal_page_kind_on_main() {
        let pager = mk_pager().await;
        let realm = RealmId([0; 16]);
        let body = vec![0u8; PAGE - ENVELOPE_OVERHEAD];
        let err = pager
            .write_main_page(1, realm, PageKind::SegmentData, &body)
            .await
            .err()
            .unwrap();
        assert!(matches!(err, PagedbError::IllegalPageKind));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn rejects_illegal_page_kind_on_segment() {
        let pager = mk_pager().await;
        let realm = RealmId([0; 16]);
        let body = vec![0u8; PAGE - ENVELOPE_OVERHEAD];
        let err = pager
            .append_segment_page([0; 16], realm, PageKind::BTreeLeaf, &body)
            .await
            .err()
            .unwrap();
        assert!(matches!(err, PagedbError::IllegalPageKind));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn body_size_enforced() {
        let pager = mk_pager().await;
        let realm = RealmId([0; 16]);
        // Too-small body.
        let small = vec![0u8; 10];
        let err = pager
            .write_main_page(1, realm, PageKind::BTreeLeaf, &small)
            .await
            .err()
            .unwrap();
        assert!(matches!(err, PagedbError::PayloadTooLarge));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cache_class_isolation() {
        let pager = mk_pager().await;
        let realm = RealmId([3; 16]);
        let body = vec![0u8; PAGE - ENVELOPE_OVERHEAD];
        // Fill buffer_pool with 4 dirty main pages.
        for p in 1..=4u64 {
            pager
                .write_main_page(p, realm, PageKind::BTreeLeaf, &body)
                .await
                .unwrap();
        }
        // Hammer the segment cache with 8 pages — these go into segment_cache,
        // not buffer_pool, so main pages must remain dirty and intact.
        for _ in 0..8u64 {
            let _ = pager
                .append_segment_page([9; 16], realm, PageKind::SegmentData, &body)
                .await
                .unwrap();
        }
        let dirty = pager.inner.buffer_pool.lock().dirty_for_file(FileKey::Main);
        assert_eq!(dirty.len(), 4);
    }
}
