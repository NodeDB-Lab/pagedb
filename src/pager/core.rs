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
#[cfg(test)]
use crate::crypto::nonce::DEFAULT_ANCHOR_BUDGET;
use crate::crypto::nonce::{MainDbNonceGen, SegmentNonceGen};
use crate::crypto::{Aad, CipherId, Nonce};
use crate::errors::{CorruptionDetail, PagedbError};
#[cfg(test)]
use crate::pager::anchor::AnchorTestFault;
use crate::pager::anchor::{HeaderCursor, LiveHeader, refresh_anchor};
use crate::pager::cache::{Page, PageCache};
use crate::pager::format::data_page::{
    ENVELOPE_OVERHEAD, HEADER_LEN, body, extract_page_header_ids, extract_page_kind,
    open_data_page, seal_data_page,
};
use crate::pager::format::page_kind::PageKind;
use crate::txn::db::rekey::EpochKeyring;
use crate::vfs::types::{OpenMode, WriteReq};
use crate::vfs::{Vfs, VfsFile, read_exact_at};
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
    /// a `PageUnverifiable`. Set to > 0 only in `Observer` mode to absorb torn
    /// reads; all other modes keep this at 0 so that AEAD failures remain
    /// hard corruption signals.
    pub observer_retry_count: u32,
    /// When `false`, buffer-pool hit/miss counters are not bumped on each
    /// page read. Default in `with_defaults`: `true`.
    pub metrics_enabled: bool,
}

impl PagerConfig {
    /// Every production open site builds a `PagerConfig` field by field from
    /// `OpenOptions`, so the defaulted constructor survives only for tests that
    /// need a working pager without an `OpenOptions` in hand.
    #[cfg(test)]
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
    /// Slab index of the pinned entry, so releasing it on drop costs an
    /// indexed load rather than another hash of `key`. `key` still identifies
    /// the entry the pin was taken on; the cache verifies the two agree.
    /// `None` marks a page returned without caching, which holds no pin.
    slot: Option<usize>,
    inner: Arc<PagerInner>,
}

impl PageGuard {
    /// Decrypted body bytes (slot directory + payload area of the page,
    /// `page_size - 40` bytes) as an owned handle that outlives the guard.
    ///
    /// Shares the page's buffer rather than copying it, on the same terms as
    /// [`body_slice`](Self::body_slice). Prefer [`body_ref`](Self::body_ref)
    /// where a borrow will do.
    #[must_use]
    pub fn body(&self) -> Bytes {
        // Extent comes from the same helper `body_ref` uses, so the two cannot
        // disagree about where the body ends.
        let len = body(&self.page.bytes).len();
        self.page.bytes.slice(HEADER_LEN..HEADER_LEN + len)
    }

    /// Zero-copy borrow of the decrypted body. Valid for the lifetime of the
    /// guard; the underlying cache entry stays pinned for that lifetime.
    #[must_use]
    pub fn body_ref(&self) -> &[u8] {
        body(&self.page.bytes)
    }

    /// Slice `range` of the body as an owned [`Bytes`] sharing this page's
    /// buffer — a refcount bump, not a copy.
    ///
    /// The returned handle keeps the buffer alive by itself, so it stays valid
    /// after the guard drops and after the page leaves the cache. The bytes it
    /// sees never change: a write installs a new page rather than mutating this
    /// one, which makes the slice a snapshot of the version that was read.
    ///
    /// It does pin the whole page for as long as it lives. A caller keeping a
    /// small value from each of many pages should copy it out instead.
    #[must_use]
    pub fn body_slice(&self, range: std::ops::Range<usize>) -> Bytes {
        let start = HEADER_LEN + range.start;
        let end = HEADER_LEN + range.end;
        self.page.bytes.slice(start..end)
    }

    /// Per-page memo for the structural extent check run by decoders over
    /// [`body_ref`](Self::body_ref). Scoped to the pinned cache entry, so it is
    /// discarded whenever the page is replaced or evicted.
    #[must_use]
    pub fn extents_validated(&self) -> &std::sync::atomic::AtomicBool {
        &self.page.extents_validated
    }
}

impl Drop for PageGuard {
    fn drop(&mut self) {
        if let Some(slot) = self.slot {
            let mut cache = self.inner.cache_for_key(self.key.0).lock();
            cache.unpin_at(slot, self.key);
        }
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
            FileKey::ApplyJournal(_) => &self.segment_cache,
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
    /// Counts how many times the cached file handles were invalidated. Bumped
    /// under the `files` lock. A handle or a main page fetched under an older
    /// value is never cached.
    handle_generation: AtomicU64,
    dek_lru: parking_lot::Mutex<DekLru>,
    main_nonce: parking_lot::Mutex<MainDbNonceGen>,
    /// Header key and A/B cursor for the live `main.db`, installed by the owning
    /// `Db` once its header has been read (or bootstrapped). `None` on a handle
    /// that never writes a main.db header — a read-only image view — which is
    /// also a handle that never issues a main.db nonce.
    live_header: parking_lot::Mutex<Option<LiveHeader>>,
    /// Per-journal-sidecar nonce generators. Each apply allocates a fresh,
    /// never-reused `journal_id`, so a generator seeded from that id never
    /// collides with another journal's nonces under one key.
    journal_nonces: parking_lot::Mutex<BTreeMap<[u8; 16], SegmentNonceGen>>,
    pub(crate) inner: Arc<PagerInner>,
    /// Retries on AEAD failure before surfacing `PageUnverifiable`. Non-zero
    /// only in `Observer` mode to absorb torn reads from a concurrent writer.
    observer_retry_count: u32,
    /// One-shot interruption of the nonce-anchor durability path. See
    /// [`AnchorTestFault`].
    #[cfg(test)]
    anchor_test_fault: parking_lot::Mutex<Option<AnchorTestFault>>,
}

/// How a read resolves the `page_kind` used to build the AAD.
#[derive(Debug, Clone, Copy)]
enum KindBinding {
    /// The caller knows the kind; authenticate strictly under it. A page whose
    /// header kind byte differs is a misroute / structural damage.
    Fixed(PageKind),
    /// The kind is not known in advance (B+ tree navigation): trust the page's
    /// own authenticated header kind byte, restricted to the two node kinds.
    Node,
}

impl KindBinding {
    /// Resolve the kind for a warm cache hit, given the cached page's kind byte.
    fn resolve_cached(self, cached_kind_byte: u8) -> Result<PageKind> {
        match self {
            Self::Fixed(k) => {
                if cached_kind_byte != 0 && cached_kind_byte != k.as_byte() {
                    return Err(PagedbError::ChecksumFailure);
                }
                Ok(k)
            }
            Self::Node => match PageKind::from_byte(cached_kind_byte) {
                Ok(k @ (PageKind::BTreeLeaf | PageKind::BTreeInternal)) => Ok(k),
                _ => Err(PagedbError::ChecksumFailure),
            },
        }
    }

    /// Resolve the kind to authenticate under on a cold read, from the on-disk
    /// page header. For `Node`, the header kind byte selects a leaf or internal
    /// node; anything else means the pointer led to a non-node page.
    fn resolve_on_disk(self, page_buf: &[u8]) -> Result<PageKind> {
        match self {
            Self::Fixed(k) => Ok(k),
            Self::Node => match extract_page_kind(page_buf) {
                Ok(k @ (PageKind::BTreeLeaf | PageKind::BTreeInternal)) => Ok(k),
                _ => Err(PagedbError::ChecksumFailure),
            },
        }
    }
}

impl<V: Vfs + Clone> Pager<V> {
    /// A read-only Pager over an alternate main.db image at `image_path`.
    ///
    /// An incremental apply builds the target image in a scratch file and has to
    /// authenticate the producer's trees *inside* that image before the rename
    /// that makes it live. The live Pager cannot serve those reads: it is still
    /// answering base-image reads for concurrent Follower readers, and
    /// repointing it would hand them target bytes for a state no durable header
    /// names yet.
    ///
    /// The view carries a snapshot of the epoch keyring, so a page sealed under
    /// any epoch the live handle can decrypt opens here too. It is read-only, so
    /// it can never issue a nonce or write to the image — the single nonce
    /// counter stays with the live Pager, and no page is ever sealed twice.
    ///
    /// The view's buffer pool is sized by the same `OpenOptions` budget as the
    /// live one. Callers drop cached main pages before opening a view and drop
    /// the view before the swap, so the two pools are not resident at full size
    /// at the same time.
    // Only the incremental-apply staging path opens a view, and that path is
    // native-only.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn open_main_view(&self, image_path: String) -> Self {
        let mut cfg = self.cfg.clone();
        cfg.main_db_path = image_path;
        let inner = Arc::new(PagerInner {
            buffer_pool: parking_lot::Mutex::new(PageCache::with_capacity(cfg.buffer_pool_pages)),
            // A view exists to walk main-db trees; no caller routes a segment or
            // journal page through it, so its second cache class is given the
            // smallest legal budget rather than a copy of the configured one.
            segment_cache: parking_lot::Mutex::new(PageCache::with_capacity(1)),
            buffer_pool_hits: AtomicU64::new(0),
            buffer_pool_misses: AtomicU64::new(0),
            metrics_enabled: false,
        });
        let main_nonce = MainDbNonceGen::new(&cfg.main_db_file_id, cfg.anchor_budget);
        Self {
            dek_lru: parking_lot::Mutex::new(DekLru::with_capacity(cfg.dek_lru_capacity)),
            main_nonce: parking_lot::Mutex::new(main_nonce),
            live_header: parking_lot::Mutex::new(None),
            journal_nonces: parking_lot::Mutex::new(BTreeMap::new()),
            files: AsyncMutex::new(BTreeMap::new()),
            handle_generation: AtomicU64::new(0),
            inner,
            active_epoch: AtomicU64::new(self.active_epoch.load(AtomOrd::SeqCst)),
            read_only: AtomicBool::new(true),
            keyring: self.keyring.duplicate(),
            observer_retry_count: self.observer_retry_count,
            #[cfg(test)]
            anchor_test_fault: parking_lot::Mutex::new(None),
            vfs: self.vfs.clone(),
            cfg,
        }
    }
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

    /// The 16-byte identity that partitions one file's nonce space, and
    /// therefore scopes its encryption key.
    ///
    /// This is the single definition of "which file is this, cryptographically":
    /// the nonce generator seeds from it (`next_nonce_for_flush`) and the key
    /// derivation scopes by it (`DekLru::get_or_derive`). Deriving the two from
    /// one function is what keeps them from drifting apart — a file whose key
    /// said one identity while its nonce said another would be back to sharing
    /// a nonce space across keys.
    ///
    /// Note this is *not* the AAD's `segment_id` field, which is all-zero for
    /// `main.db`; that field names the segment a page belongs to, while this
    /// names the file the page is written into.
    pub(crate) fn file_identity(&self, file: FileKey) -> [u8; 16] {
        match file {
            FileKey::Main => self.cfg.main_db_file_id,
            FileKey::ApplyJournal(id) => id,
        }
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

    #[allow(clippy::unused_async, clippy::unused_async_trait_impl)]
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
            live_header: parking_lot::Mutex::new(None),
            journal_nonces: parking_lot::Mutex::new(BTreeMap::new()),
            files: AsyncMutex::new(BTreeMap::new()),
            handle_generation: AtomicU64::new(0),
            inner,
            active_epoch: AtomicU64::new(initial_epoch),
            read_only: AtomicBool::new(false),
            keyring: EpochKeyring::new(initial_epoch, cfg.cipher_id, mk),
            observer_retry_count,
            #[cfg(test)]
            anchor_test_fault: parking_lot::Mutex::new(None),
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
        let mut files = self.files.lock().await;
        self.handle_generation.fetch_add(1, AtomOrd::SeqCst);
        files.clear();
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
        let (guard, _kind) = self
            .read_page(
                FileKey::Main,
                page_id,
                realm_id,
                KindBinding::Fixed(expected_kind),
                MAIN_DB_SEGMENT_ID,
            )
            .await?;
        Ok(guard)
    }

    /// Read a main.db B+ tree node whose kind (leaf vs internal) is not known in
    /// advance, returning the pinned guard and the decoded kind. The page's own
    /// authenticated header kind byte selects the AAD, so a single read+decrypt
    /// suffices — unlike probing one kind, catching the `ChecksumFailure`, and
    /// retrying the other, which reads and AEAD-checks twice and logs the first
    /// (expected) miss as an error. A page that is neither a leaf nor an
    /// internal node surfaces as `ChecksumFailure`; one that is a node kind but
    /// fails to authenticate under it surfaces as `PageUnverifiable`, naming
    /// the page.
    pub async fn read_main_node(
        &self,
        page_id: u64,
        realm_id: RealmId,
    ) -> Result<(PageGuard, PageKind)> {
        self.read_page(
            FileKey::Main,
            page_id,
            realm_id,
            KindBinding::Node,
            MAIN_DB_SEGMENT_ID,
        )
        .await
    }

    /// Write (insert into cache as dirty) a main.db page. The copy-on-write caller has
    /// already chosen `page_id`. `body_plain` is the plaintext payload
    /// (length must equal `page_size - 40`).
    #[allow(clippy::unused_async, clippy::unused_async_trait_impl)]
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
        self.write_page(FileKey::Main, page_id, realm_id, page_kind, body_plain)
    }

    /// Stage an apply-journal sidecar page into the cache as dirty. `page_id`
    /// is the 0-based page index within `applyjournal/<hex(journal_id)>`.
    ///
    /// Only the `apply_incremental` write path calls this, and that path is
    /// native-only (filesystem-backed VFS root); on wasm32 it never compiles
    /// in, leaving this unreachable there.
    #[cfg(not(target_arch = "wasm32"))]
    #[allow(clippy::unused_async, clippy::unused_async_trait_impl)]
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
        )
    }

    /// Flush all dirty pages of an apply-journal sidecar to disk and fsync.
    ///
    /// Native-only: paired with `stage_journal_page` in the native-only
    /// `apply_incremental` write path.
    #[cfg(not(target_arch = "wasm32"))]
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
        let (guard, _kind) = self
            .read_page(
                FileKey::ApplyJournal(journal_id),
                page_id,
                realm_id,
                KindBinding::Fixed(PageKind::ApplyJournal),
                journal_id,
            )
            .await?;
        Ok(guard)
    }

    /// Remove an apply-journal sidecar file and drop all its in-memory state
    /// (cache pages, file handle, nonce generator). Called after the journal
    /// has been fully replayed and the header pointer cleared.
    pub async fn remove_journal(&self, journal_id: [u8; 16]) -> Result<()> {
        let key = FileKey::ApplyJournal(journal_id);
        self.files.lock().await.remove(&key);
        self.inner.cache_for_key(key).lock().clear_file(key)?;
        self.journal_nonces.lock().remove(&journal_id);
        let path = format!("applyjournal/{}", crate::hex::to_hex_lower(&journal_id));
        self.vfs.remove(&path).await?;
        self.vfs.sync_dir("applyjournal").await
    }

    /// Drop an apply-journal sidecar's cached pages without removing the file,
    /// forcing subsequent reads to AEAD-decrypt from disk.
    #[cfg(test)]
    pub(crate) fn drop_journal_cache(&self, journal_id: [u8; 16]) -> Result<()> {
        let key = FileKey::ApplyJournal(journal_id);
        self.inner
            .cache_for_key(key)
            .lock()
            .clear_file(key)
            .map_err(PagedbError::from)
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

    /// Whether the dirty main.db page set has reached the configured
    /// buffer-pool budget.
    ///
    /// Dirty pages are never evicted, so the dirty set can push the pool past
    /// its budget. Pinned pages also stay resident over the budget.
    /// A transaction that dirties pages between flushes grows the set too.
    /// A producer that seals pages in a long loop polls this and flushes
    /// when it answers `true`.
    pub fn main_dirty_at_budget(&self) -> bool {
        self.inner.buffer_pool.lock().dirty_len() >= self.cfg.buffer_pool_pages.max(1)
    }

    /// Drop all cached main.db pages so subsequent reads re-fetch from disk.
    /// Used after compaction replaces main.db (the cached pages no longer match
    /// the on-disk file) and on a failed compaction (to discard the partially
    /// built, never-persisted compacted pages).
    pub fn reset_main_pages(&self) -> Result<()> {
        self.inner
            .buffer_pool
            .lock()
            .clear_file(FileKey::Main)
            .map_err(PagedbError::from)
    }

    /// Close the cached main.db file handle. The next access reopens the file.
    /// An atomic rename over main.db requires this close. Closing first lets the
    /// rename replace the file on platforms that reject replacing an open file
    /// (Windows). Reopening afterwards picks up the new inode (Unix).
    ///
    /// Each close bumps the handle generation. A swap closes twice. The close
    /// before the rename releases the file. The close after it drops any handle
    /// a read reopened in between. The generation then stops a read that fetched
    /// from the old inode from caching its handle or its page.
    pub async fn close_main_handle(&self) {
        let mut files = self.files.lock().await;
        self.handle_generation.fetch_add(1, AtomOrd::SeqCst);
        files.remove(&FileKey::Main);
    }

    /// Snapshot of the anchor the header writer should persist next.
    pub fn pending_anchor(&self) -> u64 {
        self.main_nonce.lock().pending_anchor()
    }

    /// Tell the Pager that the supplied anchor has been durably persisted to
    /// the A/B header. Future nonces will be issued in `(persisted_anchor,
    /// persisted_anchor + budget]`.
    pub fn commit_anchor(&self, persisted: u64) -> Result<()> {
        #[cfg(test)]
        self.interrupt_anchor_if_requested(AnchorTestFault::Commit)?;
        self.main_nonce.lock().commit_anchor(persisted)
    }

    /// Arm a one-shot interruption of the anchor path. Consumed by the first
    /// matching check; a mismatched point is left armed.
    #[cfg(test)]
    pub(crate) fn interrupt_anchor_after(&self, point: AnchorTestFault) {
        *self.anchor_test_fault.lock() = Some(point);
    }

    #[cfg(test)]
    fn interrupt_anchor_if_requested(&self, point: AnchorTestFault) -> Result<()> {
        let mut fault = self.anchor_test_fault.lock();
        if *fault == Some(point) {
            *fault = None;
            return Err(PagedbError::Io(std::io::Error::other(
                "anchor test interruption",
            )));
        }
        Ok(())
    }

    /// Bind the live `main.db` header to this pager: the key its A/B slots are
    /// MAC'd under, and which slot is currently authoritative.
    ///
    /// Called once by each writable `Db` constructor. Until it is called the
    /// pager cannot refresh the nonce anchor on its own, and a long run of
    /// nonces fails at the budget exactly as it did before.
    pub(crate) fn bind_live_header(
        &self,
        hk: Arc<parking_lot::RwLock<crate::crypto::keys::DerivedKey>>,
        cursor: HeaderCursor,
    ) {
        *self.live_header.lock() = Some(LiveHeader { hk, cursor });
    }

    /// The slot and sequence the next `main.db` header write must use.
    ///
    /// Every writer path takes its A/B slot from here rather than from its own
    /// state, because an anchor refresh can have moved the cursor since the last
    /// commit without changing anything a commit would notice.
    pub(crate) fn header_cursor(&self) -> Result<HeaderCursor> {
        self.live_header
            .lock()
            .as_ref()
            .map(|live| live.cursor)
            .ok_or_else(|| PagedbError::structural_header_invalid("main.db", "header_cursor"))
    }

    /// Record a header this writer just made durable, so the next write — by a
    /// commit or by an anchor refresh — targets the other slot.
    pub(crate) fn note_header_written(&self, cursor: HeaderCursor) {
        let mut live_header = self.live_header.lock();
        if let Some(live) = live_header.as_mut() {
            live.cursor = cursor;
        }
    }

    /// How many more main.db nonces can be issued before the durable anchor has
    /// to be advanced.
    pub(crate) fn main_anchor_window(&self) -> u64 {
        self.main_nonce.lock().window_remaining()
    }

    /// The anchor value currently recorded in the durable header. Tests assert
    /// on it to prove an operation advanced the anchor as it ran, rather than
    /// merely fitting inside a wider window.
    #[cfg(test)]
    pub(crate) fn durable_anchor(&self) -> u64 {
        self.main_nonce.lock().durable_anchor()
    }

    /// Make the nonces issued so far durable by writing them into the live
    /// header, changing nothing else, and reopen the issuing window.
    ///
    /// Safe to call at any point in any operation: the header written here names
    /// exactly the state that was already durable, so it publishes nothing and a
    /// crash straight afterwards reopens at the same commit. See
    /// [`crate::pager::anchor`] for the full argument.
    pub(crate) async fn refresh_main_anchor(&self) -> Result<()> {
        let binding = {
            let live_header = self.live_header.lock();
            live_header
                .as_ref()
                .map(|live| (live.hk.clone(), live.cursor))
        };
        let Some((hk_handle, cursor)) = binding else {
            // No live header bound: the caller is a read-only view, which has no
            // business issuing main.db nonces at all. Report the same exhaustion
            // the nonce generator would.
            return Err(PagedbError::Aborted);
        };
        let anchor = self.main_nonce.lock().pending_anchor();
        // Clone out of the lock: a rekey may swap the header key, and no
        // `parking_lot` guard may cross the header write's awaits.
        let hk = hk_handle.read().clone();
        let next = refresh_anchor(
            &self.vfs,
            &self.cfg.main_db_path,
            &hk,
            cursor,
            anchor,
            self.cfg.page_size,
        )
        .await?;
        #[cfg(test)]
        self.interrupt_anchor_if_requested(AnchorTestFault::RefreshAfterHeader)?;
        // Only now is the anchor durable, so only now may the generator issue
        // past it. A crash before this point leaves the old anchor authoritative
        // and no nonce beyond it was ever issued.
        self.main_nonce.lock().commit_anchor(anchor)?;
        self.note_header_written(next);
        Ok(())
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
    ///
    /// The dirty set is kept inside the configured buffer-pool budget. A rekey
    /// re-seals every page a root can reach. Dirty entries are never evicted, and
    /// they are off the cache's eviction list. Without an intermediate flush, the
    /// walk pins the whole decrypted database in memory whatever the budget the
    /// caller asked for. Flushing mid-walk is safe and
    /// idempotent: the active epoch is already the target, so a page re-read
    /// after being re-sealed opens under the same key, and a crash resumes
    /// from the durable rekey intent.
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
        let over_budget = {
            let mut cache = self.inner.cache_for_key(file).lock();
            cache.mark_dirty((file, page_id))?;
            cache.dirty_len() >= self.cfg.buffer_pool_pages.max(1)
        };
        drop(guard);
        if over_budget {
            self.flush_main(realm_id).await?;
        }
        Ok(())
    }

    /// Replace a free page with a zeroed `Free` page under the active epoch,
    /// without reading it. A torn page therefore costs nothing. The old plaintext
    /// never reaches disk under the active key. Each flush of the page draws one
    /// fresh nonce.
    ///
    /// The caller proves that nothing can still read this page. The dirty set
    /// stays inside the buffer-pool budget, as in
    /// [`Self::rewrite_page_under_current_epoch`].
    pub(crate) async fn write_blank_free_page(
        &self,
        page_id: u64,
        realm_id: RealmId,
    ) -> Result<()> {
        let body = vec![0u8; self.cfg.page_size - ENVELOPE_OVERHEAD];
        self.write_main_page(page_id, realm_id, PageKind::Free, &body)
            .await?;
        if self.main_dirty_at_budget() {
            self.flush_main(realm_id).await?;
        }
        Ok(())
    }

    /// Discard all dirty main.db pages from the cache without flushing them.
    /// Used by `WriteTxn::abort` to undo in-flight `CoW` writes. Unpinned pages
    /// leave the cache, so an aborted plaintext never stays resident as clean.
    /// The next read of such an id fetches the last persisted ciphertext. A
    /// pinned page clears its dirty marker and stays until its guard is released.
    /// The pool then returns to its budget unless pins hold it over.
    ///
    /// Callers include a drop, so this returns nothing. A cache fault stops the
    /// loop and stays latched. The latch then refuses every later flush, so the
    /// pages still marked dirty never reach disk.
    pub fn discard_dirty_main(&self) {
        self.inner.buffer_pool.lock().discard_dirty(FileKey::Main);
    }

    /// Evict unpinned clean main.db pages so later reads fetch and authenticate
    /// durable bytes without discarding in-flight writes.
    #[cfg(any(test, not(target_arch = "wasm32")))]
    pub fn evict_clean_main_pages(&self) -> Result<()> {
        self.inner
            .buffer_pool
            .lock()
            .clear_clean_file(FileKey::Main)
            .map_err(PagedbError::from)
    }

    fn write_page(
        &self,
        file: FileKey,
        page_id: u64,
        realm_id: RealmId,
        page_kind: PageKind,
        body_plain: &[u8],
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
        cache.insert((file, page_id), page)?;
        cache.mark_dirty((file, page_id))?;
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
        binding: KindBinding,
        segment_id: [u8; 16],
    ) -> Result<(PageGuard, PageKind)> {
        // Cache fast-path: verify realm matches to prevent cross-realm hits.
        {
            let mut cache = self.inner.cache_for_key(file).lock();
            if let Some((page, slot)) = cache.get_and_pin((file, page_id))? {
                let kind = match check_resident_page(&page, realm_id, binding) {
                    Ok(kind) => kind,
                    Err(error) => {
                        cache.unpin_at(slot, (file, page_id));
                        return Err(error);
                    }
                };
                self.inner.record_hit(file);
                return Ok((
                    PageGuard {
                        page,
                        key: (file, page_id),
                        slot: Some(slot),
                        inner: self.inner.clone(),
                    },
                    kind,
                ));
            }
        }

        // Miss: read raw bytes from VFS, then extract on-disk cipher_id and
        // mk_epoch before constructing AAD and selecting the DEK.
        self.inner.record_miss(file);
        let page_size = self.cfg.page_size;
        let page_offset = crate::pager::page_space::page_offset(page_id, page_size, "page read")?;
        // Read before the handle is taken. A swap at any later point then shows
        // as a mismatch when the page is about to enter the cache.
        let handle_generation = self.handle_generation.load(AtomOrd::SeqCst);
        let file_handle = self.open_file_handle(file).await?;

        // Observer-mode retry loop: on AEAD failure retry up to
        // `observer_retry_count` times (10 ms backoff, a yield where no time
        // driver exists; see the per-target split below) to absorb torn reads
        // from a concurrent writer. In non-observer mode (retry_count == 0)
        // the loop body executes exactly once and any AEAD failure is a hard
        // corruption signal.
        let max_attempts = self
            .observer_retry_count
            .checked_add(1)
            .ok_or_else(|| PagedbError::arithmetic_overflow("observer retry attempts"))?;
        let mut last_err: Option<PagedbError> = None;
        // What the last attempt's page said about itself, kept for the
        // corruption report: the envelope is authenticated rather than
        // encrypted, so it is readable even though the page as a whole is not,
        // and it is what separates a misroute from a torn write.
        let mut last_envelope: Option<crate::diag::PageEnvelope> = None;
        for attempt in 0..max_attempts {
            if attempt > 0 {
                // Yield the executor on `wasm32-unknown-unknown` rather than
                // sleeping: this loop runs on an embedder's single-threaded
                // executor, which has no Tokio time driver, and
                // `tokio::time::sleep` panics without one. That panic would
                // replace the corruption this loop exists to report with a
                // crash. Every other target sleeps, so a torn read still gets
                // its backoff.
                #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
                tokio::task::yield_now().await;
            }
            let mut buf = vec![0u8; page_size];
            {
                // Returned rather than retried, unlike the AEAD failures below.
                // The transient this loop absorbs is a *torn* read — a
                // full-length buffer of mixed old and new bytes — which is why
                // retrying it can succeed. A transfer that ends short or errors
                // is not that condition, and retrying it would only mask a
                // one-shot backend fault.
                let mut f = file_handle.lock().await;
                read_exact_at(&mut *f, page_offset, &mut buf).await?;
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

            // Resolve the kind to authenticate under. `Fixed` uses the caller's
            // kind (a mismatch with the on-disk byte is a misroute detected by
            // the AAD). `Node` reads the page's own kind byte and authenticates
            // under it, so a leaf and an internal node are each read correctly
            // in one pass; a byte that is neither node kind means the pointer
            // led somewhere structurally wrong and is surfaced immediately.
            let on_disk_kind_byte = extract_page_kind(&buf).map_or(0xFF, PageKind::as_byte);
            let auth_kind = match binding.resolve_on_disk(&buf) {
                Ok(k) => k,
                Err(e) => return Err(e),
            };
            last_envelope = Some(crate::diag::PageEnvelope {
                on_disk_kind: on_disk_kind_byte,
                expected_kind: auth_kind.as_byte(),
                cipher_id: on_disk_cipher_id.as_byte(),
                mk_epoch: on_disk_epoch,
            });
            let aad = Aad::from_fields(AadFields {
                cipher_id: on_disk_cipher_id.as_byte(),
                page_kind: auth_kind.as_byte(),
                mk_epoch: on_disk_epoch,
                page_id,
                realm_id,
                segment_id,
            });
            let decrypt_result = {
                let mk_snapshot = self.mk_for(on_disk_epoch, on_disk_cipher_id);
                let mut lru = self.dek_lru.lock();
                let cipher_res = mk_snapshot.and_then(|mk| {
                    lru.get_or_derive(
                        realm_id,
                        self.file_identity(file),
                        on_disk_epoch,
                        on_disk_cipher_id,
                        &mk,
                    )
                });
                match cipher_res {
                    Ok(cipher) => open_data_page(&mut buf, &aad, cipher),
                    Err(e) => Err(e),
                }
            };
            match decrypt_result {
                Ok(_page_kind) => {
                    let page = Arc::new(Page::new_with_meta(buf, auth_kind.as_byte(), realm_id.0));
                    let key = (file, page_id);
                    let mut cache = self.inner.cache_for_key(file).lock();
                    // A main handle closed since this read began. The bytes can
                    // belong to the replaced image, so the caller keeps them and
                    // the cache never sees them.
                    if matches!(file, FileKey::Main)
                        && self.handle_generation.load(AtomOrd::SeqCst) != handle_generation
                    {
                        return Ok((
                            PageGuard {
                                page,
                                key,
                                slot: None,
                                inner: self.inner.clone(),
                            },
                            auth_kind,
                        ));
                    }
                    // The cache lock was dropped across the fetch, so another
                    // page can be resident by now. That page wins, and it gets
                    // the same checks as a cache hit.
                    let (page, slot) = cache.insert_and_pin(key, page)?;
                    let kind = match check_resident_page(&page, realm_id, binding) {
                        Ok(kind) => kind,
                        Err(error) => {
                            cache.unpin_at(slot, key);
                            return Err(error);
                        }
                    };
                    return Ok((
                        PageGuard {
                            page,
                            key,
                            slot: Some(slot),
                            inner: self.inner.clone(),
                        },
                        kind,
                    ));
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
            binding = ?binding,
            realm = ?realm_id.0,
            "page AEAD/MAC verification failed on read"
        );
        // `last_err` is not always an authentication failure: the loop above
        // also lands here after exhausting retries on a header-decode
        // rejection (`extract_page_header_ids` / on-disk cipher id), which is
        // a plain `PagedbError`, not proof the page failed to authenticate.
        // Only `ChecksumFailure` — the AEAD/MAC tag actually failing to
        // verify — is the corruption signal this report exists for; anything
        // else (and any plain I/O error, which already returns earlier via
        // `?` and never reaches this tail at all) must not raise one.
        if matches!(last_err, Some(PagedbError::ChecksumFailure)) {
            // Black box: capture a structured corruption report (and, once per
            // process, a snapshot of the store for offline `pagedb-fsck`) so this
            // is debuggable from production without reproduction. Inert unless the
            // host app called `faultbox::init`.
            // The guard must outlive the `corruption()` call below: it is what
            // keeps the constructor's generic capture from filing a second,
            // thinner report for the same failure.
            let _reported = crate::diag::page_read_verify_failed(
                &self.cfg.main_db_path,
                page_id,
                &crate::diag::dbg_str(&file),
                &crate::diag::dbg_str(&binding),
                &realm_id,
                last_envelope.unwrap_or(crate::diag::PageEnvelope {
                    on_disk_kind: 0xFF,
                    expected_kind: 0xFF,
                    cipher_id: 0xFF,
                    mk_epoch: u64::MAX,
                }),
            );
            // Report the page that failed, not just that something did: the
            // pager is the only layer that knows which file and page id the
            // tag failure belongs to. `evictable` stays `None` — that is a
            // catalog fact, and nothing below the catalog may invent it.
            return Err(PagedbError::corruption(
                CorruptionDetail::PageUnverifiable {
                    realm_id,
                    // An apply-journal sidecar is not a segment, so its id does
                    // not go in a field named `segment_id`; `file` is already
                    // in the diagnostic report above.
                    segment_id: None,
                    page_id,
                    evictable: None,
                },
            ));
        }
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
        let dirty_ids = {
            let cache = self.inner.cache_for_key(file).lock();
            // An empty dirty set must not hide a latched fault as a clean flush.
            cache.check_usable()?;
            cache.dirty_for_file(file)
        };
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
                .get_dirty((file, *pid))?
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
        //
        // main.db nonces are drawn from the window the durable anchor opens, and
        // that window is refreshed here rather than being assumed wide enough.
        // The first refresh of a run lands immediately after the *previous*
        // flush's `sync`, so the anchor is only ever made durable for nonces
        // whose pages already are. A dirty set larger than one whole budget
        // refreshes again mid-allocation; that anchor covers nonces this flush
        // has claimed but not yet written, which is over-advancing — it can only
        // skip counter values, never repeat one.
        let mut nonces: Vec<Nonce> = Vec::with_capacity(prepared.len());
        while nonces.len() < prepared.len() {
            let still_needed = prepared.len() - nonces.len();
            let mut window = self.flush_nonce_window(file);
            if window < still_needed {
                self.refresh_main_anchor().await?;
                window = self.flush_nonce_window(file);
            }
            // A window of zero after a refresh means the configured budget
            // cannot cover a single page; issue anyway so the generator reports
            // the real exhaustion rather than looping here.
            for _ in 0..window.min(still_needed).max(1) {
                nonces.push(self.next_nonce_for_flush(file)?);
            }
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
            let derived = lru.get_or_derive(
                realm_id,
                self.file_identity(file),
                flush_epoch,
                cipher_id,
                &mk_snapshot,
            )?;
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
        crate::diag::flushed(page_size_u64.saturating_mul(reqs.len() as u64));

        // Clear the flags of pages that still hold the gathered `Arc<Page>`.
        // Those pages are now evictable, so return the pool to its budget.
        self.inner
            .cache_for_key(file)
            .lock()
            .finish_flush(file, gathered)?;
        Ok(())
    }

    /// The cached handle for `file`, opening and caching one on a miss.
    ///
    /// An open that overlaps a handle invalidation can bind the replaced file.
    /// That handle is discarded and the open runs again.
    async fn open_file_handle(&self, file: FileKey) -> Result<Arc<AsyncMutex<V::File>>> {
        let path = match file {
            FileKey::Main => self.cfg.main_db_path.clone(),
            FileKey::ApplyJournal(id) => {
                format!("applyjournal/{}", crate::hex::to_hex_lower(&id))
            }
        };
        loop {
            let generation = {
                let files = self.files.lock().await;
                if let Some(handle) = files.get(&file) {
                    return Ok(handle.clone());
                }
                self.handle_generation.load(AtomOrd::SeqCst)
            };
            let mode = if self.read_only.load(AtomOrd::SeqCst) {
                OpenMode::Read
            } else {
                OpenMode::CreateOrOpen
            };
            let opened = Arc::new(AsyncMutex::new(self.vfs.open(&path, mode).await?));
            let mut files = self.files.lock().await;
            if self.handle_generation.load(AtomOrd::SeqCst) != generation {
                continue;
            }
            if let Some(handle) = files.get(&file) {
                return Ok(handle.clone());
            }
            files.insert(file, opened.clone());
            return Ok(opened);
        }
    }

    /// How many nonces this flush may still issue before its generator needs an
    /// anchor commit. Only `main.db` has an anchor. Apply-journal counters have
    /// no anchor, so their window is unbounded here.
    fn flush_nonce_window(&self, file: FileKey) -> usize {
        match file {
            FileKey::Main => usize::try_from(self.main_anchor_window()).unwrap_or(usize::MAX),
            FileKey::ApplyJournal(_) => usize::MAX,
        }
    }

    fn next_nonce_for_flush(&self, file: FileKey) -> Result<Nonce> {
        match file {
            FileKey::Main => {
                let mut g = self.main_nonce.lock();
                g.next_nonce()
            }
            FileKey::ApplyJournal(id) => {
                let mut gens = self.journal_nonces.lock();
                let nonce_gen = gens.entry(id).or_insert_with(|| SegmentNonceGen::new(&id));
                nonce_gen.next_nonce()
            }
        }
    }
}

/// Check a resident page against the caller's realm and kind binding.
///
/// A `Fixed` binding enforces the same kind check a cold read's AAD does. Without
/// it, a stale pointer reading a recycled page under the wrong kind succeeds while
/// the page is warm. The damage then stays hidden until the page is evicted. A
/// `Node` binding trusts the page's own authenticated kind byte, restricted to
/// the two B+ tree node kinds.
fn check_resident_page(page: &Page, realm_id: RealmId, binding: KindBinding) -> Result<PageKind> {
    if page.realm_id_bytes != Some(realm_id.0) {
        return Err(PagedbError::ChecksumFailure);
    }
    binding.resolve_cached(page.kind_byte)
}

fn derive_kind_for_flush(file: FileKey) -> PageKind {
    // The page-kind context is supplied by the caller at write time. For this
    // slice we store it implicitly via the FileKey class: main.db dirty pages
    // are conservatively flagged BTreeLeaf and segment pages as SegmentData.
    // Real classification lives in the B+ tree / segment-manager layers where
    // page roles are explicit.
    match file {
        FileKey::Main => PageKind::BTreeLeaf,
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
        mk_pager_on(MemVfs::new()).await
    }

    async fn mk_pager_on<V: Vfs>(vfs: V) -> Pager<V> {
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
        Pager::open(vfs, mk, cfg).await.unwrap()
    }

    /// A read that misses before a write and finishes after it holds older bytes.
    /// Those bytes cannot replace the dirty page, because the flush writes the
    /// resident page under the dirty marker.
    #[tokio::test(flavor = "current_thread")]
    async fn read_miss_completing_after_a_write_keeps_the_dirty_page() {
        use crate::vfs::gated::{GatedVfs, bounded};

        const PAGE_ID: u64 = 10;
        let realm = RealmId([7; 16]);
        let older = vec![0x11u8; PAGE - ENVELOPE_OVERHEAD];
        let newer = vec![0x22u8; PAGE - ENVELOPE_OVERHEAD];

        let vfs = GatedVfs::new();
        let pager = mk_pager_on(vfs.clone()).await;
        pager
            .write_main_page(PAGE_ID, realm, PageKind::BTreeLeaf, &older)
            .await
            .unwrap();
        pager.flush_main(realm).await.unwrap();
        pager.evict_clean_main_pages().unwrap();

        let in_flight = vfs.park_next_read("/main.db", PAGE_ID * PAGE as u64);
        let racing_read = async {
            let guard = pager
                .read_main_page(PAGE_ID, realm, PageKind::BTreeLeaf)
                .await
                .unwrap();
            drop(guard);
        };
        let writer = async {
            in_flight.wait_until_parked().await;
            pager
                .write_main_page(PAGE_ID, realm, PageKind::BTreeLeaf, &newer)
                .await
                .unwrap();
            in_flight.release();
        };
        bounded(async { tokio::join!(racing_read, writer) }).await;

        pager.flush_main(realm).await.unwrap();
        pager.evict_clean_main_pages().unwrap();

        let guard = pager
            .read_main_page(PAGE_ID, realm, PageKind::BTreeLeaf)
            .await
            .unwrap();
        assert_eq!(
            &guard.body()[..16],
            &newer[..16],
            "the flush wrote the older bytes the racing read fetched"
        );
    }

    /// An open that starts before a main-file swap binds the old inode and
    /// finishes after the swap. It runs again, so the new inode is the one cached.
    #[tokio::test(flavor = "current_thread")]
    async fn open_overlapping_a_main_swap_retries_on_the_new_inode() {
        use crate::vfs::gated::{GatedVfs, bounded};

        const PAGE_ID: u64 = 10;
        const NEW_IMAGE: &str = "/main.db.new";
        let realm = RealmId([7; 16]);
        let older = vec![0x11u8; PAGE - ENVELOPE_OVERHEAD];
        let newer = vec![0x22u8; PAGE - ENVELOPE_OVERHEAD];

        let vfs = GatedVfs::new();
        let pager = mk_pager_on(vfs.clone()).await;
        pager
            .write_main_page(PAGE_ID, realm, PageKind::BTreeLeaf, &older)
            .await
            .unwrap();
        pager.flush_main(realm).await.unwrap();
        pager
            .write_main_page(PAGE_ID, realm, PageKind::BTreeLeaf, &newer)
            .await
            .unwrap();
        pager.flush_main_to(realm, NEW_IMAGE).await.unwrap();
        pager.close_main_handle().await;
        pager.reset_main_pages().unwrap();

        let in_flight = vfs.park_next_open("/main.db");
        let racing_read = async {
            pager
                .read_main_page(PAGE_ID, realm, PageKind::BTreeLeaf)
                .await
                .unwrap()
                .body()
        };
        let swap = async {
            in_flight.wait_until_parked().await;
            pager.close_main_handle().await;
            vfs.rename(NEW_IMAGE, "/main.db").await.unwrap();
            pager.close_main_handle().await;
            pager.reset_main_pages().unwrap();
            in_flight.release();
        };
        let (racing_body, ()) = bounded(async { tokio::join!(racing_read, swap) }).await;
        assert_eq!(&racing_body[..16], &newer[..16]);

        pager.evict_clean_main_pages().unwrap();
        let guard = pager
            .read_main_page(PAGE_ID, realm, PageKind::BTreeLeaf)
            .await
            .unwrap();
        assert_eq!(
            &guard.body()[..16],
            &newer[..16],
            "the cached handle still names the replaced file"
        );
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

    /// `read_main_node` must discover a node's kind from one physical read.
    ///
    /// This locks the single-read shape of the API, not the B+ tree's
    /// envelope/body agreement check — that check lives in
    /// `BTree::read_node_guard` and is covered by the corruption regressions in
    /// `tests/btree_basic.rs`. Kept separate on purpose: the agreement check is
    /// only free because the authenticated kind arrives with the page, so if a
    /// refactor reintroduces a second read here, the check stops being free and
    /// this test is what says so.
    #[tokio::test(flavor = "current_thread")]
    async fn read_main_node_discovers_kind_in_a_single_read() {
        let pager = mk_pager().await;
        let realm = RealmId([1; 16]);
        let mut body = vec![0u8; PAGE - ENVELOPE_OVERHEAD];
        body[..4].copy_from_slice(b"node");
        pager
            .write_main_page(8, realm, PageKind::BTreeInternal, &body)
            .await
            .unwrap();
        pager.flush_main(realm).await.unwrap();
        pager
            .inner
            .buffer_pool
            .lock()
            .clear_file(FileKey::Main)
            .unwrap();
        let misses_before = pager.inner.buffer_pool_misses.load(AtomOrd::Relaxed);

        let (guard, kind) = pager.read_main_node(8, realm).await.unwrap();

        assert_eq!(kind, PageKind::BTreeInternal);
        assert_eq!(&guard.body_ref()[..4], b"node");
        assert_eq!(
            pager.inner.buffer_pool_misses.load(AtomOrd::Relaxed),
            misses_before + 1,
            "node-kind discovery must authenticate one cold-cache read"
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test(flavor = "current_thread")]
    async fn write_flush_read_round_trip_journal() {
        let pager = mk_pager().await;
        let realm = RealmId([7; 16]);
        let journal_id = [0x11; 16];
        let mut body = vec![0u8; PAGE - ENVELOPE_OVERHEAD];
        body[..6].copy_from_slice(b"segdat");
        pager
            .stage_journal_page(journal_id, 0, realm, &body)
            .await
            .unwrap();
        pager.flush_journal(journal_id, realm).await.unwrap();
        // Push other pages to evict.
        let blank = vec![0u8; PAGE - ENVELOPE_OVERHEAD];
        for page_id in 1..=10u64 {
            pager
                .stage_journal_page(journal_id, page_id, realm, &blank)
                .await
                .unwrap();
        }
        pager.flush_journal(journal_id, realm).await.unwrap();

        let guard = pager.read_journal_page(journal_id, 0, realm).await.unwrap();
        let got = guard.body();
        assert_eq!(&got[..6], b"segdat");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn wrong_realm_read_fails_page_verification() {
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
        assert!(
            matches!(
                err,
                PagedbError::Corruption(CorruptionDetail::PageUnverifiable {
                    realm_id,
                    segment_id: None,
                    page_id: 5,
                    evictable: None,
                }) if realm_id == realm_b
            ),
            "cold cross-realm read must name the page that failed, got: {err:?}"
        );
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
                    .unwrap()
                    .map(|page| page.realm_id_bytes),
                Some(Some(zero_realm.0))
            );
            assert_eq!(
                cache
                    .get((FileKey::Main, 2))
                    .unwrap()
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

    #[cfg(not(target_arch = "wasm32"))]
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
        // Hammer the segment cache with 8 journal pages. They go into
        // segment_cache, not buffer_pool, so main pages must remain dirty and intact.
        for page_id in 0..8u64 {
            pager
                .stage_journal_page([9; 16], page_id, realm, &body)
                .await
                .unwrap();
        }
        let dirty = pager.inner.buffer_pool.lock().dirty_for_file(FileKey::Main);
        assert_eq!(dirty.len(), 4);
    }

    /// Write and flush page 1, then read it back to learn its slab slot.
    async fn flushed_page_slot(pager: &Pager<MemVfs>, realm: RealmId) -> usize {
        let body = vec![0u8; PAGE - ENVELOPE_OVERHEAD];
        pager
            .write_main_page(1, realm, PageKind::BTreeLeaf, &body)
            .await
            .unwrap();
        pager.flush_main(realm).await.unwrap();
        let guard = pager
            .read_main_page(1, realm, PageKind::BTreeLeaf)
            .await
            .unwrap();
        guard.slot.expect("a cached page holds a slot")
    }

    #[tokio::test(flavor = "current_thread")]
    async fn guard_held_across_flush_returns_pool_to_budget_on_release() {
        const BUDGET: usize = 4;
        let pager = mk_pager().await;
        let realm = RealmId([7; 16]);
        let body = vec![0u8; PAGE - ENVELOPE_OVERHEAD];
        for page_id in 1..=8u64 {
            pager
                .write_main_page(page_id, realm, PageKind::BTreeLeaf, &body)
                .await
                .unwrap();
        }
        let mut guards = Vec::new();
        for page_id in 1..=6u64 {
            guards.push(
                pager
                    .read_main_page(page_id, realm, PageKind::BTreeLeaf)
                    .await
                    .unwrap(),
            );
        }

        pager.flush_main(realm).await.unwrap();

        assert_eq!(
            pager.inner.buffer_pool.lock().len(),
            6,
            "the flush evicts every unpinned page and spares the pinned ones"
        );

        // Each release past the budget evicts one entry.
        drop(guards.pop());
        assert_eq!(pager.inner.buffer_pool.lock().len(), 5);
        drop(guards.pop());
        assert_eq!(pager.inner.buffer_pool.lock().len(), BUDGET);
        guards.clear();

        let cache = pager.inner.buffer_pool.lock();
        assert_eq!(cache.len(), BUDGET);
        assert_eq!(cache.dirty_len(), 0);
        cache.check_usable().unwrap();
    }

    fn assert_dead_slot_fault(err: &PagedbError, expected_operation: &str, expected_slot: usize) {
        assert!(
            matches!(
                err,
                PagedbError::PageCacheStateInvalid {
                    operation,
                    detail: "slot holds no entry",
                    slot: Some(slot),
                } if *operation == expected_operation && *slot == expected_slot
            ),
            "expected a dead-slot fault from {expected_operation}, got: {err:?}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn guard_drop_on_a_dead_slot_fails_the_next_read() {
        let pager = mk_pager().await;
        let realm = RealmId([7; 16]);
        let slot = flushed_page_slot(&pager, realm).await;

        let guard = pager
            .read_main_page(1, realm, PageKind::BTreeLeaf)
            .await
            .unwrap();
        pager.inner.buffer_pool.lock().clear_slot(slot);
        drop(guard);

        let err = pager
            .read_main_page(2, realm, PageKind::BTreeLeaf)
            .await
            .err()
            .unwrap();
        assert_dead_slot_fault(&err, "unpin_at", slot);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn discard_on_a_dead_slot_fails_the_next_flush() {
        let pager = mk_pager().await;
        let realm = RealmId([7; 16]);
        let slot = flushed_page_slot(&pager, realm).await;
        let body = vec![0u8; PAGE - ENVELOPE_OVERHEAD];
        pager
            .write_main_page(1, realm, PageKind::BTreeLeaf, &body)
            .await
            .unwrap();

        pager.inner.buffer_pool.lock().clear_slot(slot);
        pager.discard_dirty_main();

        let err = pager.flush_main(realm).await.unwrap_err();
        assert_dead_slot_fault(&err, "discard_dirty", slot);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn latched_fault_fails_a_flush_with_nothing_dirty() {
        let pager = mk_pager().await;
        let realm = RealmId([7; 16]);
        let slot = flushed_page_slot(&pager, realm).await;
        assert_eq!(
            pager.inner.buffer_pool.lock().dirty_for_file(FileKey::Main),
            Vec::<u64>::new()
        );

        let guard = pager
            .read_main_page(1, realm, PageKind::BTreeLeaf)
            .await
            .unwrap();
        pager.inner.buffer_pool.lock().clear_slot(slot);
        drop(guard);

        let err = pager.flush_main(realm).await.unwrap_err();
        assert_dead_slot_fault(&err, "unpin_at", slot);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn dirty_page_missing_at_flush_is_a_typed_fault() {
        let pager = mk_pager().await;
        let realm = RealmId([7; 16]);
        let body = vec![0u8; PAGE - ENVELOPE_OVERHEAD];
        pager
            .write_main_page(1, realm, PageKind::BTreeLeaf, &body)
            .await
            .unwrap();
        {
            let mut cache = pager.inner.buffer_pool.lock();
            cache.forget_key((FileKey::Main, 1));
        }

        let err = pager.flush_main(realm).await.unwrap_err();
        assert!(
            matches!(
                err,
                PagedbError::PageCacheStateInvalid {
                    operation: "get_dirty",
                    detail: "dirty page not resident",
                    slot: None,
                }
            ),
            "got: {err:?}"
        );
    }
}
