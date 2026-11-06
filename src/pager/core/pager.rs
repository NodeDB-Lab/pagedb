//! `Pager`: struct, constructors, accessors, and epoch key management.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering as AtomOrd};

use tokio::sync::Mutex as AsyncMutex;

use super::config::PagerConfig;
use super::inner::PagerInner;
use crate::Result;
use crate::crypto::CipherId;
use crate::crypto::key_manager::DekLru;
use crate::crypto::keys::MasterKey;
use crate::crypto::nonce::{MainDbNonceGen, SegmentNonceGen};
use crate::errors::PagedbError;
#[cfg(test)]
use crate::pager::anchor::AnchorTestFault;
use crate::pager::anchor::LiveHeader;
use crate::pager::cache::{FileKey, PageCache};
use crate::txn::db::rekey::EpochKeyring;
use crate::vfs::Vfs;

/// The Pager. Owns one main.db handle plus N segment handles, both cache
/// classes, the DEK LRU, and the main.db nonce generator.
pub struct Pager<V: Vfs> {
    pub(super) cfg: PagerConfig,
    pub(super) vfs: V,
    /// Memory-only master-key leases, selected by the epoch and cipher carried
    /// by every encrypted page. The keyring is the sole decryption authority
    /// during mixed-epoch rekey state.
    pub(super) keyring: EpochKeyring,
    /// Active `mk_epoch` for flush (write) operations. May differ from
    /// `cfg.mk_epoch` during an online rekey while old-epoch pages still live
    /// in the cache. Reads use per-page epoch routing; writes always use this
    /// atomic to pick the DEK.
    pub(super) active_epoch: AtomicU64,
    pub(super) read_only: AtomicBool,
    pub(super) files: AsyncMutex<BTreeMap<FileKey, Arc<AsyncMutex<V::File>>>>,
    /// Counts how many times the cached file handles were invalidated. Bumped
    /// under the `files` lock. A handle or a main page fetched under an older
    /// value is never cached.
    pub(super) handle_generation: AtomicU64,
    pub(super) dek_lru: parking_lot::Mutex<DekLru>,
    pub(super) main_nonce: parking_lot::Mutex<MainDbNonceGen>,
    /// Header key and A/B cursor for the live `main.db`, installed by the owning
    /// `Db` once its header has been read (or bootstrapped). `None` on a handle
    /// that never writes a main.db header — a read-only image view — which is
    /// also a handle that never issues a main.db nonce.
    pub(super) live_header: parking_lot::Mutex<Option<LiveHeader>>,
    /// Per-journal-sidecar nonce generators. Each apply allocates a fresh,
    /// never-reused `journal_id`, so a generator seeded from that id never
    /// collides with another journal's nonces under one key.
    pub(super) journal_nonces: parking_lot::Mutex<BTreeMap<[u8; 16], SegmentNonceGen>>,
    pub(crate) inner: Arc<PagerInner>,
    /// Retries on AEAD failure before surfacing `PageUnverifiable`. Non-zero
    /// only in `Observer` mode to absorb torn reads from a concurrent writer.
    pub(super) observer_retry_count: u32,
    /// One-shot interruption of the nonce-anchor durability path. See
    /// [`AnchorTestFault`].
    #[cfg(test)]
    pub(super) anchor_test_fault: parking_lot::Mutex<Option<AnchorTestFault>>,
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
    /// A Follower handle keeps this identity for its key. Its generator seals the
    /// handle's own pages under a random prefix, because the source holds this key
    /// and this identity's prefix too.
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

    /// Install a leased epoch key without changing which epoch flushes use.
    ///
    /// The DEK cache keys on the epoch and holds no key identity, so a cipher cached
    /// under an earlier key for this epoch leaves here. It must not answer for the
    /// new key.
    pub(crate) fn install_mk_epoch(&self, mk: MasterKey, epoch: u64, cipher_id: CipherId) {
        self.keyring.install(epoch, cipher_id, mk);
        self.dek_lru.lock().invalidate_epoch(epoch, cipher_id);
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
}
