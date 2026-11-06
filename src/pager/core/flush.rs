//! Flush path: seal dirty pages, issue nonces, and write them to the VFS.

use std::sync::Arc;
use std::sync::atomic::Ordering as AtomOrd;

use rayon::prelude::*;

use super::pager::Pager;
use crate::crypto::Aad;
use crate::crypto::MasterKey;
use crate::crypto::Nonce;
use crate::crypto::aad::{AadFields, MAIN_DB_SEGMENT_ID};
use crate::crypto::key_manager::derive_cipher;
use crate::crypto::nonce::SegmentNonceGen;
use crate::errors::PagedbError;
use crate::pager::cache::{FileKey, Page};
use crate::pager::format::data_page::{HEADER_LEN, body, seal_data_page};
use crate::pager::format::page_kind::PageKind;
use crate::vfs::types::{OpenMode, WriteReq};
use crate::vfs::{Vfs, VfsFile};
use crate::{RealmId, Result};

/// The file a rekey rebuilds `main.db` into, with the epoch and key that file's
/// pages seal under. A rebuild passes this to every page it writes, so the pager's
/// active epoch stays on the epoch the live header names until the rename.
pub(crate) struct RebuildImage {
    path: String,
    epoch: u64,
    cipher: crate::crypto::Cipher,
}

/// Where a flush writes, and so which epoch it seals under.
#[derive(Clone, Copy)]
pub(super) enum FlushDest<'a> {
    /// The file itself, under the active epoch.
    Live,
    /// Another file, under the active epoch.
    Path(&'a str),
    /// A rebuild image, under the image's epoch and key.
    Image(&'a RebuildImage),
}

impl<V: Vfs> Pager<V> {
    /// Flush all dirty main.db pages to the VFS in physical-id order.
    pub async fn flush_main(&self, realm_id: RealmId) -> Result<()> {
        tracing::debug!(name = "pager.flush", "flushing dirty main db pages");
        self.flush_file(FileKey::Main, realm_id, MAIN_DB_SEGMENT_ID, FlushDest::Live)
            .await
    }

    /// Flush all dirty main.db pages to an alternate file `dest_path` (rather
    /// than the live main.db), clearing their dirty flags. Pages are sealed with
    /// the same AAD as a normal main flush, so the destination is a bit-identical
    /// main.db. Used by compaction to build a compacted copy that is then
    /// atomically renamed into place.
    pub async fn flush_main_to(&self, realm_id: RealmId, dest_path: &str) -> Result<()> {
        self.flush_file(
            FileKey::Main,
            realm_id,
            MAIN_DB_SEGMENT_ID,
            FlushDest::Path(dest_path),
        )
        .await
    }

    /// Flush all dirty main.db pages into a rekey's rebuild image, sealed under
    /// the image's own epoch and key. The active epoch does not move.
    pub(crate) async fn flush_main_to_image(
        &self,
        realm_id: RealmId,
        image: &RebuildImage,
    ) -> Result<()> {
        self.flush_file(
            FileKey::Main,
            realm_id,
            MAIN_DB_SEGMENT_ID,
            FlushDest::Image(image),
        )
        .await
    }

    /// A rebuild image at `path`, sealed under `key` as `epoch`.
    ///
    /// The cipher stays out of the shared DEK cache, whose key has no key identity.
    /// A rebuild that never reaches its rename therefore leaves no trace of `key`
    /// in the pager.
    pub(crate) fn rebuild_image(
        &self,
        realm_id: RealmId,
        path: String,
        epoch: u64,
        key: &MasterKey,
    ) -> Result<RebuildImage> {
        let cipher = derive_cipher(
            self.cfg.cipher_id,
            key,
            realm_id,
            &self.file_identity(FileKey::Main),
        )?;
        Ok(RebuildImage {
            path,
            epoch,
            cipher,
        })
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

    #[allow(clippy::too_many_lines)]
    pub(super) async fn flush_file(
        &self,
        file: FileKey,
        realm_id: RealmId,
        segment_id: [u8; 16],
        dest: FlushDest<'_>,
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
        let flush_epoch = match dest {
            FlushDest::Image(image) => image.epoch,
            FlushDest::Live | FlushDest::Path(_) => self.active_epoch.load(AtomOrd::SeqCst),
        };

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
        //
        // An open writes no header, so its window starts empty. The first flush
        // after an open therefore persists the anchor before it seals a page. A
        // failed refresh returns here, and no page is sealed or written.
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
        let leased_cipher: Option<crate::crypto::Cipher> = match dest {
            FlushDest::Image(_) => None,
            FlushDest::Live | FlushDest::Path(_) => {
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
                Some(match derived {
                    crate::crypto::Cipher::Aes256Gcm(c) => {
                        crate::crypto::Cipher::Aes256Gcm(c.clone())
                    }
                    crate::crypto::Cipher::ChaCha20Poly1305(c) => {
                        crate::crypto::Cipher::ChaCha20Poly1305(c.clone())
                    }
                    crate::crypto::Cipher::PlaintextMac(k) => {
                        crate::crypto::Cipher::PlaintextMac(k.clone())
                    }
                })
            }
        };
        let cipher: &crate::crypto::Cipher = match (&dest, &leased_cipher) {
            (FlushDest::Image(image), _) => &image.cipher,
            (_, Some(leased)) => leased,
            (_, None) => {
                return Err(PagedbError::Io(std::io::Error::other(
                    "flush cipher contract",
                )));
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
                seal_data_page(wire, *kind, 0, flush_epoch, nonce, &aad, cipher)
            })?;

        // Issue physical-id-order vectored writes.
        let mut reqs: Vec<WriteReq<'_>> = Vec::with_capacity(prepared.len());
        for ((_, _kind, wire), offset) in prepared.iter().zip(offsets) {
            reqs.push(WriteReq { offset, buf: wire });
        }
        let alternate_path = match dest {
            FlushDest::Live => None,
            FlushDest::Path(path) => Some(path),
            FlushDest::Image(image) => Some(image.path.as_str()),
        };
        if let Some(path) = alternate_path {
            // Alternate destination (compaction's compacted copy, a rekey's
            // rebuild image): open it directly, never via the cached main handle.
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
