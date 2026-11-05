//! Read path: kind binding, cache lookup, cold read, and AEAD verification.

use std::sync::Arc;
use std::sync::atomic::Ordering as AtomOrd;

use super::guard::PageGuard;
use super::pager::Pager;
use crate::crypto::Aad;
use crate::crypto::aad::{AadFields, MAIN_DB_SEGMENT_ID};
use crate::errors::{CorruptionDetail, PagedbError};
use crate::pager::cache::{FileKey, Page};
use crate::pager::format::data_page::{extract_page_header_ids, extract_page_kind, open_data_page};
use crate::pager::format::page_kind::PageKind;
use crate::vfs::{Vfs, read_exact_at};
use crate::{RealmId, Result};

/// How a read resolves the `page_kind` used to build the AAD.
#[derive(Debug, Clone, Copy)]
pub(super) enum KindBinding {
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

impl<V: Vfs> Pager<V> {
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
    pub(super) async fn read_page(
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
