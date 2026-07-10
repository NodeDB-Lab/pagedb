//! Segment reader: opens a sealed segment file at its identity-keyed live
//! path, validates header + footer, exposes page reads.

use std::sync::Arc;

use bytes::Bytes;

use crate::Result;
use crate::catalog::codec::SegmentMeta;
use crate::crypto::CipherId;
use crate::crypto::aad::{Aad, AadFields};
use crate::errors::PagedbError;
use crate::pager::Pager;
use crate::pager::format::data_page::{body, extract_page_header_ids, open_data_page};
use crate::pager::format::page_kind::PageKind;
use crate::vfs::types::OpenMode;
use crate::vfs::{Vfs, VfsFile};

use super::authenticated_metadata::{
    ExtentIndexDecodeContext, authenticate_segment_metadata, decode_extent_index,
};
use super::types::{ExtentIndexEntry, ExtentRef, MmapView, SegmentPageKind};
use super::writer::{live_path, staging_path};

/// Authenticated footer material retained for internal segment rewrites.
pub(crate) struct AuthenticatedSegmentFooter {
    pub(crate) fields: crate::pager::format::segment_footer::SegmentFooterFields,
    pub(crate) manifest: Vec<u8>,
}

struct MmapBudget {
    used: std::sync::Arc<std::sync::atomic::AtomicU64>,
    limit: u64,
}

pub struct SegmentReader<V: Vfs + Clone> {
    pager: Arc<Pager<V>>,
    meta: SegmentMeta,
    page_size: usize,
    file: V::File,
    /// Owned master-key lease for this reader. It keeps authenticated reads
    /// valid after an online rekey removes an obsolete keyring entry.
    master_key: crate::crypto::keys::MasterKey,
    /// Shared budget counter for `mmap_view` scratch bytes. Cloned from `Db`.
    /// Only read by the native `mmap_view` path; unused on `wasm32`.
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    mmap_budget_used: std::sync::Arc<std::sync::atomic::AtomicU64>,
    /// Maximum bytes allowed across all live mmap views for this Db.
    /// Only read by the native `mmap_view` path; unused on `wasm32`.
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    mmap_budget_limit: u64,
    /// v2 extent index, lazily loaded on the first `find_extent` call.
    /// `None` = not yet loaded (or v1 segment).
    /// `Some(vec)` = loaded and sorted by `start_page_id`.
    extent_index: tokio::sync::OnceCell<Vec<ExtentIndexEntry>>,
    /// v2 index block location from the footer (0/0 for v1 segments).
    index_page_count: u32,
    footer: AuthenticatedSegmentFooter,
}

impl<V: Vfs + Clone> SegmentReader<V> {
    pub(crate) async fn open_internal(
        pager: Arc<Pager<V>>,
        catalog_meta: SegmentMeta,
        mmap_budget_used: std::sync::Arc<std::sync::atomic::AtomicU64>,
        mmap_budget_limit: u64,
    ) -> Result<Self> {
        let page_size = pager.page_size();
        let live = live_path(&catalog_meta.segment_id);
        let file = pager
            .vfs()
            .open(&live, OpenMode::Read)
            .await
            .map_err(|_| PagedbError::NotFound)?;
        Self::finish_open(
            pager,
            catalog_meta,
            page_size,
            file,
            MmapBudget {
                used: mmap_budget_used,
                limit: mmap_budget_limit,
            },
        )
        .await
    }

    /// Open a sealed replacement from either publication location. The
    /// replacement identity is durable progress, so a missing or malformed
    /// file must fail closed rather than being regenerated.
    pub(crate) async fn open_rekey_replacement(
        pager: Arc<Pager<V>>,
        source: &SegmentMeta,
        replacement_segment_id: [u8; 16],
        target_mk_epoch: u64,
        target_cipher_id: u8,
        mmap_budget_used: std::sync::Arc<std::sync::atomic::AtomicU64>,
        mmap_budget_limit: u64,
    ) -> Result<Self> {
        let page_size = pager.page_size();
        let file = match pager
            .vfs()
            .open(&live_path(&replacement_segment_id), OpenMode::Read)
            .await
        {
            Ok(file) => file,
            Err(PagedbError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => pager
                .vfs()
                .open(&staging_path(&replacement_segment_id), OpenMode::Read)
                .await
                .map_err(|_| PagedbError::RekeyReplacementMissing {
                    replacement_segment_id,
                })?,
            Err(_) => {
                return Err(PagedbError::RekeyReplacementMissing {
                    replacement_segment_id,
                });
            }
        };
        let total_bytes = file
            .len()
            .await
            .map_err(|_| PagedbError::RekeyReplacementMissing {
                replacement_segment_id,
            })?;
        let page_size_u64 = u64::try_from(page_size).map_err(|_| PagedbError::Unsupported)?;
        if total_bytes < page_size_u64 * 2 || total_bytes % page_size_u64 != 0 {
            return Err(PagedbError::RekeyReplacementMissing {
                replacement_segment_id,
            });
        }
        CipherId::from_byte(target_cipher_id)?;
        let mut expected = source.clone();
        expected.segment_id = replacement_segment_id;
        expected.page_count = total_bytes / page_size_u64;
        expected.total_bytes = total_bytes;
        expected.final_counter = source.final_counter;
        expected.mk_epoch = target_mk_epoch;
        expected.cipher_id = target_cipher_id;
        let reader = Self::finish_open(
            pager,
            expected,
            page_size,
            file,
            MmapBudget {
                used: mmap_budget_used,
                limit: mmap_budget_limit,
            },
        )
        .await;
        reader.map_err(|_| PagedbError::RekeyReplacementMissing {
            replacement_segment_id,
        })
    }

    async fn finish_open(
        pager: Arc<Pager<V>>,
        catalog_meta: SegmentMeta,
        page_size: usize,
        file: V::File,
        mmap_budget: MmapBudget,
    ) -> Result<Self> {
        let authenticated = authenticate_segment_metadata(
            &pager,
            &file,
            &catalog_meta,
            pager.main_db_file_id(),
            page_size,
        )
        .await?;
        let index_page_count = authenticated.footer.index_page_count;
        let footer = AuthenticatedSegmentFooter {
            fields: authenticated.footer,
            manifest: authenticated.manifest,
        };

        Ok(Self {
            pager,
            meta: catalog_meta,
            page_size,
            file,
            master_key: authenticated.master_key,
            mmap_budget_used: mmap_budget.used,
            mmap_budget_limit: mmap_budget.limit,
            extent_index: tokio::sync::OnceCell::new(),
            index_page_count,
            footer,
        })
    }

    pub(crate) async fn read_authenticated_page(
        &self,
        id: u64,
    ) -> Result<(SegmentPageKind, Bytes)> {
        // page 0 = header, page page_count-1 = footer; data pages are 1..page_count-2.
        if id == 0 || id >= self.meta.page_count - 1 {
            return Err(PagedbError::NotFound);
        }
        let page_size = u64::try_from(self.page_size)
            .map_err(|_| PagedbError::arithmetic_overflow("segment page size"))?;
        let offset = id
            .checked_mul(page_size)
            .ok_or_else(|| PagedbError::arithmetic_overflow("segment page offset"))?;
        let mut buf = vec![0u8; self.page_size];
        let n = self.file.read_at(offset, &mut buf).await?;
        if n < self.page_size {
            return Err(PagedbError::NotFound);
        }

        // Try each segment page kind; AAD binding rejects wrong ones.
        let try_kinds = [
            PageKind::SegmentData,
            PageKind::SegmentIndex,
            PageKind::SegmentOverflow,
        ];
        let (on_wire_cipher, on_wire_epoch) = extract_page_header_ids(&buf)?;
        if on_wire_cipher.as_byte() != self.meta.cipher_id {
            return Err(PagedbError::segment_metadata_mismatch(
                "data_page.cipher_id",
            ));
        }
        if on_wire_epoch != self.meta.mk_epoch {
            return Err(PagedbError::segment_metadata_mismatch("data_page.mk_epoch"));
        }
        let mut lru = self.pager.dek_lru().lock();
        let cipher = lru.get_or_derive(
            self.meta.realm_id,
            self.meta.mk_epoch,
            on_wire_cipher,
            &self.master_key,
        )?;
        let mut last_err: Option<PagedbError> = None;
        for kind in try_kinds {
            let mut buf_try = buf.clone();
            let aad_try = Aad::from_fields(AadFields {
                cipher_id: self.meta.cipher_id,
                page_kind: kind.as_byte(),
                mk_epoch: self.meta.mk_epoch,
                page_id: id,
                realm_id: self.meta.realm_id,
                segment_id: self.meta.segment_id,
            });
            match open_data_page(&mut buf_try, &aad_try, cipher) {
                Ok(_) => {
                    let body_bytes = body(&buf_try).to_vec();
                    let segment_kind = match kind {
                        PageKind::SegmentData => SegmentPageKind::Data,
                        PageKind::SegmentIndex => SegmentPageKind::Index,
                        PageKind::SegmentOverflow => SegmentPageKind::Overflow,
                        _ => return Err(PagedbError::IllegalPageKind),
                    };
                    return Ok((segment_kind, Bytes::from(body_bytes)));
                }
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.unwrap_or(PagedbError::ChecksumFailure))
    }

    pub async fn read_page(&self, id: u64) -> Result<Bytes> {
        self.read_authenticated_page(id).await.map(|(_, body)| body)
    }

    pub(crate) fn authenticated_footer(&self) -> &AuthenticatedSegmentFooter {
        &self.footer
    }

    pub async fn read_extent(&self, r: ExtentRef) -> Result<Vec<Bytes>> {
        let capacity = usize::try_from(r.count)
            .map_err(|_| PagedbError::arithmetic_overflow("segment extent capacity"))?;
        let mut out = Vec::with_capacity(capacity);
        for i in 0..u64::from(r.count) {
            let page_id = r
                .start_page_id
                .checked_add(i)
                .ok_or_else(|| PagedbError::arithmetic_overflow("segment extent page id"))?;
            out.push(self.read_page(page_id).await?);
        }
        Ok(out)
    }

    pub async fn read_range(&self, start: u64, count: u32) -> Result<Vec<Bytes>> {
        self.read_extent(ExtentRef {
            start_page_id: start,
            count,
        })
        .await
    }

    /// Return a zero-copy read-only view over the decrypted contents of `extent`.
    ///
    /// Pages are decrypted into an anonymous temporary file which is immediately
    /// unlinked, then memory-mapped read-only. The mapping is charged against
    /// `OpenOptions::mmap_view_scratch_bytes`; returns
    /// `PagedbError::MmapViewQuotaExceeded` when the budget is full.
    ///
    /// On WASM targets this always returns `PagedbError::Unsupported`.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn mmap_view(&self, extent: ExtentRef) -> Result<MmapView> {
        let pages_bytes = self.read_extent(extent).await?;
        let page_slices: Vec<&[u8]> = pages_bytes.iter().map(AsRef::as_ref).collect();
        super::mmap::MmapView::from_pages(
            &page_slices,
            self.mmap_budget_used.clone(),
            self.mmap_budget_limit,
        )
    }

    /// WASM stub — always returns `PagedbError::Unsupported`.
    ///
    /// Kept `async` to match the native `mmap_view` signature so callers compile
    /// unchanged on both targets; the stub itself has nothing to await.
    #[cfg(target_arch = "wasm32")]
    #[allow(clippy::unused_async)]
    pub async fn mmap_view(&self, _extent: ExtentRef) -> Result<MmapView> {
        Err(PagedbError::Unsupported)
    }

    /// Look up an extent by its `start_page_id` using the v2 binary-searchable
    /// extent index. Only the matching extent's pages are read from disk; the
    /// full index is loaded lazily on the first call and cached.
    ///
    /// Returns `PagedbError::NotFound` if:
    /// - the segment has no extent index (`format_version == 1` or
    ///   `index_page_count == 0`), or
    /// - no extent with `start_page_id` equal to `id` exists in the index.
    ///
    /// Use `read_extent` / `read_range` for v1 segments or when you already
    /// know the extent bounds.
    pub async fn find_extent(&self, start_page_id: u64) -> Result<Vec<bytes::Bytes>> {
        if self.index_page_count == 0 {
            return Err(PagedbError::NotFound);
        }

        let index = self
            .extent_index
            .get_or_try_init(|| self.load_extent_index())
            .await?;

        // Binary search on start_page_id.
        match index.binary_search_by_key(&start_page_id, |e| e.start_page_id) {
            Ok(pos) => {
                let entry = &index[pos];
                self.read_extent(ExtentRef {
                    start_page_id: entry.start_page_id,
                    count: entry.page_count,
                })
                .await
            }
            Err(_) => Err(PagedbError::NotFound),
        }
    }

    /// Load the extent index through the same authenticated decoder used by
    /// open-time reconciliation.
    async fn load_extent_index(&self) -> Result<Vec<ExtentIndexEntry>> {
        let context = ExtentIndexDecodeContext {
            pager: &self.pager,
            file: &self.file,
            meta: &self.meta,
            master_key: &self.master_key,
            footer: &self.footer.fields,
            cipher_id: CipherId::from_byte(self.meta.cipher_id)?,
            page_size: self.page_size,
        };
        decode_extent_index(&context).await
    }

    /// Number of extent-index pages in this segment (0 for segments without
    /// an extent index). Useful for verifying lazy-loading behaviour in tests
    /// and for capacity planning.
    #[must_use]
    pub fn index_page_count(&self) -> u32 {
        self.index_page_count
    }

    pub fn meta(&self) -> &SegmentMeta {
        &self.meta
    }
}
