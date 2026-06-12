//! Segment reader: opens a sealed segment file at its identity-keyed live
//! path, validates header + footer, exposes page reads.

use std::sync::Arc;

use bytes::Bytes;

use crate::Result;
use crate::catalog::codec::SegmentMeta;
use crate::crypto::aad::{Aad, AadFields};
use crate::crypto::kdf::derive_hk;
use crate::errors::PagedbError;
use crate::pager::Pager;
use crate::pager::format::data_page::{body, open_data_page};
use crate::pager::format::page_kind::PageKind;
use crate::pager::format::segment_footer::decode_segment_footer;
use crate::pager::format::structural_header::decode_segment_header;
use crate::vfs::types::OpenMode;
use crate::vfs::{Vfs, VfsFile};

use super::types::{EXTENT_INDEX_ENTRY_LEN, ExtentIndexEntry, ExtentRef, MmapView};
use super::writer::live_path;

pub struct SegmentReader<V: Vfs + Clone> {
    pager: Arc<Pager<V>>,
    meta: SegmentMeta,
    page_size: usize,
    file: V::File,
    /// When set, used instead of `pager.mk()` for DEK derivation. Needed
    /// during online rekey when the pager has already advanced to a new epoch
    /// but this reader is reading a segment sealed under an older epoch.
    mk_override: Option<crate::crypto::keys::MasterKey>,
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
    index_start_page: u64,
    index_page_count: u32,
}

impl<V: Vfs + Clone> SegmentReader<V> {
    pub(crate) async fn open_internal(
        pager: Arc<Pager<V>>,
        catalog_meta: SegmentMeta,
        mmap_budget_used: std::sync::Arc<std::sync::atomic::AtomicU64>,
        mmap_budget_limit: u64,
    ) -> Result<Self> {
        let page_size = pager.page_size();
        let pager_mk = pager.mk();
        let hk = derive_hk(&pager_mk)?;
        let live = live_path(&catalog_meta.segment_id);
        let file = pager
            .vfs()
            .open(&live, OpenMode::Read)
            .await
            .map_err(|_| PagedbError::NotFound)?;
        Self::finish_open(
            pager,
            catalog_meta,
            hk,
            None,
            page_size,
            file,
            mmap_budget_used,
            mmap_budget_limit,
        )
        .await
    }

    /// Like `open_internal` but uses an explicit `MasterKey` rather than the
    /// pager's current active key. Used during online rekey when the pager has
    /// already advanced to the new epoch but old segments still need to be read
    /// under the old epoch's HK.
    pub(crate) async fn open_internal_with_mk(
        pager: Arc<Pager<V>>,
        catalog_meta: SegmentMeta,
        mk: &crate::crypto::keys::MasterKey,
        mmap_budget_used: std::sync::Arc<std::sync::atomic::AtomicU64>,
        mmap_budget_limit: u64,
    ) -> Result<Self> {
        let page_size = pager.page_size();
        let hk = derive_hk(mk)?;
        let live = live_path(&catalog_meta.segment_id);
        let file = pager
            .vfs()
            .open(&live, OpenMode::Read)
            .await
            .map_err(|_| PagedbError::NotFound)?;
        Self::finish_open(
            pager,
            catalog_meta,
            hk,
            Some(mk.clone()),
            page_size,
            file,
            mmap_budget_used,
            mmap_budget_limit,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn finish_open(
        pager: Arc<Pager<V>>,
        catalog_meta: SegmentMeta,
        hk: crate::crypto::keys::DerivedKey,
        mk_override: Option<crate::crypto::keys::MasterKey>,
        page_size: usize,
        file: V::File,
        mmap_budget_used: std::sync::Arc<std::sync::atomic::AtomicU64>,
        mmap_budget_limit: u64,
    ) -> Result<Self> {
        // Validate header.
        let mut header_buf = vec![0u8; page_size];
        file.read_at(0, &mut header_buf).await?;
        let header_fields = decode_segment_header(&header_buf, &hk, page_size)?;

        if header_fields.segment_id != catalog_meta.segment_id {
            return Err(PagedbError::corruption(
                crate::errors::CorruptionDetail::FooterUnverifiable {
                    realm_id: catalog_meta.realm_id,
                    name: String::new(),
                    segment_id: catalog_meta.segment_id,
                },
            ));
        }
        if header_fields.parent_file_id != catalog_meta.parent_file_id {
            return Err(PagedbError::corruption(
                crate::errors::CorruptionDetail::ForeignSegment {
                    realm_id: catalog_meta.realm_id,
                    name: String::new(),
                    segment_id: catalog_meta.segment_id,
                    footer_parent_file_id: header_fields.parent_file_id,
                    expected_parent_file_id: catalog_meta.parent_file_id,
                },
            ));
        }

        // Validate footer. Use `mk_override` if present so the DEK is derived
        // from the correct epoch's master key even if the pager has advanced.
        let footer_page_id = catalog_meta.page_count - 1;
        let footer_offset = footer_page_id
            .checked_mul(page_size as u64)
            .ok_or_else(|| PagedbError::Io(std::io::Error::other("offset overflow")))?;
        let mut footer_buf = vec![0u8; page_size];
        file.read_at(footer_offset, &mut footer_buf).await?;
        let (index_start_page, index_page_count) = {
            let effective_mk;
            let effective_mk_ref = if let Some(m) = &mk_override {
                m
            } else {
                effective_mk = pager.mk();
                &effective_mk
            };
            let mut lru = pager.dek_lru().lock();
            let cipher = lru.get_or_derive(
                catalog_meta.realm_id,
                catalog_meta.mk_epoch,
                pager.cipher_id(),
                effective_mk_ref,
            )?;
            let (footer_fields, _manifest) =
                decode_segment_footer(&footer_buf, &hk, cipher, page_size)?;
            if footer_fields.segment_id != catalog_meta.segment_id {
                return Err(PagedbError::corruption(
                    crate::errors::CorruptionDetail::FooterUnverifiable {
                        realm_id: catalog_meta.realm_id,
                        name: String::new(),
                        segment_id: catalog_meta.segment_id,
                    },
                ));
            }
            (
                footer_fields.index_start_page,
                footer_fields.index_page_count,
            )
        };

        Ok(Self {
            pager,
            meta: catalog_meta,
            page_size,
            file,
            mk_override,
            mmap_budget_used,
            mmap_budget_limit,
            extent_index: tokio::sync::OnceCell::new(),
            index_start_page,
            index_page_count,
        })
    }

    pub async fn read_page(&self, id: u64) -> Result<Bytes> {
        // page 0 = header, page page_count-1 = footer; data pages are 1..page_count-2.
        if id == 0 || id >= self.meta.page_count - 1 {
            return Err(PagedbError::NotFound);
        }
        let offset = id
            .checked_mul(self.page_size as u64)
            .ok_or_else(|| PagedbError::Io(std::io::Error::other("offset overflow")))?;
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
        // Use mk_override when present so old-epoch pages decrypt correctly
        // after the pager has advanced to a new epoch during online rekey.
        let effective_mk_read;
        let effective_mk_read_ref = if let Some(m) = &self.mk_override {
            m
        } else {
            effective_mk_read = self.pager.mk();
            &effective_mk_read
        };
        let mut lru = self.pager.dek_lru().lock();
        let cipher = lru.get_or_derive(
            self.meta.realm_id,
            self.meta.mk_epoch,
            self.pager.cipher_id(),
            effective_mk_read_ref,
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
                    return Ok(Bytes::from(body_bytes));
                }
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.unwrap_or(PagedbError::ChecksumFailure))
    }

    pub async fn read_extent(&self, r: ExtentRef) -> Result<Vec<Bytes>> {
        let mut out = Vec::with_capacity(r.count as usize);
        for i in 0..u64::from(r.count) {
            out.push(self.read_page(r.start_page_id + i).await?);
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

    /// Load the extent index from the index pages written during `seal`.
    async fn load_extent_index(&self) -> Result<Vec<ExtentIndexEntry>> {
        let entries_per_page = (self.page_size
            - crate::pager::format::data_page::ENVELOPE_OVERHEAD)
            / EXTENT_INDEX_ENTRY_LEN;

        let mut entries: Vec<ExtentIndexEntry> =
            Vec::with_capacity(entries_per_page * self.index_page_count as usize);

        for page_idx in 0..u64::from(self.index_page_count) {
            let page_id = self.index_start_page + page_idx;
            let offset = page_id
                .checked_mul(self.page_size as u64)
                .ok_or_else(|| PagedbError::Io(std::io::Error::other("offset overflow")))?;
            let mut buf = vec![0u8; self.page_size];
            let n = self.file.read_at(offset, &mut buf).await?;
            if n < self.page_size {
                return Err(PagedbError::NotFound);
            }

            // Decrypt the index page.
            let effective_mk_read;
            let effective_mk_read_ref = if let Some(m) = &self.mk_override {
                m
            } else {
                effective_mk_read = self.pager.mk();
                &effective_mk_read
            };
            let aad = crate::crypto::aad::Aad::from_fields(crate::crypto::aad::AadFields {
                cipher_id: self.meta.cipher_id,
                page_kind: crate::pager::format::page_kind::PageKind::SegmentIndex.as_byte(),
                mk_epoch: self.meta.mk_epoch,
                page_id,
                realm_id: self.meta.realm_id,
                segment_id: self.meta.segment_id,
            });
            {
                let mut lru = self.pager.dek_lru().lock();
                let cipher = lru.get_or_derive(
                    self.meta.realm_id,
                    self.meta.mk_epoch,
                    self.pager.cipher_id(),
                    effective_mk_read_ref,
                )?;
                let _ = crate::pager::format::data_page::open_data_page(&mut buf, &aad, cipher)?;
            }

            // Parse entries from the decrypted body.
            let body = crate::pager::format::data_page::body(&buf);
            let mut off = 0;
            while off + EXTENT_INDEX_ENTRY_LEN <= body.len() {
                let entry_buf: &[u8; EXTENT_INDEX_ENTRY_LEN] = body
                    [off..off + EXTENT_INDEX_ENTRY_LEN]
                    .try_into()
                    .map_err(|_| PagedbError::Io(std::io::Error::other("slice len")))?;
                let entry = ExtentIndexEntry::decode(entry_buf);
                if entry.start_page_id == 0 && entry.page_count == 0 {
                    // Zero padding at end of last page.
                    break;
                }
                entries.push(entry);
                off += EXTENT_INDEX_ENTRY_LEN;
            }
        }

        Ok(entries)
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
