//! Segment reader: opens a sealed segment file at its identity-keyed live
//! path, validates header + footer, exposes page reads.

use std::sync::Arc;

use bytes::Bytes;

use crate::Result;
use crate::catalog::codec::{SegmentKind, SegmentMeta};
use crate::crypto::CipherId;
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

use super::types::{
    EXTENT_INDEX_ENTRY_LEN, ExtentIndexEntry, ExtentRef, MmapView, SegmentPageKind,
};
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
    footer: AuthenticatedSegmentFooter,
}

fn footer_unverifiable(meta: &SegmentMeta) -> PagedbError {
    PagedbError::corruption(crate::errors::CorruptionDetail::FooterUnverifiable {
        realm_id: meta.realm_id,
        name: String::new(),
        segment_id: meta.segment_id,
    })
}

fn validate_segment_header(
    header: &crate::pager::format::structural_header::SegmentHeaderFields,
    meta: &SegmentMeta,
) -> Result<()> {
    if header.segment_id != meta.segment_id
        || SegmentKind::from_byte(header.segment_kind)? != meta.segment_kind
        || header.realm_id != meta.realm_id
        || header.mk_epoch != meta.mk_epoch
        || header.cipher_id != meta.cipher_id
    {
        return Err(footer_unverifiable(meta));
    }
    if header.parent_file_id != meta.parent_file_id {
        return Err(PagedbError::corruption(
            crate::errors::CorruptionDetail::ForeignSegment {
                realm_id: meta.realm_id,
                name: String::new(),
                segment_id: meta.segment_id,
                footer_parent_file_id: header.parent_file_id,
                expected_parent_file_id: meta.parent_file_id,
            },
        ));
    }
    Ok(())
}

fn invalid_footer_index(
    format_version: u16,
    index_start_page: u64,
    index_page_count: u32,
    footer_page_id: u64,
) -> bool {
    match format_version {
        1 => index_start_page != 0 || index_page_count != 0,
        2 if index_page_count == 0 => index_start_page != 0,
        2 => {
            index_start_page == 0
                || index_start_page.checked_add(u64::from(index_page_count)) != Some(footer_page_id)
        }
        _ => true,
    }
}

async fn read_authenticated_footer<V: Vfs + Clone>(
    pager: &Arc<Pager<V>>,
    file: &V::File,
    meta: &SegmentMeta,
    hk: &crate::crypto::keys::DerivedKey,
    mk_override: Option<&crate::crypto::keys::MasterKey>,
    page_size: usize,
) -> Result<(u64, u32, AuthenticatedSegmentFooter)> {
    if meta.page_count < 2 {
        return Err(footer_unverifiable(meta));
    }
    let footer_page_id = meta.page_count - 1;
    let footer_offset = footer_page_id
        .checked_mul(page_size as u64)
        .ok_or_else(|| PagedbError::Io(std::io::Error::other("offset overflow")))?;
    let mut footer_buf = vec![0u8; page_size];
    file.read_at(footer_offset, &mut footer_buf).await?;

    let effective_master_key;
    let effective_master_key_ref = if let Some(master_key) = mk_override {
        master_key
    } else {
        effective_master_key = pager.mk_for(meta.mk_epoch, CipherId::from_byte(meta.cipher_id)?)?;
        &effective_master_key
    };
    let mut lru = pager.dek_lru().lock();
    let cipher = lru.get_or_derive(
        meta.realm_id,
        meta.mk_epoch,
        CipherId::from_byte(meta.cipher_id)?,
        effective_master_key_ref,
    )?;
    let (footer_fields, manifest) = decode_segment_footer(&footer_buf, hk, cipher, page_size)?;
    let invalid_index = invalid_footer_index(
        footer_fields.format_version,
        footer_fields.index_start_page,
        footer_fields.index_page_count,
        footer_page_id,
    );
    if footer_fields.segment_id != meta.segment_id
        || footer_fields.parent_file_id != meta.parent_file_id
        || footer_fields.realm_id != meta.realm_id
        || footer_fields.mk_epoch != meta.mk_epoch
        || footer_fields.cipher_id != meta.cipher_id
        || footer_fields.format_version != meta.format_version
        || footer_fields.page_count != meta.page_count
        || footer_fields.total_bytes != meta.total_bytes
        || invalid_index
    {
        return Err(footer_unverifiable(meta));
    }
    Ok((
        footer_fields.index_start_page,
        footer_fields.index_page_count,
        AuthenticatedSegmentFooter {
            fields: footer_fields,
            manifest,
        },
    ))
}

impl<V: Vfs + Clone> SegmentReader<V> {
    pub(crate) async fn open_internal(
        pager: Arc<Pager<V>>,
        catalog_meta: SegmentMeta,
        mmap_budget_used: std::sync::Arc<std::sync::atomic::AtomicU64>,
        mmap_budget_limit: u64,
    ) -> Result<Self> {
        let page_size = pager.page_size();
        let pager_mk = pager.mk_for(
            catalog_meta.mk_epoch,
            CipherId::from_byte(catalog_meta.cipher_id)?,
        )?;
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
            Some(pager_mk),
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
        let target_cipher = CipherId::from_byte(target_cipher_id)?;
        let mk = pager.mk_for(target_mk_epoch, target_cipher)?;
        let mut expected = source.clone();
        expected.segment_id = replacement_segment_id;
        expected.page_count = total_bytes / page_size_u64;
        expected.total_bytes = total_bytes;
        expected.final_counter = 0;
        expected.mk_epoch = target_mk_epoch;
        expected.cipher_id = target_cipher_id;
        let reader = Self::finish_open(
            pager,
            expected,
            derive_hk(&mk)?,
            Some(mk),
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
        mut catalog_meta: SegmentMeta,
        hk: crate::crypto::keys::DerivedKey,
        mk_override: Option<crate::crypto::keys::MasterKey>,
        page_size: usize,
        file: V::File,
        mmap_budget: MmapBudget,
    ) -> Result<Self> {
        let mut header_buf = vec![0u8; page_size];
        file.read_at(0, &mut header_buf).await?;
        validate_segment_header(
            &decode_segment_header(&header_buf, &hk, page_size)?,
            &catalog_meta,
        )?;
        let (index_start_page, index_page_count, footer) = read_authenticated_footer(
            &pager,
            &file,
            &catalog_meta,
            &hk,
            mk_override.as_ref(),
            page_size,
        )
        .await?;
        catalog_meta.final_counter = footer.fields.final_counter;

        Ok(Self {
            pager,
            meta: catalog_meta,
            page_size,
            file,
            mk_override,
            mmap_budget_used: mmap_budget.used,
            mmap_budget_limit: mmap_budget.limit,
            extent_index: tokio::sync::OnceCell::new(),
            index_start_page,
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
            effective_mk_read = self.pager.mk_for(
                self.meta.mk_epoch,
                CipherId::from_byte(self.meta.cipher_id)?,
            )?;
            &effective_mk_read
        };
        let mut lru = self.pager.dek_lru().lock();
        let cipher = lru.get_or_derive(
            self.meta.realm_id,
            self.meta.mk_epoch,
            CipherId::from_byte(self.meta.cipher_id)?,
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
                effective_mk_read = self.pager.mk_for(
                    self.meta.mk_epoch,
                    CipherId::from_byte(self.meta.cipher_id)?,
                )?;
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
                    CipherId::from_byte(self.meta.cipher_id)?,
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
