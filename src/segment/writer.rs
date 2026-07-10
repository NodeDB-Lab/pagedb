//! Segment writer: builds an encrypted segment file on disk at the staging
//! path. Pages are appended after construction; `seal()` writes the footer
//! and fsyncs.

use std::sync::Arc;

use crate::catalog::codec::{SegmentKind, SegmentMeta};
use crate::crypto::aad::{Aad, AadFields};
use crate::crypto::kdf::derive_hk;
use crate::crypto::nonce::SegmentNonceGen;
use crate::errors::{Evictable, PagedbError};
use crate::pager::Pager;
use crate::pager::format::data_page::{ENVELOPE_OVERHEAD, body_mut, seal_data_page};
use crate::pager::format::segment_footer::{
    SegmentFooterFields, encode_segment_footer, max_manifest_len_v2,
};
use crate::pager::format::structural_header::{SegmentHeaderFields, encode_segment_header};
use crate::vfs::types::OpenMode;
use crate::vfs::{Vfs, VfsFile};
use crate::{RealmId, Result};
use tracing;

use super::types::{EXTENT_INDEX_ENTRY_LEN, ExtentIndexEntry, ExtentRef, PageId, SegmentPageKind};

/// Format version written by `SegmentWriter::seal`.
/// v2 adds an encrypted extent index block between data pages and the footer,
/// enabling `SegmentReader::find_extent` to perform lazy binary-search lookups
/// without decoding all extents on open.
const FORMAT_VERSION: u16 = 2;

pub struct SegmentWriter<V: Vfs + Clone> {
    pager: Arc<Pager<V>>,
    realm_id: RealmId,
    segment_id: [u8; 16],
    parent_file_id: [u8; 16],
    mk_epoch: u64,
    cipher_id: u8,
    segment_kind: SegmentKind,
    page_size: usize,
    file: V::File,
    nonce_gen: SegmentNonceGen,
    next_page_id: u64,
    manifest: Vec<u8>,
    total_bytes: u64,
    /// Extents appended via `append_extent`. Each entry records the start
    /// page id, count, and total logical bytes. Written as the index block
    /// in v2 segments before the footer page.
    extents: Vec<ExtentIndexEntry>,
    format_version: u16,
    evictable: Evictable,
    /// Exact footer layout copied during rekey. Its index pages have already
    /// been authenticated and appended as logical segment pages.
    rekey_footer_layout: Option<(u64, u32)>,
}

impl<V: Vfs + Clone> SegmentWriter<V> {
    pub(crate) async fn create_internal(
        pager: Arc<Pager<V>>,
        realm_id: RealmId,
        segment_id: [u8; 16],
        parent_file_id: [u8; 16],
        segment_kind: SegmentKind,
    ) -> Result<Self> {
        let page_size = pager.page_size();
        let cipher_id = pager.cipher_id().as_byte();
        let mk_epoch = pager.mk_epoch();
        let pager_mk = pager.mk()?;
        let hk = derive_hk(&pager_mk)?;
        let page_size_log2 = page_size_to_log2(page_size)?;

        // Ensure the staging directory exists and its entry is durable before
        // creating the staging file, so the file's inode survives a power loss
        // before seal is called.
        pager.vfs().mkdir_all("seg/.staging").await?;
        pager.vfs().sync_dir("seg/.staging").await?;

        let path = staging_path(&segment_id);
        let mut file = pager.vfs().open(&path, OpenMode::CreateNew).await?;

        let header_fields = SegmentHeaderFields {
            format_version: 1, // structural header is always v1; v2 is a footer-only version bump
            cipher_id,
            segment_kind: segment_kind as u8,
            segment_id,
            parent_file_id,
            realm_id,
            mk_epoch,
            page_size_log2,
            flags: 0,
        };
        let header_bytes = encode_segment_header(&header_fields, &hk, page_size)?;
        file.write_at(0, &header_bytes).await?;

        let total_bytes = u64::try_from(page_size)
            .map_err(|_| PagedbError::Io(std::io::Error::other("page_size > u64")))?;

        Ok(Self {
            pager,
            realm_id,
            segment_id,
            parent_file_id,
            mk_epoch,
            cipher_id,
            segment_kind,
            page_size,
            file,
            nonce_gen: SegmentNonceGen::new(&segment_id),
            next_page_id: 1,
            manifest: Vec::new(),
            total_bytes,
            extents: Vec::new(),
            format_version: FORMAT_VERSION,
            evictable: Evictable::Authoritative,
            rekey_footer_layout: None,
        })
    }

    /// Construct a replacement writer that preserves the source segment's
    /// logical footer version, extent-index layout, kind, and evictability.
    pub(crate) async fn create_rekey_internal(
        pager: Arc<Pager<V>>,
        source: &SegmentMeta,
        segment_id: [u8; 16],
        index_start_page: u64,
        index_page_count: u32,
    ) -> Result<Self> {
        let mut writer = Self::create_internal(
            pager,
            source.realm_id,
            segment_id,
            source.parent_file_id,
            source.segment_kind,
        )
        .await?;
        writer.format_version = source.format_version;
        writer.evictable = source.evictable;
        writer.rekey_footer_layout = Some((index_start_page, index_page_count));
        Ok(writer)
    }

    pub(crate) async fn append_rekey_page(
        &mut self,
        kind: SegmentPageKind,
        payload: &[u8],
    ) -> Result<PageId> {
        self.append_page(kind, payload).await
    }

    #[cfg(test)]
    pub(crate) fn set_format_version_for_rekey_test(&mut self, format_version: u16) {
        self.format_version = format_version;
    }

    pub async fn append_page(&mut self, kind: SegmentPageKind, payload: &[u8]) -> Result<PageId> {
        let cap = self.page_size - ENVELOPE_OVERHEAD;
        if payload.len() > cap {
            return Err(PagedbError::PayloadTooLarge);
        }
        let page_kind = kind.as_page_kind();
        let page_id = self.next_page_id;
        let nonce = self.nonce_gen.next_nonce()?;
        let aad = Aad::from_fields(AadFields {
            cipher_id: self.cipher_id,
            page_kind: page_kind.as_byte(),
            mk_epoch: self.mk_epoch,
            page_id,
            realm_id: self.realm_id,
            segment_id: self.segment_id,
        });

        let mut buf = vec![0u8; self.page_size];
        body_mut(&mut buf)[..payload.len()].copy_from_slice(payload);
        {
            let pager_mk_append = self.pager.mk()?;
            let mut lru = self.pager.dek_lru().lock();
            let cipher = lru.get_or_derive(
                self.realm_id,
                self.mk_epoch,
                crate::crypto::CipherId::from_byte(self.cipher_id)?,
                &pager_mk_append,
            )?;
            seal_data_page(&mut buf, page_kind, 0, self.mk_epoch, &nonce, &aad, cipher)?;
        }

        let offset = page_id
            .checked_mul(self.page_size as u64)
            .ok_or_else(|| PagedbError::Io(std::io::Error::other("offset overflow")))?;
        self.file.write_at(offset, &buf).await?;
        self.next_page_id += 1;
        self.total_bytes = self.total_bytes.saturating_add(self.page_size as u64);
        Ok(page_id)
    }

    pub async fn append_extent(&mut self, pages: &[&[u8]]) -> Result<ExtentRef> {
        if pages.is_empty() {
            return Err(PagedbError::EmptyExtent);
        }
        let start = self.next_page_id;
        let mut logical_bytes = 0u64;
        for payload in pages {
            self.append_page(SegmentPageKind::Data, payload).await?;
            logical_bytes = logical_bytes.saturating_add(payload.len() as u64);
        }
        let count = u32::try_from(pages.len()).map_err(|_| PagedbError::PayloadTooLarge)?;
        // Record the extent in the index for v2 seal.
        self.extents.push(ExtentIndexEntry {
            start_page_id: start,
            page_count: count,
            logical_bytes,
        });
        Ok(ExtentRef {
            start_page_id: start,
            count,
        })
    }

    pub fn set_manifest(&mut self, manifest: &[u8]) -> Result<()> {
        let max_len = if self.format_version == 1 {
            crate::pager::format::segment_footer::max_manifest_len(self.page_size)
        } else {
            max_manifest_len_v2(self.page_size)
        };
        if manifest.len() > max_len {
            return Err(PagedbError::ManifestTooLarge);
        }
        self.manifest = manifest.to_vec();
        Ok(())
    }

    /// Seal the segment file.
    ///
    /// If `append_extent` was called at least once, a v2 segment is written:
    /// the extent index is serialised into a block of encrypted pages between
    /// the last data page and the footer. The footer cleartext includes the
    /// `index_start_page` and `index_page_count` so that `SegmentReader` can
    /// locate the index without scanning the whole file.
    ///
    /// Segments with no extents (only `append_page` calls) are also written as
    /// v2 with `index_page_count = 0`.
    #[allow(clippy::too_many_lines)]
    pub async fn seal(mut self) -> Result<SegmentMeta> {
        tracing::debug!(name = "segment.seal", "sealing segment file");
        let pager_mk_seal = self.pager.mk()?;
        let hk = derive_hk(&pager_mk_seal)?;

        // ── Write extent index block (v2) ─────────────────────────────────────
        let entries_per_page = (self.page_size
            - crate::pager::format::data_page::ENVELOPE_OVERHEAD)
            / EXTENT_INDEX_ENTRY_LEN;
        let index_start_page: u64;
        let index_page_count: u32;

        if let Some((source_index_start, source_index_count)) = self.rekey_footer_layout {
            let footer_page_id = self.next_page_id;
            let invalid_layout = if self.format_version == 1 {
                source_index_start != 0 || source_index_count != 0
            } else if source_index_count == 0 {
                source_index_start != 0
            } else {
                source_index_start == 0
                    || source_index_start.checked_add(u64::from(source_index_count))
                        != Some(footer_page_id)
            };
            if invalid_layout {
                return Err(PagedbError::corruption(
                    crate::errors::CorruptionDetail::HeaderUnverifiable,
                ));
            }
            index_start_page = source_index_start;
            index_page_count = source_index_count;
        } else if self.extents.is_empty() {
            index_start_page = 0;
            index_page_count = 0;
        } else {
            // Entries sorted by start_page_id (they are already in insertion
            // order, which equals ascending start_page_id because append_extent
            // assigns monotonically increasing page ids).
            index_start_page = self.next_page_id;
            let total_entries = self.extents.len();
            let pages_needed = total_entries.div_ceil(entries_per_page);
            index_page_count =
                u32::try_from(pages_needed).map_err(|_| PagedbError::PayloadTooLarge)?;

            for page_idx in 0..pages_needed {
                let page_id = self.next_page_id;
                let nonce = self.nonce_gen.next_nonce()?;
                let aad = crate::crypto::aad::Aad::from_fields(crate::crypto::aad::AadFields {
                    cipher_id: self.cipher_id,
                    page_kind: crate::pager::format::page_kind::PageKind::SegmentIndex.as_byte(),
                    mk_epoch: self.mk_epoch,
                    page_id,
                    realm_id: self.realm_id,
                    segment_id: self.segment_id,
                });

                let body_cap = self.page_size - crate::pager::format::data_page::ENVELOPE_OVERHEAD;
                let mut body = vec![0u8; body_cap];

                let start_entry = page_idx * entries_per_page;
                let end_entry = (start_entry + entries_per_page).min(total_entries);
                for (i, entry) in self.extents[start_entry..end_entry].iter().enumerate() {
                    let off = i * EXTENT_INDEX_ENTRY_LEN;
                    body[off..off + EXTENT_INDEX_ENTRY_LEN].copy_from_slice(&entry.encode());
                }

                let mut buf = vec![0u8; self.page_size];
                crate::pager::format::data_page::body_mut(&mut buf)[..body_cap]
                    .copy_from_slice(&body);
                {
                    let pager_mk_idx = self.pager.mk()?;
                    let mut lru = self.pager.dek_lru().lock();
                    let cipher = lru.get_or_derive(
                        self.realm_id,
                        self.mk_epoch,
                        crate::crypto::CipherId::from_byte(self.cipher_id)?,
                        &pager_mk_idx,
                    )?;
                    crate::pager::format::data_page::seal_data_page(
                        &mut buf,
                        crate::pager::format::page_kind::PageKind::SegmentIndex,
                        0,
                        self.mk_epoch,
                        &nonce,
                        &aad,
                        cipher,
                    )?;
                }

                let offset = page_id
                    .checked_mul(self.page_size as u64)
                    .ok_or_else(|| PagedbError::Io(std::io::Error::other("offset overflow")))?;
                self.file.write_at(offset, &buf).await?;
                self.next_page_id += 1;
                self.total_bytes = self.total_bytes.saturating_add(self.page_size as u64);
            }
        }

        // ── Write footer ──────────────────────────────────────────────────────
        let footer_page_id = self.next_page_id;
        let footer_fields = SegmentFooterFields {
            format_version: self.format_version,
            cipher_id: self.cipher_id,
            segment_id: self.segment_id,
            parent_file_id: self.parent_file_id,
            realm_id: self.realm_id,
            mk_epoch: self.mk_epoch,
            page_count: footer_page_id + 1,
            total_bytes: self.total_bytes + self.page_size as u64,
            final_counter: self.nonce_gen.final_counter(),
            index_start_page,
            index_page_count,
        };
        let footer_bytes = {
            let pager_mk_footer = self.pager.mk()?;
            let mut lru = self.pager.dek_lru().lock();
            let cipher = lru.get_or_derive(
                self.realm_id,
                self.mk_epoch,
                crate::crypto::CipherId::from_byte(self.cipher_id)?,
                &pager_mk_footer,
            )?;
            encode_segment_footer(&footer_fields, &self.manifest, &hk, cipher, self.page_size)?
        };
        let offset = footer_page_id
            .checked_mul(self.page_size as u64)
            .ok_or_else(|| PagedbError::Io(std::io::Error::other("offset overflow")))?;
        self.file.write_at(offset, &footer_bytes).await?;
        self.file.sync().await?;
        self.pager.vfs().sync_dir("seg/.staging").await?;

        Ok(SegmentMeta {
            segment_id: self.segment_id,
            segment_kind: self.segment_kind,
            realm_id: self.realm_id,
            parent_file_id: self.parent_file_id,
            linked_commit: None,
            page_count: footer_page_id + 1,
            total_bytes: footer_fields.total_bytes,
            final_counter: footer_fields.final_counter,
            mk_epoch: self.mk_epoch,
            cipher_id: self.cipher_id,
            format_version: self.format_version,
            evictable: self.evictable,
        })
    }

    pub fn abort(self) {
        // Drop file handle. Best-effort cleanup; reconciliation at next open
        // is the authoritative path.
        let _ = self.file;
    }

    pub fn segment_id(&self) -> [u8; 16] {
        self.segment_id
    }
}

pub(crate) fn staging_path(segment_id: &[u8; 16]) -> String {
    format!("seg/.staging/{}", crate::hex::to_hex_lower(segment_id))
}

pub(crate) fn live_path(segment_id: &[u8; 16]) -> String {
    format!("seg/{}", crate::hex::to_hex_lower(segment_id))
}

fn page_size_to_log2(page_size: usize) -> Result<u8> {
    match page_size {
        4096 => Ok(12),
        8192 => Ok(13),
        16384 => Ok(14),
        32768 => Ok(15),
        65536 => Ok(16),
        _ => Err(PagedbError::Unsupported),
    }
}
