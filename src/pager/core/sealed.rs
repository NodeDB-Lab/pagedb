//! Authenticated main.db reads that report the page's seal stamp.
//!
//! A cached page cannot supply its stamp. A write inserts a zeroed header, and
//! a rekey marks a page dirty with its old header still in the buffer. So these
//! reads skip the cache and take one file read and one tag check per page.
//!
//! The caller excludes writers for the walk, so the file holds what the cache
//! holds. The stamp counts only after the page opens, because the envelope is
//! cleartext.

use super::pager::Pager;
use super::read::KindBinding;
use crate::crypto::Aad;
use crate::crypto::aad::{AadFields, MAIN_DB_SEGMENT_ID};
use crate::errors::{CorruptionDetail, PagedbError};
use crate::pager::cache::FileKey;
use crate::pager::format::data_page::{
    SealStamp, extract_page_header_ids, open_data_page, read_seal_stamp,
};
use crate::pager::format::page_kind::PageKind;
use crate::pager::page_space::page_offset;
use crate::vfs::{Vfs, read_exact_at};
use crate::{RealmId, Result};

/// One page read past the cache. `page` holds the decrypted full-page buffer.
pub(crate) struct SealedRead {
    pub page: Vec<u8>,
    pub kind: PageKind,
    pub stamp: SealStamp,
}

impl<V: Vfs> Pager<V> {
    /// Read a B+ tree node past the cache. Its own envelope picks leaf or internal.
    pub(crate) async fn read_main_node_sealed(
        &self,
        page_id: u64,
        realm_id: RealmId,
    ) -> Result<SealedRead> {
        self.read_sealed(page_id, realm_id, KindBinding::Node).await
    }

    /// Read a page of a known kind past the cache.
    pub(crate) async fn read_main_page_sealed(
        &self,
        page_id: u64,
        realm_id: RealmId,
        kind: PageKind,
    ) -> Result<SealedRead> {
        self.read_sealed(page_id, realm_id, KindBinding::Fixed(kind))
            .await
    }

    /// Each failure matches a cold [`Self::read_page`] on the same bytes, so
    /// `proves_unreadable_pages` classifies the two alike.
    async fn read_sealed(
        &self,
        page_id: u64,
        realm_id: RealmId,
        binding: KindBinding,
    ) -> Result<SealedRead> {
        let page_size = self.cfg.page_size;
        let offset = page_offset(page_id, page_size, "sealed page read")?;
        let handle = self.open_file_handle(FileKey::Main).await?;
        let mut page = vec![0u8; page_size];
        {
            let mut file = handle.lock().await;
            read_exact_at(&mut *file, offset, &mut page).await?;
        }
        let unverifiable = || {
            PagedbError::corruption(CorruptionDetail::PageUnverifiable {
                realm_id,
                segment_id: None,
                page_id,
                evictable: None,
            })
        };
        let (cipher_id, mk_epoch) = match extract_page_header_ids(&page) {
            Ok(ids) => ids,
            Err(PagedbError::Unsupported) => return Err(unverifiable()),
            Err(error) => return Err(error),
        };
        let kind = binding.resolve_on_disk(&page)?;
        let stamp = read_seal_stamp(&page)?;
        let aad = Aad::from_fields(AadFields {
            cipher_id: cipher_id.as_byte(),
            page_kind: kind.as_byte(),
            mk_epoch,
            page_id,
            realm_id,
            segment_id: MAIN_DB_SEGMENT_ID,
        });
        let opened = {
            let mk = self.mk_for(mk_epoch, cipher_id)?;
            let mut lru = self.dek_lru.lock();
            let cipher = lru.get_or_derive(
                realm_id,
                self.file_identity(FileKey::Main),
                mk_epoch,
                cipher_id,
                &mk,
            )?;
            open_data_page(&mut page, &aad, cipher)
        };
        match opened {
            Ok(_) => Ok(SealedRead { page, kind, stamp }),
            Err(PagedbError::ChecksumFailure) => Err(unverifiable()),
            Err(error) => Err(error),
        }
    }
}
