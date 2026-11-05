//! Write path: stage dirty pages in the cache and rewrite pages under the active epoch.

use std::sync::Arc;

use super::pager::Pager;
use crate::errors::PagedbError;
use crate::pager::cache::{FileKey, Page};
use crate::pager::format::data_page::{ENVELOPE_OVERHEAD, HEADER_LEN};
use crate::pager::format::page_kind::PageKind;
use crate::vfs::Vfs;
use crate::{RealmId, Result};

impl<V: Vfs> Pager<V> {
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

    pub(super) fn write_page(
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
}
