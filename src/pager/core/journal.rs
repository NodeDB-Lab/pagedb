//! Apply-journal sidecar methods: stage, flush, read, and remove.

use super::guard::PageGuard;
use super::pager::Pager;
use super::read::KindBinding;
#[cfg(test)]
use crate::errors::PagedbError;
use crate::pager::cache::FileKey;
use crate::pager::format::page_kind::PageKind;
use crate::vfs::Vfs;
use crate::{RealmId, Result};

impl<V: Vfs> Pager<V> {
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

    /// Drop a sidecar's cached pages, dirty ones included, and its nonce generator
    /// and cached handle. The file stays on disk, and no header names it.
    ///
    /// A cancelled apply calls this from a drop, so it cannot wait for the handle
    /// lock. A held lock leaves the cached handle for the next reopen. A cache
    /// fault stays latched, and every later operation on the cache reports it.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn discard_unflushed_journal(&self, journal_id: [u8; 16]) {
        let key = FileKey::ApplyJournal(journal_id);
        {
            let mut cache = self.inner.cache_for_key(key).lock();
            cache.discard_dirty(key);
            let _ = cache.clear_file(key);
        }
        self.journal_nonces.lock().remove(&journal_id);
        if let Ok(mut files) = self.files.try_lock() {
            files.remove(&key);
        }
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
}
