//! `PageGuard`: RAII handle to a pinned cache entry.

use std::sync::Arc;

use bytes::Bytes;

use super::inner::PagerInner;
use crate::pager::cache::{FileKey, Page};
use crate::pager::format::data_page::{HEADER_LEN, body};

/// RAII handle to a pinned cache entry. Holds a clone of the `Arc<Page>` and
/// the cache lock long enough to unpin on drop. Borrow `body()` to access the
/// decrypted plaintext bytes.
pub struct PageGuard {
    pub(super) page: Arc<Page>,
    pub(super) key: (FileKey, u64),
    /// Slab index of the pinned entry, so releasing it on drop costs an
    /// indexed load rather than another hash of `key`. `key` still identifies
    /// the entry the pin was taken on; the cache verifies the two agree.
    /// `None` marks a page returned without caching, which holds no pin.
    pub(super) slot: Option<usize>,
    pub(super) inner: Arc<PagerInner>,
}

impl PageGuard {
    /// Decrypted body bytes (slot directory + payload area of the page,
    /// `page_size - 40` bytes) as an owned handle that outlives the guard.
    ///
    /// Shares the page's buffer rather than copying it, on the same terms as
    /// [`body_slice`](Self::body_slice). Prefer [`body_ref`](Self::body_ref)
    /// where a borrow will do.
    #[must_use]
    pub fn body(&self) -> Bytes {
        // Extent comes from the same helper `body_ref` uses, so the two cannot
        // disagree about where the body ends.
        let len = body(&self.page.bytes).len();
        self.page.bytes.slice(HEADER_LEN..HEADER_LEN + len)
    }

    /// Zero-copy borrow of the decrypted body. Valid for the lifetime of the
    /// guard; the underlying cache entry stays pinned for that lifetime.
    #[must_use]
    pub fn body_ref(&self) -> &[u8] {
        body(&self.page.bytes)
    }

    /// Slice `range` of the body as an owned [`Bytes`] sharing this page's
    /// buffer — a refcount bump, not a copy.
    ///
    /// The returned handle keeps the buffer alive by itself, so it stays valid
    /// after the guard drops and after the page leaves the cache. The bytes it
    /// sees never change: a write installs a new page rather than mutating this
    /// one, which makes the slice a snapshot of the version that was read.
    ///
    /// It does pin the whole page for as long as it lives. A caller keeping a
    /// small value from each of many pages should copy it out instead.
    #[must_use]
    pub fn body_slice(&self, range: std::ops::Range<usize>) -> Bytes {
        let start = HEADER_LEN + range.start;
        let end = HEADER_LEN + range.end;
        self.page.bytes.slice(start..end)
    }

    /// Per-page memo for the structural extent check run by decoders over
    /// [`body_ref`](Self::body_ref). Scoped to the pinned cache entry, so it is
    /// discarded whenever the page is replaced or evicted.
    #[must_use]
    pub fn extents_validated(&self) -> &std::sync::atomic::AtomicBool {
        &self.page.extents_validated
    }
}

impl Drop for PageGuard {
    fn drop(&mut self) {
        if let Some(slot) = self.slot {
            let mut cache = self.inner.cache_for_key(self.key.0).lock();
            cache.unpin_at(slot, self.key);
        }
    }
}
