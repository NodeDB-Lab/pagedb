use std::sync::atomic::AtomicBool;

use bytes::Bytes;

/// File-identity discriminator for the cache key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum FileKey {
    Main,
    /// Apply-journal sidecar at `applyjournal/<hex(id)>`. A receiver-local,
    /// AEAD-authenticated file written before an `apply_incremental` header
    /// swap; it is neither a `main.db` page nor a catalog-tracked segment.
    ApplyJournal([u8; 16]),
}

/// Bytes plus pin count. `bytes` holds the decrypted full-page buffer
/// (envelope header + body slot + tag slot). Body access goes through the
/// helpers in `format::data_page`.
///
/// `bytes` is logically immutable for the page's cache lifetime — set once at
/// insert, never mutated. Mutation happens by replacing the whole `Arc<Page>`
/// in the cache map.
///
/// Held as [`Bytes`] rather than `Vec<u8>` so a reader can hand out a slice of
/// a value without copying it: the slice shares this buffer's refcount and
/// keeps it alive on its own. That the buffer never changes is what makes such
/// a slice a stable snapshot even after the page leaves the cache.
pub struct Page {
    pub bytes: Bytes,
    /// Page kind recorded at write time; used by the Pager flush path to
    /// reconstruct the correct AAD for each dirty page.
    pub kind_byte: u8,
    /// Realm that owns this cached plaintext. `None` marks metadata-less test
    /// pages, which the Pager read path must reject rather than treat as a
    /// cache hit.
    pub realm_id_bytes: Option<[u8; 16]>,
    /// Set once a structural extent check has proven this buffer's slot
    /// directory and records lie in bounds.
    ///
    /// Sound to memoise precisely because `bytes` is immutable for the page's
    /// cache lifetime (see above): a mutation installs a *new* `Arc<Page>`,
    /// which starts out unvalidated. The check is extent-only and depends on
    /// nothing but these bytes, so proving it once proves it for every later
    /// reader of the same buffer.
    pub extents_validated: AtomicBool,
}

impl Page {
    /// Metadata-less page. Every page the Pager inserts carries a realm, so
    /// this exists only for cache-policy tests, which exercise eviction order
    /// without building envelopes.
    #[cfg(test)]
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes: Bytes::from(bytes),
            kind_byte: 0,
            realm_id_bytes: None,
            extents_validated: AtomicBool::new(false),
        }
    }

    /// `bytes` is moved into a [`Bytes`], not copied.
    #[must_use]
    pub fn new_with_meta(bytes: Vec<u8>, kind_byte: u8, realm_id_bytes: [u8; 16]) -> Self {
        Self {
            bytes: Bytes::from(bytes),
            kind_byte,
            realm_id_bytes: Some(realm_id_bytes),
            extents_validated: AtomicBool::new(false),
        }
    }
}
