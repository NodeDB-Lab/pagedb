//! Typed error spine. All domain errors land in `PagedbError`; sub-errors From-convert in.

use crate::{CommitId, RealmId};

/// Authoritative error type for every fallible operation in this crate.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum PagedbError {
    #[error("checksum / AEAD tag verification failed")]
    ChecksumFailure,

    #[error("corruption: {0:?}")]
    Corruption(CorruptionDetail),

    #[error("quota exceeded: realm={realm:?} kind={kind:?} used={used} limit={limit}")]
    Quota {
        realm: RealmId,
        kind: QuotaKind,
        used: u64,
        limit: u64,
    },

    #[error("no space (VFS-level exhaustion)")]
    NoSpace,

    #[error("nonce counter exhausted (per-file 2^48 limit reached); rekey required")]
    NonceCounterExhausted,

    #[error("read-only handle")]
    ReadOnly,

    #[error("writer already present")]
    WriterPresent,

    #[error("readers present")]
    ReadersPresent,

    #[error("already open")]
    AlreadyOpen,

    #[error("path lock contention")]
    AlreadyLocked,

    #[error("restored directory not promoted")]
    RestoredNotPromoted,

    #[error("identity forked; apply_incremental refused")]
    IdentityForked,

    #[error("commit {commit:?} gone; oldest_available={oldest_available:?}")]
    CommitGone {
        commit: CommitId,
        oldest_available: CommitId,
    },

    #[error("not found")]
    NotFound,

    #[error("already linked")]
    AlreadyLinked,

    #[error("not linked")]
    NotLinked,

    #[error("name too long")]
    NameTooLong,

    #[error("illegal page kind for segment")]
    IllegalPageKind,

    #[error("payload too large")]
    PayloadTooLarge,

    #[error("manifest too large")]
    ManifestTooLarge,

    #[error(
        "mmap-view quota exceeded: segment_bytes={segment_bytes} available_bytes={available_bytes}"
    )]
    MmapViewQuotaExceeded {
        segment_bytes: u64,
        available_bytes: u64,
    },

    #[error("aborted (reader stall policy)")]
    Aborted,

    /// `WriteTxn::put_append` was called with a key that is not strictly
    /// greater than the previously-appended key. The append-mode API
    /// requires monotonically increasing keys; mixing it with regular
    /// `put`/`delete` invalidates the cached rightmost path and the next
    /// `put_append` call must again start strictly above the maximum key
    /// observed so far in this txn.
    #[error("put_append called with non-monotonic key")]
    AppendNotMonotonic,

    /// The deferred-free backlog exceeds the configured threshold and
    /// active reader pins prevent draining it.
    #[non_exhaustive]
    #[error(
        "deferred-free backlog of {pages_pending} pages blocked by oldest pinning commit {oldest_pinning_commit}"
    )]
    DeferredFreeBacklog {
        pages_pending: u64,
        oldest_pinning_commit: u64,
    },

    #[error("free list exhausted")]
    FreeListExhausted,

    #[error("segment tombstone stalled by reader pin")]
    SegmentTombstoneStalled,

    #[error("readers pinning truncated range")]
    ReadersPinningTruncatedRange,

    #[error("unsupported by backend")]
    Unsupported,

    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// Per-reason detail for [`PagedbError::Corruption`]. Each variant carries exactly the
/// fields the failure-mode contract specifies — no optional fields, no field reuse across
/// reasons.
#[non_exhaustive]
#[derive(Debug)]
pub enum CorruptionDetail {
    /// A segment file authenticates under this DB's HK but its `parent_file_id` belongs
    /// to a different `main.db`. Fail closed; never promote, never silently accept.
    ForeignSegment {
        realm_id: RealmId,
        name: String,
        segment_id: [u8; 16],
        footer_parent_file_id: [u8; 16],
        expected_parent_file_id: [u8; 16],
    },
    /// Footer HK-MAC failed; segment identity is unverifiable.
    FooterUnverifiable {
        realm_id: RealmId,
        name: String,
        segment_id: [u8; 16],
    },
    /// Catalog references a segment whose file is absent from both `seg/` and `seg/.staging/`.
    SegmentMissing {
        realm_id: RealmId,
        name: String,
        segment_id: [u8; 16],
    },
    /// Pre-link staging file expected but not present.
    StagingMissing {
        realm_id: RealmId,
        name: String,
        segment_id: [u8; 16],
    },
    /// Per-page AEAD tag verification failed during a read.
    PageUnverifiable {
        realm_id: RealmId,
        segment_id: Option<[u8; 16]>,
        page_id: u64,
        evictable: Option<Evictable>,
    },
    /// Footer manifest AEAD tag verification failed.
    ManifestUnverifiable {
        realm_id: RealmId,
        segment_id: [u8; 16],
    },
    /// main.db A/B header HK-MAC failed on both copies.
    HeaderUnverifiable,
}

/// Quota failure reason, distinguishing which resource was exhausted.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotaKind {
    Pages,
    DirtyPages,
    ScratchPages,
    SegmentBytes,
}

/// Whether a segment is authoritative or replaceable under quota pressure.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Evictable {
    Authoritative,
    Replaceable,
}

impl PagedbError {
    /// Canonical constructor for corruption errors. Call sites never write
    /// `PagedbError::Corruption { … }` directly.
    #[must_use]
    pub fn corruption(detail: CorruptionDetail) -> Self {
        Self::Corruption(detail)
    }

    /// Canonical constructor for deferred-free backlog errors.
    #[must_use]
    pub fn deferred_free_backlog(pages_pending: u64, oldest_pinning_commit: u64) -> Self {
        Self::DeferredFreeBacklog {
            pages_pending,
            oldest_pinning_commit,
        }
    }

    /// Canonical constructor for quota errors.
    #[must_use]
    pub fn quota(realm: RealmId, kind: QuotaKind, used: u64, limit: u64) -> Self {
        Self::Quota {
            realm,
            kind,
            used,
            limit,
        }
    }
}
