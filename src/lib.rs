//! Encrypted, portable, embedded page store exposing two surfaces: a **B+ tree** for
//! sorted byte-table workloads (ACID transactions, range scans) and a **Segment File API**
//! for engine-owned append-mostly encrypted files (vectors, columnar blocks, FTS postings).

#![deny(unsafe_code)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(
    clippy::module_name_repetitions,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc
)]

pub mod btree;
pub mod catalog;
pub mod compaction;
pub mod crypto;
pub mod errors;
#[doc(hidden)]
pub mod hex;
pub mod observability;
pub mod options;
pub mod pager;
pub mod realm;
pub mod recovery;
pub mod segment;
pub mod snapshot;
pub mod txn;
pub mod vfs;

pub use catalog::codec::{RealmQuotas, SegmentKind, SegmentMeta};
pub use compaction::{CompactBudget, CompactProgress, CompactStats};
pub use crypto::CipherId;
pub use errors::{CorruptionDetail, Evictable, PagedbError, QuotaKind};
pub use observability::DbStats;
pub use options::OpenOptions;
pub use recovery::{DeepWalkReport, run_deep_walk};
pub use segment::{
    ExtentRef, GcStats, MmapView, PageId, SegmentPageKind, SegmentReader, SegmentWriter,
};
pub use snapshot::{ApplyStats, SnapshotStats};
pub use txn::{
    CounterRef, Db, DbMode, ReadTxn, ReaderStallPolicy, ScratchOffset, SpillScope, WriteTxn,
};

/// Opaque cryptographic isolation scope identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RealmId(pub(crate) [u8; 16]);

impl RealmId {
    /// Construct a `RealmId` from raw bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Return the raw bytes of the `RealmId`.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Monotonically increasing commit sequence number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CommitId(pub(crate) u64);

impl CommitId {
    /// Construct a `CommitId` from a raw value.
    #[must_use]
    pub const fn new(v: u64) -> Self {
        Self(v)
    }

    /// Return the raw numeric value of the `CommitId`.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }
}

/// Convenience alias for fallible operations in this crate.
pub type Result<T> = core::result::Result<T, PagedbError>;
