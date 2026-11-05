//! What a deep walk reports about retained commit-history rows.

use crate::CommitId;

/// Why a store's page seals prove no order.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealOrderVoid {
    /// The store's epoch is above zero. A rekey reseals retained pages in walk
    /// order, so counters no longer follow commit order.
    RekeyedEpoch,
    /// A walked page carries another epoch, cipher, or file identity.
    MixedPageSeals,
    /// The store uses `PlaintextMac`. That tag does not cover the nonce.
    UnauthenticatedNonce,
    /// An observer handle reads beside a live writer, so its walk is not a
    /// consistent view of the file.
    ObserverHandle,
    /// The live root cannot authenticate, so no row has a bound from it.
    UnreadableLiveRoot,
    /// An I/O error stopped the scan. The report lists it under page issues.
    ScanInterrupted,
}

/// The outcome of comparing retained rows against their page seals.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HistorySealVerdict {
    /// The store holds no rows this handle keeps.
    #[default]
    NoRows,
    /// Every row was compared. An undetected page is still possible. See
    /// `CHANGELOG.md` for the limits.
    Compared,
    /// The store cannot show seal order, so the scan reports nothing further.
    Inconclusive(SealOrderVoid),
}

/// Why one retained row reads wrong bytes or none.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StaleRowEvidence {
    /// A page the row reaches was sealed at or after a root of a later commit.
    /// Every page of an intact row was sealed before that root.
    SealedAfterLaterRoot {
        page_id: u64,
        page_counter: u64,
        later_root_page_id: u64,
        later_root_counter: u64,
    },
    /// A page the row reaches cannot authenticate as its role.
    UnreadablePages { description: String },
}

/// A retained row a deep walk found stale. `begin_read_at` on this commit can
/// return wrong bytes with no error, or fail. The walk changes nothing.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaleHistoryRow {
    pub commit: CommitId,
    pub evidence: StaleRowEvidence,
}
