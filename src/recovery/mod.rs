//! Open-flow recovery: apply-journal replay, catalog reconciliation,
//! tombstone GC, spill-scratch reclamation.

pub(crate) mod deep_walk;
pub(crate) mod gc;
pub(crate) mod journal;
pub(crate) mod provenance;
pub(crate) mod quarantine;
pub(crate) mod reconcile;
pub(crate) mod scratch;
#[cfg(test)]
mod tests;

pub use deep_walk::{DeepWalkReport, DriftIssue, PageIssue, SegmentIssue, run_deep_walk};
// `pub` here is crate-scoped in effect: the `recovery` module itself is
// `pub(crate)`, so these do not escape the crate. The deep-walk items above are
// re-exported from the crate root and are the only public part of recovery.
pub use reconcile::{repair_catalog, verify_catalog};
