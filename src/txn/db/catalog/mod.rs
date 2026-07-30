//! Catalog-backed operations: realm-quota persistence, named-counter
//! validation, and commit-history maintenance.

pub(crate) mod counters;
pub(crate) mod history;
pub(crate) mod quotas;
