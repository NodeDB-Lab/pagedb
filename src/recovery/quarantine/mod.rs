//! Preserving a store that failed to authenticate, instead of discarding it.

pub(crate) mod preserve;

pub use preserve::{QuarantineReport, quarantine_store};
