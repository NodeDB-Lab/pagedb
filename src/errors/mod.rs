//! Typed error spine. All domain errors land in `PagedbError`; sub-errors From-convert in.

mod constructors;
mod corruption;
mod error;
mod eviction;
mod io;
mod quota;

pub use corruption::CorruptionDetail;
pub use error::PagedbError;
pub use eviction::Evictable;
pub use quota::QuotaKind;
