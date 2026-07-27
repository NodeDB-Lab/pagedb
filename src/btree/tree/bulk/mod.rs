//! Bulk load: build a dense tree from ordered records without `CoW` overhead.

pub(crate) mod levels;
pub(crate) mod loader;
