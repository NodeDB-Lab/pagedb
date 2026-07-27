//! Pager: cache, page envelopes, header IO, AEAD dispatch.

pub(crate) mod cache;
pub(crate) mod core;
pub(crate) mod format;
pub(crate) mod freelist;
pub(crate) mod header;
pub(crate) mod page_space;
#[cfg(test)]
mod tests;

// `pub` here is crate-scoped in effect: the `pager` module itself is
// `pub(crate)`, so none of these escape the crate.
pub use core::{PageGuard, Pager, PagerConfig};
// The format submodules are `pub(crate)`, so re-exporting the modules
// themselves has to match — a `pub use` of a crate-public module is rejected
// even from inside a `pub(crate)` parent.
pub use format::page_kind::PageKind;
pub(crate) use format::structural_header;
