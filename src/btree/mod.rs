//! `CoW` B+ tree (Layer 3a): sorted `bytes→bytes` table over the Pager.

pub(crate) mod internal;
pub(crate) mod leaf;
pub(crate) mod node;
pub(crate) mod overflow;
pub(crate) mod scan;
pub(crate) mod split;
#[cfg(test)]
mod tests;
pub(crate) mod tree;

// `pub` here is crate-scoped in effect: the `btree` module itself is
// `pub(crate)`, so this does not escape the crate.
pub use tree::BTree;
