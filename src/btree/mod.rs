//! `CoW` B+ tree (Layer 3a): sorted `bytes→bytes` table over the Pager.

pub mod internal;
pub mod leaf;
pub mod node;
pub mod overflow;
pub mod scan;
pub mod split;
pub mod tree;

pub use tree::BTree;
