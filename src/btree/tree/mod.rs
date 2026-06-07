//! `BTree` — the `CoW` shadow-paging B+ tree.

pub mod bulk;
pub mod core;
pub mod flush;
pub mod maintenance;
pub mod navigate;
pub mod read;
pub mod scan;
pub mod write;

pub use core::BTree;
