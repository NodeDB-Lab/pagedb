//! Pager core. Owns VFS file handles, the two cache classes, the DEK LRU,
//! and the nonce generators. Exposes read/write/flush primitives to the B+
//! tree and segment managers.

mod config;
mod flush;
mod guard;
mod handles;
mod header_binding;
mod inner;
mod journal;
mod pager;
mod read;
#[cfg(test)]
#[allow(clippy::too_many_lines)]
mod tests;
mod write;

pub use crate::pager::cache::FileKey;
pub use config::PagerConfig;
pub use guard::PageGuard;
pub use pager::Pager;
