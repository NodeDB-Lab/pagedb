mod dirty;
mod eviction;
mod fault;
mod lookup;
mod page;
mod page_cache;
mod reclaim;
#[cfg(test)]
mod tests;

pub(crate) use fault::CacheFault;
pub use page::{FileKey, Page};
pub use page_cache::PageCache;
