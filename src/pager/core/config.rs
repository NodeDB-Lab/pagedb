//! Static configuration for a `Pager`.

use crate::crypto::CipherId;
#[cfg(test)]
use crate::crypto::nonce::DEFAULT_ANCHOR_BUDGET;

/// Static configuration for a Pager instance.
#[derive(Debug, Clone)]
pub struct PagerConfig {
    pub page_size: usize,
    pub buffer_pool_pages: usize,
    pub segment_cache_pages: usize,
    pub cipher_id: CipherId,
    pub mk_epoch: u64,
    pub main_db_file_id: [u8; 16],
    pub main_db_path: String,
    pub anchor_budget: u64,
    pub dek_lru_capacity: usize,
    /// Number of AEAD-verification retries on a cache miss before surfacing
    /// a `PageUnverifiable`. Set to > 0 only in `Observer` mode to absorb torn
    /// reads; all other modes keep this at 0 so that AEAD failures remain
    /// hard corruption signals.
    pub observer_retry_count: u32,
    /// When `false`, buffer-pool hit/miss counters are not bumped on each
    /// page read. Default in `with_defaults`: `true`.
    pub metrics_enabled: bool,
}

impl PagerConfig {
    /// Every production open site builds a `PagerConfig` field by field from
    /// `OpenOptions`, so the defaulted constructor survives only for tests that
    /// need a working pager without an `OpenOptions` in hand.
    #[cfg(test)]
    pub fn with_defaults(
        page_size: usize,
        cipher_id: CipherId,
        mk_epoch: u64,
        main_db_file_id: [u8; 16],
        main_db_path: impl Into<String>,
    ) -> Self {
        Self {
            page_size,
            buffer_pool_pages: 1024,
            segment_cache_pages: 1024,
            cipher_id,
            mk_epoch,
            main_db_file_id,
            main_db_path: main_db_path.into(),
            anchor_budget: DEFAULT_ANCHOR_BUDGET,
            dek_lru_capacity: 256,
            observer_retry_count: 0,
            metrics_enabled: true,
        }
    }
}
