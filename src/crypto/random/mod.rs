//! Cryptographically secure generation of persistent identities and salts.

mod identity;

#[cfg(not(target_arch = "wasm32"))]
pub(crate) use identity::journal_id;
pub(crate) use identity::{database_identity, local_nonce_prefix, segment_id, spill_epoch};
