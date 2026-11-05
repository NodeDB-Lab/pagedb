//! Restore mode: the handle modes a directory admits, kept in the `main.db`
//! A/B header.
//!
//! `restore_from` copies `main.db` byte for byte. A restored directory
//! shares its source's DEK and nonce space. Independent writes on both
//! directories repeat nonces under one key. A Standalone open refuses every
//! restore mode except `STANDALONE`. Transitions only move forward:
//!
//! | From | To | Operation |
//! |---|---|---|
//! | `READ_ONLY` | `FOLLOWER` | `promote_to_follower` |
//! | `STANDALONE` | `FOLLOWER` | The first `apply_incremental`, which only a byte copy reaches |
//! | `READ_ONLY` or `FOLLOWER` | `STANDALONE` | `rekey_into_writer`, under a fresh identity |
//!
//! A copy that took an apply under an older release holds no stamp, and this
//! byte cannot show it.

#[cfg(not(target_arch = "wasm32"))]
mod stamp;
mod values;

#[cfg(not(target_arch = "wasm32"))]
pub(in crate::txn::db) use stamp::{HeaderKey, stamp_read_only};
pub(crate) use values::{FOLLOWER, READ_ONLY, STANDALONE};
