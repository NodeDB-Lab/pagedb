//! Restore-mode byte values stored in the `main.db` A/B header.

/// An original store, or one `rekey_into_writer` gave a fresh identity.
pub(crate) const STANDALONE: u8 = 0;
/// A restored directory promoted to track its source through
/// `apply_incremental`, or a byte copy that took an apply.
pub(crate) const FOLLOWER: u8 = 1;
/// A snapshot or a restored directory not yet promoted.
pub(crate) const READ_ONLY: u8 = 2;
