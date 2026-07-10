//! Cryptographically secure generation of persistent identities and salts.

mod identity;

pub(crate) use identity::{database_identity, journal_id, segment_id};
