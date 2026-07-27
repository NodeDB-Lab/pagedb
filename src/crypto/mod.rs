//! Key hierarchy (KEK → MK → DEK / IK / HK), cipher dispatch, nonce discipline.

pub(crate) mod aad;
pub(crate) mod cipher;
pub(crate) mod kdf;
pub(crate) mod key_manager;
pub(crate) mod keys;
pub(crate) mod nonce;
pub(crate) mod random;

// `pub` here is crate-scoped in effect: the `crypto` module itself is
// `pub(crate)`, so none of these escape the crate.
pub use aad::Aad;
pub use cipher::{Cipher, CipherId};
pub use keys::{DerivedKey, MasterKey, SecretKey};
pub use nonce::Nonce;
