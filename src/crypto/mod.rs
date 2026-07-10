//! Key hierarchy (KEK → MK → DEK / IK / HK), cipher dispatch, nonce discipline.

pub mod aad;
pub mod cipher;
pub mod kdf;
pub mod key_manager;
pub mod keys;
pub mod nonce;
pub(crate) mod random;

pub use aad::{Aad, AadFields};
pub use cipher::{Cipher, CipherId};
pub use keys::{DerivedKey, MasterKey};
pub use nonce::{MainDbNonceGen, Nonce, SegmentNonceGen};
