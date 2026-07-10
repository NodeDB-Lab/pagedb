//! Zeroizing key types. KEK, MK, and derived 256-bit symmetric keys all use
//! a single shared inner representation; the wrapper type signals intent.

use zeroize::Zeroizing;

/// 256-bit key-encryption key supplied by the embedder.
///
/// The bytes are zeroized on drop and intentionally never exposed outside this
/// crate. Construct it from a `[u8; 32]` at an API boundary.
pub struct SecretKey(Zeroizing<[u8; 32]>);

impl SecretKey {
    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<[u8; 32]> for SecretKey {
    fn from(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }
}

/// 256-bit master key derived from the embedder-supplied KEK and the per-DB
/// `kek_salt` / `mk_epoch`. Held in memory only; zeroized on drop.
pub struct MasterKey(pub(crate) Zeroizing<[u8; 32]>);

impl MasterKey {
    pub(crate) fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }
    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Clone for MasterKey {
    fn clone(&self) -> Self {
        Self(Zeroizing::new(*self.0))
    }
}

/// 256-bit derived key: realm DEK (AEAD modes), Integrity Key (plaintext+MAC),
/// or Header Key. Zeroized on drop.
pub struct DerivedKey(pub(crate) Zeroizing<[u8; 32]>);

impl DerivedKey {
    pub(crate) fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }
    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Clone for DerivedKey {
    fn clone(&self) -> Self {
        Self(Zeroizing::new(*self.0))
    }
}
