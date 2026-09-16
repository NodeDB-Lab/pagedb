//! Zeroizing key types. KEK, MK, and derived 256-bit symmetric keys all use
//! a single shared inner representation; the wrapper type signals intent.
//!
//! # Formatting
//!
//! Every type here formats as a redacted placeholder and the byte array is
//! private, so there is no safe-looking way to spell a key into a log line.
//!
//! Both halves are load bearing. `Zeroizing<T>` derives `Debug` and forwards to
//! the inner `T`, so a `pub(crate)` field was enough for
//! `format!("{key.0:?}")` to print all 32 bytes — a wrapper's own `Debug` does
//! not help if callers can reach past it. Keeping the field private removes
//! that spelling; the manual `Debug` implementations make the ordinary
//! `{key:?}` spelling inert rather than a compile error someone works around.

use std::fmt;

use zeroize::Zeroizing;

/// Formats a key as a redacted placeholder, never as bytes.
macro_rules! redacted_debug {
    ($type:ty) => {
        impl fmt::Debug for $type {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($type), "(<redacted>)"))
            }
        }
    };
}

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

redacted_debug!(SecretKey);

/// 256-bit master key derived from the embedder-supplied KEK and the per-DB
/// `kek_salt` / `mk_epoch`. Held in memory only; zeroized on drop.
pub struct MasterKey(Zeroizing<[u8; 32]>);

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

redacted_debug!(MasterKey);

/// 256-bit derived key: realm DEK (AEAD modes), Integrity Key (plaintext+MAC),
/// or Header Key. Zeroized on drop.
pub struct DerivedKey(Zeroizing<[u8; 32]>);

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

redacted_debug!(DerivedKey);

#[cfg(test)]
mod tests {
    use super::*;

    /// Every byte is distinct, so a leak in any position is caught rather than
    /// only a leak of the first byte.
    fn distinctive_bytes() -> [u8; 32] {
        #[allow(clippy::cast_possible_truncation)]
        std::array::from_fn(|index| (index as u8).wrapping_mul(7).wrapping_add(3)) // index < 32
    }

    /// A key must not spell its bytes when formatted.
    ///
    /// Check every byte in both the decimal form an array's `Debug` uses and
    /// the hexadecimal form a hand-written formatter might use.
    fn assert_redacted(rendered: &str, label: &str) {
        let bytes = distinctive_bytes();
        assert!(
            rendered.contains("<redacted>"),
            "{label} must render a redaction marker, got {rendered:?}"
        );
        for (index, byte) in bytes.iter().enumerate() {
            let decimal = byte.to_string();
            let hex = format!("{byte:02x}");
            assert!(
                !rendered.contains(&decimal),
                "{label} leaked byte {index} ({byte}) in decimal: {rendered:?}"
            );
            assert!(
                !rendered.contains(&hex),
                "{label} leaked byte {index} ({byte}) in hex: {rendered:?}"
            );
        }
    }

    #[test]
    fn a_secret_key_does_not_format_its_bytes() {
        let key = SecretKey::from(distinctive_bytes());
        assert_redacted(&format!("{key:?}"), "SecretKey");
    }

    #[test]
    fn a_master_key_does_not_format_its_bytes() {
        let key = MasterKey::from_bytes(distinctive_bytes());
        assert_redacted(&format!("{key:?}"), "MasterKey");
    }

    #[test]
    fn a_derived_key_does_not_format_its_bytes() {
        let key = DerivedKey::from_bytes(distinctive_bytes());
        assert_redacted(&format!("{key:?}"), "DerivedKey");
    }

    #[test]
    fn alternate_debug_is_redacted() {
        let key = MasterKey::from_bytes(distinctive_bytes());
        assert_redacted(&format!("{key:#?}"), "MasterKey alternate");
    }

    #[test]
    fn nested_debug_is_redacted() {
        #[derive(Debug)]
        #[allow(dead_code)]
        struct Envelope {
            epoch: u64,
            key: DerivedKey,
        }

        let envelope = Envelope {
            epoch: 7,
            key: DerivedKey::from_bytes(distinctive_bytes()),
        };
        assert_redacted(&format!("{envelope:?}"), "nested DerivedKey");
    }
}
