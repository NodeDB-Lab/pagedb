//! Purpose-specific CSPRNG helpers for nonce-space partitioning identities.

use crate::Result;

fn random_bytes() -> Result<[u8; 16]> {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes)?;
    Ok(bytes)
}

fn random_nonzero_identity() -> Result<[u8; 16]> {
    loop {
        let bytes = random_bytes()?;
        if bytes != [0u8; 16] {
            return Ok(bytes);
        }
    }
}

pub(crate) fn database_identity() -> Result<([u8; 16], [u8; 16])> {
    Ok((random_nonzero_identity()?, random_bytes()?))
}

pub(crate) fn segment_id() -> Result<[u8; 16]> {
    random_nonzero_identity()
}

/// Identity partitioning the spill nonce space of one open handle.
///
/// The per-transaction spill key is derived from the durable `file_id` and the
/// transaction sequence, and the spill nonce is built from that same sequence.
/// The sequence restarts at 1 on every open, so without a per-open component
/// two handles over the same store would encrypt different scratch payloads
/// under one key at one nonce. Mixing this in makes the key distinct per open,
/// which is what leaves the sequence free to serve as the nonce.
pub(crate) fn spill_epoch() -> Result<[u8; 16]> {
    random_nonzero_identity()
}

// Sole caller is `txn::db::snapshot::apply_incremental`, which is native-only
// (`#![cfg(not(target_arch = "wasm32"))]`); gate the function the same way.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn journal_id() -> Result<[u8; 16]> {
    random_nonzero_identity()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn purpose_specific_identities_reserve_zero() {
        assert_ne!(database_identity().unwrap().0, [0u8; 16]);
        assert_ne!(segment_id().unwrap(), [0u8; 16]);
        assert_ne!(journal_id().unwrap(), [0u8; 16]);
        assert_ne!(spill_epoch().unwrap(), [0u8; 16]);
    }

    #[test]
    fn spill_epochs_do_not_repeat_across_opens() {
        assert_ne!(spill_epoch().unwrap(), spill_epoch().unwrap());
    }
}
