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

/// The nonce prefix a Follower handle seals its own `main.db` pages under.
///
/// A follower holds its source's key and `file_id`, and its counter runs apart
/// from the source's. A draw equal to `file_id[0..6]` is refused, so a local page
/// never takes the prefix the source seals under. Two followers can still draw
/// one prefix. That match is improbable at 2^-48 per pair of opens, not impossible.
pub(crate) fn local_nonce_prefix(file_id: &[u8; 16]) -> Result<[u8; 6]> {
    prefix_other_than(file_id, random_bytes)
}

fn prefix_other_than(
    file_id: &[u8; 16],
    mut draw: impl FnMut() -> Result<[u8; 16]>,
) -> Result<[u8; 6]> {
    loop {
        let bytes = draw()?;
        let mut prefix = [0u8; 6];
        prefix.copy_from_slice(&bytes[..6]);
        if prefix[..] != file_id[..6] {
            return Ok(prefix);
        }
    }
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

    #[test]
    fn a_local_prefix_draw_equal_to_the_file_prefix_is_refused() {
        let mut draws = [[0xAB; 16], [0xAB; 16], [0xCD; 16]].into_iter();
        let prefix = prefix_other_than(&[0xAB; 16], || Ok(draws.next().unwrap())).unwrap();
        assert_eq!(prefix, [0xCD; 6]);
    }

    #[test]
    fn a_local_prefix_differs_from_the_file_prefix() {
        let file_id = [0x3C; 16];
        assert_ne!(local_nonce_prefix(&file_id).unwrap()[..], file_id[..6]);
    }
}
