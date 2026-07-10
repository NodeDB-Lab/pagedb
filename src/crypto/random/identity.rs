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
    }
}
