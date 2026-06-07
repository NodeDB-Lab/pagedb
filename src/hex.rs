//! Lowercase hex encoding/decoding for fixed-size identifiers (segment ids,
//! file ids, KEK material). Shared by the pager, recovery, snapshot, segment,
//! and `pagedb-fsck` code paths so the encoding stays byte-identical everywhere.

/// Encode bytes as a lowercase hex string (two chars per byte).
#[must_use]
pub fn to_hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// Decode a single hex digit (upper- or lowercase) into its nibble value.
#[must_use]
pub fn hex_digit(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Decode a hex string of exactly `2 * N` characters into an `N`-byte array.
/// Returns `None` if the length is wrong or any character is not a hex digit.
#[must_use]
pub fn parse_hex<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != N * 2 {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = [0u8; N];
    for (i, byte) in out.iter_mut().enumerate() {
        let high = hex_digit(bytes[i * 2])?;
        let low = hex_digit(bytes[i * 2 + 1])?;
        *byte = (high << 4) | low;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_16() {
        let id = [
            0x00, 0x12, 0xab, 0xff, 0x9c, 0x3d, 0x40, 0x55, 1, 2, 3, 4, 5, 6, 7, 8,
        ];
        let s = to_hex_lower(&id);
        assert_eq!(s.len(), 32);
        assert_eq!(parse_hex::<16>(&s), Some(id));
    }

    #[test]
    fn parse_accepts_uppercase() {
        assert_eq!(parse_hex::<2>("AbCd"), Some([0xab, 0xcd]));
    }

    #[test]
    fn parse_rejects_wrong_length_and_nonhex() {
        assert_eq!(parse_hex::<2>("abc"), None);
        assert_eq!(parse_hex::<2>("abcg"), None);
    }
}
