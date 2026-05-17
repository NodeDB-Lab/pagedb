//! Format B — cleartext-with-HK-MAC structural headers for main.db A/B
//! header pages and segment header page 0.

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::crypto::keys::DerivedKey;
use crate::errors::PagedbError;
use crate::{CommitId, RealmId, Result};

pub const MAGIC_MAIN: [u8; 8] = *b"PAGEDB\0\0";
pub const MAGIC_SEGMENT: [u8; 8] = *b"PAGESEG\0";

pub const MAIN_FIELDS_END: usize = 185;
pub const SEGMENT_FIELDS_END: usize = 76;
pub const MAC_LEN: usize = 16;

type HmacSha256 = Hmac<Sha256>;

/// All fields of a main.db A/B header. Matches the on-wire layout one-to-one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MainDbHeaderFields {
    pub format_version: u16,
    pub cipher_id: u8,
    pub page_size_log2: u8,
    pub flags: u32,
    pub file_id: [u8; 16],
    pub kek_salt: [u8; 16],
    pub mk_epoch: u64,
    pub seq: u64,
    pub active_root_page_id: u64,
    pub active_root_txn_id: u64,
    pub counter_anchor: u64,
    pub commit_id: CommitId,
    pub free_list_root: [u8; 16],
    pub catalog_root: [u8; 16],
    pub apply_journal_root_page_id: u64,
    pub apply_journal_root_version: u64,
    pub commit_history_root_page_id: u64,
    pub commit_history_root_version: u64,
    pub restore_mode: u8,
    pub next_page_id: u64,
    /// Retention policy tag: 0 = Count, 1 = Age (seconds), 2 = Unbounded.
    pub commit_retain_policy_tag: u8,
    /// Policy value: for Count, the count; for Age, the duration in seconds;
    /// for Unbounded, 0.
    pub commit_retain_policy_value: u64,
}

/// All fields of a segment header page 0.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentHeaderFields {
    pub format_version: u16,
    pub cipher_id: u8,
    pub segment_kind: u8,
    pub segment_id: [u8; 16],
    pub parent_file_id: [u8; 16],
    pub realm_id: RealmId,
    pub mk_epoch: u64,
    pub page_size_log2: u8,
    pub flags: u8,
}

fn validate_page_size_log2(log2: u8) -> Result<usize> {
    match log2 {
        12..=16 => Ok(1usize << log2),
        _ => Err(PagedbError::Unsupported),
    }
}

fn mac_hk(hk: &DerivedKey, bytes: &[u8]) -> Result<[u8; MAC_LEN]> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(hk.as_bytes())
        .map_err(|_| PagedbError::Io(std::io::Error::other("hk key length")))?;
    mac.update(bytes);
    let full = mac.finalize().into_bytes();
    let mut out = [0u8; MAC_LEN];
    out.copy_from_slice(&full[..MAC_LEN]);
    Ok(out)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc: u8 = 0;
    for (x, y) in a.iter().zip(b) {
        acc |= x ^ y;
    }
    acc == 0
}

/// Encode a main.db A/B header into a `page_size`-byte buffer.
pub fn encode_main_db_header(
    fields: &MainDbHeaderFields,
    hk: &DerivedKey,
    page_size: usize,
) -> Result<Vec<u8>> {
    if validate_page_size_log2(fields.page_size_log2)? != page_size {
        return Err(PagedbError::Unsupported);
    }
    if page_size < MAIN_FIELDS_END + MAC_LEN {
        return Err(PagedbError::Unsupported);
    }
    let mut buf = vec![0u8; page_size];
    let mut o = 0;
    buf[o..o + 8].copy_from_slice(&MAGIC_MAIN);
    o += 8;
    buf[o..o + 2].copy_from_slice(&fields.format_version.to_le_bytes());
    o += 2;
    buf[o] = fields.cipher_id;
    o += 1;
    buf[o] = fields.page_size_log2;
    o += 1;
    buf[o..o + 4].copy_from_slice(&fields.flags.to_le_bytes());
    o += 4;
    buf[o..o + 16].copy_from_slice(&fields.file_id);
    o += 16;
    buf[o..o + 16].copy_from_slice(&fields.kek_salt);
    o += 16;
    buf[o..o + 8].copy_from_slice(&fields.mk_epoch.to_le_bytes());
    o += 8;
    buf[o..o + 8].copy_from_slice(&fields.seq.to_le_bytes());
    o += 8;
    buf[o..o + 8].copy_from_slice(&fields.active_root_page_id.to_le_bytes());
    o += 8;
    buf[o..o + 8].copy_from_slice(&fields.active_root_txn_id.to_le_bytes());
    o += 8;
    buf[o..o + 8].copy_from_slice(&fields.counter_anchor.to_le_bytes());
    o += 8;
    buf[o..o + 8].copy_from_slice(&fields.commit_id.0.to_le_bytes());
    o += 8;
    buf[o..o + 16].copy_from_slice(&fields.free_list_root);
    o += 16;
    buf[o..o + 16].copy_from_slice(&fields.catalog_root);
    o += 16;
    buf[o..o + 8].copy_from_slice(&fields.apply_journal_root_page_id.to_le_bytes());
    o += 8;
    buf[o..o + 8].copy_from_slice(&fields.apply_journal_root_version.to_le_bytes());
    o += 8;
    buf[o..o + 8].copy_from_slice(&fields.commit_history_root_page_id.to_le_bytes());
    o += 8;
    buf[o..o + 8].copy_from_slice(&fields.commit_history_root_version.to_le_bytes());
    o += 8;
    buf[o] = fields.restore_mode;
    o += 1;
    debug_assert_eq!(o, 161);
    // Bytes 161..168 are the explicit _reserved 7 bytes; remain zero.
    o += 7;
    debug_assert_eq!(o, 168);
    buf[o..o + 8].copy_from_slice(&fields.next_page_id.to_le_bytes());
    o += 8;
    buf[o] = fields.commit_retain_policy_tag;
    o += 1;
    buf[o..o + 8].copy_from_slice(&fields.commit_retain_policy_value.to_le_bytes());
    // Bytes 185..page_size-MAC_LEN are the unused tail; remain zero.
    // MAC over bytes 0..page_size-MAC_LEN.
    let mac = mac_hk(hk, &buf[..page_size - MAC_LEN])?;
    buf[page_size - MAC_LEN..].copy_from_slice(&mac);
    Ok(buf)
}

/// Decode and verify a main.db A/B header. Returns `Corruption{HeaderUnverifiable}`
/// on MAC failure or non-zero tail.
pub fn decode_main_db_header(
    bytes: &[u8],
    hk: &DerivedKey,
    page_size: usize,
) -> Result<MainDbHeaderFields> {
    if bytes.len() != page_size || page_size < MAIN_FIELDS_END + MAC_LEN {
        return Err(PagedbError::Unsupported);
    }
    if bytes[..8] != MAGIC_MAIN {
        return Err(PagedbError::corruption(
            crate::errors::CorruptionDetail::HeaderUnverifiable,
        ));
    }
    // Bytes 161..168 are reserved and must be zero.
    if !bytes[161..168].iter().all(|b| *b == 0) {
        return Err(PagedbError::corruption(
            crate::errors::CorruptionDetail::HeaderUnverifiable,
        ));
    }
    // Bytes 185..page_size-MAC_LEN are the unused tail and must be zero.
    if !bytes[185..page_size - MAC_LEN].iter().all(|b| *b == 0) {
        return Err(PagedbError::corruption(
            crate::errors::CorruptionDetail::HeaderUnverifiable,
        ));
    }
    let expected = mac_hk(hk, &bytes[..page_size - MAC_LEN])?;
    if !constant_time_eq(&expected, &bytes[page_size - MAC_LEN..]) {
        return Err(PagedbError::corruption(
            crate::errors::CorruptionDetail::HeaderUnverifiable,
        ));
    }
    let mut o = 8; // past magic
    let format_version = u16_le(&bytes[o..o + 2]);
    o += 2;
    if format_version != 1 {
        return Err(PagedbError::Unsupported);
    }
    let cipher_id = bytes[o];
    o += 1;
    let page_size_log2 = bytes[o];
    o += 1;
    let flags = u32_le(&bytes[o..o + 4]);
    o += 4;
    let file_id = arr16(&bytes[o..o + 16]);
    o += 16;
    let kek_salt = arr16(&bytes[o..o + 16]);
    o += 16;
    let mk_epoch = u64_le(&bytes[o..o + 8]);
    o += 8;
    let seq = u64_le(&bytes[o..o + 8]);
    o += 8;
    let active_root_page_id = u64_le(&bytes[o..o + 8]);
    o += 8;
    let active_root_txn_id = u64_le(&bytes[o..o + 8]);
    o += 8;
    let counter_anchor = u64_le(&bytes[o..o + 8]);
    o += 8;
    let commit_id = CommitId(u64_le(&bytes[o..o + 8]));
    o += 8;
    let free_list_root = arr16(&bytes[o..o + 16]);
    o += 16;
    let catalog_root = arr16(&bytes[o..o + 16]);
    o += 16;
    let apply_journal_root_page_id = u64_le(&bytes[o..o + 8]);
    o += 8;
    let apply_journal_root_version = u64_le(&bytes[o..o + 8]);
    o += 8;
    let commit_history_root_page_id = u64_le(&bytes[o..o + 8]);
    o += 8;
    let commit_history_root_version = u64_le(&bytes[o..o + 8]);
    o += 8;
    let restore_mode = bytes[o];
    o += 1;
    // skip 7 reserved bytes (161..168 already zero-checked)
    o += 7;
    let next_page_id = u64_le(&bytes[o..o + 8]);
    o += 8;
    let commit_retain_policy_tag = bytes[o];
    o += 1;
    let commit_retain_policy_value = u64_le(&bytes[o..o + 8]);
    Ok(MainDbHeaderFields {
        format_version,
        cipher_id,
        page_size_log2,
        flags,
        file_id,
        kek_salt,
        mk_epoch,
        seq,
        active_root_page_id,
        active_root_txn_id,
        counter_anchor,
        commit_id,
        free_list_root,
        catalog_root,
        apply_journal_root_page_id,
        apply_journal_root_version,
        commit_history_root_page_id,
        commit_history_root_version,
        restore_mode,
        next_page_id,
        commit_retain_policy_tag,
        commit_retain_policy_value,
    })
}

/// Encode a segment header page 0 into a `page_size`-byte buffer.
pub fn encode_segment_header(
    fields: &SegmentHeaderFields,
    hk: &DerivedKey,
    page_size: usize,
) -> Result<Vec<u8>> {
    if validate_page_size_log2(fields.page_size_log2)? != page_size {
        return Err(PagedbError::Unsupported);
    }
    if page_size < SEGMENT_FIELDS_END + MAC_LEN {
        return Err(PagedbError::Unsupported);
    }
    let mut buf = vec![0u8; page_size];
    let mut o = 0;
    buf[o..o + 8].copy_from_slice(&MAGIC_SEGMENT);
    o += 8;
    buf[o..o + 2].copy_from_slice(&fields.format_version.to_le_bytes());
    o += 2;
    buf[o] = fields.cipher_id;
    o += 1;
    buf[o] = fields.segment_kind;
    o += 1;
    buf[o..o + 16].copy_from_slice(&fields.segment_id);
    o += 16;
    buf[o..o + 16].copy_from_slice(&fields.parent_file_id);
    o += 16;
    buf[o..o + 16].copy_from_slice(&fields.realm_id.0);
    o += 16;
    buf[o..o + 8].copy_from_slice(&fields.mk_epoch.to_le_bytes());
    o += 8;
    buf[o] = fields.page_size_log2;
    o += 1;
    buf[o] = fields.flags;
    o += 1;
    debug_assert_eq!(o, 70);
    // 6 bytes _reserved zero, then unused tail to page_size - MAC_LEN.
    let mac = mac_hk(hk, &buf[..page_size - MAC_LEN])?;
    buf[page_size - MAC_LEN..].copy_from_slice(&mac);
    Ok(buf)
}

/// Decode and verify a segment header page 0.
pub fn decode_segment_header(
    bytes: &[u8],
    hk: &DerivedKey,
    page_size: usize,
) -> Result<SegmentHeaderFields> {
    if bytes.len() != page_size || page_size < SEGMENT_FIELDS_END + MAC_LEN {
        return Err(PagedbError::Unsupported);
    }
    if bytes[..8] != MAGIC_SEGMENT {
        return Err(PagedbError::corruption(
            crate::errors::CorruptionDetail::HeaderUnverifiable,
        ));
    }
    let tail = &bytes[70..page_size - MAC_LEN];
    if !tail.iter().all(|b| *b == 0) {
        return Err(PagedbError::corruption(
            crate::errors::CorruptionDetail::HeaderUnverifiable,
        ));
    }
    let expected = mac_hk(hk, &bytes[..page_size - MAC_LEN])?;
    if !constant_time_eq(&expected, &bytes[page_size - MAC_LEN..]) {
        return Err(PagedbError::corruption(
            crate::errors::CorruptionDetail::HeaderUnverifiable,
        ));
    }
    let mut o = 8;
    let format_version = u16_le(&bytes[o..o + 2]);
    o += 2;
    if format_version != 1 {
        return Err(PagedbError::Unsupported);
    }
    let cipher_id = bytes[o];
    o += 1;
    let segment_kind = bytes[o];
    o += 1;
    let segment_id = arr16(&bytes[o..o + 16]);
    o += 16;
    let parent_file_id = arr16(&bytes[o..o + 16]);
    o += 16;
    let realm_id_bytes = arr16(&bytes[o..o + 16]);
    o += 16;
    let mk_epoch = u64_le(&bytes[o..o + 8]);
    o += 8;
    let page_size_log2 = bytes[o];
    o += 1;
    let flags = bytes[o];
    Ok(SegmentHeaderFields {
        format_version,
        cipher_id,
        segment_kind,
        segment_id,
        parent_file_id,
        realm_id: RealmId(realm_id_bytes),
        mk_epoch,
        page_size_log2,
        flags,
    })
}

fn u16_le(b: &[u8]) -> u16 {
    let mut x = [0u8; 2];
    x.copy_from_slice(b);
    u16::from_le_bytes(x)
}
fn u32_le(b: &[u8]) -> u32 {
    let mut x = [0u8; 4];
    x.copy_from_slice(b);
    u32::from_le_bytes(x)
}
fn u64_le(b: &[u8]) -> u64 {
    let mut x = [0u8; 8];
    x.copy_from_slice(b);
    u64::from_le_bytes(x)
}
fn arr16(b: &[u8]) -> [u8; 16] {
    let mut x = [0u8; 16];
    x.copy_from_slice(b);
    x
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::crypto::kdf::{derive_hk, derive_mk};

    fn hk() -> DerivedKey {
        let mk = derive_mk(&[5u8; 32], &[0u8; 16], 0).unwrap();
        derive_hk(&mk).unwrap()
    }

    fn sample_main() -> MainDbHeaderFields {
        MainDbHeaderFields {
            format_version: 1,
            cipher_id: 1,
            page_size_log2: 12,
            flags: 0,
            file_id: [1; 16],
            kek_salt: [2; 16],
            mk_epoch: 0,
            seq: 7,
            active_root_page_id: 4,
            active_root_txn_id: 8,
            counter_anchor: 100,
            commit_id: CommitId(12),
            free_list_root: [3; 16],
            catalog_root: [4; 16],
            apply_journal_root_page_id: 0,
            apply_journal_root_version: 0,
            commit_history_root_page_id: 0,
            commit_history_root_version: 0,
            restore_mode: 0,
            next_page_id: 4,
            commit_retain_policy_tag: 0,
            commit_retain_policy_value: 1024,
        }
    }

    fn sample_segment() -> SegmentHeaderFields {
        SegmentHeaderFields {
            format_version: 1,
            cipher_id: 1,
            segment_kind: 0,
            segment_id: [9; 16],
            parent_file_id: [1; 16],
            realm_id: RealmId([3; 16]),
            mk_epoch: 0,
            page_size_log2: 12,
            flags: 0,
        }
    }

    #[test]
    fn main_round_trip_all_page_sizes() {
        let hk = hk();
        for log2 in [12u8, 13, 14, 15, 16] {
            let page_size = 1usize << log2;
            let mut f = sample_main();
            f.page_size_log2 = log2;
            let buf = encode_main_db_header(&f, &hk, page_size).unwrap();
            assert_eq!(buf.len(), page_size);
            let decoded = decode_main_db_header(&buf, &hk, page_size).unwrap();
            assert_eq!(decoded, f);
        }
    }

    #[test]
    fn main_mac_tamper_rejected() {
        let hk = hk();
        let f = sample_main();
        let mut buf = encode_main_db_header(&f, &hk, 4096).unwrap();
        let last = buf.len() - 1;
        buf[last] ^= 1;
        let err = decode_main_db_header(&buf, &hk, 4096).unwrap_err();
        assert!(matches!(err, PagedbError::Corruption(_)));
    }

    #[test]
    fn main_nonzero_tail_rejected() {
        let hk = hk();
        let f = sample_main();
        let mut buf = encode_main_db_header(&f, &hk, 4096).unwrap();
        // Pick a byte in the unused tail (after _reserved field at 161, before MAC at 4080).
        buf[300] = 0xAB;
        let err = decode_main_db_header(&buf, &hk, 4096).unwrap_err();
        assert!(matches!(err, PagedbError::Corruption(_)));
    }

    #[test]
    fn segment_round_trip_all_page_sizes() {
        let hk = hk();
        for log2 in [12u8, 13, 14, 15, 16] {
            let page_size = 1usize << log2;
            let mut f = sample_segment();
            f.page_size_log2 = log2;
            let buf = encode_segment_header(&f, &hk, page_size).unwrap();
            let decoded = decode_segment_header(&buf, &hk, page_size).unwrap();
            assert_eq!(decoded, f);
        }
    }

    #[test]
    fn segment_mac_tamper_rejected() {
        let hk = hk();
        let f = sample_segment();
        let mut buf = encode_segment_header(&f, &hk, 4096).unwrap();
        let last = buf.len() - 1;
        buf[last] ^= 1;
        let err = decode_segment_header(&buf, &hk, 4096).unwrap_err();
        assert!(matches!(err, PagedbError::Corruption(_)));
    }

    #[test]
    fn page_size_log2_rejected_outside_range() {
        let hk = hk();
        let mut f = sample_main();
        f.page_size_log2 = 11; // 2 KiB — unsupported
        let err = encode_main_db_header(&f, &hk, 2048).unwrap_err();
        assert!(matches!(err, PagedbError::Unsupported));
    }
}
