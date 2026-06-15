//! Encoding for catalog rows.

use crate::errors::{Evictable, PagedbError};
use crate::{CommitId, RealmId, Result};

pub const MAX_SEGMENT_NAME_LEN: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CatalogRowKind {
    Quota = 0x00,
    Segment = 0x01,
    /// Durable monotonic counter stored as 8-byte little-endian `u64`.
    /// Counter rows are per-`Db` (not per-realm); the key is
    /// `[0x02] || name_bytes`.
    ///
    /// Note: the dedicated `PageKind::Counter = 0x06` byte stays reserved
    /// for a future per-page counter format; current counters are B+ tree rows
    /// under this row kind. The page-kind reservation remains available for
    /// that later optimisation.
    Counter = 0x02,
    /// Durable rekey watermark. Cleared on rekey completion. Key is `[0x03]`
    /// (singleton; no name suffix). Value is `RekeyState` encoded as 13 bytes:
    /// `target_mk_epoch[8] || main_db_done[1] || segments_remaining_idx[4]`.
    RekeyState = 0x03,
    // 0x04 and 0x05 are reserved: they were the in-catalog free-list and
    // deferred-free queue, superseded by the durable free-list chain rooted in
    // the A/B header (see `crate::pager::freelist`). Do not reuse these bytes.
    /// Durable reader pin. One row per active cross-process read transaction.
    /// Key: `[0x06] || pid_u32_be[4] || lease_id_u64_be[8]` (13 bytes).
    /// Value: `commit_id[8] || root_page_id[8] || catalog_root_page_id[8] ||
    ///          free_list_root_page_id[8] || expires_unix_seconds[8] || flags[1]`
    /// (41 bytes).
    ///
    /// On `begin_read` the writer inserts a row; on `ReadTxn::drop` the row is
    /// deleted. If a reader crashes, its row is cleaned up at the next
    /// `Db::open` of a writer handle. A row whose `expires_unix_seconds` is
    /// older than the current wall-clock time is treated as expired by GC and
    /// does not block page reclamation.
    ///
    /// On a `ReadOnly` or `Follower` handle that cannot write to its own
    /// catalog, reader pins are maintained in-memory only and the writer process
    /// must be trusted to honor the catalog pins.
    ReaderPin = 0x06,
    /// Reserved (`0x07`). Older builds wrote an incremental-compaction watermark
    /// here; compaction is now a single atomic operation and never writes it.
    /// Retained as a row-kind boundary and so any legacy row is recognised and
    /// dropped during compaction.
    CompactionState = 0x07,
}

/// Rekey watermark persisted in the catalog during an online rekey operation.
/// A present row means a rekey is in flight or was interrupted by a crash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RekeyStateRow {
    /// The `mk_epoch` the rekey is converging toward.
    pub target_mk_epoch: u64,
    /// True once every main.db B+ tree page has been rewritten.
    pub main_db_done: bool,
    /// Index into the segment list at which resume should start.
    /// Segments at indices `< segments_remaining_idx` have been rekeyed.
    pub segments_remaining_idx: u32,
}

pub const REKEY_STATE_LEN: usize = 13;

/// Engine-defined segment type tag. This slice ships only `Unspecified`;
/// engine adapters add concrete variants later.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SegmentKind {
    Unspecified = 0x00,
}

impl SegmentKind {
    pub fn from_byte(b: u8) -> Result<Self> {
        match b {
            0x00 => Ok(Self::Unspecified),
            _ => Err(PagedbError::Unsupported),
        }
    }

    #[must_use]
    pub fn as_byte(self) -> u8 {
        self as u8
    }
}

/// Catalog value for a segment row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentMeta {
    pub segment_id: [u8; 16],
    pub segment_kind: SegmentKind,
    pub realm_id: RealmId,
    pub parent_file_id: [u8; 16],
    pub linked_commit: Option<CommitId>,
    pub page_count: u64,
    pub total_bytes: u64,
    pub final_counter: u64,
    pub mk_epoch: u64,
    pub cipher_id: u8,
    pub format_version: u16,
    pub evictable: Evictable,
}

/// Catalog value for a quota row. Default = no caps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RealmQuotas {
    pub max_pages: Option<u64>,
    pub max_dirty_pages: Option<u64>,
    pub max_scratch_pages: Option<u64>,
    pub max_segment_bytes: Option<u64>,
}

/// Value for a durable reader-pin row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReaderPinValue {
    pub commit_id: u64,
    pub root_page_id: u64,
    pub catalog_root_page_id: u64,
    pub free_list_root_page_id: u64,
    pub expires_unix_seconds: u64,
    pub flags: u8,
}

pub const READER_PIN_VALUE_LEN: usize = 41;
pub const READER_PIN_KEY_LEN: usize = 13;

pub const SEGMENT_META_LEN: usize = 94;
pub const REALM_QUOTAS_LEN: usize = 33;

pub struct Catalog;

impl Catalog {
    /// Quota row key: `[0x00] || realm_id`.
    #[must_use]
    pub fn quota_key(realm: RealmId) -> Vec<u8> {
        let mut k = Vec::with_capacity(17);
        k.push(CatalogRowKind::Quota as u8);
        k.extend_from_slice(&realm.0);
        k
    }

    /// Segment row key: `[0x01] || realm_id || name_bytes`. Rejects names
    /// longer than `MAX_SEGMENT_NAME_LEN`.
    pub fn segment_key(realm: RealmId, name: &[u8]) -> Result<Vec<u8>> {
        if name.len() > MAX_SEGMENT_NAME_LEN {
            return Err(PagedbError::NameTooLong);
        }
        let mut k = Vec::with_capacity(1 + 16 + name.len());
        k.push(CatalogRowKind::Segment as u8);
        k.extend_from_slice(&realm.0);
        k.extend_from_slice(name);
        Ok(k)
    }

    /// Rekey-state row key: `[0x03]` (singleton, no suffix).
    #[must_use]
    pub fn rekey_state_key() -> Vec<u8> {
        vec![CatalogRowKind::RekeyState as u8]
    }

    /// Encode a `RekeyStateRow` as 13 bytes.
    #[must_use]
    pub fn encode_rekey_state(r: &RekeyStateRow) -> [u8; REKEY_STATE_LEN] {
        let mut o = [0u8; REKEY_STATE_LEN];
        o[0..8].copy_from_slice(&r.target_mk_epoch.to_le_bytes());
        o[8] = u8::from(r.main_db_done);
        o[9..13].copy_from_slice(&r.segments_remaining_idx.to_le_bytes());
        o
    }

    /// Decode a `RekeyStateRow` from a 13-byte slice.
    pub fn decode_rekey_state(bytes: &[u8]) -> Result<RekeyStateRow> {
        if bytes.len() != REKEY_STATE_LEN {
            return Err(PagedbError::corruption(
                crate::errors::CorruptionDetail::HeaderUnverifiable,
            ));
        }
        let mut ep = [0u8; 8];
        ep.copy_from_slice(&bytes[0..8]);
        let target_mk_epoch = u64::from_le_bytes(ep);
        let main_db_done = bytes[8] != 0;
        let mut idx = [0u8; 4];
        idx.copy_from_slice(&bytes[9..13]);
        let segments_remaining_idx = u32::from_le_bytes(idx);
        Ok(RekeyStateRow {
            target_mk_epoch,
            main_db_done,
            segments_remaining_idx,
        })
    }

    /// Reader-pin row key: `[0x06] || pid_u32_be[4] || lease_id_u64_be[8]`.
    #[must_use]
    pub fn reader_pin_key(pid: u32, lease_id: u64) -> [u8; READER_PIN_KEY_LEN] {
        let mut k = [0u8; READER_PIN_KEY_LEN];
        k[0] = CatalogRowKind::ReaderPin as u8;
        k[1..5].copy_from_slice(&pid.to_be_bytes());
        k[5..13].copy_from_slice(&lease_id.to_be_bytes());
        k
    }

    /// Range start key for all reader-pin rows: `[0x06]`.
    #[must_use]
    pub fn reader_pin_range_start() -> [u8; 1] {
        [CatalogRowKind::ReaderPin as u8]
    }

    /// Range end key (exclusive) for all reader-pin rows: `[0x07]`.
    #[must_use]
    pub fn reader_pin_range_end() -> [u8; 1] {
        [CatalogRowKind::CompactionState as u8]
    }

    /// Encode a `ReaderPinValue` as 41 bytes.
    #[must_use]
    pub fn encode_reader_pin(v: &ReaderPinValue) -> [u8; READER_PIN_VALUE_LEN] {
        let mut o = [0u8; READER_PIN_VALUE_LEN];
        o[0..8].copy_from_slice(&v.commit_id.to_le_bytes());
        o[8..16].copy_from_slice(&v.root_page_id.to_le_bytes());
        o[16..24].copy_from_slice(&v.catalog_root_page_id.to_le_bytes());
        o[24..32].copy_from_slice(&v.free_list_root_page_id.to_le_bytes());
        o[32..40].copy_from_slice(&v.expires_unix_seconds.to_le_bytes());
        o[40] = v.flags;
        o
    }

    /// Decode a `ReaderPinValue` from a 41-byte slice.
    pub fn decode_reader_pin(bytes: &[u8]) -> Result<ReaderPinValue> {
        if bytes.len() != READER_PIN_VALUE_LEN {
            return Err(PagedbError::corruption(
                crate::errors::CorruptionDetail::HeaderUnverifiable,
            ));
        }
        let read_u64 = |off: usize| {
            let mut b = [0u8; 8];
            b.copy_from_slice(&bytes[off..off + 8]);
            u64::from_le_bytes(b)
        };
        Ok(ReaderPinValue {
            commit_id: read_u64(0),
            root_page_id: read_u64(8),
            catalog_root_page_id: read_u64(16),
            free_list_root_page_id: read_u64(24),
            expires_unix_seconds: read_u64(32),
            flags: bytes[40],
        })
    }

    /// Counter row key: `[0x02] || name_bytes`. Rejects names longer than
    /// `MAX_SEGMENT_NAME_LEN`. Counter rows are per-`Db`, not per-realm.
    pub fn counter_key(name: &[u8]) -> Result<Vec<u8>> {
        if name.len() > MAX_SEGMENT_NAME_LEN {
            return Err(PagedbError::NameTooLong);
        }
        let mut k = Vec::with_capacity(1 + name.len());
        k.push(CatalogRowKind::Counter as u8);
        k.extend_from_slice(name);
        Ok(k)
    }

    /// Encode a counter value as 8-byte little-endian.
    #[must_use]
    pub fn encode_counter(value: u64) -> [u8; 8] {
        value.to_le_bytes()
    }

    /// Decode a counter value from an 8-byte little-endian slice.
    pub fn decode_counter(bytes: &[u8]) -> Result<u64> {
        if bytes.len() != 8 {
            return Err(PagedbError::corruption(
                crate::errors::CorruptionDetail::HeaderUnverifiable,
            ));
        }
        let mut b = [0u8; 8];
        b.copy_from_slice(bytes);
        Ok(u64::from_le_bytes(b))
    }

    #[must_use]
    pub fn encode_realm_quotas(q: &RealmQuotas) -> [u8; REALM_QUOTAS_LEN] {
        let mut out = [0u8; REALM_QUOTAS_LEN];
        let mut mask = 0u8;
        if q.max_pages.is_some() {
            mask |= 1 << 0;
        }
        if q.max_dirty_pages.is_some() {
            mask |= 1 << 1;
        }
        if q.max_scratch_pages.is_some() {
            mask |= 1 << 2;
        }
        if q.max_segment_bytes.is_some() {
            mask |= 1 << 3;
        }
        out[0] = mask;
        out[1..9].copy_from_slice(&q.max_pages.unwrap_or(0).to_le_bytes());
        out[9..17].copy_from_slice(&q.max_dirty_pages.unwrap_or(0).to_le_bytes());
        out[17..25].copy_from_slice(&q.max_scratch_pages.unwrap_or(0).to_le_bytes());
        out[25..33].copy_from_slice(&q.max_segment_bytes.unwrap_or(0).to_le_bytes());
        out
    }

    pub fn decode_realm_quotas(bytes: &[u8]) -> Result<RealmQuotas> {
        if bytes.len() != REALM_QUOTAS_LEN {
            return Err(PagedbError::corruption(
                crate::errors::CorruptionDetail::HeaderUnverifiable,
            ));
        }
        let mask = bytes[0];
        let read = |off: usize| -> u64 {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&bytes[off..off + 8]);
            u64::from_le_bytes(buf)
        };
        let max_pages = if mask & 0b0001 != 0 {
            Some(read(1))
        } else {
            None
        };
        let max_dirty_pages = if mask & 0b0010 != 0 {
            Some(read(9))
        } else {
            None
        };
        let max_scratch_pages = if mask & 0b0100 != 0 {
            Some(read(17))
        } else {
            None
        };
        let max_segment_bytes = if mask & 0b1000 != 0 {
            Some(read(25))
        } else {
            None
        };
        Ok(RealmQuotas {
            max_pages,
            max_dirty_pages,
            max_scratch_pages,
            max_segment_bytes,
        })
    }

    #[must_use]
    pub fn encode_segment_meta(m: &SegmentMeta) -> [u8; SEGMENT_META_LEN] {
        let mut o = [0u8; SEGMENT_META_LEN];
        o[0..16].copy_from_slice(&m.segment_id);
        o[16] = m.segment_kind.as_byte();
        o[17..33].copy_from_slice(&m.realm_id.0);
        o[33..49].copy_from_slice(&m.parent_file_id);
        match m.linked_commit {
            Some(CommitId(c)) => {
                o[49] = 1;
                o[50..58].copy_from_slice(&c.to_le_bytes());
            }
            None => {
                o[49] = 0;
                // o[50..58] stays zero
            }
        }
        o[58..66].copy_from_slice(&m.page_count.to_le_bytes());
        o[66..74].copy_from_slice(&m.total_bytes.to_le_bytes());
        o[74..82].copy_from_slice(&m.final_counter.to_le_bytes());
        o[82..90].copy_from_slice(&m.mk_epoch.to_le_bytes());
        o[90] = m.cipher_id;
        o[91..93].copy_from_slice(&m.format_version.to_le_bytes());
        o[93] = match m.evictable {
            Evictable::Authoritative => 0,
            Evictable::Replaceable => 1,
        };
        o
    }

    pub fn decode_segment_meta(bytes: &[u8]) -> Result<SegmentMeta> {
        if bytes.len() != SEGMENT_META_LEN {
            return Err(PagedbError::corruption(
                crate::errors::CorruptionDetail::HeaderUnverifiable,
            ));
        }
        let segment_id = {
            let mut b = [0u8; 16];
            b.copy_from_slice(&bytes[0..16]);
            b
        };
        let segment_kind = SegmentKind::from_byte(bytes[16])?;
        let realm_id = {
            let mut b = [0u8; 16];
            b.copy_from_slice(&bytes[17..33]);
            RealmId(b)
        };
        let parent_file_id = {
            let mut b = [0u8; 16];
            b.copy_from_slice(&bytes[33..49]);
            b
        };
        let linked_commit = if bytes[49] == 1 {
            let mut b = [0u8; 8];
            b.copy_from_slice(&bytes[50..58]);
            Some(CommitId(u64::from_le_bytes(b)))
        } else {
            None
        };
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&bytes[58..66]);
        let page_count = u64::from_le_bytes(buf);
        buf.copy_from_slice(&bytes[66..74]);
        let total_bytes = u64::from_le_bytes(buf);
        buf.copy_from_slice(&bytes[74..82]);
        let final_counter = u64::from_le_bytes(buf);
        buf.copy_from_slice(&bytes[82..90]);
        let mk_epoch = u64::from_le_bytes(buf);
        let cipher_id = bytes[90];
        let mut buf2 = [0u8; 2];
        buf2.copy_from_slice(&bytes[91..93]);
        let format_version = u16::from_le_bytes(buf2);
        let evictable = match bytes[93] {
            0 => Evictable::Authoritative,
            1 => Evictable::Replaceable,
            _ => {
                return Err(PagedbError::corruption(
                    crate::errors::CorruptionDetail::HeaderUnverifiable,
                ));
            }
        };
        Ok(SegmentMeta {
            segment_id,
            segment_kind,
            realm_id,
            parent_file_id,
            linked_commit,
            page_count,
            total_bytes,
            final_counter,
            mk_epoch,
            cipher_id,
            format_version,
            evictable,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quota_key_layout() {
        let k = Catalog::quota_key(RealmId([0xAB; 16]));
        assert_eq!(k[0], 0x00);
        assert_eq!(&k[1..17], &[0xAB; 16]);
        assert_eq!(k.len(), 17);
    }

    #[test]
    fn segment_key_layout() {
        let k = Catalog::segment_key(RealmId([0xCD; 16]), b"hnsw-index").unwrap();
        assert_eq!(k[0], 0x01);
        assert_eq!(&k[1..17], &[0xCD; 16]);
        assert_eq!(&k[17..], b"hnsw-index");
    }

    #[test]
    fn segment_key_rejects_too_long_name() {
        let too_long = vec![b'a'; MAX_SEGMENT_NAME_LEN + 1];
        let err = Catalog::segment_key(RealmId([0; 16]), &too_long)
            .err()
            .unwrap();
        assert!(matches!(err, PagedbError::NameTooLong));
    }

    #[test]
    fn realm_quotas_round_trip() {
        let q = RealmQuotas {
            max_pages: Some(1_000_000),
            max_dirty_pages: None,
            max_scratch_pages: Some(64),
            max_segment_bytes: Some(10 * 1024 * 1024),
        };
        let encoded = Catalog::encode_realm_quotas(&q);
        assert_eq!(encoded.len(), REALM_QUOTAS_LEN);
        let decoded = Catalog::decode_realm_quotas(&encoded).unwrap();
        assert_eq!(decoded, q);
    }

    #[test]
    fn realm_quotas_default_round_trip() {
        let q = RealmQuotas::default();
        let encoded = Catalog::encode_realm_quotas(&q);
        let decoded = Catalog::decode_realm_quotas(&encoded).unwrap();
        assert_eq!(decoded, q);
    }

    #[test]
    fn segment_meta_round_trip() {
        let m = SegmentMeta {
            segment_id: [1; 16],
            segment_kind: SegmentKind::Unspecified,
            realm_id: RealmId([2; 16]),
            parent_file_id: [3; 16],
            linked_commit: Some(CommitId(42)),
            page_count: 100,
            total_bytes: 409_600,
            final_counter: 99,
            mk_epoch: 7,
            cipher_id: 1,
            format_version: 1,
            evictable: Evictable::Replaceable,
        };
        let encoded = Catalog::encode_segment_meta(&m);
        assert_eq!(encoded.len(), SEGMENT_META_LEN);
        let decoded = Catalog::decode_segment_meta(&encoded).unwrap();
        assert_eq!(decoded, m);
    }

    #[test]
    fn counter_key_layout() {
        let k = Catalog::counter_key(b"my-counter").unwrap();
        assert_eq!(k[0], 0x02);
        assert_eq!(&k[1..], b"my-counter");
        assert_eq!(k.len(), 11);
    }

    #[test]
    fn counter_key_rejects_too_long_name() {
        let too_long = vec![b'x'; MAX_SEGMENT_NAME_LEN + 1];
        let err = Catalog::counter_key(&too_long).err().unwrap();
        assert!(matches!(err, PagedbError::NameTooLong));
    }

    #[test]
    fn counter_codec_round_trip() {
        for v in [0u64, 1, 42, u64::MAX, u64::MAX - 1] {
            let enc = Catalog::encode_counter(v);
            assert_eq!(enc.len(), 8);
            let dec = Catalog::decode_counter(&enc).unwrap();
            assert_eq!(dec, v);
        }
    }

    #[test]
    fn counter_decode_wrong_length_errors() {
        let err = Catalog::decode_counter(&[0u8; 7]).err().unwrap();
        assert!(matches!(err, PagedbError::Corruption { .. }));
        let err = Catalog::decode_counter(&[]).err().unwrap();
        assert!(matches!(err, PagedbError::Corruption { .. }));
    }

    #[test]
    fn segment_meta_unlinked_round_trip() {
        let m = SegmentMeta {
            segment_id: [9; 16],
            segment_kind: SegmentKind::Unspecified,
            realm_id: RealmId([0; 16]),
            parent_file_id: [0; 16],
            linked_commit: None,
            page_count: 0,
            total_bytes: 0,
            final_counter: 0,
            mk_epoch: 0,
            cipher_id: 1,
            format_version: 1,
            evictable: Evictable::Authoritative,
        };
        let encoded = Catalog::encode_segment_meta(&m);
        let decoded = Catalog::decode_segment_meta(&encoded).unwrap();
        assert_eq!(decoded, m);
    }
}
