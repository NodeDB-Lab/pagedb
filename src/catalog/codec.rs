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
    /// Durable versioned rekey intent. Key is `[0x03]` (singleton; no name
    /// suffix). Its fixed-size value records both cryptographic epochs and
    /// keys' non-secret proofs; it is never a segment-list index.
    RekeyState = 0x03,
    // 0x04 and 0x05 are reserved: they were the in-catalog free-list and
    // deferred-free queue, superseded by the durable free-list chain rooted in
    // the A/B header (see `crate::pager::freelist`). Do not reuse these bytes.
    // 0x06 is reserved, deliberately uninterpreted, and must never be reused.
    /// Reserved (`0x07`). Older builds wrote an incremental-compaction watermark
    /// here; compaction is now a single atomic operation and never writes it.
    /// Retained as a row-kind boundary and so any legacy row is recognised and
    /// dropped during compaction.
    CompactionState = 0x07,
    /// Fixed-size progress for one immutable source segment. The key suffix is
    /// its old `segment_id`, never a catalog-order index.
    RekeySegmentProgress = 0x08,
}

/// Explicit durable rekey transition points. They are ordered so recovery can
/// reject an A/B header that is newer than the intent's durable transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RekeyStage {
    Intent = 1,
    MainPagesTargetReadable = 2,
    HeaderTargetPublished = 3,
    MainDone = 4,
    SegmentsPending = 5,
}

impl RekeyStage {
    fn from_byte(byte: u8) -> Result<Self> {
        match byte {
            1 => Ok(Self::Intent),
            2 => Ok(Self::MainPagesTargetReadable),
            3 => Ok(Self::HeaderTargetPublished),
            4 => Ok(Self::MainDone),
            5 => Ok(Self::SegmentsPending),
            _ => Err(PagedbError::corruption(
                crate::errors::CorruptionDetail::HeaderUnverifiable,
            )),
        }
    }
}

/// Version-one durable rekey intent. HK proofs are one-way identifiers used to
/// validate caller-provided key material; neither KEKs nor master keys are
/// ever persisted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RekeyIntent {
    pub source_mk_epoch: u64,
    pub target_mk_epoch: u64,
    pub source_cipher_id: u8,
    pub target_cipher_id: u8,
    pub same_kek: bool,
    pub stage: RekeyStage,
    pub source_hk_proof: [u8; 16],
    pub target_hk_proof: [u8; 16],
}

/// Old, insufficient rekey state. It is decoded only to admit a conservative
/// same-KEK upgrade; its positional segment index is never correctness state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyRekeyState {
    pub target_mk_epoch: u64,
    pub main_db_done: bool,
    pub discarded_segments_index: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RekeyStateRow {
    V1(RekeyIntent),
    Legacy(LegacyRekeyState),
}

pub const LEGACY_REKEY_STATE_LEN: usize = 13;
pub const REKEY_INTENT_V1_LEN: usize = 64;
pub const REKEY_SEGMENT_PROGRESS_LEN: usize = 20;

/// Durable state of a replacement segment recorded under its source identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RekeySegmentProgressState {
    /// The replacement file was sealed and synced, but its catalog swap may not
    /// yet have been made durable.
    Sealed = 1,
}

impl RekeySegmentProgressState {
    fn from_byte(byte: u8) -> Result<Self> {
        match byte {
            1 => Ok(Self::Sealed),
            _ => Err(PagedbError::corruption(
                crate::errors::CorruptionDetail::HeaderUnverifiable,
            )),
        }
    }
}

/// Fixed-width replacement identity for a source segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RekeySegmentProgress {
    pub replacement_segment_id: [u8; 16],
    pub state: RekeySegmentProgressState,
}

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

    /// Validate and return the name suffix of a segment-row key. This is used
    /// before recovery derives a diagnostic name from authenticated catalog
    /// bytes, so malformed rows cannot cause a slice panic or a repair action.
    pub fn validate_segment_key<'a>(key: &'a [u8], meta: &SegmentMeta) -> Result<&'a [u8]> {
        const SEGMENT_KEY_PREFIX_LEN: usize = 1 + 16;
        if key.first().copied() != Some(CatalogRowKind::Segment as u8) {
            return Err(PagedbError::catalog_row_invalid("segment.key.kind"));
        }
        if key.len() < SEGMENT_KEY_PREFIX_LEN {
            return Err(PagedbError::catalog_row_invalid("segment.key.length"));
        }
        let name = &key[SEGMENT_KEY_PREFIX_LEN..];
        if name.len() > MAX_SEGMENT_NAME_LEN {
            return Err(PagedbError::catalog_row_invalid("segment.key.name_length"));
        }
        if key[1..SEGMENT_KEY_PREFIX_LEN] != meta.realm_id.0[..] {
            return Err(PagedbError::catalog_row_invalid("segment.key.realm_id"));
        }
        Ok(name)
    }

    /// Rekey-state row key: `[0x03]` (singleton, no suffix).
    #[must_use]
    pub fn rekey_state_key() -> Vec<u8> {
        vec![CatalogRowKind::RekeyState as u8]
    }

    /// Per-source-segment progress key: `[0x08] || old_segment_id[16]`.
    #[must_use]
    pub fn rekey_segment_progress_key(old_segment_id: [u8; 16]) -> [u8; 17] {
        let mut key = [0u8; 17];
        key[0] = CatalogRowKind::RekeySegmentProgress as u8;
        key[1..].copy_from_slice(&old_segment_id);
        key
    }

    /// Encode a V1 rekey intent. All reserved bytes are emitted as zero.
    #[must_use]
    pub fn encode_rekey_intent(intent: &RekeyIntent) -> [u8; REKEY_INTENT_V1_LEN] {
        let mut out = [0u8; REKEY_INTENT_V1_LEN];
        out[0] = 1;
        out[1] = intent.stage as u8;
        out[2] = u8::from(intent.same_kek);
        out[4..12].copy_from_slice(&intent.source_mk_epoch.to_le_bytes());
        out[12..20].copy_from_slice(&intent.target_mk_epoch.to_le_bytes());
        out[20] = intent.source_cipher_id;
        out[21] = intent.target_cipher_id;
        out[24..40].copy_from_slice(&intent.source_hk_proof);
        out[40..56].copy_from_slice(&intent.target_hk_proof);
        out
    }

    /// Decode either a fixed V1 intent or the legacy 13-byte row. Legacy
    /// positional progress is deliberately preserved only for diagnostics.
    pub fn decode_rekey_state(bytes: &[u8]) -> Result<RekeyStateRow> {
        if bytes.len() == LEGACY_REKEY_STATE_LEN {
            let target_mk_epoch = u64::from_le_bytes(bytes[0..8].try_into().map_err(|_| {
                PagedbError::corruption(crate::errors::CorruptionDetail::HeaderUnverifiable)
            })?);
            if target_mk_epoch == 0 {
                return Err(PagedbError::corruption(
                    crate::errors::CorruptionDetail::HeaderUnverifiable,
                ));
            }
            return Ok(RekeyStateRow::Legacy(LegacyRekeyState {
                target_mk_epoch,
                main_db_done: match bytes[8] {
                    0 => false,
                    1 => true,
                    _ => {
                        return Err(PagedbError::corruption(
                            crate::errors::CorruptionDetail::HeaderUnverifiable,
                        ));
                    }
                },
                discarded_segments_index: u32::from_le_bytes(bytes[9..13].try_into().map_err(
                    |_| {
                        PagedbError::corruption(crate::errors::CorruptionDetail::HeaderUnverifiable)
                    },
                )?),
            }));
        }
        if bytes.len() != REKEY_INTENT_V1_LEN
            || bytes[0] != 1
            || bytes[3] != 0
            || bytes[22..24].iter().any(|byte| *byte != 0)
            || bytes[56..].iter().any(|byte| *byte != 0)
        {
            return Err(PagedbError::corruption(
                crate::errors::CorruptionDetail::HeaderUnverifiable,
            ));
        }
        let source_mk_epoch = u64::from_le_bytes(bytes[4..12].try_into().map_err(|_| {
            PagedbError::corruption(crate::errors::CorruptionDetail::HeaderUnverifiable)
        })?);
        let target_mk_epoch = u64::from_le_bytes(bytes[12..20].try_into().map_err(|_| {
            PagedbError::corruption(crate::errors::CorruptionDetail::HeaderUnverifiable)
        })?);
        if target_mk_epoch == 0 || target_mk_epoch <= source_mk_epoch {
            return Err(PagedbError::corruption(
                crate::errors::CorruptionDetail::HeaderUnverifiable,
            ));
        }
        let same_kek = match bytes[2] {
            0 => false,
            1 => true,
            _ => {
                return Err(PagedbError::corruption(
                    crate::errors::CorruptionDetail::HeaderUnverifiable,
                ));
            }
        };
        crate::crypto::CipherId::from_byte(bytes[20])?;
        crate::crypto::CipherId::from_byte(bytes[21])?;
        if bytes[20] != bytes[21] {
            return Err(PagedbError::rekey_state_invalid("target_cipher_id"));
        }
        let mut source_hk_proof = [0u8; 16];
        source_hk_proof.copy_from_slice(&bytes[24..40]);
        let mut target_hk_proof = [0u8; 16];
        target_hk_proof.copy_from_slice(&bytes[40..56]);
        Ok(RekeyStateRow::V1(RekeyIntent {
            source_mk_epoch,
            target_mk_epoch,
            source_cipher_id: bytes[20],
            target_cipher_id: bytes[21],
            same_kek,
            stage: RekeyStage::from_byte(bytes[1])?,
            source_hk_proof,
            target_hk_proof,
        }))
    }

    /// Encode fixed rekey replacement progress:
    /// `version[1] || state[1] || reserved[2] || replacement_segment_id[16]`.
    #[must_use]
    pub fn encode_rekey_segment_progress(
        progress: RekeySegmentProgress,
    ) -> [u8; REKEY_SEGMENT_PROGRESS_LEN] {
        let mut out = [0u8; REKEY_SEGMENT_PROGRESS_LEN];
        out[0] = 1;
        out[1] = progress.state as u8;
        out[4..20].copy_from_slice(&progress.replacement_segment_id);
        out
    }

    pub fn decode_rekey_segment_progress(bytes: &[u8]) -> Result<RekeySegmentProgress> {
        if bytes.len() != REKEY_SEGMENT_PROGRESS_LEN
            || bytes[0] != 1
            || bytes[2..4].iter().any(|byte| *byte != 0)
        {
            return Err(PagedbError::corruption(
                crate::errors::CorruptionDetail::HeaderUnverifiable,
            ));
        }
        let mut replacement_segment_id = [0u8; 16];
        replacement_segment_id.copy_from_slice(&bytes[4..20]);
        Ok(RekeySegmentProgress {
            replacement_segment_id,
            state: RekeySegmentProgressState::from_byte(bytes[1])?,
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
        let linked_commit = match bytes[49] {
            0 => {
                if bytes[50..58].iter().any(|byte| *byte != 0) {
                    return Err(PagedbError::catalog_row_invalid(
                        "segment_meta.linked_commit",
                    ));
                }
                None
            }
            1 => {
                let mut b = [0u8; 8];
                b.copy_from_slice(&bytes[50..58]);
                Some(CommitId(u64::from_le_bytes(b)))
            }
            _ => {
                return Err(PagedbError::catalog_row_invalid(
                    "segment_meta.linked_commit",
                ));
            }
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
    fn rekey_intent_v1_round_trip() {
        let intent = RekeyIntent {
            source_mk_epoch: 0,
            target_mk_epoch: 27,
            source_cipher_id: 2,
            target_cipher_id: 2,
            same_kek: false,
            stage: RekeyStage::HeaderTargetPublished,
            source_hk_proof: [7; 16],
            target_hk_proof: [8; 16],
        };
        let encoded = Catalog::encode_rekey_intent(&intent);
        assert_eq!(
            Catalog::decode_rekey_state(&encoded).unwrap(),
            RekeyStateRow::V1(intent)
        );
    }

    #[test]
    fn legacy_rekey_state_discards_positional_progress() {
        let mut bytes = [0u8; LEGACY_REKEY_STATE_LEN];
        bytes[..8].copy_from_slice(&4u64.to_le_bytes());
        bytes[8] = 1;
        bytes[9..].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            Catalog::decode_rekey_state(&bytes).unwrap(),
            RekeyStateRow::Legacy(LegacyRekeyState {
                target_mk_epoch: 4,
                main_db_done: true,
                discarded_segments_index: u32::MAX,
            })
        );
    }

    #[test]
    fn rekey_intent_rejects_invalid_boolean_epoch_and_progress_reserved_bytes() {
        let mut intent = RekeyIntent {
            source_mk_epoch: 1,
            target_mk_epoch: 2,
            source_cipher_id: 1,
            target_cipher_id: 1,
            same_kek: true,
            stage: RekeyStage::Intent,
            source_hk_proof: [0; 16],
            target_hk_proof: [0; 16],
        };
        let mut encoded = Catalog::encode_rekey_intent(&intent);
        encoded[2] = 2;
        assert!(Catalog::decode_rekey_state(&encoded).is_err());
        intent.target_mk_epoch = 0;
        assert!(Catalog::decode_rekey_state(&Catalog::encode_rekey_intent(&intent)).is_err());
        let progress = RekeySegmentProgress {
            replacement_segment_id: [5; 16],
            state: RekeySegmentProgressState::Sealed,
        };
        let mut encoded_progress = Catalog::encode_rekey_segment_progress(progress);
        assert_eq!(
            Catalog::decode_rekey_segment_progress(&encoded_progress).unwrap(),
            progress
        );
        encoded_progress[2] = 1;
        assert!(Catalog::decode_rekey_segment_progress(&encoded_progress).is_err());
        intent.target_mk_epoch = 2;
        let mut encoded_intent = Catalog::encode_rekey_intent(&intent);
        encoded_intent[21] = u8::MAX;
        assert!(Catalog::decode_rekey_state(&encoded_intent).is_err());
        let mut mixed_cipher_intent = Catalog::encode_rekey_intent(&intent);
        mixed_cipher_intent[21] = 2;
        assert!(matches!(
            Catalog::decode_rekey_state(&mixed_cipher_intent),
            Err(PagedbError::RekeyStateInvalid {
                field: "target_cipher_id"
            })
        ));
    }

    #[test]
    fn counter_decode_wrong_length_errors() {
        let err = Catalog::decode_counter(&[0u8; 7]).err().unwrap();
        assert!(matches!(err, PagedbError::Corruption { .. }));
        let err = Catalog::decode_counter(&[]).err().unwrap();
        assert!(matches!(err, PagedbError::Corruption { .. }));
    }

    #[test]
    fn segment_meta_rejects_invalid_linked_commit_discriminator_and_unused_bytes() {
        let meta = SegmentMeta {
            segment_id: [9; 16],
            segment_kind: SegmentKind::Unspecified,
            realm_id: RealmId([0; 16]),
            parent_file_id: [0; 16],
            linked_commit: None,
            page_count: 2,
            total_bytes: 8192,
            final_counter: 0,
            mk_epoch: 0,
            cipher_id: 1,
            format_version: 1,
            evictable: Evictable::Authoritative,
        };
        let mut encoded = Catalog::encode_segment_meta(&meta);
        encoded[49] = 2;
        assert!(matches!(
            Catalog::decode_segment_meta(&encoded),
            Err(PagedbError::Corruption(
                crate::errors::CorruptionDetail::CatalogRowInvalid {
                    field: "segment_meta.linked_commit"
                }
            ))
        ));

        let mut encoded = Catalog::encode_segment_meta(&meta);
        encoded[50] = 1;
        assert!(matches!(
            Catalog::decode_segment_meta(&encoded),
            Err(PagedbError::Corruption(
                crate::errors::CorruptionDetail::CatalogRowInvalid {
                    field: "segment_meta.linked_commit"
                }
            ))
        ));
    }

    #[test]
    fn segment_key_validation_rejects_malformed_routing_bytes() {
        let meta = SegmentMeta {
            segment_id: [1; 16],
            segment_kind: SegmentKind::Unspecified,
            realm_id: RealmId([2; 16]),
            parent_file_id: [3; 16],
            linked_commit: None,
            page_count: 2,
            total_bytes: 8192,
            final_counter: 0,
            mk_epoch: 0,
            cipher_id: 1,
            format_version: 1,
            evictable: Evictable::Authoritative,
        };
        assert!(Catalog::validate_segment_key(&[], &meta).is_err());
        assert!(Catalog::validate_segment_key(&[CatalogRowKind::Quota as u8; 17], &meta).is_err());
        assert!(
            Catalog::validate_segment_key(&[CatalogRowKind::Segment as u8; 16], &meta).is_err()
        );
        let wrong_realm = Catalog::segment_key(RealmId([4; 16]), b"name").unwrap();
        assert!(Catalog::validate_segment_key(&wrong_realm, &meta).is_err());
        let mut long_name = vec![CatalogRowKind::Segment as u8];
        long_name.extend_from_slice(&meta.realm_id.0);
        long_name.extend_from_slice(&vec![b'n'; MAX_SEGMENT_NAME_LEN + 1]);
        assert!(Catalog::validate_segment_key(&long_name, &meta).is_err());
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
