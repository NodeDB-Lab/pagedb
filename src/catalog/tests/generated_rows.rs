//! Generated adversarial input for the catalog row decoders.
//!
//! Catalog rows are fixed-width records read out of an authenticated B+ tree
//! page, which means the bytes are trusted to be *ours* but not trusted to be
//! *sensible*: a row can be the right length with an impossible discriminant, a
//! reserved byte that is not zero, or an epoch ordering that no writer could
//! have produced. Those are the inputs that reach the row decoders in the
//! field, and enumerating them by hand is exactly what has not caught defects
//! so far.

use crate::catalog::codec::{
    Catalog, LegacyRekeyState, REALM_QUOTAS_LEN, REKEY_INTENT_V1_LEN, REKEY_SEGMENT_PROGRESS_LEN,
    RekeyIntent, RekeySegmentProgress, RekeySegmentProgressState, RekeyStage, RekeyStateRow,
    SEGMENT_META_LEN, SegmentKind,
};
use crate::crypto::CipherId;
use crate::{CommitId, Evictable, RealmId, RealmQuotas, SegmentMeta};
use proptest::prelude::*;

fn cases() -> u32 {
    std::env::var("PAGEDB_PROPTEST_CASES")
        .ok()
        .and_then(|raw| raw.parse().ok())
        .unwrap_or(32)
}

fn config() -> ProptestConfig {
    ProptestConfig {
        cases: cases(),
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}

fn perturb(mut bytes: Vec<u8>, edits: &[(usize, u8)]) -> Vec<u8> {
    if bytes.is_empty() {
        return bytes;
    }
    for &(index, value) in edits {
        let at = index % bytes.len();
        bytes[at] = value;
    }
    bytes
}

/// Run every row decoder over the same bytes. Row kind is a key prefix, not a
/// value prefix, so a misrouted key hands one row's bytes to another row's
/// decoder — that cross-product has to be safe for all of them.
fn decode_every_row_kind(bytes: &[u8]) {
    let _ = Catalog::decode_segment_meta(bytes);
    let _ = Catalog::decode_realm_quotas(bytes);
    let _ = Catalog::decode_counter(bytes);
    let _ = Catalog::decode_rekey_state(bytes);
    let _ = Catalog::decode_rekey_segment_progress(bytes);
}

fn valid_segment_meta(
    linked_commit: Option<u64>,
    page_count: u64,
    total_bytes: u64,
    evictable: Evictable,
) -> SegmentMeta {
    SegmentMeta {
        segment_id: [0x77; 16],
        segment_kind: SegmentKind::Unspecified,
        realm_id: RealmId::new([0x5A; 16]),
        parent_file_id: [0x11; 16],
        linked_commit: linked_commit.map(CommitId::new),
        page_count,
        total_bytes,
        final_counter: 42,
        mk_epoch: 3,
        cipher_id: CipherId::Aes256Gcm.as_byte(),
        format_version: 1,
        evictable,
    }
}

fn valid_rekey_intent(source_mk_epoch: u64, target_mk_epoch: u64) -> RekeyIntent {
    RekeyIntent {
        source_mk_epoch,
        target_mk_epoch,
        source_cipher_id: CipherId::Aes256Gcm.as_byte(),
        target_cipher_id: CipherId::Aes256Gcm.as_byte(),
        same_kek: false,
        stage: RekeyStage::Intent,
        source_hk_proof: [0x01; 16],
        target_hk_proof: [0x02; 16],
    }
}

proptest! {
    #![proptest_config(config())]

    /// Wholly random bytes at every length that brackets each row's fixed
    /// width, so short, exact and over-long rows all reach every decoder.
    #[test]
    fn random_bytes_never_panic_any_catalog_row_decoder(
        bytes in prop::collection::vec(any::<u8>(), 0..=(SEGMENT_META_LEN + 8)),
    ) {
        decode_every_row_kind(&bytes);
    }

    /// Length-pinned random bytes. Length checks gate almost every decoder, so
    /// uniform lengths would leave the field-level checks nearly unvisited.
    #[test]
    fn random_bytes_at_exact_row_widths_never_panic(
        width in prop::sample::select(vec![
            8usize,
            13,
            REKEY_SEGMENT_PROGRESS_LEN,
            REALM_QUOTAS_LEN,
            REKEY_INTENT_V1_LEN,
            SEGMENT_META_LEN,
        ]),
        filler in prop::collection::vec(any::<u8>(), 0..=SEGMENT_META_LEN + 8),
    ) {
        let mut bytes = vec![0u8; width];
        for (slot, byte) in bytes.iter_mut().zip(filler.iter()) {
            *slot = *byte;
        }
        decode_every_row_kind(&bytes);
    }

    #[test]
    fn perturbed_valid_segment_meta_never_panics(
        linked_commit in prop::option::of(any::<u64>()),
        page_count in any::<u64>(),
        total_bytes in any::<u64>(),
        replaceable in any::<bool>(),
        edits in prop::collection::vec((any::<usize>(), any::<u8>()), 1..=8),
    ) {
        let evictable = if replaceable {
            Evictable::Replaceable
        } else {
            Evictable::Authoritative
        };
        let meta = valid_segment_meta(linked_commit, page_count, total_bytes, evictable);
        let encoded = Catalog::encode_segment_meta(&meta).to_vec();
        // The unperturbed encoding must survive a round trip, or the
        // perturbation property is testing nothing.
        prop_assert_eq!(Catalog::decode_segment_meta(&encoded).unwrap(), meta);
        let mutated = perturb(encoded, &edits);
        decode_every_row_kind(&mutated);
    }

    #[test]
    fn perturbed_valid_realm_quotas_never_panics(
        max_pages in prop::option::of(any::<u64>()),
        max_dirty_pages in prop::option::of(any::<u64>()),
        max_scratch_pages in prop::option::of(any::<u64>()),
        max_segment_bytes in prop::option::of(any::<u64>()),
        edits in prop::collection::vec((any::<usize>(), any::<u8>()), 1..=8),
    ) {
        let quotas = RealmQuotas {
            max_pages,
            max_dirty_pages,
            max_scratch_pages,
            max_segment_bytes,
        };
        let encoded = Catalog::encode_realm_quotas(&quotas).to_vec();
        prop_assert_eq!(Catalog::decode_realm_quotas(&encoded).unwrap(), quotas);
        let mutated = perturb(encoded, &edits);
        decode_every_row_kind(&mutated);
    }

    #[test]
    fn perturbed_valid_rekey_intent_never_panics(
        source_mk_epoch in any::<u64>(),
        target_mk_epoch in any::<u64>(),
        edits in prop::collection::vec((any::<usize>(), any::<u8>()), 1..=8),
    ) {
        let intent = valid_rekey_intent(source_mk_epoch, target_mk_epoch);
        let encoded = Catalog::encode_rekey_intent(&intent).to_vec();
        // Epoch ordering is a decode-time rule, so only the well-ordered case
        // is required to round-trip; the rest must still decline safely.
        if target_mk_epoch != 0 && target_mk_epoch > source_mk_epoch {
            prop_assert_eq!(
                Catalog::decode_rekey_state(&encoded).unwrap(),
                RekeyStateRow::V1(intent)
            );
        } else {
            prop_assert!(Catalog::decode_rekey_state(&encoded).is_err());
        }
        let mutated = perturb(encoded, &edits);
        decode_every_row_kind(&mutated);
    }

    /// The legacy 13-byte row shares one decoder with the fixed V1 intent, so
    /// its bytes are also adversarial input for the V1 framing checks.
    #[test]
    fn legacy_rekey_state_rows_never_panic(
        target_mk_epoch in any::<u64>(),
        main_db_done in any::<u8>(),
        discarded_segments_index in any::<u32>(),
    ) {
        let mut bytes = Vec::with_capacity(13);
        bytes.extend_from_slice(&target_mk_epoch.to_le_bytes());
        bytes.push(main_db_done);
        bytes.extend_from_slice(&discarded_segments_index.to_le_bytes());
        match Catalog::decode_rekey_state(&bytes) {
            Ok(RekeyStateRow::Legacy(LegacyRekeyState { target_mk_epoch: got, .. })) => {
                prop_assert_eq!(got, target_mk_epoch);
                prop_assert!(main_db_done <= 1);
            }
            Ok(other) => prop_assert!(false, "13-byte row decoded as {:?}", other),
            Err(_) => prop_assert!(target_mk_epoch == 0 || main_db_done > 1),
        }
    }

    #[test]
    fn perturbed_valid_rekey_segment_progress_never_panics(
        replacement_segment_id in any::<[u8; 16]>(),
        edits in prop::collection::vec((any::<usize>(), any::<u8>()), 1..=8),
    ) {
        let progress = RekeySegmentProgress {
            replacement_segment_id,
            state: RekeySegmentProgressState::Sealed,
        };
        let encoded = Catalog::encode_rekey_segment_progress(progress).to_vec();
        prop_assert_eq!(
            Catalog::decode_rekey_segment_progress(&encoded).unwrap(),
            progress
        );
        let mutated = perturb(encoded, &edits);
        decode_every_row_kind(&mutated);
    }

    /// Counter rows are the narrowest surface and the easiest to hand a
    /// foreign row: only an exact 8-byte value may decode.
    #[test]
    fn counter_rows_accept_only_exact_width(
        bytes in prop::collection::vec(any::<u8>(), 0..=24),
    ) {
        match Catalog::decode_counter(&bytes) {
            Ok(_) => prop_assert_eq!(bytes.len(), 8),
            Err(_) => prop_assert_ne!(bytes.len(), 8),
        }
    }

    /// Row keys are attacker-influenced too: an over-long name must be
    /// rejected rather than shaping an unbounded key allocation.
    #[test]
    fn row_keys_never_panic(name in prop::collection::vec(any::<u8>(), 0..=2048)) {
        let counter = Catalog::counter_key(&name);
        prop_assert_eq!(counter.is_ok(), name.len() <= 1024);
        if let Ok(key) = counter {
            prop_assert_eq!(key.len(), name.len() + 1);
        }
    }
}
