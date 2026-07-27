//! Generated adversarial input for the apply-journal record decoder.
//!
//! The journal stream is the one artifact read *before* the header swap is
//! trusted, and its first four bytes are a length that selects the record
//! extent, followed by an action count that would otherwise size a `Vec`
//! straight from disk. Both are attacker- or bug-controlled. The properties
//! here drive those two fields across their whole range and assert the decoder
//! declines rather than allocating, panicking, or spinning.

use crate::recovery::journal::{
    ApplyJournalRecord, JournalAction, decode_journal_stream, decode_record, encode_journal_pages,
};
use proptest::prelude::*;

const PAGE: usize = 4096;
const STREAM_PREFIX_LEN: usize = 4;

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

fn actions() -> impl Strategy<Value = Vec<JournalAction>> {
    prop::collection::vec(
        prop_oneof![
            any::<[u8; 16]>().prop_map(|segment_id| JournalAction::Promote { segment_id }),
            (any::<[u8; 16]>(), any::<u64>()).prop_map(|(segment_id, tombstone_commit_id)| {
                JournalAction::Tombstone {
                    segment_id,
                    tombstone_commit_id,
                }
            }),
        ],
        0..=24,
    )
}

/// Concatenate the sidecar page bodies exactly as replay does.
fn stream_for(record: &ApplyJournalRecord) -> Option<Vec<u8>> {
    let pages = encode_journal_pages(record, PAGE).ok()?;
    Some(pages.concat())
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn random_bytes_never_panic_the_journal_decoders(
        bytes in prop::collection::vec(any::<u8>(), 0..=512),
    ) {
        let _ = decode_journal_stream(&bytes);
        let _ = decode_record(&bytes);
    }

    /// A declared stream length spanning the whole `u32` range in front of an
    /// arbitrary body. This is the field that decides how much of the sidecar
    /// is treated as a record.
    #[test]
    fn hostile_stream_length_never_panics(
        declared_len in any::<u32>(),
        body in prop::collection::vec(any::<u8>(), 0..=256),
    ) {
        let mut stream = declared_len.to_le_bytes().to_vec();
        stream.extend_from_slice(&body);
        let _ = decode_journal_stream(&stream);
    }

    /// A declared action count spanning the whole `u32` range in front of a
    /// short body. A count of four billion must be rejected from the buffer
    /// length alone, before it can reach `Vec::with_capacity`.
    #[test]
    fn hostile_action_count_is_rejected_before_allocating(
        target_commit_id in any::<u64>(),
        action_count in any::<u32>(),
        tail in prop::collection::vec(any::<u8>(), 0..=64),
    ) {
        let mut record = target_commit_id.to_le_bytes().to_vec();
        record.extend_from_slice(&action_count.to_le_bytes());
        record.extend_from_slice(&tail);
        // Every action costs at least a kind byte plus a 16-byte segment id, so
        // any count above that bound is impossible for this buffer length.
        let representable = (action_count as usize) <= tail.len() / 17;
        let decoded = decode_record(&record);
        if !representable {
            prop_assert!(
                decoded.is_err(),
                "action_count={} over a {}-byte tail must not be accepted",
                action_count,
                tail.len()
            );
        }
    }

    #[test]
    fn valid_records_round_trip_through_the_stream(
        target_commit_id in any::<u64>(),
        actions in actions(),
    ) {
        let record = ApplyJournalRecord { target_commit_id, actions };
        let Some(stream) = stream_for(&record) else {
            return Ok(());
        };
        let decoded = decode_journal_stream(&stream).unwrap();
        prop_assert_eq!(decoded.target_commit_id, record.target_commit_id);
        prop_assert_eq!(decoded.actions.len(), record.actions.len());
    }

    #[test]
    fn perturbed_valid_stream_never_panics(
        target_commit_id in any::<u64>(),
        actions in actions(),
        edits in prop::collection::vec((any::<usize>(), any::<u8>()), 1..=12),
    ) {
        let record = ApplyJournalRecord { target_commit_id, actions };
        let Some(stream) = stream_for(&record) else {
            return Ok(());
        };
        let mutated = perturb(stream, &edits);
        let _ = decode_journal_stream(&mutated);
        if mutated.len() > STREAM_PREFIX_LEN {
            let _ = decode_record(&mutated[STREAM_PREFIX_LEN..]);
        }
    }

    /// Truncation: replay reads page bodies, so a lost trailing page yields a
    /// stream shorter than its own declared length.
    #[test]
    fn truncated_valid_stream_never_panics(
        target_commit_id in any::<u64>(),
        actions in actions(),
        keep in 0usize..=(PAGE * 2),
    ) {
        let record = ApplyJournalRecord { target_commit_id, actions };
        let Some(stream) = stream_for(&record) else {
            return Ok(());
        };
        let truncated = &stream[..keep.min(stream.len())];
        let _ = decode_journal_stream(truncated);
    }
}
