//! Generated adversarial input for the B+ tree node decoders.
//!
//! A node body reaches `validate_node_body` already authenticated, so its bytes
//! are whatever some holder of the key wrote — which is not the same as what a
//! correct writer would have written. `slot_count`, `prefix_len`, and every
//! slot-directory entry are `u16`s used directly as slice indices downstream,
//! so the interesting inputs are the ones a human would not think to write
//! down: a valid encoding with exactly one length field moved. Hand-built
//! regressions cover the shapes someone already imagined; these properties
//! cover the rest of the space.
//!
//! The contract every case asserts is uniform: for any bytes, the decoders
//! return a typed `PagedbError` or a value — never a panic, an abort, or an
//! out-of-bounds index. A `proptest` failure here is the panic being reported
//! with the smallest input that still triggers it.

use crate::btree::internal::{Internal, InternalEntry};
use crate::btree::leaf::{Leaf, LeafValue};
use crate::btree::node::{
    HEADER_LEN, NodeKind, OFF_PREFIX_LEN, OFF_SLOT_COUNT, body_capacity, validate_node_body,
};
use proptest::prelude::*;

const PAGE: usize = 4096;

/// Case count per property. Deliberately small: the suite has to stay fast
/// enough that people actually run it, and a property is a standing net rather
/// than a one-off sweep — every push re-rolls a fresh sample, so coverage
/// accumulates over runs. Raise `PAGEDB_PROPTEST_CASES` for a deep soak.
fn cases() -> u32 {
    std::env::var("PAGEDB_PROPTEST_CASES")
        .ok()
        .and_then(|raw| raw.parse().ok())
        .unwrap_or(32)
}

/// Failure persistence is off: a counterexample belongs in the test output and
/// in a hand-written regression, not in an untracked sidecar file that silently
/// changes what CI runs.
fn config() -> ProptestConfig {
    ProptestConfig {
        cases: cases(),
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}

/// Overwrite bytes at generated positions. Indices are taken modulo the length
/// so the generator never has to know the encoding's size.
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

fn inline_records() -> impl Strategy<Value = Vec<(Vec<u8>, Vec<u8>)>> {
    prop::collection::vec(
        (
            prop::collection::vec(any::<u8>(), 1..=12),
            prop::collection::vec(any::<u8>(), 0..=24),
        ),
        0..=12,
    )
}

/// Encode a structurally valid leaf, or `None` when the generated records do
/// not fit a page (an encoder rejection, not a decoder concern).
fn encoded_leaf(records: &[(Vec<u8>, Vec<u8>)], overflow_every: Option<u64>) -> Option<Vec<u8>> {
    let mut leaf = Leaf::new();
    for (index, (key, value)) in records.iter().enumerate() {
        let value = match overflow_every {
            Some(root_page_id) if index % 2 == 0 => LeafValue::Overflow {
                total_len: value.len() as u64,
                root_page_id,
            },
            _ => LeafValue::Inline(value.clone()),
        };
        leaf.upsert(key, value);
    }
    let mut body = vec![0u8; body_capacity(PAGE)];
    leaf.encode(&mut body).ok()?;
    Some(body)
}

fn encoded_internal(leftmost_child: u64, mut entries: Vec<(Vec<u8>, u64)>) -> Option<Vec<u8>> {
    entries.sort();
    entries.dedup_by(|a, b| a.0 == b.0);
    let internal = Internal {
        leftmost_child,
        entries: entries
            .into_iter()
            .map(|(key, right_child)| InternalEntry { key, right_child })
            .collect(),
    };
    let mut body = vec![0u8; body_capacity(PAGE)];
    internal.encode(&mut body).ok()?;
    Some(body)
}

/// Read the slot-directory extent the header claims, without trusting it.
fn slot_directory_span(body: &[u8]) -> Option<(usize, usize)> {
    if body.len() < HEADER_LEN {
        return None;
    }
    let slot_count = usize::from(u16::from_le_bytes([
        body[OFF_SLOT_COUNT],
        body[OFF_SLOT_COUNT + 1],
    ]));
    let prefix_len = usize::from(u16::from_le_bytes([
        body[OFF_PREFIX_LEN],
        body[OFF_PREFIX_LEN + 1],
    ]));
    Some((HEADER_LEN + prefix_len, slot_count))
}

proptest! {
    #![proptest_config(config())]

    /// Wholly random bytes, at every length around the header and page
    /// boundaries.
    #[test]
    fn random_bytes_never_panic_any_node_decoder(
        body in prop::collection::vec(any::<u8>(), 0..=body_capacity(PAGE)),
    ) {
        let _ = validate_node_body(&body);
        let _ = Leaf::decode(&body);
        let _ = Internal::decode(&body);
    }

    /// Random bytes whose first byte is a legal node kind. Without this the
    /// generator spends almost every case bouncing off the kind byte and never
    /// reaches the slot-directory validation at all.
    #[test]
    fn random_bytes_under_a_legal_kind_byte_never_panic(
        kind in prop::sample::select(vec![NodeKind::Internal, NodeKind::Leaf]),
        tail in prop::collection::vec(any::<u8>(), 0..=body_capacity(PAGE)),
    ) {
        let mut body = vec![kind.as_byte()];
        body.extend_from_slice(&tail);
        let _ = validate_node_body(&body);
        let _ = Leaf::decode(&body);
        let _ = Internal::decode(&body);
    }

    /// A valid leaf with arbitrary bytes overwritten. This is the shape that
    /// finds index defects: framing stays plausible, one field lies.
    #[test]
    fn perturbed_valid_leaf_never_panics(
        records in inline_records(),
        // The leaf *encoder* refuses a reserved overflow root outright, so the
        // generator stays above the reserved range: this property is about what
        // the decoders do with the bytes, not about the writer's precondition.
        overflow_root in prop::option::of(4u64..u64::MAX),
        edits in prop::collection::vec((any::<usize>(), any::<u8>()), 1..=24),
    ) {
        let Some(body) = encoded_leaf(&records, overflow_root) else {
            return Ok(());
        };
        let mutated = perturb(body, &edits);
        let _ = validate_node_body(&mutated);
        let _ = Leaf::decode(&mutated);
        // Cross-kind dispatch: an internal decoder pointed at leaf bytes must
        // report a kind mismatch, not walk leaf records as internal records.
        let _ = Internal::decode(&mutated);
    }

    #[test]
    fn perturbed_valid_internal_never_panics(
        leftmost_child in any::<u64>(),
        entries in prop::collection::vec(
            (prop::collection::vec(any::<u8>(), 1..=12), any::<u64>()),
            0..=12,
        ),
        edits in prop::collection::vec((any::<usize>(), any::<u8>()), 1..=24),
    ) {
        let Some(body) = encoded_internal(leftmost_child, entries) else {
            return Ok(());
        };
        let mutated = perturb(body, &edits);
        let _ = validate_node_body(&mutated);
        let _ = Internal::decode(&mutated);
        let _ = Leaf::decode(&mutated);
    }

    /// Target the three fields that drive every downstream slice index
    /// directly. Uniform byte edits hit them only by luck; here every case
    /// lands on one.
    #[test]
    fn hostile_header_and_slot_directory_never_panic(
        records in inline_records(),
        as_internal in any::<bool>(),
        slot_count in any::<u16>(),
        prefix_len in any::<u16>(),
        slot_values in prop::collection::vec(any::<u16>(), 0..=16),
    ) {
        let body = if as_internal {
            encoded_internal(
                7,
                records.iter().map(|(key, _)| (key.clone(), 9)).collect(),
            )
        } else {
            encoded_leaf(&records, None)
        };
        let Some(mut body) = body else { return Ok(()) };

        // Rewrite the slot directory the *original* header describes, then lie
        // about the counts. Both the pre- and post-edit extents get exercised.
        if let Some((directory_start, original_slots)) = slot_directory_span(&body) {
            for (slot, value) in slot_values
                .iter()
                .enumerate()
                .take(original_slots.min(slot_values.len()))
            {
                let at = directory_start + slot * 2;
                if at + 2 <= body.len() {
                    body[at..at + 2].copy_from_slice(&value.to_le_bytes());
                }
            }
        }
        body[OFF_SLOT_COUNT..OFF_SLOT_COUNT + 2].copy_from_slice(&slot_count.to_le_bytes());
        body[OFF_PREFIX_LEN..OFF_PREFIX_LEN + 2].copy_from_slice(&prefix_len.to_le_bytes());

        // The contract: whatever the header claims, validation decides, and a
        // successful validation must make the decoders safe by construction.
        if validate_node_body(&body).is_ok() {
            let _ = Leaf::decode(&body);
            let _ = Internal::decode(&body);
        }
        let _ = Leaf::decode(&body);
        let _ = Internal::decode(&body);
    }

    /// Truncation: a valid encoding cut short at an arbitrary point. Every
    /// offset the header names now points past the end.
    #[test]
    fn truncated_valid_node_never_panics(
        records in inline_records(),
        keep in 0usize..=body_capacity(PAGE),
    ) {
        let Some(body) = encoded_leaf(&records, None) else {
            return Ok(());
        };
        let truncated = &body[..keep.min(body.len())];
        let _ = validate_node_body(truncated);
        let _ = Leaf::decode(truncated);
        let _ = Internal::decode(truncated);
    }

    /// `NodeKind::from_byte` must classify every byte without panicking, and
    /// only the two defined discriminants may be accepted.
    #[test]
    fn node_kind_byte_dispatch_is_total(byte in any::<u8>()) {
        match NodeKind::from_byte(byte) {
            Ok(kind) => prop_assert_eq!(kind.as_byte(), byte),
            Err(_) => prop_assert!(byte > 0x01),
        }
    }
}
