//! Node split policy. Leaf splits use a 90/10 bias when the inserting key
//! is strictly greater than all existing keys in the leaf (monotonic-insert
//! detection); 50/50 otherwise. Internal node splits always use 50/50.

use super::internal::Internal;
use super::leaf::Leaf;

/// Split a leaf. `monotonic` controls the bias: `true` → 90/10, `false` → 50/50.
/// Returns `(left, right, separator_key)`. Caller wires sibling pointers and
/// allocates `page_ids`.
#[must_use]
pub fn split_leaf(mut leaf: Leaf, monotonic: bool) -> (Leaf, Leaf, Vec<u8>) {
    let total = leaf.records.len();
    let split_at = if monotonic {
        // 90% to the left, at least 1 to the right.
        let n = (total * 9) / 10;
        n.min(total - 1).max(1)
    } else {
        total / 2
    };
    let right_records = leaf.records.split_off(split_at);
    let sep_key = right_records[0].0.clone();
    let left = Leaf {
        left_sibling: leaf.left_sibling,
        right_sibling: 0,
        records: leaf.records,
    };
    let right = Leaf {
        left_sibling: 0,
        right_sibling: 0,
        records: right_records,
    };
    (left, right, sep_key)
}

/// Split an internal node 50/50. Internal splits are rare and the 90/10 bias
/// materially helps only at the leaf layer.
#[must_use]
pub fn split_internal(internal: Internal) -> (Internal, Internal, Vec<u8>) {
    internal.split()
}
