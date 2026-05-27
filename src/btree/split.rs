//! Node split policy. Leaf splits use a 90/10 bias when the inserting key
//! is strictly greater than all existing keys in the leaf (monotonic-insert
//! detection); 50/50 otherwise. Internal node splits always use 50/50.

use super::internal::Internal;
use super::leaf::Leaf;

/// Split a leaf into two halves that each fit within `page_size`.
///
/// `monotonic` controls the initial bias: `true` → 90/10 (right-most insert
/// pattern), `false` → 50/50. After the initial split the resulting halves are
/// checked for fit; if the left half still overflows, the split point is walked
/// leftward one record at a time until both halves fit. This guarantees the
/// caller never receives a half that would fail `leaf.encode()`.
///
/// Returns `(left, right, separator_key)`. Caller wires sibling pointers and
/// allocates `page_ids`.
#[must_use]
pub fn split_leaf(mut leaf: Leaf, monotonic: bool, page_size: usize) -> (Leaf, Leaf, Vec<u8>) {
    let total = leaf.records.len();
    // Initial split-point guess.
    let mut split_at = if monotonic {
        // 90% to the left, at least 1 to the right.
        let n = (total * 9) / 10;
        n.min(total - 1).max(1)
    } else {
        total / 2
    };

    // Adjust split_at until both halves fit.  Walk split_at left (fewer
    // records on the left) until the left slice fits.  Then verify the right
    // slice fits too; if not, split_at must move right instead — in the
    // extreme case every record is a wide inline value and we just need the
    // largest half that fits.
    loop {
        // Guarantee at least 1 record on each side.
        let split_at_clamped = split_at.min(total - 1).max(1);
        if split_at_clamped != split_at {
            split_at = split_at_clamped;
        }

        let left_fits = Leaf::slice_fits(&leaf.records[..split_at], page_size);
        let right_fits = Leaf::slice_fits(&leaf.records[split_at..], page_size);

        if left_fits && right_fits {
            break;
        }

        if !left_fits && split_at > 1 {
            split_at -= 1;
            continue;
        }
        if !right_fits && split_at < total - 1 {
            split_at += 1;
            continue;
        }
        // Cannot satisfy both constraints (e.g. a single record that is too
        // large on its own — an invariant violation that overflow encoding
        // should have prevented).  Fall through with the best split we have.
        break;
    }

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
