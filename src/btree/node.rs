//! Node layout shared by leaf and internal pages.

use crate::Result;
use crate::errors::{CorruptionDetail, PagedbError};
use crate::pager::format::data_page::ENVELOPE_OVERHEAD;

/// `node_kind` byte value at offset 0 of the node body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum NodeKind {
    Internal = 0x00,
    Leaf = 0x01,
}

impl NodeKind {
    pub fn from_byte(b: u8) -> Result<Self> {
        match b {
            0x00 => Ok(Self::Internal),
            0x01 => Ok(Self::Leaf),
            _ => Err(PagedbError::corruption(
                CorruptionDetail::HeaderUnverifiable,
            )),
        }
    }

    #[must_use]
    pub fn as_byte(self) -> u8 {
        self as u8
    }
}

pub const HEADER_LEN: usize = 24;
pub const OFF_NODE_KIND: usize = 0;
pub const OFF_SLOT_COUNT: usize = 2;
pub const OFF_PREFIX_LEN: usize = 4;
pub const OFF_LEFT_SIBLING: usize = 8;
pub const OFF_DUAL_USE: usize = 16;

/// Body capacity for a node — the bytes between the Format-A envelope header
/// and the AEAD tag.
#[must_use]
pub const fn body_capacity(page_size: usize) -> usize {
    page_size - ENVELOPE_OVERHEAD
}

/// Read a slot directory entry (record offset) from a body.
#[must_use]
pub fn slot_offset(body: &[u8], prefix_len: usize, slot_index: usize) -> usize {
    let off = HEADER_LEN + prefix_len + slot_index * 2;
    u16::from_le_bytes([body[off], body[off + 1]]) as usize
}

pub fn write_slot_offset(body: &mut [u8], prefix_len: usize, slot_index: usize, value: u16) {
    let off = HEADER_LEN + prefix_len + slot_index * 2;
    body[off..off + 2].copy_from_slice(&value.to_le_bytes());
}

#[must_use]
pub fn read_u16_le(body: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([body[offset], body[offset + 1]])
}

#[must_use]
pub fn read_u64_le(body: &[u8], offset: usize) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&body[offset..offset + 8]);
    u64::from_le_bytes(b)
}

pub fn write_u16_le(body: &mut [u8], offset: usize, value: u16) {
    body[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

pub fn write_u64_le(body: &mut [u8], offset: usize, value: u64) {
    body[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

/// `value_len` marker meaning the record stores an overflow reference
/// (`u64` total length + `u64` root page id) instead of inline bytes.
pub const OVERFLOW_SENTINEL: u16 = 0xFFFF;

/// Parsed common header fields.
#[derive(Debug, Clone, Copy)]
pub struct NodeHeader {
    pub kind: NodeKind,
    pub slot_count: u16,
    pub prefix_len: u16,
    pub left_sibling: u64,
    pub dual_use: u64,
}

pub fn read_header(body: &[u8]) -> Result<NodeHeader> {
    if body.len() < HEADER_LEN {
        return Err(PagedbError::corruption(
            CorruptionDetail::HeaderUnverifiable,
        ));
    }
    let kind = NodeKind::from_byte(body[OFF_NODE_KIND])?;
    let slot_count = read_u16_le(body, OFF_SLOT_COUNT);
    let prefix_len = read_u16_le(body, OFF_PREFIX_LEN);
    let left_sibling = read_u64_le(body, OFF_LEFT_SIBLING);
    let dual_use = read_u64_le(body, OFF_DUAL_USE);
    Ok(NodeHeader {
        kind,
        slot_count,
        prefix_len,
        left_sibling,
        dual_use,
    })
}

/// Structurally validate an encoded node body, returning its header.
///
/// A page body reaches this code already authenticated, so its bytes are what
/// some holder of the key wrote — but *not* necessarily what a correct writer
/// would have written. `prefix_len`, `slot_count`, and every slot-directory
/// entry are attacker- or bug-controlled `u16`s that the decoders and the
/// zero-copy accessors use directly as slice indices. Without this pass a
/// malformed-but-authenticated page panics the library (an out-of-range slice
/// index) instead of surfacing as [`CorruptionDetail::HeaderUnverifiable`],
/// which is a strictly worse failure than the one it would report.
///
/// Every constructor that turns raw bytes into a node runs this first, so the
/// unchecked indexing downstream is sound by construction. Validation is
/// extent-only: it proves each record lies inside the body, not that the
/// records are semantically sensible. Overlapping or nonsensical offsets still
/// decode to garbage — authenticated garbage is the writer's problem — but they
/// cannot read out of bounds.
pub fn validate_node_body(body: &[u8]) -> Result<NodeHeader> {
    let header = read_header(body)?;
    let prefix_len = header.prefix_len as usize;
    let slot_count = header.slot_count as usize;

    // Header, key prefix, and slot directory must all fit.
    let directory_end = HEADER_LEN
        .checked_add(prefix_len)
        .and_then(|end| end.checked_add(slot_count.checked_mul(2)?))
        .ok_or_else(malformed)?;
    if directory_end > body.len() {
        return Err(malformed());
    }

    for slot_index in 0..slot_count {
        // In range: the directory extent was just proven to fit.
        let offset = slot_offset(body, prefix_len, slot_index);
        match header.kind {
            NodeKind::Leaf => validate_leaf_record(body, offset)?,
            NodeKind::Internal => validate_internal_record(body, offset)?,
        }
    }
    Ok(header)
}

/// `u16 suffix_len ‖ suffix ‖ u16 value_len ‖ (inline value | u64 total_len ‖ u64 root_page_id)`
fn validate_leaf_record(body: &[u8], offset: usize) -> Result<()> {
    let after_suffix_len = field_end(body, offset, 2)?;
    let suffix_len = read_u16_le(body, offset) as usize;
    let after_suffix = field_end(body, after_suffix_len, suffix_len)?;
    let after_value_len = field_end(body, after_suffix, 2)?;
    let value_len_raw = read_u16_le(body, after_suffix);
    if value_len_raw == OVERFLOW_SENTINEL {
        field_end(body, after_value_len, 16)?;
    } else {
        field_end(body, after_value_len, value_len_raw as usize)?;
    }
    Ok(())
}

/// `u16 key_len ‖ key ‖ u64 right_child`
fn validate_internal_record(body: &[u8], offset: usize) -> Result<()> {
    let after_key_len = field_end(body, offset, 2)?;
    let key_len = read_u16_le(body, offset) as usize;
    let after_key = field_end(body, after_key_len, key_len)?;
    field_end(body, after_key, 8)?;
    Ok(())
}

/// End offset of a `len`-byte field starting at `start`, or a corruption error
/// if it overflows or runs past the body.
fn field_end(body: &[u8], start: usize, len: usize) -> Result<usize> {
    let end = start.checked_add(len).ok_or_else(malformed)?;
    if end > body.len() {
        return Err(malformed());
    }
    Ok(end)
}

fn malformed() -> PagedbError {
    PagedbError::corruption(CorruptionDetail::HeaderUnverifiable)
}

pub fn write_header(
    body: &mut [u8],
    kind: NodeKind,
    slot_count: u16,
    prefix_len: u16,
    left_sibling: u64,
    dual_use: u64,
) {
    body[OFF_NODE_KIND] = kind.as_byte();
    body[1] = 0;
    write_u16_le(body, OFF_SLOT_COUNT, slot_count);
    write_u16_le(body, OFF_PREFIX_LEN, prefix_len);
    write_u16_le(body, 6, 0);
    write_u64_le(body, OFF_LEFT_SIBLING, left_sibling);
    write_u64_le(body, OFF_DUAL_USE, dual_use);
}

#[cfg(test)]
mod tests {
    use super::*;

    const CAP: usize = 4056;

    fn assert_malformed(body: &[u8], label: &str) {
        assert!(
            matches!(
                validate_node_body(body),
                Err(PagedbError::Corruption(
                    CorruptionDetail::HeaderUnverifiable
                ))
            ),
            "{label}: expected HeaderUnverifiable"
        );
    }

    #[test]
    fn rejects_header_shorter_than_the_fixed_fields() {
        assert_malformed(&[0u8; HEADER_LEN - 1], "truncated header");
    }

    #[test]
    fn rejects_prefix_or_directory_past_the_body() {
        let mut body = vec![0u8; CAP];
        write_header(&mut body, NodeKind::Leaf, 0, u16::MAX, 0, 0);
        assert_malformed(&body, "prefix_len past body");

        let mut body = vec![0u8; CAP];
        write_header(&mut body, NodeKind::Leaf, u16::MAX, 0, 0, 0);
        assert_malformed(&body, "slot directory past body");
    }

    #[test]
    fn rejects_records_that_leave_the_body() {
        // Slot points outside the body entirely.
        let mut body = vec![0u8; CAP];
        write_header(&mut body, NodeKind::Leaf, 1, 0, 0, 0);
        write_slot_offset(&mut body, 0, 0, u16::MAX);
        assert_malformed(&body, "leaf slot past body");

        // Slot is in range but the suffix it declares is not.
        let mut body = vec![0u8; CAP];
        write_header(&mut body, NodeKind::Leaf, 1, 0, 0, 0);
        let offset = CAP - 4;
        write_slot_offset(&mut body, 0, 0, u16::try_from(offset).unwrap());
        write_u16_le(&mut body, offset, 600);
        assert_malformed(&body, "leaf suffix past body");

        // Internal records carry a trailing u64 child pointer that must fit.
        let mut body = vec![0u8; CAP];
        write_header(&mut body, NodeKind::Internal, 1, 0, 0, 0);
        write_slot_offset(&mut body, 0, 0, u16::try_from(CAP - 3).unwrap());
        assert_malformed(&body, "internal child pointer past body");
    }

    #[test]
    fn accepts_a_well_formed_empty_node() {
        let mut body = vec![0u8; CAP];
        write_header(&mut body, NodeKind::Leaf, 0, 0, 0, 0);
        let header = validate_node_body(&body).expect("empty leaf is well formed");
        assert_eq!(header.kind, NodeKind::Leaf);
        assert_eq!(header.slot_count, 0);
    }
}
