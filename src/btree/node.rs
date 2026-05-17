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
