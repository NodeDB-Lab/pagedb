//! Internal node operations.

use crate::Result;
use crate::errors::PagedbError;

use super::node::{
    HEADER_LEN, NodeHeader, NodeKind, body_capacity, read_u16_le, read_u64_le, slot_offset,
    validate_node_body, write_header, write_slot_offset, write_u16_le,
};

/// A separator key with the child `page_id` to its right.
#[derive(Debug, Clone)]
pub struct InternalEntry {
    pub key: Vec<u8>,
    pub right_child: u64,
}

/// Decoded internal node. `leftmost_child` is the child to the left of
/// `entries[0].key`. `entries` are sorted by key.
#[derive(Debug, Clone)]
pub struct Internal {
    pub leftmost_child: u64,
    pub entries: Vec<InternalEntry>,
}

/// Fixed bytes an internal record costs beyond its key: the `key_len` `u16`
/// and the `right_child` `u64`.
///
/// Named so the sizing used to decide whether a separator fits stays tied to
/// the layout [`Internal::encode`] actually writes.
pub(crate) const SEPARATOR_RECORD_OVERHEAD: usize = 2 + 8;

/// Bytes one slot-directory entry costs.
pub(crate) const SLOT_DIRECTORY_ENTRY_SIZE: usize = 2;

/// Encoded byte cost of one internal separator plus its slot-directory entry.
pub(crate) fn separator_entry_size(key_len: usize) -> Result<usize> {
    if key_len > u16::MAX as usize {
        return Err(PagedbError::PayloadTooLarge);
    }
    key_len
        .checked_add(SEPARATOR_RECORD_OVERHEAD)
        .and_then(|size| size.checked_add(SLOT_DIRECTORY_ENTRY_SIZE))
        .ok_or(PagedbError::PayloadTooLarge)
}

#[must_use]
pub(crate) fn separator_fits(key_len: usize, page_size: usize) -> bool {
    separator_entry_size(key_len)
        .ok()
        .and_then(|entry_size| HEADER_LEN.checked_add(entry_size))
        .is_some_and(|needed| needed <= body_capacity(page_size))
}

impl Internal {
    pub fn decode(body: &[u8]) -> Result<Self> {
        let h: NodeHeader = validate_node_body(body)?;
        if h.kind != NodeKind::Internal {
            return Err(PagedbError::node_kind_mismatch(None, "internal", "leaf"));
        }
        let prefix_len = h.prefix_len as usize;
        let mut entries = Vec::with_capacity(h.slot_count as usize);
        for i in 0..h.slot_count as usize {
            let off = slot_offset(body, prefix_len, i);
            let key_len = read_u16_le(body, off) as usize;
            let key = body[off + 2..off + 2 + key_len].to_vec();
            let right_child = read_u64_le(body, off + 2 + key_len);
            entries.push(InternalEntry { key, right_child });
        }
        Ok(Self {
            leftmost_child: h.dual_use,
            entries,
        })
    }

    pub fn encode(&self, body: &mut [u8]) -> Result<()> {
        let cap = body.len();
        let prefix_len = 0usize;
        let slot_count = self.entries.len();
        let record_bytes: usize = self
            .entries
            .iter()
            .map(|e| e.key.len() + SEPARATOR_RECORD_OVERHEAD)
            .sum();
        let slot_dir_bytes = slot_count * SLOT_DIRECTORY_ENTRY_SIZE;
        if HEADER_LEN + prefix_len + slot_dir_bytes + record_bytes > cap {
            return Err(PagedbError::PayloadTooLarge);
        }
        write_header(
            body,
            NodeKind::Internal,
            u16::try_from(slot_count)
                .map_err(|_| PagedbError::Io(std::io::Error::other("slot_count overflow")))?,
            u16::try_from(prefix_len)
                .map_err(|_| PagedbError::Io(std::io::Error::other("prefix_len overflow")))?,
            0,
            self.leftmost_child,
        );
        for b in &mut body[HEADER_LEN..cap] {
            *b = 0;
        }
        let mut tail = cap;
        for (i, e) in self.entries.iter().enumerate() {
            let rec_size = e.key.len() + SEPARATOR_RECORD_OVERHEAD;
            tail -= rec_size;
            let off = tail;
            write_u16_le(
                body,
                off,
                u16::try_from(e.key.len())
                    .map_err(|_| PagedbError::Io(std::io::Error::other("key_len overflow")))?,
            );
            body[off + 2..off + 2 + e.key.len()].copy_from_slice(&e.key);
            body[off + 2 + e.key.len()..off + 2 + e.key.len() + 8]
                .copy_from_slice(&e.right_child.to_le_bytes());
            write_slot_offset(
                body,
                prefix_len,
                i,
                u16::try_from(off).map_err(|_| {
                    PagedbError::Io(std::io::Error::other("record_offset overflow"))
                })?,
            );
        }
        Ok(())
    }

    #[must_use]
    pub fn fits(&self, page_size: usize) -> bool {
        let cap = body_capacity(page_size);
        let record_bytes: usize = self.entries.iter().map(|e| 2 + e.key.len() + 8).sum();
        let slot_dir_bytes = self.entries.len() * 2;
        HEADER_LEN + slot_dir_bytes + record_bytes <= cap
    }

    /// Insert an entry sorted by key. Updates an existing entry's `right_child`
    /// if the key already exists.
    pub fn upsert(&mut self, key: &[u8], right_child: u64) {
        match self.entries.binary_search_by(|e| e.key.as_slice().cmp(key)) {
            Ok(i) => self.entries[i].right_child = right_child,
            Err(i) => {
                self.entries.insert(
                    i,
                    InternalEntry {
                        key: key.to_vec(),
                        right_child,
                    },
                );
            }
        }
    }

    /// 50/50 split.
    #[must_use]
    pub fn split(mut self) -> (Internal, Internal, Vec<u8>) {
        let mid = self.entries.len() / 2;
        let right_entries: Vec<InternalEntry> = self.entries.split_off(mid);
        // The first key of the right side is promoted to the parent. The
        // right_child of that promoted entry becomes the leftmost_child of
        // the right internal node.
        let promoted = right_entries[0].key.clone();
        let right_leftmost = right_entries[0].right_child;
        let right = Internal {
            leftmost_child: right_leftmost,
            entries: right_entries[1..].to_vec(),
        };
        let left = Internal {
            leftmost_child: self.leftmost_child,
            entries: self.entries,
        };
        (left, right, promoted)
    }
}

/// Zero-allocation accessor over an encoded internal page body. Used on the
/// read path to descend the tree without decoding every entry into owned
/// `Vec<u8>`s. Lifetime is tied to the `PageGuard` that pins the page.
pub struct InternalAccessor<'a> {
    body: &'a [u8],
    slot_count: usize,
    leftmost_child: u64,
}

impl<'a> InternalAccessor<'a> {
    pub fn new(body: &'a [u8]) -> Result<Self> {
        let h = validate_node_body(body)?;
        if h.kind != NodeKind::Internal {
            return Err(PagedbError::node_kind_mismatch(None, "internal", "leaf"));
        }
        // Internal nodes always encode with prefix_len = 0 today; if that ever
        // changes, this accessor needs the same prefix handling as LeafAccessor.
        debug_assert_eq!(h.prefix_len, 0);
        Ok(Self {
            body,
            slot_count: h.slot_count as usize,
            leftmost_child: h.dual_use,
        })
    }

    fn entry_key(&self, idx: usize) -> &'a [u8] {
        let off = slot_offset(self.body, 0, idx);
        let key_len = read_u16_le(self.body, off) as usize;
        &self.body[off + 2..off + 2 + key_len]
    }

    fn entry_right_child(&self, idx: usize) -> u64 {
        let off = slot_offset(self.body, 0, idx);
        let key_len = read_u16_le(self.body, off) as usize;
        read_u64_le(self.body, off + 2 + key_len)
    }

    /// Descend selection: returns the child `page_id` covering `query`. Reads
    /// the slot directory in place, so descending a spine never materializes
    /// the node's keys.
    #[must_use]
    pub fn child_for(&self, query: &[u8]) -> u64 {
        // Rightmost index where entry.key <= query. Use partition_point logic
        // open-coded over slot indices to avoid materializing keys.
        let mut lo = 0usize;
        let mut hi = self.slot_count;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if self.entry_key(mid) <= query {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        if lo == 0 {
            self.leftmost_child
        } else {
            self.entry_right_child(lo - 1)
        }
    }
}
