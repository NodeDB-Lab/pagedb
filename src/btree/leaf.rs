//! Leaf node operations.

use crate::Result;
use crate::errors::PagedbError;

use super::node::{
    HEADER_LEN, NodeHeader, NodeKind, body_capacity, read_header, read_u16_le, read_u64_le,
    slot_offset, write_header, write_slot_offset, write_u16_le, write_u64_le,
};

/// Value stored in a leaf record — either inline bytes or a pointer to an
/// overflow chain.
#[derive(Debug, Clone)]
pub enum LeafValue {
    Inline(Vec<u8>),
    Overflow { total_len: u64, root_page_id: u64 },
}

impl LeafValue {
    /// Number of bytes this value occupies in the encoded record body (after
    /// the key suffix):  2-byte `value_len` field plus the payload.
    #[must_use]
    pub fn encoded_size(&self) -> usize {
        match self {
            Self::Inline(v) => 2 + v.len(),
            // sentinel u16 + total_len u64 + root_page_id u64
            Self::Overflow { .. } => 2 + 8 + 8,
        }
    }
}

/// Decoded leaf node. Keys and values held in sorted order.
#[derive(Debug, Clone)]
pub struct Leaf {
    pub left_sibling: u64,
    pub right_sibling: u64,
    pub records: Vec<(Vec<u8>, LeafValue)>,
}

/// Sentinel `value_len` that signals an overflow record.
const OVERFLOW_SENTINEL: u16 = 0xFFFF;

impl Leaf {
    #[must_use]
    pub fn new() -> Self {
        Self {
            left_sibling: 0,
            right_sibling: 0,
            records: Vec::new(),
        }
    }

    pub fn decode(body: &[u8]) -> Result<Self> {
        let h: NodeHeader = read_header(body)?;
        if h.kind != NodeKind::Leaf {
            return Err(PagedbError::corruption(
                crate::errors::CorruptionDetail::HeaderUnverifiable,
            ));
        }
        let prefix_len = h.prefix_len as usize;
        let prefix_bytes = body[HEADER_LEN..HEADER_LEN + prefix_len].to_vec();
        let mut records = Vec::with_capacity(h.slot_count as usize);
        for i in 0..h.slot_count as usize {
            let off = slot_offset(body, prefix_len, i);
            let suffix_len = read_u16_le(body, off) as usize;
            let suffix = &body[off + 2..off + 2 + suffix_len];
            let value_len_raw = read_u16_le(body, off + 2 + suffix_len);
            let value = if value_len_raw == OVERFLOW_SENTINEL {
                let total_len = read_u64_le(body, off + 2 + suffix_len + 2);
                let root_page_id = read_u64_le(body, off + 2 + suffix_len + 2 + 8);
                LeafValue::Overflow {
                    total_len,
                    root_page_id,
                }
            } else {
                let vlen = value_len_raw as usize;
                let v = body[off + 2 + suffix_len + 2..off + 2 + suffix_len + 2 + vlen].to_vec();
                LeafValue::Inline(v)
            };
            // Reconstruct full key by prepending the common prefix.
            let mut full_key = prefix_bytes.clone();
            full_key.extend_from_slice(suffix);
            records.push((full_key, value));
        }
        Ok(Self {
            left_sibling: h.left_sibling,
            right_sibling: h.dual_use,
            records,
        })
    }

    /// Encode into a body buffer. The slice must be exactly
    /// `body_capacity(page_size)` bytes.
    pub fn encode(&self, body: &mut [u8]) -> Result<()> {
        let cap = body.len();
        let prefix = lcp(&self.records);
        let prefix_len = prefix.len();
        let slot_count = self.records.len();

        // Compute total size needed.
        let record_bytes: usize = self
            .records
            .iter()
            .map(|(k, v)| {
                let suffix_len = k.len().saturating_sub(prefix_len);
                2 + suffix_len + v.encoded_size()
            })
            .sum();
        let slot_dir_bytes = slot_count * 2;
        let needed = HEADER_LEN + prefix_len + slot_dir_bytes + record_bytes;
        if needed > cap {
            return Err(PagedbError::PayloadTooLarge);
        }

        write_header(
            body,
            NodeKind::Leaf,
            u16::try_from(slot_count)
                .map_err(|_| PagedbError::Io(std::io::Error::other("slot_count overflow")))?,
            u16::try_from(prefix_len)
                .map_err(|_| PagedbError::Io(std::io::Error::other("prefix_len overflow")))?,
            self.left_sibling,
            self.right_sibling,
        );

        for b in &mut body[HEADER_LEN..cap] {
            *b = 0;
        }

        // Write prefix bytes.
        body[HEADER_LEN..HEADER_LEN + prefix_len].copy_from_slice(&prefix);

        let mut tail = cap;
        for (i, (k, v)) in self.records.iter().enumerate() {
            let suffix = &k[prefix_len..];
            let rec_size = 2 + suffix.len() + v.encoded_size();
            tail -= rec_size;
            let off = tail;
            write_u16_le(
                body,
                off,
                u16::try_from(suffix.len())
                    .map_err(|_| PagedbError::Io(std::io::Error::other("suffix_len overflow")))?,
            );
            body[off + 2..off + 2 + suffix.len()].copy_from_slice(suffix);
            let after_key = off + 2 + suffix.len();
            match v {
                LeafValue::Inline(val) => {
                    write_u16_le(
                        body,
                        after_key,
                        u16::try_from(val.len()).map_err(|_| {
                            PagedbError::Io(std::io::Error::other("value_len overflow"))
                        })?,
                    );
                    body[after_key + 2..after_key + 2 + val.len()].copy_from_slice(val);
                }
                LeafValue::Overflow {
                    total_len,
                    root_page_id,
                } => {
                    write_u16_le(body, after_key, OVERFLOW_SENTINEL);
                    write_u64_le(body, after_key + 2, *total_len);
                    write_u64_le(body, after_key + 2 + 8, *root_page_id);
                }
            }
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

    /// Returns the index where `key` is or would be inserted.
    pub fn position(&self, key: &[u8]) -> std::result::Result<usize, usize> {
        self.records
            .binary_search_by(|(k, _)| k.as_slice().cmp(key))
    }

    /// Insert or overwrite. Returns `(is_new, old_value_if_replaced)`.
    pub fn upsert(&mut self, key: &[u8], value: LeafValue) -> (bool, Option<LeafValue>) {
        match self.position(key) {
            Ok(i) => {
                let old = std::mem::replace(&mut self.records[i].1, value);
                (false, Some(old))
            }
            Err(i) => {
                self.records.insert(i, (key.to_vec(), value));
                (true, None)
            }
        }
    }

    /// Remove a key if present. Returns the removed value if any.
    pub fn remove(&mut self, key: &[u8]) -> Option<LeafValue> {
        match self.position(key) {
            Ok(i) => {
                let (_, v) = self.records.remove(i);
                Some(v)
            }
            Err(_) => None,
        }
    }

    #[must_use]
    pub fn get(&self, key: &[u8]) -> Option<&LeafValue> {
        match self.position(key) {
            Ok(i) => Some(&self.records[i].1),
            Err(_) => None,
        }
    }

    /// True iff encoding `self` into a body of `page_size - 40` bytes fits.
    #[must_use]
    pub fn fits(&self, page_size: usize) -> bool {
        let cap = body_capacity(page_size);
        let prefix_len = lcp(&self.records).len();
        let record_bytes: usize = self
            .records
            .iter()
            .map(|(k, v)| {
                let suffix_len = k.len().saturating_sub(prefix_len);
                2 + suffix_len + v.encoded_size()
            })
            .sum();
        let slot_dir_bytes = self.records.len() * 2;
        HEADER_LEN + prefix_len + slot_dir_bytes + record_bytes <= cap
    }
}

impl Default for Leaf {
    fn default() -> Self {
        Self::new()
    }
}

/// Borrowed view of one leaf value (zero-copy).
#[derive(Debug)]
pub enum LeafValueRef<'a> {
    Inline(&'a [u8]),
    Overflow { total_len: u64, root_page_id: u64 },
}

/// Zero-allocation accessor over an encoded leaf page body. Used on the read
/// path (`Tree::get` and friends) to avoid the per-record `Vec` allocations
/// performed by [`Leaf::decode`]. Holds a borrow of the page body; lifetime is
/// tied to the [`PageGuard`](crate::pager::PageGuard) that pins the cache page.
pub struct LeafAccessor<'a> {
    body: &'a [u8],
    prefix_len: usize,
    slot_count: usize,
}

impl<'a> LeafAccessor<'a> {
    /// Parse the leaf header and return an accessor borrowing `body`. Performs
    /// no record allocations and does not touch the slot directory or records.
    pub fn new(body: &'a [u8]) -> Result<Self> {
        let h = read_header(body)?;
        if h.kind != NodeKind::Leaf {
            return Err(PagedbError::corruption(
                crate::errors::CorruptionDetail::HeaderUnverifiable,
            ));
        }
        Ok(Self {
            body,
            prefix_len: h.prefix_len as usize,
            slot_count: h.slot_count as usize,
        })
    }

    #[must_use]
    pub fn slot_count(&self) -> usize {
        self.slot_count
    }

    fn prefix(&self) -> &'a [u8] {
        &self.body[HEADER_LEN..HEADER_LEN + self.prefix_len]
    }

    /// Borrow the suffix bytes for slot `idx`.
    fn suffix(&self, idx: usize) -> &'a [u8] {
        let off = slot_offset(self.body, self.prefix_len, idx);
        let suffix_len = read_u16_le(self.body, off) as usize;
        &self.body[off + 2..off + 2 + suffix_len]
    }

    /// Compare the full key at slot `idx` (`prefix ‖ suffix`) against `query`.
    fn cmp_slot_to_query(&self, idx: usize, query: &[u8]) -> std::cmp::Ordering {
        use std::cmp::Ordering;
        let prefix = self.prefix();
        let suffix = self.suffix(idx);
        // Compare prefix vs query[..min(prefix.len(), query.len())].
        let n = prefix.len().min(query.len());
        match prefix[..n].cmp(&query[..n]) {
            Ordering::Equal => {
                if query.len() <= prefix.len() {
                    // Query has no bytes past the prefix range we compared.
                    if query.len() < prefix.len() || !suffix.is_empty() {
                        Ordering::Greater
                    } else {
                        Ordering::Equal
                    }
                } else {
                    // prefix fully matches; compare suffix vs query tail.
                    suffix.cmp(&query[prefix.len()..])
                }
            }
            non_eq => non_eq,
        }
    }

    /// Binary-search for `query`. Returns `Some(slot_idx)` on exact match.
    #[must_use]
    pub fn find(&self, query: &[u8]) -> Option<usize> {
        use std::cmp::Ordering;
        let mut lo = 0usize;
        let mut hi = self.slot_count;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            match self.cmp_slot_to_query(mid, query) {
                Ordering::Less => lo = mid + 1,
                Ordering::Greater => hi = mid,
                Ordering::Equal => return Some(mid),
            }
        }
        None
    }

    /// Decode the value at slot `idx`. Inline values borrow from the page body;
    /// overflow values return only the chain root + total length.
    pub fn value_at(&self, idx: usize) -> Result<LeafValueRef<'a>> {
        let off = slot_offset(self.body, self.prefix_len, idx);
        let suffix_len = read_u16_le(self.body, off) as usize;
        let after_key = off + 2 + suffix_len;
        let value_len_raw = read_u16_le(self.body, after_key);
        if value_len_raw == OVERFLOW_SENTINEL {
            let total_len = read_u64_le(self.body, after_key + 2);
            let root_page_id = read_u64_le(self.body, after_key + 2 + 8);
            Ok(LeafValueRef::Overflow {
                total_len,
                root_page_id,
            })
        } else {
            let vlen = value_len_raw as usize;
            Ok(LeafValueRef::Inline(
                &self.body[after_key + 2..after_key + 2 + vlen],
            ))
        }
    }
}

/// Longest common prefix of all keys in the record slice.
/// Returns the full key when `records.len() == 1`; empty when
/// `records.len() == 0`.
#[must_use]
pub fn lcp(records: &[(Vec<u8>, LeafValue)]) -> Vec<u8> {
    match records.len() {
        0 => Vec::new(),
        1 => records[0].0.clone(),
        _ => {
            let first = &records[0].0;
            let last = &records[records.len() - 1].0;
            // Since records are sorted, first and last bracket the range.
            let common_len = first
                .iter()
                .zip(last.iter())
                .take_while(|(a, b)| a == b)
                .count();
            first[..common_len].to_vec()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pager::format::data_page::ENVELOPE_OVERHEAD;

    const PAGE: usize = 4096;
    const CAP: usize = PAGE - ENVELOPE_OVERHEAD;

    fn make_body() -> Vec<u8> {
        vec![0u8; CAP]
    }

    #[test]
    fn inline_round_trip() {
        let mut leaf = Leaf::new();
        leaf.upsert(b"hello", LeafValue::Inline(b"world".to_vec()));
        leaf.upsert(b"hello2", LeafValue::Inline(b"world2".to_vec()));
        let mut body = make_body();
        leaf.encode(&mut body).unwrap();
        let decoded = Leaf::decode(&body).unwrap();
        assert_eq!(decoded.records.len(), 2);
        match &decoded.records[0].1 {
            LeafValue::Inline(v) => assert_eq!(v, b"world"),
            LeafValue::Overflow { .. } => panic!("expected inline"),
        }
    }

    #[test]
    fn overflow_round_trip() {
        let mut leaf = Leaf::new();
        leaf.upsert(
            b"bigkey",
            LeafValue::Overflow {
                total_len: 99999,
                root_page_id: 42,
            },
        );
        let mut body = make_body();
        leaf.encode(&mut body).unwrap();
        let decoded = Leaf::decode(&body).unwrap();
        match &decoded.records[0].1 {
            LeafValue::Overflow {
                total_len,
                root_page_id,
            } => {
                assert_eq!(*total_len, 99999);
                assert_eq!(*root_page_id, 42);
            }
            LeafValue::Inline(_) => panic!("expected overflow"),
        }
    }

    #[test]
    fn prefix_compression_applied() {
        let mut leaf = Leaf::new();
        leaf.upsert(b"prefix/aaa", LeafValue::Inline(b"v1".to_vec()));
        leaf.upsert(b"prefix/bbb", LeafValue::Inline(b"v2".to_vec()));
        leaf.upsert(b"prefix/ccc", LeafValue::Inline(b"v3".to_vec()));
        let mut body = make_body();
        leaf.encode(&mut body).unwrap();
        // Check prefix_len in header is 7 ("prefix/")
        let h = super::super::node::read_header(&body).unwrap();
        assert_eq!(h.prefix_len, 7);
        let decoded = Leaf::decode(&body).unwrap();
        assert_eq!(decoded.records[0].0, b"prefix/aaa");
        assert_eq!(decoded.records[1].0, b"prefix/bbb");
        assert_eq!(decoded.records[2].0, b"prefix/ccc");
    }

    #[test]
    fn lcp_edge_cases() {
        let records: Vec<(Vec<u8>, LeafValue)> = Vec::new();
        assert_eq!(lcp(&records), b"");
        let one = vec![(b"hello".to_vec(), LeafValue::Inline(vec![]))];
        assert_eq!(lcp(&one), b"hello");
        let two = vec![
            (b"abc".to_vec(), LeafValue::Inline(vec![])),
            (b"abd".to_vec(), LeafValue::Inline(vec![])),
        ];
        assert_eq!(lcp(&two), b"ab");
    }
}
