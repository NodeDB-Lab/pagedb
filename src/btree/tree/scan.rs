//! Range, reverse, and prefix scans.

use crate::Result;
use crate::vfs::Vfs;

use super::core::{BTree, SeenPageIds};

/// Duplicate-leaf detector spanning one whole forward scan.
///
/// Every scan below is a loop over `next_leaf_after`, and that function builds
/// a fresh descent guard per call, seeded only from the path it was handed. So
/// it can prove one *step* does not revisit a page, and cannot see the scan as
/// a whole revisiting a leaf it already yielded.
///
/// That gap is reachable from a single authenticated internal node, because
/// the leaf successor is parent-mediated and resolves a child by its first
/// occurrence: a node whose `leftmost_child` is `A` and whose entries are
/// `[k1 → B, k2 → A]` answers "after A comes B" and "after B comes A". Each
/// step is individually acyclic and each page authenticates; the scan simply
/// alternates forever. Only a guard that lives as long as the scan ends it.
///
/// A healthy tree visits each leaf exactly once in key order, so this never
/// fires on a well-formed scan.
fn scan_guard() -> SeenPageIds {
    SeenPageIds::new("btree_scan")
}

impl<V: Vfs> BTree<V> {
    /// Forward range scan: `start` inclusive, `end` exclusive.
    ///
    /// Parent-mediated traversal: walks the tree via internal nodes to find
    /// each successive leaf, rather than chasing leaf sibling pointers. This
    /// lets the write path skip sibling-pointer `CoW` (saves ~2 leaf rewrites
    /// per put) at the cost of one extra internal-node lookup per leaf
    /// boundary crossed during a scan.
    pub async fn collect_range(&self, start: &[u8], end: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        if self.root_page_id == 0 {
            return Ok(Vec::new());
        }
        let mut path = self.path_to_leaf_for_key(start).await?;
        let mut seen_leaves = scan_guard();
        let mut out: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        loop {
            let leaf_id = *path.last().expect("non-empty path");
            seen_leaves.insert(leaf_id)?;
            let leaf = self.read_leaf(leaf_id).await?;
            for (k, v) in &leaf.records {
                if k.as_slice() >= end {
                    return Ok(out);
                }
                if k.as_slice() >= start {
                    let val = self.resolve_leaf_value(v).await?;
                    out.push((k.clone(), val));
                }
            }
            match self.next_leaf_after(&path).await? {
                Some(next_path) => path = next_path,
                None => return Ok(out),
            }
        }
    }

    /// Collect every key-value pair in the tree, in ascending key order.
    ///
    /// Deliberately expressed as an unbounded traversal rather than a range
    /// scan against an invented maximum key. Keys are arbitrary byte strings
    /// with no reserved sentinel and no length ceiling, so *no* concrete upper
    /// bound is beyond the valid key domain: a bounded "scan everything" would
    /// silently drop records at the top of the keyspace (`[0xFF; N]` and any
    /// key extending it). Callers that need the whole tree must use this.
    pub async fn collect_all(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        if self.root_page_id == 0 {
            return Ok(Vec::new());
        }
        // The empty key sorts below every stored key, so the descent lands on
        // the leftmost leaf.
        let mut path = self.path_to_leaf_for_key(&[]).await?;
        let mut seen_leaves = scan_guard();
        let mut out: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        loop {
            let leaf_id = *path.last().expect("non-empty path");
            seen_leaves.insert(leaf_id)?;
            let leaf = self.read_leaf(leaf_id).await?;
            for (k, v) in &leaf.records {
                let val = self.resolve_leaf_value(v).await?;
                out.push((k.clone(), val));
            }
            match self.next_leaf_after(&path).await? {
                Some(next_path) => path = next_path,
                None => return Ok(out),
            }
        }
    }

    /// Collect at most `limit` records at or after `start`, in ascending key
    /// order.
    ///
    /// The bounded counterpart to [`Self::collect_all`], for callers that must
    /// traverse a whole tree without holding it in memory at once. Like
    /// `collect_all` it has no upper key bound, for the same reason: no
    /// concrete maximum key is outside the valid domain, so a bounded "scan to
    /// the end" would silently drop records at the top of the keyspace.
    ///
    /// Resume by passing the last returned key with a `0x00` byte appended.
    /// That is the immediate successor in the key ordering — no key can sort
    /// strictly between `k` and `k ‖ 0x00` — so paging this way never skips a
    /// record and never returns one twice. A short batch means the tree ended.
    pub async fn collect_batch_from(
        &self,
        start: &[u8],
        limit: usize,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        if self.root_page_id == 0 || limit == 0 {
            return Ok(Vec::new());
        }
        let mut path = self.path_to_leaf_for_key(start).await?;
        let mut seen_leaves = scan_guard();
        let mut out: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(limit);
        loop {
            let leaf_id = *path.last().expect("non-empty path");
            seen_leaves.insert(leaf_id)?;
            let leaf = self.read_leaf(leaf_id).await?;
            for (k, v) in &leaf.records {
                if k.as_slice() < start {
                    continue;
                }
                if out.len() == limit {
                    return Ok(out);
                }
                let val = self.resolve_leaf_value(v).await?;
                out.push((k.clone(), val));
            }
            if out.len() == limit {
                return Ok(out);
            }
            match self.next_leaf_after(&path).await? {
                Some(next_path) => path = next_path,
                None => return Ok(out),
            }
        }
    }

    /// Collect at most `limit` records at or after `start` whose keys still
    /// carry `prefix`, in ascending key order.
    ///
    /// The bounded counterpart to [`Self::scan_prefix`]. Rows sharing a prefix
    /// sort contiguously, so the first key outside it ends the range — the scan
    /// stops there rather than reading the rest of the tree.
    ///
    /// Resume as with [`Self::collect_batch_from`]: pass the last returned key
    /// with a `0x00` byte appended. A batch shorter than `limit` means the
    /// prefix range ended.
    pub async fn collect_prefix_batch_from(
        &self,
        prefix: &[u8],
        start: &[u8],
        limit: usize,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let mut batch = self.collect_batch_from(start, limit).await?;
        if let Some(end) = batch.iter().position(|(key, _)| !key.starts_with(prefix)) {
            batch.truncate(end);
        }
        Ok(batch)
    }

    /// Return the smallest key in the tree, or `None` if the tree is empty.
    /// Descends the leftmost spine only — O(tree height), not O(tree size).
    pub async fn first_key(&self) -> Result<Option<Vec<u8>>> {
        if self.root_page_id == 0 {
            return Ok(None);
        }
        // The empty key sorts below every stored key, so the descent lands on
        // the leftmost leaf.
        let path = self.path_to_leaf_for_key(&[]).await?;
        let leaf_id = *path.last().expect("non-empty path");
        let leaf = self.read_leaf(leaf_id).await?;
        Ok(leaf.records.first().map(|(k, _)| k.clone()))
    }

    /// Reverse range scan: `start` inclusive, `end` exclusive. Returns results
    /// in descending key order. Collects matching records forward then reverses.
    pub async fn scan_rev(&self, start: &[u8], end: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let mut forward = self.collect_range(start, end).await?;
        forward.reverse();
        Ok(forward)
    }

    /// Prefix scan: returns all records whose key starts with `prefix`, in
    /// ascending order.
    pub async fn scan_prefix(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        if self.root_page_id == 0 {
            return Ok(Vec::new());
        }
        let mut path = self.path_to_leaf_for_key(prefix).await?;
        let mut seen_leaves = scan_guard();
        let mut out: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        loop {
            let leaf_id = *path.last().expect("non-empty path");
            seen_leaves.insert(leaf_id)?;
            let leaf = self.read_leaf(leaf_id).await?;
            let mut past_prefix = false;
            for (k, v) in &leaf.records {
                if k.as_slice() < prefix {
                    continue;
                }
                if !k.starts_with(prefix) {
                    past_prefix = true;
                    break;
                }
                let val = self.resolve_leaf_value(v).await?;
                out.push((k.clone(), val));
            }
            if past_prefix {
                return Ok(out);
            }
            match self.next_leaf_after(&path).await? {
                Some(next_path) => path = next_path,
                None => return Ok(out),
            }
        }
    }
}
