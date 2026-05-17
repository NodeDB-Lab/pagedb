//! Bounded page cache with SIEVE eviction, pin / unpin / dirty tracking. The
//! eviction policy is a private impl detail; the public surface is stable.
//!
//! SIEVE (Zhang et al., NSDI 2024) replaces classic LRU. The hit path is a
//! single bit set — no list-shuffle, no `O(N)` order maintenance. Eviction
//! walks a "hand" through a FIFO of insertions, clearing `visited` bits and
//! evicting the first unvisited (and unpinned, undirty) entry.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

/// File-identity discriminator for the cache key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum FileKey {
    Main,
    Segment([u8; 16]),
}

/// Bytes plus pin count. `bytes` holds the decrypted full-page buffer
/// (envelope header + body slot + tag slot). Body access goes through the
/// helpers in `format::data_page`.
///
/// `bytes` is logically immutable for the page's cache lifetime — set once at
/// insert, never mutated. Mutation happens by replacing the whole `Arc<Page>`
/// in the cache map.
pub struct Page {
    pub bytes: Vec<u8>,
    /// Page kind recorded at write time; used by the Pager flush path to
    /// reconstruct the correct AAD for each dirty page.
    pub kind_byte: u8,
    /// Realm that owns this cached plaintext. Used by the Pager read path to
    /// reject cross-realm cache hits without a VFS round-trip.
    pub realm_id_bytes: [u8; 16],
}

impl Page {
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            kind_byte: 0,
            realm_id_bytes: [0u8; 16],
        }
    }

    #[must_use]
    pub fn new_with_kind(bytes: Vec<u8>, kind_byte: u8) -> Self {
        Self {
            bytes,
            kind_byte,
            realm_id_bytes: [0u8; 16],
        }
    }

    #[must_use]
    pub fn new_with_meta(bytes: Vec<u8>, kind_byte: u8, realm_id_bytes: [u8; 16]) -> Self {
        Self {
            bytes,
            kind_byte,
            realm_id_bytes,
        }
    }
}

/// Node in the SIEVE FIFO. `prev` points toward the tail (older), `next`
/// toward the head (newer). The hand walks tail→head via `next`.
struct Node {
    key: (FileKey, u64),
    page: Arc<Page>,
    visited: bool,
    prev: Option<usize>,
    next: Option<usize>,
}

/// Bounded page cache with SIEVE eviction. Pinned and dirty entries are
/// skipped by the eviction hand.
pub struct PageCache {
    capacity: usize,
    map: HashMap<(FileKey, u64), usize>,
    /// Slab of nodes. `None` slots are free and recorded in `free`.
    slab: Vec<Option<Node>>,
    free: Vec<usize>,
    head: Option<usize>,
    tail: Option<usize>,
    /// SIEVE hand. Walks tail→head via `next`. `None` means "start from tail
    /// on next eviction"; after wrapping past head it is reset to `None`.
    hand: Option<usize>,
    pins: HashMap<(FileKey, u64), u32>,
    dirty: BTreeSet<(FileKey, u64)>,
}

impl PageCache {
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        let cap = capacity.max(1);
        Self {
            capacity: cap,
            map: HashMap::with_capacity(cap),
            slab: Vec::with_capacity(cap),
            free: Vec::new(),
            head: None,
            tail: None,
            hand: None,
            pins: HashMap::new(),
            dirty: BTreeSet::new(),
        }
    }

    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Lookup. Sets the `visited` bit on hit; does not touch the FIFO order.
    pub fn get(&mut self, key: (FileKey, u64)) -> Option<Arc<Page>> {
        let idx = *self.map.get(&key)?;
        let node = self.slab[idx].as_mut().expect("indexed node alive");
        node.visited = true;
        Some(node.page.clone())
    }

    /// Insert `(key, page)`. Evicts one unpinned, undirty, unvisited entry
    /// (per SIEVE) if at capacity. Returns the evicted key if any.
    pub fn insert(&mut self, key: (FileKey, u64), page: Arc<Page>) -> Option<(FileKey, u64)> {
        // Update in place if key already present (preserve list position).
        if let Some(&idx) = self.map.get(&key) {
            let node = self.slab[idx].as_mut().expect("indexed node alive");
            node.page = page;
            return None;
        }
        let evicted = if self.map.len() >= self.capacity {
            self.evict_one()
        } else {
            None
        };
        let idx = self.alloc_node(Node {
            key,
            page,
            visited: false,
            prev: self.head,
            next: None,
        });
        // Splice in as new head.
        if let Some(old_head) = self.head {
            self.slab[old_head].as_mut().expect("old head alive").next = Some(idx);
        } else {
            // Empty list; this node is also the new tail.
            self.tail = Some(idx);
        }
        self.head = Some(idx);
        self.map.insert(key, idx);
        evicted
    }

    fn evict_one(&mut self) -> Option<(FileKey, u64)> {
        // Walk the hand at most `capacity * 2` steps to bound worst case
        // (every entry either visited or unevictable triggers a wrap).
        let max_steps = self.capacity.saturating_mul(2).max(1);
        let mut cur = self.hand.or(self.tail);
        for _ in 0..max_steps {
            let Some(idx) = cur else {
                // Reached past head — wrap to tail.
                cur = self.tail;
                continue;
            };
            let (key, next_idx, visited, prev_idx) = {
                let node = self.slab[idx].as_ref().expect("hand on live node");
                (node.key, node.next, node.visited, node.prev)
            };
            let pinned = self.pins.get(&key).copied().unwrap_or(0) > 0;
            let is_dirty = self.dirty.contains(&key);
            if pinned || is_dirty {
                // Skip without touching the visited bit.
                cur = next_idx;
                continue;
            }
            if visited {
                self.slab[idx].as_mut().expect("hand on live node").visited = false;
                cur = next_idx;
                continue;
            }
            // Evict this node. Advance hand to the next node (toward head)
            // so subsequent evictions resume from the right place.
            self.unlink_node(idx, prev_idx, next_idx);
            self.hand = next_idx;
            self.map.remove(&key);
            self.free_node(idx);
            return Some(key);
        }
        // No evictable entry — capacity overrun is possible if everything is
        // pinned or dirty. Caller handles by letting the cache grow.
        None
    }

    fn alloc_node(&mut self, node: Node) -> usize {
        if let Some(idx) = self.free.pop() {
            self.slab[idx] = Some(node);
            idx
        } else {
            let idx = self.slab.len();
            self.slab.push(Some(node));
            idx
        }
    }

    fn free_node(&mut self, idx: usize) {
        self.slab[idx] = None;
        self.free.push(idx);
    }

    fn unlink_node(&mut self, _idx: usize, prev: Option<usize>, next: Option<usize>) {
        if let Some(p) = prev {
            self.slab[p].as_mut().expect("prev alive").next = next;
        } else {
            self.tail = next;
        }
        if let Some(n) = next {
            self.slab[n].as_mut().expect("next alive").prev = prev;
        } else {
            self.head = prev;
        }
    }

    pub fn pin(&mut self, key: (FileKey, u64)) {
        *self.pins.entry(key).or_insert(0) += 1;
    }

    pub fn unpin(&mut self, key: (FileKey, u64)) {
        if let Some(count) = self.pins.get_mut(&key) {
            if *count > 0 {
                *count -= 1;
            }
            if *count == 0 {
                self.pins.remove(&key);
            }
        }
    }

    #[must_use]
    pub fn is_pinned(&self, key: (FileKey, u64)) -> bool {
        self.pins.get(&key).copied().unwrap_or(0) > 0
    }

    pub fn mark_dirty(&mut self, key: (FileKey, u64)) {
        self.dirty.insert(key);
    }

    pub fn clear_dirty(&mut self, key: (FileKey, u64)) {
        self.dirty.remove(&key);
    }

    #[must_use]
    pub fn is_dirty(&self, key: (FileKey, u64)) -> bool {
        self.dirty.contains(&key)
    }

    /// Sorted iterator over the dirty page ids for one file, ascending by
    /// `page_id`. Used by the Pager to flush in physical-id order.
    #[must_use]
    pub fn dirty_for_file(&self, file: FileKey) -> Vec<u64> {
        self.dirty
            .iter()
            .filter_map(|(f, p)| if *f == file { Some(*p) } else { None })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page(byte: u8) -> Arc<Page> {
        Arc::new(Page::new(vec![byte; 16]))
    }

    #[test]
    fn insert_and_get() {
        let mut c = PageCache::with_capacity(4);
        c.insert((FileKey::Main, 1), page(0));
        assert!(c.get((FileKey::Main, 1)).is_some());
    }

    #[test]
    fn evicts_oldest_unvisited_on_overflow() {
        let mut c = PageCache::with_capacity(2);
        c.insert((FileKey::Main, 1), page(1));
        c.insert((FileKey::Main, 2), page(2));
        // No gets — both unvisited. Hand starts at tail = key 1. Evicts it.
        let evicted = c.insert((FileKey::Main, 3), page(3));
        assert_eq!(evicted, Some((FileKey::Main, 1)));
        assert!(c.get((FileKey::Main, 1)).is_none());
        assert!(c.get((FileKey::Main, 2)).is_some());
        assert!(c.get((FileKey::Main, 3)).is_some());
    }

    #[test]
    fn visited_entries_survive_one_pass() {
        // SIEVE: hit sets visited; first hand pass clears it; second pass evicts.
        let mut c = PageCache::with_capacity(2);
        c.insert((FileKey::Main, 1), page(1));
        c.insert((FileKey::Main, 2), page(2));
        let _ = c.get((FileKey::Main, 1)); // mark 1 as visited
        // Hand starts at tail = 1, sees visited, clears, moves to 2 (unvisited): evicts 2.
        let evicted = c.insert((FileKey::Main, 3), page(3));
        assert_eq!(evicted, Some((FileKey::Main, 2)));
        assert!(
            c.get((FileKey::Main, 1)).is_some(),
            "recently-used survives"
        );
    }

    #[test]
    fn pinned_pages_survive_eviction() {
        let mut c = PageCache::with_capacity(2);
        c.insert((FileKey::Main, 1), page(1));
        c.pin((FileKey::Main, 1));
        c.insert((FileKey::Main, 2), page(2));
        let evicted = c.insert((FileKey::Main, 3), page(3));
        assert_eq!(evicted, Some((FileKey::Main, 2)));
        assert!(
            c.get((FileKey::Main, 1)).is_some(),
            "pinned page must survive"
        );
    }

    #[test]
    fn dirty_pages_not_evicted() {
        let mut c = PageCache::with_capacity(2);
        c.insert((FileKey::Main, 1), page(1));
        c.mark_dirty((FileKey::Main, 1));
        c.insert((FileKey::Main, 2), page(2));
        let evicted = c.insert((FileKey::Main, 3), page(3));
        assert_eq!(evicted, Some((FileKey::Main, 2)));
        assert!(c.get((FileKey::Main, 1)).is_some());
    }

    #[test]
    fn dirty_iter_is_sorted_ascending() {
        let mut c = PageCache::with_capacity(16);
        for p in [50, 25, 100, 75] {
            c.insert((FileKey::Main, p), page(0));
            c.mark_dirty((FileKey::Main, p));
        }
        assert_eq!(c.dirty_for_file(FileKey::Main), vec![25, 50, 75, 100]);
    }

    #[test]
    fn file_classes_dont_collide() {
        let mut c = PageCache::with_capacity(4);
        c.insert((FileKey::Main, 1), page(1));
        c.insert((FileKey::Segment([0; 16]), 1), page(2));
        assert!(c.get((FileKey::Main, 1)).is_some());
        assert!(c.get((FileKey::Segment([0; 16]), 1)).is_some());
    }

    #[test]
    fn reuse_slab_slots() {
        // Insert N+1 over capacity N to force one eviction; slab should reuse the slot.
        let mut c = PageCache::with_capacity(2);
        c.insert((FileKey::Main, 1), page(1));
        c.insert((FileKey::Main, 2), page(2));
        c.insert((FileKey::Main, 3), page(3));
        assert_eq!(c.slab.len(), 2, "slab reuses freed slot");
    }
}
