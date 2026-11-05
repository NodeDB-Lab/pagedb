//! Bounded page cache with SIEVE eviction, pin / unpin / dirty tracking. The
//! eviction policy is a private impl detail; the public surface is stable.
//!
//! SIEVE (Zhang et al., NSDI 2024) replaces classic LRU. The hit path is a
//! single bit set — no list-shuffle, no `O(N)` order maintenance. Eviction
//! walks a "hand" through a FIFO of insertions, clearing `visited` bits and
//! evicting the first unvisited, unpinned entry. Dirty entries are off the
//! FIFO until they are clean again.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use bytes::Bytes;
use rustc_hash::FxHashMap;

use crate::{PagedbError, Result};

/// File-identity discriminator for the cache key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum FileKey {
    Main,
    Segment([u8; 16]),
    /// Apply-journal sidecar at `applyjournal/<hex(id)>`. A receiver-local,
    /// AEAD-authenticated file written before an `apply_incremental` header
    /// swap; it is neither a `main.db` page nor a catalog-tracked segment.
    ApplyJournal([u8; 16]),
}

/// Bytes plus pin count. `bytes` holds the decrypted full-page buffer
/// (envelope header + body slot + tag slot). Body access goes through the
/// helpers in `format::data_page`.
///
/// `bytes` is logically immutable for the page's cache lifetime — set once at
/// insert, never mutated. Mutation happens by replacing the whole `Arc<Page>`
/// in the cache map.
///
/// Held as [`Bytes`] rather than `Vec<u8>` so a reader can hand out a slice of
/// a value without copying it: the slice shares this buffer's refcount and
/// keeps it alive on its own. That the buffer never changes is what makes such
/// a slice a stable snapshot even after the page leaves the cache.
pub struct Page {
    pub bytes: Bytes,
    /// Page kind recorded at write time; used by the Pager flush path to
    /// reconstruct the correct AAD for each dirty page.
    pub kind_byte: u8,
    /// Realm that owns this cached plaintext. `None` marks metadata-less test
    /// pages, which the Pager read path must reject rather than treat as a
    /// cache hit.
    pub realm_id_bytes: Option<[u8; 16]>,
    /// Set once a structural extent check has proven this buffer's slot
    /// directory and records lie in bounds.
    ///
    /// Sound to memoise precisely because `bytes` is immutable for the page's
    /// cache lifetime (see above): a mutation installs a *new* `Arc<Page>`,
    /// which starts out unvalidated. The check is extent-only and depends on
    /// nothing but these bytes, so proving it once proves it for every later
    /// reader of the same buffer.
    pub extents_validated: AtomicBool,
}

impl Page {
    /// Metadata-less page. Every page the Pager inserts carries a realm, so
    /// this exists only for cache-policy tests, which exercise eviction order
    /// without building envelopes.
    #[cfg(test)]
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes: Bytes::from(bytes),
            kind_byte: 0,
            realm_id_bytes: None,
            extents_validated: AtomicBool::new(false),
        }
    }

    /// `bytes` is moved into a [`Bytes`], not copied.
    #[must_use]
    pub fn new_with_meta(bytes: Vec<u8>, kind_byte: u8, realm_id_bytes: [u8; 16]) -> Self {
        Self {
            bytes: Bytes::from(bytes),
            kind_byte,
            realm_id_bytes: Some(realm_id_bytes),
            extents_validated: AtomicBool::new(false),
        }
    }
}

/// Node in the SIEVE FIFO. `prev` points toward the tail (older), `next`
/// toward the head (newer). The hand walks tail→head via `next`.
struct Node {
    key: (FileKey, u64),
    page: Arc<Page>,
    /// Outstanding `PageGuard`s over this entry. Lives on the node rather than
    /// in a side table so a lookup that already resolved the slab index does
    /// not pay a second hash to pin, nor a third to unpin on drop.
    pins: u32,
    visited: bool,
    /// Whether the node is on the SIEVE list. A dirty node is off it: dirty
    /// pages are never evicted, so the hand has no reason to visit them.
    linked: bool,
    prev: Option<usize>,
    next: Option<usize>,
}

/// Bounded page cache with SIEVE eviction. Dirty entries leave the SIEVE
/// list until they are clean again, and pinned entries are skipped by the
/// eviction hand.
///
/// A large write transaction leaves most of the cache dirty. Keeping dirty
/// entries off the list lets an eviction reach the few clean pages without
/// walking past every dirty one, so a transaction's inserts stay linear in
/// the pages it writes.
pub struct PageCache {
    capacity: usize,
    /// Keys are `(FileKey, u64)` page identities, never attacker-chosen in a
    /// way that could be ground into collisions, so the DoS-resistant `SipHash`
    /// default buys nothing here and costs a measurable slice of every warm
    /// page hit. `FxHashMap` is the same map with a cheap integer hash.
    map: FxHashMap<(FileKey, u64), usize>,
    /// Slab of nodes. `None` slots are free and recorded in `free`.
    slab: Vec<Option<Node>>,
    free: Vec<usize>,
    head: Option<usize>,
    tail: Option<usize>,
    /// SIEVE hand. Walks tail→head via `next`. `None` means "start from tail
    /// on next eviction"; after wrapping past head it is reset to `None`.
    hand: Option<usize>,
    dirty: BTreeSet<(FileKey, u64)>,
    /// How many live entries are neither dirty nor pinned, i.e. how many the
    /// eviction hand could actually take.
    ///
    /// A large write transaction dirties every page it touches, and dirty pages
    /// are never evicted, so the cache legitimately grows past capacity with
    /// nothing evictable in it. Without this the hand re-swept the whole list on
    /// every insert only to fail — and the list it swept was the overgrown one,
    /// so a single transaction's page inserts cost time quadratic in the pages
    /// it wrote.
    evictable: usize,
}

impl PageCache {
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        let cap = capacity.max(1);
        Self {
            capacity: cap,
            map: FxHashMap::with_capacity_and_hasher(cap, rustc_hash::FxBuildHasher),
            slab: Vec::with_capacity(cap),
            free: Vec::new(),
            head: None,
            tail: None,
            hand: None,
            dirty: BTreeSet::new(),
            evictable: 0,
        }
    }

    /// Whether the entry at `idx` is currently a candidate for the hand.
    fn is_evictable(&self, idx: usize) -> bool {
        self.slab[idx]
            .as_ref()
            .is_some_and(|node| node.pins == 0 && !self.dirty.contains(&node.key))
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Lookup. Sets the `visited` bit on hit; does not touch the FIFO order.
    pub fn get(&mut self, key: (FileKey, u64)) -> Option<Arc<Page>> {
        let idx = *self.map.get(&key)?;
        let node = self.slab[idx].as_mut().expect("indexed node alive");
        node.visited = true;
        Some(node.page.clone())
    }

    /// [`get`](Self::get) that also pins, returning the slab index to release
    /// it with. One hash lookup serves the read, the `visited` bit, and the
    /// pin — the read path's hottest operation, so the separate `pin` call it
    /// replaces was a second hash of the same key.
    pub fn get_and_pin(&mut self, key: (FileKey, u64)) -> Option<(Arc<Page>, usize)> {
        let idx = *self.map.get(&key)?;
        let was_evictable = self.is_evictable(idx);
        let node = self.slab[idx].as_mut().expect("indexed node alive");
        node.visited = true;
        node.pins = node.pins.saturating_add(1);
        let page = node.page.clone();
        if was_evictable {
            self.evictable -= 1;
        }
        Some((page, idx))
    }

    /// Pin the entry at `idx`, which the caller must have just obtained from
    /// [`insert_and_index`](Self::insert_and_index) or
    /// [`get_and_pin`](Self::get_and_pin).
    pub fn pin_at(&mut self, idx: usize) {
        let was_evictable = self.is_evictable(idx);
        let node = self.slab[idx].as_mut().expect("indexed node alive");
        node.pins = node.pins.saturating_add(1);
        if was_evictable {
            self.evictable -= 1;
        }
    }

    /// Release a pin taken at `idx`. `key` identifies the entry the pin was
    /// taken on: slab slots are recycled, so a stale index could otherwise
    /// decrement an unrelated entry's count. Every removal path spares pinned
    /// entries, so for a live pin the check always passes — it is there to keep
    /// that a checked invariant rather than an assumed one.
    pub fn unpin_at(&mut self, idx: usize, key: (FileKey, u64)) {
        let Some(node) = self.slab.get_mut(idx).and_then(Option::as_mut) else {
            return;
        };
        if node.key != key {
            return;
        }
        node.pins = node.pins.saturating_sub(1);
        if self.is_evictable(idx) {
            self.evictable += 1;
        }
    }

    /// Insert `(key, page)`. Evicts one unpinned, undirty, unvisited entry
    /// (per SIEVE) if at capacity. Returns the evicted key if any.
    pub fn insert(
        &mut self,
        key: (FileKey, u64),
        page: Arc<Page>,
    ) -> Result<Option<(FileKey, u64)>> {
        Ok(self.insert_and_index(key, page)?.0)
    }

    /// [`insert`](Self::insert), additionally returning the slab index of the
    /// inserted entry so a caller that pins immediately does not re-hash.
    pub fn insert_and_index(
        &mut self,
        key: (FileKey, u64),
        page: Arc<Page>,
    ) -> Result<(Option<(FileKey, u64)>, usize)> {
        // Update in place if key already present (preserve list position).
        if let Some(&idx) = self.map.get(&key) {
            let node = self.slab[idx].as_mut().expect("indexed node alive");
            node.page = page;
            return Ok((None, idx));
        }
        let evicted = if self.map.len() >= self.capacity {
            self.evict_one()
        } else {
            None
        };
        let idx = self.alloc_node(Node {
            key,
            page,
            pins: 0,
            visited: false,
            linked: false,
            prev: None,
            next: None,
        });
        self.map.insert(key, idx);
        // Fresh entries are unpinned; a caller that pins or dirties this one
        // adjusts the count through those paths. A key already marked dirty
        // stays off the list until it is clean.
        if !self.dirty.contains(&key) {
            self.link_as_head(idx)?;
            self.evictable += 1;
        }
        Ok((evicted, idx))
    }

    /// Splice the unlinked node at `idx` in as the newest entry.
    fn link_as_head(&mut self, idx: usize) -> Result<()> {
        let old_head = self.head;
        {
            let node = self.slab[idx]
                .as_mut()
                .ok_or(PagedbError::page_cache_inconsistent("link an entry"))?;
            debug_assert!(!node.linked, "node linked twice");
            node.linked = true;
            node.prev = old_head;
            node.next = None;
        }
        if let Some(old_head) = old_head {
            self.slab[old_head].as_mut().expect("old head alive").next = Some(idx);
        } else {
            // Empty list; this node is also the new tail.
            self.tail = Some(idx);
        }
        self.head = Some(idx);
        Ok(())
    }

    /// Take the node at `idx` off the list, moving the hand off it first.
    fn unlink_from_list(&mut self, idx: usize) -> Result<()> {
        let (prev, next) = {
            let node = self.slab[idx]
                .as_mut()
                .ok_or(PagedbError::page_cache_inconsistent("unlink an entry"))?;
            if !node.linked {
                return Ok(());
            }
            node.linked = false;
            (node.prev.take(), node.next.take())
        };
        if self.hand == Some(idx) {
            self.hand = next;
        }
        self.unlink_node(idx, prev, next);
        Ok(())
    }

    fn evict_one(&mut self) -> Option<(FileKey, u64)> {
        // Two passes are sufficient to clear visited bits and then evict.
        // A drifted count would either skip a possible eviction (unbounded
        // growth) or reintroduce the sweep it exists to avoid, and neither is
        // visible without checking.
        debug_assert_eq!(
            self.evictable,
            self.map
                .values()
                .filter(|&&idx| self.is_evictable(idx))
                .count(),
            "evictable count drifted from the live entries"
        );
        debug_assert!(
            self.map.iter().all(|(key, &idx)| self.slab[idx]
                .as_ref()
                .is_some_and(|node| node.linked != self.dirty.contains(key))),
            "an entry's list membership disagrees with its dirty state"
        );
        // Nothing clean and unpinned exists, so no sweep can succeed. Bailing
        // here is what keeps a write transaction linear in the pages it dirties.
        if self.evictable == 0 {
            return None;
        }
        // Use the live list length rather than the configured capacity because
        // pinned or dirty pages can temporarily grow the cache past capacity.
        let max_steps = self.map.len().saturating_mul(2).max(1);
        let mut cur = self.hand.or(self.tail);
        for _ in 0..max_steps {
            let Some(idx) = cur else {
                // Reached past head — wrap to tail.
                cur = self.tail;
                continue;
            };
            let (key, next_idx, visited, prev_idx, pins) = {
                let node = self.slab[idx].as_ref().expect("hand on live node");
                (node.key, node.next, node.visited, node.prev, node.pins)
            };
            debug_assert!(
                !self.dirty.contains(&key),
                "a dirty page is on the SIEVE list"
            );
            if pins > 0 {
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
            self.evictable -= 1;
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

    /// Mark `key` dirty, taking a cached entry off the SIEVE list. The list
    /// is updated first, so an error leaves the dirty set and the evictable
    /// count as they were.
    pub fn mark_dirty(&mut self, key: (FileKey, u64)) -> Result<()> {
        let idx = self.map.get(&key).copied();
        let was_evictable = idx.is_some_and(|i| self.is_evictable(i));
        if let Some(idx) = idx {
            self.unlink_from_list(idx)?;
        }
        self.dirty.insert(key);
        if was_evictable {
            self.evictable -= 1;
        }
        Ok(())
    }

    /// Mark `key` clean, putting a cached entry back on the SIEVE list as the
    /// newest entry. The list is updated first, so an error leaves the dirty
    /// set and the evictable count as they were.
    pub fn clear_dirty(&mut self, key: (FileKey, u64)) -> Result<()> {
        if !self.dirty.contains(&key) {
            return Ok(());
        }
        let idx = self.map.get(&key).copied();
        if let Some(idx) = idx {
            self.link_as_head(idx)?;
        }
        self.dirty.remove(&key);
        if idx.is_some_and(|i| self.is_evictable(i)) {
            self.evictable += 1;
        }
        Ok(())
    }

    /// How many entries are currently dirty, across every file.
    ///
    /// Dirty entries are never evicted, so this is the part of the cache that
    /// can push it past its configured capacity. Callers that seal pages in a
    /// long loop watch this to decide when they must flush.
    #[must_use]
    pub fn dirty_len(&self) -> usize {
        self.dirty.len()
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

    /// Drop every (unpinned) entry for `file`, including dirty ones, so that the
    /// cached plaintext is discarded and later reads re-fetch from disk. Used
    /// when compaction replaces the backing file (the cached pages no longer
    /// match what is on disk). Pinned entries are left untouched.
    pub fn clear_file(&mut self, file: FileKey) {
        self.clear_file_entries(file, false);
    }

    /// Drop every unpinned clean entry for `file`, leaving dirty entries
    /// available for a later flush and pinned entries available to readers.
    /// Used to force a re-read of the durable bytes without discarding the
    /// in-flight writes that have not reached them yet.
    #[cfg(test)]
    pub fn clear_clean_file(&mut self, file: FileKey) {
        self.clear_file_entries(file, true);
    }

    /// Shared body of the two `clear_*` entry points. Pinned entries are always
    /// spared: a reader holds them. `keep_dirty` decides whether an unflushed
    /// entry is spared as well, or dropped along with its dirty marker.
    fn clear_file_entries(&mut self, file: FileKey, keep_dirty: bool) {
        let keys: Vec<(FileKey, u64)> = self
            .map
            .keys()
            .filter(|(f, _)| *f == file)
            .copied()
            .collect();
        for key in keys {
            let pinned = self
                .map
                .get(&key)
                .and_then(|&idx| self.slab[idx].as_ref())
                .is_some_and(|node| node.pins > 0);
            if pinned {
                continue;
            }
            if keep_dirty && self.dirty.contains(&key) {
                continue;
            }
            if let Some(&idx) = self.map.get(&key) {
                let was_evictable = self.is_evictable(idx);
                self.map.remove(&key);
                // The entry is dropped either way, so a list error is logged
                // and the clear goes on. A slot that failed is already empty
                // and is not freed again, so it cannot be handed out twice.
                match self.unlink_from_list(idx) {
                    Ok(()) => self.free_node(idx),
                    Err(error) => {
                        tracing::error!(page_id = key.1, error = %error, "page cache clear");
                    }
                }
                if was_evictable {
                    self.evictable -= 1;
                }
            }
            if !keep_dirty {
                self.dirty.remove(&key);
            }
        }
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
        c.insert((FileKey::Main, 1), page(0)).unwrap();
        assert_eq!(
            c.get((FileKey::Main, 1))
                .map(|cached| cached.realm_id_bytes),
            Some(None)
        );
    }

    #[test]
    fn evicts_oldest_unvisited_on_overflow() {
        let mut c = PageCache::with_capacity(2);
        c.insert((FileKey::Main, 1), page(1)).unwrap();
        c.insert((FileKey::Main, 2), page(2)).unwrap();
        // No gets — both unvisited. Hand starts at tail = key 1. Evicts it.
        let evicted = c.insert((FileKey::Main, 3), page(3)).unwrap();
        assert_eq!(evicted, Some((FileKey::Main, 1)));
        assert!(c.get((FileKey::Main, 1)).is_none());
        assert!(c.get((FileKey::Main, 2)).is_some());
        assert!(c.get((FileKey::Main, 3)).is_some());
    }

    #[test]
    fn visited_entries_survive_one_pass() {
        // SIEVE: hit sets visited; first hand pass clears it; second pass evicts.
        let mut c = PageCache::with_capacity(2);
        c.insert((FileKey::Main, 1), page(1)).unwrap();
        c.insert((FileKey::Main, 2), page(2)).unwrap();
        let _ = c.get((FileKey::Main, 1)); // mark 1 as visited
        // Hand starts at tail = 1, sees visited, clears, moves to 2 (unvisited): evicts 2.
        let evicted = c.insert((FileKey::Main, 3), page(3)).unwrap();
        assert_eq!(evicted, Some((FileKey::Main, 2)));
        assert!(
            c.get((FileKey::Main, 1)).is_some(),
            "recently-used survives"
        );
    }

    #[test]
    fn pinned_pages_survive_eviction() {
        let mut c = PageCache::with_capacity(2);
        let (_, pinned) = c.insert_and_index((FileKey::Main, 1), page(1)).unwrap();
        c.pin_at(pinned);
        c.insert((FileKey::Main, 2), page(2)).unwrap();
        let evicted = c.insert((FileKey::Main, 3), page(3)).unwrap();
        assert_eq!(evicted, Some((FileKey::Main, 2)));
        assert!(
            c.get((FileKey::Main, 1)).is_some(),
            "pinned page must survive"
        );
    }

    #[test]
    fn releasing_the_last_pin_makes_an_entry_evictable_again() {
        let mut c = PageCache::with_capacity(2);
        let key = (FileKey::Main, 1);
        let (_, idx) = c.insert_and_index(key, page(1)).unwrap();
        c.pin_at(idx);
        c.insert((FileKey::Main, 2), page(2)).unwrap();
        assert_eq!(
            c.insert((FileKey::Main, 3), page(3)).unwrap(),
            Some((FileKey::Main, 2))
        );

        c.unpin_at(idx, key);
        // Unpinned and never re-read, so it is now the eviction hand's victim.
        assert_eq!(c.insert((FileKey::Main, 4), page(4)).unwrap(), Some(key));
    }

    #[test]
    fn nested_pins_each_need_releasing() {
        let mut c = PageCache::with_capacity(2);
        let key = (FileKey::Main, 1);
        let (_, idx) = c.insert_and_index(key, page(1)).unwrap();
        c.pin_at(idx);
        c.pin_at(idx);

        c.unpin_at(idx, key);
        c.insert((FileKey::Main, 2), page(2)).unwrap();
        assert_eq!(
            c.insert((FileKey::Main, 3), page(3)).unwrap(),
            Some((FileKey::Main, 2)),
            "one outstanding pin still protects the entry"
        );
    }

    /// Slab slots are recycled, so an index outliving its entry must not
    /// decrement whatever now occupies the slot.
    #[test]
    fn unpinning_a_recycled_slot_leaves_the_new_occupant_pinned() {
        let mut c = PageCache::with_capacity(1);
        let old_key = (FileKey::Main, 1);
        let (_, idx) = c.insert_and_index(old_key, page(1)).unwrap();
        assert_eq!(
            c.insert((FileKey::Main, 2), page(2)).unwrap(),
            Some(old_key)
        );

        // The slot now belongs to page 2. Pin it, then replay the stale
        // release for page 1 against the same index.
        let new_key = (FileKey::Main, 2);
        let (_, new_idx) = c.insert_and_index(new_key, page(2)).unwrap();
        c.pin_at(new_idx);
        c.unpin_at(idx, old_key);

        c.insert((FileKey::Main, 3), page(3)).unwrap();
        assert!(
            c.get(new_key).is_some(),
            "the stale release must not have unpinned the new occupant"
        );
    }

    /// An all-dirty cache must not re-sweep itself on every insert: that is
    /// what made a large write transaction cost time quadratic in its pages.
    #[test]
    fn an_all_dirty_cache_reports_nothing_evictable() {
        let mut c = PageCache::with_capacity(4);
        for id in 1u8..=6 {
            let key = (FileKey::Main, u64::from(id));
            c.insert(key, page(id)).unwrap();
            c.mark_dirty(key).unwrap();
        }
        assert_eq!(c.evictable, 0);
        assert_eq!(c.len(), 6, "dirty entries grow the cache past capacity");

        // Cleaning one makes it — and only it — a candidate again.
        c.clear_dirty((FileKey::Main, 3)).unwrap();
        assert_eq!(c.evictable, 1);
        assert_eq!(
            c.insert((FileKey::Main, 7), page(7)).unwrap(),
            Some((FileKey::Main, 3))
        );
        // Page 3 left, but page 7 arrived clean and is a candidate in its turn.
        assert_eq!(c.evictable, 1);
    }

    #[test]
    fn evictable_count_tracks_pin_and_dirty_transitions() {
        let mut c = PageCache::with_capacity(8);
        let key = (FileKey::Main, 1);
        let (_, idx) = c.insert_and_index(key, page(1)).unwrap();
        assert_eq!(c.evictable, 1, "a fresh clean entry is a candidate");

        c.pin_at(idx);
        assert_eq!(c.evictable, 0, "pinned");
        c.mark_dirty(key).unwrap();
        assert_eq!(c.evictable, 0, "pinned and dirty");
        c.unpin_at(idx, key);
        assert_eq!(c.evictable, 0, "still dirty");
        c.clear_dirty(key).unwrap();
        assert_eq!(c.evictable, 1, "clean and unpinned again");
    }

    #[test]
    fn dirty_pages_not_evicted() {
        let mut c = PageCache::with_capacity(2);
        c.insert((FileKey::Main, 1), page(1)).unwrap();
        c.mark_dirty((FileKey::Main, 1)).unwrap();
        c.insert((FileKey::Main, 2), page(2)).unwrap();
        let evicted = c.insert((FileKey::Main, 3), page(3)).unwrap();
        assert_eq!(evicted, Some((FileKey::Main, 2)));
        assert!(c.get((FileKey::Main, 1)).is_some());
    }

    #[test]
    fn clear_clean_file_preserves_dirty_entries() {
        let mut c = PageCache::with_capacity(4);
        c.insert((FileKey::Main, 1), page(1)).unwrap();
        c.insert((FileKey::Main, 2), page(2)).unwrap();
        c.mark_dirty((FileKey::Main, 2)).unwrap();

        c.clear_clean_file(FileKey::Main);

        assert!(c.get((FileKey::Main, 1)).is_none());
        assert!(c.get((FileKey::Main, 2)).is_some());
        assert_eq!(c.dirty_for_file(FileKey::Main), vec![2]);
    }

    #[test]
    fn dirty_iter_is_sorted_ascending() {
        let mut c = PageCache::with_capacity(16);
        for p in [50, 25, 100, 75] {
            c.insert((FileKey::Main, p), page(0)).unwrap();
            c.mark_dirty((FileKey::Main, p)).unwrap();
        }
        assert_eq!(c.dirty_for_file(FileKey::Main), vec![25, 50, 75, 100]);
    }

    #[test]
    fn file_classes_dont_collide() {
        let mut c = PageCache::with_capacity(4);
        c.insert((FileKey::Main, 1), page(1)).unwrap();
        c.insert((FileKey::Segment([0; 16]), 1), page(2)).unwrap();
        assert!(c.get((FileKey::Main, 1)).is_some());
        assert!(c.get((FileKey::Segment([0; 16]), 1)).is_some());
    }

    #[test]
    fn reuse_slab_slots() {
        // Insert N+1 over capacity N to force one eviction; slab should reuse the slot.
        let mut c = PageCache::with_capacity(2);
        c.insert((FileKey::Main, 1), page(1)).unwrap();
        c.insert((FileKey::Main, 2), page(2)).unwrap();
        c.insert((FileKey::Main, 3), page(3)).unwrap();
        assert_eq!(c.slab.len(), 2, "slab reuses freed slot");
    }

    #[test]
    fn overgrown_cache_still_finds_clean_victim() {
        let mut c = PageCache::with_capacity(2);

        for id in 1u8..=4 {
            let key = (FileKey::Main, u64::from(id));
            let (_, idx) = c.insert_and_index(key, page(id)).unwrap();
            c.pin_at(idx);
        }
        c.insert((FileKey::Main, 5), page(5)).unwrap();
        assert_eq!(c.len(), 5, "pinned pages may force temporary growth");

        let evicted = c.insert((FileKey::Main, 6), page(6)).unwrap();
        assert_eq!(
            evicted,
            Some((FileKey::Main, 5)),
            "eviction must scan the full over-capacity list for a clean victim"
        );
        assert_eq!(c.len(), 5);
        assert!(c.get((FileKey::Main, 5)).is_none());
        assert!(c.get((FileKey::Main, 6)).is_some());
    }

    /// Dirty entries leave the SIEVE list, so eviction takes the clean ones
    /// without visiting them, and an entry made clean is evictable again.
    #[test]
    fn dirty_entries_stay_off_the_eviction_list_until_clean() {
        let mut c = PageCache::with_capacity(3);
        for p in 1..=3u8 {
            c.insert((FileKey::Main, u64::from(p)), page(p)).unwrap();
        }
        c.mark_dirty((FileKey::Main, 1)).unwrap();
        c.mark_dirty((FileKey::Main, 2)).unwrap();
        // Page 3 is the only clean entry, so it goes, not a dirty one.
        assert_eq!(
            c.insert((FileKey::Main, 4), page(4)).unwrap(),
            Some((FileKey::Main, 3))
        );

        // Cleaned, page 1 rejoins as the newest entry: page 4 is older.
        c.clear_dirty((FileKey::Main, 1)).unwrap();
        assert_eq!(
            c.insert((FileKey::Main, 5), page(5)).unwrap(),
            Some((FileKey::Main, 4))
        );
        assert!(c.get((FileKey::Main, 2)).is_some(), "dirty page kept");

        // A key marked dirty before it is cached is inserted off the list:
        // the hand passes over it to the clean entries.
        c.mark_dirty((FileKey::Main, 9)).unwrap();
        assert_eq!(
            c.insert((FileKey::Main, 9), page(9)).unwrap(),
            Some((FileKey::Main, 1))
        );
        assert_eq!(
            c.insert((FileKey::Main, 6), page(6)).unwrap(),
            Some((FileKey::Main, 5))
        );
        assert!(c.get((FileKey::Main, 9)).is_some());
        assert_eq!(c.dirty_len(), 2);
    }

    /// Dropping a file's entries takes dirty, unlinked ones too, and leaves
    /// the list and the hand consistent for the next eviction. An entry of
    /// another file survives on the list and is evicted in its turn.
    #[test]
    fn clearing_a_file_drops_unlinked_dirty_entries() {
        let seg = FileKey::Segment([7u8; 16]);
        let mut c = PageCache::with_capacity(3);
        c.insert((FileKey::Main, 1), page(1)).unwrap();
        c.insert((seg, 1), page(2)).unwrap();
        c.insert((FileKey::Main, 2), page(3)).unwrap();
        c.mark_dirty((FileKey::Main, 1)).unwrap();
        c.clear_file(FileKey::Main);
        assert_eq!(c.len(), 1);
        assert_eq!(c.dirty_len(), 0);

        // The segment entry is the oldest on the list, then 3, then 4.
        c.insert((FileKey::Main, 3), page(4)).unwrap();
        c.insert((FileKey::Main, 4), page(5)).unwrap();
        assert_eq!(
            c.insert((FileKey::Main, 5), page(6)).unwrap(),
            Some((seg, 1))
        );
        assert_eq!(
            c.insert((FileKey::Main, 6), page(7)).unwrap(),
            Some((FileKey::Main, 3))
        );
    }

    /// A live index entry whose slot is empty is reported as an error from
    /// both list operations, not a panic.
    #[test]
    fn dead_slot_is_an_error() {
        let mut c = PageCache::with_capacity(4);
        let (_, linked) = c.insert_and_index((FileKey::Main, 1), page(1)).unwrap();
        c.slab[linked] = None;
        assert!(matches!(
            c.mark_dirty((FileKey::Main, 1)),
            Err(PagedbError::PageCacheInconsistent { .. })
        ));
        assert_eq!(c.dirty_len(), 0);
        assert_eq!(c.evictable, 1);

        let mut c = PageCache::with_capacity(4);
        let (_, unlinked) = c.insert_and_index((FileKey::Main, 2), page(2)).unwrap();
        c.mark_dirty((FileKey::Main, 2)).unwrap();
        c.slab[unlinked] = None;
        assert!(matches!(
            c.clear_dirty((FileKey::Main, 2)),
            Err(PagedbError::PageCacheInconsistent { .. })
        ));
        assert_eq!(c.dirty_len(), 1);
        assert_eq!(c.evictable, 0);
    }

    /// Clearing a file past a freed slot that a live index entry still names
    /// does not free the slot a second time, so two later inserts get two
    /// different slots.
    #[test]
    fn clearing_past_a_freed_slot_does_not_free_it_twice() {
        let mut c = PageCache::with_capacity(4);
        let (_, idx) = c.insert_and_index((FileKey::Main, 1), page(1)).unwrap();
        c.free_node(idx);
        c.clear_file(FileKey::Main);
        let (_, first) = c.insert_and_index((FileKey::Main, 2), page(2)).unwrap();
        let (_, second) = c.insert_and_index((FileKey::Main, 3), page(3)).unwrap();
        assert_ne!(first, second);
    }
}
