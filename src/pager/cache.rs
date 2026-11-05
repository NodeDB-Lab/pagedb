//! Bounded page cache with SIEVE eviction, pin / unpin / dirty tracking. The
//! eviction policy is a private impl detail; the public surface is stable.
//!
//! SIEVE (Zhang et al., NSDI 2024) replaces classic LRU. The hit path is a
//! single bit set — no list-shuffle, no `O(N)` order maintenance. Eviction
//! walks a "hand" through a FIFO of insertions, clearing `visited` bits and
//! evicting the first unvisited, unpinned entry. An entry leaves the FIFO when
//! marked dirty and rejoins as the newest entry when clean.
//!
//! When a cache mutex is released, the cache holds at most `capacity` entries,
//! or every entry is dirty or pinned. Dirty pages and pinned pages exceed the
//! budget only until they are flushed or released.
//!
//! A broken invariant becomes a [`CacheFault`]. The first fault latches, and
//! every later fallible operation reports it. No state in this module panics.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use bytes::Bytes;
use rustc_hash::FxHashMap;

use crate::errors::PagedbError;

const SLOT_EMPTY: &str = "slot holds no entry";
const SLOT_HOLDS_OTHER_KEY: &str = "slot holds another key";
const NO_VICTIM: &str = "evictable count is positive with no victim";
const RELEASE_WITHOUT_PIN: &str = "release without a pin";
const DIRTY_NOT_RESIDENT: &str = "dirty page not resident";
const EVICTABLE_COUNT_DRIFTED: &str = "evictable count differs from the live entries";
const OVER_BUDGET: &str = "entries exceed capacity while one is evictable";
const LIST_LINK_BROKEN: &str = "list link disagrees with the slot it names";
const MAP_SLOT_DISAGREES: &str = "map entry disagrees with the slot";
const LIVE_SLOTS_DRIFTED: &str = "live slots differ from the map";
const NODE_ALREADY_LINKED: &str = "node is already on the list";
const LIST_MEMBERSHIP_DRIFTED: &str = "list membership disagrees with the dirty marker";

/// A broken cache invariant. `operation` names what was running, `detail` what
/// it found, and `slot` the slab slot when one is known.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CacheFault {
    operation: &'static str,
    detail: &'static str,
    slot: Option<usize>,
}

impl CacheFault {
    #[cold]
    const fn new(operation: &'static str, detail: &'static str, slot: Option<usize>) -> Self {
        Self {
            operation,
            detail,
            slot,
        }
    }
}

impl From<CacheFault> for PagedbError {
    #[cold]
    fn from(fault: CacheFault) -> Self {
        Self::page_cache_state_invalid(fault.operation, fault.detail, fault.slot)
    }
}

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

/// Slab node, on the SIEVE FIFO unless dirty. `prev` points toward the tail
/// (older), `next` toward the head (newer). The hand walks tail→head via `next`.
struct Node {
    key: (FileKey, u64),
    page: Arc<Page>,
    /// Outstanding `PageGuard`s over this entry. Lives on the node rather than
    /// in a side table so a lookup that already resolved the slab index does
    /// not pay a second hash to pin, nor a third to unpin on drop.
    pins: u32,
    visited: bool,
    /// Whether this node is on the list. A clean node is on it, and a dirty one
    /// is off it. An unlinked node has `prev` and `next` of `None`.
    linked: bool,
    prev: Option<usize>,
    next: Option<usize>,
}

/// Bounded page cache with SIEVE eviction. The eviction hand skips pinned
/// entries. Dirty entries are off the list it walks.
///
/// A large write transaction leaves most of the cache dirty. Keeping dirty
/// entries off the list spares each clean-page eviction a walk past all of them.
pub struct PageCache {
    /// The entry budget. At every mutex release, `map.len() <= capacity` or
    /// `evictable == 0`. Transaction dirty pages and pinned pages exceed it
    /// until they are flushed or released, and the pool then returns to it.
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
    /// nothing evictable in it. At zero, a trim ends without walking the list.
    evictable: usize,
    /// The first broken invariant. Once set, every fallible method returns it
    /// and changes nothing.
    fault: Option<CacheFault>,
    /// Loop iterations of the eviction hand, so a test can bound a batch trim.
    #[cfg(test)]
    walk_visits: usize,
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
            fault: None,
            #[cfg(test)]
            walk_visits: 0,
        }
    }

    /// Report the latched fault, if any. A caller of an infallible accessor
    /// calls this first. An empty answer then never reads as a healthy cache.
    pub fn check_usable(&self) -> Result<(), CacheFault> {
        match self.fault {
            Some(fault) => Err(fault),
            None => Ok(()),
        }
    }

    /// Run `body` unless a fault is latched, and latch any fault it reports.
    #[inline]
    fn guarded<T>(
        &mut self,
        body: impl FnOnce(&mut Self) -> Result<T, CacheFault>,
    ) -> Result<T, CacheFault> {
        self.check_usable()?;
        body(self).map_err(|fault| self.latch(fault))
    }

    /// Record the first fault and log it. [`guarded`](Self::guarded) stops every
    /// later operation, so this runs once per cache.
    #[cold]
    fn latch(&mut self, fault: CacheFault) -> CacheFault {
        tracing::error!(
            operation = fault.operation,
            detail = fault.detail,
            slot = ?fault.slot,
            "page cache state invalid, close this handle and reopen"
        );
        self.fault = Some(fault);
        fault
    }

    /// Resolve a slab slot. An out-of-range index and a free slot both report
    /// `slot holds no entry`.
    fn node<'s>(
        slab: &'s [Option<Node>],
        idx: usize,
        operation: &'static str,
    ) -> Result<&'s Node, CacheFault> {
        slab.get(idx)
            .and_then(Option::as_ref)
            .ok_or_else(|| CacheFault::new(operation, SLOT_EMPTY, Some(idx)))
    }

    /// Mutable form of [`node`](Self::node).
    fn node_mut<'s>(
        slab: &'s mut [Option<Node>],
        idx: usize,
        operation: &'static str,
    ) -> Result<&'s mut Node, CacheFault> {
        slab.get_mut(idx)
            .and_then(Option::as_mut)
            .ok_or_else(|| CacheFault::new(operation, SLOT_EMPTY, Some(idx)))
    }

    /// Resolve a slab slot that the caller expects to hold `key`.
    fn keyed_node<'s>(
        slab: &'s [Option<Node>],
        idx: usize,
        key: (FileKey, u64),
        operation: &'static str,
    ) -> Result<&'s Node, CacheFault> {
        let node = Self::node(slab, idx, operation)?;
        if node.key != key {
            return Err(CacheFault::new(operation, SLOT_HOLDS_OTHER_KEY, Some(idx)));
        }
        Ok(node)
    }

    /// Mutable form of [`keyed_node`](Self::keyed_node).
    fn keyed_node_mut<'s>(
        slab: &'s mut [Option<Node>],
        idx: usize,
        key: (FileKey, u64),
        operation: &'static str,
    ) -> Result<&'s mut Node, CacheFault> {
        let node = Self::node_mut(slab, idx, operation)?;
        if node.key != key {
            return Err(CacheFault::new(operation, SLOT_HOLDS_OTHER_KEY, Some(idx)));
        }
        Ok(node)
    }

    /// Whether a resolved entry is a candidate for the hand.
    fn is_evictable(node: &Node, dirty: &BTreeSet<(FileKey, u64)>) -> bool {
        node.pins == 0 && !dirty.contains(&node.key)
    }

    /// `count` minus one. A count already at zero has drifted from the entries.
    fn one_less(count: usize, operation: &'static str) -> Result<usize, CacheFault> {
        count
            .checked_sub(1)
            .ok_or_else(|| CacheFault::new(operation, EVICTABLE_COUNT_DRIFTED, None))
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Lookup. Sets the `visited` bit on hit. Leaves the FIFO order alone.
    pub fn get(&mut self, key: (FileKey, u64)) -> Result<Option<Arc<Page>>, CacheFault> {
        const OPERATION: &str = "get";
        self.guarded(|cache| {
            let Some(&idx) = cache.map.get(&key) else {
                return Ok(None);
            };
            let node = Self::keyed_node_mut(&mut cache.slab, idx, key, OPERATION)?;
            node.visited = true;
            Ok(Some(node.page.clone()))
        })
    }

    /// Lookup for a key a flush read from the dirty set. `None` means the key
    /// is no longer dirty and left the cache.
    pub fn get_dirty(&mut self, key: (FileKey, u64)) -> Result<Option<Arc<Page>>, CacheFault> {
        const OPERATION: &str = "get_dirty";
        let page = self.get(key)?;
        // A key that is no longer dirty left through a legitimate clear.
        // A key still marked dirty cannot leave, so that one is a fault.
        if page.is_none() && self.dirty.contains(&key) {
            return Err(self.latch(CacheFault::new(OPERATION, DIRTY_NOT_RESIDENT, None)));
        }
        Ok(page)
    }

    /// Lookup that also pins, returning the slab index to release it with. One
    /// hash lookup serves the read, the `visited` bit, and the pin — the read
    /// path's hottest operation, so the separate `pin` call it replaces was a
    /// second hash of the same key.
    pub fn get_and_pin(
        &mut self,
        key: (FileKey, u64),
    ) -> Result<Option<(Arc<Page>, usize)>, CacheFault> {
        const OPERATION: &str = "get_and_pin";
        self.guarded(|cache| {
            let Some(&idx) = cache.map.get(&key) else {
                return Ok(None);
            };
            let node = cache.pin_resident(idx, key, OPERATION)?;
            node.visited = true;
            Ok(Some((node.page.clone(), idx)))
        })
    }

    /// Add a pin to the entry at `idx` and return it.
    fn pin_resident(
        &mut self,
        idx: usize,
        key: (FileKey, u64),
        operation: &'static str,
    ) -> Result<&mut Node, CacheFault> {
        let node = Self::keyed_node_mut(&mut self.slab, idx, key, operation)?;
        if Self::is_evictable(node, &self.dirty) {
            self.evictable = Self::one_less(self.evictable, operation)?;
        }
        node.pins = node.pins.saturating_add(1);
        Ok(node)
    }

    /// Release a pin taken at `idx`. `key` identifies the entry the pin was
    /// taken on. Every removal path spares pinned entries, so a live pin always
    /// finds its own entry.
    ///
    /// A stale slot, another key, or a release with no pin latches a fault. The
    /// caller is a guard drop or an error branch, so the next operation reports
    /// it.
    ///
    /// An over-budget pool has nothing evictable, so at most this entry becomes
    /// a candidate. The trim below is therefore at most one eviction.
    pub fn unpin_at(&mut self, idx: usize, key: (FileKey, u64)) {
        const OPERATION: &str = "unpin_at";
        let _ = self.guarded(|cache| {
            let node = Self::keyed_node_mut(&mut cache.slab, idx, key, OPERATION)?;
            if node.pins == 0 {
                return Err(CacheFault::new(OPERATION, RELEASE_WITHOUT_PIN, Some(idx)));
            }
            node.pins -= 1;
            if Self::is_evictable(node, &cache.dirty) {
                cache.evictable = cache.evictable.saturating_add(1);
                if cache.map.len() > cache.capacity {
                    cache.trim_to(cache.capacity)?;
                }
            }
            cache.check_within_budget(OPERATION)
        });
    }

    /// Insert `(key, page)`, trimming the pool first if it is at capacity. A new
    /// clean entry on a pool of dirty and pinned pages stays over budget until
    /// the caller marks it dirty under the same lock.
    pub fn insert(&mut self, key: (FileKey, u64), page: Arc<Page>) -> Result<(), CacheFault> {
        const OPERATION: &str = "insert";
        self.guarded(|cache| {
            // Update in place if key already present (preserve list position).
            if let Some(&idx) = cache.map.get(&key) {
                Self::keyed_node_mut(&mut cache.slab, idx, key, OPERATION)?.page = page;
                return Ok(());
            }
            cache.insert_new(key, page, 0, OPERATION)?;
            Ok(())
        })
    }

    /// [`insert`](Self::insert) that also pins the entry, returning the slab
    /// index to release it with. A new entry never counts as evictable. A
    /// present key keeps its list position, takes the new page, and adds a pin.
    pub fn insert_and_pin(
        &mut self,
        key: (FileKey, u64),
        page: Arc<Page>,
    ) -> Result<usize, CacheFault> {
        const OPERATION: &str = "insert_and_pin";
        self.guarded(|cache| {
            if let Some(&idx) = cache.map.get(&key) {
                cache.pin_resident(idx, key, OPERATION)?.page = page;
                return Ok(idx);
            }
            cache.insert_new(key, page, 1, OPERATION)
        })
    }

    /// Splice a new entry in as head, holding `pins` pins from the start. A key
    /// is resident when marked dirty, so a new entry always starts on the list.
    fn insert_new(
        &mut self,
        key: (FileKey, u64),
        page: Arc<Page>,
        pins: u32,
        operation: &'static str,
    ) -> Result<usize, CacheFault> {
        // The trim runs before the entry exists, so it is never its own victim.
        if self.map.len() >= self.capacity {
            self.trim_to(self.capacity.saturating_sub(1))?;
        }
        let idx = self.alloc_node(
            Node {
                key,
                page,
                pins,
                visited: false,
                linked: false,
                prev: None,
                next: None,
            },
            operation,
        )?;
        self.link_as_head(idx, operation)?;
        self.map.insert(key, idx);
        if pins == 0 && !self.dirty.contains(&key) {
            self.evictable = self.evictable.saturating_add(1);
        }
        Ok(idx)
    }

    /// Splice the unlinked node at `idx` in as the newest entry. A node already
    /// on the list reports a fault and changes nothing.
    fn link_as_head(&mut self, idx: usize, operation: &'static str) -> Result<(), CacheFault> {
        let old_head = self.head;
        let node = Self::node_mut(&mut self.slab, idx, operation)?;
        if node.linked {
            return Err(CacheFault::new(operation, NODE_ALREADY_LINKED, Some(idx)));
        }
        node.linked = true;
        node.prev = old_head;
        node.next = None;
        if let Some(old_head) = old_head {
            Self::node_mut(&mut self.slab, old_head, operation)?.next = Some(idx);
        } else {
            // The list is empty, so this node is also the new tail.
            self.tail = Some(idx);
        }
        self.head = Some(idx);
        Ok(())
    }

    /// Take the node at `idx` off the list, moving the hand off it first. A node
    /// already off the list is left alone.
    fn unlink_from_list(&mut self, idx: usize, operation: &'static str) -> Result<(), CacheFault> {
        let node = Self::node_mut(&mut self.slab, idx, operation)?;
        if !node.linked {
            return Ok(());
        }
        node.linked = false;
        let (prev, next) = (node.prev.take(), node.next.take());
        if self.hand == Some(idx) {
            self.hand = next;
        }
        self.unlink_node(prev, next, operation)
    }

    /// Evict entries until at most `target` remain or none is evictable. This is
    /// the only caller of [`evict_one`](Self::evict_one).
    ///
    /// Each eviction resumes from the hand. A batch therefore walks at most two
    /// passes over the list plus its evictions.
    fn trim_to(&mut self, target: usize) -> Result<(), CacheFault> {
        const OPERATION: &str = "trim_to";
        // A drifted count either skips a possible eviction (unbounded growth)
        // or reintroduces the sweep it exists to avoid. The recount costs one
        // map walk, so it runs once per trim and in debug builds only.
        if cfg!(debug_assertions) {
            self.check_evictable_count(OPERATION)?;
            self.check_list_membership(OPERATION)?;
        }
        // With nothing clean and unpinned, no sweep can succeed. The zero check
        // ends the trim without a walk.
        while self.map.len() > target && self.evictable > 0 {
            self.evict_one()?;
        }
        Ok(())
    }

    /// Report a pool over budget with a candidate left, in debug builds only.
    fn check_within_budget(&self, operation: &'static str) -> Result<(), CacheFault> {
        if cfg!(debug_assertions) && self.map.len() > self.capacity && self.evictable > 0 {
            return Err(CacheFault::new(operation, OVER_BUDGET, None));
        }
        Ok(())
    }

    /// Evict one candidate. The caller has seen a positive `evictable` count, so
    /// a walk that finds no victim is a fault.
    fn evict_one(&mut self) -> Result<(), CacheFault> {
        const OPERATION: &str = "evict_one";
        // The bound uses the live list length, which holds every entry not dirty.
        // Pinned pages can grow the list past the configured capacity.
        // Each wrap past head uses one loop iteration.
        // The worst case is one evictable visited entry directly behind the hand.
        // That entry needs two passes over the list plus two wraps.
        let list_len = self.map.len().saturating_sub(self.dirty.len());
        let max_steps = list_len.saturating_add(1).saturating_mul(2);
        let mut cur = self.hand.or(self.tail);
        for _ in 0..max_steps {
            #[cfg(test)]
            {
                self.walk_visits = self.walk_visits.saturating_add(1);
            }
            let Some(idx) = cur else {
                // Reached past head — wrap to tail.
                cur = self.tail;
                continue;
            };
            let node = Self::node_mut(&mut self.slab, idx, OPERATION)?;
            let (key, prev_idx, next_idx) = (node.key, node.prev, node.next);
            if cfg!(debug_assertions) && self.dirty.contains(&key) {
                return Err(CacheFault::new(
                    OPERATION,
                    LIST_MEMBERSHIP_DRIFTED,
                    Some(idx),
                ));
            }
            if !Self::is_evictable(node, &self.dirty) {
                // Skip a pinned entry without touching the visited bit.
                cur = next_idx;
                continue;
            }
            if node.visited {
                node.visited = false;
                cur = next_idx;
                continue;
            }
            // Evict this node. Advance hand to the next node (toward head)
            // so subsequent evictions resume from the right place.
            self.unlink_node(prev_idx, next_idx, OPERATION)?;
            self.hand = next_idx;
            self.map.remove(&key);
            self.free_node(idx, OPERATION)?;
            self.evictable = Self::one_less(self.evictable, OPERATION)?;
            return Ok(());
        }
        Err(CacheFault::new(OPERATION, NO_VICTIM, None))
    }

    /// Recount the candidates and compare against `evictable`.
    fn check_evictable_count(&self, operation: &'static str) -> Result<(), CacheFault> {
        let mut candidates = 0_usize;
        for &idx in self.map.values() {
            if Self::is_evictable(Self::node(&self.slab, idx, operation)?, &self.dirty) {
                candidates = candidates.saturating_add(1);
            }
        }
        if candidates == self.evictable {
            Ok(())
        } else {
            Err(CacheFault::new(operation, EVICTABLE_COUNT_DRIFTED, None))
        }
    }

    /// Compare each entry's list membership against its dirty marker.
    fn check_list_membership(&self, operation: &'static str) -> Result<(), CacheFault> {
        for (key, &idx) in &self.map {
            let node = Self::node(&self.slab, idx, operation)?;
            if node.linked == self.dirty.contains(key) {
                return Err(CacheFault::new(
                    operation,
                    LIST_MEMBERSHIP_DRIFTED,
                    Some(idx),
                ));
            }
        }
        Ok(())
    }

    fn alloc_node(&mut self, node: Node, operation: &'static str) -> Result<usize, CacheFault> {
        let Some(idx) = self.free.pop() else {
            let idx = self.slab.len();
            self.slab.push(Some(node));
            return Ok(idx);
        };
        let slot = self
            .slab
            .get_mut(idx)
            .ok_or_else(|| CacheFault::new(operation, SLOT_EMPTY, Some(idx)))?;
        // A slot on the free list that still holds an entry is a live page
        // about to be overwritten.
        if slot.is_some() {
            return Err(CacheFault::new(operation, SLOT_HOLDS_OTHER_KEY, Some(idx)));
        }
        *slot = Some(node);
        Ok(idx)
    }

    fn free_node(&mut self, idx: usize, operation: &'static str) -> Result<(), CacheFault> {
        self.slab
            .get_mut(idx)
            .and_then(Option::take)
            .ok_or_else(|| CacheFault::new(operation, SLOT_EMPTY, Some(idx)))?;
        self.free.push(idx);
        Ok(())
    }

    fn unlink_node(
        &mut self,
        prev: Option<usize>,
        next: Option<usize>,
        operation: &'static str,
    ) -> Result<(), CacheFault> {
        if let Some(p) = prev {
            Self::node_mut(&mut self.slab, p, operation)?.next = next;
        } else {
            self.tail = next;
        }
        if let Some(n) = next {
            Self::node_mut(&mut self.slab, n, operation)?.prev = prev;
        } else {
            self.head = prev;
        }
        Ok(())
    }

    /// Mark a resident entry dirty and take it off the eviction list. A key with
    /// no entry has nothing to flush, so it reports `dirty page not resident`.
    pub fn mark_dirty(&mut self, key: (FileKey, u64)) -> Result<(), CacheFault> {
        const OPERATION: &str = "mark_dirty";
        self.guarded(|cache| {
            let Some(&idx) = cache.map.get(&key) else {
                return Err(CacheFault::new(OPERATION, DIRTY_NOT_RESIDENT, None));
            };
            let node = Self::keyed_node(&cache.slab, idx, key, OPERATION)?;
            if Self::is_evictable(node, &cache.dirty) {
                cache.evictable = Self::one_less(cache.evictable, OPERATION)?;
            }
            cache.dirty.insert(key);
            cache.unlink_from_list(idx, OPERATION)
        })
    }

    /// Clear a dirty marker and link the entry as the newest. A key that is
    /// already clean is a no-op. A failed call leaves the marker set, so the page
    /// stays visible to the flush check.
    ///
    /// This does not trim, because a trim per key is quadratic. Each batch caller
    /// trims once at its end.
    fn clear_dirty(&mut self, key: (FileKey, u64)) -> Result<(), CacheFault> {
        const OPERATION: &str = "clear_dirty";
        self.guarded(|cache| {
            if !cache.dirty.contains(&key) {
                return Ok(());
            }
            let Some(&idx) = cache.map.get(&key) else {
                return Err(CacheFault::new(OPERATION, DIRTY_NOT_RESIDENT, None));
            };
            let unpinned = Self::keyed_node(&cache.slab, idx, key, OPERATION)?.pins == 0;
            cache.link_as_head(idx, OPERATION)?;
            cache.dirty.remove(&key);
            if unpinned {
                cache.evictable = cache.evictable.saturating_add(1);
            }
            Ok(())
        })
    }

    /// Clear the dirty markers of pages that reached disk, then return the pool
    /// to its budget.
    ///
    /// Only a page still holding the gathered `Arc<Page>` is cleared. A concurrent
    /// writer replaces the `Arc` on every write. Clearing its flag loses content
    /// that never reached disk, so the next cold read finds a stale page. A
    /// replaced page keeps its flag and flushes on the next cycle.
    pub fn finish_flush(
        &mut self,
        file: FileKey,
        gathered: Vec<(u64, Arc<Page>)>,
    ) -> Result<(), CacheFault> {
        const OPERATION: &str = "finish_flush";
        for (pid, snapshot) in gathered {
            match self.get((file, pid))? {
                Some(current) if Arc::ptr_eq(&current, &snapshot) => {
                    self.clear_dirty((file, pid))?;
                }
                _ => {
                    tracing::debug!(
                        page_id = pid,
                        "page re-dirtied during flush; keeping dirty for next cycle"
                    );
                }
            }
        }
        self.guarded(|cache| cache.settle_batch(OPERATION))
    }

    /// Clear every dirty marker of `file` without flushing, then return the pool
    /// to its budget. A fault stops the loop and stays latched, so the pages
    /// still marked dirty never reach disk.
    pub fn discard_dirty(&mut self, file: FileKey) {
        const OPERATION: &str = "discard_dirty";
        for pid in self.dirty_for_file(file) {
            if self.clear_dirty((file, pid)).is_err() {
                return;
            }
        }
        let _ = self.guarded(|cache| cache.settle_batch(OPERATION));
    }

    /// The single trim that ends a batch, plus its index memory reclaim.
    fn settle_batch(&mut self, operation: &'static str) -> Result<(), CacheFault> {
        self.trim_to(self.capacity)?;
        self.reclaim_index_memory()?;
        self.check_within_budget(operation)
    }

    /// Return the map and slab memory of an overgrown pool once the pool shrinks.
    /// The cost is linear in `slab.len()`.
    fn reclaim_index_memory(&mut self) -> Result<(), CacheFault> {
        const OPERATION: &str = "reclaim_index_memory";
        let bound = self.capacity.saturating_mul(2);
        if self.map.capacity() <= bound && self.slab.len() <= bound {
            return Ok(());
        }
        self.map.shrink_to(self.capacity);
        self.compact_high_slots(OPERATION)?;
        let keep = self
            .slab
            .iter()
            .rposition(Option::is_some)
            .map_or(0, |top| top.saturating_add(1));
        self.slab.truncate(keep);
        self.slab.shrink_to(self.capacity);
        // Listed highest first, so allocation pops the lowest free slot.
        let free_slots = self
            .slab
            .iter()
            .enumerate()
            .rev()
            .filter_map(|(idx, slot)| slot.is_none().then_some(idx));
        self.free.clear();
        self.free.extend(free_slots);
        self.free.shrink_to_fit();
        if self.free.len().saturating_add(self.map.len()) != self.slab.len() {
            return Err(CacheFault::new(OPERATION, LIVE_SLOTS_DRIFTED, None));
        }
        Ok(())
    }

    /// Move unpinned nodes from the top of the slab into its lowest free slots.
    /// The walk stops at the highest pin. A `PageGuard` holds that slot, so the
    /// slab cannot truncate below it, and a move below it frees nothing.
    fn compact_high_slots(&mut self, operation: &'static str) -> Result<(), CacheFault> {
        let mut low = 0_usize;
        for high in (0..self.slab.len()).rev() {
            let Some(node) = self.slab.get(high).and_then(Option::as_ref) else {
                continue;
            };
            if node.pins > 0 {
                break;
            }
            while low < high && matches!(self.slab.get(low), Some(Some(_))) {
                low = low.saturating_add(1);
            }
            if low >= high {
                break;
            }
            self.move_node(high, low, operation)?;
        }
        Ok(())
    }

    /// Move an unpinned node into the free slot `to`. This fixes the map entry,
    /// and for a node on the list also its list links. Dirty tracking is by key,
    /// and a dirty node is off the list, so only its map entry changes.
    fn move_node(
        &mut self,
        from: usize,
        to: usize,
        operation: &'static str,
    ) -> Result<(), CacheFault> {
        let node = Self::node(&self.slab, from, operation)?;
        let (key, linked, prev, next) = (node.key, node.linked, node.prev, node.next);
        if linked {
            self.retarget_list_links(from, to, prev, next, operation)?;
        }
        match self.map.get_mut(&key) {
            Some(mapped) if *mapped == from => *mapped = to,
            _ => {
                return Err(CacheFault::new(operation, MAP_SLOT_DISAGREES, Some(from)));
            }
        }
        let moved = self.slab.get_mut(from).and_then(Option::take);
        let slot = self
            .slab
            .get_mut(to)
            .ok_or_else(|| CacheFault::new(operation, SLOT_EMPTY, Some(to)))?;
        if slot.is_some() {
            return Err(CacheFault::new(operation, SLOT_HOLDS_OTHER_KEY, Some(to)));
        }
        *slot = moved;
        Ok(())
    }

    /// Point the neighbours, `head`, `tail`, and `hand` of the linked node at
    /// `from` to its new slot `to`.
    fn retarget_list_links(
        &mut self,
        from: usize,
        to: usize,
        prev: Option<usize>,
        next: Option<usize>,
        operation: &'static str,
    ) -> Result<(), CacheFault> {
        let broken = CacheFault::new(operation, LIST_LINK_BROKEN, Some(from));
        if let Some(p) = prev {
            let neighbour = Self::node_mut(&mut self.slab, p, operation)?;
            if neighbour.next != Some(from) {
                return Err(broken);
            }
            neighbour.next = Some(to);
        } else if self.tail == Some(from) {
            self.tail = Some(to);
        } else {
            return Err(broken);
        }
        if let Some(n) = next {
            let neighbour = Self::node_mut(&mut self.slab, n, operation)?;
            if neighbour.prev != Some(from) {
                return Err(broken);
            }
            neighbour.prev = Some(to);
        } else if self.head == Some(from) {
            self.head = Some(to);
        } else {
            return Err(broken);
        }
        if self.hand == Some(from) {
            self.hand = Some(to);
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
    pub fn clear_file(&mut self, file: FileKey) -> Result<(), CacheFault> {
        self.clear_file_entries(file, false)
    }

    /// Drop every unpinned clean entry for `file`, leaving dirty entries
    /// available for a later flush and pinned entries available to readers.
    /// Used to force a re-read of the durable bytes without discarding the
    /// in-flight writes that have not reached them yet.
    #[cfg(test)]
    pub fn clear_clean_file(&mut self, file: FileKey) -> Result<(), CacheFault> {
        self.clear_file_entries(file, true)
    }

    /// Shared body of the two `clear_*` entry points. Pinned entries are always
    /// spared: a reader holds them. `keep_dirty` decides whether an unflushed
    /// entry is spared as well, or dropped along with its dirty marker.
    fn clear_file_entries(&mut self, file: FileKey, keep_dirty: bool) -> Result<(), CacheFault> {
        const OPERATION: &str = "clear_file";
        self.guarded(|cache| {
            let entries: Vec<((FileKey, u64), usize)> = cache
                .map
                .iter()
                .filter(|((f, _), _)| *f == file)
                .map(|(&key, &idx)| (key, idx))
                .collect();
            for (key, idx) in entries {
                let node = Self::keyed_node(&cache.slab, idx, key, OPERATION)?;
                if node.pins > 0 {
                    continue;
                }
                if keep_dirty && cache.dirty.contains(&key) {
                    continue;
                }
                let was_evictable = Self::is_evictable(node, &cache.dirty);
                cache.map.remove(&key);
                cache.unlink_from_list(idx, OPERATION)?;
                cache.free_node(idx, OPERATION)?;
                if was_evictable {
                    cache.evictable = Self::one_less(cache.evictable, OPERATION)?;
                }
                if !keep_dirty {
                    cache.dirty.remove(&key);
                }
            }
            Ok(())
        })
    }

    /// Whether `key` is resident. Leaves the `visited` bit alone, so a test can
    /// observe an eviction without changing the next one.
    #[cfg(test)]
    fn contains(&self, key: (FileKey, u64)) -> bool {
        self.map.contains_key(&key)
    }

    /// Empty a slab slot behind the map's back, to inject a dead-slot fault.
    #[cfg(test)]
    pub(crate) fn clear_slot(&mut self, idx: usize) {
        self.slab[idx] = None;
    }

    /// Remove a key from the map alone, to inject a non-resident dirty page.
    #[cfg(test)]
    pub(crate) fn forget_key(&mut self, key: (FileKey, u64)) {
        self.map.remove(&key);
    }

    /// Rewrite the key a slab slot holds, to inject a stale-index fault.
    #[cfg(test)]
    fn set_slot_key(&mut self, idx: usize, key: (FileKey, u64)) {
        self.slab[idx].as_mut().unwrap().key = key;
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
                .unwrap()
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
        c.insert((FileKey::Main, 3), page(3)).unwrap();
        assert!(!c.contains((FileKey::Main, 1)));
        assert!(c.get((FileKey::Main, 1)).unwrap().is_none());
        assert!(c.get((FileKey::Main, 2)).unwrap().is_some());
        assert!(c.get((FileKey::Main, 3)).unwrap().is_some());
    }

    #[test]
    fn visited_entries_survive_one_pass() {
        // SIEVE: hit sets visited; first hand pass clears it; second pass evicts.
        let mut c = PageCache::with_capacity(2);
        c.insert((FileKey::Main, 1), page(1)).unwrap();
        c.insert((FileKey::Main, 2), page(2)).unwrap();
        let _ = c.get((FileKey::Main, 1)).unwrap(); // mark 1 as visited
        // Hand starts at tail = 1, sees visited, clears, moves to 2 (unvisited): evicts 2.
        c.insert((FileKey::Main, 3), page(3)).unwrap();
        assert!(!c.contains((FileKey::Main, 2)));
        assert!(
            c.get((FileKey::Main, 1)).unwrap().is_some(),
            "recently-used survives"
        );
    }

    #[test]
    fn pinned_pages_survive_eviction() {
        let mut c = PageCache::with_capacity(2);
        c.insert_and_pin((FileKey::Main, 1), page(1)).unwrap();
        c.insert((FileKey::Main, 2), page(2)).unwrap();
        c.insert((FileKey::Main, 3), page(3)).unwrap();
        assert!(!c.contains((FileKey::Main, 2)));
        assert!(
            c.get((FileKey::Main, 1)).unwrap().is_some(),
            "pinned page must survive"
        );
    }

    #[test]
    fn releasing_the_last_pin_makes_an_entry_evictable_again() {
        let mut c = PageCache::with_capacity(2);
        let key = (FileKey::Main, 1);
        let idx = c.insert_and_pin(key, page(1)).unwrap();
        c.insert((FileKey::Main, 2), page(2)).unwrap();
        c.insert((FileKey::Main, 3), page(3)).unwrap();
        assert!(!c.contains((FileKey::Main, 2)));
        assert!(c.contains(key));

        c.unpin_at(idx, key);
        // Unpinned and never re-read, so it is now the eviction hand's victim.
        c.insert((FileKey::Main, 4), page(4)).unwrap();
        assert!(!c.contains(key));
        assert!(c.contains((FileKey::Main, 3)));
    }

    #[test]
    fn nested_pins_each_need_releasing() {
        let mut c = PageCache::with_capacity(2);
        let key = (FileKey::Main, 1);
        let idx = c.insert_and_pin(key, page(1)).unwrap();
        c.get_and_pin(key).unwrap().unwrap();

        c.unpin_at(idx, key);
        c.insert((FileKey::Main, 2), page(2)).unwrap();
        c.insert((FileKey::Main, 3), page(3)).unwrap();
        assert!(
            !c.contains((FileKey::Main, 2)) && c.contains(key),
            "one outstanding pin still protects the entry"
        );
    }

    /// Slab slots are recycled, so an index outliving its entry must not
    /// decrement whatever now occupies the slot. No production path does this,
    /// so the stale release is a fault as well.
    #[test]
    fn stale_unpin_latches_a_fault_and_leaves_the_occupant_pinned() {
        let mut c = PageCache::with_capacity(1);
        let old_key = (FileKey::Main, 1);
        let idx = c.insert_and_pin(old_key, page(1)).unwrap();
        c.unpin_at(idx, old_key);
        c.insert((FileKey::Main, 2), page(2)).unwrap();
        assert!(!c.contains(old_key));

        // The slot now belongs to page 2. Pin it, then replay the stale
        // release for page 1 against the same index.
        let new_key = (FileKey::Main, 2);
        let new_idx = c.insert_and_pin(new_key, page(2)).unwrap();
        assert_eq!(new_idx, idx, "the fixture must recycle the slot");
        c.unpin_at(idx, old_key);

        assert_eq!(
            c.check_usable(),
            Err(CacheFault::new("unpin_at", SLOT_HOLDS_OTHER_KEY, Some(idx)))
        );
        assert!(c.contains(new_key));
        assert_eq!(
            PageCache::node(&c.slab, new_idx, "test").unwrap().pins,
            1,
            "the stale release must not have unpinned the new occupant"
        );
        assert_eq!(c.evictable, 0);
    }

    #[test]
    fn dead_slot_lookup_reports_a_typed_fault() {
        let key = (FileKey::Main, 1);

        let mut dead = PageCache::with_capacity(4);
        dead.insert(key, page(1)).unwrap();
        let idx = dead.map[&key];
        dead.clear_slot(idx);
        assert_eq!(
            dead.get(key).err(),
            Some(CacheFault::new("get", SLOT_EMPTY, Some(idx)))
        );

        let mut out_of_range = PageCache::with_capacity(4);
        out_of_range.map.insert(key, 99);
        assert_eq!(
            out_of_range.get_and_pin(key).err(),
            Some(CacheFault::new("get_and_pin", SLOT_EMPTY, Some(99)))
        );
    }

    /// A stale map index must not hand back another page's plaintext.
    #[test]
    fn slot_holding_another_key_reports_a_fault() {
        let key = (FileKey::Main, 1);
        let other = (FileKey::Main, 2);

        let mut c = PageCache::with_capacity(4);
        c.insert(key, page(1)).unwrap();
        let idx = c.map[&key];
        c.set_slot_key(idx, other);
        assert_eq!(
            c.get(key).err(),
            Some(CacheFault::new("get", SLOT_HOLDS_OTHER_KEY, Some(idx)))
        );

        let mut pinning = PageCache::with_capacity(4);
        pinning.insert(key, page(1)).unwrap();
        let idx = pinning.map[&key];
        pinning.set_slot_key(idx, other);
        assert_eq!(
            pinning.get_and_pin(key).err(),
            Some(CacheFault::new(
                "get_and_pin",
                SLOT_HOLDS_OTHER_KEY,
                Some(idx)
            ))
        );
        assert_eq!(pinning.evictable, 1, "a failed pin changes no count");
    }

    #[test]
    fn double_release_latches_a_fault() {
        let mut c = PageCache::with_capacity(4);
        let key = (FileKey::Main, 1);
        let idx = c.insert_and_pin(key, page(1)).unwrap();
        c.unpin_at(idx, key);
        assert_eq!(c.check_usable(), Ok(()));

        c.unpin_at(idx, key);
        assert_eq!(
            c.check_usable(),
            Err(CacheFault::new("unpin_at", RELEASE_WITHOUT_PIN, Some(idx)))
        );
        assert_eq!(c.evictable, 1, "the second release must not overcount");
    }

    #[test]
    fn latched_fault_fails_every_fallible_operation() {
        let mut c = PageCache::with_capacity(4);
        let dead = (FileKey::Main, 1);
        let healthy = (FileKey::Main, 2);
        let absent = (FileKey::Main, 3);
        c.insert(dead, page(1)).unwrap();
        let pinned_slot = c.insert_and_pin(healthy, page(2)).unwrap();
        c.mark_dirty(healthy).unwrap();
        let idx = c.map[&dead];
        c.clear_slot(idx);

        let first = CacheFault::new("get", SLOT_EMPTY, Some(idx));
        assert_eq!(c.get(dead).err(), Some(first));

        assert_eq!(c.check_usable(), Err(first));
        assert_eq!(c.get(healthy).err(), Some(first));
        assert_eq!(c.get_dirty(healthy).err(), Some(first));
        assert_eq!(c.get_and_pin(healthy).err(), Some(first));
        assert_eq!(c.insert(absent, page(3)), Err(first));
        assert_eq!(c.insert_and_pin(absent, page(3)), Err(first));
        assert_eq!(c.mark_dirty(absent), Err(first));
        assert_eq!(c.clear_dirty(healthy), Err(first));
        assert_eq!(c.finish_flush(FileKey::Main, Vec::new()), Err(first));
        c.discard_dirty(FileKey::Main);
        assert_eq!(c.clear_file(FileKey::Main), Err(first));
        assert_eq!(c.clear_clean_file(FileKey::Main), Err(first));

        c.unpin_at(pinned_slot, healthy);
        assert_eq!(c.check_usable(), Err(first), "the first fault stays");
        assert_eq!(
            PageCache::node(&c.slab, pinned_slot, "test").unwrap().pins,
            1,
            "a latched cache changes nothing"
        );
        assert_eq!(c.len(), 2);
        assert_eq!(c.dirty_len(), 1);
        assert!(!c.contains(absent));
    }

    /// A severed list keeps the count accurate. The debug recount passes, so
    /// every build reports the same fault.
    #[test]
    fn positive_evictable_with_no_victim_reports_a_fault() {
        let mut c = PageCache::with_capacity(1);
        c.insert((FileKey::Main, 1), page(1)).unwrap();
        c.tail = None;
        c.hand = None;
        assert_eq!(c.evictable, 1);

        assert_eq!(
            c.insert((FileKey::Main, 2), page(2)),
            Err(CacheFault::new("evict_one", NO_VICTIM, None))
        );
        assert!(!c.contains((FileKey::Main, 2)));
    }

    #[test]
    fn evictable_underflow_reports_a_fault() {
        let mut c = PageCache::with_capacity(4);
        let key = (FileKey::Main, 1);
        c.insert(key, page(1)).unwrap();
        c.evictable = 0;

        assert_eq!(
            c.get_and_pin(key).err(),
            Some(CacheFault::new(
                "get_and_pin",
                EVICTABLE_COUNT_DRIFTED,
                None
            ))
        );
    }

    #[test]
    fn dirty_key_with_no_entry_reports_a_fault() {
        let key = (FileKey::Main, 1);

        let mut marking = PageCache::with_capacity(4);
        assert_eq!(
            marking.mark_dirty(key),
            Err(CacheFault::new("mark_dirty", DIRTY_NOT_RESIDENT, None))
        );

        let mut reading = PageCache::with_capacity(4);
        reading.dirty.insert(key);
        assert_eq!(
            reading.get_dirty(key).err(),
            Some(CacheFault::new("get_dirty", DIRTY_NOT_RESIDENT, None))
        );
    }

    #[test]
    fn cache_fault_message_names_reopen_and_refuses_quarantine() {
        let fault = CacheFault::new("unpin_at", RELEASE_WITHOUT_PIN, Some(3));
        let message = PagedbError::from(fault).to_string();

        for expected in [
            "unpin_at",
            RELEASE_WITHOUT_PIN,
            "Some(3)",
            "no fault is known in the store files",
            "do not quarantine",
            "close this handle and reopen",
        ] {
            assert!(message.contains(expected), "{expected:?} not in {message}");
        }
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
        c.insert((FileKey::Main, 7), page(7)).unwrap();
        assert!(!c.contains((FileKey::Main, 3)));
        assert_eq!(c.len(), 6, "only page 3 left");
        // Page 3 left, but page 7 arrived clean and is a candidate in its turn.
        assert_eq!(c.evictable, 1);
    }

    #[test]
    fn evictable_count_tracks_pin_and_dirty_transitions() {
        let mut c = PageCache::with_capacity(8);
        let key = (FileKey::Main, 1);
        c.insert(key, page(1)).unwrap();
        assert_eq!(c.evictable, 1, "a fresh clean entry is a candidate");

        let (_, idx) = c.get_and_pin(key).unwrap().unwrap();
        assert_eq!(c.evictable, 0, "pinned");
        c.mark_dirty(key).unwrap();
        assert_eq!(c.evictable, 0, "pinned and dirty");
        c.unpin_at(idx, key);
        assert_eq!(c.evictable, 0, "still dirty");
        c.clear_dirty(key).unwrap();
        assert_eq!(c.evictable, 1, "clean and unpinned again");
    }

    #[test]
    fn insert_and_pin_on_a_present_key_replaces_the_page_and_adds_a_pin() {
        let mut c = PageCache::with_capacity(4);
        let key = (FileKey::Main, 1);
        c.insert(key, page(1)).unwrap();
        assert_eq!(c.evictable, 1);

        let idx = c.insert_and_pin(key, page(2)).unwrap();
        assert_eq!(c.evictable, 0, "the pin removes the candidate");
        assert_eq!(c.len(), 1);

        let again = c.insert_and_pin(key, page(3)).unwrap();
        assert_eq!(again, idx);
        assert_eq!(c.evictable, 0, "a second pin changes no count");
        assert_eq!(c.get(key).unwrap().unwrap().bytes[0], 3);

        c.unpin_at(idx, key);
        assert_eq!(c.evictable, 0, "one pin is left");
        c.unpin_at(idx, key);
        assert_eq!(c.evictable, 1, "the last release restores the candidate");
    }

    #[test]
    fn dirty_pages_not_evicted() {
        let mut c = PageCache::with_capacity(2);
        c.insert((FileKey::Main, 1), page(1)).unwrap();
        c.mark_dirty((FileKey::Main, 1)).unwrap();
        c.insert((FileKey::Main, 2), page(2)).unwrap();
        c.insert((FileKey::Main, 3), page(3)).unwrap();
        assert!(!c.contains((FileKey::Main, 2)));
        assert!(c.get((FileKey::Main, 1)).unwrap().is_some());
    }

    #[test]
    fn clear_clean_file_preserves_dirty_entries() {
        let mut c = PageCache::with_capacity(4);
        c.insert((FileKey::Main, 1), page(1)).unwrap();
        c.insert((FileKey::Main, 2), page(2)).unwrap();
        c.mark_dirty((FileKey::Main, 2)).unwrap();

        c.clear_clean_file(FileKey::Main).unwrap();

        assert!(c.get((FileKey::Main, 1)).unwrap().is_none());
        assert!(c.get((FileKey::Main, 2)).unwrap().is_some());
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
        assert!(c.get((FileKey::Main, 1)).unwrap().is_some());
        assert!(c.get((FileKey::Segment([0; 16]), 1)).unwrap().is_some());
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
            c.insert_and_pin(key, page(id)).unwrap();
        }
        c.insert((FileKey::Main, 5), page(5)).unwrap();
        assert_eq!(c.len(), 5, "pinned pages may force temporary growth");

        c.insert((FileKey::Main, 6), page(6)).unwrap();
        assert!(
            !c.contains((FileKey::Main, 5)),
            "eviction must scan the full over-capacity list for a clean victim"
        );
        assert_eq!(c.len(), 5);
        assert!(c.get((FileKey::Main, 5)).unwrap().is_none());
        assert!(c.get((FileKey::Main, 6)).unwrap().is_some());
    }

    /// A flush can race a legitimate clear. That is a one-off miss, never a latch.
    #[test]
    fn get_dirty_on_a_cleared_key_reports_no_page_without_a_fault() {
        let mut c = PageCache::with_capacity(4);
        let key = (FileKey::Main, 1);
        assert!(c.get_dirty(key).unwrap().is_none());
        c.check_usable().unwrap();
    }

    /// The hand clears the visited bit, wraps past head, and evicts on its
    /// second visit. The wrap uses a loop iteration of its own.
    #[test]
    fn evict_takes_a_lone_visited_head_entry() {
        let mut c = PageCache::with_capacity(1);
        let key = (FileKey::Main, 1);
        c.insert(key, page(1)).unwrap();
        let _ = c.get(key).unwrap();

        c.insert((FileKey::Main, 2), page(2)).unwrap();
        assert!(!c.contains(key));
        assert_eq!(c.len(), 1, "the eviction keeps the cache at capacity");
    }

    /// The longest possible sweep has one evictable visited entry directly
    /// behind the hand. It takes two passes over the list plus two wraps.
    #[test]
    fn evict_takes_a_lone_visited_entry_directly_behind_the_hand() {
        let mut c = PageCache::with_capacity(4);
        for id in 1u8..=4 {
            c.insert((FileKey::Main, u64::from(id)), page(id)).unwrap();
        }
        let behind = (FileKey::Main, 1);
        let _ = c.get(behind).unwrap();

        // Evicting page 2 leaves the hand on page 3, with page 1 directly behind it.
        c.insert((FileKey::Main, 5), page(5)).unwrap();
        assert!(!c.contains((FileKey::Main, 2)));
        assert_eq!(c.tail, c.map.get(&behind).copied());
        assert_eq!(c.hand, c.map.get(&(FileKey::Main, 3)).copied());

        let _ = c.get(behind).unwrap();
        // Pinned entries stay on the list, so the hand walks them on both passes.
        for id in 3..=5 {
            c.get_and_pin((FileKey::Main, id)).unwrap().unwrap();
        }
        assert_eq!(c.evictable, 1, "only page 1 is a candidate");

        c.insert((FileKey::Main, 6), page(6)).unwrap();
        assert!(!c.contains(behind));
        assert_eq!(c.len(), 4, "the eviction keeps the cache at capacity");
    }

    #[test]
    fn second_clear_of_a_clean_key_leaves_evictable_count_unchanged() {
        let mut c = PageCache::with_capacity(4);
        let key = (FileKey::Main, 1);
        c.insert(key, page(1)).unwrap();
        c.mark_dirty(key).unwrap();
        c.clear_dirty(key).unwrap();
        assert_eq!(c.evictable, 1);

        c.clear_dirty(key).unwrap();
        assert_eq!(c.evictable, 1);
    }

    fn main_key(id: u64) -> (FileKey, u64) {
        (FileKey::Main, id)
    }

    /// Add dirty main.db entries, one per id, in ascending list order.
    fn add_dirty(c: &mut PageCache, ids: std::ops::RangeInclusive<u64>) {
        for id in ids {
            c.insert(main_key(id), page(u8::try_from(id % 251).unwrap()))
                .unwrap();
            c.mark_dirty(main_key(id)).unwrap();
        }
    }

    /// Snapshot pages the way a flush gathers them.
    fn gather(c: &mut PageCache, ids: impl Iterator<Item = u64>) -> Vec<(u64, Arc<Page>)> {
        ids.map(|id| (id, c.get_dirty(main_key(id)).unwrap().unwrap()))
            .collect()
    }

    /// Walk the list both ways against the map, the free list, and the counts. A
    /// dirty entry is absent from the walk and has no list links.
    fn assert_list_matches_map(c: &PageCache) {
        let mut walked = 0_usize;
        let mut prev = None;
        let mut cur = c.tail;
        while let Some(idx) = cur {
            let node = PageCache::node(&c.slab, idx, "test").unwrap();
            assert!(node.linked, "slot {idx} is on the list but not linked");
            assert!(!c.dirty.contains(&node.key), "slot {idx} is dirty");
            assert_eq!(
                node.prev, prev,
                "slot {idx} names the wrong older neighbour"
            );
            assert_eq!(c.map.get(&node.key), Some(&idx), "map disagrees at {idx}");
            walked += 1;
            assert!(walked <= c.map.len(), "the list holds a cycle");
            prev = Some(idx);
            cur = node.next;
        }
        assert_eq!(c.head, prev);
        assert_eq!(walked, c.map.len() - c.dirty.len());
        if let Some(hand) = c.hand {
            let node = PageCache::node(&c.slab, hand, "test").unwrap();
            assert!(node.linked, "the hand rests on an entry off the list");
        }
        c.check_evictable_count("test").unwrap();
        c.check_list_membership("test").unwrap();
        for key in &c.dirty {
            let node = PageCache::node(&c.slab, c.map[key], "test").unwrap();
            assert_eq!((node.prev, node.next), (None, None), "{key:?} has links");
        }

        let mut free = c.free.clone();
        free.sort_unstable();
        free.dedup();
        assert_eq!(free.len(), c.free.len(), "a free slot is listed twice");
        assert!(free.iter().all(|&idx| c.slab[idx].is_none()));
        assert_eq!(free.len() + c.map.len(), c.slab.len());
    }

    #[test]
    fn insert_evicts_until_below_capacity_after_overgrowth() {
        let mut c = PageCache::with_capacity(4);
        add_dirty(&mut c, 1..=10);
        for id in 1..=10 {
            c.clear_dirty(main_key(id)).unwrap();
        }
        assert_eq!(c.len(), 10, "clearing a marker does not trim");

        c.insert(main_key(11), page(11)).unwrap();

        assert_eq!(c.len(), 4);
        assert!(
            c.contains(main_key(11)),
            "the new entry is never its own victim"
        );
        for id in 8..=10 {
            assert!(c.contains(main_key(id)), "the oldest entries leave first");
        }
    }

    #[test]
    fn finish_flush_returns_pool_to_capacity() {
        let mut c = PageCache::with_capacity(4);
        add_dirty(&mut c, 1..=10);
        let gathered = gather(&mut c, 1..=10);

        c.finish_flush(FileKey::Main, gathered).unwrap();

        assert_eq!(c.len(), 4);
        assert_eq!(c.dirty_len(), 0);
        assert_eq!(c.evictable, 4);
        assert_list_matches_map(&c);
    }

    #[test]
    fn finish_flush_keeps_a_replaced_page_dirty() {
        let mut c = PageCache::with_capacity(2);
        add_dirty(&mut c, 1..=5);
        let gathered = gather(&mut c, 1..=5);
        c.insert(main_key(3), page(99)).unwrap();

        c.finish_flush(FileKey::Main, gathered).unwrap();

        assert_eq!(c.dirty_for_file(FileKey::Main), vec![3]);
        assert_eq!(c.get(main_key(3)).unwrap().unwrap().bytes[0], 99);
        assert_eq!(c.len(), 2);
        assert_eq!(c.evictable, 1);
    }

    #[test]
    fn discard_dirty_returns_pool_to_capacity() {
        let mut c = PageCache::with_capacity(4);
        let other_file = (FileKey::Segment([1; 16]), 1);
        add_dirty(&mut c, 1..=10);
        c.insert(other_file, page(1)).unwrap();
        c.mark_dirty(other_file).unwrap();

        c.discard_dirty(FileKey::Main);

        assert_eq!(c.dirty_for_file(FileKey::Main), Vec::<u64>::new());
        assert_eq!(c.dirty_len(), 1, "another file keeps its dirty page");
        assert!(c.contains(other_file));
        assert_eq!(c.len(), 4);
        c.check_usable().unwrap();
    }

    #[test]
    fn last_unpin_over_capacity_evicts_one_entry() {
        let mut c = PageCache::with_capacity(2);
        let mut slots = Vec::new();
        for id in 1u8..=4 {
            let key = main_key(u64::from(id));
            slots.push((c.insert_and_pin(key, page(id)).unwrap(), key));
        }
        let (first_slot, first_key) = slots[0];
        c.get_and_pin(first_key).unwrap().unwrap();
        assert_eq!(c.len(), 4);

        c.unpin_at(first_slot, first_key);
        assert_eq!(c.len(), 4, "a release that leaves a pin evicts nothing");

        c.unpin_at(first_slot, first_key);
        assert_eq!(c.len(), 3);
        assert!(!c.contains(first_key));

        c.unpin_at(slots[1].0, slots[1].1);
        assert_eq!(c.len(), 2);
        c.unpin_at(slots[2].0, slots[2].1);
        c.unpin_at(slots[3].0, slots[3].1);
        assert_eq!(c.len(), 2, "a pool within budget keeps its entries");
        c.check_usable().unwrap();
    }

    #[test]
    fn trim_spares_pinned_and_dirty_entries() {
        let mut c = PageCache::with_capacity(1);
        let pinned = main_key(1);
        let slot = c.insert_and_pin(pinned, page(1)).unwrap();
        add_dirty(&mut c, 2..=3);
        let gathered = gather(&mut c, 3..=3);

        c.finish_flush(FileKey::Main, gathered).unwrap();

        assert!(c.contains(pinned));
        assert!(c.contains(main_key(2)));
        assert!(!c.contains(main_key(3)));
        assert_eq!(c.evictable, 0);
        assert_eq!(c.len(), 2, "pins and dirty pages exceed the budget");

        c.unpin_at(slot, pinned);
        assert!(!c.contains(pinned));
        assert_eq!(c.len(), 1);
        c.check_usable().unwrap();
    }

    #[test]
    fn batch_trim_walk_steps_are_linear_in_entries() {
        for entries in [512_u64, 2048] {
            let mut c = PageCache::with_capacity(4);
            add_dirty(&mut c, 1..=entries);
            for id in 1..=entries {
                let _ = c.get(main_key(id)).unwrap();
            }
            let gathered = gather(&mut c, (1..=entries).filter(|id| id % 4 != 0));
            c.walk_visits = 0;

            c.finish_flush(FileKey::Main, gathered).unwrap();

            let total = usize::try_from(entries).unwrap();
            let evicted = total - c.len();
            assert_eq!(evicted, total / 4 * 3);
            let passes = (total + 1) * 2;
            assert!(
                c.walk_visits > total,
                "every visited candidate takes a clearing visit, got {}",
                c.walk_visits
            );
            assert!(
                c.walk_visits <= passes + evicted,
                "{} visits for {total} entries and {evicted} evictions",
                c.walk_visits
            );
        }
    }

    #[test]
    fn index_memory_returns_near_budget_after_overgrowth() {
        const CAPACITY: usize = 16;
        let mut c = PageCache::with_capacity(CAPACITY);
        add_dirty(&mut c, 1..=1024);
        assert!(c.map.capacity() > CAPACITY * 2);
        assert_eq!(c.slab.len(), 1024);
        let gathered = gather(&mut c, 1..=1024);

        c.finish_flush(FileKey::Main, gathered).unwrap();

        assert_eq!(c.len(), CAPACITY);
        assert!(c.map.capacity() <= CAPACITY * 2);
        assert_eq!(c.slab.len(), CAPACITY, "survivors fill the lowest slots");
        assert!(c.slab.capacity() <= CAPACITY * 2);
        assert_eq!(c.free.len(), 0);
        assert_list_matches_map(&c);

        c.insert(main_key(2000), page(1)).unwrap();
        assert_eq!(c.len(), CAPACITY);
        assert_list_matches_map(&c);
    }

    #[test]
    fn moved_nodes_keep_the_list_and_map_consistent() {
        let mut c = PageCache::with_capacity(4);
        add_dirty(&mut c, 1..=64);
        let (_, low_pin) = c.get_and_pin(main_key(21)).unwrap().unwrap();
        let (_, high_pin) = c.get_and_pin(main_key(61)).unwrap().unwrap();
        assert_eq!(
            (low_pin, high_pin),
            (20, 60),
            "slots follow insertion order"
        );
        let gathered = gather(&mut c, 1..=64);

        c.finish_flush(FileKey::Main, gathered).unwrap();

        // Pins stay put, and the two survivors above the high pin move down.
        assert_eq!(c.len(), 4);
        assert_eq!(c.map[&main_key(21)], low_pin);
        assert_eq!(c.map[&main_key(61)], high_pin);
        assert_eq!(c.map[&main_key(64)], 0);
        assert_eq!(c.map[&main_key(63)], 1);
        assert_eq!(c.hand, Some(1), "the hand follows the node it pointed at");
        assert_eq!(c.tail, Some(low_pin));
        assert_eq!(c.head, Some(0));
        assert_eq!(c.slab.len(), high_pin + 1, "the high pin bounds truncation");
        assert_list_matches_map(&c);
        for id in [21_u64, 61, 63, 64] {
            let byte = u8::try_from(id).unwrap();
            assert_eq!(c.get(main_key(id)).unwrap().unwrap().bytes[0], byte);
        }

        // New entries take low slots and leave the pinned slots alone.
        c.insert(main_key(65), page(65)).unwrap();
        assert_list_matches_map(&c);

        // Each guard slot still resolves to the entry it pinned.
        c.unpin_at(high_pin, main_key(61));
        c.unpin_at(low_pin, main_key(21));
        c.check_usable().unwrap();
        assert_eq!(c.evictable, 4);

        // With the pins gone, the next batch empties the high slots.
        c.discard_dirty(FileKey::Main);
        c.check_usable().unwrap();
        assert_eq!(c.len(), 4);
        assert_eq!(c.slab.len(), 4);
        assert_list_matches_map(&c);
    }

    #[test]
    fn a_dirty_node_keeps_its_marker_when_it_moves() {
        let mut c = PageCache::with_capacity(2);
        add_dirty(&mut c, 1..=8);
        let gathered = gather(&mut c, 1..=7);

        c.finish_flush(FileKey::Main, gathered).unwrap();

        assert_eq!(c.dirty_for_file(FileKey::Main), vec![8]);
        assert_eq!(
            c.map[&main_key(8)],
            0,
            "the dirty survivor moves to a low slot"
        );
        assert_eq!(c.get_dirty(main_key(8)).unwrap().unwrap().bytes[0], 8);
        assert_list_matches_map(&c);
    }

    #[test]
    fn a_move_over_a_broken_link_or_map_entry_reports_a_fault() {
        let free_slot = 3;
        let fixture = || {
            let mut c = PageCache::with_capacity(8);
            for id in 1..=3 {
                c.insert(main_key(id), page(1)).unwrap();
            }
            c.slab.push(None);
            c
        };

        let mut broken_link = fixture();
        broken_link.slab[0].as_mut().unwrap().next = None;
        assert_eq!(
            broken_link.move_node(1, free_slot, "test"),
            Err(CacheFault::new("test", LIST_LINK_BROKEN, Some(1)))
        );

        let mut broken_map = fixture();
        broken_map.map.insert(main_key(2), 0);
        assert_eq!(
            broken_map.move_node(1, free_slot, "test"),
            Err(CacheFault::new("test", MAP_SLOT_DISAGREES, Some(1)))
        );
    }

    /// Eviction takes the clean entries, and an entry made clean is evictable
    /// again in its new list position.
    #[test]
    fn dirty_entries_stay_off_the_eviction_list_until_clean() {
        let mut c = PageCache::with_capacity(3);
        for id in 1..=3_u8 {
            c.insert(main_key(u64::from(id)), page(id)).unwrap();
        }
        c.mark_dirty(main_key(1)).unwrap();
        c.mark_dirty(main_key(2)).unwrap();
        assert_list_matches_map(&c);

        // Page 3 is the only clean entry, so it leaves and the dirty ones stay.
        c.insert(main_key(4), page(4)).unwrap();
        assert!(!c.contains(main_key(3)));
        assert!(c.contains(main_key(1)) && c.contains(main_key(2)));

        // Cleaned, page 1 rejoins as the newest entry, so page 4 is older.
        c.clear_dirty(main_key(1)).unwrap();
        c.insert(main_key(5), page(5)).unwrap();
        assert!(!c.contains(main_key(4)));
        assert!(c.contains(main_key(1)));
        assert!(c.contains(main_key(2)), "the dirty page stays");
        assert_eq!(c.dirty_for_file(FileKey::Main), vec![2]);
        assert_list_matches_map(&c);
    }

    /// Dropping a file's entries takes the dirty, unlinked ones too. The list
    /// stays consistent, and another file's entry is evicted in its turn.
    #[test]
    fn clearing_a_file_drops_unlinked_dirty_entries() {
        let segment_key = (FileKey::Segment([7; 16]), 1);
        let mut c = PageCache::with_capacity(3);
        c.insert(main_key(1), page(1)).unwrap();
        c.insert(segment_key, page(2)).unwrap();
        c.insert(main_key(2), page(3)).unwrap();
        c.mark_dirty(main_key(1)).unwrap();

        c.clear_file(FileKey::Main).unwrap();

        assert_eq!(c.len(), 1);
        assert_eq!(c.dirty_len(), 0);
        assert_list_matches_map(&c);

        // The segment entry is the oldest on the list, then page 3, then page 4.
        c.insert(main_key(3), page(4)).unwrap();
        c.insert(main_key(4), page(5)).unwrap();
        c.insert(main_key(5), page(6)).unwrap();
        assert!(!c.contains(segment_key));
        c.insert(main_key(6), page(7)).unwrap();
        assert!(!c.contains(main_key(3)));
        assert!(c.contains(main_key(4)));
        assert_list_matches_map(&c);
    }

    #[test]
    fn the_hand_moves_off_an_entry_when_it_turns_dirty() {
        let mut c = PageCache::with_capacity(4);
        for id in 1..=4_u8 {
            c.insert(main_key(u64::from(id)), page(id)).unwrap();
        }
        // Evicting page 1 leaves the hand on page 2.
        c.insert(main_key(5), page(5)).unwrap();
        assert_eq!(c.hand, c.map.get(&main_key(2)).copied());

        c.mark_dirty(main_key(2)).unwrap();
        assert_eq!(c.hand, c.map.get(&main_key(3)).copied());
        assert_list_matches_map(&c);

        // The next eviction starts from the entry the hand moved to.
        c.insert(main_key(6), page(6)).unwrap();
        assert!(!c.contains(main_key(3)));
        assert!(c.contains(main_key(2)));
        assert_eq!(c.hand, c.map.get(&main_key(4)).copied());

        // Past the newest entry, the hand has nowhere left to rest.
        for id in 4..=6 {
            c.mark_dirty(main_key(id)).unwrap();
        }
        assert_eq!(c.hand, None);
        assert_eq!((c.head, c.tail), (None, None));
        assert_list_matches_map(&c);
    }

    #[test]
    fn a_cleaned_entry_rejoins_as_the_newest_entry() {
        let mut c = PageCache::with_capacity(3);
        for id in 1..=3_u8 {
            c.insert(main_key(u64::from(id)), page(id)).unwrap();
        }
        c.mark_dirty(main_key(1)).unwrap();

        c.clear_dirty(main_key(1)).unwrap();

        assert_eq!(c.head, c.map.get(&main_key(1)).copied());
        assert_eq!(c.tail, c.map.get(&main_key(2)).copied());
        assert_list_matches_map(&c);

        // Eviction order follows the list, with page 1 last.
        c.insert(main_key(4), page(4)).unwrap();
        assert!(!c.contains(main_key(2)));
        c.insert(main_key(5), page(5)).unwrap();
        assert!(!c.contains(main_key(3)));
        assert!(c.contains(main_key(1)));
        c.insert(main_key(6), page(6)).unwrap();
        assert!(!c.contains(main_key(1)));
    }

    #[test]
    fn a_dirty_entry_on_the_list_reports_list_membership_drift() {
        let mut c = PageCache::with_capacity(4);
        let key = (FileKey::Main, 1);
        c.insert(key, page(1)).unwrap();
        c.dirty.insert(key);

        let fault = c.check_list_membership("test").unwrap_err();
        assert_eq!(fault.detail, LIST_MEMBERSHIP_DRIFTED);
    }

    #[test]
    fn linking_a_linked_node_reports_a_fault() {
        let mut c = PageCache::with_capacity(4);
        let key = main_key(1);
        c.insert(key, page(1)).unwrap();
        let idx = c.map[&key];

        assert_eq!(
            c.link_as_head(idx, "test"),
            Err(CacheFault::new("test", NODE_ALREADY_LINKED, Some(idx)))
        );
        assert_list_matches_map(&c);

        // A dirty marker on a linked node reaches the same fault through a clear.
        // The fault latches, and the marker stays set for the flush check.
        c.dirty.insert(key);
        let fault = CacheFault::new("clear_dirty", NODE_ALREADY_LINKED, Some(idx));
        assert_eq!(c.clear_dirty(key), Err(fault));
        assert_eq!(c.check_usable(), Err(fault));
        assert!(c.dirty.contains(&key));
    }

    #[test]
    fn moved_unlinked_node_stays_off_the_list() {
        let mut c = PageCache::with_capacity(2);
        add_dirty(&mut c, 1..=8);
        let dirty_slot = c.map[&main_key(8)];
        let gathered = gather(&mut c, 1..=7);

        c.finish_flush(FileKey::Main, gathered).unwrap();

        // Compaction moves the dirty node down, and it stays unlinked.
        let moved_slot = c.map[&main_key(8)];
        assert_ne!(moved_slot, dirty_slot);
        let moved = PageCache::node(&c.slab, moved_slot, "test").unwrap();
        assert!(!moved.linked);
        let clean_slot = c.map[&main_key(7)];
        assert_eq!(c.head, Some(clean_slot));
        assert_eq!(c.tail, Some(clean_slot));
        assert_eq!(c.hand, Some(clean_slot));
        assert_list_matches_map(&c);

        // Cleaned, it joins from the new slot as the newest entry.
        c.clear_dirty(main_key(8)).unwrap();
        assert_eq!(c.head, Some(moved_slot));
        assert_eq!(c.tail, Some(clean_slot));
        assert_eq!(c.evictable, 2);
        assert_list_matches_map(&c);

        c.insert(main_key(9), page(9)).unwrap();
        assert!(!c.contains(main_key(7)));
        assert!(c.contains(main_key(8)));
        assert_list_matches_map(&c);
    }
}
