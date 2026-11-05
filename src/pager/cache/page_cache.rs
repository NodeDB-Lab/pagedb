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

use rustc_hash::FxHashMap;

use super::fault::{EVICTABLE_COUNT_DRIFTED, SLOT_EMPTY, SLOT_HOLDS_OTHER_KEY};
use super::{CacheFault, FileKey, Page};

/// Slab node, on the SIEVE FIFO unless dirty. `prev` points toward the tail
/// (older), `next` toward the head (newer). The hand walks tail→head via `next`.
pub(super) struct Node {
    pub(super) key: (FileKey, u64),
    pub(super) page: Arc<Page>,
    /// Outstanding `PageGuard`s over this entry. Lives on the node rather than
    /// in a side table so a lookup that already resolved the slab index does
    /// not pay a second hash to pin, nor a third to unpin on drop.
    pub(super) pins: u32,
    pub(super) visited: bool,
    /// Whether this node is on the list. A clean node is on it, and a dirty one
    /// is off it. An unlinked node has `prev` and `next` of `None`.
    pub(super) linked: bool,
    pub(super) prev: Option<usize>,
    pub(super) next: Option<usize>,
}

/// Bounded page cache with SIEVE eviction. The eviction hand skips pinned
/// entries. Dirty entries are off the list it walks.
///
/// A large write transaction leaves most of the cache dirty. Keeping dirty
/// entries off the list spares each clean-page eviction a walk past all of them.
pub struct PageCache {
    /// The entry budget. At every mutex release, `map.len() <= capacity` or
    /// `evictable == 0`. Transaction dirty pages and pinned pages exceed it.
    /// The pool returns to it once they are flushed or released.
    pub(super) capacity: usize,
    /// Keys are `(FileKey, u64)` page identities, never attacker-chosen in a
    /// way that could be ground into collisions, so the DoS-resistant `SipHash`
    /// default buys nothing here and costs a measurable slice of every warm
    /// page hit. `FxHashMap` is the same map with a cheap integer hash.
    pub(super) map: FxHashMap<(FileKey, u64), usize>,
    /// Slab of nodes. `None` slots are free and recorded in `free`.
    pub(super) slab: Vec<Option<Node>>,
    pub(super) free: Vec<usize>,
    pub(super) head: Option<usize>,
    pub(super) tail: Option<usize>,
    /// SIEVE hand. Walks tail→head via `next`. `None` means "start from tail
    /// on next eviction"; after wrapping past head it is reset to `None`.
    pub(super) hand: Option<usize>,
    pub(super) dirty: BTreeSet<(FileKey, u64)>,
    /// How many live entries are neither dirty nor pinned, i.e. how many the
    /// eviction hand could actually take.
    ///
    /// A large write transaction dirties every page it touches, and dirty pages
    /// are never evicted, so the cache legitimately grows past capacity with
    /// nothing evictable in it. At zero, a trim ends without walking the list.
    pub(super) evictable: usize,
    /// The first broken invariant. Once set, every fallible method returns it
    /// and changes nothing.
    pub(super) fault: Option<CacheFault>,
    /// Loop iterations of the eviction hand, so a test can bound a batch trim.
    #[cfg(test)]
    pub(super) walk_visits: usize,
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
    pub(super) fn guarded<T>(
        &mut self,
        body: impl FnOnce(&mut Self) -> Result<T, CacheFault>,
    ) -> Result<T, CacheFault> {
        self.check_usable()?;
        body(self).map_err(|fault| self.latch(fault))
    }

    /// Record the first fault and log it. [`guarded`](Self::guarded) stops every
    /// later operation, so this runs once per cache.
    #[cold]
    pub(super) fn latch(&mut self, fault: CacheFault) -> CacheFault {
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
    pub(super) fn node<'s>(
        slab: &'s [Option<Node>],
        idx: usize,
        operation: &'static str,
    ) -> Result<&'s Node, CacheFault> {
        slab.get(idx)
            .and_then(Option::as_ref)
            .ok_or_else(|| CacheFault::new(operation, SLOT_EMPTY, Some(idx)))
    }

    /// Mutable form of [`node`](Self::node).
    pub(super) fn node_mut<'s>(
        slab: &'s mut [Option<Node>],
        idx: usize,
        operation: &'static str,
    ) -> Result<&'s mut Node, CacheFault> {
        slab.get_mut(idx)
            .and_then(Option::as_mut)
            .ok_or_else(|| CacheFault::new(operation, SLOT_EMPTY, Some(idx)))
    }

    /// Resolve a slab slot that the caller expects to hold `key`.
    pub(super) fn keyed_node<'s>(
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
    pub(super) fn keyed_node_mut<'s>(
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
    pub(super) fn is_evictable(node: &Node, dirty: &BTreeSet<(FileKey, u64)>) -> bool {
        node.pins == 0 && !dirty.contains(&node.key)
    }

    /// `count` minus one. A count already at zero has drifted from the entries.
    pub(super) fn one_less(count: usize, operation: &'static str) -> Result<usize, CacheFault> {
        count
            .checked_sub(1)
            .ok_or_else(|| CacheFault::new(operation, EVICTABLE_COUNT_DRIFTED, None))
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Whether `key` is resident. Leaves the `visited` bit alone, so a test can
    /// observe an eviction without changing the next one.
    #[cfg(test)]
    pub(super) fn contains(&self, key: (FileKey, u64)) -> bool {
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
    pub(super) fn set_slot_key(&mut self, idx: usize, key: (FileKey, u64)) {
        self.slab[idx].as_mut().unwrap().key = key;
    }
}
