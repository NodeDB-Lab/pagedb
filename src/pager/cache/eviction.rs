use super::CacheFault;
use super::fault::{
    EVICTABLE_COUNT_DRIFTED, LIST_MEMBERSHIP_DRIFTED, NO_VICTIM, NODE_ALREADY_LINKED, OVER_BUDGET,
};
use super::page_cache::PageCache;

impl PageCache {
    /// Evict entries until at most `target` remain or none is evictable. This is
    /// the only caller of [`evict_one`](Self::evict_one).
    ///
    /// Each eviction resumes from the hand. A batch therefore walks at most two
    /// passes over the list plus its evictions.
    pub(super) fn trim_to(&mut self, target: usize) -> Result<(), CacheFault> {
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
    pub(super) fn check_within_budget(&self, operation: &'static str) -> Result<(), CacheFault> {
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
    pub(super) fn check_evictable_count(&self, operation: &'static str) -> Result<(), CacheFault> {
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
    pub(super) fn check_list_membership(&self, operation: &'static str) -> Result<(), CacheFault> {
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

    /// Splice the unlinked node at `idx` in as the newest entry. A node already
    /// on the list reports a fault and changes nothing.
    pub(super) fn link_as_head(
        &mut self,
        idx: usize,
        operation: &'static str,
    ) -> Result<(), CacheFault> {
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
    pub(super) fn unlink_from_list(
        &mut self,
        idx: usize,
        operation: &'static str,
    ) -> Result<(), CacheFault> {
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
}
