use super::CacheFault;
use super::fault::{
    LIST_LINK_BROKEN, LIVE_SLOTS_DRIFTED, MAP_SLOT_DISAGREES, SLOT_EMPTY, SLOT_HOLDS_OTHER_KEY,
};
use super::page_cache::PageCache;

impl PageCache {
    /// The single trim that ends a batch, plus its index memory reclaim.
    pub(super) fn settle_batch(&mut self, operation: &'static str) -> Result<(), CacheFault> {
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
    pub(super) fn move_node(
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
}
