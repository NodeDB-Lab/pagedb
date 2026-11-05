use std::sync::Arc;

use super::fault::{DIRTY_NOT_RESIDENT, RELEASE_WITHOUT_PIN, SLOT_EMPTY, SLOT_HOLDS_OTHER_KEY};
use super::page_cache::{Node, PageCache};
use super::{CacheFault, FileKey, Page};

impl PageCache {
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

    /// Insert `(key, page)`, trimming the pool first if it is at capacity.
    ///
    /// A pool of only dirty and pinned pages cannot evict. A new clean entry
    /// then stays over budget. It stays until the caller marks it dirty under
    /// the same lock.
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

    /// Pin the entry for a page a cache miss fetched. Returns the page the entry
    /// holds and the slab index to release the pin with.
    ///
    /// A resident page always wins. The miss fetched its bytes without the cache
    /// lock, so a page resident now is at least as new. It can also be dirty. A
    /// present key therefore keeps its page and list position, and adds a pin.
    /// A new entry never counts as evictable.
    pub fn insert_and_pin(
        &mut self,
        key: (FileKey, u64),
        page: Arc<Page>,
    ) -> Result<(Arc<Page>, usize), CacheFault> {
        const OPERATION: &str = "insert_and_pin";
        self.guarded(|cache| {
            if let Some(&idx) = cache.map.get(&key) {
                let node = cache.pin_resident(idx, key, OPERATION)?;
                node.visited = true;
                return Ok((node.page.clone(), idx));
            }
            let idx = cache.insert_new(key, page.clone(), 1, OPERATION)?;
            Ok((page, idx))
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

    pub(super) fn free_node(
        &mut self,
        idx: usize,
        operation: &'static str,
    ) -> Result<(), CacheFault> {
        self.slab
            .get_mut(idx)
            .and_then(Option::take)
            .ok_or_else(|| CacheFault::new(operation, SLOT_EMPTY, Some(idx)))?;
        self.free.push(idx);
        Ok(())
    }
}
