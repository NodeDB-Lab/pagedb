use std::sync::Arc;

use super::fault::{DIRTY_NOT_RESIDENT, DISCARD_DIRTY};
use super::page_cache::PageCache;
use super::{CacheFault, FileKey, Page};

impl PageCache {
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
    pub(super) fn clear_dirty(&mut self, key: (FileKey, u64)) -> Result<(), CacheFault> {
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
            .range((file, 0)..=(file, u64::MAX))
            .map(|(_, p)| *p)
            .collect()
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

    /// Discard every dirty page of `file` without flushing, then return the pool
    /// to its budget. A fault stops the loop and stays latched, so the pages
    /// still marked dirty never reach disk.
    ///
    /// An unpinned dirty entry leaves the cache, so the next read of its id
    /// fetches the durable bytes. A pinned one clears its marker and stays until
    /// released, because its guard resolves the entry by slot.
    pub fn discard_dirty(&mut self, file: FileKey) {
        for pid in self.dirty_for_file(file) {
            if self.discard_dirty_entry((file, pid)).is_err() {
                return;
            }
        }
        let _ = self.guarded(|cache| cache.settle_batch(DISCARD_DIRTY));
    }

    /// Discard one dirty entry. A failed call leaves the marker set, so the page
    /// stays visible to the flush check. A pinned entry rejoins the list as the
    /// newest, and its release makes it evictable.
    fn discard_dirty_entry(&mut self, key: (FileKey, u64)) -> Result<(), CacheFault> {
        self.guarded(|cache| {
            let Some(&idx) = cache.map.get(&key) else {
                return Err(CacheFault::new(DISCARD_DIRTY, DIRTY_NOT_RESIDENT, None));
            };
            if Self::keyed_node(&cache.slab, idx, key, DISCARD_DIRTY)?.pins > 0 {
                cache.link_as_head(idx, DISCARD_DIRTY)?;
            } else {
                cache.remove_unpinned_entry(key, idx, DISCARD_DIRTY)?;
            }
            cache.dirty.remove(&key);
            Ok(())
        })
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
    #[cfg(any(test, not(target_arch = "wasm32")))]
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
                cache.remove_unpinned_entry(key, idx, OPERATION)?;
                if !keep_dirty {
                    cache.dirty.remove(&key);
                }
            }
            Ok(())
        })
    }

    /// Remove the unpinned entry at `idx` from the map, the list, and the slab.
    /// The caller clears any dirty marker. A dirty node is off the list, so its
    /// unlink is a no-op and it never counted as evictable.
    fn remove_unpinned_entry(
        &mut self,
        key: (FileKey, u64),
        idx: usize,
        operation: &'static str,
    ) -> Result<(), CacheFault> {
        let node = Self::keyed_node(&self.slab, idx, key, operation)?;
        let was_evictable = Self::is_evictable(node, &self.dirty);
        self.map.remove(&key);
        self.unlink_from_list(idx, operation)?;
        self.free_node(idx, operation)?;
        if was_evictable {
            self.evictable = Self::one_less(self.evictable, operation)?;
        }
        Ok(())
    }
}
