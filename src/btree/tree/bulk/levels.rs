//! Bottom-up internal-node accumulators used while a dense tree is built.
//!
//! A level holds exactly one node under construction. Children arrive from the
//! level below as they are written and are packed into that node until the next
//! one no longer fits, at which point the node is emitted and its own
//! `(page_id, separator)` becomes a child of the level above. Resident cost is
//! therefore one partially-filled node per level — `O(height × page_size)` for
//! the whole build — rather than one entry per leaf.

use crate::Result;
use crate::btree::internal::{self, Internal, InternalEntry};
use crate::btree::node;
use crate::errors::PagedbError;

/// A child reference queued for the level above: the child's `page_id` and the
/// separator key that routes to it (the first key in its subtree).
pub(crate) type Child = (u64, Vec<u8>);

/// The node under construction at one internal level.
pub(crate) struct LevelAccum {
    children: Vec<Child>,
    /// Encoded body bytes the buffered children already consume.
    used: usize,
    /// Children ever accepted at this level, across every node it emitted.
    /// A level that only ever saw one child needs no node of its own: that
    /// child already is the top of the tree.
    total: u64,
}

impl LevelAccum {
    pub(crate) fn new() -> Self {
        Self {
            children: Vec::new(),
            used: node::HEADER_LEN,
            total: 0,
        }
    }

    /// The single child this level ever saw, if that is all it saw. Such a level
    /// is the root: wrapping one child in a node would add a level that routes
    /// nowhere.
    pub(crate) fn sole_child(&self) -> Option<u64> {
        if self.total == 1 {
            self.children.first().map(|(page_id, _)| *page_id)
        } else {
            None
        }
    }

    /// Offer `child` to the node under construction.
    ///
    /// `Ok(true)` means it was buffered. `Ok(false)` means the node is full: the
    /// caller must [`take_node`](Self::take_node) it, write it, and then
    /// [`restart`](Self::restart) this level with the same child.
    pub(crate) fn try_push(&mut self, child: &Child, body_cap: usize) -> Result<bool> {
        // The leftmost child is addressed by the node header, not by a separator
        // entry, so it always fits and costs nothing beyond the header.
        if self.children.is_empty() {
            self.children.push(child.clone());
            self.total += 1;
            return Ok(true);
        }
        let entry_size = internal::separator_entry_size(child.1.len())?;
        let needed = self
            .used
            .checked_add(entry_size)
            .ok_or(PagedbError::PayloadTooLarge)?;
        if needed > body_cap {
            // Closing a node that holds only its leftmost child makes no
            // progress: the level above would receive exactly as many children
            // as this one did and the build would never shrink. The one legal
            // single-child node is the final remainder, which `take_node`
            // emits without consulting this path.
            if self.children.len() == 1 {
                return Err(PagedbError::PayloadTooLarge);
            }
            return Ok(false);
        }
        self.used = needed;
        self.children.push(child.clone());
        self.total += 1;
        Ok(true)
    }

    /// Begin a fresh node with `child` as its leftmost child, after the previous
    /// one was taken.
    pub(crate) fn restart(&mut self, child: Child) {
        self.children.clear();
        self.children.push(child);
        self.used = node::HEADER_LEN;
        self.total += 1;
    }

    /// Take the node under construction together with its own separator — the
    /// first key of its leftmost child, which is the smallest key in its
    /// subtree. Leaves the level empty and ready to be restarted.
    pub(crate) fn take_node(&mut self) -> Option<(Internal, Vec<u8>)> {
        if self.children.is_empty() {
            return None;
        }
        let children = std::mem::take(&mut self.children);
        self.used = node::HEADER_LEN;
        let mut children = children.into_iter();
        let (leftmost_child, separator) = children.next()?;
        let entries = children
            .map(|(right_child, key)| InternalEntry { key, right_child })
            .collect();
        Some((
            Internal {
                leftmost_child,
                entries,
            },
            separator,
        ))
    }
}

impl Default for LevelAccum {
    fn default() -> Self {
        Self::new()
    }
}
