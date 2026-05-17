//! Concrete `MmapView` implementation for native targets.
//!
//! Decrypted segment data is written into an anonymous temporary file (unlinked
//! from the filesystem immediately after creation) and then memory-mapped
//! read-only. Encrypted bytes are never mmap'd — only the plaintext scratch.
//!
//! Allocation is tracked against `OpenOptions::mmap_view_scratch_bytes` via a
//! shared `AtomicU64`. The counter is decremented when the view drops.

#![allow(unsafe_code)]

use std::io::Write;
use std::ops::Deref;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use memmap2::Mmap;
use tempfile::tempfile;

use crate::Result;
use crate::errors::PagedbError;

/// A read-only zero-copy view over already-decrypted segment data.
///
/// The underlying memory is backed by an anonymous temporary file that is
/// unlinked from the filesystem immediately after creation. The mapping is
/// read-only; the decrypted plaintext lives in OS page cache backed by swap
/// (or a tmpfs-style file), never touching the encrypted segment file.
pub struct MmapView {
    /// The actual memory-mapped region.
    _map: Mmap,
    /// Slice pointing into `_map` for the valid data range.
    data: *const u8,
    len: usize,
    /// Shared budget counter; decremented on drop.
    budget_used: Arc<AtomicU64>,
    /// How many bytes this view charged to the budget.
    charged: u64,
}

// SAFETY: `Mmap` is `Send` on all native targets (the OS mapping is
// process-global and the pointer is valid for the mapping's lifetime).
unsafe impl Send for MmapView {}
// SAFETY: We only hand out `&[u8]` (shared, read-only), so `Sync` is safe.
unsafe impl Sync for MmapView {}

impl MmapView {
    /// Construct from a sequence of plaintext page buffers, checking and
    /// charging the supplied budget counter.
    pub(crate) fn from_pages(
        pages: &[&[u8]],
        budget_used: Arc<AtomicU64>,
        budget_limit: u64,
    ) -> Result<Self> {
        let total: usize = pages.iter().map(|p| p.len()).sum();
        let total_u64 = u64::try_from(total)
            .map_err(|_| PagedbError::Io(std::io::Error::other("extent too large")))?;

        // Atomic compare-and-try-charge loop.
        loop {
            let current = budget_used.load(Ordering::Acquire);
            let new_total = current.saturating_add(total_u64);
            if new_total > budget_limit {
                return Err(PagedbError::MmapViewQuotaExceeded {
                    segment_bytes: total_u64,
                    available_bytes: budget_limit.saturating_sub(current),
                });
            }
            if budget_used
                .compare_exchange(current, new_total, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                break;
            }
        }

        // Write plaintext into an anonymous temp file, then mmap it.
        let map = (|| -> std::io::Result<Mmap> {
            let mut f = tempfile()?;
            for page in pages {
                f.write_all(page)?;
            }
            f.flush()?;
            // SAFETY: The file contains exactly `total` bytes of plaintext we
            // just wrote. No other writer has a handle to this file (tempfile()
            // returns a unique fd). The Mmap is read-only and we keep `_map`
            // alive for the lifetime of the view.
            let map = unsafe { Mmap::map(&f)? };
            Ok(map)
        })()
        .map_err(|e| {
            // Roll back charge on failure.
            budget_used.fetch_sub(total_u64, Ordering::AcqRel);
            PagedbError::Io(e)
        })?;

        let data = map.as_ptr();
        let len = map.len();

        Ok(Self {
            _map: map,
            data,
            len,
            budget_used,
            charged: total_u64,
        })
    }

    /// Returns the decrypted data as a byte slice.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: `data` points into `_map` which is alive for `'self`.
        // The mapping is read-only and covers exactly `len` bytes.
        unsafe { std::slice::from_raw_parts(self.data, self.len) }
    }
}

impl Deref for MmapView {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl Drop for MmapView {
    fn drop(&mut self) {
        self.budget_used.fetch_sub(self.charged, Ordering::AcqRel);
    }
}

impl std::fmt::Debug for MmapView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MmapView")
            .field("len", &self.len)
            .field("charged_bytes", &self.charged)
            .finish_non_exhaustive()
    }
}
