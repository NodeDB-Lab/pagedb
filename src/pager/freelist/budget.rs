//! Resident-cost budget for the write path's free-list scan.
//!
//! `begin_write` materialises a bounded **window** of the durable chain and the
//! commit that follows rewrites exactly that window, splicing the fresh pages
//! onto the untouched tail. Everything the write hot path holds in memory for
//! the free list is therefore capped at `WINDOW_PAGES × chain_capacity(page)`
//! entries — a constant — instead of growing with the number of free pages in
//! the store, which is what made the whole-chain load defeat the buffer-pool
//! budget it was supposed to live inside.
//!
//! ## Why the window is larger than the working set
//!
//! [`SCAN_PAGES`] is the *working* part of the window: enough recyclable page
//! ids to satisfy an ordinary commit's allocations without falling through to
//! bump growth. [`TAIL_COMPACT_PAGES`] is the *compaction* part: pages pulled
//! in beyond the working set purely so the rewrite's splice point moves
//! forward, past entries that would otherwise be stranded.
//!
//! Stranding is the failure this exists to prevent. New frees are prepended at
//! the head, so without a deliberate pull the splice point would sit at a fixed
//! depth forever and below-floor entries deeper than it would never be
//! revisited, never recycled, and never removed — bounded memory bought with an
//! unbounded disk leak.
//!
//! ## What the pull actually guarantees
//!
//! One commit rewrites the `WINDOW_PAGES` scanned pages into `J` fresh pages,
//! where `J` is what the surviving entries repack into. The splice point
//! therefore advances by `WINDOW_PAGES − J` pages of the old chain. It advances
//! whenever the window holds a drainable entry, a consumed entry, or a
//! partially-filled page — dense repacking alone reclaims the slack that a
//! previous rewrite's trailing page left. It stalls only while the window is
//! both dense and entirely at or above the reclamation floor, which is exactly
//! the state in which nothing in the window is reclaimable anyway. When the
//! floor advances the window drains, `J` collapses, and the splice point sweeps
//! into the tail up to `WINDOW_PAGES` pages per commit, so a chain of `L` pages
//! is fully revisited within `L / TAIL_COMPACT_PAGES` commits in the pessimal
//! case where only the compaction pull makes progress.

/// Chain pages whose entries feed the allocator on an ordinary commit.
pub const SCAN_PAGES: usize = 64;

/// Extra chain pages pulled into the rewrite per commit so the splice point
/// advances into the tail instead of parking at a fixed depth.
pub const TAIL_COMPACT_PAGES: usize = 4;

/// Total chain pages `begin_write` materialises and the commit rewrites.
pub const WINDOW_PAGES: usize = SCAN_PAGES + TAIL_COMPACT_PAGES;
