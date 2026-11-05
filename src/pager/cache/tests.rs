use std::sync::Arc;

use super::fault::{
    DIRTY_NOT_RESIDENT, EVICTABLE_COUNT_DRIFTED, LIST_LINK_BROKEN, LIST_MEMBERSHIP_DRIFTED,
    MAP_SLOT_DISAGREES, NO_VICTIM, NODE_ALREADY_LINKED, RELEASE_WITHOUT_PIN, SLOT_EMPTY,
    SLOT_HOLDS_OTHER_KEY,
};
use super::{CacheFault, FileKey, Page, PageCache};
use crate::errors::PagedbError;

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
    let (_, idx) = c.insert_and_pin(key, page(1)).unwrap();
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
    let (_, idx) = c.insert_and_pin(key, page(1)).unwrap();
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
    let (_, idx) = c.insert_and_pin(old_key, page(1)).unwrap();
    c.unpin_at(idx, old_key);
    c.insert((FileKey::Main, 2), page(2)).unwrap();
    assert!(!c.contains(old_key));

    // The slot now belongs to page 2. Pin it, then replay the stale
    // release for page 1 against the same index.
    let new_key = (FileKey::Main, 2);
    let (_, new_idx) = c.insert_and_pin(new_key, page(2)).unwrap();
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
    let (_, idx) = c.insert_and_pin(key, page(1)).unwrap();
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
    let (_, pinned_slot) = c.insert_and_pin(healthy, page(2)).unwrap();
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
    assert_eq!(
        c.insert_and_pin(absent, page(3)).map(|(_, slot)| slot),
        Err(first)
    );
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
fn insert_and_pin_on_a_present_key_keeps_the_resident_page_and_adds_a_pin() {
    let mut c = PageCache::with_capacity(4);
    let key = (FileKey::Main, 1);
    c.insert(key, page(1)).unwrap();
    assert_eq!(c.evictable, 1);

    let (kept, idx) = c.insert_and_pin(key, page(2)).unwrap();
    assert_eq!(kept.bytes[0], 1, "the caller receives the resident page");
    assert_eq!(c.evictable, 0, "the pin removes the candidate");
    assert_eq!(c.len(), 1);

    let (kept, again) = c.insert_and_pin(key, page(3)).unwrap();
    assert_eq!(kept.bytes[0], 1);
    assert_eq!(again, idx);
    assert_eq!(c.evictable, 0, "a second pin changes no count");
    assert_eq!(c.get(key).unwrap().unwrap().bytes[0], 1);

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
fn dirty_for_file_returns_only_that_files_pages_in_order() {
    let mut c = PageCache::with_capacity(16);
    let seg = FileKey::ApplyJournal([7; 16]);
    let journal = FileKey::ApplyJournal([9; 16]);
    for key in [
        (seg, 9),
        (FileKey::Main, 30),
        (seg, u64::MAX),
        (journal, 4),
        (FileKey::Main, 10),
        (seg, 0),
        (seg, 3),
    ] {
        c.insert(key, page(0)).unwrap();
        c.mark_dirty(key).unwrap();
    }
    assert_eq!(c.dirty_for_file(seg), vec![0, 3, 9, u64::MAX]);
    assert_eq!(c.dirty_for_file(FileKey::Main), vec![10, 30]);
    assert_eq!(c.dirty_for_file(journal), vec![4]);
    assert_eq!(
        c.dirty_for_file(FileKey::ApplyJournal([8; 16])),
        Vec::<u64>::new()
    );
}

#[test]
fn file_classes_dont_collide() {
    let mut c = PageCache::with_capacity(4);
    c.insert((FileKey::Main, 1), page(1)).unwrap();
    c.insert((FileKey::ApplyJournal([0; 16]), 1), page(2))
        .unwrap();
    assert!(c.get((FileKey::Main, 1)).unwrap().is_some());
    assert!(
        c.get((FileKey::ApplyJournal([0; 16]), 1))
            .unwrap()
            .is_some()
    );
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
    let other_file = (FileKey::ApplyJournal([1; 16]), 1);
    add_dirty(&mut c, 1..=10);
    c.insert(other_file, page(1)).unwrap();
    c.mark_dirty(other_file).unwrap();

    c.discard_dirty(FileKey::Main);

    assert_eq!(c.dirty_for_file(FileKey::Main), Vec::<u64>::new());
    assert_eq!(c.dirty_len(), 1, "another file keeps its dirty page");
    assert!(c.contains(other_file));
    assert_eq!(c.len(), 1, "only the other file's dirty page stays");
    c.check_usable().unwrap();
}

#[test]
fn discard_removes_unpinned_dirty_entries_and_keeps_pinned_ones() {
    let mut c = PageCache::with_capacity(8);
    c.insert(main_key(1), page(1)).unwrap();
    add_dirty(&mut c, 2..=4);
    let (_, pinned_slot) = c.get_and_pin(main_key(3)).unwrap().unwrap();

    c.discard_dirty(FileKey::Main);

    c.check_usable().unwrap();
    assert_eq!(c.dirty_for_file(FileKey::Main), Vec::<u64>::new());
    assert!(c.contains(main_key(1)), "a clean entry stays");
    assert!(c.contains(main_key(3)), "a pinned entry stays");
    assert_eq!(c.len(), 2);
    assert_eq!(c.evictable, 1, "the pinned entry is not yet evictable");
    assert_list_matches_map(&c);
    assert!(
        c.get(main_key(2)).unwrap().is_none(),
        "a discarded id misses, so the next read fetches durable bytes"
    );
    assert!(c.get(main_key(4)).unwrap().is_none());

    c.unpin_at(pinned_slot, main_key(3));

    c.check_usable().unwrap();
    assert_eq!(c.evictable, 2, "the release makes the entry evictable");
    assert_list_matches_map(&c);
}

#[test]
fn last_unpin_over_capacity_evicts_one_entry() {
    let mut c = PageCache::with_capacity(2);
    let mut slots = Vec::new();
    for id in 1u8..=4 {
        let key = main_key(u64::from(id));
        slots.push((c.insert_and_pin(key, page(id)).unwrap().1, key));
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
    let (_, slot) = c.insert_and_pin(pinned, page(1)).unwrap();
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
    let segment_key = (FileKey::ApplyJournal([7; 16]), 1);
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
