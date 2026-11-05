use crate::errors::PagedbError;

pub(super) const SLOT_EMPTY: &str = "slot holds no entry";
pub(super) const SLOT_HOLDS_OTHER_KEY: &str = "slot holds another key";
pub(super) const NO_VICTIM: &str = "evictable count is positive with no victim";
pub(super) const RELEASE_WITHOUT_PIN: &str = "release without a pin";
pub(super) const DIRTY_NOT_RESIDENT: &str = "dirty page not resident";
pub(super) const EVICTABLE_COUNT_DRIFTED: &str = "evictable count differs from the live entries";
pub(super) const OVER_BUDGET: &str = "entries exceed capacity while one is evictable";
pub(super) const LIST_LINK_BROKEN: &str = "list link disagrees with the slot it names";
pub(super) const MAP_SLOT_DISAGREES: &str = "map entry disagrees with the slot";
pub(super) const LIVE_SLOTS_DRIFTED: &str = "live slots differ from the map";
pub(super) const NODE_ALREADY_LINKED: &str = "node is already on the list";
pub(super) const LIST_MEMBERSHIP_DRIFTED: &str = "list membership disagrees with the dirty marker";
pub(super) const DISCARD_DIRTY: &str = "discard_dirty";

/// A broken cache invariant. `operation` names what was running, `detail` what
/// it found, and `slot` the slab slot when one is known.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CacheFault {
    pub(super) operation: &'static str,
    pub(super) detail: &'static str,
    pub(super) slot: Option<usize>,
}

impl CacheFault {
    #[cold]
    pub(super) const fn new(
        operation: &'static str,
        detail: &'static str,
        slot: Option<usize>,
    ) -> Self {
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
