//! `WriteTxn` and its supporting types: the exclusive write session, spill
//! scratch storage, durable monotonic counters, and the commit path.

mod commit;
mod counter;
mod spill;
mod txn;

pub use counter::CounterRef;
pub use spill::{ScratchOffset, SpillScope};
pub(crate) use txn::SegmentSideEffect;
pub use txn::WriteTxn;
