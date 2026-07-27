//! Transaction layer: `ReadTxn` / `WriteTxn` / Db façade and group-commit
//! infrastructure.

pub(crate) mod db;
pub(crate) mod group_commit;
pub(crate) mod mode;
pub(crate) mod policy;
pub(crate) mod read;
pub(crate) mod write;

pub use db::Db;
pub use mode::DbMode;
pub use policy::ReaderStallPolicy;
pub use read::ReadTxn;
pub use write::{CounterRef, ScratchOffset, SpillScope, WriteTxn};
