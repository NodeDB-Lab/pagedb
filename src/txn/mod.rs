//! Transaction layer: `ReadTxn` / `WriteTxn` / Db façade and group-commit
//! infrastructure.

pub mod db;
pub mod group_commit;
pub mod mode;
pub mod policy;
pub mod read;
pub mod write;

pub use db::Db;
pub use mode::DbMode;
pub use policy::ReaderStallPolicy;
pub use read::ReadTxn;
pub use write::{CounterRef, ScratchOffset, SpillScope, WriteTxn};
