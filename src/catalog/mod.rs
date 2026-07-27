//! Reserved B+ tree table for segment metadata and per-realm quotas. Rows
//! are partitioned by a leading row-kind byte: 0x00 = quota row, 0x01 =
//! segment row.

pub(crate) mod codec;
#[cfg(test)]
mod tests;
