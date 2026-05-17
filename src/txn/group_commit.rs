//! Group commit coordination. H ships serial commits — each `commit()`
//! produces its own root and header fsync. Future letters will coalesce
//! concurrent `commit()` futures into a single fsync. The public contract
//! (distinct `CommitId`s may map to one durable root within a batch) is
//! preserved trivially with batch size 1.
