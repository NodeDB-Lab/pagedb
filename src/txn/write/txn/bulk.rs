//! Bounded-batch transaction bulk loading.

use bytes::Bytes;

use crate::Result;
use crate::errors::PagedbError;
use crate::vfs::Vfs;

use super::WriteTxn;

const BULK_LOAD_BATCH_MAX_RECORDS: usize = 8_192;
const BULK_LOAD_BATCH_MAX_BYTES: usize = 32 * 1024 * 1024;

impl<V: Vfs + Clone> WriteTxn<'_, V> {
    /// Build an empty data tree bottom-up from a sorted, unique record stream.
    /// The consumed transaction aborts on any source or loader error.
    pub async fn bulk_load_sorted_unique<I>(mut self, records: I) -> Result<Self>
    where
        I: IntoIterator<Item = Result<(Vec<u8>, Bytes)>>,
    {
        {
            let mut loader = self.btree.bulk_loader()?;
            let mut batch = Vec::with_capacity(BULK_LOAD_BATCH_MAX_RECORDS);
            let mut batch_bytes = 0usize;
            for record in records {
                let (key, value) = record?;
                let record_bytes = key
                    .len()
                    .checked_add(value.len())
                    .ok_or(PagedbError::PayloadTooLarge)?;
                let exceeds_bytes = batch_bytes
                    .checked_add(record_bytes)
                    .is_none_or(|total| total > BULK_LOAD_BATCH_MAX_BYTES);
                if !batch.is_empty()
                    && (batch.len() == BULK_LOAD_BATCH_MAX_RECORDS || exceeds_bytes)
                {
                    let pending = std::mem::replace(
                        &mut batch,
                        Vec::with_capacity(BULK_LOAD_BATCH_MAX_RECORDS),
                    );
                    loader.push_batch(pending).await?;
                    batch_bytes = 0;
                }
                batch_bytes = batch_bytes
                    .checked_add(record_bytes)
                    .ok_or(PagedbError::PayloadTooLarge)?;
                batch.push((key, value));
            }
            if !batch.is_empty() {
                loader.push_batch(batch).await?;
            }
            loader.finish().await?;
        }
        Ok(self)
    }
}
