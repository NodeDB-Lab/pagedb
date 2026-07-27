//! `IouringFile`: per-file I/O using `io_uring` for reads, writes and fsync,
//! plus `ftruncate` / `metadata` where the ring has no opcode.
//!
//! Nothing here runs on the async executor. `submit_and_wait` parks the caller
//! inside `io_uring_enter` until the requested completions land, and it does so
//! while holding the shared ring mutex — so every operation hands a
//! self-contained closure to the blocking pool instead. The closure owns
//! everything the kernel can reach for the duration: the descriptor through an
//! `Arc`, the transfer buffer, and the SQEs that point at it. A caller that
//! drops the future mid-flight therefore cannot free memory the kernel is still
//! writing into — the pool thread runs the submit + drain to completion and
//! releases the ring lock before it returns.
//!
//! That costs one buffer copy and one pool hop per operation, and the copy is
//! not negotiable: it is what makes the buffer outlive a cancelled future.
//! The alternative is not "the same behaviour, faster" — a backend that parks
//! the polling thread stalls every other task on a current-thread runtime, from
//! the group-commit batcher down to unrelated readers. That is a correctness
//! failure with a latency symptom, not a slow path, so it loses to the copy
//! every time.
#![allow(unsafe_code)]

use std::os::unix::io::AsRawFd;
use std::sync::Arc;

use io_uring::IoUring;
use io_uring::opcode;
use io_uring::types::Fd;
use parking_lot::Mutex;

use crate::Result;
use crate::errors::PagedbError;
use crate::vfs::blocking::offload;
use crate::vfs::traits::{
    VfsFile, checked_indexed_completion, checked_iouring_positioned_offset, checked_read_count,
    checked_signed_file_len, write_all_at,
};
use crate::vfs::types::{ReadReq, WriteReq};

/// Per-file handle backed by an `std::fs::File` fd and the shared `io_uring`.
///
/// `Send` and `Sync` are both derived, not asserted: `Arc<std::fs::File>` is
/// thread-safe, and `io_uring::IoUring` is `Send + Sync`, so `Arc<Mutex<_>>`
/// around it is too. Nothing about this type needs a hand-written auto-trait
/// impl, and it must not grow one — a manual impl would silently keep holding
/// once a future field stopped qualifying.
pub struct IouringFile {
    /// Shared so a blocking-pool call can own a reference to the descriptor
    /// for its whole duration, independently of when this handle drops.
    file: Arc<std::fs::File>,
    writable: bool,
    ring: Arc<Mutex<IoUring>>,
}

impl IouringFile {
    pub(crate) fn new(file: std::fs::File, writable: bool, ring: Arc<Mutex<IoUring>>) -> Self {
        Self {
            file: Arc::new(file),
            writable,
            ring,
        }
    }

    /// The two owned handles a blocking-pool cycle needs. Both are `Arc`
    /// clones, and both keep their target alive for as long as the cycle runs.
    fn shared(&self) -> (Arc<std::fs::File>, Arc<Mutex<IoUring>>) {
        (Arc::clone(&self.file), Arc::clone(&self.ring))
    }

    fn check_write_range(offset: u64, len: usize) -> Result<()> {
        let len = u64::try_from(len).map_err(|_| {
            PagedbError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "buffer length does not fit in u64",
            ))
        })?;
        offset.checked_add(len).ok_or_else(|| {
            PagedbError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "write offset overflow",
            ))
        })?;
        Ok(())
    }

    /// Validate a buffer length against the SQE length field. Called once on
    /// the executor so a deterministic input error is reported before any
    /// buffer is copied, and again on the pool where the SQE is actually built.
    fn entry_len(len: usize) -> Result<u32> {
        u32::try_from(len)
            .map_err(|_| PagedbError::Io(std::io::Error::other("buffer too large for u32")))
    }

    /// Submit a single SQE, wait for exactly one CQE with matching
    /// `user_data`, and return the CQE result.
    ///
    /// # Safety
    ///
    /// The caller must ensure that any buffers referenced by the SQE remain
    /// valid for the duration of this call (i.e. until `submit_and_wait`
    /// returns and the CQE is drained). Because the ring lock is held across
    /// the entire submit+drain sequence and we wait for the exact CQE before
    /// returning, this invariant is satisfied for any buffer whose lifetime
    /// outlasts this function.
    unsafe fn submit_one(
        ring: &mut IoUring,
        entry: &io_uring::squeue::Entry,
        user_data: u64,
    ) -> std::io::Result<i32> {
        // SAFETY: caller guarantees the buffers referenced by `entry` are live.
        unsafe {
            ring.submission()
                .push(entry)
                .map_err(|_| std::io::Error::other("submission queue full"))?;
        }
        ring.submit_and_wait(1)?;
        let mut result = None;
        {
            let mut cq = ring.completion();
            cq.sync();
            for cqe in cq.by_ref() {
                if cqe.user_data() == user_data {
                    result = Some(cqe.result());
                    break;
                }
                // Stale CQEs from prior submissions are discarded.
            }
        }
        let res =
            result.ok_or_else(|| std::io::Error::other("io_uring: expected CQE not found"))?;
        if res < 0 {
            Err(std::io::Error::from_raw_os_error(-res))
        } else {
            Ok(res)
        }
    }

    /// Submit a batch of SQEs and wait for all of them. Each SQE must carry
    /// its index (0..n) as `user_data`. Returns CQE results in submission order.
    ///
    /// # Safety
    ///
    /// All buffers referenced by every entry in `entries` must remain valid
    /// until this function returns (same contract as `submit_one`).
    unsafe fn submit_batch(
        ring: &mut IoUring,
        entries: &[io_uring::squeue::Entry],
    ) -> std::io::Result<Vec<i32>> {
        let total = entries.len();
        if total == 0 {
            return Ok(Vec::new());
        }
        // Cap each submission at the ring's SQ depth. Larger callers
        // (a full B+ tree flush) get chunked across multiple ring round-trips.
        // Each chunk re-tags `user_data` with the index within the chunk so
        // the CQE drain can match results into the global results vector.
        let chunk_size = crate::vfs::iouring::ring::RING_DEPTH as usize;
        let mut results = vec![0i32; total];
        let mut base = 0usize;
        while base < total {
            let end = (base + chunk_size).min(total);
            let chunk_len = end - base;
            {
                let mut sq = ring.submission();
                for (i, entry) in entries[base..end].iter().enumerate() {
                    // Re-tag with the in-chunk index. The caller-assigned
                    // `user_data` is overwritten because the outer `for cqe`
                    // loop needs a stable 0..chunk_len keyspace.
                    let tagged = entry.clone().user_data(i as u64);
                    // SAFETY: caller guarantees buffers are live for `entries`.
                    unsafe {
                        sq.push(&tagged)
                            .map_err(|_| std::io::Error::other("submission queue full"))?;
                    }
                }
            }
            ring.submit_and_wait(chunk_len)?;
            let mut chunk_results = vec![None; chunk_len];
            let mut found = 0usize;
            {
                let mut cq = ring.completion();
                cq.sync();
                for cqe in cq.by_ref() {
                    if checked_indexed_completion(&mut chunk_results, cqe.user_data(), cqe.result())
                        .map_err(|error| match error {
                            PagedbError::Io(io) => io,
                            other => std::io::Error::other(other.to_string()),
                        })?
                    {
                        found += 1;
                    }
                    if found == chunk_len {
                        break;
                    }
                }
            }
            if found < chunk_len {
                return Err(std::io::Error::other(
                    "io_uring: fewer CQEs returned than submitted",
                ));
            }
            for (index, result) in chunk_results.into_iter().enumerate() {
                results[base + index] = result
                    .ok_or_else(|| std::io::Error::other("io_uring: missing indexed CQE result"))?;
            }
            base = end;
        }
        Ok(results)
    }
}

impl VfsFile for IouringFile {
    async fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let len = buf.len();
        checked_iouring_positioned_offset(offset, len)?;
        // Reject an impossible length before allocating scratch for it.
        Self::entry_len(len)?;
        let (file, ring) = self.shared();
        let (scratch, read) = offload(move || {
            let fd = Fd(file.as_raw_fd());
            let entry_len = IouringFile::entry_len(len)?;
            let mut scratch = vec![0u8; len];
            let entry = opcode::Read::new(fd, scratch.as_mut_ptr(), entry_len)
                .offset(offset)
                .build()
                .user_data(0);
            let n = {
                let mut guard = ring.lock();
                // SAFETY: `scratch` is owned by this closure and outlives the
                // submit+drain below, and the ring lock is held across both, so
                // the kernel is finished with the buffer before this returns.
                unsafe { IouringFile::submit_one(&mut guard, &entry, 0) }
            }
            .map_err(PagedbError::Io)?;
            // n >= 0 guaranteed by submit_one (negative becomes Err).
            #[allow(clippy::cast_sign_loss)]
            let read = checked_read_count(n as usize, len)?;
            Ok((scratch, read))
        })
        .await?;
        buf[..read].copy_from_slice(&scratch[..read]);
        Ok(read)
    }

    async fn read_at_vectored(&self, reqs: &mut [ReadReq<'_>]) -> Result<()> {
        if reqs.is_empty() {
            return Ok(());
        }
        // Validate every request before any I/O runs, so a deterministic input
        // error cannot leave a prefix of the batch applied.
        let mut plan: Vec<(u64, usize)> = Vec::with_capacity(reqs.len());
        for req in reqs.iter() {
            checked_iouring_positioned_offset(req.offset, req.buf.len())?;
            Self::entry_len(req.buf.len())?;
            plan.push((req.offset, req.buf.len()));
        }
        let (file, ring) = self.shared();
        let completed = offload(move || {
            let fd = Fd(file.as_raw_fd());
            // Build one Read SQE per request; each gets its index as user_data.
            let mut buffers: Vec<Vec<u8>> = plan.iter().map(|&(_, len)| vec![0u8; len]).collect();
            let mut entries: Vec<io_uring::squeue::Entry> = Vec::with_capacity(plan.len());
            for (i, ((offset, len), scratch)) in plan.iter().zip(buffers.iter_mut()).enumerate() {
                let entry_len = IouringFile::entry_len(*len)?;
                entries.push(
                    opcode::Read::new(fd, scratch.as_mut_ptr(), entry_len)
                        .offset(*offset)
                        .build()
                        .user_data(i as u64),
                );
            }

            let results = {
                let mut guard = ring.lock();
                // SAFETY: every buffer referenced by `entries` lives in
                // `buffers`, owned by this closure, and the ring lock is held
                // across submit+drain so the kernel cannot touch them after
                // `submit_batch` returns.
                unsafe { IouringFile::submit_batch(&mut guard, &entries) }
            }
            .map_err(PagedbError::Io)?;
            drop(entries); // buf raw-ptrs no longer needed

            let mut out: Vec<(Vec<u8>, usize)> = Vec::with_capacity(plan.len());
            for ((_, len), (scratch, res)) in plan.iter().zip(buffers.into_iter().zip(results)) {
                if res < 0 {
                    return Err(PagedbError::Io(std::io::Error::from_raw_os_error(-res)));
                }
                // res >= 0 guaranteed above.
                #[allow(clippy::cast_sign_loss)]
                let nread = checked_read_count(res as usize, *len)?;
                out.push((scratch, nread));
            }
            Ok(out)
        })
        .await?;

        // Zero tail past EOF — mirrors TokioVfs / MemVfs contract.
        for (req, (scratch, nread)) in reqs.iter_mut().zip(completed) {
            req.buf[..nread].copy_from_slice(&scratch[..nread]);
            for b in &mut req.buf[nread..] {
                *b = 0;
            }
        }
        Ok(())
    }

    async fn write_at(&mut self, offset: u64, buf: &[u8]) -> Result<usize> {
        if !self.writable {
            return Err(PagedbError::ReadOnly);
        }
        if buf.is_empty() {
            return Ok(0);
        }
        Self::check_write_range(offset, buf.len())?;
        Self::entry_len(buf.len())?;
        let (file, ring) = self.shared();
        // The pool thread outlives this future, so it writes from its own copy
        // rather than from the caller's borrow.
        let data = buf.to_vec();
        offload(move || {
            let fd = Fd(file.as_raw_fd());
            let entry_len = IouringFile::entry_len(data.len())?;
            let entry = opcode::Write::new(fd, data.as_ptr(), entry_len)
                .offset(offset)
                .build()
                .user_data(0);
            let n = {
                let mut guard = ring.lock();
                // SAFETY: `data` is owned by this closure and outlives the
                // submit+drain below; the ring lock is held across both.
                unsafe { IouringFile::submit_one(&mut guard, &entry, 0) }
            }
            .map_err(PagedbError::Io)?;
            // n >= 0 guaranteed by submit_one.
            #[allow(clippy::cast_sign_loss)]
            let written = n as usize;
            Ok(written)
        })
        .await
    }

    async fn write_at_vectored(&mut self, reqs: &[WriteReq<'_>]) -> Result<()> {
        if !self.writable {
            return Err(PagedbError::ReadOnly);
        }
        if reqs.is_empty() {
            return Ok(());
        }
        for req in reqs {
            Self::check_write_range(req.offset, req.buf.len())?;
        }
        // Empty requests are already complete. Skipping them also ensures that
        // a zero-byte CQE always represents impossible progress on real data.
        // Each surviving entry carries the index of the request it came from so
        // a short write can be finished against the caller's own buffer.
        let mut plan: Vec<(usize, u64, Vec<u8>)> = Vec::with_capacity(reqs.len());
        for (i, req) in reqs.iter().enumerate() {
            if req.buf.is_empty() {
                continue;
            }
            Self::entry_len(req.buf.len())?;
            plan.push((i, req.offset, req.buf.to_vec()));
        }
        if plan.is_empty() {
            return Ok(());
        }
        let (file, ring) = self.shared();
        let short_writes = offload(move || {
            let fd = Fd(file.as_raw_fd());
            let mut entries: Vec<io_uring::squeue::Entry> = Vec::with_capacity(plan.len());
            for (slot, (_, offset, data)) in plan.iter().enumerate() {
                let entry_len = IouringFile::entry_len(data.len())?;
                let user_data = u64::try_from(slot).map_err(|_| {
                    PagedbError::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "too many vectored write requests",
                    ))
                })?;
                entries.push(
                    opcode::Write::new(fd, data.as_ptr(), entry_len)
                        .offset(*offset)
                        .build()
                        .user_data(user_data),
                );
            }

            let results = {
                let mut guard = ring.lock();
                // SAFETY: every buffer referenced by `entries` lives in `plan`,
                // owned by this closure, and the ring lock is held across
                // submit+drain.
                unsafe { IouringFile::submit_batch(&mut guard, &entries) }
            }
            .map_err(PagedbError::Io)?;
            drop(entries);

            let mut short_writes = Vec::new();
            for (slot, &res) in results.iter().enumerate() {
                if res < 0 {
                    return Err(PagedbError::Io(std::io::Error::from_raw_os_error(-res)));
                }
                let written = usize::try_from(res)
                    .map_err(|_| PagedbError::Io(std::io::Error::other("negative write result")))?;
                let (request_index, _, data) = &plan[slot];
                if written > data.len() {
                    return Err(PagedbError::Io(std::io::Error::other(
                        "io_uring write overreported bytes",
                    )));
                }
                if written == 0 {
                    return Err(PagedbError::Io(std::io::Error::from(
                        std::io::ErrorKind::WriteZero,
                    )));
                }
                if written < data.len() {
                    short_writes.push((*request_index, written));
                }
            }
            Ok(short_writes)
        })
        .await?;

        for (request_index, written) in short_writes {
            let request = &reqs[request_index];
            let written_u64 = u64::try_from(written).map_err(|_| {
                PagedbError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "write count does not fit in u64",
                ))
            })?;
            let offset = request.offset.checked_add(written_u64).ok_or_else(|| {
                PagedbError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "write offset overflow",
                ))
            })?;
            write_all_at(self, offset, &request.buf[written..]).await?;
        }
        Ok(())
    }

    async fn sync(&mut self) -> Result<()> {
        let (file, ring) = self.shared();
        offload(move || {
            let fd = Fd(file.as_raw_fd());
            let entry = opcode::Fsync::new(fd).build().user_data(0);
            let completed = {
                let mut guard = ring.lock();
                // SAFETY: `Fsync` carries no buffer pointer; there is nothing
                // to alias. The `Arc` keeps the fd open for the whole call.
                unsafe { IouringFile::submit_one(&mut guard, &entry, 0) }
            };
            completed.map_err(PagedbError::Io)?;
            Ok(())
        })
        .await
    }

    async fn truncate(&mut self, len: u64) -> Result<()> {
        if !self.writable {
            return Err(PagedbError::ReadOnly);
        }
        // `ftruncate` is not available as a first-class `io_uring` opcode in
        // v0.7, so it goes through libc — which means it parks the calling
        // thread (shrinking a file can free extents on a busy device) and
        // belongs on the blocking pool.
        let len = checked_signed_file_len(len, "ftruncate")?;
        let file = Arc::clone(&self.file);
        offload(move || {
            // SAFETY: the `Arc` keeps the fd valid for the whole call and
            // `len` was checked before entering the signed native syscall.
            let rc = unsafe { libc::ftruncate(file.as_raw_fd(), len) };
            if rc != 0 {
                return Err(PagedbError::Io(std::io::Error::last_os_error()));
            }
            Ok(())
        })
        .await
    }

    async fn len(&self) -> Result<u64> {
        let file = Arc::clone(&self.file);
        offload(move || Ok(file.metadata().map_err(PagedbError::Io)?.len())).await
    }

    async fn is_empty(&self) -> Result<bool> {
        Ok(self.len().await? == 0)
    }

    fn supports_direct_io(&self) -> bool {
        true
    }
}
