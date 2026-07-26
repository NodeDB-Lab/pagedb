//! `IouringFile`: per-file I/O using `io_uring` for reads, writes, fsync, and
//! ftruncate. Each async op acquires the shared ring mutex, pushes SQE(s),
//! calls `submit_and_wait(N)`, drains matching CQEs, then releases the lock.
//! No background poller thread, no `spawn_blocking`.
#![allow(unsafe_code)]

use std::os::unix::io::AsRawFd;
use std::sync::Arc;

use io_uring::IoUring;
use io_uring::opcode;
use io_uring::types::Fd;
use parking_lot::Mutex;

use crate::Result;
use crate::errors::PagedbError;
use crate::vfs::traits::{
    VfsFile, checked_indexed_completion, checked_iouring_positioned_offset, checked_read_count,
    checked_signed_file_len, write_all_at,
};
use crate::vfs::types::{ReadReq, WriteReq};

/// Per-file handle backed by an `std::fs::File` fd and the shared `io_uring`.
pub struct IouringFile {
    file: std::fs::File,
    writable: bool,
    ring: Arc<Mutex<IoUring>>,
}

impl IouringFile {
    pub(crate) fn new(file: std::fs::File, writable: bool, ring: Arc<Mutex<IoUring>>) -> Self {
        Self {
            file,
            writable,
            ring,
        }
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

// SAFETY: `IouringFile` contains a `std::fs::File` (which is `Send`) and an
// `Arc<Mutex<IoUring>>`. `IoUring` itself is not `Send`; however we only
// access it while holding the `parking_lot::Mutex` lock. The trait contract
// (`&self`/`&mut self`) means at most one async I/O method executes at a
// time per file handle, so the ring is never accessed from multiple threads
// simultaneously.
unsafe impl Send for IouringFile {}

impl VfsFile for IouringFile {
    async fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        checked_iouring_positioned_offset(offset, buf.len())?;
        let fd = Fd(self.file.as_raw_fd());
        let len = u32::try_from(buf.len())
            .map_err(|_| PagedbError::Io(std::io::Error::other("buffer too large for u32")))?;
        // SAFETY: `buf` is a mutable slice alive for this async fn frame;
        // the ring lock is held across submit+drain so the kernel cannot
        // touch the buffer after we return.
        let entry = opcode::Read::new(fd, buf.as_mut_ptr(), len)
            .offset(offset)
            .build()
            .user_data(0);
        let mut ring = self.ring.lock();
        let n = unsafe { Self::submit_one(&mut ring, &entry, 0) }.map_err(PagedbError::Io)?;
        // n >= 0 guaranteed by submit_one (negative becomes Err).
        #[allow(clippy::cast_sign_loss)]
        checked_read_count(n as usize, buf.len())
    }

    async fn read_at_vectored(&self, reqs: &mut [ReadReq<'_>]) -> Result<()> {
        if reqs.is_empty() {
            return Ok(());
        }
        let fd = Fd(self.file.as_raw_fd());
        // Build one Read SQE per request; each gets its index as user_data.
        let mut entries: Vec<io_uring::squeue::Entry> = Vec::with_capacity(reqs.len());
        for (i, req) in reqs.iter_mut().enumerate() {
            checked_iouring_positioned_offset(req.offset, req.buf.len())?;
            let len = u32::try_from(req.buf.len())
                .map_err(|_| PagedbError::Io(std::io::Error::other("buffer too large for u32")))?;
            entries.push(
                opcode::Read::new(fd, req.buf.as_mut_ptr(), len)
                    .offset(req.offset)
                    .build()
                    .user_data(i as u64),
            );
        }

        let mut ring = self.ring.lock();
        // SAFETY: `req.buf` slices are tied to the `reqs` argument's `'_`
        // lifetime. The ring lock is held across submit+drain so the kernel
        // cannot access those buffers after `submit_batch` returns.
        let results =
            unsafe { Self::submit_batch(&mut ring, &entries) }.map_err(PagedbError::Io)?;
        drop(entries); // buf raw-ptrs no longer needed; drop before touching reqs

        // Zero tail past EOF — mirrors TokioVfs / MemVfs contract.
        for (req, &res) in reqs.iter_mut().zip(results.iter()) {
            if res < 0 {
                return Err(PagedbError::Io(std::io::Error::from_raw_os_error(-res)));
            }
            // res >= 0 guaranteed above.
            #[allow(clippy::cast_sign_loss)]
            let nread = checked_read_count(res as usize, req.buf.len())?;
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
        let fd = Fd(self.file.as_raw_fd());
        let len = u32::try_from(buf.len())
            .map_err(|_| PagedbError::Io(std::io::Error::other("buffer too large for u32")))?;
        // SAFETY: `buf` is an immutable slice alive for this async fn frame;
        // the ring lock is held across submit+drain.
        let entry = opcode::Write::new(fd, buf.as_ptr(), len)
            .offset(offset)
            .build()
            .user_data(0);
        let mut ring = self.ring.lock();
        let n = unsafe { Self::submit_one(&mut ring, &entry, 0) }.map_err(PagedbError::Io)?;
        // n >= 0 guaranteed by submit_one.
        #[allow(clippy::cast_sign_loss)]
        Ok(n as usize)
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
        let fd = Fd(self.file.as_raw_fd());
        // Empty requests are already complete. Skipping them also ensures that
        // a zero-byte CQE always represents impossible progress on real data.
        let mut entries: Vec<io_uring::squeue::Entry> = Vec::with_capacity(reqs.len());
        let mut entry_to_request = Vec::with_capacity(reqs.len());
        for (i, req) in reqs.iter().enumerate() {
            if req.buf.is_empty() {
                continue;
            }
            let len = u32::try_from(req.buf.len())
                .map_err(|_| PagedbError::Io(std::io::Error::other("buffer too large for u32")))?;
            let user_data = u64::try_from(entry_to_request.len()).map_err(|_| {
                PagedbError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "too many vectored write requests",
                ))
            })?;
            entries.push(
                opcode::Write::new(fd, req.buf.as_ptr(), len)
                    .offset(req.offset)
                    .build()
                    .user_data(user_data),
            );
            entry_to_request.push(i);
        }
        if entries.is_empty() {
            return Ok(());
        }

        let results = {
            let mut ring = self.ring.lock();
            // SAFETY: `req.buf` slices are tied to the `reqs` argument's `'_`
            // lifetime. The ring lock is held across submit+drain.
            unsafe { Self::submit_batch(&mut ring, &entries) }.map_err(PagedbError::Io)?
        };
        drop(entries);

        let mut short_writes = Vec::new();
        for (entry_index, &res) in results.iter().enumerate() {
            if res < 0 {
                return Err(PagedbError::Io(std::io::Error::from_raw_os_error(-res)));
            }
            let written = usize::try_from(res)
                .map_err(|_| PagedbError::Io(std::io::Error::other("negative write result")))?;
            let request_index = entry_to_request[entry_index];
            let request = &reqs[request_index];
            if written > request.buf.len() {
                return Err(PagedbError::Io(std::io::Error::other(
                    "io_uring write overreported bytes",
                )));
            }
            if written == 0 {
                return Err(PagedbError::Io(std::io::Error::from(
                    std::io::ErrorKind::WriteZero,
                )));
            }
            if written < request.buf.len() {
                short_writes.push((request_index, written));
            }
        }

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
        let fd = Fd(self.file.as_raw_fd());
        let entry = opcode::Fsync::new(fd).build().user_data(0);
        let mut ring = self.ring.lock();
        // SAFETY: `Fsync` carries no buffer pointer; there is nothing to alias.
        unsafe { Self::submit_one(&mut ring, &entry, 0) }.map_err(PagedbError::Io)?;
        Ok(())
    }

    async fn truncate(&mut self, len: u64) -> Result<()> {
        if !self.writable {
            return Err(PagedbError::ReadOnly);
        }
        // `ftruncate` is not available as a first-class `io_uring` opcode in
        // v0.7. Use the syscall directly via libc; for regular files this is
        // synchronous and does not trigger disk I/O in the common path.
        //
        let len = checked_signed_file_len(len, "ftruncate")?;
        // SAFETY: `self.file.as_raw_fd()` is valid for this method call and
        // `len` was checked before entering the signed native syscall.
        let rc = unsafe { libc::ftruncate(self.file.as_raw_fd(), len) };
        if rc != 0 {
            return Err(PagedbError::Io(std::io::Error::last_os_error()));
        }
        Ok(())
    }

    async fn len(&self) -> Result<u64> {
        let meta = self.file.metadata().map_err(PagedbError::Io)?;
        Ok(meta.len())
    }

    async fn is_empty(&self) -> Result<bool> {
        Ok(self.len().await? == 0)
    }

    fn supports_direct_io(&self) -> bool {
        true
    }
}
