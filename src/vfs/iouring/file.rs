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
use crate::vfs::traits::VfsFile;
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
            let mut found = 0usize;
            {
                let mut cq = ring.completion();
                cq.sync();
                for cqe in cq.by_ref() {
                    let ud = cqe.user_data();
                    if ud < chunk_len as u64 {
                        #[allow(clippy::cast_possible_truncation)]
                        let idx = base + ud as usize;
                        results[idx] = cqe.result();
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
        Ok(n as usize)
    }

    async fn read_at_vectored(&self, reqs: &mut [ReadReq<'_>]) -> Result<()> {
        if reqs.is_empty() {
            return Ok(());
        }
        let fd = Fd(self.file.as_raw_fd());
        // Build one Read SQE per request; each gets its index as user_data.
        let mut entries: Vec<io_uring::squeue::Entry> = Vec::with_capacity(reqs.len());
        for (i, req) in reqs.iter_mut().enumerate() {
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
            let nread = res as usize;
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
        let fd = Fd(self.file.as_raw_fd());
        // Build one Write SQE per request; each gets its index as user_data.
        let mut entries: Vec<io_uring::squeue::Entry> = Vec::with_capacity(reqs.len());
        for (i, req) in reqs.iter().enumerate() {
            let len = u32::try_from(req.buf.len())
                .map_err(|_| PagedbError::Io(std::io::Error::other("buffer too large for u32")))?;
            entries.push(
                opcode::Write::new(fd, req.buf.as_ptr(), len)
                    .offset(req.offset)
                    .build()
                    .user_data(i as u64),
            );
        }

        let mut ring = self.ring.lock();
        // SAFETY: `req.buf` slices are tied to the `reqs` argument's `'_`
        // lifetime. The ring lock is held across submit+drain.
        let results =
            unsafe { Self::submit_batch(&mut ring, &entries) }.map_err(PagedbError::Io)?;

        for &res in &results {
            if res < 0 {
                return Err(PagedbError::Io(std::io::Error::from_raw_os_error(-res)));
            }
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
        // SAFETY: `self.file.as_raw_fd()` is a valid open fd for the lifetime
        // of this method call (`self` keeps `file` alive). `len` fits in
        // `libc::off_t` (i64) on any 64-bit Linux target; on 32-bit targets
        // `off_t` is 32-bit but `_FILE_OFFSET_BITS=64` is standard, so the
        // cast is safe in practice. We allow the truncation lint here because
        // we are on Linux where `off_t` is always i64 in practice.
        #[allow(clippy::cast_possible_wrap)]
        let rc = unsafe { libc::ftruncate(self.file.as_raw_fd(), len as libc::off_t) };
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
