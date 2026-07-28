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

use io_uring::opcode;
use io_uring::types::Fd;

use crate::Result;
use crate::errors::PagedbError;
use crate::vfs::blocking::offload;
use crate::vfs::iouring::ring::{SharedRing, SubmitError};
use crate::vfs::traits::{
    VfsFile, checked_iouring_positioned_offset, checked_read_count, checked_signed_file_len,
    write_all_at,
};
use crate::vfs::types::{ReadReq, WriteReq};

/// Per-file handle backed by an `std::fs::File` fd and the shared `io_uring`.
///
/// `Send` and `Sync` are both derived, not asserted: `Arc<std::fs::File>` is
/// thread-safe, and `SharedRing` wraps the ring in a `Mutex`, so an `Arc` of
/// it is too. Nothing about this type needs a hand-written auto-trait impl,
/// and it must not grow one — a manual impl would silently keep holding once a
/// future field stopped qualifying.
pub struct IouringFile {
    /// Shared so a blocking-pool call can own a reference to the descriptor
    /// for its whole duration, independently of when this handle drops.
    file: Arc<std::fs::File>,
    writable: bool,
    ring: Arc<SharedRing>,
}

impl IouringFile {
    pub(crate) fn new(file: std::fs::File, writable: bool, ring: Arc<SharedRing>) -> Self {
        Self {
            file: Arc::new(file),
            writable,
            ring,
        }
    }

    /// The two owned handles a blocking-pool cycle needs. Both are `Arc`
    /// clones, and both keep their target alive for as long as the cycle runs.
    fn shared(&self) -> (Arc<std::fs::File>, Arc<SharedRing>) {
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

    /// Run one submit + drain cycle, translating the ring's memory-safety
    /// verdict into a plain error while leaking whatever the kernel may still
    /// own.
    ///
    /// `buffers` is every allocation the SQEs point at. On the abandoned path
    /// it is forgotten rather than dropped: entries are still outstanding, and
    /// the kernel writing into reclaimed memory is the one outcome that must
    /// not be possible. Leaking a bounded amount on a failing device is the
    /// cheap side of that trade.
    fn run_cycle<B>(
        ring: &SharedRing,
        entries: &[io_uring::squeue::Entry],
        buffers: B,
    ) -> Result<(Vec<i32>, B)> {
        // SAFETY: `buffers` owns every allocation the entries reference and is
        // moved into this function, so the buffers outlive the call; on the
        // `Abandoned` path it is leaked instead of dropped, which extends that
        // lifetime for the rest of the process as the contract requires.
        match unsafe { ring.submit_and_collect(entries) } {
            Ok(results) => Ok((results, buffers)),
            Err(SubmitError::Settled(error)) => Err(PagedbError::Io(error)),
            Err(abandoned @ SubmitError::Abandoned(_)) => {
                std::mem::forget(buffers);
                Err(PagedbError::Io(abandoned.into_io()))
            }
        }
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
            let (results, scratch) = IouringFile::run_cycle(&ring, &[entry], scratch)?;
            let n = single_result(&results)?;
            // `single_result` rejects a negative CQE, so this is non-negative.
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

            let (results, buffers) = IouringFile::run_cycle(&ring, &entries, buffers)?;
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
            let (results, data) = IouringFile::run_cycle(&ring, &[entry], data)?;
            let n = single_result(&results)?;
            drop(data);
            // `single_result` rejects a negative CQE, so this is non-negative.
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

            let (results, plan) = IouringFile::run_cycle(&ring, &entries, plan)?;
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
            // `Fsync` carries no buffer pointer, so there is nothing the
            // kernel could still be reading; the unit payload makes that
            // explicit rather than leaving an empty allocation to leak.
            let (results, ()) = IouringFile::run_cycle(&ring, &[entry], ())?;
            single_result(&results)?;
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

/// Unwrap a one-entry cycle's result, turning a negative CQE into its errno.
fn single_result(results: &[i32]) -> Result<i32> {
    let result = *results
        .first()
        .ok_or_else(|| PagedbError::Io(std::io::Error::other("io_uring: no CQE for entry")))?;
    if result < 0 {
        return Err(PagedbError::Io(std::io::Error::from_raw_os_error(-result)));
    }
    Ok(result)
}
