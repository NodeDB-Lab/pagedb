//! The staged `main.db` image an incremental apply builds, and the rename that
//! makes it live.
//!
//! An apply installs pages by absolute id, and copy-on-write means the producer
//! routinely recycles ids the follower's base state still occupies. Writing
//! those pages into the live `main.db` would destroy base state while the only
//! durable header still points at it, so nothing is written there at all: the
//! base image is copied to a scratch file, the delta and the follower's
//! relocated metadata are written into the scratch, the target header is
//! written into the scratch's inactive slot, and the scratch is then renamed
//! over `main.db`.
//!
//! **The rename is the single commit point.** Every failure or crash before it
//! leaves `main.db` byte-for-byte as it was, so the follower reopens at the base
//! commit; after it, the follower reopens at the target. There is no ordering in
//! between that can produce a mix, because no byte of the target ever lands in
//! the live file until the whole target is in the scratch.

use crate::Result;
use crate::errors::PagedbError;
use crate::vfs::types::OpenMode;
use crate::vfs::{Vfs, VfsFile, read_exact_at, write_all_at};

/// Bytes copied per read/write round trip while cloning the base image. A fixed
/// window keeps the copy's residency independent of how large `main.db` is.
const COPY_CHUNK_BYTES: usize = 64 * 1024;

/// Path of the scratch image an apply builds before renaming it over `main.db`.
#[must_use]
pub(crate) fn staged_image_path(main_db_path: &str) -> String {
    format!("{main_db_path}.applying")
}

/// Copy the live `main.db` to `staged_path`, replacing anything already there.
///
/// The copy is verbatim: the base image's pages are already sealed under this
/// handle's keys at their own page ids, and the staged image occupies the same
/// ids, so re-sealing would consume nonces and change bytes for no gain. Both
/// A/B header slots come along too, which is what lets the scratch be opened
/// directly if a crash happens to land after the rename.
pub(crate) async fn clone_base_image<V: Vfs>(
    vfs: &V,
    base_path: &str,
    staged_path: &str,
) -> Result<()> {
    discard_staged_image(vfs, staged_path).await;

    let mut base = vfs.open(base_path, OpenMode::Read).await?;
    let total = base.len().await?;
    let mut staged = vfs.open(staged_path, OpenMode::CreateOrOpen).await?;
    staged.set_len(total).await?;

    let mut buf = vec![0u8; COPY_CHUNK_BYTES];
    let mut offset = 0u64;
    while offset < total {
        // `min` against the buffer length keeps the conversion in range on any
        // pointer width, so the chunk is always a real slice of `buf`.
        let want = usize::try_from(total.saturating_sub(offset))
            .unwrap_or(COPY_CHUNK_BYTES)
            .min(COPY_CHUNK_BYTES);
        read_exact_at(&mut base, offset, &mut buf[..want]).await?;
        write_all_at(&mut staged, offset, &buf[..want]).await?;
        let advance = u64::try_from(want)
            .map_err(|_| PagedbError::arithmetic_overflow("staged image copy offset"))?;
        offset = offset.saturating_add(advance);
    }
    staged.sync().await
}

/// Remove an abandoned staged image.
///
/// Errors are dropped deliberately: the scratch is unreferenced by any durable
/// header, so its absence is the only state that matters and a removal failure
/// must not replace the error the caller is already returning.
pub(crate) async fn discard_staged_image<V: Vfs>(vfs: &V, staged_path: &str) {
    let _ = vfs.remove(staged_path).await;
}
