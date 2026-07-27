//! Anchor-only refreshes of the live `main.db` A/B header.
//!
//! The nonce counter may only run `anchor_budget` values ahead of the anchor
//! recorded in the durable header, and only a header write advances it. Every
//! ordinary commit writes a header, so ordinary writes never notice the ceiling.
//! Operations that seal many pages before they publish anything — a compaction
//! rebuild into a scratch file, a rekey re-sealing every reachable page, an
//! incremental apply staging a whole image — write no header until their final
//! swap, so without this they draw their entire run from a single window and
//! stop working above a fixed store size.
//!
//! The refresh here rewrites the live header with **every field unchanged
//! except the anchor** (and the `seq` the A/B protocol requires to make the new
//! slot authoritative). That publishes nothing: the roots, the allocation
//! cursor, the free-list head and the commit id all still name exactly the state
//! that was already durable, so a crash immediately afterwards reopens at the
//! same commit — just with a higher anchor. Over-advancing the anchor is always
//! safe, because its only effect is to skip counter values; under-advancing is
//! the direction that risks reuse, and a refresh never moves it down.
//!
//! Slots alternate exactly as an ordinary commit's do. That is what makes a torn
//! refresh safe: the write always targets the slot that is *not* authoritative,
//! so tearing it destroys only a superseded copy and the surviving slot still
//! carries an anchor at least as large as every nonce issued before the crash.

use crate::Result;
use crate::crypto::keys::DerivedKey;
use crate::errors::PagedbError;
use crate::pager::format::structural_header::decode_main_db_header;
use crate::pager::header::{ActiveSlot, commit_header, read_header_slot};
use crate::vfs::Vfs;
use crate::vfs::types::OpenMode;

/// Which A/B slot of `main.db` currently holds the authoritative header, and the
/// `seq` it carries.
///
/// One writer owns this at a time (it is only advanced under the writer mutex),
/// and it is the single authority for the next header write's slot and sequence.
/// Keeping a second copy in writer state would let an anchor refresh and an
/// ordinary commit disagree about which slot is live, which loses a commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeaderCursor {
    pub slot: ActiveSlot,
    pub seq: u64,
}

impl HeaderCursor {
    /// The sequence the next header write must carry.
    pub fn next_seq(&self) -> Result<u64> {
        self.seq
            .checked_add(1)
            .ok_or_else(|| PagedbError::arithmetic_overflow("header sequence"))
    }
}

/// Everything an anchor refresh needs that the pager cannot derive on its own:
/// the header key (which a rekey swaps under the handle) and the A/B cursor.
pub(crate) struct LiveHeader {
    pub hk: std::sync::Arc<parking_lot::RwLock<DerivedKey>>,
    pub cursor: HeaderCursor,
}

/// Rewrite the header at `path` with `anchor` and nothing else changed, into the
/// slot the A/B protocol says is next. Returns the cursor describing the header
/// now authoritative.
///
/// The current fields are read back from the authoritative slot rather than
/// rebuilt from writer state: "leave every other field exactly as it is" is only
/// literally true if the bytes come from the header being replaced.
pub(crate) async fn refresh_anchor<V: Vfs>(
    vfs: &V,
    path: &str,
    hk: &DerivedKey,
    cursor: HeaderCursor,
    anchor: u64,
    page_size: usize,
) -> Result<HeaderCursor> {
    let page_size_u64 = u64::try_from(page_size)
        .map_err(|_| PagedbError::arithmetic_overflow("header page size"))?;
    let offset = cursor.slot.page_id().saturating_mul(page_size_u64);

    let mut file = vfs.open(path, OpenMode::Read).await?;
    let mut buf = vec![0u8; page_size];
    read_header_slot(&mut file, offset, &mut buf).await?;
    drop(file);

    let mut fields = decode_main_db_header(&buf, hk, page_size)?;
    if anchor < fields.counter_anchor {
        // A refresh may only ever raise the anchor. Writing a smaller one would
        // let recovery hand back counter values the pre-crash run already used.
        return Err(PagedbError::structural_header_invalid(
            "main.db",
            "counter_anchor",
        ));
    }
    fields.counter_anchor = anchor;
    fields.seq = cursor.next_seq()?;

    let slot = commit_header(vfs, path, hk, &fields, cursor.slot, page_size).await?;
    Ok(HeaderCursor {
        slot,
        seq: fields.seq,
    })
}

#[cfg(test)]
mod tests {
    use crate::vfs::memory::MemVfs;
    use crate::vfs::types::OpenMode;
    use crate::vfs::{Vfs, VfsFile};
    use crate::{CommitId, Db, OpenOptions, RealmId};

    const PAGE: usize = 4096;
    const KEK: [u8; 32] = [0x6Au8; 32];
    const REALM: RealmId = RealmId::new([0xC3u8; 16]);

    async fn seeded_db(vfs: MemVfs) -> Db<MemVfs> {
        let db = Db::open_internal_with_options(
            vfs,
            KEK,
            PAGE,
            REALM,
            OpenOptions::default().with_anchor_budget(8),
        )
        .await
        .unwrap();
        let mut writer = db.begin_write().await.unwrap();
        for index in 0u32..16 {
            writer
                .put(format!("k-{index:03}").as_bytes(), b"anchored")
                .await
                .unwrap();
        }
        writer.commit().await.unwrap();
        db
    }

    async fn assert_store_intact(vfs: MemVfs, expected_commit: CommitId) {
        let reopened = Db::open_existing(vfs, KEK, PAGE, REALM).await.unwrap();
        assert_eq!(
            reopened.latest_commit(),
            expected_commit,
            "an anchor refresh must not move the committed state"
        );
        let reader = reopened.begin_read().await.unwrap();
        for index in 0u32..16 {
            let key = format!("k-{index:03}");
            assert_eq!(
                reader.get(key.as_bytes()).await.unwrap().as_deref(),
                Some(b"anchored".as_slice()),
                "value {key} lost across an anchor refresh"
            );
        }
    }

    /// A refresh makes nonces durable without publishing anything: the reopened
    /// store is at the same commit with the same data, and the anchor is higher.
    #[tokio::test(flavor = "current_thread")]
    async fn refreshing_the_anchor_publishes_nothing() {
        let vfs = MemVfs::new();
        let db = seeded_db(vfs.clone()).await;
        let committed = db.latest_commit();
        let before = db.pager.durable_anchor();

        for _ in 0..3 {
            db.pager.refresh_main_anchor().await.unwrap();
        }
        assert!(
            db.pager.durable_anchor() >= before,
            "a refresh may never lower the durable anchor"
        );
        drop(db);

        assert_store_intact(vfs, committed).await;
    }

    /// Refreshes alternate A/B slots exactly as commits do, so at every instant
    /// one slot is a complete, verifiable header for the committed state.
    /// Destroying either one — the shape a torn write leaves — must still reopen
    /// at the same commit off the other.
    ///
    /// Both halves matter. Tearing the slot the *next* refresh targets is the
    /// ordinary case; tearing the slot the *last* refresh made authoritative is
    /// the case that would be unsafe if refreshes reused one slot, because
    /// falling back would then regress the durable anchor below nonces already
    /// issued. Alternation is what makes the fallback a slot whose anchor was
    /// never exceeded.
    #[tokio::test(flavor = "current_thread")]
    async fn a_torn_refresh_reopens_at_the_same_commit() {
        for (refreshes_before_tear, tear_authoritative) in
            [(1u32, false), (2, false), (1, true), (2, true)]
        {
            let vfs = MemVfs::new();
            let db = seeded_db(vfs.clone()).await;
            let committed = db.latest_commit();
            for _ in 0..refreshes_before_tear {
                db.pager.refresh_main_anchor().await.unwrap();
            }
            let live = db.pager.header_cursor().unwrap().slot;
            let target = if tear_authoritative {
                live
            } else {
                live.other()
            };
            drop(db);

            let offset = target.page_id() * PAGE as u64;
            let mut file = vfs.open("/main.db", OpenMode::ReadWrite).await.unwrap();
            file.write_at(offset, &[0u8; PAGE]).await.unwrap();
            file.sync().await.unwrap();
            drop(file);

            assert_store_intact(vfs, committed).await;
        }
    }
}
