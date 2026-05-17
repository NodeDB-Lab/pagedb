use pagedb::catalog::codec::SegmentKind;
use pagedb::segment::types::SegmentPageKind;
use pagedb::vfs::memory::MemVfs;
use pagedb::vfs::{OpenMode, Vfs};
use pagedb::{Db, RealmId};

const PAGE: usize = 4096;

/// Simulate a crash AFTER seal but BEFORE the link_segment commit by sealing
/// the segment writer, then dropping it without linking. The file lives at
/// `seg/.staging/<hex(id)>`. Reopening the Db should sweep it as an orphan.
#[tokio::test(flavor = "current_thread")]
async fn unlinked_sealed_staging_swept_on_open() {
    let vfs = MemVfs::new();
    let segment_id_hex: String;
    {
        let db = Db::open_internal(vfs.clone(), [9u8; 32], PAGE, RealmId::new([1; 16]))
            .await
            .unwrap();
        let mut w = db
            .create_segment(RealmId::new([1; 16]), SegmentKind::Unspecified)
            .await
            .unwrap();
        w.append_page(SegmentPageKind::Data, b"orphan")
            .await
            .unwrap();
        let meta = w.seal().await.unwrap();
        segment_id_hex = hex_lower(&meta.segment_id);
        // No link_segment + commit. Drop the Db.
    }
    // Confirm the staging file exists before reopen.
    let staging_path = format!("seg/.staging/{segment_id_hex}");
    let _f = vfs.open(&staging_path, OpenMode::Read).await.unwrap();
    drop(_f);
    // Reopen. Reconciliation should sweep the orphan staging file.
    let _db = Db::open_existing(vfs.clone(), [9u8; 32], PAGE, RealmId::new([1; 16]))
        .await
        .unwrap();
    // Staging file is gone.
    let res = vfs.open(&staging_path, OpenMode::Read).await;
    assert!(res.is_err(), "orphan staging file should have been swept");
}

/// Simulate a crash BETWEEN a link_segment commit's header-fsync and the
/// rename of staging -> live: manually rename the live file back to
/// staging after a successful link, then reopen and verify reconciliation
/// promotes the staging file back to live.
#[tokio::test(flavor = "current_thread")]
async fn link_commit_then_rename_staging_recovers() {
    let vfs = MemVfs::new();
    let segment_id_hex: String;
    {
        let db = Db::open_internal(vfs.clone(), [9u8; 32], PAGE, RealmId::new([1; 16]))
            .await
            .unwrap();
        let mut w = db
            .create_segment(RealmId::new([1; 16]), SegmentKind::Unspecified)
            .await
            .unwrap();
        w.append_page(SegmentPageKind::Data, b"recovered")
            .await
            .unwrap();
        let meta = w.seal().await.unwrap();
        segment_id_hex = hex_lower(&meta.segment_id);
        let mut t = db.begin_write().await.unwrap();
        t.link_segment("name", &meta).await.unwrap();
        t.commit().await.unwrap();
    }
    // Simulate the crash window: rename seg/<id> -> seg/.staging/<id>.
    let live = format!("seg/{segment_id_hex}");
    let staging = format!("seg/.staging/{segment_id_hex}");
    vfs.rename(&live, &staging).await.unwrap();
    // Reopen. Reconciliation finds catalog row but file missing at live ->
    // looks for staging and promotes.
    let db = Db::open_existing(vfs.clone(), [9u8; 32], PAGE, RealmId::new([1; 16]))
        .await
        .unwrap();
    // The live file is back.
    let _f = vfs.open(&live, OpenMode::Read).await.unwrap();
    drop(_f);
    let r = db
        .open_segment(RealmId::new([1; 16]), "name")
        .await
        .unwrap();
    let page = r.read_page(1).await.unwrap();
    assert!(page.starts_with(b"recovered"));
}

fn hex_lower(bytes: &[u8; 16]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(32);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}
