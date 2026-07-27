/// Verify apply-journal encode/decode round-trips and idempotent action replay.
/// These tests exercise the journal machinery at the level of the public
/// encode/decode API and the VFS rename layer without requiring a full crash.
use crate::recovery::journal::{ApplyJournalRecord, JournalAction, decode_record, encode_record};
use crate::vfs::Vfs;
use crate::vfs::memory::MemVfs;

#[test]
fn encode_promote_then_decode() {
    let seg_id = [0xAA; 16];
    let record = ApplyJournalRecord {
        target_commit_id: 7,
        actions: vec![JournalAction::Promote { segment_id: seg_id }],
    };
    let buf = encode_record(&record);
    let decoded = decode_record(&buf).unwrap();
    assert_eq!(decoded.target_commit_id, 7);
    assert_eq!(decoded.actions.len(), 1);
    assert!(
        matches!(decoded.actions[0], JournalAction::Promote { segment_id } if segment_id == seg_id)
    );
}

#[test]
fn encode_tombstone_then_decode() {
    let seg_id = [0xBB; 16];
    let record = ApplyJournalRecord {
        target_commit_id: 42,
        actions: vec![JournalAction::Tombstone {
            segment_id: seg_id,
            tombstone_commit_id: 41,
        }],
    };
    let buf = encode_record(&record);
    let decoded = decode_record(&buf).unwrap();
    assert_eq!(decoded.target_commit_id, 42);
    assert!(
        matches!(decoded.actions[0], JournalAction::Tombstone { segment_id, tombstone_commit_id } if segment_id == seg_id && tombstone_commit_id == 41)
    );
}

#[test]
fn encode_mixed_actions_then_decode() {
    let seg_a = [0x01; 16];
    let seg_b = [0x02; 16];
    let record = ApplyJournalRecord {
        target_commit_id: 100,
        actions: vec![
            JournalAction::Promote { segment_id: seg_a },
            JournalAction::Tombstone {
                segment_id: seg_b,
                tombstone_commit_id: 99,
            },
        ],
    };
    let buf = encode_record(&record);
    let decoded = decode_record(&buf).unwrap();
    assert_eq!(decoded.actions.len(), 2);
    assert_eq!(decoded, record);
}

#[tokio::test(flavor = "current_thread")]
async fn promote_action_is_idempotent_when_live_exists() {
    use crate::recovery::journal::execute_journal_actions;
    use crate::vfs::types::OpenMode;

    let vfs = MemVfs::new();
    let segment_id = [0xCC; 16];
    let live = format!(
        "seg/{}",
        segment_id
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    vfs.open(&live, OpenMode::CreateNew).await.unwrap();

    let actions = vec![JournalAction::Promote { segment_id }];
    execute_journal_actions(&vfs, &actions).await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn promote_action_propagates_missing_staging() {
    use crate::recovery::journal::execute_journal_actions;

    let vfs = MemVfs::new();
    let actions = vec![JournalAction::Promote {
        segment_id: [0xCE; 16],
    }];
    assert!(execute_journal_actions(&vfs, &actions).await.is_err());
}

#[tokio::test(flavor = "current_thread")]
async fn promote_action_renames_staging_to_live() {
    use crate::recovery::journal::execute_journal_actions;
    use crate::vfs::VfsFile;
    use crate::vfs::types::OpenMode;

    let vfs = MemVfs::new();
    let seg_id: [u8; 16] = [0xDD; 16];

    // Create the staging directory and file.
    vfs.mkdir_all("seg/.staging").await.unwrap();
    let staging_name = format!(
        "seg/.staging/{}",
        seg_id
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    {
        let mut f = vfs.open(&staging_name, OpenMode::CreateNew).await.unwrap();
        f.write_at(0, b"segment_content").await.unwrap();
        f.sync().await.unwrap();
    }

    // Execute promote; staging should move to live.
    let actions = vec![JournalAction::Promote { segment_id: seg_id }];
    execute_journal_actions(&vfs, &actions).await.unwrap();

    let live_name = format!(
        "seg/{}",
        seg_id
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    // Live file should now exist.
    let f = vfs.open(&live_name, OpenMode::Read).await.unwrap();
    let mut buf = vec![0u8; 15];
    let n = f.read_at(0, &mut buf).await.unwrap();
    assert_eq!(n, 15);
    assert_eq!(&buf, b"segment_content");
}

/// A tombstone's goal state is that the live file is *gone*, so its absence is
/// itself the proof that the action completed — unlike a promote, whose goal
/// state is a file that exists and whose absence therefore proves nothing.
///
/// The two are not symmetric and must not be made so. `seg/.tombstone/` is
/// reclaimed wholesale by `recovery::gc::delete_tombstone_files`, so "live gone
/// and tombstone gone" is the ordinary state of a delete that finished and was
/// then collected. Treating it as unproven would make replay of an already
/// completed journal fail permanently, and would diverge from the pin-aware
/// `Db::tombstone_segment` this fixture models, which reports the same state as
/// complete.
#[tokio::test(flavor = "current_thread")]
async fn tombstone_action_is_idempotent_when_live_absent() {
    use crate::recovery::journal::execute_journal_actions;
    use crate::vfs::types::OpenMode;

    let vfs = MemVfs::new();
    let segment_id = [0xEE; 16];
    let actions = vec![JournalAction::Tombstone {
        segment_id,
        tombstone_commit_id: 5,
    }];
    execute_journal_actions(&vfs, &actions).await.unwrap();

    // A no-op, not a rename of nothing into something: replay must not leave a
    // tombstone behind for a segment whose bytes are already gone.
    let tombstone = tombstone_path(&segment_id, 5);
    assert!(
        vfs.open(&tombstone, OpenMode::Read).await.is_err(),
        "replay must not fabricate a tombstone for an already-deleted segment"
    );
}

/// Replay after a crash between the rename and the journal clear finds the
/// destination already in place. It must leave those bytes untouched — a
/// second rename would either fail or overwrite the retained copy that a
/// reader may still be pinning.
#[tokio::test(flavor = "current_thread")]
async fn tombstone_action_preserves_an_existing_destination() {
    use crate::recovery::journal::execute_journal_actions;
    use crate::vfs::VfsFile;
    use crate::vfs::types::OpenMode;

    let vfs = MemVfs::new();
    let segment_id = [0xEF; 16];
    let tombstone = tombstone_path(&segment_id, 5);
    vfs.mkdir_all("seg/.tombstone").await.unwrap();
    {
        let mut file = vfs.open(&tombstone, OpenMode::CreateNew).await.unwrap();
        file.write_at(0, b"already-tombstoned").await.unwrap();
        file.sync().await.unwrap();
    }

    let actions = vec![JournalAction::Tombstone {
        segment_id,
        tombstone_commit_id: 5,
    }];
    execute_journal_actions(&vfs, &actions).await.unwrap();

    let file = vfs.open(&tombstone, OpenMode::Read).await.unwrap();
    let mut bytes = vec![0u8; b"already-tombstoned".len()];
    let read = file.read_at(0, &mut bytes).await.unwrap();
    assert_eq!(read, bytes.len());
    assert_eq!(&bytes, b"already-tombstoned");
}

#[tokio::test(flavor = "current_thread")]
async fn tombstone_action_renames_live_to_tombstone() {
    use crate::recovery::journal::execute_journal_actions;
    use crate::vfs::VfsFile;
    use crate::vfs::types::OpenMode;

    let vfs = MemVfs::new();
    let segment_id = [0xF0; 16];
    let live = crate::segment::writer::live_path(&segment_id);
    vfs.mkdir_all("seg").await.unwrap();
    {
        let mut file = vfs.open(&live, OpenMode::CreateNew).await.unwrap();
        file.write_at(0, b"segment_content").await.unwrap();
        file.sync().await.unwrap();
    }

    let actions = vec![JournalAction::Tombstone {
        segment_id,
        tombstone_commit_id: 9,
    }];
    execute_journal_actions(&vfs, &actions).await.unwrap();

    assert!(
        vfs.open(&live, OpenMode::Read).await.is_err(),
        "the live path must be vacated by the rename"
    );
    let file = vfs
        .open(&tombstone_path(&segment_id, 9), OpenMode::Read)
        .await
        .unwrap();
    let mut bytes = vec![0u8; b"segment_content".len()];
    let read = file.read_at(0, &mut bytes).await.unwrap();
    assert_eq!(read, bytes.len());
    assert_eq!(&bytes, b"segment_content");
}

fn tombstone_path(segment_id: &[u8; 16], tombstone_commit_id: u64) -> String {
    format!(
        "seg/.tombstone/{}.{tombstone_commit_id}",
        crate::hex::to_hex_lower(segment_id)
    )
}
