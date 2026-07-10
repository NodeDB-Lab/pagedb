/// Verify apply-journal encode/decode round-trips and idempotent action replay.
/// These tests exercise the journal machinery at the level of the public
/// encode/decode API and the VFS rename layer without requiring a full crash.
use pagedb::recovery::journal::{ApplyJournalRecord, JournalAction, decode_record, encode_record};
use pagedb::vfs::Vfs;
use pagedb::vfs::memory::MemVfs;

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
async fn promote_action_is_idempotent_when_staging_absent() {
    // If the staging file is absent, the promote rename is a no-op.
    // execute_journal_actions must not return an error.
    use pagedb::recovery::journal::execute_journal_actions;
    let vfs = MemVfs::new();
    let actions = vec![JournalAction::Promote {
        segment_id: [0xCC; 16],
    }];
    // No staging file exists; execute must succeed silently.
    execute_journal_actions(&vfs, &actions).await;
}

#[tokio::test(flavor = "current_thread")]
async fn promote_action_renames_staging_to_live() {
    use pagedb::recovery::journal::execute_journal_actions;
    use pagedb::vfs::VfsFile;
    use pagedb::vfs::types::OpenMode;

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
    execute_journal_actions(&vfs, &actions).await;

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

#[tokio::test(flavor = "current_thread")]
async fn tombstone_action_is_idempotent_when_live_absent() {
    // If the live file is absent, the tombstone rename is a no-op.
    use pagedb::recovery::journal::execute_journal_actions;
    let vfs = MemVfs::new();
    let actions = vec![JournalAction::Tombstone {
        segment_id: [0xEE; 16],
        tombstone_commit_id: 5,
    }];
    execute_journal_actions(&vfs, &actions).await;
}
