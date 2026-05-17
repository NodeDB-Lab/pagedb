use pagedb::crypto::kdf::{derive_hk, derive_mk};
use pagedb::pager::header::{ActiveSlot, bootstrap_header, commit_header, open_header};
use pagedb::pager::structural_header::{MainDbHeaderFields, encode_main_db_header};
use pagedb::vfs::memory::MemVfs;
use pagedb::vfs::{OpenMode, Vfs, VfsFile};
use pagedb::{CommitId, PagedbError};

fn sample(seq: u64, page_size_log2: u8, anchor: u64) -> MainDbHeaderFields {
    MainDbHeaderFields {
        format_version: 1,
        cipher_id: 1,
        page_size_log2,
        flags: 0,
        file_id: [0xAB; 16],
        kek_salt: [0xCD; 16],
        mk_epoch: 0,
        seq,
        active_root_page_id: 4,
        active_root_txn_id: 1,
        counter_anchor: anchor,
        commit_id: CommitId::new(seq),
        free_list_root: [0; 16],
        catalog_root: [0; 16],
        apply_journal_root_page_id: 0,
        apply_journal_root_version: 0,
        commit_history_root_page_id: 0,
        commit_history_root_version: 0,
        restore_mode: 0,
        next_page_id: 4,
        commit_retain_policy_tag: 0,
        commit_retain_policy_value: 1024,
    }
}

fn hk() -> pagedb::crypto::DerivedKey {
    let mk = derive_mk(&[7u8; 32], &[0u8; 16], 0).unwrap();
    derive_hk(&mk).unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn alternation_picks_latest_seq() {
    let vfs = MemVfs::new();
    let hk = hk();
    bootstrap_header(&vfs, "/main.db", &hk, &sample(1, 12, 0), 4096)
        .await
        .unwrap();
    // commit 2 -> slot B
    let slot = commit_header(
        &vfs,
        "/main.db",
        &hk,
        &sample(2, 12, 1024),
        ActiveSlot::A,
        4096,
    )
    .await
    .unwrap();
    assert_eq!(slot, ActiveSlot::B);
    // commit 3 -> slot A
    let slot = commit_header(
        &vfs,
        "/main.db",
        &hk,
        &sample(3, 12, 2048),
        ActiveSlot::B,
        4096,
    )
    .await
    .unwrap();
    assert_eq!(slot, ActiveSlot::A);
    // commit 4 -> slot B
    let slot = commit_header(
        &vfs,
        "/main.db",
        &hk,
        &sample(4, 12, 3072),
        ActiveSlot::A,
        4096,
    )
    .await
    .unwrap();
    assert_eq!(slot, ActiveSlot::B);

    let (got, active) = open_header(&vfs, "/main.db", &hk, 4096).await.unwrap();
    assert_eq!(got.seq, 4);
    assert_eq!(got.counter_anchor, 3072);
    assert_eq!(active, ActiveSlot::B);
}

#[tokio::test(flavor = "current_thread")]
async fn torn_write_to_inactive_slot_recovers_active() {
    let vfs = MemVfs::new();
    let hk = hk();
    bootstrap_header(&vfs, "/main.db", &hk, &sample(1, 12, 0), 4096)
        .await
        .unwrap();
    // commit (seq=2) into slot B. Active is now B.
    commit_header(
        &vfs,
        "/main.db",
        &hk,
        &sample(2, 12, 100),
        ActiveSlot::A,
        4096,
    )
    .await
    .unwrap();
    // Simulate a torn write by zeroing slot B's MAC tail. The other slot
    // (A with seq=1) must still verify and win the open.
    let mut f = vfs.open("/main.db", OpenMode::ReadWrite).await.unwrap();
    let mut buf = vec![0u8; 4096];
    f.read_at(4096, &mut buf).await.unwrap();
    // Zero the MAC tail (last 16 bytes of slot B).
    for b in &mut buf[4080..] {
        *b = 0;
    }
    f.write_at(4096, &buf).await.unwrap();
    f.sync().await.unwrap();
    drop(f);

    let (got, active) = open_header(&vfs, "/main.db", &hk, 4096).await.unwrap();
    assert_eq!(got.seq, 1);
    assert_eq!(active, ActiveSlot::A);
}

#[tokio::test(flavor = "current_thread")]
async fn both_slots_corrupt_returns_header_unverifiable() {
    let vfs = MemVfs::new();
    let hk = hk();
    bootstrap_header(&vfs, "/main.db", &hk, &sample(1, 12, 0), 4096)
        .await
        .unwrap();
    // Zero both slots' MAC tails.
    let mut f = vfs.open("/main.db", OpenMode::ReadWrite).await.unwrap();
    let zeros16 = [0u8; 16];
    f.write_at(4080, &zeros16).await.unwrap();
    f.write_at(8176, &zeros16).await.unwrap();
    f.sync().await.unwrap();
    drop(f);
    let err = open_header(&vfs, "/main.db", &hk, 4096)
        .await
        .err()
        .unwrap();
    assert!(matches!(err, PagedbError::Corruption(_)));
}

#[tokio::test(flavor = "current_thread")]
async fn anchor_recovery_picks_max_via_seq() {
    // The anchor field is carried by whichever header has the greater seq;
    // we verify the recovered anchor is the one bound to the latest header,
    // not a separate max across slots.
    let vfs = MemVfs::new();
    let hk = hk();
    bootstrap_header(&vfs, "/main.db", &hk, &sample(1, 12, 4500), 4096)
        .await
        .unwrap();
    commit_header(
        &vfs,
        "/main.db",
        &hk,
        &sample(2, 12, 5000),
        ActiveSlot::A,
        4096,
    )
    .await
    .unwrap();
    let (got, _) = open_header(&vfs, "/main.db", &hk, 4096).await.unwrap();
    assert_eq!(got.counter_anchor, 5000);
}

#[tokio::test(flavor = "current_thread")]
async fn page_size_4k_8k_16k_round_trip() {
    let hk = hk();
    for log2 in [12u8, 13, 14] {
        let page_size = 1usize << log2;
        let vfs = MemVfs::new();
        let path = format!("/main_{log2}.db");
        bootstrap_header(&vfs, &path, &hk, &sample(1, log2, 0), page_size)
            .await
            .unwrap();
        commit_header(
            &vfs,
            &path,
            &hk,
            &sample(2, log2, 1024),
            ActiveSlot::A,
            page_size,
        )
        .await
        .unwrap();
        let (got, slot) = open_header(&vfs, &path, &hk, page_size).await.unwrap();
        assert_eq!(got.seq, 2);
        assert_eq!(slot, ActiveSlot::B);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn bootstrap_refuses_existing_file() {
    let vfs = MemVfs::new();
    let hk = hk();
    bootstrap_header(&vfs, "/main.db", &hk, &sample(1, 12, 0), 4096)
        .await
        .unwrap();
    let err = bootstrap_header(&vfs, "/main.db", &hk, &sample(1, 12, 0), 4096)
        .await
        .err()
        .unwrap();
    // CreateNew over an existing path surfaces as Io(AlreadyExists).
    assert!(matches!(err, PagedbError::Io(_)));
}

#[tokio::test(flavor = "current_thread")]
async fn commit_returns_inverted_slot() {
    let vfs = MemVfs::new();
    let hk = hk();
    bootstrap_header(&vfs, "/main.db", &hk, &sample(1, 12, 0), 4096)
        .await
        .unwrap();
    let s = commit_header(
        &vfs,
        "/main.db",
        &hk,
        &sample(2, 12, 0),
        ActiveSlot::A,
        4096,
    )
    .await
    .unwrap();
    assert_eq!(s, ActiveSlot::B);
    let s = commit_header(
        &vfs,
        "/main.db",
        &hk,
        &sample(3, 12, 0),
        ActiveSlot::B,
        4096,
    )
    .await
    .unwrap();
    assert_eq!(s, ActiveSlot::A);
}

#[tokio::test(flavor = "current_thread")]
async fn open_picks_higher_seq_when_both_verify() {
    let vfs = MemVfs::new();
    let hk = hk();
    bootstrap_header(&vfs, "/main.db", &hk, &sample(1, 12, 0), 4096)
        .await
        .unwrap();
    // Write a valid header with seq=5 directly into slot B without going
    // through commit_header. Both slots are now valid; open must pick B.
    let bytes = encode_main_db_header(&sample(5, 12, 9000), &hk, 4096).unwrap();
    let mut f = vfs.open("/main.db", OpenMode::ReadWrite).await.unwrap();
    f.write_at(4096, &bytes).await.unwrap();
    f.sync().await.unwrap();
    drop(f);
    let (got, slot) = open_header(&vfs, "/main.db", &hk, 4096).await.unwrap();
    assert_eq!(got.seq, 5);
    assert_eq!(slot, ActiveSlot::B);
    assert_eq!(got.counter_anchor, 9000);
}
