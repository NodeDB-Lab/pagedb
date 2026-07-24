// SPDX-License-Identifier: MIT OR Apache-2.0
#![cfg(feature = "diagnostics")]

//! Proves the black-box wiring fires end to end: a page that fails AEAD/MAC
//! verification on read (here via a cross-realm reopen, the same failure class
//! as the freed-page use-after-free) produces a structured corruption report
//! with pagedb's forensic domain context.

use pagedb::vfs::memory::MemVfs;
use pagedb::{CipherId, Db, PagedbError, RealmId};

const PAGE: usize = 4096;

#[tokio::test(flavor = "current_thread")]
async fn read_verify_failure_emits_blackbox_corruption_report() {
    let reports = tempfile::tempdir().unwrap();
    // The host app owns init; here the test plays that role.
    blackbox::init(
        blackbox::Config::new("pagedb", env!("CARGO_PKG_VERSION"), reports.path())
            .install_panic_hook(false),
    );

    let vfs = MemVfs::new();
    // realm_a writes; a breadcrumb is recorded on commit.
    {
        let db_a = Db::open_internal_with_cipher(
            vfs.clone(),
            [9u8; 32],
            PAGE,
            RealmId::new([1; 16]),
            CipherId::Aes256Gcm,
        )
        .await
        .unwrap();
        let mut w = db_a.begin_write().await.unwrap();
        w.put(b"k", b"v").await.unwrap();
        w.commit().await.unwrap();
    }

    // realm_b reopens the same bytes: the B+ tree root was AAD'd under realm_a,
    // so realm_b's read triggers a tag failure — routed through the wired
    // `diag::page_read_verify_failed`.
    let db_b = Db::open_existing(vfs, [9u8; 32], PAGE, RealmId::new([2; 16]))
        .await
        .unwrap();
    let r = db_b.begin_read().await.unwrap();
    let err = r.get(b"k").await.err().unwrap();
    assert!(matches!(err, PagedbError::ChecksumFailure));

    // A corruption report was written with pagedb's forensic domain context.
    let dirs: Vec<_> = std::fs::read_dir(reports.path())
        .unwrap()
        .filter_map(Result::ok)
        .collect();
    assert!(!dirs.is_empty(), "at least one report was written");

    let report = dirs
        .iter()
        .find_map(|d| std::fs::read_to_string(d.path().join("report.json")).ok())
        .expect("a report.json exists");

    assert!(
        report.contains("pagedb.page_read_verify_failure"),
        "domain kind present: {report}"
    );
    assert!(report.contains("\"corruption\""), "corruption event kind");
    assert!(report.contains("page_id"), "page forensics present");
    assert!(report.contains("fsck_hint"), "operator hint present");
}
