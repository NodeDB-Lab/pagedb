// SPDX-License-Identifier: MIT OR Apache-2.0
#![cfg(feature = "diagnostics")]

//! Proves the black-box wiring fires end to end: a page that fails AEAD/MAC
//! verification on read produces a structured corruption report with pagedb's
//! forensic domain context.
//!
//! The failure is induced by damaging a page's authentication tag on disk,
//! which is the same failure class a freed-page use-after-free surfaces as —
//! and, unlike a parameter mistake such as a wrong realm, one that genuinely
//! has to be discovered at read time rather than refused at open.

use pagedb::vfs::memory::MemVfs;
use pagedb::{CipherId, CorruptionDetail, Db, OpenOptions, PagedbError, RealmId};

const PAGE: usize = 4096;

#[tokio::test(flavor = "current_thread")]
async fn read_verify_failure_emits_faultbox_corruption_report() {
    let reports = tempfile::tempdir().unwrap();
    // The host app owns init; here the test plays that role.
    faultbox::init(
        faultbox::Config::new("pagedb", env!("CARGO_PKG_VERSION"), reports.path())
            .install_panic_hook(false),
    );

    let vfs = MemVfs::new();
    // Seed some data, then close the handle before touching its bytes
    // underneath it.
    let next_page_id = {
        let db = Db::open(
            vfs.clone(),
            [9u8; 32],
            PAGE,
            RealmId::new([1; 16]),
            OpenOptions::default().with_cipher(CipherId::Aes256Gcm),
        )
        .await
        .unwrap();
        let mut w = db.begin_write().await.unwrap();
        for i in 0u64..10 {
            w.put(format!("k{i:04}").as_bytes(), &[0xAB; 64])
                .await
                .unwrap();
        }
        w.commit().await.unwrap();
        let next_page_id = db.stats().await.unwrap().main_db_next_page_id;
        assert!(
            next_page_id > 4,
            "the seed writes must allocate at least one data page"
        );
        next_page_id
    };

    // Flip the AEAD tag of every data page, so whichever page the read walks
    // to is damaged regardless of where copy-on-write left the live root.
    {
        use pagedb::vfs::OpenMode;
        use pagedb::vfs::{Vfs, VfsFile};
        let mut f = vfs.open("/main.db", OpenMode::ReadWrite).await.unwrap();
        for page_id in 4..next_page_id {
            let tag_offset = page_id * PAGE as u64 + (PAGE - 16) as u64;
            let mut tag = [0u8; 16];
            f.read_at(tag_offset, &mut tag).await.unwrap();
            for byte in &mut tag {
                *byte ^= 0xFF;
            }
            f.write_at(tag_offset, &tag).await.unwrap();
        }
        f.sync().await.unwrap();
    }

    // A fresh handle has a cold buffer pool, so this reads the damaged bytes
    // rather than the page the writer left warm.
    let db = Db::open(
        vfs,
        [9u8; 32],
        PAGE,
        RealmId::new([1; 16]),
        OpenOptions::default(),
    )
    .await
    .unwrap();
    let reader = db.begin_read().await.unwrap();
    let Err(err) = reader.get(b"k0000").await else {
        panic!("a damaged tag must fail the read");
    };
    assert!(
        matches!(
            err,
            PagedbError::Corruption(CorruptionDetail::PageUnverifiable { .. })
        ),
        "expected a page-identified verification failure, got: {err:?}"
    );

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
