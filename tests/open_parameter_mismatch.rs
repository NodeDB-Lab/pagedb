//! A caller who supplies the wrong open parameters must be told *which*
//! parameter is wrong — never that their store is corrupt.
//!
//! These three cases are the ones an operator meets in practice: a rotated or
//! mistyped KEK, a store created at a non-default page size, and a realm that
//! belongs to a different tenant. All three used to surface as
//! `Corruption(HeaderUnverifiable)` or as a tag failure on the first read, and
//! the reasonable reaction to "your database is corrupt" — discard and
//! re-create — destroys data that the right parameter would have opened. So
//! every test here asserts both halves: the refusal names the mistake, *and*
//! the store still opens and still holds its data afterwards.

use pagedb::vfs::memory::MemVfs;
use pagedb::{Db, OpenOptions, PagedbError, RealmId};

const KEK: [u8; 32] = [0x11; 32];
const OTHER_KEK: [u8; 32] = [0x22; 32];
const REALM: RealmId = RealmId::new([0xAA; 16]);
const PAGE: usize = 4096;

/// A store with one committed key, and the VFS holding it.
async fn seeded_store() -> MemVfs {
    let vfs = MemVfs::new();
    let db = Db::open(vfs.clone(), KEK, PAGE, REALM, OpenOptions::default())
        .await
        .unwrap();
    let mut writer = db.begin_write().await.unwrap();
    writer.put(b"k", b"v").await.unwrap();
    writer.commit().await.unwrap();
    vfs
}

/// The store opens under its real parameters and still has its data.
async fn assert_still_intact(vfs: MemVfs) {
    let db = Db::open(vfs, KEK, PAGE, REALM, OpenOptions::default())
        .await
        .expect("the rightful parameters must still open the store");
    let reader = db.begin_read().await.unwrap();
    assert_eq!(
        reader.get(b"k").await.unwrap().as_deref(),
        Some(b"v".as_slice())
    );
}

#[tokio::test(flavor = "current_thread")]
async fn a_wrong_kek_is_not_reported_as_corruption() {
    let vfs = seeded_store().await;
    let error = Db::open(vfs.clone(), OTHER_KEK, PAGE, REALM, OpenOptions::default())
        .await
        .err()
        .expect("the wrong KEK must not open the store");
    assert!(
        matches!(error, PagedbError::KeyMismatch),
        "a wrong key must be named as such, not as damage: {error:?}"
    );
    // The message is the part an operator acts on, so it carries the
    // instruction not to discard the store.
    let rendered = error.to_string();
    assert!(
        rendered.contains("not modified") && rendered.contains("discard"),
        "the message must tell the operator the store is intact: {rendered}"
    );
    assert_still_intact(vfs).await;
}

#[tokio::test(flavor = "current_thread")]
async fn a_wrong_page_size_names_the_stored_size() {
    let vfs = seeded_store().await;
    for supplied in [8192usize, 16384, 65536] {
        let error = Db::open(vfs.clone(), KEK, supplied, REALM, OpenOptions::default())
            .await
            .err()
            .expect("a mismatched page size must not open the store");
        assert!(
            matches!(
                error,
                PagedbError::PageSizeMismatch { stored, supplied: got }
                    if stored == PAGE && got == supplied
            ),
            "expected the stored and supplied sizes to be named: {error:?}"
        );
    }
    assert_still_intact(vfs).await;
}

/// A page size *smaller* than the store's is the direction where the read
/// lands inside slot A rather than spanning both slots, so it exercises the
/// other half of the cleartext probe.
#[tokio::test(flavor = "current_thread")]
async fn a_wrong_page_size_is_named_in_both_directions() {
    let vfs = MemVfs::new();
    {
        let db = Db::open(vfs.clone(), KEK, 16384, REALM, OpenOptions::default())
            .await
            .unwrap();
        let mut writer = db.begin_write().await.unwrap();
        writer.put(b"k", b"v").await.unwrap();
        writer.commit().await.unwrap();
    }
    let error = Db::open(vfs.clone(), KEK, 4096, REALM, OpenOptions::default())
        .await
        .err()
        .expect("a too-small page size must not open the store");
    assert!(
        matches!(
            error,
            PagedbError::PageSizeMismatch {
                stored: 16384,
                supplied: 4096
            }
        ),
        "{error:?}"
    );

    let db = Db::open(vfs, KEK, 16384, REALM, OpenOptions::default())
        .await
        .unwrap();
    let reader = db.begin_read().await.unwrap();
    assert_eq!(
        reader.get(b"k").await.unwrap().as_deref(),
        Some(b"v".as_slice())
    );
}

/// The read-only modes reach the header through a separate probe that decides
/// `restore_mode` before the full open runs. It must reach the same verdict,
/// or the same mistake would report as damage on one path and as itself on
/// the other.
#[tokio::test(flavor = "current_thread")]
async fn read_only_modes_classify_the_same_mistakes() {
    let vfs = seeded_store().await;

    let error = Db::open_read_only(vfs.clone(), OTHER_KEK, PAGE, REALM, OpenOptions::default())
        .await
        .err()
        .expect("the wrong KEK must not open a read-only handle");
    assert!(matches!(error, PagedbError::KeyMismatch), "{error:?}");

    let error = Db::open_read_only(vfs.clone(), KEK, 8192, REALM, OpenOptions::default())
        .await
        .err()
        .expect("a mismatched page size must not open a read-only handle");
    assert!(
        matches!(
            error,
            PagedbError::PageSizeMismatch {
                stored: 4096,
                supplied: 8192
            }
        ),
        "{error:?}"
    );

    let error = Db::open_read_only(
        vfs.clone(),
        KEK,
        PAGE,
        RealmId::new([0xBB; 16]),
        OpenOptions::default(),
    )
    .await
    .err()
    .expect("a foreign realm must not open a read-only handle");
    assert!(
        matches!(error, PagedbError::RealmMismatch { .. }),
        "{error:?}"
    );

    assert_still_intact(vfs).await;
}

/// A store from another format version must be told to migrate.
///
/// This is the case the wrong-key verdict would otherwise swallow: a store at a
/// different format version has an intact magic and an intact frame, so once
/// the MAC has merely failed it looks exactly like a wrong key. Deciding it
/// from the cleartext version, before any derivation, is what keeps
/// "your store needs migrating" from being reported as "your key is wrong".
#[tokio::test(flavor = "current_thread")]
async fn a_store_from_another_format_version_is_told_to_migrate() {
    use pagedb::vfs::OpenMode;
    use pagedb::vfs::{Vfs, VfsFile};

    let vfs = seeded_store().await;
    // Stamp a future format version into both slots' cleartext version field
    // (bytes 8..10). The MAC no longer covers these bytes correctly, which is
    // precisely the ambiguity being resolved: without the version check this
    // would surface as `KeyMismatch`.
    {
        let mut file = vfs.open("/main.db", OpenMode::ReadWrite).await.unwrap();
        for slot in 0..2u64 {
            file.write_at(slot * PAGE as u64 + 8, &99u16.to_le_bytes())
                .await
                .unwrap();
        }
        file.sync().await.unwrap();
    }

    let error = Db::open(vfs.clone(), KEK, PAGE, REALM, OpenOptions::default())
        .await
        .err()
        .expect("a store at an unknown format version must not open");
    assert!(
        matches!(
            error,
            PagedbError::FormatVersionUnsupported {
                stored: 99,
                supported: 1
            }
        ),
        "expected a version verdict rather than a key verdict: {error:?}"
    );
    let rendered = error.to_string();
    assert!(
        rendered.contains("not modified") && rendered.contains("migration"),
        "the message must point at migration, not discarding: {rendered}"
    );

    // Read-only handles reach the header through a separate probe; it must
    // reach the same verdict.
    let error = Db::open_read_only(vfs, KEK, PAGE, REALM, OpenOptions::default())
        .await
        .err()
        .expect("a read-only handle must refuse it too");
    assert!(
        matches!(error, PagedbError::FormatVersionUnsupported { .. }),
        "{error:?}"
    );
}

/// Bytes that are not a pagedb header at all are still corruption. The
/// wrong-key verdict must not swallow the genuine case.
#[tokio::test(flavor = "current_thread")]
async fn bytes_that_are_not_a_pagedb_header_are_still_corruption() {
    use pagedb::vfs::OpenMode;
    use pagedb::vfs::{Vfs, VfsFile};

    let vfs = seeded_store().await;
    {
        let mut file = vfs.open("/main.db", OpenMode::ReadWrite).await.unwrap();
        // Destroy the magic in both slots: nothing here claims to be ours.
        for slot in 0..2u64 {
            file.write_at(slot * PAGE as u64, b"NOTPGDB!")
                .await
                .unwrap();
        }
        file.sync().await.unwrap();
    }
    let error = Db::open(vfs, KEK, PAGE, REALM, OpenOptions::default())
        .await
        .err()
        .expect("a destroyed header must not open");
    assert!(
        matches!(error, PagedbError::Corruption(_)),
        "a store that no longer claims to be pagedb is damage, not a key \
         problem: {error:?}"
    );
}
