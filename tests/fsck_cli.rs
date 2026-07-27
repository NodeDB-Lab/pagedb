#![cfg(not(target_arch = "wasm32"))]

use std::{collections::BTreeMap, path::Path, process::Command};

use pagedb::options::{OpenOptions, RetainPolicy};
use pagedb::vfs::tokio_backend::TokioVfs;
use pagedb::{Db, RealmId, SegmentKind, SegmentPageKind};

const KEK: [u8; 32] = [0xA5; 32];
const KEK_HEX: &str = "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5";
const OTHER_KEK_HEX: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const REALM: RealmId = RealmId::new([0; 16]);
const REALM_HEX: &str = "00000000000000000000000000000000";
const PAGE: usize = 4096;

/// The command line was invalid; the store was never touched.
const EXIT_USAGE: i32 = 2;
/// The store could not be opened.
const EXIT_OPERATIONAL: i32 = 3;
/// An integrity problem was found.
const EXIT_INTEGRITY: i32 = 1;

fn fsck() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_pagedb-fsck"));
    command.env_remove("PAGEDB_KEK");
    command
}

/// Build a store holding one committed key and one sealed, catalog-linked
/// segment, so a deep walk has both surfaces to traverse.
async fn create_store(path: &Path) {
    let options = OpenOptions::default().with_commit_history_retain(RetainPolicy::Disabled);
    let db = Db::open(TokioVfs::new(path), KEK, PAGE, REALM, options)
        .await
        .unwrap();
    let mut segment = db
        .create_segment(REALM, SegmentKind::Unspecified)
        .await
        .unwrap();
    segment
        .append_page(SegmentPageKind::Data, b"fsck-segment")
        .await
        .unwrap();
    let segment_meta = segment.seal().await.unwrap();
    let mut write = db.begin_write().await.unwrap();
    write.put(b"fsck-key", b"fsck-value").await.unwrap();
    write
        .link_segment("fsck-segment", &segment_meta)
        .await
        .unwrap();
    write.commit().await.unwrap();
}

fn collect_files(root: &Path, current: &Path, files: &mut BTreeMap<String, Vec<u8>>) {
    if !current.exists() {
        return;
    }
    for entry in std::fs::read_dir(current).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.is_dir() {
            collect_files(root, &path, files);
        } else {
            let relative = path
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .into_owned();
            files.insert(relative, std::fs::read(path).unwrap());
        }
    }
}

fn authoritative_bytes(root: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut files = BTreeMap::new();
    files.insert(
        "main.db".to_string(),
        std::fs::read(root.join("main.db")).unwrap(),
    );
    collect_files(root, &root.join("seg"), &mut files);
    files
}

/// Path of the single live segment file, so a test can damage it.
fn live_segment_file(root: &Path) -> std::path::PathBuf {
    std::fs::read_dir(root.join("seg"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.is_file())
        .expect("expected exactly one live segment file")
}

#[tokio::test(flavor = "current_thread")]
async fn fsck_accepts_explicit_realm_and_preserves_authoritative_bytes() {
    let dir = tempfile::tempdir().unwrap();
    create_store(dir.path()).await;

    let before = authoritative_bytes(dir.path());
    // Without this the comparison below silently degrades to main.db alone if
    // the segment layout ever moves, and the segment half of the claim would
    // pass while covering nothing.
    assert!(
        before.keys().any(|path| path.starts_with("seg")),
        "snapshot captured no segment files, so byte preservation would be \
         vacuously true for segments: {:?}",
        before.keys().collect::<Vec<_>>()
    );

    let output = fsck()
        .arg(dir.path())
        .args(["--deep", "--realm", REALM_HEX, KEK_HEX])
        .output()
        .unwrap();
    let after = authoritative_bytes(dir.path());

    assert!(
        output.status.success(),
        "fsck failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        after, before,
        "fsck changed authoritative main.db or segment bytes"
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("result: CLEAN"),
        "deep fsck did not emit a clean report: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[tokio::test(flavor = "current_thread")]
async fn fsck_reads_the_kek_from_the_environment_when_no_positional_key_is_given() {
    let dir = tempfile::tempdir().unwrap();
    create_store(dir.path()).await;

    let output = fsck()
        .env("PAGEDB_KEK", KEK_HEX)
        .arg(dir.path())
        .args(["--deep", "--realm", REALM_HEX])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "PAGEDB_KEK fallback did not open the store: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// A shallow open is the common invocation and must stay valid.
#[tokio::test(flavor = "current_thread")]
async fn fsck_opens_without_deep_and_reports_success() {
    let dir = tempfile::tempdir().unwrap();
    create_store(dir.path()).await;

    let output = fsck()
        .arg(dir.path())
        .args(["--realm", REALM_HEX, KEK_HEX])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("structural open OK"), "{stdout}");
    assert!(
        !stdout.contains("running deep walk"),
        "deep walk ran without --deep: {stdout}"
    );
}

/// A store written at a non-default page size is inspectable. Header B lives
/// at byte offset `page_size`, so without the override the checker reads the
/// wrong bytes and blames the header.
#[tokio::test(flavor = "current_thread")]
async fn fsck_inspects_a_store_whose_page_size_is_not_the_default() {
    let dir = tempfile::tempdir().unwrap();
    {
        let options = OpenOptions::default().with_commit_history_retain(RetainPolicy::Disabled);
        let db = Db::open(TokioVfs::new(dir.path()), KEK, 16384, REALM, options)
            .await
            .unwrap();
        let mut write = db.begin_write().await.unwrap();
        write.put(b"k", b"v").await.unwrap();
        write.commit().await.unwrap();
    }

    let without_override = fsck()
        .arg(dir.path())
        .args(["--realm", REALM_HEX, KEK_HEX])
        .output()
        .unwrap();
    assert_eq!(
        without_override.status.code(),
        Some(EXIT_OPERATIONAL),
        "a page-size mismatch should report an unreadable store"
    );

    let with_override = fsck()
        .arg(dir.path())
        .args([
            "--deep",
            "--page-size",
            "16384",
            "--realm",
            REALM_HEX,
            KEK_HEX,
        ])
        .output()
        .unwrap();
    assert!(
        with_override.status.success(),
        "--page-size did not make the store inspectable: stdout={} stderr={}",
        String::from_utf8_lossy(&with_override.stdout),
        String::from_utf8_lossy(&with_override.stderr)
    );
}

#[test]
fn fsck_rejects_ambiguous_or_unknown_arguments() {
    let dir = tempfile::tempdir().unwrap();
    let cases: &[(&[&str], &str)] = &[
        (&["--deep", "--deep"], "duplicate --deep"),
        (
            &["--realm", REALM_HEX, "--realm", REALM_HEX],
            "duplicate --realm",
        ),
        (
            &["--page-size", "4096", "--page-size", "8192"],
            "duplicate --page-size",
        ),
        (&[KEK_HEX, KEK_HEX], "multiple KEK"),
        (&["--unknown"], "unknown option --unknown"),
        // A single-dash token must not fall through to the key slot and
        // resurface as a hex complaint about something the operator never
        // meant as a key.
        (&["-v"], "unknown option -v"),
        (&["--realm"], "--realm requires"),
        (&["--realm", "--deep"], "--realm requires"),
        (&["--page-size"], "--page-size requires"),
        (&["--page-size", "0"], "--page-size requires"),
        (&["--page-size", "many"], "--page-size requires"),
    ];

    for (args, expected) in cases {
        let output = fsck().arg(dir.path()).args(*args).output().unwrap();
        assert_eq!(
            output.status.code(),
            Some(EXIT_USAGE),
            "args {args:?}: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(expected),
            "args {args:?}: expected stderr containing {expected:?}, got {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let output = fsck().arg("--deep").output().unwrap();
    assert_eq!(output.status.code(), Some(EXIT_USAGE));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("found option --deep"),
        "option used as path was not rejected: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let output = fsck().output().unwrap();
    assert_eq!(output.status.code(), Some(EXIT_USAGE));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("database path is required"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// A tool that has just tightened its grammar has to be able to state that
/// grammar on request, on stdout, without an error status.
#[test]
fn fsck_prints_the_grammar_for_help_and_exits_successfully() {
    for flag in ["--help", "-h"] {
        let output = fsck().arg(flag).output().unwrap();
        assert!(
            output.status.success(),
            "{flag} exited {:?}",
            output.status.code()
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("usage: pagedb-fsck"), "{flag}: {stdout}");
        assert!(stdout.contains("--page-size"), "{flag}: {stdout}");
        assert!(
            output.stderr.is_empty(),
            "{flag} wrote to stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

/// The three failure classes an operator has to act on differently must not
/// collapse into one non-zero code.
#[tokio::test(flavor = "current_thread")]
async fn fsck_separates_usage_unreadable_and_integrity_exit_codes() {
    let dir = tempfile::tempdir().unwrap();
    create_store(dir.path()).await;

    let usage = fsck().arg(dir.path()).arg("--unknown").output().unwrap();
    assert_eq!(usage.status.code(), Some(EXIT_USAGE));

    let empty = tempfile::tempdir().unwrap();
    let missing = fsck()
        .arg(empty.path())
        .args(["--realm", REALM_HEX, KEK_HEX])
        .output()
        .unwrap();
    assert_eq!(
        missing.status.code(),
        Some(EXIT_OPERATIONAL),
        "an absent store must not look like corruption: {}",
        String::from_utf8_lossy(&missing.stderr)
    );

    let wrong_key = fsck()
        .arg(dir.path())
        .args(["--realm", REALM_HEX, OTHER_KEK_HEX])
        .output()
        .unwrap();
    assert_eq!(
        wrong_key.status.code(),
        Some(EXIT_OPERATIONAL),
        "a wrong key must not look like corruption: {}",
        String::from_utf8_lossy(&wrong_key.stderr)
    );

    // Damage a live segment body: main.db's headers stay intact, so the open
    // succeeds and only the deep walk can find the fault.
    let segment_path = live_segment_file(dir.path());
    let mut bytes = std::fs::read(&segment_path).unwrap();
    let middle = bytes.len() / 2;
    bytes[middle] ^= 0xFF;
    std::fs::write(&segment_path, &bytes).unwrap();

    let damaged = fsck()
        .arg(dir.path())
        .args(["--deep", "--realm", REALM_HEX, KEK_HEX])
        .output()
        .unwrap();
    assert_eq!(
        damaged.status.code(),
        Some(EXIT_INTEGRITY),
        "a damaged store did not report the integrity code: stdout={} stderr={}",
        String::from_utf8_lossy(&damaged.stdout),
        String::from_utf8_lossy(&damaged.stderr)
    );
}
