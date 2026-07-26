#![cfg(not(target_arch = "wasm32"))]

use std::{collections::BTreeMap, path::Path, process::Command};

use pagedb::options::{OpenOptions, RetainPolicy};
use pagedb::segment::types::SegmentPageKind;
use pagedb::vfs::tokio_backend::TokioVfs;
use pagedb::{Db, RealmId, SegmentKind};

const KEK: [u8; 32] = [0xA5; 32];
const KEK_HEX: &str = "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5";
const REALM: RealmId = RealmId::new([0; 16]);
const REALM_HEX: &str = "00000000000000000000000000000000";
const PAGE: usize = 4096;

fn fsck() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_pagedb-fsck"));
    command.env_remove("PAGEDB_KEK");
    command
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

#[tokio::test(flavor = "current_thread")]
async fn fsck_accepts_explicit_realm_and_preserves_authoritative_bytes() {
    let dir = tempfile::tempdir().unwrap();
    {
        let options = OpenOptions::default().with_commit_history_retain(RetainPolicy::Disabled);
        let db = Db::open(TokioVfs::new(dir.path()), KEK, PAGE, REALM, options)
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

    let before = authoritative_bytes(dir.path());
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

#[test]
fn fsck_rejects_ambiguous_or_unknown_arguments() {
    let dir = tempfile::tempdir().unwrap();
    let cases: &[(&[&str], &str)] = &[
        (&["--deep", "--deep"], "duplicate --deep"),
        (
            &["--realm", REALM_HEX, "--realm", REALM_HEX],
            "duplicate --realm",
        ),
        (&[KEK_HEX, KEK_HEX], "multiple KEK"),
        (&["--unknown"], "unknown option"),
        (&["--realm"], "--realm requires"),
        (&["--realm", "--deep"], "--realm requires"),
    ];

    for (args, expected) in cases {
        let output = fsck().arg(dir.path()).args(*args).output().unwrap();
        assert_eq!(
            output.status.code(),
            Some(2),
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
    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("unknown option --deep"),
        "option used as path was not rejected: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
