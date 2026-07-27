//! Generated adversarial input for the snapshot artifacts: the manifest and
//! the `pages.delta` record stream.
//!
//! A snapshot directory arrives from somewhere else. Its manifest is
//! HK-MAC'd, but the delta stream's per-record page ids are structural claims
//! that no MAC can make sensible — a record may name a reserved page, a page
//! beyond the target's allocation, or the same page twice. The delta path is
//! also the one that decides what lands in the follower's store, so these
//! properties assert both halves of the contract: never panic,
//! and never touch the live `main.db` — accepted or rejected, a delta stream
//! only ever reaches the staged image that the apply's rename commits.

use std::collections::BTreeSet;
use std::path::Path;

use crate::pager::page_space::is_reserved;
use crate::snapshot::apply::{plan_delta_stream, write_delta_into_image};
use crate::snapshot::export::{SnapshotManifest, decode_manifest, encode_manifest};
use crate::vfs::tokio_backend::TokioVfs;
use proptest::prelude::*;

/// Deliberately small: the delta path is byte-for-byte generic in page size,
/// and a 64-byte page keeps a few hundred generated streams cheap.
const DELTA_PAGE_SIZE: usize = 64;
const FOLLOWER_PAGE_COUNT: usize = 32;

fn cases() -> u32 {
    std::env::var("PAGEDB_PROPTEST_CASES")
        .ok()
        .and_then(|raw| raw.parse().ok())
        .unwrap_or(32)
}

fn config() -> ProptestConfig {
    ProptestConfig {
        cases: cases(),
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}

fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(future)
}

fn valid_manifest() -> SnapshotManifest {
    SnapshotManifest {
        version: 1,
        kind: 1,
        target_commit: 9,
        base_commit: 4,
        file_id: [0x11; 16],
        mk_epoch: 0,
        kek_salt: [0x22; 16],
        cipher_id: 1,
        page_size: 4096,
        next_page_id_at_target: 64,
        segments_count: 2,
        realm_id: [0x5A; 16],
        target_active_root_page_id: 8,
        target_catalog_root_page_id: 9,
    }
}

/// Lay out a follower `main.db` of known bytes so any write the delta path
/// performs is detectable.
fn write_follower_main_db(path: &Path) -> Vec<u8> {
    let contents = vec![0xEE_u8; FOLLOWER_PAGE_COUNT * DELTA_PAGE_SIZE];
    std::fs::write(path, &contents).unwrap();
    contents
}

/// Encode one `pages.delta` record: big-endian page id then a full page.
fn delta_record(page_id: u64, filler: u8) -> Vec<u8> {
    let mut record = page_id.to_be_bytes().to_vec();
    record.extend(std::iter::repeat_n(filler, DELTA_PAGE_SIZE));
    record
}

proptest! {
    #![proptest_config(config())]

    /// Wholly random manifest bytes. The MAC gate is first, so this mostly
    /// proves the framing checks in front of it cannot be walked past.
    #[test]
    fn random_bytes_never_panic_the_manifest_decoder(
        filler in prop::collection::vec(any::<u8>(), 0..=240),
        key in any::<[u8; 32]>(),
    ) {
        let mut buf = encode_manifest(&valid_manifest(), &[0u8; 32]);
        for (slot, byte) in buf.iter_mut().zip(filler.iter()) {
            *slot = *byte;
        }
        let _ = decode_manifest(&buf, &key);
    }

    /// A genuinely MAC'd manifest with bytes flipped: either the MAC catches
    /// the edit, or the edit landed in the MAC itself. Both must be an `Err`,
    /// never a decode of the tampered fields.
    #[test]
    fn perturbed_valid_manifest_is_never_accepted(
        edits in prop::collection::vec((any::<usize>(), any::<u8>()), 1..=8),
    ) {
        let key = [0x33_u8; 32];
        let manifest = valid_manifest();
        let encoded = encode_manifest(&manifest, &key);
        let decoded = decode_manifest(&encoded, &key).unwrap();
        prop_assert_eq!(decoded.target_commit, manifest.target_commit);

        let mut mutated = encoded;
        let mut changed = false;
        for (index, value) in edits {
            let at = index % mutated.len();
            changed |= mutated[at] != value;
            mutated[at] = value;
        }
        if changed {
            prop_assert!(
                decode_manifest(&mutated, &key).is_err(),
                "a tampered manifest must not authenticate"
            );
        }
    }

    /// A manifest authenticated under a different header key is a misrouted
    /// artifact, not a corrupt one — it must still be rejected.
    #[test]
    fn manifest_under_a_foreign_key_is_rejected(
        producer_key in any::<[u8; 32]>(),
        consumer_key in any::<[u8; 32]>(),
    ) {
        prop_assume!(producer_key != consumer_key);
        let encoded = encode_manifest(&valid_manifest(), &producer_key);
        prop_assert!(decode_manifest(&encoded, &consumer_key).is_err());
    }

    /// Wholly random `pages.delta` bytes, at lengths that straddle the record
    /// stride so the alignment check is reached from both sides.
    #[test]
    fn random_delta_bytes_never_panic_and_never_write(
        bytes in prop::collection::vec(any::<u8>(), 0..=(4 * (8 + DELTA_PAGE_SIZE) + 8)),
        // Bounded deliberately: an unbounded allocation ceiling would let an
        // accepted record claim a petabyte offset. The framing, alignment and
        // page-id checks under test are all reached well below this.
        target_next_page_id in 0u64..1024,
    ) {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("pages.delta"), &bytes).unwrap();
        let main_db = dir.path().join("main.db");
        let before = write_follower_main_db(&main_db);

        let _ = block_on(plan_delta_stream(
            dir.path(),
            DELTA_PAGE_SIZE,
            &BTreeSet::new(),
            target_next_page_id,
        ));

        // Planning is pure inspection: whatever it decided, nothing moved.
        let after = std::fs::read(&main_db).unwrap();
        prop_assert_eq!(after, before, "planning a delta stream must write nothing");
    }

    /// Structurally plausible streams: correctly framed records whose page ids
    /// are drawn from a pool that deliberately includes reserved pages, pages
    /// past the target allocation, and repeats.
    #[test]
    fn plausible_delta_records_never_panic_and_never_partially_write(
        page_ids in prop::collection::vec(
            prop_oneof![
                0u64..8,
                (FOLLOWER_PAGE_COUNT as u64 - 4)..(FOLLOWER_PAGE_COUNT as u64 + 4),
                Just(u64::MAX),
                Just(u64::MAX / 2),
            ],
            0..=6,
        ),
        target_next_page_id in 0u64..(FOLLOWER_PAGE_COUNT as u64 + 8),
        base_live in prop::collection::vec(0u64..16, 0..=3),
        filler in any::<u8>(),
    ) {
        let dir = tempfile::tempdir().unwrap();
        let mut stream = Vec::new();
        for &page_id in &page_ids {
            stream.extend_from_slice(&delta_record(page_id, filler));
        }
        std::fs::write(dir.path().join("pages.delta"), &stream).unwrap();
        let main_db = dir.path().join("main.db");
        let before = write_follower_main_db(&main_db);
        let base_live: BTreeSet<u64> = base_live.into_iter().collect();

        let outcome = block_on(plan_delta_stream(
            dir.path(),
            DELTA_PAGE_SIZE,
            &base_live,
            target_next_page_id,
        ));

        if let Ok(plan) = outcome {
            // Acceptance implies every record named a page the target both
            // allocated and does not reserve, and that no record claimed a page
            // the base commit is still reading through.
            prop_assert_eq!(plan.record_count as usize, page_ids.len());
            for page_id in &plan.page_ids {
                prop_assert!(!is_reserved(*page_id));
                prop_assert!(*page_id < target_next_page_id);
                prop_assert!(!base_live.contains(page_id));
            }

            // Writing an accepted plan still leaves the live file alone: every
            // record lands in the staged image the apply renames into place.
            let vfs = TokioVfs::new(dir.path());
            block_on(write_delta_into_image(
                &vfs,
                "/main.db.applying",
                dir.path(),
                DELTA_PAGE_SIZE,
                &plan,
            )).unwrap();
            let after = std::fs::read(&main_db).unwrap();
            prop_assert_eq!(after, before, "an applied delta must not touch main.db");

            if !plan.page_ids.is_empty() {
                let staged = std::fs::read(dir.path().join("main.db.applying")).unwrap();
                for page_id in &plan.page_ids {
                    let offset = usize::try_from(*page_id).unwrap() * DELTA_PAGE_SIZE;
                    prop_assert_eq!(
                        &staged[offset..offset + DELTA_PAGE_SIZE],
                        &vec![filler; DELTA_PAGE_SIZE][..],
                        "delta page {} must be present in the staged image",
                        page_id
                    );
                }
            }
        } else {
            let after = std::fs::read(&main_db).unwrap();
            prop_assert_eq!(
                after,
                before,
                "a rejected delta stream must leave main.db untouched"
            );
        }
    }
}
