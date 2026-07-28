//! Verifies that opening a database whose header carries an unrecognised
//! format_version field returns an error rather than silently misreading it.
//!
//! The test writes a minimal main.db, then directly patches the
//! format_version bytes in the VFS buffer to an unsupported version (99),
//! and confirms that the decoder returns `PagedbError::Unsupported`.

use crate::CommitId;
use crate::RealmId;
use crate::errors::PagedbError;
use crate::pager::format::structural_header::{
    MAIN_FORMAT_VERSION, MainDbHeaderFields, decode_main_db_header, encode_main_db_header,
};

use crate::crypto::kdf::{derive_hk, derive_mk};
use crate::crypto::keys::DerivedKey;

const PAGE: usize = 4096;

fn hk() -> DerivedKey {
    let mk = derive_mk(&[3u8; 32], &[0u8; 16], 0).unwrap();
    derive_hk(&mk).unwrap()
}

fn sample_header() -> MainDbHeaderFields {
    MainDbHeaderFields {
        format_version: MAIN_FORMAT_VERSION,
        cipher_id: 1,
        page_size_log2: 12,
        flags: 0,
        file_id: [0xAB; 16],
        kek_salt: [0xCD; 16],
        mk_epoch: 0,
        seq: 1,
        active_root_page_id: 4,
        active_root_txn_id: 1,
        counter_anchor: 0,
        commit_id: CommitId::new(0),
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
        realm_id: RealmId::new([0x9E; 16]),
    }
}

#[test]
fn unsupported_format_version_rejected_in_main_db_header() {
    let hk = hk();
    let fields = sample_header();

    // Re-encode with the patched version rather than patching the buffer, so
    // the MAC still covers what it claims and the version check is what fires.
    let mut fields_v99 = fields.clone();
    fields_v99.format_version = 99;
    let buf_v99 = encode_main_db_header(&fields_v99, &hk, PAGE).unwrap();

    // Named as a version this build does not read, with both numbers, so the
    // operator knows a migration is the answer rather than a discard.
    let result = decode_main_db_header(&buf_v99, &hk, PAGE);
    assert!(
        matches!(
            result,
            Err(PagedbError::FormatVersionUnsupported {
                stored: 99,
                supported: MAIN_FORMAT_VERSION,
            })
        ),
        "expected a version verdict for format_version=99, got: {result:?}"
    );
}

#[test]
fn current_format_version_accepted() {
    let hk = hk();
    let fields = sample_header();
    let buf = encode_main_db_header(&fields, &hk, PAGE).unwrap();
    let decoded = decode_main_db_header(&buf, &hk, PAGE);
    assert!(
        decoded.is_ok(),
        "the current format_version must be accepted"
    );
}
