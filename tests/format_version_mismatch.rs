//! Verifies that opening a database whose header carries an unrecognised
//! format_version field returns an error rather than silently misreading it.
//!
//! The test writes a minimal main.db, then directly patches the
//! format_version bytes in the VFS buffer to an unsupported version (99),
//! and confirms that the decoder returns `PagedbError::Unsupported`.

use pagedb::CommitId;
use pagedb::errors::PagedbError;
use pagedb::pager::format::structural_header::{
    MainDbHeaderFields, decode_main_db_header, encode_main_db_header,
};

use pagedb::crypto::kdf::{derive_hk, derive_mk};
use pagedb::crypto::keys::DerivedKey;

const PAGE: usize = 4096;

fn hk() -> DerivedKey {
    let mk = derive_mk(&[3u8; 32], &[0u8; 16], 0).unwrap();
    derive_hk(&mk).unwrap()
}

fn sample_header() -> MainDbHeaderFields {
    MainDbHeaderFields {
        format_version: 1,
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
    }
}

#[test]
fn unsupported_format_version_rejected_in_main_db_header() {
    let hk = hk();
    let fields = sample_header();

    // Encode a valid v1 header.
    let mut buf = encode_main_db_header(&fields, &hk, PAGE).unwrap();

    // Patch bytes 8..10 (format_version field, LE u16) to version 99.
    let v: u16 = 99;
    buf[8..10].copy_from_slice(&v.to_le_bytes());

    // Re-encode the MAC over the patched buffer so the MAC check passes
    // but the version check triggers. We need to recompute the MAC.
    // Since we patch the fields before MAC computation, re-encode with the
    // patched version using a modified MainDbHeaderFields.
    let mut fields_v99 = fields.clone();
    fields_v99.format_version = 99;
    let buf_v99 = encode_main_db_header(&fields_v99, &hk, PAGE).unwrap();

    let result = decode_main_db_header(&buf_v99, &hk, PAGE);
    assert!(
        matches!(result, Err(PagedbError::Unsupported)),
        "expected Unsupported for format_version=99, got: {result:?}"
    );
}

#[test]
fn valid_format_version_1_accepted() {
    let hk = hk();
    let fields = sample_header();
    let buf = encode_main_db_header(&fields, &hk, PAGE).unwrap();
    let decoded = decode_main_db_header(&buf, &hk, PAGE);
    assert!(decoded.is_ok(), "format_version=1 must be accepted");
}
