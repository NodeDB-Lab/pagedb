//! Generated adversarial input for the three page envelopes and the page-kind
//! dispatch.
//!
//! Format A (data page), Format B (structural header) and Format C (segment
//! footer) all parse cleartext framing *before* anything is authenticated:
//! lengths, offsets, version tags, and the kind byte are read off disk and used
//! to slice the buffer. That prefix is exactly where a semantically impossible
//! but byte-legal page does its damage, and it is the part no hand-written
//! regression can enumerate. Every case here asserts the same contract: a typed
//! `PagedbError` or a value, never a panic.

use pagedb::CommitId;
use pagedb::RealmId;
use pagedb::crypto::aad::{AadFields, MAIN_DB_SEGMENT_ID};
use pagedb::crypto::kdf::{derive_dek, derive_hk, derive_mk};
use pagedb::crypto::{Aad, Cipher, CipherId, Nonce};
use pagedb::pager::PageKind;
use pagedb::pager::format::data_page::{
    ENVELOPE_OVERHEAD, body_mut, extract_page_header_ids, extract_page_kind, open_data_page,
    seal_data_page,
};
use pagedb::pager::format::segment_footer::{
    SegmentFooterFields, decode_segment_footer, encode_segment_footer,
};
use pagedb::pager::format::structural_header::{
    MainDbHeaderFields, SegmentHeaderFields, decode_main_db_header, decode_segment_header,
    encode_main_db_header, encode_segment_header,
};
use proptest::prelude::*;

const PAGE: usize = 4096;
const PAGE_SIZE_LOG2: u8 = 12;
const REALM: RealmId = RealmId::new([0x5A; 16]);

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

fn perturb(mut bytes: Vec<u8>, edits: &[(usize, u8)]) -> Vec<u8> {
    if bytes.is_empty() {
        return bytes;
    }
    for &(index, value) in edits {
        let at = index % bytes.len();
        bytes[at] = value;
    }
    bytes
}

fn master_key() -> pagedb::crypto::MasterKey {
    derive_mk(&[0x31; 32], &[0u8; 16], 0).unwrap()
}

fn data_page_cipher() -> Cipher {
    Cipher::new_aes_gcm(&derive_dek(&master_key(), REALM).unwrap())
}

fn data_page_aad(page_kind: PageKind, page_id: u64) -> Aad {
    Aad::from_fields(AadFields {
        cipher_id: CipherId::Aes256Gcm.as_byte(),
        page_kind: page_kind.as_byte(),
        mk_epoch: 0,
        page_id,
        realm_id: REALM,
        segment_id: MAIN_DB_SEGMENT_ID,
    })
}

fn sealed_data_page(page_kind: PageKind, page_id: u64, plaintext: &[u8]) -> Vec<u8> {
    let cipher = data_page_cipher();
    let aad = data_page_aad(page_kind, page_id);
    let nonce = Nonce::from_parts(&[0xC1; 6], 7);
    let mut page = vec![0u8; PAGE];
    let body = body_mut(&mut page);
    let take = plaintext.len().min(body.len());
    body[..take].copy_from_slice(&plaintext[..take]);
    seal_data_page(&mut page, page_kind, 0, 0, &nonce, &aad, &cipher).unwrap();
    page
}

fn main_db_fields() -> MainDbHeaderFields {
    MainDbHeaderFields {
        format_version: 1,
        cipher_id: CipherId::Aes256Gcm.as_byte(),
        page_size_log2: PAGE_SIZE_LOG2,
        flags: 0,
        file_id: [0x11; 16],
        kek_salt: [0x22; 16],
        mk_epoch: 0,
        seq: 3,
        active_root_page_id: 8,
        active_root_txn_id: 4,
        counter_anchor: 100,
        commit_id: CommitId::new(9),
        free_list_root: [0u8; 16],
        catalog_root: [0u8; 16],
        apply_journal_root_page_id: 0,
        apply_journal_root_version: 0,
        commit_history_root_page_id: 0,
        commit_history_root_version: 0,
        restore_mode: 0,
        next_page_id: 64,
        commit_retain_policy_tag: 0,
        commit_retain_policy_value: 8,
    }
}

fn segment_header_fields() -> SegmentHeaderFields {
    SegmentHeaderFields {
        format_version: 1,
        cipher_id: CipherId::Aes256Gcm.as_byte(),
        segment_kind: 0,
        segment_id: [0x77; 16],
        parent_file_id: [0x11; 16],
        realm_id: REALM,
        mk_epoch: 0,
        page_size_log2: PAGE_SIZE_LOG2,
        flags: 0,
    }
}

fn footer_fields(format_version: u16, page_count: u64, final_counter: u64) -> SegmentFooterFields {
    SegmentFooterFields {
        format_version,
        cipher_id: CipherId::Aes256Gcm.as_byte(),
        segment_id: [0x77; 16],
        parent_file_id: [0x11; 16],
        realm_id: REALM,
        mk_epoch: 0,
        page_count,
        total_bytes: page_count * PAGE as u64,
        final_counter,
        index_start_page: 1,
        index_page_count: if format_version == 2 { 1 } else { 0 },
    }
}

proptest! {
    #![proptest_config(config())]

    /// Every byte must classify as a kind or be rejected — no gap in the match
    /// can reach a slice index or an unreachable branch.
    #[test]
    fn page_kind_byte_dispatch_is_total(byte in any::<u8>()) {
        if let Ok(kind) = PageKind::from_byte(byte) {
            prop_assert_eq!(kind.as_byte(), byte);
            // The two contexts must stay disjoint: a kind legal in main.db
            // must never also be legal in a segment file, or a smuggled page
            // could pass the pre-AAD kind check in either direction.
            prop_assert!(kind.is_main_db() != kind.is_segment());
        }
    }

    /// Wholly random bytes at every length, including lengths below the
    /// envelope overhead where the header fields do not exist at all.
    #[test]
    fn random_bytes_never_panic_the_data_page_envelope(
        bytes in prop::collection::vec(any::<u8>(), 0..=(ENVELOPE_OVERHEAD * 2 + 64)),
    ) {
        let mut page = bytes;
        let cipher = data_page_cipher();
        let aad = data_page_aad(PageKind::BTreeLeaf, 5);
        let _ = extract_page_kind(&page);
        let _ = extract_page_header_ids(&page);
        let _ = open_data_page(&mut page, &aad, &cipher);
    }

    /// A genuinely sealed page with bytes flipped. Header, ciphertext and tag
    /// are all in range of the edits, so this covers a tampered kind byte, a
    /// tampered cipher id, and a torn body alike.
    #[test]
    fn perturbed_sealed_data_page_never_panics(
        plaintext in prop::collection::vec(any::<u8>(), 0..=512),
        page_id in any::<u64>(),
        edits in prop::collection::vec((any::<usize>(), any::<u8>()), 1..=16),
    ) {
        let page = sealed_data_page(PageKind::BTreeLeaf, page_id, &plaintext);
        let mut mutated = perturb(page, &edits);
        let cipher = data_page_cipher();
        let aad = data_page_aad(PageKind::BTreeLeaf, page_id);
        let _ = extract_page_kind(&mutated);
        let _ = extract_page_header_ids(&mutated);
        let _ = open_data_page(&mut mutated, &aad, &cipher);
    }

    /// The AAD is caller-supplied, so a misrouted read is a decoder input too:
    /// a page opened under a foreign page id, realm, or kind must fail
    /// authentication rather than produce plaintext.
    #[test]
    fn sealed_data_page_opened_under_foreign_aad_never_authenticates(
        plaintext in prop::collection::vec(any::<u8>(), 1..=256),
        sealed_page_id in any::<u64>(),
        foreign_page_id in any::<u64>(),
        foreign_realm in any::<[u8; 16]>(),
    ) {
        prop_assume!(sealed_page_id != foreign_page_id || foreign_realm != *REALM.as_bytes());
        let mut page = sealed_data_page(PageKind::BTreeLeaf, sealed_page_id, &plaintext);
        let cipher = data_page_cipher();
        let foreign = Aad::from_fields(AadFields {
            cipher_id: CipherId::Aes256Gcm.as_byte(),
            page_kind: PageKind::BTreeLeaf.as_byte(),
            mk_epoch: 0,
            page_id: foreign_page_id,
            realm_id: RealmId::new(foreign_realm),
            segment_id: MAIN_DB_SEGMENT_ID,
        });
        prop_assert!(open_data_page(&mut page, &foreign, &cipher).is_err());
    }

    /// Random bytes as a main.db A/B header, at page sizes that straddle the
    /// `MAIN_FIELDS_END + MAC_LEN` guard. `page_size` tracks the buffer length
    /// so the guard, not the buffer, is what has to hold.
    #[test]
    fn random_bytes_never_panic_the_main_db_header(
        bytes in prop::collection::vec(any::<u8>(), 0..=320),
    ) {
        let hk = derive_hk(&master_key()).unwrap();
        let page_size = bytes.len();
        let _ = decode_main_db_header(&bytes, &hk, page_size);
        // A declared page size that disagrees with the buffer must be rejected
        // by length, never by reading past the end.
        let _ = decode_main_db_header(&bytes, &hk, PAGE);
    }

    #[test]
    fn perturbed_valid_main_db_header_never_panics(
        edits in prop::collection::vec((any::<usize>(), any::<u8>()), 1..=12),
        declared_page_size in prop::sample::select(vec![0usize, 1, 200, 201, PAGE, PAGE * 2]),
    ) {
        let hk = derive_hk(&master_key()).unwrap();
        let encoded = encode_main_db_header(&main_db_fields(), &hk, PAGE).unwrap();
        let mutated = perturb(encoded, &edits);
        let _ = decode_main_db_header(&mutated, &hk, PAGE);
        let _ = decode_main_db_header(&mutated, &hk, declared_page_size);
    }

    #[test]
    fn random_bytes_never_panic_the_segment_header(
        bytes in prop::collection::vec(any::<u8>(), 0..=200),
    ) {
        let hk = derive_hk(&master_key()).unwrap();
        let page_size = bytes.len();
        let _ = decode_segment_header(&bytes, &hk, page_size);
        let _ = decode_segment_header(&bytes, &hk, PAGE);
    }

    #[test]
    fn perturbed_valid_segment_header_never_panics(
        edits in prop::collection::vec((any::<usize>(), any::<u8>()), 1..=12),
        declared_page_size in prop::sample::select(vec![0usize, 1, 91, 92, PAGE, PAGE * 2]),
    ) {
        let hk = derive_hk(&master_key()).unwrap();
        let encoded = encode_segment_header(&segment_header_fields(), &hk, PAGE).unwrap();
        let mutated = perturb(encoded, &edits);
        let _ = decode_segment_header(&mutated, &hk, PAGE);
        let _ = decode_segment_header(&mutated, &hk, declared_page_size);
    }

    /// The footer's cleartext prefix carries a version tag plus a manifest
    /// offset and length that select the ciphertext extent. Random bytes drive
    /// that selection directly.
    #[test]
    fn random_bytes_never_panic_the_segment_footer(
        bytes in prop::collection::vec(any::<u8>(), 0..=400),
    ) {
        let hk = derive_hk(&master_key()).unwrap();
        let cipher = data_page_cipher();
        let page_size = bytes.len();
        let _ = decode_segment_footer(&bytes, &hk, &cipher, page_size);
        let _ = decode_segment_footer(&bytes, &hk, &cipher, PAGE);
    }

    /// Random bytes behind a valid magic and version tag: without pinning
    /// those two the generator almost never reaches the length fields.
    #[test]
    fn random_footer_body_under_valid_framing_never_panics(
        format_version in prop::sample::select(vec![0u16, 1, 2, 3, u16::MAX]),
        tail in prop::collection::vec(any::<u8>(), 0..=PAGE),
    ) {
        let hk = derive_hk(&master_key()).unwrap();
        let cipher = data_page_cipher();
        let mut bytes = vec![0u8; PAGE];
        bytes[..8].copy_from_slice(b"PAGESEAL");
        bytes[8..10].copy_from_slice(&format_version.to_le_bytes());
        let take = tail.len().min(PAGE - 10);
        bytes[10..10 + take].copy_from_slice(&tail[..take]);
        let _ = decode_segment_footer(&bytes, &hk, &cipher, PAGE);
    }

    #[test]
    fn perturbed_valid_segment_footer_never_panics(
        format_version in prop::sample::select(vec![1u16, 2]),
        page_count in 1u64..64,
        final_counter in 0u64..(1 << 40),
        manifest in prop::collection::vec(any::<u8>(), 0..=256),
        edits in prop::collection::vec((any::<usize>(), any::<u8>()), 1..=16),
    ) {
        let hk = derive_hk(&master_key()).unwrap();
        let cipher = data_page_cipher();
        let fields = footer_fields(format_version, page_count, final_counter);
        let Ok(encoded) = encode_segment_footer(&fields, &manifest, &hk, &cipher, PAGE) else {
            return Ok(());
        };
        let mutated = perturb(encoded, &edits);
        let _ = decode_segment_footer(&mutated, &hk, &cipher, PAGE);
    }
}
