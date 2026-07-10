use crate::RealmId;
use crate::crypto::Cipher;
use crate::crypto::kdf::{derive_dek, derive_hk, derive_mk};
use crate::crypto::nonce::Nonce;
use crate::errors::PagedbError;

use super::{
    FOOTER_CLEARTEXT_END, FOOTER_FIELDS_END, SegmentFooterFields, decode_segment_footer,
    encode_segment_footer, max_manifest_len,
};

const PAGE_SIZE: usize = 4096;

fn keys() -> (crate::crypto::keys::DerivedKey, Cipher) {
    let master = derive_mk(&[7; 32], &[0; 16], 0).unwrap();
    let header = derive_hk(&master).unwrap();
    let data = derive_dek(&master, RealmId([3; 16])).unwrap();
    (header, Cipher::new_aes_gcm(&data))
}

fn fields() -> SegmentFooterFields {
    SegmentFooterFields {
        format_version: 1,
        cipher_id: 1,
        segment_id: [9; 16],
        parent_file_id: [1; 16],
        realm_id: RealmId([3; 16]),
        mk_epoch: 0,
        page_count: 10,
        total_bytes: 40_960,
        final_counter: 9,
        index_start_page: 0,
        index_page_count: 0,
    }
}

#[test]
fn round_trip_preserves_manifest_and_authenticated_fields() {
    let (header, cipher) = keys();
    let expected = fields();
    let encoded =
        encode_segment_footer(&expected, b"manifest", &header, &cipher, PAGE_SIZE).unwrap();
    let (actual, manifest) = decode_segment_footer(&encoded, &header, &cipher, PAGE_SIZE).unwrap();
    assert_eq!(actual, expected);
    assert_eq!(manifest, b"manifest");
}

#[test]
fn rejects_manifest_larger_than_footer_payload() {
    let (header, cipher) = keys();
    let err = encode_segment_footer(
        &fields(),
        &vec![0; max_manifest_len(PAGE_SIZE) + 1],
        &header,
        &cipher,
        PAGE_SIZE,
    )
    .unwrap_err();
    assert!(matches!(err, PagedbError::ManifestTooLarge));
}

#[test]
fn rejects_footer_nonce_beyond_u48_counter_space() {
    let (header, cipher) = keys();
    let mut exhausted = fields();
    exhausted.final_counter = Nonce::COUNTER_MAX;
    assert!(matches!(
        encode_segment_footer(&exhausted, b"manifest", &header, &cipher, PAGE_SIZE),
        Err(PagedbError::NonceCounterExhausted)
    ));

    exhausted.final_counter = Nonce::COUNTER_MAX - 1;
    assert!(encode_segment_footer(&exhausted, b"manifest", &header, &cipher, PAGE_SIZE).is_ok());
}

#[test]
fn rejects_header_mac_and_manifest_tampering() {
    let (header, cipher) = keys();
    let mut encoded =
        encode_segment_footer(&fields(), b"manifest", &header, &cipher, PAGE_SIZE).unwrap();
    encoded[FOOTER_FIELDS_END] ^= 1;
    assert!(matches!(
        decode_segment_footer(&encoded, &header, &cipher, PAGE_SIZE),
        Err(PagedbError::Corruption(_))
    ));

    let mut encoded =
        encode_segment_footer(&fields(), b"manifest", &header, &cipher, PAGE_SIZE).unwrap();
    encoded[FOOTER_CLEARTEXT_END] ^= 1;
    assert!(matches!(
        decode_segment_footer(&encoded, &header, &cipher, PAGE_SIZE),
        Err(PagedbError::Corruption(_))
    ));
}
