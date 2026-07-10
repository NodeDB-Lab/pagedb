use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::Result;
use crate::crypto::aad::{Aad, AadFields, PAGE_KIND_SEGMENT_FOOTER};
use crate::crypto::keys::DerivedKey;
use crate::errors::PagedbError;

use super::fields::{FOOTER_HEADER_MAC_LEN, SegmentFooterFields};

type HmacSha256 = Hmac<Sha256>;

pub(super) fn mac_hk(hk: &DerivedKey, bytes: &[u8]) -> Result<[u8; FOOTER_HEADER_MAC_LEN]> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(hk.as_bytes())
        .map_err(|_| PagedbError::Io(std::io::Error::other("hk key length")))?;
    mac.update(bytes);
    let full = mac.finalize().into_bytes();
    let mut out = [0u8; FOOTER_HEADER_MAC_LEN];
    out.copy_from_slice(&full[..FOOTER_HEADER_MAC_LEN]);
    Ok(out)
}

pub(super) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc = 0u8;
    for (left, right) in a.iter().zip(b) {
        acc |= left ^ right;
    }
    acc == 0
}

pub(super) fn footer_aad(fields: &SegmentFooterFields) -> Aad {
    Aad::from_fields(AadFields {
        cipher_id: fields.cipher_id,
        page_kind: PAGE_KIND_SEGMENT_FOOTER,
        mk_epoch: fields.mk_epoch,
        page_id: 0,
        realm_id: fields.realm_id,
        segment_id: fields.segment_id,
    })
}
