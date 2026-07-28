//! Cleartext classification of a `main.db` header before any key is trusted.
//!
//! Three open failures are indistinguishable from damage once you are down to
//! "the MAC did not verify", and none of them means the store is damaged: the
//! caller supplied the wrong page size, the wrong KEK, or the store is at a
//! format version this build does not read. Told instead that the store is
//! corrupt, an operator may discard a database that a correct parameter — or a
//! migration — would have opened. So all three are decided here, from framing
//! no key protects, and reported as themselves.
//!
//! Everything in this module reads unauthenticated bytes, so it may only ever
//! *refuse* an open or *classify* one that already failed. Nothing here can
//! admit a store; that stays with the HK-MAC.

use crate::Result;
use crate::errors::PagedbError;
use crate::pager::format::structural_header::{
    MAC_LEN, MAGIC_MAIN, MAIN_FIELDS_END, MAIN_FORMAT_VERSION,
};

/// A slot's cleartext `page_size_log2`, if the slot is recognisably ours.
///
/// The magic check is what makes the byte worth acting on. Reading a
/// wrong-sized slot still lands the first 12 bytes on the real header's first
/// 12 bytes whichever direction the mismatch runs — a too-small read is a
/// prefix of slot A, a too-large read starts at slot A — so the field is
/// legible in exactly the case it is needed.
fn declared_page_size(slot: &[u8]) -> Option<usize> {
    if slot.len() < 12 || slot[..8] != MAGIC_MAIN {
        return None;
    }
    match slot[11] {
        log2 @ 12..=16 => Some(1usize << log2),
        _ => None,
    }
}

/// Refuse an open whose `page_size` disagrees with what the store records.
///
/// Runs before any derivation: a wrong page size also makes every later check
/// meaningless, since the slot boundaries, the MAC extent, and slot B's offset
/// are all computed from it.
pub(crate) fn check_page_size(slot_a: &[u8], slot_b: &[u8], supplied: usize) -> Result<()> {
    let Some(stored) = declared_page_size(slot_a).or_else(|| declared_page_size(slot_b)) else {
        return Ok(());
    };
    if stored == supplied {
        return Ok(());
    }
    Err(PagedbError::PageSizeMismatch { stored, supplied })
}

/// A slot's cleartext `format_version`, if the slot is recognisably ours.
fn declared_format_version(slot: &[u8]) -> Option<u16> {
    if slot.len() < 10 || slot[..8] != MAGIC_MAIN {
        return None;
    }
    Some(u16::from_le_bytes([slot[8], slot[9]]))
}

/// Refuse an open whose on-disk format version this build does not read.
///
/// This has to run *before* the MAC check, not after it. A store from another
/// format version has an intact magic and an intact frame, so once both slots
/// have merely "failed to verify" it is indistinguishable from a wrong key —
/// and `KeyMismatch` is the wrong thing to tell someone whose store needs
/// migrating. The version is cleartext, so the question is answerable before
/// any key is derived.
pub(crate) fn check_format_version(slot_a: &[u8], slot_b: &[u8]) -> Result<()> {
    let Some(stored) = declared_format_version(slot_a).or_else(|| declared_format_version(slot_b))
    else {
        return Ok(());
    };
    if stored == MAIN_FORMAT_VERSION {
        return Ok(());
    }
    Err(PagedbError::FormatVersionUnsupported {
        stored,
        supported: MAIN_FORMAT_VERSION,
    })
}

/// Classify a store whose every header slot failed to verify.
///
/// A slot still carrying the pagedb magic and a well-formed frame is a pagedb
/// header the supplied key did not open — recoverable, and it must not read as
/// damage. A slot that is not is genuinely unusable. Reporting
/// [`PagedbError::KeyMismatch`] whenever *either* slot still looks like ours is
/// the deliberately conservative direction: naming damage as a key problem
/// costs a retry, while naming a key problem as damage costs a database.
pub(crate) fn unverifiable_header_cause(
    slot_a: &[u8],
    slot_b: &[u8],
    page_size: usize,
) -> PagedbError {
    let framed = |slot: &[u8]| -> bool {
        slot.len() == page_size
            && slot[..8] == MAGIC_MAIN
            && slot[161..168].iter().all(|byte| *byte == 0)
            && slot[MAIN_FIELDS_END..page_size - MAC_LEN]
                .iter()
                .all(|byte| *byte == 0)
    };
    if page_size > MAIN_FIELDS_END + MAC_LEN && (framed(slot_a) || framed(slot_b)) {
        PagedbError::KeyMismatch
    } else {
        PagedbError::corruption(crate::errors::CorruptionDetail::HeaderUnverifiable)
    }
}
