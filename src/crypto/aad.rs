//! AAD (Associated Authenticated Data) builders for the page envelope.
//!
//! Layout for Format A data pages and Format C segment footers:
//!   `cipher_id` ‖ `page_kind` ‖ `mk_epoch` ‖ `page_id` ‖ `realm_id` ‖ `segment_id`
//!
//! Widths: 1 + 1 + 8 + 8 + 16 + 16 = 50 bytes.

use crate::RealmId;

/// Sentinel `page_kind` for the segment-footer manifest AEAD AAD. Falls in the
/// reserved range above the segment-data kinds (0x10..=0x12) and below any
/// future structural values.
pub const PAGE_KIND_SEGMENT_FOOTER: u8 = 0x20;

/// Sentinel `segment_id` for main.db pages (B+ tree, catalog, counter).
pub const MAIN_DB_SEGMENT_ID: [u8; 16] = [0u8; 16];

/// Fields that constitute one AAD value. Pass-by-value; cheap.
#[derive(Debug, Clone, Copy)]
pub struct AadFields {
    pub cipher_id: u8,
    pub page_kind: u8,
    pub mk_epoch: u64,
    pub page_id: u64,
    pub realm_id: RealmId,
    pub segment_id: [u8; 16],
}

/// Materialised AAD bytes ready to hand to an AEAD primitive.
#[derive(Debug, Clone)]
pub struct Aad(pub [u8; Aad::LEN]);

impl Aad {
    pub const LEN: usize = 1 + 1 + 8 + 8 + 16 + 16;

    #[must_use]
    pub fn from_fields(f: AadFields) -> Self {
        let mut out = [0u8; Self::LEN];
        let mut o = 0;
        out[o] = f.cipher_id;
        o += 1;
        out[o] = f.page_kind;
        o += 1;
        out[o..o + 8].copy_from_slice(&f.mk_epoch.to_le_bytes());
        o += 8;
        out[o..o + 8].copy_from_slice(&f.page_id.to_le_bytes());
        o += 8;
        out[o..o + 16].copy_from_slice(&f.realm_id.0);
        o += 16;
        out[o..o + 16].copy_from_slice(&f.segment_id);
        Self(out)
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aad_layout_widths() {
        let f = AadFields {
            cipher_id: 1,
            page_kind: 2,
            mk_epoch: 0x0102_0304_0506_0708,
            page_id: 0xAABB_CCDD_EEFF_0011,
            realm_id: RealmId([0x33; 16]),
            segment_id: [0x44; 16],
        };
        let aad = Aad::from_fields(f);
        assert_eq!(aad.0[0], 1);
        assert_eq!(aad.0[1], 2);
        // mk_epoch little-endian
        assert_eq!(&aad.0[2..10], &0x0102_0304_0506_0708u64.to_le_bytes());
        // page_id little-endian
        assert_eq!(&aad.0[10..18], &0xAABB_CCDD_EEFF_0011u64.to_le_bytes());
        assert_eq!(&aad.0[18..34], &[0x33; 16]);
        assert_eq!(&aad.0[34..50], &[0x44; 16]);
        assert_eq!(aad.0.len(), 50);
    }

    #[test]
    fn changing_any_field_changes_aad() {
        let base = AadFields {
            cipher_id: 1,
            page_kind: 2,
            mk_epoch: 5,
            page_id: 99,
            realm_id: RealmId([0; 16]),
            segment_id: [0; 16],
        };
        let a = Aad::from_fields(base).0;
        let mut variants: Vec<[u8; 50]> = Vec::new();
        for f in [
            AadFields {
                cipher_id: 2,
                ..base
            },
            AadFields {
                page_kind: 3,
                ..base
            },
            AadFields {
                mk_epoch: 6,
                ..base
            },
            AadFields {
                page_id: 100,
                ..base
            },
            AadFields {
                realm_id: RealmId([1; 16]),
                ..base
            },
            AadFields {
                segment_id: [1; 16],
                ..base
            },
        ] {
            variants.push(Aad::from_fields(f).0);
        }
        for v in variants {
            assert_ne!(a, v);
        }
    }
}
