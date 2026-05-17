//! Overflow page encode / decode and chain management.
//!
//! Overflow pages form a singly-linked chain: each page body carries a `next`
//! pointer (page id, 0 = end of chain) followed by raw data bytes. Chain pages
//! (not the root) always use `PageKind::Overflow`.
//!
//! ## v1 root layout (`PageKind::Overflow`)
//! `next[8] || data_len[4] || data[...]`
//!
//! ## v2 root layout (`PageKind::OverflowRoot`)
//! `refcount[4] || next[8] || data_len[4] || data[...]`
//!
//! v2 root pages carry a `refcount: u32` enabling shared overflow chains.
//! `increment_ref` CoW-copies the root with `refcount + 1`.
//! `release` CoW-copies the root with `refcount - 1`; if it reaches 0 the
//! entire chain is freed. Chain pages (not the root) continue to use
//! `PageKind::Overflow` and `OVERFLOW_HEADER_LEN`.

use crate::errors::PagedbError;
use crate::pager::Pager;
use crate::pager::format::data_page::ENVELOPE_OVERHEAD;
use crate::pager::format::page_kind::PageKind;
use crate::vfs::Vfs;
use crate::{RealmId, Result};

/// Header length for chain pages (non-root): `next[8] || data_len[4]`.
pub const OVERFLOW_HEADER_LEN: usize = 12;

/// Extra bytes at the start of a v2 root body before the standard header:
/// `refcount[4]`.
const OVERFLOW_ROOT_V2_PREFIX: usize = 4;

/// Header length for a v2 root page:
/// `refcount[4] || next[8] || data_len[4]`.
pub const OVERFLOW_ROOT_HEADER_LEN: usize = OVERFLOW_ROOT_V2_PREFIX + OVERFLOW_HEADER_LEN;

#[must_use]
pub fn overflow_page_capacity(page_size: usize) -> usize {
    page_size - ENVELOPE_OVERHEAD - OVERFLOW_HEADER_LEN
}

/// Capacity of a v2 root page body (4 bytes smaller than a chain page).
#[must_use]
pub fn overflow_root_capacity(page_size: usize) -> usize {
    page_size - ENVELOPE_OVERHEAD - OVERFLOW_ROOT_HEADER_LEN
}

/// Encode a single overflow chain page body (non-root, `PageKind::Overflow`).
/// `data.len()` must be ≤ `overflow_page_capacity(page_size)`.
pub fn encode_overflow(body: &mut [u8], next: u64, data: &[u8]) -> Result<()> {
    let page_size = body.len() + ENVELOPE_OVERHEAD;
    let cap = overflow_page_capacity(page_size);
    if data.len() > cap {
        return Err(PagedbError::PayloadTooLarge);
    }
    for b in body.iter_mut() {
        *b = 0;
    }
    body[0..8].copy_from_slice(&next.to_le_bytes());
    let data_len = u32::try_from(data.len())
        .map_err(|_| PagedbError::Io(std::io::Error::other("overflow data_len overflow")))?;
    body[8..12].copy_from_slice(&data_len.to_le_bytes());
    body[12..12 + data.len()].copy_from_slice(data);
    Ok(())
}

/// Decode an overflow chain page body (non-root). Returns `(next, data_slice)`.
pub fn decode_overflow(body: &[u8]) -> Result<(u64, &[u8])> {
    if body.len() < OVERFLOW_HEADER_LEN {
        return Err(PagedbError::corruption(
            crate::errors::CorruptionDetail::HeaderUnverifiable,
        ));
    }
    let mut n = [0u8; 8];
    n.copy_from_slice(&body[0..8]);
    let next = u64::from_le_bytes(n);
    let mut l = [0u8; 4];
    l.copy_from_slice(&body[8..12]);
    let data_len = u32::from_le_bytes(l) as usize;
    if 12 + data_len > body.len() {
        return Err(PagedbError::corruption(
            crate::errors::CorruptionDetail::HeaderUnverifiable,
        ));
    }
    Ok((next, &body[12..12 + data_len]))
}

/// Encode a v2 overflow root page body (`PageKind::OverflowRoot`).
/// `data.len()` must be ≤ `overflow_root_capacity(page_size)`.
fn encode_overflow_root_v2(body: &mut [u8], refcount: u32, next: u64, data: &[u8]) -> Result<()> {
    let page_size = body.len() + ENVELOPE_OVERHEAD;
    let cap = overflow_root_capacity(page_size);
    if data.len() > cap {
        return Err(PagedbError::PayloadTooLarge);
    }
    for b in body.iter_mut() {
        *b = 0;
    }
    body[0..4].copy_from_slice(&refcount.to_le_bytes());
    body[4..12].copy_from_slice(&next.to_le_bytes());
    let data_len = u32::try_from(data.len())
        .map_err(|_| PagedbError::Io(std::io::Error::other("overflow root data_len overflow")))?;
    body[12..16].copy_from_slice(&data_len.to_le_bytes());
    body[16..16 + data.len()].copy_from_slice(data);
    Ok(())
}

/// Decode a v2 overflow root page body. Returns `(refcount, next, data_slice)`.
fn decode_overflow_root_v2(body: &[u8]) -> Result<(u32, u64, &[u8])> {
    if body.len() < OVERFLOW_ROOT_HEADER_LEN {
        return Err(PagedbError::corruption(
            crate::errors::CorruptionDetail::HeaderUnverifiable,
        ));
    }
    let mut r = [0u8; 4];
    r.copy_from_slice(&body[0..4]);
    let refcount = u32::from_le_bytes(r);
    let mut n = [0u8; 8];
    n.copy_from_slice(&body[4..12]);
    let next = u64::from_le_bytes(n);
    let mut l = [0u8; 4];
    l.copy_from_slice(&body[12..16]);
    let data_len = u32::from_le_bytes(l) as usize;
    if 16 + data_len > body.len() {
        return Err(PagedbError::corruption(
            crate::errors::CorruptionDetail::HeaderUnverifiable,
        ));
    }
    Ok((refcount, next, &body[16..16 + data_len]))
}

/// Decoded contents of an overflow root page (v1 or v2).
pub struct RootPageInfo {
    /// Reference count. Always 1 for v1 roots (treated as single-owner).
    pub refcount: u32,
    /// `next` page id in the chain (0 = end).
    pub next: u64,
    /// Data bytes stored in the root page.
    pub root_data: Vec<u8>,
    /// True iff this is a v2 root (`PageKind::OverflowRoot`).
    pub is_v2: bool,
}

/// Read the root page of an overflow chain. Tries `OverflowRoot` (v2) first,
/// falls back to `Overflow` (v1). v1 roots are reported with `refcount = 1`.
pub async fn read_root_page<V: Vfs>(
    pager: &Pager<V>,
    realm_id: RealmId,
    root_page_id: u64,
) -> Result<RootPageInfo> {
    // Try v2 first.
    if let Ok(guard) = pager
        .read_main_page(root_page_id, realm_id, PageKind::OverflowRoot)
        .await
    {
        let body = guard.body();
        let (refcount, next, data) = decode_overflow_root_v2(&body)?;
        return Ok(RootPageInfo {
            refcount,
            next,
            root_data: data.to_vec(),
            is_v2: true,
        });
    }
    // Fall back to v1: treat as refcount=1.
    let guard = pager
        .read_main_page(root_page_id, realm_id, PageKind::Overflow)
        .await?;
    let body = guard.body();
    let (next, data) = decode_overflow(&body)?;
    Ok(RootPageInfo {
        refcount: 1,
        next,
        root_data: data.to_vec(),
        is_v2: false,
    })
}

/// Write a value's overflow chain via the Pager. The root page is written as
/// `PageKind::OverflowRoot` (v2) with `refcount = 1`; chain pages use
/// `PageKind::Overflow`. Returns the root page's `page_id`.
pub async fn write_chain<V: Vfs>(
    pager: &Pager<V>,
    realm_id: RealmId,
    value: &[u8],
    page_size: usize,
    allocate_page: &mut dyn FnMut() -> u64,
) -> Result<u64> {
    let root_cap = overflow_root_capacity(page_size);
    let chain_cap = overflow_page_capacity(page_size);

    // Collect chunk boundaries. The first chunk goes into the root page
    // (smaller capacity); subsequent chunks go into chain pages.
    let mut offsets: Vec<usize> = Vec::new();
    let mut o = 0usize;
    loop {
        offsets.push(o);
        let cap = if offsets.len() == 1 {
            root_cap
        } else {
            chain_cap
        };
        o += cap;
        if o >= value.len() {
            break;
        }
    }
    // Always have at least one page (root), even for zero-byte values.

    let page_ids: Vec<u64> = offsets.iter().map(|_| allocate_page()).collect();

    for (i, &start) in offsets.iter().enumerate() {
        let is_root = i == 0;
        let cap = if is_root { root_cap } else { chain_cap };
        let end = (start + cap).min(value.len());
        let next = if i + 1 < page_ids.len() {
            page_ids[i + 1]
        } else {
            0
        };
        let chunk = &value[start..end];
        let mut body = vec![0u8; page_size - ENVELOPE_OVERHEAD];
        if is_root {
            encode_overflow_root_v2(&mut body, 1, next, chunk)?;
            pager
                .write_main_page(page_ids[i], realm_id, PageKind::OverflowRoot, &body)
                .await?;
        } else {
            encode_overflow(&mut body, next, chunk)?;
            pager
                .write_main_page(page_ids[i], realm_id, PageKind::Overflow, &body)
                .await?;
        }
    }
    Ok(page_ids[0])
}

/// Increment the reference count of an overflow root page. Writes a new `CoW`
/// copy of the root at `new_page_id` with `refcount + 1`. The caller is
/// responsible for allocating `new_page_id` and freeing the old root page when
/// appropriate.
///
/// Returns the new root page id (`new_page_id`).
pub async fn increment_ref<V: Vfs>(
    pager: &Pager<V>,
    realm_id: RealmId,
    root_page_id: u64,
    new_page_id: u64,
) -> Result<u64> {
    let page_size = pager.page_size();
    let info = read_root_page(pager, realm_id, root_page_id).await?;
    let new_refcount = info
        .refcount
        .checked_add(1)
        .ok_or_else(|| PagedbError::Io(std::io::Error::other("overflow refcount overflow")))?;
    let mut body = vec![0u8; page_size - ENVELOPE_OVERHEAD];
    encode_overflow_root_v2(&mut body, new_refcount, info.next, &info.root_data)?;
    pager
        .write_main_page(new_page_id, realm_id, PageKind::OverflowRoot, &body)
        .await?;
    Ok(new_page_id)
}

/// The result of a `release` call.
pub enum ReleaseResult {
    /// Refcount decremented; new root page written at `new_root_page_id`.
    /// The caller must free `old_root_page_id`.
    Decremented { new_root_page_id: u64 },
    /// Refcount reached 0; all chain pages are listed in `freed_pages`
    /// (including the original root). The caller must free them all.
    Freed { freed_pages: Vec<u64> },
}

/// Decrement the reference count of an overflow root page (`CoW`).
///
/// - If `refcount > 1`: writes new root at `new_page_id` with `refcount - 1`
///   and returns `ReleaseResult::Decremented`. The caller must free the old
///   root page.
/// - If `refcount == 1`: collects all chain page ids and returns
///   `ReleaseResult::Freed`. The caller must free them all.
///   `new_page_id` is unused in this case.
pub async fn release<V: Vfs>(
    pager: &Pager<V>,
    realm_id: RealmId,
    root_page_id: u64,
    new_page_id: u64,
) -> Result<ReleaseResult> {
    let page_size = pager.page_size();
    let info = read_root_page(pager, realm_id, root_page_id).await?;

    if info.refcount <= 1 {
        // Collect entire chain.
        let mut freed = vec![root_page_id];
        let mut cur = info.next;
        while cur != 0 {
            let guard = pager
                .read_main_page(cur, realm_id, PageKind::Overflow)
                .await?;
            let body = guard.body();
            let (n, _) = decode_overflow(&body)?;
            freed.push(cur);
            cur = n;
        }
        return Ok(ReleaseResult::Freed { freed_pages: freed });
    }

    let new_refcount = info.refcount - 1;
    let mut body = vec![0u8; page_size - ENVELOPE_OVERHEAD];
    encode_overflow_root_v2(&mut body, new_refcount, info.next, &info.root_data)?;
    pager
        .write_main_page(new_page_id, realm_id, PageKind::OverflowRoot, &body)
        .await?;
    Ok(ReleaseResult::Decremented {
        new_root_page_id: new_page_id,
    })
}

/// Read a value's overflow chain via the Pager. Follows `next` pointers until
/// 0. Handles both v1 (`PageKind::Overflow` root) and v2
/// (`PageKind::OverflowRoot` root) transparently.
pub async fn read_chain<V: Vfs>(
    pager: &Pager<V>,
    realm_id: RealmId,
    root_page_id: u64,
    total_len: u64,
) -> Result<Vec<u8>> {
    let mut out: Vec<u8> = Vec::with_capacity(usize::try_from(total_len).unwrap_or(0));

    let info = read_root_page(pager, realm_id, root_page_id).await?;
    out.extend_from_slice(&info.root_data);

    let mut next = info.next;
    while next != 0 {
        let guard = pager
            .read_main_page(next, realm_id, PageKind::Overflow)
            .await?;
        let body = guard.body();
        let (n, data) = decode_overflow(&body)?;
        out.extend_from_slice(data);
        next = n;
    }
    if out.len() as u64 != total_len {
        return Err(PagedbError::corruption(
            crate::errors::CorruptionDetail::HeaderUnverifiable,
        ));
    }
    Ok(out)
}

/// Collect every `page_id` in an overflow chain. Does not modify any pages.
/// Handles v1 and v2 roots. Used when refcount tracking is handled externally.
pub async fn collect_chain<V: Vfs>(
    pager: &Pager<V>,
    realm_id: RealmId,
    root_page_id: u64,
) -> Result<Vec<u64>> {
    let mut out = vec![root_page_id];
    let info = read_root_page(pager, realm_id, root_page_id).await?;
    let mut next = info.next;
    while next != 0 {
        let guard = pager
            .read_main_page(next, realm_id, PageKind::Overflow)
            .await?;
        let body = guard.body();
        let (n, _) = decode_overflow(&body)?;
        out.push(next);
        next = n;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_chain_page() {
        let mut body = vec![0u8; 4096 - ENVELOPE_OVERHEAD];
        encode_overflow(&mut body, 7, b"hello").unwrap();
        let (n, d) = decode_overflow(&body).unwrap();
        assert_eq!(n, 7);
        assert_eq!(d, b"hello");
    }

    #[test]
    fn round_trip_root_v2() {
        let mut body = vec![0u8; 4096 - ENVELOPE_OVERHEAD];
        encode_overflow_root_v2(&mut body, 3, 99, b"world").unwrap();
        let (rc, n, d) = decode_overflow_root_v2(&body).unwrap();
        assert_eq!(rc, 3);
        assert_eq!(n, 99);
        assert_eq!(d, b"world");
    }

    #[test]
    fn capacity_4k_page() {
        // chain: 4096 - 40 - 12 = 4044
        assert_eq!(overflow_page_capacity(4096), 4044);
        // root v2: 4096 - 40 - 16 = 4040
        assert_eq!(overflow_root_capacity(4096), 4040);
    }
}
