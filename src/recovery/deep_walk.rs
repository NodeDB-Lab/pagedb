//! Deep-walk integrity check for `pagedb-fsck --deep`.
//!
//! Walks every page in `main.db` and every segment file, verifying AEAD tags,
//! structural invariants, and catalog–disk consistency. Returns a structured
//! `DeepWalkReport` rather than printing directly so callers can choose output
//! format.

use std::collections::BTreeSet;

use crate::Result;
use crate::btree::BTree;
use crate::catalog::codec::{Catalog, SegmentMeta};
use crate::crypto::aad::{Aad, AadFields, MAIN_DB_SEGMENT_ID};
use crate::pager::Pager;
use crate::pager::format::data_page::extract_page_header_ids;
use crate::pager::format::page_kind::PageKind;
use crate::segment::authenticated_metadata::authenticate_segment_metadata;
use crate::txn::db::Db;
use crate::vfs::types::OpenMode;
use crate::vfs::{Vfs, VfsFile};

/// A single page-level issue found during deep walk.
#[derive(Debug, Clone)]
pub struct PageIssue {
    pub page_id: u64,
    pub description: String,
}

/// An issue found in a segment file during deep walk.
#[derive(Debug, Clone)]
pub struct SegmentIssue {
    pub segment_id: [u8; 16],
    pub description: String,
}

/// A catalog-vs-disk discrepancy.
#[derive(Debug, Clone)]
pub struct DriftIssue {
    pub segment_id: [u8; 16],
    pub description: String,
}

/// Full report produced by [`run_deep_walk`].
#[derive(Debug, Default)]
pub struct DeepWalkReport {
    /// Pages whose AEAD verification failed or whose structure is invalid.
    pub page_issues: Vec<PageIssue>,
    /// Segment-level issues (bad footer MAC, unreadable pages inside a segment).
    pub segment_issues: Vec<SegmentIssue>,
    /// Pages with valid AEAD but unreachable from any live tree root.
    pub orphan_page_ids: Vec<u64>,
    /// Catalog rows that reference segments missing from disk, or where
    /// the on-disk file size disagrees with the catalog record.
    pub drift_issues: Vec<DriftIssue>,
    /// Total pages examined in main.db.
    pub pages_examined: u64,
    /// Total segment files examined.
    pub segments_examined: u64,
}

impl DeepWalkReport {
    /// `true` iff no integrity issues were found.
    ///
    /// Orphan pages (pages with valid AEAD but unreachable from any live root)
    /// are **informational** and do not affect cleanliness — they are expected
    /// for deferred-free pages awaiting GC.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.page_issues.is_empty()
            && self.segment_issues.is_empty()
            && self.drift_issues.is_empty()
    }

    /// Write a human-readable text report to `out`.
    pub fn write_text(&self, out: &mut impl std::io::Write) -> std::io::Result<()> {
        writeln!(out, "=== pagedb deep-walk report ===")?;
        writeln!(out, "pages_examined    : {}", self.pages_examined)?;
        writeln!(out, "segments_examined : {}", self.segments_examined)?;
        writeln!(out)?;

        writeln!(
            out,
            "--- structural / AEAD issues ({}) ---",
            self.page_issues.len()
        )?;
        for issue in &self.page_issues {
            writeln!(out, "  page {:>6}: {}", issue.page_id, issue.description)?;
        }
        writeln!(out)?;

        writeln!(
            out,
            "--- segment issues ({}) ---",
            self.segment_issues.len()
        )?;
        for issue in &self.segment_issues {
            writeln!(
                out,
                "  seg {}: {}",
                crate::hex::to_hex_lower(&issue.segment_id),
                issue.description
            )?;
        }
        writeln!(out)?;

        writeln!(out, "--- orphan pages ({}) ---", self.orphan_page_ids.len())?;
        let sample: Vec<_> = self.orphan_page_ids.iter().take(20).collect();
        for pid in &sample {
            writeln!(out, "  page {pid}")?;
        }
        if self.orphan_page_ids.len() > 20 {
            writeln!(out, "  ... and {} more", self.orphan_page_ids.len() - 20)?;
        }
        writeln!(out)?;

        writeln!(
            out,
            "--- catalog-disk drift ({}) ---",
            self.drift_issues.len()
        )?;
        for issue in &self.drift_issues {
            writeln!(
                out,
                "  seg {}: {}",
                crate::hex::to_hex_lower(&issue.segment_id),
                issue.description
            )?;
        }
        writeln!(out)?;

        if self.is_clean() {
            writeln!(out, "result: CLEAN")?;
        } else {
            writeln!(out, "result: ISSUES FOUND")?;
        }
        Ok(())
    }
}

/// Run a deep walk against an already-opened `Db<V>`.
///
/// The `Db` must be open in any mode. The walk reads from the VFS directly
/// rather than going through the B+ tree API so it can examine every physical
/// page including free, spill, and unreferenced pages.
#[allow(clippy::too_many_lines)]
pub async fn run_deep_walk<V: Vfs + Clone>(db: &Db<V>) -> Result<DeepWalkReport> {
    db.ensure_usable()?;
    let mut report = DeepWalkReport::default();

    let (next_page_id, catalog_root, catalog_next, free_list_root) = {
        let state = db.writer.lock().await;
        (
            state.next_page_id,
            state.catalog_root_page_id,
            state.next_page_id,
            state.free_list_root_page_id,
        )
    };

    // ------------------------------------------------------------------ //
    // 1. Walk every page in main.db from page 0 to next_page_id.
    // ------------------------------------------------------------------ //
    let page_size = db.page_size;
    let main_db_path = &db.main_db_path;
    let realm_id = db.realm_id;

    // Collect the set of page IDs reachable from all live roots.
    let mut reachable = collect_reachable_pages(db).await;

    // Walk and validate the durable free-list chain. Reading it verifies each
    // chain page's AEAD; a corrupt chain surfaces as a page issue. Validate the
    // entries (in range, unique, and not also live), then account the chain's
    // own pages and the free pages it tracks so they are not reported as
    // orphans — they are legitimately owned by the free-list, not stray.
    match crate::pager::freelist::read_chain(&db.pager, realm_id, free_list_root).await {
        Ok((free_entries, chain_pages)) => {
            let mut seen: BTreeSet<u64> = BTreeSet::new();
            for &(_cid, pid) in &free_entries {
                if pid >= next_page_id {
                    report.page_issues.push(PageIssue {
                        page_id: pid,
                        description: "free-list entry references a page past next_page_id"
                            .to_string(),
                    });
                } else if reachable.contains(&pid) {
                    report.page_issues.push(PageIssue {
                        page_id: pid,
                        description: "page is both live (reachable from a root) and free-listed"
                            .to_string(),
                    });
                }
                if !seen.insert(pid) {
                    report.page_issues.push(PageIssue {
                        page_id: pid,
                        description: "duplicate free-list entry".to_string(),
                    });
                }
            }
            for p in chain_pages {
                reachable.insert(p);
            }
            for (_cid, pid) in free_entries {
                reachable.insert(pid);
            }
        }
        Err(e) => {
            report.page_issues.push(PageIssue {
                page_id: free_list_root,
                description: format!("free-list chain unreadable: {e}"),
            });
        }
    }

    let vfs: &V = &db.vfs;
    let main_file_res = vfs.open(main_db_path, OpenMode::Read).await;
    let main_file = match main_file_res {
        Ok(f) => f,
        Err(e) => {
            report.page_issues.push(PageIssue {
                page_id: 0,
                description: format!("cannot open main.db: {e}"),
            });
            return Ok(report);
        }
    };

    // Pages 0 and 1 are A/B structural headers — they use a different format
    // (HK-MAC, cleartext) and are already verified by `Db::open`. Skip them.
    // Page 2 and 3 are reserved (apply-journal). Walk from page 4.
    for page_id in 4..next_page_id {
        let offset = page_id * page_size as u64;
        let mut buf = vec![0u8; page_size];
        match main_file.read_at(offset, &mut buf).await {
            Ok(n) if n < page_size => {
                // Short read at the tail — the file may be smaller than expected.
                // Report but continue.
                report.page_issues.push(PageIssue {
                    page_id,
                    description: format!("short read: expected {page_size} bytes, got {n}"),
                });
                report.pages_examined += 1;
                continue;
            }
            Ok(_) => {}
            Err(e) => {
                report.page_issues.push(PageIssue {
                    page_id,
                    description: format!("read error: {e}"),
                });
                report.pages_examined += 1;
                continue;
            }
        }

        // Skip all-zero pages — they are freed/reclaimed pages that GC has
        // zeroed out. They carry no AEAD tag and are not corruption.
        if buf.iter().all(|&b| b == 0) {
            report.pages_examined += 1;
            continue;
        }

        // Extract cipher_id and epoch from the page header.
        let Ok((on_disk_cipher_id, on_disk_epoch)) = extract_page_header_ids(&buf) else {
            report.page_issues.push(PageIssue {
                page_id,
                description: "unreadable page header (cipher_id / epoch extraction failed)"
                    .to_string(),
            });
            report.pages_examined += 1;
            continue;
        };

        // We don't know the page kind without decrypting; try each main-db
        // kind until one succeeds. In practice any valid page has exactly one
        // matching kind.
        let kind_byte = buf[1]; // OFF_PAGE_KIND
        let kind = PageKind::from_byte(kind_byte).ok();
        let aead_ok = if let Some(k) = kind {
            if k.is_main_db() {
                let aad = Aad::from_fields(AadFields {
                    cipher_id: on_disk_cipher_id.as_byte(),
                    page_kind: k.as_byte(),
                    mk_epoch: on_disk_epoch,
                    page_id,
                    realm_id,
                    segment_id: MAIN_DB_SEGMENT_ID,
                });
                let mk_snapshot = db.pager.mk()?;
                let mut lru = db.pager.dek_lru().lock();
                let cipher_res =
                    lru.get_or_derive(realm_id, on_disk_epoch, on_disk_cipher_id, &mk_snapshot);
                match cipher_res {
                    Ok(cipher) => {
                        let mut buf2 = buf.clone();
                        crate::pager::format::data_page::open_data_page(&mut buf2, &aad, cipher)
                            .is_ok()
                    }
                    Err(_) => false,
                }
            } else {
                false
            }
        } else {
            false
        };

        if !aead_ok {
            report.page_issues.push(PageIssue {
                page_id,
                description: "AEAD verification failed".to_string(),
            });
        } else if !reachable.contains(&page_id) {
            report.orphan_page_ids.push(page_id);
        }

        report.pages_examined += 1;
    }

    // ------------------------------------------------------------------ //
    // 1b. Structural descent: every internal-node child pointer must resolve
    // to a valid B+ tree node. A pointer to a Free/non-node page is a
    // use-after-free dangling pointer — the page's own AEAD still verifies
    // (under its recycled kind), so the physical page-walk above cannot catch
    // it; only a keyed descent that authenticates each child *as a node* can.
    // ------------------------------------------------------------------ //
    let (data_root, hist_root) = {
        let state = db.writer.lock().await;
        (state.root_page_id, state.commit_history_root_page_id)
    };
    for root in [data_root, catalog_root, hist_root]
        .into_iter()
        .filter(|&r| r != 0)
    {
        check_dangling_child_pointers(db, root, next_page_id, &mut report).await;
    }

    // ------------------------------------------------------------------ //
    // 2. Walk every segment in seg/.
    // ------------------------------------------------------------------ //
    if catalog_root == 0 {
        return Ok(report);
    }

    let cat_tree = BTree::open(
        db.pager.clone(),
        realm_id,
        catalog_root,
        catalog_next,
        page_size,
    );
    let seg_start = vec![0x01u8]; // CatalogRowKind::Segment
    let seg_end = vec![0x02u8];
    let catalog_rows = match cat_tree.collect_range(&seg_start, &seg_end).await {
        Ok(rows) => rows,
        Err(e) => {
            report.page_issues.push(PageIssue {
                page_id: catalog_root,
                description: format!("catalog scan failed: {e}"),
            });
            return Ok(report);
        }
    };

    let mk = db.pager.mk()?;

    for (_k, v) in &catalog_rows {
        let meta = match Catalog::decode_segment_meta(v) {
            Ok(m) => m,
            Err(e) => {
                report.drift_issues.push(DriftIssue {
                    segment_id: [0; 16],
                    description: format!("catalog decode error: {e}"),
                });
                continue;
            }
        };

        check_segment(vfs, &meta, &mk, db.pager.clone(), &mut report).await;
        report.segments_examined += 1;
    }

    Ok(report)
}

/// Attempt to verify the segment at its live path and walk its pages.
#[allow(clippy::too_many_lines)]
async fn check_segment<V: Vfs + Clone>(
    vfs: &V,
    meta: &SegmentMeta,
    mk: &crate::crypto::keys::MasterKey,
    pager: std::sync::Arc<Pager<V>>,
    report: &mut DeepWalkReport,
) {
    let live = crate::segment::writer::live_path(&meta.segment_id);
    let page_size = pager.page_size();

    // Check file exists.
    let Ok(file) = vfs.open(&live, OpenMode::Read).await else {
        report.drift_issues.push(DriftIssue {
            segment_id: meta.segment_id,
            description: "segment file missing from seg/".to_string(),
        });
        return;
    };

    if let Err(e) =
        authenticate_segment_metadata(&pager, &file, meta, pager.main_db_file_id(), page_size).await
    {
        report.segment_issues.push(SegmentIssue {
            segment_id: meta.segment_id,
            description: format!("authenticated segment metadata invalid: {e}"),
        });
        return;
    }
    let Some(footer_page_id) = meta.page_count.checked_sub(1) else {
        report.segment_issues.push(SegmentIssue {
            segment_id: meta.segment_id,
            description: "segment page count cannot locate footer".to_string(),
        });
        return;
    };

    // Catalog-disk drift: compare page count with actual file size.
    // We don't have a metadata API, but we can check via read: try reading one
    // byte past the expected end. If it succeeds (on some VFS) we skip the
    // check; if we read exactly `page_count * page_size` bytes we're consistent.
    let expected_size = meta.page_count * page_size as u64;
    let mut probe = vec![0u8; 1];
    let over_read = file.read_at(expected_size, &mut probe).await;
    match over_read {
        Ok(n) if n > 0 => {
            report.drift_issues.push(DriftIssue {
                segment_id: meta.segment_id,
                description: format!(
                    "file is larger than catalog record (catalog page_count={}, but data found at offset {expected_size})",
                    meta.page_count
                ),
            });
        }
        _ => {}
    }

    // Walk data pages (1 .. page_count - 1, skipping header=0 and footer=last).
    let last_data = footer_page_id;
    for page_id in 1..last_data {
        let offset = page_id * page_size as u64;
        let mut buf = vec![0u8; page_size];
        let read_res = file.read_at(offset, &mut buf).await;
        match read_res {
            Ok(n) if n < page_size => {
                report.segment_issues.push(SegmentIssue {
                    segment_id: meta.segment_id,
                    description: format!(
                        "short read at page {page_id}: expected {page_size} bytes, got {n}"
                    ),
                });
                continue;
            }
            Ok(_) => {}
            Err(e) => {
                report.segment_issues.push(SegmentIssue {
                    segment_id: meta.segment_id,
                    description: format!("read error at page {page_id}: {e}"),
                });
                continue;
            }
        }

        let Ok((on_disk_cipher_id, on_disk_epoch)) = extract_page_header_ids(&buf) else {
            report.segment_issues.push(SegmentIssue {
                segment_id: meta.segment_id,
                description: format!("page {page_id}: unreadable header"),
            });
            continue;
        };

        let kind_byte = buf[1];
        let kind = PageKind::from_byte(kind_byte).ok();
        let verified = if let Some(k) = kind {
            if k.is_segment() {
                let aad = Aad::from_fields(AadFields {
                    cipher_id: on_disk_cipher_id.as_byte(),
                    page_kind: k.as_byte(),
                    mk_epoch: on_disk_epoch,
                    page_id,
                    realm_id: meta.realm_id,
                    segment_id: meta.segment_id,
                });
                let mut lru = pager.dek_lru().lock();
                let cipher_res =
                    lru.get_or_derive(meta.realm_id, on_disk_epoch, on_disk_cipher_id, mk);
                match cipher_res {
                    Ok(cipher) => {
                        let mut b2 = buf.clone();
                        crate::pager::format::data_page::open_data_page(&mut b2, &aad, cipher)
                            .is_ok()
                    }
                    Err(_) => false,
                }
            } else {
                false
            }
        } else {
            false
        };

        if !verified {
            report.segment_issues.push(SegmentIssue {
                segment_id: meta.segment_id,
                description: format!("page {page_id}: AEAD verification failed"),
            });
        }
    }
}

/// Collect the set of all page IDs reachable from the main B+ tree root,
/// the catalog root, the commit-history root, and the free-list root.
/// Pages 0..=3 (reserved) are always considered reachable.
async fn collect_reachable_pages<V: Vfs + Clone>(db: &Db<V>) -> BTreeSet<u64> {
    let mut reachable: BTreeSet<u64> = BTreeSet::new();
    // Reserved pages.
    for pid in 0u64..4 {
        reachable.insert(pid);
    }

    let (root, cat_root, hist_root, next) = {
        let state = db.writer.lock().await;
        (
            state.root_page_id,
            state.catalog_root_page_id,
            state.commit_history_root_page_id,
            state.next_page_id,
        )
    };

    for tree_root in [root, cat_root, hist_root]
        .iter()
        .copied()
        .filter(|&r| r != 0)
    {
        let tree = BTree::open(db.pager.clone(), db.realm_id, tree_root, next, db.page_size);
        let _ = tree.collect_all_page_ids(&mut reachable).await;
    }

    reachable
}

/// Descend `root` breadth-first, authenticating every internal-node child
/// pointer *as a B+ tree node*. Any pointer to a page that is out of range or
/// does not read back as a leaf/internal node (e.g. a recycled `Free` page) is
/// a use-after-free dangling pointer; it is appended to `report.page_issues`.
async fn check_dangling_child_pointers<V: Vfs + Clone>(
    db: &Db<V>,
    root: u64,
    next_page_id: u64,
    report: &mut DeepWalkReport,
) {
    use crate::btree::internal::Internal;

    let mut visited: BTreeSet<u64> = BTreeSet::new();
    let mut queue: Vec<u64> = vec![root];
    // Bound the walk defensively so a corrupt cyclic tree cannot spin forever.
    let mut budget: u64 = next_page_id.saturating_mul(2).saturating_add(16);

    while let Some(page_id) = queue.pop() {
        if budget == 0 {
            break;
        }
        budget -= 1;
        if !visited.insert(page_id) {
            continue;
        }
        // The physical page-walk above already reports unreadable pages.
        let Ok((guard, kind)) = db.pager.read_main_node(page_id, db.realm_id).await else {
            continue;
        };
        if kind != PageKind::BTreeInternal {
            continue; // leaf: nothing to descend
        }
        let Ok(internal) = Internal::decode(guard.body_ref()) else {
            continue;
        };
        drop(guard);
        let children = std::iter::once(internal.leftmost_child)
            .chain(internal.entries.iter().map(|e| e.right_child));
        for child in children {
            if child == 0 {
                continue;
            }
            if child >= next_page_id {
                report.page_issues.push(PageIssue {
                    page_id,
                    description: format!(
                        "internal node child pointer → {child} is past next_page_id ({next_page_id})"
                    ),
                });
                continue;
            }
            if db.pager.read_main_node(child, db.realm_id).await.is_ok() {
                queue.push(child);
            } else {
                // The child page does not authenticate as a btree node — a
                // freed/recycled page still referenced by this parent.
                let mut buf = vec![0u8; db.page_size];
                let kind_byte = if let Ok(f) = db.vfs.open(&db.main_db_path, OpenMode::Read).await {
                    let _ = f.read_at(child * db.page_size as u64, &mut buf).await;
                    buf.get(1).copied().unwrap_or(0)
                } else {
                    0
                };
                report.page_issues.push(PageIssue {
                    page_id: child,
                    description: format!(
                        "dangling child pointer: internal node {page_id} references page \
                         {child}, which is not a valid btree node (on-disk kind byte \
                         0x{kind_byte:02x}) — use-after-free"
                    ),
                });
            }
        }
    }
}
