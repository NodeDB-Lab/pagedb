//! Deep-walk integrity check for `pagedb-fsck --deep`.
//!
//! Walks every page in `main.db` and every segment file, verifying AEAD tags,
//! structural invariants, and catalog–disk consistency. Returns a structured
//! `DeepWalkReport` rather than printing directly so callers can choose output
//! format.

use std::collections::{BTreeSet, VecDeque};

use crate::Result;
use crate::btree::BTree;
use crate::btree::internal::Internal;
use crate::btree::leaf::{Leaf, LeafValue};
use crate::btree::overflow;
use crate::catalog::codec::{Catalog, SegmentMeta};
use crate::crypto::aad::{Aad, AadFields, MAIN_DB_SEGMENT_ID};
use crate::errors::PagedbError;
use crate::pager::format::data_page::extract_page_header_ids;
use crate::pager::format::page_kind::PageKind;
use crate::pager::page_space::{FIRST_ALLOCATABLE_PAGE_ID, is_reserved, page_offset};
use crate::pager::{PageGuard, Pager};
use crate::segment::authenticated_metadata::authenticate_segment_metadata;
use crate::txn::db::Db;
use crate::vfs::types::OpenMode;
use crate::vfs::{Vfs, VfsFile, read_exact_at};

/// A single page-level issue found during deep walk.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct PageIssue {
    pub page_id: u64,
    pub description: String,
}

/// An issue found in a segment file during deep walk.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct SegmentIssue {
    pub segment_id: [u8; 16],
    pub description: String,
}

/// A catalog-vs-disk discrepancy.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct DriftIssue {
    pub segment_id: [u8; 16],
    pub description: String,
}

/// Full report produced by [`run_deep_walk`].
#[non_exhaustive]
#[derive(Debug, Default)]
pub struct DeepWalkReport {
    /// Pages whose AEAD verification failed or whose structure is invalid.
    pub page_issues: Vec<PageIssue>,
    /// Segment-level issues (bad footer MAC, unreadable pages inside a segment).
    pub segment_issues: Vec<SegmentIssue>,
    /// Leaked pages: unreferenced by every live root *and* absent from the free
    /// list, so nothing will ever hand them out again.
    ///
    /// This is a claim about an allocator, not about bytes, so it is only ever
    /// populated for a handle that owns the allocator behind `main.db` — see
    /// [`DeepWalkReport::is_clean`]. On a replicating handle the set is always
    /// empty, and its emptiness carries no information.
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
    /// Orphan pages are not informational: pages deferred for GC are recorded
    /// in the free-list chain and are already folded into `reachable` by
    /// `run_deep_walk`, so a page that still lands in `orphan_page_ids` is
    /// unreferenced by any root *and* absent from the free list — a genuine
    /// leak. A leak that doesn't fail this check is invisible, so it must
    /// count here.
    ///
    /// That verdict is not universal, because an orphan is unreferenced space
    /// in an allocator *this handle controls*. A replicating handle's `main.db`
    /// is the producer's allocator: the handle adopts the producer's cursor,
    /// receives only the pages the producer's roots reach, and never allocates
    /// from the ids in between — those are the producer's free space. The same
    /// page that is a leak on the writer that owns it is simply not this
    /// handle's leak to report. So [`run_deep_walk`] records orphans only for
    /// [`DbMode::Standalone`](crate::DbMode::Standalone).
    ///
    /// Every other part of the report is a claim about bytes rather than about
    /// ownership — AEAD, structure, catalog drift — and still applies in every
    /// mode, so `is_clean` remains meaningful on a follower.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.page_issues.is_empty()
            && self.segment_issues.is_empty()
            && self.drift_issues.is_empty()
            && self.orphan_page_ids.is_empty()
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

        writeln!(
            out,
            "--- orphan pages: leaked, unreferenced by any root or the free list ({}) ---",
            self.orphan_page_ids.len()
        )?;
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
///
/// Leak detection is mode-scoped — see [`DeepWalkReport::is_clean`]. Everything
/// else the walk verifies holds in every mode.
#[allow(clippy::too_many_lines)]
pub async fn run_deep_walk<V: Vfs + Clone>(db: &Db<V>) -> Result<DeepWalkReport> {
    db.ensure_usable()?;
    let mut report = DeepWalkReport::default();

    // Only a Standalone handle owns the allocator behind `main.db`, so only it
    // can be leaking. Follower and ReadOnly replicate a producer's page space,
    // and an Observer is reading a live writer's — in all three the ids no root
    // reaches belong to that other writer's free space, and calling them leaks
    // would report someone else's bookkeeping as this store's corruption.
    // Matching Standalone positively rather than excluding the others keeps
    // that conservative reading if `DbMode` ever grows a variant.
    let owns_page_space = db.is_writer();

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
    let mut reachable = collect_reachable_pages(db, &mut report).await;

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
    let mut main_file = match main_file_res {
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
        let offset = match page_offset(page_id, page_size, "deep-walk main page offset") {
            Ok(offset) => offset,
            Err(error) => {
                report.page_issues.push(PageIssue {
                    page_id,
                    description: format!("{error}"),
                });
                report.pages_examined += 1;
                continue;
            }
        };
        let mut buf = vec![0u8; page_size];
        match read_exact_at(&mut main_file, offset, &mut buf).await {
            Ok(()) => {}
            Err(error) => {
                let description = describe_page_read_failure(&mut main_file, offset, error).await;
                report.page_issues.push(PageIssue {
                    page_id,
                    description,
                });
                report.pages_examined += 1;
                continue;
            }
        }

        // A zeroed page carries no AEAD tag, so authentication can say nothing
        // about it and accounting is the only evidence available. That evidence
        // is already complete here: `reachable` holds the reserved pages, every
        // live root's pages, and — folded in above — the free-list chain's own
        // pages plus every page it names. Either way the page is skipped without
        // attempting a tag it cannot have; the only question left is whether
        // its absence from `reachable` is this store's problem. On a handle that
        // owns the allocator it is — no root and no free list names the page, so
        // nothing will ever hand it out again. On a replicating handle the very
        // same page is the producer's free space, which is why the judgement is
        // gated rather than the skip.
        if buf.iter().all(|&b| b == 0) {
            if owns_page_space && !reachable.contains(&page_id) {
                report.orphan_page_ids.push(page_id);
            }
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
        } else if owns_page_space && !reachable.contains(&page_id) {
            report.orphan_page_ids.push(page_id);
        }

        report.pages_examined += 1;
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
    let seg_prefix = [crate::catalog::codec::CatalogRowKind::Segment as u8];
    let catalog_rows = match cat_tree.scan_prefix(&seg_prefix).await {
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
    let Ok(mut file) = vfs.open(&live, OpenMode::Read).await else {
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
    let expected_size = match page_offset(meta.page_count, page_size, "segment expected size") {
        Ok(offset) => offset,
        Err(error) => {
            report.segment_issues.push(SegmentIssue {
                segment_id: meta.segment_id,
                description: format!("{error}"),
            });
            return;
        }
    };
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
        let offset = match page_offset(page_id, page_size, "segment data page offset") {
            Ok(offset) => offset,
            Err(error) => {
                report.segment_issues.push(SegmentIssue {
                    segment_id: meta.segment_id,
                    description: format!("page {page_id}: {error}"),
                });
                continue;
            }
        };
        let mut buf = vec![0u8; page_size];
        match read_exact_at(&mut file, offset, &mut buf).await {
            Ok(()) => {}
            Err(error) => {
                let description = describe_page_read_failure(&mut file, offset, error).await;
                report.segment_issues.push(SegmentIssue {
                    segment_id: meta.segment_id,
                    description: format!("page {page_id}: {description}"),
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

/// Turn a failed full-page read into a description that keeps the byte counts.
///
/// `read_exact_at` completes a legal short read and only gives up once the
/// backend stops making progress, so the partial count it consumed never
/// reaches the caller — a truncated file arrives here as a bare
/// `UnexpectedEof`. On a diagnostic surface those numbers are the product: an
/// operator needs to know the file is short and by how much, not merely that a
/// read ended. Any other error is already self-describing and passes through.
async fn describe_page_read_failure<F: VfsFile>(
    file: &mut F,
    offset: u64,
    error: PagedbError,
) -> String {
    let is_eof = matches!(
        &error,
        PagedbError::Io(io) if io.kind() == std::io::ErrorKind::UnexpectedEof
    );
    if !is_eof {
        return format!("read error: {error}");
    }
    match file.len().await {
        Ok(len) => format!("truncated: page starts at offset {offset}, file is {len} bytes"),
        Err(len_error) => {
            format!("read error: {error} (file length unavailable: {len_error})")
        }
    }
}

/// Collect the set of all page IDs reachable from the main B+ tree root,
/// the catalog root, the commit-history root, and the free-list root.
/// Pages 0..=3 (reserved) are always considered reachable.
async fn collect_reachable_pages<V: Vfs + Clone>(
    db: &Db<V>,
    report: &mut DeepWalkReport,
) -> BTreeSet<u64> {
    let mut reachable: BTreeSet<u64> = BTreeSet::new();
    // Reserved pages are owned by the headers and the apply-journal, so they
    // are never orphans even though no tree points at them.
    for pid in 0..FIRST_ALLOCATABLE_PAGE_ID {
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

    for (tree_name, tree_root) in [
        ("main tree", root),
        ("catalog tree", cat_root),
        ("commit-history tree", hist_root),
    ]
    .into_iter()
    .filter(|&(_name, root)| root != 0)
    {
        let tree = BTree::open(db.pager.clone(), db.realm_id, tree_root, next, db.page_size);
        if let Err(error) = tree.collect_all_page_ids(&mut reachable).await {
            report.page_issues.push(PageIssue {
                page_id: tree_root,
                description: format!("{tree_name} reachability walk failed: {error}"),
            });
            diagnose_tree_structure(db, tree_name, tree_root, next, report).await;
        }
    }

    reachable
}

/// Localize the corruption after a tree's authoritative reachability walk has
/// already failed.
///
/// Healthy trees are never traversed twice — this runs only once
/// [`BTree::collect_all_page_ids`] has reported an error, and its job is to say
/// *where* rather than *whether*. It is therefore deliberately best-effort and
/// bounded: it keeps walking past each anomaly to collect siblings, which is
/// only sound because the authoritative verdict is already recorded.
///
/// Every page it inspects is authenticated first. A recycled child is
/// identified by reading it as a B+ tree node and failing, never by trusting a
/// raw on-disk kind byte — unauthenticated bytes are not evidence.
async fn diagnose_tree_structure<V: Vfs + Clone>(
    db: &Db<V>,
    tree_name: &str,
    root: u64,
    next_page_id: u64,
    report: &mut DeepWalkReport,
) {
    let mut visited = BTreeSet::new();
    let mut queue = VecDeque::from([(root, None)]);
    let mut budget = next_page_id.saturating_mul(2).saturating_add(16);

    while let Some((page_id, parent)) = queue.pop_front() {
        if budget == 0 {
            report.page_issues.push(PageIssue {
                page_id: root,
                description: format!(
                    "{tree_name} structural diagnostic exhausted its traversal budget"
                ),
            });
            return;
        }
        budget -= 1;
        if !visited.insert(page_id) {
            continue;
        }

        let (guard, authenticated_kind) = match db.pager.read_main_node(page_id, db.realm_id).await
        {
            Ok(page) => page,
            Err(error) => {
                // With no parent this is the root itself, whose failure the
                // caller already recorded against the tree.
                if let Some(parent_page_id) = parent {
                    report.page_issues.push(PageIssue {
                        page_id,
                        description: format!(
                            "dangling child pointer: {tree_name} internal node \
                             {parent_page_id} references page {page_id}, which is not a valid \
                             B+ tree node: {error}"
                        ),
                    });
                }
                continue;
            }
        };

        // `read_main_node` binds `KindBinding::Node`, so the authenticated kind
        // is one of exactly these two.
        match authenticated_kind {
            PageKind::BTreeLeaf => {
                let overflow_roots = leaf_overflow_roots(tree_name, page_id, &guard, report);
                drop(guard);
                for overflow_root in overflow_roots {
                    diagnose_overflow_chain(
                        db,
                        tree_name,
                        page_id,
                        overflow_root,
                        next_page_id,
                        report,
                    )
                    .await;
                }
            }
            PageKind::BTreeInternal => {
                let internal = match Internal::decode(guard.body_ref()) {
                    Ok(internal) => internal,
                    Err(error) => {
                        report.page_issues.push(PageIssue {
                            page_id,
                            description: format!(
                                "{tree_name} internal node {page_id} authenticates but could not \
                                 be decoded: {error}"
                            ),
                        });
                        continue;
                    }
                };
                drop(guard);
                queue.extend(diagnose_children(
                    tree_name,
                    page_id,
                    &internal,
                    next_page_id,
                    report,
                ));
            }
            other => {
                drop(guard);
                report.page_issues.push(PageIssue {
                    page_id,
                    description: format!(
                        "{tree_name} page {page_id} authenticated as {other:?}, which is not a \
                         B+ tree node"
                    ),
                });
            }
        }
    }
}

/// Decode an authenticated leaf and return the overflow roots it references.
/// A leaf that authenticates but will not decode is reported and contributes
/// no roots.
fn leaf_overflow_roots(
    tree_name: &str,
    page_id: u64,
    guard: &PageGuard,
    report: &mut DeepWalkReport,
) -> Vec<u64> {
    match Leaf::decode(guard.body_ref()) {
        Ok(leaf) => leaf
            .records
            .iter()
            .filter_map(|(_, value)| match value {
                LeafValue::Overflow { root_page_id, .. } => Some(*root_page_id),
                LeafValue::Inline(_) => None,
            })
            .collect(),
        Err(error) => {
            report.page_issues.push(PageIssue {
                page_id,
                description: format!(
                    "{tree_name} leaf {page_id} authenticates but could not be decoded: {error}"
                ),
            });
            Vec::new()
        }
    }
}

/// Report every child pointer of `internal` that cannot be a live page, and
/// return the ones still worth descending into, each paired with its parent.
fn diagnose_children(
    tree_name: &str,
    page_id: u64,
    internal: &Internal,
    next_page_id: u64,
    report: &mut DeepWalkReport,
) -> Vec<(u64, Option<u64>)> {
    let mut descend = Vec::new();
    for child in std::iter::once(internal.leftmost_child)
        .chain(internal.entries.iter().map(|entry| entry.right_child))
    {
        // A zero child id is an absent slot, not a pointer.
        if child == 0 {
            continue;
        }
        let out_of_range = if is_reserved(child) {
            Some(format!("references reserved page {child}"))
        } else if child >= next_page_id {
            Some(format!(
                "references page {child}, past next_page_id {next_page_id}"
            ))
        } else {
            None
        };
        match out_of_range {
            Some(reason) => report.page_issues.push(PageIssue {
                page_id: child,
                description: format!(
                    "dangling child pointer: {tree_name} internal node {page_id} {reason}"
                ),
            }),
            None => descend.push((child, Some(page_id))),
        }
    }
    descend
}

/// Report the first anomaly in the overflow chain rooted at `root`, referenced
/// by leaf `leaf_page_id`. Companion to [`diagnose_tree_structure`]; the same
/// best-effort-after-the-verdict caveat applies.
async fn diagnose_overflow_chain<V: Vfs + Clone>(
    db: &Db<V>,
    tree_name: &str,
    leaf_page_id: u64,
    root: u64,
    next_page_id: u64,
    report: &mut DeepWalkReport,
) {
    if is_reserved(root) {
        report.page_issues.push(PageIssue {
            page_id: root,
            description: format!(
                "{tree_name} leaf {leaf_page_id} has an overflow value rooted at reserved \
                 page {root}"
            ),
        });
        return;
    }

    let mut seen = BTreeSet::from([root]);
    let root_info = match overflow::read_root_page(&db.pager, db.realm_id, root).await {
        Ok(info) => info,
        Err(error) => {
            report.page_issues.push(PageIssue {
                page_id: root,
                description: format!(
                    "{tree_name} leaf {leaf_page_id} references overflow root {root}, which is \
                     not a valid overflow root page: {error}"
                ),
            });
            return;
        }
    };

    let mut chain_id = root_info.next;
    while chain_id != 0 {
        if is_reserved(chain_id) || chain_id >= next_page_id {
            report.page_issues.push(PageIssue {
                page_id: chain_id,
                description: format!(
                    "{tree_name} overflow chain rooted at {root} (leaf {leaf_page_id}) links to \
                     out-of-range page {chain_id}"
                ),
            });
            return;
        }
        if !seen.insert(chain_id) {
            report.page_issues.push(PageIssue {
                page_id: chain_id,
                description: format!(
                    "{tree_name} overflow chain rooted at {root} (leaf {leaf_page_id}) cycles \
                     back to page {chain_id}"
                ),
            });
            return;
        }

        let guard = match db
            .pager
            .read_main_page(chain_id, db.realm_id, PageKind::Overflow)
            .await
        {
            Ok(guard) => guard,
            Err(error) => {
                report.page_issues.push(PageIssue {
                    page_id: chain_id,
                    description: format!(
                        "{tree_name} overflow chain rooted at {root} (leaf {leaf_page_id}) links \
                         to page {chain_id}, which is not a valid overflow page: {error}"
                    ),
                });
                return;
            }
        };
        let body = guard.body();
        match overflow::decode_overflow(&body) {
            Ok((next, _)) => chain_id = next,
            Err(error) => {
                report.page_issues.push(PageIssue {
                    page_id: chain_id,
                    description: format!(
                        "{tree_name} overflow page {chain_id} (root {root}, leaf \
                         {leaf_page_id}) authenticates but could not be decoded: {error}"
                    ),
                });
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::btree::node::body_capacity;
    use crate::pager::format::data_page::ENVELOPE_OVERHEAD;
    use crate::vfs::memory::MemVfs;
    use crate::{OpenOptions, SegmentKind, SegmentPageKind};

    const PAGE: usize = 4096;
    const REALM: crate::RealmId = crate::RealmId::new([0xD3; 16]);

    async fn open_db() -> Db<MemVfs> {
        Db::open_internal_with_options(
            MemVfs::new(),
            [9u8; 32],
            PAGE,
            REALM,
            OpenOptions::default(),
        )
        .await
        .unwrap()
    }

    /// Persist `body` at `page_id` under `kind` and drop the cached copy, so the
    /// next read authenticates the bytes actually on disk.
    async fn persist_page(db: &Db<MemVfs>, page_id: u64, kind: PageKind, body: &[u8]) {
        db.pager
            .write_main_page(page_id, REALM, kind, body)
            .await
            .unwrap();
        db.pager.flush_main(REALM).await.unwrap();
        db.pager.reset_main_pages();
    }

    fn issue_matching(report: &DeepWalkReport, page_id: u64, needle: &str) -> bool {
        report
            .page_issues
            .iter()
            .any(|issue| issue.page_id == page_id && issue.description.contains(needle))
    }

    /// An authenticated but structurally malformed live node must not be
    /// silently omitted from the reachable set: it authenticates, so the
    /// physical page walk is happy, and it is inserted into `reachable`, so it
    /// is not an orphan either. Only a strict traversal can see it.
    #[tokio::test(flavor = "current_thread")]
    async fn deep_walk_reports_aead_valid_malformed_live_btree_root() {
        let db = open_db().await;
        let mut txn = db.begin_write().await.unwrap();
        txn.put(b"live-root", b"value").await.unwrap();
        txn.commit().await.unwrap();

        let root_page_id = db.writer.lock().await.root_page_id;
        let mut malformed_body = vec![0u8; PAGE - ENVELOPE_OVERHEAD];
        malformed_body[0] = 0xFF;
        persist_page(&db, root_page_id, PageKind::BTreeLeaf, &malformed_body).await;

        let report = run_deep_walk(&db).await.unwrap();
        assert!(
            issue_matching(&report, root_page_id, "reachability walk failed"),
            "deep walk must surface the authoritative tree traversal failure: {report:?}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn deep_walk_reports_a_cycle_in_a_live_overflow_chain() {
        let db = open_db().await;
        let mut txn = db.begin_write().await.unwrap();
        txn.put(b"overflow", &vec![0xA5; 9_000]).await.unwrap();
        txn.commit().await.unwrap();

        let root_page_id = db.writer.lock().await.root_page_id;
        let overflow_root_page_id = sole_overflow_root(&db, root_page_id).await;

        let root_info = overflow::read_root_page(&db.pager, REALM, overflow_root_page_id)
            .await
            .unwrap();
        assert_ne!(root_info.next, 0);
        let chain_guard = db
            .pager
            .read_main_page(root_info.next, REALM, PageKind::Overflow)
            .await
            .unwrap();
        let chain_body = chain_guard.body();
        let (_, chain_data) = overflow::decode_overflow(&chain_body).unwrap();
        let chain_data = chain_data.to_vec();
        drop(chain_body);
        drop(chain_guard);

        // Re-seal the first chain page pointing at itself. The envelope stays
        // valid, so only the structural walk can catch this.
        let mut cyclic_body = vec![0u8; PAGE - ENVELOPE_OVERHEAD];
        overflow::encode_overflow(&mut cyclic_body, root_info.next, &chain_data).unwrap();
        persist_page(&db, root_info.next, PageKind::Overflow, &cyclic_body).await;

        let report = run_deep_walk(&db).await.unwrap();
        assert!(
            issue_matching(&report, root_page_id, "OverflowChainCycle"),
            "deep walk must fail closed on an overflow cycle, by name: {report:?}"
        );
        assert!(
            issue_matching(&report, root_info.next, "cycles back to page"),
            "deep walk must localize the cycle to the repeated page: {report:?}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn deep_walk_identifies_the_dangling_child_page() {
        let db = open_db().await;
        let root_page_id = FIRST_ALLOCATABLE_PAGE_ID;
        let recycled_child_page_id = root_page_id + 1;

        write_internal_root(&db, root_page_id, recycled_child_page_id).await;
        persist_page(
            &db,
            recycled_child_page_id,
            PageKind::Free,
            &vec![0u8; body_capacity(PAGE)],
        )
        .await;
        set_root(&db, root_page_id, recycled_child_page_id + 1).await;

        let report = run_deep_walk(&db).await.unwrap();
        assert!(
            report.page_issues.iter().any(|issue| {
                issue.page_id == recycled_child_page_id
                    && issue.description.contains("dangling child pointer")
                    && issue.description.contains(&root_page_id.to_string())
            }),
            "deep walk must identify the recycled child and its parent: {report:?}"
        );
    }

    /// A child pointer into the reserved region is a wild pointer: the target
    /// authenticates under a *different* envelope format (HK-MAC structural
    /// header), so nothing downstream would flag it.
    #[tokio::test(flavor = "current_thread")]
    async fn deep_walk_reports_an_internal_child_in_a_reserved_page() {
        let db = open_db().await;
        let root_page_id = FIRST_ALLOCATABLE_PAGE_ID;
        let reserved_child = 1;

        write_internal_root(&db, root_page_id, reserved_child).await;
        set_root(&db, root_page_id, root_page_id + 1).await;

        let report = run_deep_walk(&db).await.unwrap();
        // Naming the detail, not merely "some error": reading page 1 as a node
        // happens to fail its AEAD too, and that generic failure would not tell
        // an operator which pointer was wild.
        assert!(
            issue_matching(&report, root_page_id, "ReservedPageReferenced"),
            "a reserved child pointer must fail the authoritative walk by name: {report:?}"
        );
        assert!(
            issue_matching(&report, reserved_child, "references reserved page"),
            "deep walk must name the reserved child: {report:?}"
        );
    }

    /// The same rule on the overflow side: an `Overflow` value always owns at
    /// least its root page, so a root of zero or a reserved id is corruption
    /// rather than an empty chain.
    ///
    /// `Leaf::encode` already asserts this on the write path, so the bytes are
    /// forged directly — what is under test is whether a page that reached disk
    /// some other way (an older writer, a bit flip re-sealed by a key holder) is
    /// caught on the way back in.
    #[tokio::test(flavor = "current_thread")]
    async fn deep_walk_reports_an_overflow_root_in_a_reserved_page() {
        let db = open_db().await;
        let mut txn = db.begin_write().await.unwrap();
        txn.put(b"overflow", &vec![0xA5; 9_000]).await.unwrap();
        txn.commit().await.unwrap();

        let root_page_id = db.writer.lock().await.root_page_id;
        let live_overflow_root = sole_overflow_root(&db, root_page_id).await;

        let (guard, _) = db.pager.read_main_node(root_page_id, REALM).await.unwrap();
        let mut leaf_body = guard.body().to_vec();
        drop(guard);
        // The record's tail is `u16 sentinel ‖ u64 total_len ‖ u64 root_page_id`;
        // rewrite just the root id in place.
        let root_offset = leaf_body
            .windows(8)
            .position(|window| window == live_overflow_root.to_le_bytes())
            .expect("overflow root id present in the encoded leaf");
        leaf_body[root_offset..root_offset + 8].copy_from_slice(&0u64.to_le_bytes());
        persist_page(&db, root_page_id, PageKind::BTreeLeaf, &leaf_body).await;

        let report = run_deep_walk(&db).await.unwrap();
        assert!(
            issue_matching(&report, root_page_id, "ReservedPageReferenced"),
            "an overflow value with no root page must fail the walk by name: {report:?}"
        );
        assert!(
            issue_matching(&report, 0, "overflow value rooted at reserved page"),
            "deep walk must name the invalid overflow root: {report:?}"
        );
    }

    /// A catalog `page_count` large enough to overflow a byte offset must be
    /// rejected as a structured issue, never reach the arithmetic that would
    /// wrap it, and never abort the walk. Authenticated metadata validation is
    /// what stops it, ahead of any footer index or loop bound; the checked
    /// `page_offset` behind it is the second line, covered directly in
    /// `pager::page_space`.
    #[tokio::test(flavor = "current_thread")]
    async fn deep_walk_rejects_impossible_catalog_page_count() {
        let db = open_db().await;
        let mut segment = db
            .create_segment(REALM, SegmentKind::Unspecified)
            .await
            .unwrap();
        segment
            .append_page(SegmentPageKind::Data, b"deep-walk")
            .await
            .unwrap();
        let mut meta = segment.seal().await.unwrap();
        {
            let mut txn = db.begin_write().await.unwrap();
            txn.link_segment("overflow", &meta).await.unwrap();
            txn.commit().await.unwrap();
        }

        meta.page_count = (u64::MAX / PAGE as u64) + 2;
        let (catalog_root, next_page_id) = {
            let state = db.writer.lock().await;
            (state.catalog_root_page_id, state.next_page_id)
        };
        let mut tree = BTree::open(
            db.pager.clone(),
            db.realm_id,
            catalog_root,
            next_page_id,
            db.page_size,
        );
        let key = Catalog::segment_key(REALM, b"overflow").unwrap();
        tree.put(&key, &Catalog::encode_segment_meta(&meta))
            .await
            .unwrap();
        tree.flush().await.unwrap();
        {
            let mut state = db.writer.lock().await;
            state.catalog_root_page_id = tree.root_page_id();
            state.next_page_id = state.next_page_id.max(tree.next_page_id());
        }

        let report = run_deep_walk(&db).await.unwrap();
        assert!(
            report.segment_issues.iter().any(|issue| {
                issue.segment_id == meta.segment_id
                    && issue
                        .description
                        .contains("authenticated segment metadata invalid")
            }),
            "impossible segment geometry must become a structured issue, got {report:?}"
        );
        assert!(
            report.segment_issues.iter().all(|issue| {
                !issue.description.contains("segment expected size")
                    && !issue.description.contains("segment data page offset")
            }),
            "validation must reject the record before any offset arithmetic runs: {report:?}"
        );
    }

    async fn sole_overflow_root(db: &Db<MemVfs>, leaf_page_id: u64) -> u64 {
        let (guard, _) = db.pager.read_main_node(leaf_page_id, REALM).await.unwrap();
        let leaf = Leaf::decode(guard.body_ref()).unwrap();
        match leaf.records[0].1 {
            LeafValue::Overflow { root_page_id, .. } => root_page_id,
            LeafValue::Inline(_) => panic!("expected an overflow value"),
        }
    }

    async fn write_internal_root(db: &Db<MemVfs>, page_id: u64, leftmost_child: u64) {
        let internal = Internal {
            leftmost_child,
            entries: Vec::new(),
        };
        let mut body = vec![0u8; body_capacity(PAGE)];
        internal.encode(&mut body).unwrap();
        persist_page(db, page_id, PageKind::BTreeInternal, &body).await;
    }

    async fn set_root(db: &Db<MemVfs>, root_page_id: u64, next_page_id: u64) {
        let mut state = db.writer.lock().await;
        state.root_page_id = root_page_id;
        state.next_page_id = next_page_id;
    }
}
