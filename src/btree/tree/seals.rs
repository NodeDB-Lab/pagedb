//! A walk that records when each reachable page was sealed.
//!
//! The ledger keeps, per page, its own counter and the newest counter at or
//! below it. A later tree that shares the page reads nothing and still learns
//! the newest seal under it. A plain visited set cannot answer that, because it
//! ends the walk at the shared page.
//!
//! A walk reads each page past the cache, once per ledger. The ledger costs one
//! entry per page across every tree it has seen.

use std::collections::{BTreeMap, BTreeSet};

use crate::Result;
use crate::btree::internal::Internal;
use crate::btree::leaf::{Leaf, LeafValue};
use crate::btree::node::{NodeKind, read_header};
use crate::btree::overflow;
use crate::crypto::CipherId;
use crate::errors::PagedbError;
use crate::pager::format::data_page::{SealStamp, body};
use crate::pager::format::page_kind::PageKind;
use crate::pager::page_space::is_reserved;
use crate::vfs::Vfs;

use super::core::BTree;

/// One page and the counter its envelope holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SealedPage {
    pub page_id: u64,
    pub counter: u64,
}

impl SealedPage {
    /// The side with the higher counter. An absent side loses.
    pub(crate) fn newer(left: Option<Self>, right: Option<Self>) -> Option<Self> {
        match (left, right) {
            (Some(a), Some(b)) => Some(if b.counter > a.counter { b } else { a }),
            (a, None) => a,
            (None, b) => b,
        }
    }

    /// The side with the lower counter. An absent side loses.
    pub(crate) fn older(left: Option<Self>, right: Option<Self>) -> Option<Self> {
        match (left, right) {
            (Some(a), Some(b)) => Some(if b.counter < a.counter { b } else { a }),
            (a, None) => a,
            (None, b) => b,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct LedgerEntry {
    /// `None` when this page's stamp cannot be ordered against the others.
    own: Option<SealedPage>,
    /// The newest comparable seal at or below this page. A page still being
    /// walked holds its own stamp here.
    newest: Option<SealedPage>,
}

/// Every page one scan has read, with the seal order it can prove.
pub(crate) struct SealLedger {
    identity: [u8; 6],
    pages: BTreeMap<u64, LedgerEntry>,
    saw_foreign_seal: bool,
}

impl SealLedger {
    /// A ledger that orders seals under the file identity `file_id` starts with.
    pub(crate) fn new(file_id: &[u8; 16]) -> Self {
        let mut identity = [0u8; 6];
        identity.copy_from_slice(&file_id[..6]);
        Self {
            identity,
            pages: BTreeMap::new(),
            saw_foreign_seal: false,
        }
    }

    /// Whether any page carried a stamp this ledger cannot order.
    pub(crate) fn saw_foreign_seal(&self) -> bool {
        self.saw_foreign_seal
    }

    /// The stamp's counter, when seal order means anything for it.
    ///
    /// A rekey reseals pages in walk order under a non-zero epoch. A stamp from
    /// another epoch, cipher, or identity therefore orders nothing. `PlaintextMac`
    /// leaves the nonce outside its tag, so its counter proves nothing either.
    ///
    /// A follower's own pages carry a per-open prefix, so they count as another
    /// identity. No row walk reaches them, so they leave a follower's scan intact.
    pub(crate) fn comparable(&mut self, page_id: u64, stamp: &SealStamp) -> Option<SealedPage> {
        if stamp.identity == self.identity
            && stamp.mk_epoch == 0
            && stamp.cipher_id != CipherId::PlaintextMac
        {
            return Some(SealedPage {
                page_id,
                counter: stamp.counter,
            });
        }
        self.saw_foreign_seal = true;
        None
    }

    /// The comparable seal of a page this ledger holds, or `None` if it holds no
    /// such page.
    pub(crate) fn own(&self, page_id: u64) -> Option<SealedPage> {
        self.pages.get(&page_id).and_then(|entry| entry.own)
    }

    fn lookup(&self, page_id: u64) -> SealLookup {
        match self.pages.get(&page_id) {
            None => SealLookup::Unread,
            Some(LedgerEntry { newest: None, .. }) => SealLookup::NoComparableSeal,
            Some(LedgerEntry {
                newest: Some(newest),
                ..
            }) => SealLookup::Newest(*newest),
        }
    }

    fn enter(&mut self, page_id: u64, stamp: &SealStamp) -> Option<SealedPage> {
        let own = self.comparable(page_id, stamp);
        self.pages.insert(page_id, LedgerEntry { own, newest: own });
        own
    }

    fn finish(&mut self, page_id: u64, newest: Option<SealedPage>) {
        if let Some(entry) = self.pages.get_mut(&page_id) {
            entry.newest = newest;
        }
    }
}

/// What a ledger knows about one page.
enum SealLookup {
    /// No walk has read this page.
    Unread,
    /// The page was read, and nothing at or below it can be ordered.
    NoComparableSeal,
    /// The page was read, and this is the newest seal at or below it.
    Newest(SealedPage),
}

/// An internal node whose children are still being walked.
struct SealFrame {
    page_id: u64,
    pending: Vec<u64>,
    newest: Option<SealedPage>,
}

enum SealStep {
    /// The page and everything below it are done.
    Known(Option<SealedPage>),
    Descend(SealFrame),
}

impl<V: Vfs> BTree<V> {
    /// Walk this tree into `ledger`. Returns the newest comparable seal the tree
    /// reaches, including pages an earlier walk already read.
    ///
    /// `reached` gains only the pages this walk read first.
    ///
    /// Authoritative on the terms of [`Self::collect_all_page_ids`]: `Ok` means
    /// every page it read authenticated as its own kind and decoded.
    pub(crate) async fn walk_page_seals(
        &self,
        ledger: &mut SealLedger,
        reached: &mut BTreeSet<u64>,
    ) -> Result<Option<SealedPage>> {
        if self.root_page_id == 0 {
            return Ok(None);
        }
        let first = self
            .enter_node_seals(0, self.root_page_id, ledger, reached)
            .await?;
        let mut stack = match first {
            SealStep::Known(newest) => return Ok(newest),
            SealStep::Descend(frame) => vec![frame],
        };
        loop {
            let Some(top) = stack.last_mut() else {
                return Ok(None);
            };
            if let Some(child) = top.pending.pop() {
                let parent = top.page_id;
                match self
                    .enter_node_seals(parent, child, ledger, reached)
                    .await?
                {
                    SealStep::Known(newest) => top.newest = SealedPage::newer(top.newest, newest),
                    SealStep::Descend(frame) => stack.push(frame),
                }
                continue;
            }
            let (page_id, newest) = (top.page_id, top.newest);
            stack.pop();
            ledger.finish(page_id, newest);
            match stack.last_mut() {
                Some(parent) => parent.newest = SealedPage::newer(parent.newest, newest),
                None => return Ok(newest),
            }
        }
    }

    async fn enter_node_seals(
        &self,
        parent_page_id: u64,
        page_id: u64,
        ledger: &mut SealLedger,
        reached: &mut BTreeSet<u64>,
    ) -> Result<SealStep> {
        if is_reserved(page_id) {
            return Err(PagedbError::reserved_page_referenced(
                parent_page_id,
                page_id,
            ));
        }
        match ledger.lookup(page_id) {
            SealLookup::Unread => {}
            SealLookup::NoComparableSeal => return Ok(SealStep::Known(None)),
            SealLookup::Newest(newest) => return Ok(SealStep::Known(Some(newest))),
        }
        let read = self
            .pager
            .read_main_node_sealed(page_id, self.realm_id)
            .await?;
        let page_body = body(&read.page);
        let decoded_kind = read_header(page_body)?.kind;
        let expected_kind = match read.kind {
            PageKind::BTreeLeaf => NodeKind::Leaf,
            PageKind::BTreeInternal => NodeKind::Internal,
            _ => return Err(PagedbError::IllegalPageKind),
        };
        if decoded_kind != expected_kind {
            return Err(PagedbError::node_kind_mismatch(
                Some(page_id),
                expected_kind.name(),
                decoded_kind.name(),
            ));
        }
        let children: Vec<u64> = match decoded_kind {
            NodeKind::Internal => {
                let node = Internal::decode(page_body)?;
                std::iter::once(node.leftmost_child)
                    .chain(node.entries.iter().map(|entry| entry.right_child))
                    // A zero child id is an absent slot, not a pointer.
                    .filter(|&child| child != 0)
                    .collect()
            }
            NodeKind::Leaf => Vec::new(),
        };
        let overflow_roots: Vec<u64> = match decoded_kind {
            NodeKind::Leaf => Leaf::decode(page_body)?
                .records
                .iter()
                .filter_map(|(_, value)| match value {
                    LeafValue::Overflow { root_page_id, .. } => Some(*root_page_id),
                    LeafValue::Inline(_) => None,
                })
                .collect(),
            NodeKind::Internal => Vec::new(),
        };
        reached.insert(page_id);
        let own = ledger.enter(page_id, &read.stamp);
        if decoded_kind == NodeKind::Internal {
            return Ok(SealStep::Descend(SealFrame {
                page_id,
                pending: children,
                newest: own,
            }));
        }
        let mut newest = own;
        for overflow_root in overflow_roots {
            let chain = self
                .walk_overflow_seals(page_id, overflow_root, ledger, reached)
                .await?;
            newest = SealedPage::newer(newest, chain);
        }
        ledger.finish(page_id, newest);
        Ok(SealStep::Known(newest))
    }

    /// A chain page reached twice is a cycle, on the terms of
    /// `collect_overflow_chain`. A root reached twice is a refcounted share.
    async fn walk_overflow_seals(
        &self,
        leaf_page_id: u64,
        root: u64,
        ledger: &mut SealLedger,
        reached: &mut BTreeSet<u64>,
    ) -> Result<Option<SealedPage>> {
        if is_reserved(root) {
            return Err(PagedbError::reserved_page_referenced(leaf_page_id, root));
        }
        match ledger.lookup(root) {
            SealLookup::Unread => {}
            SealLookup::NoComparableSeal => return Ok(None),
            SealLookup::Newest(newest) => return Ok(Some(newest)),
        }
        let read = self
            .pager
            .read_main_page_sealed(root, self.realm_id, PageKind::OverflowRoot)
            .await?;
        let mut chain_page_id = overflow::overflow_root_next(body(&read.page))?;
        reached.insert(root);
        let mut newest = ledger.enter(root, &read.stamp);
        while chain_page_id != 0 {
            if is_reserved(chain_page_id) {
                return Err(PagedbError::reserved_page_referenced(root, chain_page_id));
            }
            if !matches!(ledger.lookup(chain_page_id), SealLookup::Unread) {
                return Err(PagedbError::overflow_chain_cycle(root, chain_page_id));
            }
            let read = self
                .pager
                .read_main_page_sealed(chain_page_id, self.realm_id, PageKind::Overflow)
                .await?;
            let (next, _) = overflow::decode_overflow(body(&read.page))?;
            reached.insert(chain_page_id);
            let own = ledger.enter(chain_page_id, &read.stamp);
            newest = SealedPage::newer(newest, own);
            chain_page_id = next;
        }
        ledger.finish(root, newest);
        Ok(newest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FILE_ID: [u8; 16] = [0xA1; 16];

    fn stamp(counter: u64) -> SealStamp {
        SealStamp {
            identity: [0xA1; 6],
            counter,
            mk_epoch: 0,
            cipher_id: CipherId::Aes256Gcm,
        }
    }

    #[test]
    fn a_stamp_from_this_identity_at_epoch_zero_is_comparable() {
        let mut ledger = SealLedger::new(&FILE_ID);
        assert_eq!(
            ledger.comparable(9, &stamp(7)),
            Some(SealedPage {
                page_id: 9,
                counter: 7
            })
        );
        assert!(!ledger.saw_foreign_seal());
    }

    #[test]
    fn a_stamp_from_another_identity_proves_nothing_and_marks_the_ledger() {
        let mut ledger = SealLedger::new(&FILE_ID);
        let foreign = SealStamp {
            identity: [0xB2; 6],
            ..stamp(u64::from(u32::MAX))
        };
        assert_eq!(ledger.comparable(9, &foreign), None);
        assert!(ledger.saw_foreign_seal());
    }

    #[test]
    fn a_stamp_from_a_later_epoch_proves_nothing_and_marks_the_ledger() {
        let mut ledger = SealLedger::new(&FILE_ID);
        let resealed = SealStamp {
            mk_epoch: 1,
            ..stamp(7)
        };
        assert_eq!(ledger.comparable(9, &resealed), None);
        assert!(ledger.saw_foreign_seal());
    }

    #[test]
    fn a_plaintext_mac_stamp_proves_nothing_and_marks_the_ledger() {
        let mut ledger = SealLedger::new(&FILE_ID);
        let unauthenticated = SealStamp {
            cipher_id: CipherId::PlaintextMac,
            ..stamp(7)
        };
        assert_eq!(ledger.comparable(9, &unauthenticated), None);
        assert!(ledger.saw_foreign_seal());
    }

    #[test]
    fn newer_and_older_prefer_the_present_side_and_order_by_counter() {
        let low = SealedPage {
            page_id: 1,
            counter: 5,
        };
        let high = SealedPage {
            page_id: 2,
            counter: 9,
        };
        assert_eq!(SealedPage::newer(Some(low), Some(high)), Some(high));
        assert_eq!(SealedPage::newer(None, Some(low)), Some(low));
        assert_eq!(SealedPage::older(Some(low), Some(high)), Some(low));
        assert_eq!(SealedPage::older(Some(high), None), Some(high));
        assert_eq!(SealedPage::older(None, None), None);
    }
}
