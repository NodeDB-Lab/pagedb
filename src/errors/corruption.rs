use super::Evictable;
use crate::RealmId;

/// Per-reason detail for [`PagedbError::Corruption`](crate::PagedbError::Corruption). Each variant carries exactly the
/// fields the failure-mode contract specifies — no optional fields, no field reuse across
/// reasons.
#[non_exhaustive]
#[derive(Debug)]
pub enum CorruptionDetail {
    /// A segment file authenticates under this DB's HK but its `parent_file_id` belongs
    /// to a different `main.db`. Fail closed; never promote, never silently accept.
    ForeignSegment {
        realm_id: RealmId,
        name: String,
        segment_id: [u8; 16],
        footer_parent_file_id: [u8; 16],
        expected_parent_file_id: [u8; 16],
    },
    /// Footer HK-MAC failed, so the file's contents cannot be trusted to be
    /// what the catalog references.
    ///
    /// Raised only where the *trusted* identity is already in hand — the
    /// catalog row that routed the read — because the footer's own cleartext
    /// identity fields are exactly what failed to authenticate. A footer that
    /// is unreadable for some other reason is [`Self::FooterFramingInvalid`].
    ///
    /// Carries the id rather than the embedder's name: segment files are
    /// identity-keyed, so the id is what locates the bytes, and the name is a
    /// catalog fact the authenticating layer does not have.
    ///
    /// The file is left in place: pagedb never auto-GCs a catalog-referenced
    /// segment, since that would destroy forensics and possibly recoverable
    /// bytes. Quarantine is the embedder's call, via `WriteTxn::unlink_segment`.
    FooterUnverifiable {
        realm_id: RealmId,
        segment_id: [u8; 16],
    },
    /// Authenticated segment metadata differs from its trusted catalog routing entry.
    SegmentMetadataMismatch { field: &'static str },
    /// Segment file geometry cannot safely locate its authenticated footer.
    SegmentGeometryInvalid { field: &'static str },
    /// Authenticated catalog-tree row bytes do not form a valid key/value pair
    /// for the row's table — segment routing, rekey state, counters, quotas, or
    /// commit-history metadata.
    CatalogRowInvalid { field: &'static str },
    /// Catalog references a segment whose file is absent from both `seg/` and `seg/.staging/`.
    SegmentMissing {
        realm_id: RealmId,
        name: String,
        segment_id: [u8; 16],
    },
    /// Publication had to promote `seg/.staging/<hex(segment_id)>`, but
    /// neither the staging file nor an already-promoted `seg/<hex(segment_id)>`
    /// exists.
    ///
    /// The durable record says this segment was published; the bytes are gone.
    /// Carries only the segment id because that is the whole identity here —
    /// paths are identity-keyed, and the promote work item is recorded by id,
    /// not by the embedder-visible name.
    StagingMissing { segment_id: [u8; 16] },
    /// Per-page AEAD tag verification failed during a read.
    ///
    /// `segment_id` is `None` for a main.db page. `evictable` is the segment's
    /// declared quarantine policy when the read went through a catalog-routed
    /// segment reader, and `None` when the page was read below that layer
    /// (the pager knows page identity but not catalog metadata). It is a hint
    /// for the embedder: the read itself never evicts anything.
    PageUnverifiable {
        realm_id: RealmId,
        segment_id: Option<[u8; 16]>,
        page_id: u64,
        evictable: Option<Evictable>,
    },
    /// Footer manifest AEAD tag verification failed.
    ManifestUnverifiable {
        realm_id: RealmId,
        segment_id: [u8; 16],
    },
    /// No copy of the main.db A/B structural header could be verified, so the
    /// database has no trustworthy root to open from.
    ///
    /// Reserved for the unrecoverable *both copies failed* case. A single copy
    /// that fails its framing or HK-MAC — which the surviving copy may still
    /// rescue — is [`Self::StructuralHeaderInvalid`].
    HeaderUnverifiable,
    /// One structural header copy is unusable: its magic, a reserved field, its
    /// zero tail, or its HK-MAC did not hold.
    ///
    /// `header` names which header (`"main.db"` or `"segment"`) and `field`
    /// what failed. Recoverable in principle — the caller may have another
    /// copy — unlike [`Self::HeaderUnverifiable`].
    StructuralHeaderInvalid {
        header: &'static str,
        field: &'static str,
    },
    /// A segment footer's cleartext framing cannot be trusted to locate the
    /// authenticated footer at all: a bad magic, an unaccepted format version,
    /// a manifest offset or length that does not fit the page.
    ///
    /// A caller that holds the segment's trusted identity checks the footer's
    /// HK-MAC first and reports [`Self::FooterUnverifiable`] instead, so this
    /// variant means the framing itself is wrong, not that authentication
    /// failed.
    FooterFramingInvalid { field: &'static str },
    /// An authenticated B+ tree node body is not structurally valid.
    ///
    /// The bytes are what some holder of the key wrote, but not what a correct
    /// writer would have written: a length, a slot-directory entry, or a
    /// discriminant that the decoders and zero-copy accessors would otherwise
    /// use directly as a slice index is out of range.
    NodeBodyMalformed { field: &'static str },
    /// A B+ tree node is not the kind the reader expected.
    ///
    /// `page_id` is present when the disagreement is between a page's
    /// *authenticated* envelope kind and the kind its own body claims — a
    /// mis-tagged page, which is a corruption of routing rather than of
    /// content — and absent when a decoder was simply handed the other node
    /// kind.
    NodeKindMismatch {
        page_id: Option<u64>,
        expected: &'static str,
        found: &'static str,
    },
    /// An authenticated overflow page body is not structurally valid, or a
    /// chain's assembled length disagrees with the total its root declared.
    OverflowBodyMalformed { field: &'static str },
    /// An apply-journal record cannot be decoded from its authenticated bytes.
    JournalRecordMalformed { field: &'static str },
    /// A snapshot manifest, or an entry in a snapshot directory, is unusable.
    SnapshotArtifactInvalid { field: &'static str },
    /// A live B+ tree or overflow pointer targets a reserved page (0..=3).
    /// Pages 0 and 1 are the A/B structural headers and 2..=3 the apply-journal;
    /// no live tree pointer may reach them, so this is a wild pointer or a
    /// use-after-free that handed a reserved page back to an allocation.
    ReservedPageReferenced {
        parent_page_id: u64,
        child_page_id: u64,
    },
    /// An overflow chain revisited a page it had already walked, so the chain
    /// has no terminator. Distinct from a truncated chain: the links
    /// authenticate, they just form a loop.
    OverflowChainCycle { root_page_id: u64, page_id: u64 },
    /// A linked page structure revisited a page it had already walked, so the
    /// walk has no terminator.
    ///
    /// The overflow-chain form is [`Self::OverflowChainCycle`], which can also
    /// name the chain's root. This is the general case — a B+ tree root-to-leaf
    /// descent, a leaf sibling walk, or the durable free-list chain — where
    /// `structure` says which walk found the loop and `page_id` is the page it
    /// reached twice. Every link authenticates; they simply form a loop, which
    /// no honest writer can produce.
    PageChainCycle {
        structure: &'static str,
        page_id: u64,
    },
    /// A leaf's persisted right-sibling link disagrees with the leaf its parent
    /// path says comes next.
    ///
    /// Both encode "the next leaf", so both must name it. A disagreement means
    /// one of them outlived the page it points at — a sibling link left behind
    /// by a page that was freed and handed to another node, or a parent whose
    /// child pointer was rewritten without its leaves. `parent_next` is `None`
    /// when the parent path has no successor at all yet the leaf still claims
    /// one.
    LeafSiblingMismatch {
        leaf_page_id: u64,
        right_sibling: u64,
        parent_next: Option<u64>,
    },
    /// One physical page was reached twice in a single traversal under two
    /// incompatible page kinds.
    ///
    /// Distinct from [`Self::NodeKindMismatch`], which is a disagreement inside
    /// one page. Here every read authenticates and every body decodes: two live
    /// references simply claim the same page for different roles, so at least
    /// one of them points at a page that was freed and handed to another
    /// object while still linked.
    PageKindAliased {
        page_id: u64,
        walked_as: &'static str,
        referenced_as: &'static str,
    },
}
