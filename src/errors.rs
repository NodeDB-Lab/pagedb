//! Typed error spine. All domain errors land in `PagedbError`; sub-errors From-convert in.

use crate::{CommitId, RealmId};

/// Authoritative error type for every fallible operation in this crate.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum PagedbError {
    /// A page or footer's AEAD tag did not verify against its authenticated
    /// bytes, and the failure could not be attributed to a more specific
    /// corruption reason. Raised on the segment page decrypt-retry path (all
    /// candidate page kinds failed) and inside the raw cipher open call.
    /// Treat the containing file or page as untrustworthy; a fuller
    /// diagnosis usually surfaces as one of the [`CorruptionDetail`]
    /// variants instead, so see those first when triaging.
    #[error("checksum / AEAD tag verification failed")]
    ChecksumFailure,

    /// The in-memory epoch keyring has no master key installed for the
    /// requested `(mk_epoch, cipher_id)` pair. Happens when a handle is
    /// asked to decrypt or derive under an epoch it was never given key
    /// material for — typically a rekey counterpart key that was not
    /// supplied on resume. The caller must install the missing epoch's key
    /// (e.g. via the rekey resume path, which takes both KEKs) before
    /// retrying.
    #[error("required persisted key is unavailable: mk_epoch={mk_epoch} cipher_id={cipher_id}")]
    MissingPersistedKey { mk_epoch: u64, cipher_id: u8 },

    #[error("corruption: {0:?}")]
    Corruption(CorruptionDetail),

    /// A realm exceeded one of the caps recorded in its
    /// [`RealmQuotas`](crate::RealmQuotas) row — page count, dirty-page
    /// count, scratch-page count, or segment bytes, per `kind`. The
    /// transaction that would have crossed the limit is refused; the caller
    /// must free space in that realm (delete data, commit and let
    /// reclamation run) or raise the configured quota before retrying.
    #[error("quota exceeded: realm={realm:?} kind={kind:?} used={used} limit={limit}")]
    Quota {
        realm: RealmId,
        kind: QuotaKind,
        used: u64,
        limit: u64,
    },

    /// The VFS backend reported the underlying storage device or filesystem
    /// is full. Not raised by any production code path today — it exists
    /// for VFS backends to report device-level exhaustion distinctly from a
    /// generic [`Self::Io`] error; a caller that sees it should free disk
    /// space or point the store at a volume with headroom.
    #[error("no space (VFS-level exhaustion)")]
    NoSpace,

    /// A nonce generator's 48-bit per-file counter reached its maximum and
    /// cannot issue another nonce without risking reuse under the same key.
    /// The file (main.db or a segment) must be rekeyed to a fresh epoch
    /// before any further page can be encrypted into it.
    #[error("nonce counter exhausted (per-file 2^48 limit reached); rekey required")]
    NonceCounterExhausted,

    /// An internal size or offset computation — page offset, extent
    /// capacity, length conversion between integer widths — would have
    /// overflowed. `operation` names what was being computed. Not
    /// recoverable by retrying with the same input; the caller must reduce
    /// whatever value (payload size, page count) drove the computation out
    /// of range.
    #[error("arithmetic overflow while computing {operation}")]
    ArithmeticOverflow { operation: &'static str },

    /// The handle is open in a mode that does not permit the attempted
    /// write. Raised by VFS backends when a file was opened read-only and by
    /// the pager for a handle without write access. Only `Standalone` and
    /// `Follower` handles may write; `ReadOnly` and `Observer` handles must
    /// reopen (or promote, for a frozen reader) before writing.
    #[error("read-only handle")]
    ReadOnly,

    /// A frozen-reader (`ReadOnly`) handle tried to acquire the writer
    /// sentinel while a `Standalone` or `Follower` writer already holds it.
    /// Only one writer may be open on a store at a time; retry once the
    /// existing writer closes, or open in a mode that does not need the
    /// writer lock.
    #[error("writer already present")]
    WriterPresent,

    /// A `Standalone`/`Follower` writer, or a `ReadOnly` promotion to
    /// `Follower`, tried to acquire the writer sentinel while a frozen
    /// (`ReadOnly`) reader already holds the frozen-readers lock. Writer
    /// modes and frozen-reader mode are mutually exclusive on the same
    /// store; retry once every frozen reader closes.
    #[error("readers present")]
    ReadersPresent,

    /// A writer-mode handle (`Standalone` or `Follower`) tried to acquire
    /// the writer sentinel while another writer already holds it. Distinct
    /// from [`Self::WriterPresent`], which is the frozen-reader side of the
    /// same contention. Only one writer handle may be open on a store at a
    /// time; close the existing writer first.
    #[error("already open")]
    AlreadyOpen,

    /// A shared or exclusive VFS-level lock could not be acquired because
    /// another handle already holds a conflicting lock on the same path.
    /// Transient — retry after the contending handle releases the lock, or
    /// treat as a longer-lived open-mode conflict if it persists.
    #[error("path lock contention")]
    AlreadyLocked,

    /// `Db::open` found a directory left by an interrupted `restore_from`
    /// that was never promoted to a live store. Restored directories must be
    /// explicitly promoted before they can be opened normally; open with the
    /// restore-completion path (or discard the directory and restore again)
    /// instead of the standard open.
    #[error("restored directory not promoted")]
    RestoredNotPromoted,

    /// `apply_incremental` was called on a handle that is not in `Follower`
    /// mode. Only a `Follower` handle has the base-commit identity an
    /// incremental apply reconciles against; open the handle as `Follower`
    /// (e.g. via `promote_to_follower`) before calling `apply_incremental`.
    #[error("identity forked; apply_incremental refused")]
    IdentityForked,

    /// An incremental snapshot's manifest disagrees with this handle's
    /// current identity or reader-visible state in a way that makes the
    /// snapshot inapplicable — `field` names which check failed (e.g. a
    /// mismatched root or base commit). Distinct from
    /// [`CorruptionDetail::SnapshotArtifactInvalid`]: the manifest itself is
    /// well-formed, it just does not describe a target this handle can
    /// reach. Apply a snapshot whose base matches this handle's state.
    #[error("incremental snapshot is incompatible: {field}")]
    SnapshotIncompatible { field: &'static str },

    /// A delta record names a page the base commit's readers can still reach.
    ///
    /// A delta is defined as target-reachable minus base-reader-visible, so no
    /// well-formed export produces such a record: the pages both sides of the
    /// protocol can name are exactly the ones it must not carry. Raised before
    /// anything is staged.
    ///
    /// Recycling ids the *follower's own* free-list chain or commit-history tree
    /// occupies is not this condition and never raises it. The producer cannot
    /// see those pages, so it cannot avoid them; the apply relocates both
    /// structures out of the incoming page space instead of refusing an
    /// otherwise-healthy delta.
    ///
    /// Not a corruption of this store: both states are internally sound, they
    /// simply cannot be related by this delta — which is why this is distinct
    /// from [`CorruptionDetail::SnapshotArtifactInvalid`]. The remedy is a full
    /// snapshot or a nearer base commit.
    #[error("incremental snapshot would overwrite base-live page {page_id}")]
    SnapshotBasePageReused { page_id: u64 },

    /// The durable A/B header names a commit whose apply-journal actions
    /// (a pending incremental-apply reconciliation) could not be replayed or
    /// reconciled on this open. The handle is poisoned at `commit`; the
    /// remedy is a fresh `Db::open`, which retries journal replay from
    /// scratch rather than continuing on a handle that may hold
    /// partially-applied in-memory state.
    #[error("commit {commit:?} is durable but unpublished; reopen required")]
    DurablyCommittedButUnpublished { commit: CommitId },

    /// A rekey resume began writing pages under the target epoch — an
    /// operation with no safe in-process rollback — and then failed before
    /// recovery could complete. The handle is poisoned at `commit` and
    /// `source` carries the underlying failure. The remedy is the same as
    /// [`Self::DurablyCommittedButUnpublished`]: reopen the store, which
    /// drives recovery from the durable header rather than resuming on a
    /// handle with mixed-epoch state in flight.
    #[error("rekey activated a target epoch at commit {commit:?}; reopen required: {source}")]
    RekeyTargetEpochActivated {
        commit: CommitId,
        #[source]
        source: Box<PagedbError>,
    },

    /// `begin_read_at(commit)` named a commit that has been pruned from the
    /// commit-history index (by [`RetainPolicy`](crate::RetainPolicy)) and
    /// is no longer reachable. `oldest_available` names the oldest commit a
    /// point-in-time read can still target; request a commit at or after it,
    /// or widen the retention policy before the commit is needed again.
    #[error("commit {commit:?} gone; oldest_available={oldest_available:?}")]
    CommitGone {
        commit: CommitId,
        oldest_available: CommitId,
    },

    /// No row or resource matched the given key. Reused across several
    /// lookups: a catalog/segment row absent from its tree, a `main.db`
    /// missing under a mode that requires it to already exist, or a segment
    /// extent index with no entry at the requested `start_page_id`.
    /// Check the operation that raised it for which of these applies; the
    /// caller's next step is usually to treat the key as absent rather than
    /// retry.
    #[error("not found")]
    NotFound,

    /// `link_segment` was called with a `name` that already has a catalog
    /// row in this realm. Names are unique per realm; `unlink_segment` or
    /// `replace_segment` the existing entry first, or choose a different
    /// name.
    #[error("already linked")]
    AlreadyLinked,

    /// `unlink_segment` or `replace_segment` named a segment that has no
    /// catalog row in this realm — either it was never linked or a
    /// concurrent operation already removed it. Nothing to do; the caller
    /// should not retry the same unlink.
    #[error("not linked")]
    NotLinked,

    /// A segment or counter name exceeds `MAX_SEGMENT_NAME_LEN` bytes.
    /// Shorten the name before retrying; the catalog key encoding has no
    /// escape for longer names.
    #[error("name too long")]
    NameTooLong,

    /// A page read or cache access was asked for a page kind that does not
    /// belong to the file it targets (a segment kind requested through the
    /// main-db read path, or vice versa), or a decrypted page's kind byte
    /// did not match any kind the caller was willing to accept. Indicates a
    /// caller bug rather than on-disk corruption — the authenticated
    /// envelope kind mismatches are instead reported as
    /// [`CorruptionDetail::NodeKindMismatch`].
    #[error("illegal page kind for segment")]
    IllegalPageKind,

    /// A value, key, or extent count would not fit its on-disk encoding —
    /// a leaf record exceeding the page's capacity even as an overflow
    /// reference, a separator too long for an internal node, or an extent
    /// page count that overflows `u32`. Shrink the value/key or split the
    /// write into multiple extents before retrying.
    #[error("payload too large")]
    PayloadTooLarge,

    /// `SegmentWriter::append_extent` was called with an empty page list.
    /// An extent must span at least one page; pass a non-empty slice.
    #[error("extent must contain at least one page")]
    EmptyExtent,

    /// A segment footer manifest exceeds the format's maximum manifest
    /// length for the segment's page size. Shrink the manifest payload
    /// before calling `set_manifest` / sealing the segment.
    #[error("manifest too large")]
    ManifestTooLarge,

    /// `mmap_view` was asked to map `segment_bytes` of decrypted scratch but
    /// only `available_bytes` remain under
    /// [`OpenOptions::mmap_view_scratch_bytes`](crate::OpenOptions). Drop an
    /// existing `MmapView` to free budget, request a smaller extent, or
    /// raise the configured budget.
    #[error(
        "mmap-view quota exceeded: segment_bytes={segment_bytes} available_bytes={available_bytes}"
    )]
    MmapViewQuotaExceeded {
        segment_bytes: u64,
        available_bytes: u64,
    },

    /// Under [`ReaderStallPolicy::AbortOldest`](crate::ReaderStallPolicy),
    /// this is the oldest conflicting reader whose pin is blocking
    /// reclamation the writer needs — its next operation is aborted so the
    /// writer can proceed. Also returned by a `MainDbNonceGen` when a nonce
    /// is requested past the current anchor budget and the caller must
    /// persist `pending_anchor()` and call `commit_anchor` before issuing
    /// more. In the reader case, drop the reader and retry with a fresh
    /// snapshot; in the nonce case, commit the pending anchor first.
    #[error("aborted (reader stall policy)")]
    Aborted,

    /// `WriteTxn::put_append` was called with a key that is not strictly
    /// greater than the previously-appended key. The append-mode API
    /// requires monotonically increasing keys; mixing it with regular
    /// `put`/`delete` invalidates the cached rightmost path and the next
    /// `put_append` call must again start strictly above the maximum key
    /// observed so far in this txn.
    #[error("put_append called with non-monotonic key")]
    AppendNotMonotonic,

    /// `BTree::bulk_load` was handed input whose keys are not strictly
    /// increasing — descending, or repeating the same key.
    ///
    /// The sibling of [`Self::AppendNotMonotonic`]: same invariant, different
    /// entry point. Bulk load builds the tree bottom-up from the input order
    /// itself, so unsorted input does not merely misplace a record — it would
    /// produce a tree whose separators do not describe its leaves.
    #[error("bulk_load keys must be strictly increasing")]
    BulkLoadNotMonotonic,

    /// The deferred-free backlog exceeds the configured threshold and
    /// active reader pins prevent draining it.
    #[non_exhaustive]
    #[error(
        "deferred-free backlog of {pages_pending} pages blocked by oldest pinning commit {oldest_pinning_commit}"
    )]
    DeferredFreeBacklog {
        pages_pending: u64,
        oldest_pinning_commit: u64,
    },

    /// Under [`ReaderStallPolicy::Reject`](crate::ReaderStallPolicy), a new
    /// write would need free-list pages that reader pins are preventing the
    /// writer from reclaiming, and no free pages remain. No production call
    /// site raises this today (`Reject` policy's free-list path is exercised
    /// only in `tests/smoke.rs`'s Display-coverage test); when it is wired
    /// up, the caller's remedy is to wait for the pinning readers to close
    /// or switch to `AbortOldest`.
    #[error("free list exhausted")]
    FreeListExhausted,

    /// Under [`ReaderStallPolicy::Reject`](crate::ReaderStallPolicy), a
    /// segment tombstone cannot be finalized because a reader still pins the
    /// truncated range. No production call site raises this today (see
    /// [`Self::FreeListExhausted`] — same policy, same test-only coverage);
    /// the intended remedy is to wait for the pinning reader to close.
    #[error("segment tombstone stalled by reader pin")]
    SegmentTombstoneStalled,

    /// An apply-journal reconciliation deferred a segment tombstone because
    /// a reader still pins the range being truncated; the durable target is
    /// published for new readers, but this transaction returns the error to
    /// signal the tombstone did not complete synchronously. Retry
    /// `retry_pending_apply_journal` (implicitly driven by later opens/GC)
    /// once the pinning reader closes.
    #[error("readers pinning truncated range")]
    ReadersPinningTruncatedRange,

    /// Resuming a rekey whose source and target epochs use different KEKs
    /// (`same_kek == false`) requires both the primary and counterpart KEK,
    /// but only the primary was supplied. Retry the resume with the
    /// counterpart KEK for `source_epoch`/`target_epoch` also provided.
    #[error(
        "rekey resume requires counterpart key for source epoch {source_epoch} and target epoch {target_epoch}"
    )]
    RekeyResumeKeyRequired {
        source_epoch: u64,
        target_epoch: u64,
    },

    /// The KEK(s) supplied to resume a rekey do not reproduce the durable
    /// intent's HK proof for `source_epoch` and/or `target_epoch` — either
    /// the wrong KEK was supplied, or (for a same-KEK rekey) the single
    /// supplied KEK cannot derive both epochs' header keys. Supply the KEK
    /// that was active when the rekey was started.
    #[error(
        "rekey counterpart key does not prove source epoch {source_epoch} for target epoch {target_epoch}"
    )]
    RekeyCounterpartKeyInvalid {
        source_epoch: u64,
        target_epoch: u64,
    },

    /// The durable rekey-intent or rekey-progress catalog row cannot be
    /// admitted — `field` names the check that failed (a missing intent row,
    /// an unexpected `target_mk_epoch`, source/target cipher mismatch, or a
    /// stage that still has segments pending when none were expected). This
    /// is a recorded-state precondition failure, not necessarily on-disk
    /// corruption of the row's bytes (that is
    /// [`CorruptionDetail::CatalogRowInvalid`]); it means the rekey cannot
    /// safely proceed from where it claims to be. Inspect the rekey state
    /// and resume from a consistent stage, or restart the rekey.
    #[error("recorded rekey state is invalid: {field}")]
    RekeyStateInvalid { field: &'static str },

    /// A rekey's replacement segment file (named by durable progress) could
    /// not be opened, is absent from both the live and staging locations, or
    /// fails its size/geometry sanity checks after opening. Because the
    /// replacement id is durable progress, this fails closed rather than
    /// regenerating the file — the caller must restore the missing
    /// replacement file (e.g. from backup) or restart the rekey for this
    /// segment.
    #[error("recorded rekey replacement segment {replacement_segment_id:?} is missing or invalid")]
    RekeyReplacementMissing { replacement_segment_id: [u8; 16] },

    /// A VFS backend reported positional-I/O progress that cannot be true —
    /// more bytes transferred than the caller's remaining buffer.
    ///
    /// Not corruption: nothing on disk is known to be wrong. The backend broke
    /// the [`VfsFile`](crate::vfs::VfsFile) contract, so the reported count
    /// cannot be reasoned about at all and the transfer stops instead of
    /// advancing by a length it cannot trust.
    #[error("vfs backend violated the {operation} contract: {detail}")]
    VfsContractViolated {
        operation: &'static str,
        detail: &'static str,
    },

    /// The requested operation is not implemented by the current backend or
    /// target — e.g. `mmap_view` on WASM (no native mmap), an unknown
    /// on-wire cipher id, or `promote_to_follower` called on a handle that
    /// is not `ReadOnly`. Check the operation's docs for which
    /// backends/modes support it; there is no runtime workaround short of
    /// switching backend, target, or handle mode.
    #[error("unsupported by backend")]
    Unsupported,

    /// The platform's cryptographically secure RNG failed to produce
    /// randomness (nonces, salts, key material). Propagated verbatim from
    /// `getrandom`. Not caller-recoverable beyond retrying — it indicates
    /// the OS entropy source itself is unavailable or refused the request.
    #[error("cryptographically secure randomness unavailable: {0}")]
    Randomness(#[from] getrandom::Error),

    /// An underlying `std::io::Error` from the VFS layer (open, read, write,
    /// sync, rename, lock) that does not map to any of the more specific
    /// variants above. Inspect the wrapped error's `kind()` for the
    /// platform-reported cause.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// Per-reason detail for [`PagedbError::Corruption`]. Each variant carries exactly the
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
    /// Footer HK-MAC failed; segment identity is unverifiable.
    FooterUnverifiable {
        realm_id: RealmId,
        name: String,
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
    /// Pre-link staging file expected but not present.
    StagingMissing {
        realm_id: RealmId,
        name: String,
        segment_id: [u8; 16],
    },
    /// Per-page AEAD tag verification failed during a read.
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
    /// authenticated footer at all.
    ///
    /// Raised before segment identity is known; once it is,
    /// [`Self::FooterUnverifiable`] carries the realm, name, and id.
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

/// Quota failure reason, distinguishing which resource was exhausted.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotaKind {
    Pages,
    DirtyPages,
    ScratchPages,
    SegmentBytes,
}

/// Whether a segment is authoritative or replaceable under quota pressure.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Evictable {
    Authoritative,
    Replaceable,
}

impl PagedbError {
    /// Canonical constructor for corruption errors. Call sites never write
    /// `PagedbError::Corruption { … }` directly.
    ///
    /// This is the one funnel every `CorruptionDetail` variant passes
    /// through — the named constructors below all route here rather than
    /// building `Self::Corruption` themselves — so a single capture call
    /// covers the whole taxonomy. Not `const fn`: `diag::corruption_captured`
    /// is a plain function call (whether it is a live capture or an inert
    /// no-op is a runtime fact — feature flag, target, and whether the host
    /// called `faultbox::init` — not something `const` evaluation can know),
    /// so nothing that reaches it can stay `const`. See the named
    /// constructors below for what that cost the call sites that used to be
    /// `const fn`.
    #[must_use]
    pub fn corruption(detail: CorruptionDetail) -> Self {
        crate::diag::corruption_captured(&detail);
        Self::Corruption(detail)
    }

    /// Canonical constructor for authenticated catalog/file metadata disagreement.
    ///
    /// Was `const fn` before diagnostics capture moved into [`Self::corruption`];
    /// routing through it to reach that one capture point costs `const`-ness
    /// here. No call site in this crate invokes it from a const context
    /// (verified), so the loss is inert in practice.
    #[must_use]
    pub fn segment_metadata_mismatch(field: &'static str) -> Self {
        Self::corruption(CorruptionDetail::SegmentMetadataMismatch { field })
    }

    /// Canonical constructor for malformed segment-file geometry.
    ///
    /// No longer `const fn`, for the same reason as [`Self::segment_metadata_mismatch`].
    #[must_use]
    pub fn segment_geometry_invalid(field: &'static str) -> Self {
        Self::corruption(CorruptionDetail::SegmentGeometryInvalid { field })
    }

    /// Canonical constructor for malformed authenticated catalog rows.
    ///
    /// No longer `const fn`, for the same reason as [`Self::segment_metadata_mismatch`].
    #[must_use]
    pub fn catalog_row_invalid(field: &'static str) -> Self {
        Self::corruption(CorruptionDetail::CatalogRowInvalid { field })
    }

    /// Canonical constructor for one unusable structural header copy.
    ///
    /// No longer `const fn`, for the same reason as [`Self::segment_metadata_mismatch`].
    #[must_use]
    pub fn structural_header_invalid(header: &'static str, field: &'static str) -> Self {
        Self::corruption(CorruptionDetail::StructuralHeaderInvalid { header, field })
    }

    /// Canonical constructor for unusable segment-footer cleartext framing.
    ///
    /// No longer `const fn`, for the same reason as [`Self::segment_metadata_mismatch`].
    #[must_use]
    pub fn footer_framing_invalid(field: &'static str) -> Self {
        Self::corruption(CorruptionDetail::FooterFramingInvalid { field })
    }

    /// Canonical constructor for a structurally invalid B+ tree node body.
    ///
    /// No longer `const fn`, for the same reason as [`Self::segment_metadata_mismatch`].
    #[must_use]
    pub fn node_body_malformed(field: &'static str) -> Self {
        Self::corruption(CorruptionDetail::NodeBodyMalformed { field })
    }

    /// Canonical constructor for a node that is not the expected kind. Pass
    /// `Some(page_id)` when the authenticated envelope kind and the body
    /// disagree, `None` when a decoder was handed the other node kind.
    ///
    /// No longer `const fn`, for the same reason as [`Self::segment_metadata_mismatch`].
    #[must_use]
    pub fn node_kind_mismatch(
        page_id: Option<u64>,
        expected: &'static str,
        found: &'static str,
    ) -> Self {
        Self::corruption(CorruptionDetail::NodeKindMismatch {
            page_id,
            expected,
            found,
        })
    }

    /// Canonical constructor for a structurally invalid overflow page or chain.
    ///
    /// No longer `const fn`, for the same reason as [`Self::segment_metadata_mismatch`].
    #[must_use]
    pub fn overflow_body_malformed(field: &'static str) -> Self {
        Self::corruption(CorruptionDetail::OverflowBodyMalformed { field })
    }

    /// Canonical constructor for an undecodable apply-journal record.
    ///
    /// No longer `const fn`, for the same reason as [`Self::segment_metadata_mismatch`].
    #[must_use]
    pub fn journal_record_malformed(field: &'static str) -> Self {
        Self::corruption(CorruptionDetail::JournalRecordMalformed { field })
    }

    /// Canonical constructor for an unusable snapshot manifest or directory entry.
    ///
    /// No longer `const fn`, for the same reason as [`Self::segment_metadata_mismatch`].
    #[must_use]
    pub fn snapshot_artifact_invalid(field: &'static str) -> Self {
        Self::corruption(CorruptionDetail::SnapshotArtifactInvalid { field })
    }

    /// Canonical constructor for a live tree pointer into a reserved page.
    ///
    /// No longer `const fn`, for the same reason as [`Self::segment_metadata_mismatch`].
    #[must_use]
    pub fn reserved_page_referenced(parent_page_id: u64, child_page_id: u64) -> Self {
        Self::corruption(CorruptionDetail::ReservedPageReferenced {
            parent_page_id,
            child_page_id,
        })
    }

    /// Canonical constructor for a cyclic linked page structure. `structure`
    /// names the walk that found the loop — `"btree_descent"`,
    /// `"leaf_siblings"`, `"free_list"`.
    ///
    /// No longer `const fn`, for the same reason as [`Self::segment_metadata_mismatch`].
    #[must_use]
    pub fn page_chain_cycle(structure: &'static str, page_id: u64) -> Self {
        Self::corruption(CorruptionDetail::PageChainCycle { structure, page_id })
    }

    /// Canonical constructor for a leaf whose sibling link and parent path
    /// disagree about which leaf comes next.
    ///
    /// No longer `const fn`, for the same reason as [`Self::segment_metadata_mismatch`].
    #[must_use]
    pub fn leaf_sibling_mismatch(
        leaf_page_id: u64,
        right_sibling: u64,
        parent_next: Option<u64>,
    ) -> Self {
        Self::corruption(CorruptionDetail::LeafSiblingMismatch {
            leaf_page_id,
            right_sibling,
            parent_next,
        })
    }

    /// Canonical constructor for a cyclic overflow chain.
    ///
    /// No longer `const fn`, for the same reason as [`Self::segment_metadata_mismatch`].
    #[must_use]
    pub fn overflow_chain_cycle(root_page_id: u64, page_id: u64) -> Self {
        Self::corruption(CorruptionDetail::OverflowChainCycle {
            root_page_id,
            page_id,
        })
    }

    /// Canonical constructor for one page claimed by two incompatible
    /// references in a single traversal.
    ///
    /// No longer `const fn`, for the same reason as [`Self::segment_metadata_mismatch`].
    #[must_use]
    pub fn page_kind_aliased(
        page_id: u64,
        walked_as: &'static str,
        referenced_as: &'static str,
    ) -> Self {
        Self::corruption(CorruptionDetail::PageKindAliased {
            page_id,
            walked_as,
            referenced_as,
        })
    }

    /// Canonical constructor for an incremental snapshot that cannot be
    /// applied to this handle's current identity or reader-visible state.
    #[must_use]
    pub const fn snapshot_incompatible(field: &'static str) -> Self {
        Self::SnapshotIncompatible { field }
    }

    /// Canonical constructor for a target state that reuses a base-live page.
    #[must_use]
    pub const fn snapshot_base_page_reused(page_id: u64) -> Self {
        Self::SnapshotBasePageReused { page_id }
    }

    /// Canonical constructor for a handle whose newest durable commit could
    /// not be reconciled into its reader-visible state.
    #[must_use]
    pub const fn durably_committed_but_unpublished(commit: CommitId) -> Self {
        Self::DurablyCommittedButUnpublished { commit }
    }

    /// Canonical constructor for a rekey that cannot safely continue after
    /// activating target-key routing before recovery completes.
    #[must_use]
    pub fn rekey_target_epoch_activated(commit: CommitId, source: PagedbError) -> Self {
        Self::RekeyTargetEpochActivated {
            commit,
            source: Box::new(source),
        }
    }

    /// Canonical constructor for arithmetic-overflow errors.
    #[must_use]
    pub const fn arithmetic_overflow(operation: &'static str) -> Self {
        Self::ArithmeticOverflow { operation }
    }

    /// Canonical constructor for a VFS backend that broke the positional-I/O
    /// contract.
    #[must_use]
    pub const fn vfs_contract_violated(operation: &'static str, detail: &'static str) -> Self {
        Self::VfsContractViolated { operation, detail }
    }

    /// Canonical constructor for a rekey admission that needs both KEKs.
    #[must_use]
    pub const fn rekey_resume_key_required(source_epoch: u64, target_epoch: u64) -> Self {
        Self::RekeyResumeKeyRequired {
            source_epoch,
            target_epoch,
        }
    }

    /// Canonical constructor for counterpart material that fails the durable proof.
    #[must_use]
    pub const fn rekey_counterpart_key_invalid(source_epoch: u64, target_epoch: u64) -> Self {
        Self::RekeyCounterpartKeyInvalid {
            source_epoch,
            target_epoch,
        }
    }

    /// Canonical constructor for a durable rekey intent that cannot be admitted.
    #[must_use]
    pub const fn rekey_state_invalid(field: &'static str) -> Self {
        Self::RekeyStateInvalid { field }
    }

    /// Canonical constructor for deferred-free backlog errors.
    #[must_use]
    pub fn deferred_free_backlog(pages_pending: u64, oldest_pinning_commit: u64) -> Self {
        Self::DeferredFreeBacklog {
            pages_pending,
            oldest_pinning_commit,
        }
    }

    /// Canonical constructor for quota errors.
    #[must_use]
    pub fn quota(realm: RealmId, kind: QuotaKind, used: u64, limit: u64) -> Self {
        Self::Quota {
            realm,
            kind,
            used,
            limit,
        }
    }
}
