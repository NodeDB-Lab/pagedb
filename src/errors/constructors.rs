use super::{CorruptionDetail, PagedbError, QuotaKind};
use crate::{CommitId, DbMode, RealmId};

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

    /// Canonical constructor for a mode gate turning an operation away.
    ///
    /// Every gate funnels through here so the pair an embedder acts on —
    /// what it asked for, and the mode that would have served it — can never
    /// be assembled inconsistently at a call site.
    #[must_use]
    pub const fn wrong_mode(operation: &'static str, required: DbMode, actual: DbMode) -> Self {
        Self::WrongMode {
            operation,
            required,
            actual,
        }
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
