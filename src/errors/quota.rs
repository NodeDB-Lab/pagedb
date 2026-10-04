/// Quota failure reason, distinguishing which resource was exhausted.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotaKind {
    Pages,
    DirtyPages,
    ScratchPages,
    SegmentBytes,
}
