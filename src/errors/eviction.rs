/// Whether a segment is authoritative or replaceable under quota pressure.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Evictable {
    Authoritative,
    Replaceable,
}
