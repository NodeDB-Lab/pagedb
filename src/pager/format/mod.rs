//! On-wire page envelopes: Format A (Data Page), Format B (Structural
//! Header), Format C (Segment Footer).

pub(crate) mod data_page;
pub(crate) mod page_kind;
pub(crate) mod segment_footer;
pub(crate) mod structural_header;
