//! Pager tests that exercise page envelopes, the A/B header protocol and the
//! durable free-list. They live here rather than in `tests/` because the
//! envelope, header and free-list codecs are crate-internal.
#![allow(clippy::pedantic)]

mod format_version_mismatch;
mod freelist_chain;
mod generated_freelist_chain;
mod generated_page_envelopes;
mod header;
