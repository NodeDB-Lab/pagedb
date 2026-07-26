//! Structural integrity checker. Opens a pagedb directory and reports basic
//! structural facts: header validates, catalog walks cleanly, segment count.
//! With `--deep`, additionally walks every page in main.db and every segment
//! file, verifying AEAD tags, structural invariants, orphan pages, and
//! catalog–disk consistency.

#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]

#[cfg(not(target_arch = "wasm32"))]
mod cli;
#[cfg(not(target_arch = "wasm32"))]
mod run;

#[cfg(target_arch = "wasm32")]
fn main() {
    // pagedb-fsck is a native-only tool; it is not functional on wasm32.
}

#[cfg(not(target_arch = "wasm32"))]
fn main() -> std::process::ExitCode {
    run::execute()
}
