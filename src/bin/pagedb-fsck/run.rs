//! Execution and exit-code policy for `pagedb-fsck`.
//!
//! The exit code is this tool's real output for anything that is not a human
//! reading stdout. A checker that answers "not zero" to an invalid command, an
//! absent store, a wrong key, and an actually damaged database has told a
//! supervisor nothing it can act on, so each of those classes gets its own
//! code and the class is decided before the corresponding work starts.

use std::process::ExitCode;

use pagedb::options::{OpenOptions, RetainPolicy};
use pagedb::vfs::tokio_backend::TokioVfs;
use pagedb::{Db, RealmId, run_deep_walk};

use crate::cli::{self, CliArgs, CliRequest};

/// The deep walk failed, or the report it produced was not clean.
const EXIT_INTEGRITY: u8 = 1;
/// The command line was invalid. Nothing was opened and nothing was read.
const EXIT_USAGE: u8 = 2;
/// The store could not be opened, or the report could not be delivered.
const EXIT_OPERATIONAL: u8 = 3;

#[tokio::main(flavor = "current_thread")]
pub async fn execute() -> ExitCode {
    let command_line: Vec<std::ffi::OsString> = std::env::args_os().collect();
    let request = match cli::parse(&command_line) {
        Ok(request) => request,
        Err(error) => {
            eprintln!("pagedb-fsck: {error}");
            eprintln!("{}", cli::USAGE);
            return ExitCode::from(EXIT_USAGE);
        }
    };

    match request {
        CliRequest::Help => {
            println!("{}", cli::USAGE);
            ExitCode::SUCCESS
        }
        CliRequest::Check(args) => check(args).await,
    }
}

async fn check(args: CliArgs) -> ExitCode {
    let CliArgs {
        path,
        deep,
        page_size,
        realm_hex,
        kek_hex,
    } = args;

    // An explicit positional key wins over the environment, which wins over
    // the all-zero default.
    let kek_hex = kek_hex.or_else(|| std::env::var("PAGEDB_KEK").ok());
    let kek = match kek_hex.as_deref().map(pagedb::hex::parse_hex::<32>) {
        Some(Some(kek)) => kek,
        Some(None) => {
            eprintln!("pagedb-fsck: invalid hex KEK (must be 64 hex chars / 32 bytes)");
            return ExitCode::from(EXIT_USAGE);
        }
        None => [0u8; 32],
    };

    let realm = match realm_hex.as_deref().map(pagedb::hex::parse_hex::<16>) {
        Some(Some(realm)) => RealmId::new(realm),
        Some(None) => {
            eprintln!("pagedb-fsck: invalid hex realm (must be 32 hex chars / 16 bytes)");
            return ExitCode::from(EXIT_USAGE);
        }
        None => RealmId::new(cli::DEFAULT_REALM),
    };

    let vfs = TokioVfs::new(&path);

    // Read-only: a checker must never mutate the store it inspects. Match
    // nodedb-lite's open options (commit history disabled) so lite stores open.
    let opts = OpenOptions::default().with_commit_history_retain(RetainPolicy::Disabled);
    let db = match Db::open_read_only(vfs, kek, page_size, realm, opts).await {
        Ok(db) => db,
        Err(error) => {
            eprintln!("pagedb-fsck: error opening directory: {error}");
            // A failed open is indistinguishable at the byte level from a
            // correct key applied at the wrong page size or realm, so name the
            // assumptions rather than let the operator hunt for corruption
            // that is not there.
            eprintln!(
                "pagedb-fsck: assumed page size {page_size} and the given realm must both \
                 match the store (see --page-size, --realm)"
            );
            return ExitCode::from(EXIT_OPERATIONAL);
        }
    };

    println!("pagedb-fsck: structural open OK");
    println!("  latest_commit = {:?}", db.latest_commit());

    if !deep {
        println!("pagedb-fsck: OK");
        return ExitCode::SUCCESS;
    }

    println!("pagedb-fsck: running deep walk...");
    let report = match run_deep_walk(&db).await {
        Ok(report) => report,
        Err(error) => {
            eprintln!("pagedb-fsck: deep walk failed: {error}");
            return ExitCode::from(EXIT_INTEGRITY);
        }
    };

    // A verdict that could not be delivered is not a verdict. Exiting zero on
    // a broken stdout would report "clean" to a caller that never saw why.
    if let Err(error) = report.write_text(&mut std::io::stdout().lock()) {
        eprintln!("pagedb-fsck: failed to write report: {error}");
        return ExitCode::from(EXIT_OPERATIONAL);
    }

    if report.is_clean() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(EXIT_INTEGRITY)
    }
}
