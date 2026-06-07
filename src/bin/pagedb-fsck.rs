//! Structural integrity checker. Opens a pagedb directory and reports basic
//! structural facts: header validates, catalog walks cleanly, segment count.
//! With `--deep`, additionally walks every page in main.db and every segment
//! file, verifying AEAD tags, structural invariants, orphan pages, and
//! catalog–disk consistency.

use std::process::ExitCode;

#[cfg(not(target_arch = "wasm32"))]
use pagedb::vfs::tokio_backend::TokioVfs;
#[cfg(not(target_arch = "wasm32"))]
use pagedb::{Db, RealmId, run_deep_walk};

#[cfg(target_arch = "wasm32")]
fn main() {
    // pagedb-fsck is a native-only tool; it is not functional on wasm32.
}

#[cfg(not(target_arch = "wasm32"))]
#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: pagedb-fsck <path> [--deep] [<hex-kek>]");
        eprintln!("(KEK may also be set via PAGEDB_KEK env var; defaults to zeros)");
        return ExitCode::from(2);
    }
    let path = &args[1];

    // Parse optional flags and positional KEK.
    let mut deep = false;
    let mut kek_hex: Option<String> = None;
    for arg in args.iter().skip(2) {
        if arg == "--deep" {
            deep = true;
        } else if kek_hex.is_none() {
            kek_hex = Some(arg.clone());
        }
    }
    if kek_hex.is_none() {
        kek_hex = std::env::var("PAGEDB_KEK").ok();
    }

    let kek = match kek_hex {
        Some(s) => match pagedb::hex::parse_hex::<32>(&s) {
            Some(k) => k,
            None => {
                eprintln!("invalid hex KEK (must be 64 hex chars / 32 bytes)");
                return ExitCode::from(2);
            }
        },
        None => [0u8; 32],
    };

    let vfs = TokioVfs::new(path);
    let realm = RealmId::new([1; 16]);

    let db = match Db::open_existing(vfs, kek, 4096, realm).await {
        Ok(db) => db,
        Err(e) => {
            eprintln!("pagedb-fsck: error opening directory: {e}");
            return ExitCode::FAILURE;
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
        Ok(r) => r,
        Err(e) => {
            eprintln!("pagedb-fsck: deep walk failed: {e}");
            return ExitCode::FAILURE;
        }
    };

    let stdout = std::io::stdout();
    let _ = report.write_text(&mut stdout.lock());

    if report.is_clean() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
