//! Structural integrity checker. Opens a pagedb directory and reports basic
//! structural facts: header validates, catalog walks cleanly, segment count.
//! With `--deep`, additionally walks every page in main.db and every segment
//! file, verifying AEAD tags, structural invariants, orphan pages, and
//! catalog–disk consistency.

#[cfg(not(target_arch = "wasm32"))]
use std::process::ExitCode;

#[cfg(not(target_arch = "wasm32"))]
use pagedb::options::{OpenOptions, RetainPolicy};
#[cfg(not(target_arch = "wasm32"))]
use pagedb::vfs::tokio_backend::TokioVfs;
#[cfg(not(target_arch = "wasm32"))]
use pagedb::{Db, RealmId, run_deep_walk};

#[cfg(not(target_arch = "wasm32"))]
struct CliArgs {
    path: String,
    deep: bool,
    realm_hex: Option<String>,
    kek_hex: Option<String>,
}

#[cfg(target_arch = "wasm32")]
fn main() {
    // pagedb-fsck is a native-only tool; it is not functional on wasm32.
}

#[cfg(not(target_arch = "wasm32"))]
fn usage() {
    eprintln!("usage: pagedb-fsck <path> [--deep] [--realm <hex16>] [<hex-kek>]");
    eprintln!("(KEK may also be set via PAGEDB_KEK; defaults to zeros.");
    eprintln!(" --realm defaults to all-ones; nodedb-lite stores use all-zeros.)");
}

#[cfg(not(target_arch = "wasm32"))]
fn parse_args(args: &[String]) -> Result<CliArgs, String> {
    let Some(path) = args.get(1) else {
        return Err("database path is required".to_string());
    };
    if path.starts_with("--") {
        return Err(format!("unknown option {path}"));
    }

    let mut deep = false;
    let mut realm_hex = None;
    let mut kek_hex = None;
    let mut index = 2;
    while index < args.len() {
        match args[index].as_str() {
            "--deep" => {
                if deep {
                    return Err("duplicate --deep".to_string());
                }
                deep = true;
                index += 1;
            }
            "--realm" => {
                if realm_hex.is_some() {
                    return Err("duplicate --realm".to_string());
                }
                let value = args
                    .get(index + 1)
                    .filter(|value| !value.starts_with("--"))
                    .ok_or_else(|| "--realm requires a 32-character hex value".to_string())?;
                realm_hex = Some(value.clone());
                index += 2;
            }
            option if option.starts_with("--") => {
                return Err(format!("unknown option {option}"));
            }
            value => {
                if kek_hex.is_some() {
                    return Err("multiple KEK values supplied".to_string());
                }
                kek_hex = Some(value.to_string());
                index += 1;
            }
        }
    }

    Ok(CliArgs {
        path: path.clone(),
        deep,
        realm_hex,
        kek_hex,
    })
}

#[cfg(not(target_arch = "wasm32"))]
#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let parsed = match parse_args(&args) {
        Ok(parsed) => parsed,
        Err(error) => {
            eprintln!("pagedb-fsck: {error}");
            usage();
            return ExitCode::from(2);
        }
    };
    let CliArgs {
        path,
        deep,
        realm_hex,
        mut kek_hex,
    } = parsed;

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

    let realm = match realm_hex {
        Some(s) => match pagedb::hex::parse_hex::<16>(&s) {
            Some(r) => RealmId::new(r),
            None => {
                eprintln!("invalid hex realm (must be 32 hex chars / 16 bytes)");
                return ExitCode::from(2);
            }
        },
        None => RealmId::new([1; 16]),
    };

    let vfs = TokioVfs::new(path);

    // Read-only: a checker must never mutate the store it inspects. Match
    // nodedb-lite's open options (commit history disabled) so lite stores open.
    let opts = OpenOptions::default().with_commit_history_retain(RetainPolicy::Disabled);
    let db = match Db::open_read_only(vfs, kek, 4096, realm, opts).await {
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
