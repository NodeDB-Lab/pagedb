//! Command-line grammar for `pagedb-fsck`.
//!
//! The grammar is resolved before any key decoding, VFS construction, or
//! database open. `fsck` is a diagnostic trust boundary: an operator has to be
//! able to separate "I typed the command wrong" from "the store will not open"
//! from "the store is damaged". A parser that silently reinterprets an
//! unrecognised token as a key or a directory destroys that distinction before
//! the check has even started, and reports a filesystem problem that does not
//! exist.

use std::ffi::OsString;
use std::fmt;
use std::path::PathBuf;

/// Page size assumed when `--page-size` is absent.
///
/// This has to match the size the store was created with. Header B lives at
/// byte offset `page_size`, so a wrong value reads the wrong bytes and reports
/// an unverifiable header rather than a size mismatch.
pub const DEFAULT_PAGE_SIZE: usize = 4096;

/// Realm assumed when `--realm` is absent. nodedb-lite stores use all-zeros.
pub const DEFAULT_REALM: [u8; 16] = [1; 16];

/// What `--realm` accepts, quoted back in the diagnostic when it is missing.
const REALM_VALUE: &str = "a 32-character hex value";

/// What `--page-size` accepts, quoted back in the diagnostic when it is missing.
const PAGE_SIZE_VALUE: &str = "a positive decimal byte count";

/// The canonical grammar, printed on `--help` and after any parse failure.
pub const USAGE: &str = "\
usage: pagedb-fsck <path> [--deep] [--page-size <bytes>] [--realm <hex16>] [<hex-kek>]

  <path>               directory containing main.db and seg/
  --deep               authenticate and walk every page, not just the header
  --page-size <bytes>  page size the store was created with (default 4096)
  --realm <hex16>      32 hex characters; default all-ones, nodedb-lite uses all-zeros
  <hex-kek>            64 hex characters; required, or supply it in PAGEDB_KEK
  -h, --help           print this message

No option may be repeated, and a path beginning with '-' must be written as
'./-path' so it is not mistaken for an option.

exit codes:
  0  opened cleanly, and with --deep the report was clean
  1  an integrity problem was found
  2  the command line was invalid; the store was never touched
  3  the store could not be opened, or the report could not be written";

/// Why a command line was rejected.
///
/// Each variant names one condition so the caller reports the specific fault
/// rather than a generic parse failure. Kept as a typed enum, not a string, so
/// the parser's unit tests assert on the condition instead of on wording.
#[derive(Debug, PartialEq, Eq)]
pub enum CliError {
    /// No positional path was supplied.
    MissingPath,
    /// The required path slot held an option token.
    OptionInPathPosition(String),
    /// An option the grammar does not define.
    UnknownOption(String),
    /// An option that may appear at most once appeared again.
    DuplicateOption(&'static str),
    /// An option that takes a value ran off the end, or was handed an option.
    MissingValue {
        option: &'static str,
        expected: &'static str,
        found: Option<String>,
    },
    /// More than one positional key was supplied.
    MultipleKeks,
    /// A non-path argument was not valid UTF-8. Carries its argv position.
    NonUtf8Argument(usize),
    /// `--page-size` was handed something that is not a positive integer.
    InvalidPageSize(String),
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingPath => write!(f, "database path is required"),
            Self::OptionInPathPosition(option) => {
                write!(f, "expected a database path, found option {option}")
            }
            Self::UnknownOption(option) => write!(f, "unknown option {option}"),
            Self::DuplicateOption(option) => write!(f, "duplicate {option}"),
            Self::MissingValue {
                option,
                expected,
                found: None,
            } => write!(f, "{option} requires {expected}"),
            Self::MissingValue {
                option,
                expected,
                found: Some(found),
            } => write!(f, "{option} requires {expected}, found option {found}"),
            Self::MultipleKeks => write!(f, "multiple KEK values supplied"),
            Self::NonUtf8Argument(position) => {
                write!(f, "argument {position} is not valid UTF-8")
            }
            Self::InvalidPageSize(value) => {
                write!(f, "--page-size requires {PAGE_SIZE_VALUE}, found {value}")
            }
        }
    }
}

impl std::error::Error for CliError {}

/// What the command line asked for.
#[derive(Debug, PartialEq, Eq)]
pub enum CliRequest {
    /// Print the grammar and exit successfully.
    Help,
    /// Inspect a store.
    Check(CliArgs),
}

/// A validated inspection request.
#[derive(Debug, PartialEq, Eq)]
pub struct CliArgs {
    pub path: PathBuf,
    pub deep: bool,
    pub page_size: usize,
    pub realm_hex: Option<String>,
    pub kek_hex: Option<String>,
}

/// Whether a token occupies an option slot rather than a value slot.
///
/// Deliberately every leading dash, not just `--`. Restricting this to `--`
/// lets `-v` fall through into the positional slot and be reported as a
/// malformed key, which is exactly the failure-class confusion this grammar
/// exists to prevent. Nothing the grammar accepts as a value can lead with a
/// dash: hex keys and realms are hex, and a dash-leading path is rejected in
/// its own slot with its own message.
fn is_option(token: &str) -> bool {
    token.starts_with('-')
}

/// Read the value belonging to `option`, which sits at `index` in `rest`.
///
/// `position` is the option's index into the full argv, so a non-UTF-8 value
/// can be named by the same numbering the operator sees.
fn value_of<'a>(
    option: &'static str,
    expected: &'static str,
    rest: &'a [OsString],
    index: usize,
    position: usize,
) -> Result<&'a str, CliError> {
    let Some(raw) = rest.get(index + 1) else {
        return Err(CliError::MissingValue {
            option,
            expected,
            found: None,
        });
    };
    let value = raw
        .to_str()
        .ok_or(CliError::NonUtf8Argument(position + 1))?;
    if is_option(value) {
        return Err(CliError::MissingValue {
            option,
            expected,
            found: Some(value.to_string()),
        });
    }
    Ok(value)
}

/// Parse a full argv, including the program name at index 0.
pub fn parse(argv: &[OsString]) -> Result<CliRequest, CliError> {
    let rest = argv.get(1..).unwrap_or(&[]);

    // Help wins from any position and before every other check: a tool that
    // has just tightened its grammar has to be able to state that grammar on
    // request, and refusing `--help` because the path is missing is precisely
    // when it is most needed.
    if rest
        .iter()
        .any(|arg| matches!(arg.to_str(), Some("--help" | "-h")))
    {
        return Ok(CliRequest::Help);
    }

    let Some(path) = rest.first() else {
        return Err(CliError::MissingPath);
    };
    // The path stays an OsString: on Unix a directory name need not be valid
    // UTF-8, and refusing to inspect such a store would be a gratuitous limit
    // on a recovery tool. Only the leading byte is examined here, and lossy
    // conversion preserves it.
    let path_text = path.to_string_lossy();
    if is_option(&path_text) {
        return Err(CliError::OptionInPathPosition(path_text.into_owned()));
    }

    let mut deep = false;
    let mut page_size = None;
    let mut realm_hex = None;
    let mut kek_hex = None;

    let mut index = 1;
    while index < rest.len() {
        let position = index + 1;
        let token = rest[index]
            .to_str()
            .ok_or(CliError::NonUtf8Argument(position))?;
        match token {
            "--deep" => {
                if deep {
                    return Err(CliError::DuplicateOption("--deep"));
                }
                deep = true;
                index += 1;
            }
            "--realm" => {
                if realm_hex.is_some() {
                    return Err(CliError::DuplicateOption("--realm"));
                }
                let value = value_of("--realm", REALM_VALUE, rest, index, position)?;
                realm_hex = Some(value.to_string());
                index += 2;
            }
            "--page-size" => {
                if page_size.is_some() {
                    return Err(CliError::DuplicateOption("--page-size"));
                }
                let value = value_of("--page-size", PAGE_SIZE_VALUE, rest, index, position)?;
                let parsed = value
                    .parse::<usize>()
                    .ok()
                    .filter(|bytes| *bytes > 0)
                    .ok_or_else(|| CliError::InvalidPageSize(value.to_string()))?;
                page_size = Some(parsed);
                index += 2;
            }
            _ if is_option(token) => {
                return Err(CliError::UnknownOption(token.to_string()));
            }
            _ => {
                if kek_hex.is_some() {
                    return Err(CliError::MultipleKeks);
                }
                kek_hex = Some(token.to_string());
                index += 1;
            }
        }
    }

    Ok(CliRequest::Check(CliArgs {
        path: PathBuf::from(path),
        deep,
        page_size: page_size.unwrap_or(DEFAULT_PAGE_SIZE),
        realm_hex,
        kek_hex,
    }))
}

#[cfg(test)]
mod tests {
    use super::{CliArgs, CliError, CliRequest, DEFAULT_PAGE_SIZE, parse};
    use std::ffi::OsString;
    use std::path::PathBuf;

    const REALM_HEX: &str = "00000000000000000000000000000000";
    const KEK_HEX: &str = "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5";

    fn parse_tokens(tokens: &[&str]) -> Result<CliRequest, CliError> {
        let argv: Vec<OsString> = std::iter::once("pagedb-fsck")
            .chain(tokens.iter().copied())
            .map(OsString::from)
            .collect();
        parse(&argv)
    }

    fn check(tokens: &[&str]) -> CliArgs {
        match parse_tokens(tokens).expect("expected the command line to parse") {
            CliRequest::Check(args) => args,
            CliRequest::Help => panic!("expected an inspection request, got help"),
        }
    }

    fn error(tokens: &[&str]) -> CliError {
        match parse_tokens(tokens) {
            Err(error) => error,
            Ok(request) => panic!("expected a parse error, got {request:?}"),
        }
    }

    #[test]
    fn a_bare_path_uses_every_default() {
        let args = check(&["/store"]);
        assert_eq!(
            args,
            CliArgs {
                path: PathBuf::from("/store"),
                deep: false,
                page_size: DEFAULT_PAGE_SIZE,
                realm_hex: None,
                kek_hex: None,
            }
        );
    }

    #[test]
    fn every_option_is_accepted_together() {
        let args = check(&["/store", "--deep", "--realm", REALM_HEX, KEK_HEX]);
        assert!(args.deep);
        assert_eq!(args.realm_hex.as_deref(), Some(REALM_HEX));
        assert_eq!(args.kek_hex.as_deref(), Some(KEK_HEX));
    }

    /// The tightened grammar must not have quietly become order-sensitive:
    /// every previously valid ordering still has to parse identically.
    #[test]
    fn options_and_the_positional_key_may_appear_in_any_order() {
        let canonical = check(&["/store", "--deep", "--realm", REALM_HEX, KEK_HEX]);
        assert_eq!(
            check(&["/store", KEK_HEX, "--realm", REALM_HEX, "--deep"]),
            canonical
        );
        assert_eq!(
            check(&["/store", "--realm", REALM_HEX, "--deep", KEK_HEX]),
            canonical
        );
        assert_eq!(
            check(&["/store", "--deep", KEK_HEX, "--realm", REALM_HEX]),
            canonical
        );
    }

    #[test]
    fn page_size_overrides_the_default() {
        assert_eq!(check(&["/store", "--page-size", "16384"]).page_size, 16384);
    }

    #[test]
    fn help_is_answered_from_any_position_and_without_a_path() {
        assert_eq!(parse_tokens(&["--help"]), Ok(CliRequest::Help));
        assert_eq!(parse_tokens(&["-h"]), Ok(CliRequest::Help));
        assert_eq!(
            parse_tokens(&["/store", "--deep", "--help"]),
            Ok(CliRequest::Help)
        );
    }

    #[test]
    fn a_missing_path_is_named_as_such() {
        assert_eq!(error(&[]), CliError::MissingPath);
    }

    #[test]
    fn an_option_may_not_stand_in_for_the_path() {
        assert_eq!(
            error(&["--deep"]),
            CliError::OptionInPathPosition("--deep".to_string())
        );
    }

    #[test]
    fn no_option_may_be_repeated() {
        assert_eq!(
            error(&["/store", "--deep", "--deep"]),
            CliError::DuplicateOption("--deep")
        );
        assert_eq!(
            error(&["/store", "--realm", REALM_HEX, "--realm", REALM_HEX]),
            CliError::DuplicateOption("--realm")
        );
        assert_eq!(
            error(&["/store", "--page-size", "4096", "--page-size", "8192"]),
            CliError::DuplicateOption("--page-size")
        );
    }

    #[test]
    fn unknown_long_options_are_rejected() {
        assert_eq!(
            error(&["/store", "--unknown"]),
            CliError::UnknownOption("--unknown".to_string())
        );
    }

    /// A single-dash token must be reported as an unknown option, not fall
    /// through to the key slot and resurface as "invalid hex KEK".
    #[test]
    fn short_options_are_rejected_rather_than_read_as_a_key() {
        assert_eq!(
            error(&["/store", "-v"]),
            CliError::UnknownOption("-v".to_string())
        );
        assert_eq!(
            error(&["/store", "-"]),
            CliError::UnknownOption("-".to_string())
        );
    }

    #[test]
    fn an_option_value_may_be_neither_absent_nor_another_option() {
        assert_eq!(
            error(&["/store", "--realm"]),
            CliError::MissingValue {
                option: "--realm",
                expected: super::REALM_VALUE,
                found: None,
            }
        );
        assert_eq!(
            error(&["/store", "--realm", "--deep"]),
            CliError::MissingValue {
                option: "--realm",
                expected: super::REALM_VALUE,
                found: Some("--deep".to_string()),
            }
        );
    }

    #[test]
    fn only_one_positional_key_is_accepted() {
        assert_eq!(error(&["/store", KEK_HEX, KEK_HEX]), CliError::MultipleKeks);
    }

    #[test]
    fn page_size_must_be_a_positive_integer() {
        assert_eq!(
            error(&["/store", "--page-size", "0"]),
            CliError::InvalidPageSize("0".to_string())
        );
        assert_eq!(
            error(&["/store", "--page-size", "many"]),
            CliError::InvalidPageSize("many".to_string())
        );
    }

    /// A store directory whose name is not valid UTF-8 is still inspectable;
    /// only the tokens that must be hex or flags are required to be UTF-8.
    #[cfg(unix)]
    #[test]
    fn a_non_utf8_path_is_accepted_but_a_non_utf8_option_is_not() {
        use std::os::unix::ffi::OsStringExt;

        let path = OsString::from_vec(vec![b'/', 0xff, b'd']);
        let argv = vec![OsString::from("pagedb-fsck"), path.clone()];
        assert_eq!(
            parse(&argv),
            Ok(CliRequest::Check(CliArgs {
                path: PathBuf::from(path),
                deep: false,
                page_size: DEFAULT_PAGE_SIZE,
                realm_hex: None,
                kek_hex: None,
            }))
        );

        let argv = vec![
            OsString::from("pagedb-fsck"),
            OsString::from("/store"),
            OsString::from_vec(vec![0xff]),
        ];
        assert_eq!(parse(&argv), Err(CliError::NonUtf8Argument(2)));
    }
}
