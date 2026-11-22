//! Deterministic detection of plaintext secrets in pushed files, used by
//! check 5 of the `pre-receive` guard (see [`crate::pre_receive`]).
//!
//! Two independent checks:
//!
//! - [`check_blocked_path_bytes`] refuses plaintext dotenv files (`.env`,
//!   `.env.local`, ...) anywhere in the tree, except a few well-known template
//!   names such as `.env.example`;
//! - [`scan_blob_bytes`] looks for a short list of high-confidence credential
//!   formats (Scrim API tokens, age secret keys, PEM private keys, AWS access
//!   key IDs, GitHub, Stripe live and Slack tokens).
//!
//! Every matcher is a hand-written prefix test followed by a bounded run of
//! byte-class checks: no regular expressions, no backtracking, and at most a
//! fixed number of bytes inspected per starting offset, so scanning is linear
//! in the input. A match reports only the rule name and line number; the
//! matched bytes are never copied out, logged or returned.

/// Most bytes of one blob that [`scan_blob_bytes`] inspects. Larger blobs are
/// scanned up to this prefix rather than skipped, so padding a file cannot
/// hide a secret at its top, while memory per blob stays bounded.
pub(crate) const MAX_SCANNED_BLOB_BYTES: usize = 1024 * 1024;

/// A blob whose first this-many bytes contain a NUL byte is treated as binary
/// and not scanned (the same heuristic git uses).
const BINARY_DETECTION_BYTES: usize = 8 * 1024;

/// Rule reported for a plaintext dotenv file name.
pub(crate) const PLAINTEXT_DOTENV_RULE: &str = "plaintext-dotenv-file";

/// Dotenv file names that conventionally hold placeholders, not secrets.
/// Compared with the whole basename, ignoring ASCII case.
const DOTENV_TEMPLATE_NAMES: [&[u8]; 5] = [
    b".env.example",
    b".env.sample",
    b".env.template",
    b".env.dist",
    b".env.defaults",
];

/// Where [`scan_blob_bytes`] found a secret. Deliberately holds no part of
/// the secret itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SecretMatch {
    /// Name of the rule that matched, e.g. `aws-access-key-id`.
    pub rule: &'static str,
    /// 1-based line number of the match's first byte.
    pub line: usize,
}

/// Returns [`PLAINTEXT_DOTENV_RULE`] if the basename of the `/`-separated
/// `path` is `.env` or `.env.<anything>`, ignoring ASCII case, unless it is
/// one of the template names in [`DOTENV_TEMPLATE_NAMES`].
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn check_blocked_path(path: &str) -> Option<&'static str> {
    check_blocked_path_bytes(path.as_bytes())
}

/// Byte version of [`check_blocked_path`], for git paths that need not be
/// UTF-8: a non-UTF-8 directory name or suffix cannot hide a dotenv file.
pub(crate) fn check_blocked_path_bytes(path: &[u8]) -> Option<&'static str> {
    let basename = match path.iter().rposition(|byte| *byte == b'/') {
        Some(slash) => &path[slash + 1..],
        None => path,
    };
    let is_dotenv = basename.eq_ignore_ascii_case(b".env")
        || (basename.len() > b".env.".len()
            && basename[..b".env.".len()].eq_ignore_ascii_case(b".env."));
    let is_template = DOTENV_TEMPLATE_NAMES
        .iter()
        .any(|name| basename.eq_ignore_ascii_case(name));
    if is_dotenv && !is_template {
        Some(PLAINTEXT_DOTENV_RULE)
    } else {
        None
    }
}

/// Scans the first [`MAX_SCANNED_BLOB_BYTES`] of `bytes` for a known secret
/// format and returns the first match, or `None` if there is none or the blob
/// looks binary (a NUL byte within its first [`BINARY_DETECTION_BYTES`]).
pub(crate) fn scan_blob_bytes(bytes: &[u8]) -> Option<SecretMatch> {
    let scanned = &bytes[..bytes.len().min(MAX_SCANNED_BLOB_BYTES)];
    let binary_window = &scanned[..scanned.len().min(BINARY_DETECTION_BYTES)];
    if binary_window.contains(&0) {
        return None;
    }
    for offset in 0..scanned.len() {
        if let Some(rule) = match_secret_at(scanned, offset) {
            let line = 1 + scanned[..offset]
                .iter()
                .filter(|byte| **byte == b'\n')
                .count();
            return Some(SecretMatch { rule, line });
        }
    }
    None
}

/// Tests whether a secret starts at the beginning of `rest`, given the byte
/// before it (`None` at the start of the blob).
type SecretMatcher = fn(previous: Option<u8>, rest: &[u8]) -> bool;

/// Every content rule, by name, in the order they are tried.
const SECRET_MATCHERS: [(&str, SecretMatcher); 7] = [
    ("scrim-api-token", is_scrim_api_token),
    ("age-secret-key", is_age_secret_key),
    ("private-key-pem", is_private_key_pem),
    ("aws-access-key-id", is_aws_access_key_id),
    ("github-token", is_github_token),
    ("stripe-live-key", is_stripe_live_key),
    ("slack-token", is_slack_token),
];

/// Returns the rule whose pattern starts exactly at `offset`, if any. Each
/// matcher inspects a bounded number of bytes.
fn match_secret_at(bytes: &[u8], offset: usize) -> Option<&'static str> {
    let previous = if offset == 0 {
        None
    } else {
        Some(bytes[offset - 1])
    };
    let rest = &bytes[offset..];
    SECRET_MATCHERS
        .into_iter()
        .find(|(_, matcher)| matcher(previous, rest))
        .map(|(rule, _)| rule)
}

/// `[A-Za-z0-9_]`.
fn is_word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// Whether `previous` (the byte before a candidate, if any) is not a byte
/// for which `is_continuation` holds, i.e. the candidate starts a token.
fn starts_token(previous: Option<u8>, is_continuation: fn(u8) -> bool) -> bool {
    match previous {
        Some(byte) => !is_continuation(byte),
        None => true,
    }
}

/// Number of leading bytes of `bytes` for which `is_member` holds, counting
/// at most `limit`.
fn count_leading(bytes: &[u8], is_member: fn(u8) -> bool, limit: usize) -> usize {
    bytes
        .iter()
        .take(limit)
        .take_while(|byte| is_member(**byte))
        .count()
}

/// If `rest` starts with one of `prefixes`, returns the bytes after it.
fn strip_any_prefix<'a>(rest: &'a [u8], prefixes: &[&[u8]]) -> Option<&'a [u8]> {
    prefixes
        .iter()
        .find_map(|prefix| rest.strip_prefix(*prefix))
}

/// Whether `rest[count]`, if it exists, is not a byte for which
/// `is_continuation` holds, i.e. a token of `count` bytes ends there.
fn ends_token(rest: &[u8], count: usize, is_continuation: fn(u8) -> bool) -> bool {
    match rest.get(count) {
        Some(byte) => !is_continuation(*byte),
        None => true,
    }
}

/// `scrim_` + exactly 64 lowercase hex digits (the server's API token format).
fn is_scrim_api_token(previous: Option<u8>, rest: &[u8]) -> bool {
    const HEX_DIGITS: usize = 64;
    let Some(body) = rest.strip_prefix(b"scrim_") else {
        return false;
    };
    let is_lower_hex = |byte: u8| matches!(byte, b'0'..=b'9' | b'a'..=b'f');
    starts_token(previous, is_word_byte)
        && count_leading(body, is_lower_hex, HEX_DIGITS) == HEX_DIGITS
        && ends_token(body, HEX_DIGITS, |byte| byte.is_ascii_hexdigit())
}

/// `AGE-SECRET-KEY-1` + 58 upper-case Bech32 characters (an age X25519
/// identity).
fn is_age_secret_key(previous: Option<u8>, rest: &[u8]) -> bool {
    const DATA_CHARS: usize = 58;
    let Some(body) = rest.strip_prefix(b"AGE-SECRET-KEY-1") else {
        return false;
    };
    let is_bech32_upper = |byte: u8| b"QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L".contains(&byte);
    starts_token(previous, |byte| is_word_byte(byte) || byte == b'-')
        && count_leading(body, is_bech32_upper, DATA_CHARS) == DATA_CHARS
        && ends_token(body, DATA_CHARS, |byte| byte.is_ascii_alphanumeric())
}

/// `-----BEGIN [RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED ]PRIVATE KEY-----`.
fn is_private_key_pem(_previous: Option<u8>, rest: &[u8]) -> bool {
    let Some(after_begin) = rest.strip_prefix(b"-----BEGIN ") else {
        return false;
    };
    let after_kind = match strip_any_prefix(
        after_begin,
        &[
            b"RSA ",
            b"DSA ",
            b"EC ",
            b"OPENSSH ",
            b"PGP ",
            b"ENCRYPTED ",
        ],
    ) {
        Some(after_kind) => after_kind,
        None => after_begin,
    };
    after_kind.starts_with(b"PRIVATE KEY-----")
}

/// `AKIA` or `ASIA` + exactly 16 `[A-Z0-9]`, as a whole word.
fn is_aws_access_key_id(previous: Option<u8>, rest: &[u8]) -> bool {
    const ID_CHARS: usize = 16;
    let Some(body) = strip_any_prefix(rest, &[b"AKIA", b"ASIA"]) else {
        return false;
    };
    let is_upper_alphanumeric = |byte: u8| byte.is_ascii_uppercase() || byte.is_ascii_digit();
    starts_token(previous, is_word_byte)
        && count_leading(body, is_upper_alphanumeric, ID_CHARS) == ID_CHARS
        && ends_token(body, ID_CHARS, is_word_byte)
}

/// `gh[pousr]_` + at least 36 `[A-Za-z0-9_]`, or `github_pat_` + at least 22.
fn is_github_token(previous: Option<u8>, rest: &[u8]) -> bool {
    if !starts_token(previous, is_word_byte) {
        return false;
    }
    let (body, minimum_chars) =
        match strip_any_prefix(rest, &[b"ghp_", b"gho_", b"ghu_", b"ghs_", b"ghr_"]) {
            Some(body) => (body, 36),
            None => match rest.strip_prefix(b"github_pat_") {
                Some(body) => (body, 22),
                None => return false,
            },
        };
    count_leading(body, is_word_byte, minimum_chars) == minimum_chars
}

/// `sk_live_` or `rk_live_` + at least 24 `[A-Za-z0-9]`.
fn is_stripe_live_key(previous: Option<u8>, rest: &[u8]) -> bool {
    const MINIMUM_CHARS: usize = 24;
    let Some(body) = strip_any_prefix(rest, &[b"sk_live_", b"rk_live_"]) else {
        return false;
    };
    starts_token(previous, is_word_byte)
        && count_leading(body, |byte| byte.is_ascii_alphanumeric(), MINIMUM_CHARS) == MINIMUM_CHARS
}

/// `xox[bpars]-` + at least 10 `[A-Za-z0-9-]`.
fn is_slack_token(previous: Option<u8>, rest: &[u8]) -> bool {
    const MINIMUM_CHARS: usize = 10;
    let Some(body) = strip_any_prefix(rest, &[b"xoxb-", b"xoxp-", b"xoxa-", b"xoxr-", b"xoxs-"])
    else {
        return false;
    };
    let is_token_byte = |byte: u8| byte.is_ascii_alphanumeric() || byte == b'-';
    starts_token(previous, |byte| is_word_byte(byte) || byte == b'-')
        && count_leading(body, is_token_byte, MINIMUM_CHARS) == MINIMUM_CHARS
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_SCANNED_BLOB_BYTES, PLAINTEXT_DOTENV_RULE, SecretMatch, check_blocked_path,
        check_blocked_path_bytes, scan_blob_bytes,
    };

    // Test secrets are assembled at run time so this file never contains a
    // literal that secret scanners (including this one) would flag.
    fn scrim_token() -> String {
        format!("{}_{}", "scrim", "0123456789abcdef".repeat(4))
    }

    fn age_secret_key() -> String {
        format!(
            "{}-1{}",
            "AGE-SECRET-KEY",
            "QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L".repeat(2)
        )
        .chars()
        .take("AGE-SECRET-KEY-1".len() + 58)
        .collect()
    }

    fn aws_key_id() -> String {
        format!("{}{}", "AK", "IAABCDEFGHIJ234567")
    }

    fn github_pat() -> String {
        format!("{}_{}", "ghp", "aB3".repeat(12))
    }

    fn github_fine_grained_pat() -> String {
        format!("{}_{}", "github_pat", "x9_Y".repeat(5) + "ab")
    }

    fn stripe_key() -> String {
        format!("{}_live_{}", "sk", "Ab12".repeat(6))
    }

    fn slack_token() -> String {
        format!("{}-{}", "xoxb", "1234-abcde")
    }

    fn pem_header(kind: &str) -> String {
        format!("-----{} {kind}PRIVATE KEY-----", "BEGIN")
    }

    fn assert_match(text: &str, rule: &'static str, line: usize) {
        assert_eq!(
            scan_blob_bytes(text.as_bytes()),
            Some(SecretMatch { rule, line }),
            "{text:?}"
        );
    }

    fn assert_no_match(text: &str) {
        assert_eq!(scan_blob_bytes(text.as_bytes()), None, "{text:?}");
    }

    #[test]
    fn blocks_plaintext_dotenv_files_anywhere() {
        for path in [
            ".env",
            ".env.local",
            ".env.production",
            ".env.prod",
            ".env.dev",
            ".env.staging",
            ".env.development.local",
            "deploy/.env",
            "apps/web/.env.local",
            ".ENV",
            ".Env.Local",
            "config/.ENV.PRODUCTION",
            ".env.example.local",
        ] {
            assert_eq!(
                check_blocked_path(path),
                Some(PLAINTEXT_DOTENV_RULE),
                "{path}"
            );
        }
        assert_eq!(
            check_blocked_path_bytes(b"caf\xff/.env"),
            Some(PLAINTEXT_DOTENV_RULE)
        );
        assert_eq!(
            check_blocked_path_bytes(b"dir/.env.\xfe"),
            Some(PLAINTEXT_DOTENV_RULE)
        );
    }

    #[test]
    fn allows_templates_and_ordinary_files() {
        for path in [
            ".env.example",
            ".env.sample",
            ".env.template",
            ".env.dist",
            ".env.defaults",
            "apps/web/.ENV.EXAMPLE",
            "README.md",
            "secret.txt",
            "hello.txt",
            ".env.",
            ".envrc",
            "env",
            "my.env",
            ".env/config",
            ".scrim/secrets/dev.enc",
            ".scrim/keys/dev.toml",
        ] {
            assert_eq!(check_blocked_path(path), None, "{path}");
        }
    }

    #[test]
    fn detects_scrim_api_tokens_with_boundaries() {
        let token = scrim_token();
        assert_match(
            &format!("a\nb\nSCRIM_TOKEN={token}\n"),
            "scrim-api-token",
            3,
        );
        assert_match(&token, "scrim-api-token", 1);
        assert_match(&format!("\"{token}\" "), "scrim-api-token", 1);
        // Preceded by a word byte, followed by more hex, too short, upper case.
        assert_no_match(&format!("x{token}"));
        assert_no_match(&format!("{token}a"));
        assert_no_match(&format!("{token}A"));
        assert_no_match(&token[..token.len() - 1]);
        assert_no_match(&token.to_uppercase());
        assert_no_match("scrim_ is the token prefix");
    }

    #[test]
    fn detects_age_secret_keys_but_not_public_keys() {
        let key = age_secret_key();
        assert_match(&format!("# created\n{key}\n"), "age-secret-key", 2);
        assert_no_match(&format!("-{key}"));
        assert_no_match(&format!("{key}Q"));
        assert_no_match(&key[..key.len() - 1]);
        assert_no_match(&key.to_lowercase());
        assert_no_match(
            "[recipients]\ndev = \"age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p\"\n",
        );
    }

    #[test]
    fn detects_private_key_pem_headers() {
        for kind in ["", "RSA ", "DSA ", "EC ", "OPENSSH ", "PGP ", "ENCRYPTED "] {
            assert_match(
                &format!("line one\n\n{}\nMIIE\n", pem_header(kind)),
                "private-key-pem",
                3,
            );
        }
        assert_no_match(&format!("-----{} PUBLIC KEY-----", "BEGIN"));
        assert_no_match(&format!("-----{} CERTIFICATE-----", "BEGIN"));
        assert_no_match(&pem_header("FOO "));
        assert_no_match(&format!("-----{} AGE ENCRYPTED FILE-----\nYWdl\n", "BEGIN"));
    }

    #[test]
    fn detects_aws_access_key_ids_as_whole_words() {
        let key = aws_key_id();
        assert_match(
            &format!("aws_access_key_id = {key}\n"),
            "aws-access-key-id",
            1,
        );
        assert_match(
            &format!("x\n{}", key.replacen("AKIA", "ASIA", 1)),
            "aws-access-key-id",
            2,
        );
        assert_no_match(&format!("x{key}"));
        assert_no_match(&format!("{key}Z"));
        assert_no_match(&format!("{key}_"));
        assert_no_match(&key[..key.len() - 1]);
        assert_no_match(&key.to_lowercase());
    }

    #[test]
    fn detects_github_tokens() {
        let token = github_pat();
        assert_match(&format!("token: {token}"), "github-token", 1);
        for prefix in ["gho", "ghu", "ghs", "ghr"] {
            assert_match(&token.replacen("ghp", prefix, 1), "github-token", 1);
        }
        assert_match(
            &format!("\n\n{}", github_fine_grained_pat()),
            "github-token",
            3,
        );
        assert_no_match(&format!("x{token}"));
        assert_no_match(&token[..token.len() - 1]);
        assert_no_match(&github_fine_grained_pat()[..github_fine_grained_pat().len() - 1]);
        assert_no_match("ghx_aB3aB3aB3aB3aB3aB3aB3aB3aB3aB3aB3aB3");
    }

    #[test]
    fn detects_stripe_live_and_slack_tokens() {
        let stripe = stripe_key();
        assert_match(&format!("STRIPE={stripe}"), "stripe-live-key", 1);
        assert_match(&stripe.replacen("sk", "rk", 1), "stripe-live-key", 1);
        assert_no_match(&stripe.replacen("live", "test", 1));
        assert_no_match(&format!("x{stripe}"));
        assert_no_match(&stripe[..stripe.len() - 1]);

        let slack = slack_token();
        assert_match(&format!("a\n{slack}"), "slack-token", 2);
        for kind in ["xoxp", "xoxa", "xoxr", "xoxs"] {
            assert_match(&slack.replacen("xoxb", kind, 1), "slack-token", 1);
        }
        assert_no_match(&format!("-{slack}"));
        assert_no_match(&slack[..slack.len() - 1]);
    }

    #[test]
    fn ignores_ordinary_project_files() {
        for text in [
            "hello\n",
            "# Scrim\n\nSee docs.\n",
            "top secret\n",
            "DATABASE_URL=postgres://scrim:scrim@localhost/scrim\n",
            "-----BEGIN AGE ENCRYPTED FILE-----\nYWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBhYmMK\n-----END AGE ENCRYPTED FILE-----\n",
            "AKIA is the AWS access key prefix\n",
            "",
        ] {
            assert_no_match(text);
        }
    }

    #[test]
    fn skips_binary_blobs() {
        let mut bytes = b"\x00\x01binary".to_vec();
        bytes.extend_from_slice(aws_key_id().as_bytes());
        assert_eq!(scan_blob_bytes(&bytes), None);
    }

    #[test]
    fn scans_only_the_first_mebibyte() {
        let key = aws_key_id();
        let mut early = format!("{key}\n").into_bytes();
        early.resize(MAX_SCANNED_BLOB_BYTES * 2, b'a');
        assert_eq!(
            scan_blob_bytes(&early),
            Some(SecretMatch {
                rule: "aws-access-key-id",
                line: 1
            })
        );

        let mut late = vec![b'\n'; MAX_SCANNED_BLOB_BYTES];
        late.extend_from_slice(key.as_bytes());
        assert_eq!(scan_blob_bytes(&late), None);

        // A secret straddling the limit is cut and therefore not reported.
        let mut straddling = vec![b' '; MAX_SCANNED_BLOB_BYTES - 4];
        straddling.extend_from_slice(key.as_bytes());
        assert_eq!(scan_blob_bytes(&straddling), None);
    }
}
