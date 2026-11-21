//! Validation of ref glob patterns before they reach `globset` or Git.

use crate::PolicyError;

/// Longest ref glob accepted by [`validate_ref_glob`], in bytes.
pub const MAX_REF_GLOB_BYTES: usize = 1024;

/// Checks that `pattern` is a safe ref glob such as `refs/heads/private/*`.
///
/// Accepted patterns start with `refs/` followed by at least one byte, are at
/// most [`MAX_REF_GLOB_BYTES`] long, and may use the glob metacharacters `*`,
/// `?`, `[`, `]`, `{` and `}`. Because every pattern starts with `refs/`, it
/// can never start with `!` or `^`, which Git's `transfer.hideRefs` would
/// read as negation or full-name markers.
///
/// # Errors
///
/// Returns [`PolicyError::InvalidRefGlob`] when the pattern is too long, does
/// not start with `refs/`, contains an ASCII control character, whitespace,
/// `..`, `//`, `~`, `^`, `:`, `\` or `@{`, or ends with `/` or `.lock`. These
/// mirror Git's ref-name rules, minus the glob metacharacters.
pub fn validate_ref_glob(pattern: &str) -> Result<(), PolicyError> {
    let reject = |reason: &'static str| {
        Err(PolicyError::InvalidRefGlob {
            pattern: pattern.to_owned(),
            reason,
        })
    };

    if pattern.len() > MAX_REF_GLOB_BYTES {
        return reject("pattern is longer than 1024 bytes");
    }
    match pattern.strip_prefix("refs/") {
        Some(rest) if !rest.is_empty() => {}
        Some(_) => return reject("pattern must name something after \"refs/\""),
        None => return reject("pattern must start with \"refs/\""),
    }
    if pattern.bytes().any(|byte| byte.is_ascii_control()) {
        // `is_ascii_control` also covers NUL and DEL.
        return reject("pattern must not contain control characters");
    }
    if pattern.bytes().any(|byte| byte.is_ascii_whitespace()) {
        return reject("pattern must not contain whitespace");
    }
    if pattern.contains("..") {
        return reject("pattern must not contain \"..\"");
    }
    if pattern.contains("//") {
        return reject("pattern must not contain \"//\"");
    }
    if pattern.contains("@{") {
        return reject("pattern must not contain \"@{\"");
    }
    if pattern.contains(['~', '^', ':', '\\']) {
        return reject("pattern must not contain '~', '^', ':' or '\\'");
    }
    if pattern.ends_with('/') {
        return reject("pattern must not end with '/'");
    }
    if pattern.ends_with(".lock") {
        return reject("pattern must not end with \".lock\"");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn is_valid(pattern: &str) -> bool {
        match validate_ref_glob(pattern) {
            Ok(()) => true,
            Err(PolicyError::InvalidRefGlob { .. }) => false,
            Err(error) => panic!("unexpected error for {pattern:?}: {error}"),
        }
    }

    #[test]
    fn accepts_plain_refs_and_globs() {
        for pattern in [
            "refs/heads/secret",
            "refs/heads/private/*",
            "refs/heads/private/**",
            "refs/heads/*/secret",
            "refs/heads/release-?",
            "refs/heads/[ab]*",
            "refs/heads/{alpha,beta}",
            "refs/tags/v1.0",
            "refs/*",
        ] {
            assert!(is_valid(pattern), "{pattern:?} should be valid");
        }
    }

    #[test]
    fn rejects_unsafe_patterns() {
        let too_long = format!("refs/heads/{}", "a".repeat(MAX_REF_GLOB_BYTES));
        for pattern in [
            "",
            "refs/",
            "refs",
            "heads/main",
            "!refs/heads/main",
            "^refs/heads/main",
            "refs/heads/a b",
            "refs/heads/a\tb",
            "refs/heads/a\nb",
            "refs/heads/a\0b",
            "refs/heads/a\x7fb",
            "refs/heads/../main",
            "refs//heads",
            "refs/heads/a~1",
            "refs/heads/a^",
            "refs/heads/a:b",
            "refs/heads/a\\b",
            "refs/heads/a@{1}",
            "refs/heads/private/",
            "refs/heads/main.lock",
            too_long.as_str(),
        ] {
            assert!(!is_valid(pattern), "{pattern:?} should be rejected");
        }
    }

    #[test]
    fn accepts_pattern_at_length_limit() {
        let prefix = "refs/heads/";
        let pattern = format!("{prefix}{}", "a".repeat(MAX_REF_GLOB_BYTES - prefix.len()));
        assert_eq!(pattern.len(), MAX_REF_GLOB_BYTES);
        assert!(is_valid(&pattern));
    }
}
