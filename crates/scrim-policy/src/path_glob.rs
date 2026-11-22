//! Validation of repository-relative path globs, group names, and protected metadata paths.

use globset::{GlobBuilder, GlobMatcher};

use crate::PolicyError;

/// Longest path glob accepted by [`validate_path_glob`], in bytes.
pub const MAX_PATH_GLOB_BYTES: usize = 1024;

/// Longest group name accepted by [`validate_group_name`], in bytes.
pub const MAX_GROUP_NAME_BYTES: usize = 64;

/// Maximum number of path rules accepted by [`crate::PathPolicy::compile`].
pub const MAX_PATH_RULES: usize = 1024;

/// Representative protected paths that a user-defined path glob must never match.
const PROTECTED_METADATA_SAMPLES: [&str; 7] = [
    ".gitattributes",
    ".git/config",
    ".git/HEAD",
    ".scrim/paths.toml",
    ".scrim/keys/dev.toml",
    ".scrim/group-keys/core.toml",
    ".scrim/secrets/dev.enc",
];

/// Checks that `group` is a valid Scrim group name.
///
/// Group names must be 1 to [`MAX_GROUP_NAME_BYTES`] ASCII bytes, start with
/// `[A-Za-z0-9]`, and use only `[A-Za-z0-9._-]` for any remaining bytes.
///
/// # Errors
///
/// Returns [`PolicyError::InvalidGroupName`] when `group` is empty, exceeds
/// [`MAX_GROUP_NAME_BYTES`], or contains disallowed characters.
pub fn validate_group_name(group: &str) -> Result<(), PolicyError> {
    let reject = |reason: &'static str| {
        Err(PolicyError::InvalidGroupName {
            group: group.to_owned(),
            reason,
        })
    };

    if group.is_empty() {
        return reject("group name must not be empty");
    }
    if group.len() > MAX_GROUP_NAME_BYTES {
        return reject("group name is longer than 64 bytes");
    }

    let bytes = group.as_bytes();
    if let Some(&first) = bytes.first()
        && !first.is_ascii_alphanumeric()
    {
        return reject("group name must start with an ASCII letter or digit");
    }
    if bytes
        .iter()
        .any(|&byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')))
    {
        return reject("group name may only contain ASCII letters, digits, '.', '_' or '-'");
    }

    Ok(())
}

/// Checks that `pattern` is a safe repo-relative `.gitattributes`-compatible
/// path glob such as `config/billing/**`, `docs/internal/*.md`, `*.secret`, or
/// `secrets.json`.
///
/// Accepted patterns are non-empty, at most [`MAX_PATH_GLOB_BYTES`] long, free
/// of ASCII control characters, ASCII whitespace, backslashes, `//`, `{`, `}`,
/// partial `**` segments (like `a**b`), and `.` or `..` path segments, and do
/// not start with `/`, `!`, or `#` or end with `/`. They must also compile with `globset` (using `literal_separator(true)`, plus
/// `**/<pattern>` when `pattern` contains no `/`) and must not target or match
/// protected repository metadata such as `.git/**`, `.scrim/**`, or
/// `.gitattributes`.
///
/// # Errors
///
/// Returns [`PolicyError::InvalidPathGlob`] when `pattern` violates any syntax
/// or safety constraint, or [`PolicyError::GlobCompile`] when `globset` fails
/// to parse the glob expression.
pub fn validate_path_glob(pattern: &str) -> Result<(), PolicyError> {
    let reject = |reason: &'static str| {
        Err(PolicyError::InvalidPathGlob {
            pattern: pattern.to_owned(),
            reason,
        })
    };

    if pattern.is_empty() {
        return reject("pattern must not be empty");
    }
    if pattern.len() > MAX_PATH_GLOB_BYTES {
        return reject("pattern is longer than 1024 bytes");
    }
    if pattern.bytes().any(|byte| byte.is_ascii_control()) {
        // `is_ascii_control` also covers NUL and DEL.
        return reject("pattern must not contain control characters");
    }
    if pattern.bytes().any(|byte| byte.is_ascii_whitespace()) {
        // `.gitattributes` splits the pattern from attributes on whitespace.
        return reject("pattern must not contain whitespace");
    }
    if pattern.starts_with('/') {
        return reject("pattern must not start with '/'");
    }
    if pattern.starts_with('!') {
        return reject("pattern must not start with '!'");
    }
    if pattern.starts_with('#') {
        return reject("pattern must not start with '#'");
    }
    if pattern.ends_with('/') {
        return reject("pattern must not end with '/'");
    }
    if pattern.contains('\\') {
        return reject("pattern must not contain '\\'");
    }
    if pattern.contains("//") {
        return reject("pattern must not contain \"//\"");
    }
    if pattern.contains(['{', '}']) {
        // Git `.gitattributes` uses wildmatch, which treats `{` and `}` as
        // literals rather than brace alternation like `globset` does.
        return reject("pattern must not contain '{' or '}' (unsupported by .gitattributes)");
    }

    let mut segments = pattern.split('/');
    if let Some(first_segment) = segments.next() {
        if first_segment.is_empty() || first_segment == "." || first_segment == ".." {
            return reject("pattern must not contain empty, '.' or '..' path segments");
        }
        if first_segment.contains("**") && first_segment != "**" {
            return reject("'**' must occupy an entire path segment");
        }
        if matches!(first_segment, ".git" | ".scrim" | ".gitattributes") {
            return reject("pattern must not target protected metadata paths");
        }
    }
    for segment in segments {
        if segment.is_empty() || segment == "." || segment == ".." {
            return reject("pattern must not contain empty, '.' or '..' path segments");
        }
        if segment.contains("**") && segment != "**" {
            return reject("'**' must occupy an entire path segment");
        }
    }

    let matchers = match compile_pattern_matchers(pattern) {
        Ok(matchers) => matchers,
        Err(error) => return Err(error),
    };
    if PROTECTED_METADATA_SAMPLES
        .iter()
        .any(|sample| matchers.iter().any(|matcher| matcher.is_match(sample)))
    {
        return reject("pattern must not match protected metadata paths");
    }

    Ok(())
}

/// Validates and returns a clean repository-relative path without normalizing
/// traversal or rewriting separators.
///
/// Returns `None` when `path` is empty, starts or ends with `/`, contains `\`
/// or any ASCII control byte, or has an empty, `.`, or `..` segment.
pub fn normalize_repo_path(path: &str) -> Option<&str> {
    if path.is_empty() || path.starts_with('/') || path.ends_with('/') || path.contains('\\') {
        return None;
    }
    if path.bytes().any(|byte| byte.is_ascii_control()) {
        return None;
    }
    if path
        .split('/')
        .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        return None;
    }
    Some(path)
}

/// Reports whether `path` refers to protected Scrim or Git metadata that must
/// never be treated as a private encrypted file.
pub fn is_protected_metadata_path(path: &str) -> bool {
    path == ".gitattributes"
        || path == ".git"
        || path.starts_with(".git/")
        || path == ".scrim"
        || path.starts_with(".scrim/")
}

/// Compiles the `globset` matcher(s) representing `pattern` under
/// `.gitattributes` matching rules.
fn compile_pattern_matchers(pattern: &str) -> Result<Vec<GlobMatcher>, PolicyError> {
    let primary = match GlobBuilder::new(pattern).literal_separator(true).build() {
        Ok(glob) => glob.compile_matcher(),
        Err(source) => {
            return Err(PolicyError::GlobCompile {
                pattern: pattern.to_owned(),
                source,
            });
        }
    };

    if pattern.contains('/') {
        return Ok(vec![primary]);
    }

    let nested_pattern = format!("**/{pattern}");
    let nested = match GlobBuilder::new(&nested_pattern)
        .literal_separator(true)
        .build()
    {
        Ok(glob) => glob.compile_matcher(),
        Err(source) => {
            return Err(PolicyError::GlobCompile {
                pattern: pattern.to_owned(),
                source,
            });
        }
    };

    Ok(vec![primary, nested])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn is_valid_glob(pattern: &str) -> bool {
        match validate_path_glob(pattern) {
            Ok(()) => true,
            Err(PolicyError::InvalidPathGlob { .. } | PolicyError::GlobCompile { .. }) => false,
            Err(error) => panic!("unexpected error for {pattern:?}: {error}"),
        }
    }

    #[test]
    fn accepts_valid_group_names() {
        for group in ["core", "a", "team-1", "sec_ops", "org.billing", "TeamA9._-"] {
            assert!(
                validate_group_name(group).is_ok(),
                "{group:?} should be valid"
            );
        }
        let max_len = "a".repeat(MAX_GROUP_NAME_BYTES);
        assert!(validate_group_name(&max_len).is_ok());
    }

    #[test]
    fn rejects_invalid_group_names() {
        let too_long = "a".repeat(MAX_GROUP_NAME_BYTES + 1);
        for group in [
            "",
            "-core",
            "_core",
            ".core",
            "core/sub",
            "core team",
            "core@org",
            "café",
            too_long.as_str(),
        ] {
            assert!(
                matches!(
                    validate_group_name(group),
                    Err(PolicyError::InvalidGroupName { .. })
                ),
                "{group:?} should be rejected"
            );
        }
    }

    #[test]
    fn accepts_valid_path_globs() {
        for pattern in [
            "config/billing/**",
            "docs/internal/*.md",
            "*.secret",
            "secrets.json",
            "foo/bar.txt",
            "foo..bar.txt",
            "apps/*/config/*.json",
            "config/[ab].json",
            ".env",
            ".github/**",
        ] {
            assert!(is_valid_glob(pattern), "{pattern:?} should be valid");
        }
    }

    #[test]
    fn accepts_path_glob_at_length_limit() {
        let prefix = "config/";
        let pattern = format!("{prefix}{}", "a".repeat(MAX_PATH_GLOB_BYTES - prefix.len()));
        assert_eq!(pattern.len(), MAX_PATH_GLOB_BYTES);
        assert!(is_valid_glob(&pattern));
    }

    #[test]
    fn rejects_invalid_and_protected_path_globs() {
        let too_long = format!("config/{}", "a".repeat(MAX_PATH_GLOB_BYTES));
        for pattern in [
            "",
            "/config/secret.txt",
            "!config/secret.txt",
            "#comment",
            "config/secret file.txt",
            "config/secret\tfile.txt",
            "config/secret\nfile.txt",
            "config/secret\0file.txt",
            "config/secret\x7ffile.txt",
            "config\\secret.txt",
            "config//secret.txt",
            "config/billing/",
            ".",
            "..",
            "./secret.txt",
            "config/./secret.txt",
            "config/../secret.txt",
            "config/..",
            "*",
            "**",
            ".*",
            ".git",
            ".git/**",
            ".git/config",
            ".gitattributes",
            ".gitattributes/foo",
            ".scrim",
            ".scrim/**",
            ".scrim/paths.toml",
            ".scrim/keys/*.toml",
            "*.toml",
            "*.enc",
            "**/.gitattributes",
            "{.git,.scrim}/**",
            "apps/*/config/{dev,prod}.json",
            "config/a**b.txt",
            "config/**foo/bar.txt",
            too_long.as_str(),
        ] {
            assert!(
                matches!(
                    validate_path_glob(pattern),
                    Err(PolicyError::InvalidPathGlob { .. })
                ),
                "{pattern:?} should fail InvalidPathGlob"
            );
        }
    }

    #[test]
    fn reports_glob_compile_errors() {
        assert!(matches!(
            validate_path_glob("config/[abc"),
            Err(PolicyError::GlobCompile { .. })
        ));
    }

    #[test]
    fn normalizes_and_rejects_repo_paths() {
        assert_eq!(
            normalize_repo_path("config/billing/keys.json"),
            Some("config/billing/keys.json")
        );
        assert_eq!(
            normalize_repo_path("docs/my file.md"),
            Some("docs/my file.md")
        );

        for invalid in [
            "",
            "/config/a.txt",
            "config/",
            "config//a.txt",
            "config\\a.txt",
            ".",
            "..",
            "./a.txt",
            "config/./a.txt",
            "config/../a.txt",
            "config/a\0.txt",
            "config/a\t.txt",
            "config/a\x7f.txt",
        ] {
            assert_eq!(normalize_repo_path(invalid), None, "{invalid:?}");
        }
    }

    #[test]
    fn identifies_protected_metadata_paths() {
        for protected in [
            ".gitattributes",
            ".git",
            ".git/config",
            ".git/HEAD",
            ".scrim",
            ".scrim/paths.toml",
            ".scrim/keys/dev.toml",
        ] {
            assert!(is_protected_metadata_path(protected), "{protected:?}");
        }

        for non_protected in [
            ".gitignore",
            ".github/workflows/ci.yml",
            "sub/.gitattributes",
            "config/billing/secret.json",
        ] {
            assert!(
                !is_protected_metadata_path(non_protected),
                "{non_protected:?}"
            );
        }
    }
}
