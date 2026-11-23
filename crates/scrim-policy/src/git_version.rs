//! Parsing of `git --version` output and the minimum Git version Scrim
//! supports, shared so the server and the CLI enforce the same floor.

use std::fmt;

/// A Git release number, compared component by component.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct GitVersion {
    /// Major version, such as `2` in `2.40.1`.
    pub major: u32,
    /// Minor version, such as `40` in `2.40.1`.
    pub minor: u32,
    /// Patch version, such as `1` in `2.40.1`; `0` when Git omits it.
    pub patch: u32,
}

impl GitVersion {
    /// Builds a version from its three components.
    pub const fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }
}

impl fmt::Display for GitVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// The oldest Git release Scrim supports on both the server and the client.
pub const MIN_GIT_VERSION: GitVersion = GitVersion::new(2, 40, 0);

/// Parses the first line of `git --version` output, such as
/// `git version 2.54.0 (Apple Git-157)`, `git version 2.39.5.windows.1` or
/// `git version 2.45.0.rc1`.
///
/// Returns `None` when the text does not start with `git version` followed by
/// at least a numeric major and minor component. Vendor and release-candidate
/// suffixes are ignored, so `2.45.0.rc1` parses as `2.45.0`.
pub fn parse_git_version(output: &str) -> Option<GitVersion> {
    let first_line = match output.lines().next() {
        Some(line) => line.trim(),
        None => return None,
    };
    let version_text = match first_line.strip_prefix("git version ") {
        Some(rest) => match rest.split_whitespace().next() {
            Some(token) => token,
            None => return None,
        },
        None => return None,
    };
    let mut components = version_text.split(['.', '-']);
    let major = match components.next().and_then(parse_whole_number) {
        Some(major) => major,
        None => return None,
    };
    let minor = match components.next().and_then(parse_whole_number) {
        Some(minor) => minor,
        None => return None,
    };
    // A missing or non-numeric third component (`2.40`, `2.40.rc0`) means
    // the `.0` release line.
    let patch = components.next().map_or(0, parse_leading_number);
    Some(GitVersion::new(major, minor, patch))
}

/// Parses a component made only of ASCII digits.
fn parse_whole_number(component: &str) -> Option<u32> {
    if component.is_empty() || !component.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    component.parse().ok()
}

/// The value of the leading ASCII digits of a component such as `5` or
/// `0rc1`, or `0` when it has none. Absurdly long digit runs saturate.
fn parse_leading_number(component: &str) -> u32 {
    component
        .bytes()
        .take_while(|byte| byte.is_ascii_digit())
        .fold(0_u32, |value, digit| {
            value
                .saturating_mul(10)
                .saturating_add(u32::from(digit - b'0'))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_release_vendor_and_candidate_versions() {
        let cases = [
            ("git version 2.54.0 (Apple Git-157)\n", Some((2, 54, 0))),
            ("git version 2.39.5.windows.1", Some((2, 39, 5))),
            ("git version 2.45.0.rc1", Some((2, 45, 0))),
            ("git version 2.45.0-rc1", Some((2, 45, 0))),
            ("git version 2.40", Some((2, 40, 0))),
            ("git version 2.40.rc0", Some((2, 40, 0))),
            ("  git version 2.47.3\nsecond line", Some((2, 47, 3))),
        ];
        for (output, expected) in cases {
            let expected =
                expected.map(|(major, minor, patch)| GitVersion::new(major, minor, patch));
            assert_eq!(parse_git_version(output), expected, "{output:?}");
        }
    }

    #[test]
    fn rejects_unrecognised_output() {
        for output in [
            "",
            "git version",
            "git version ",
            "git version two.forty",
            "git version 2",
            "git version 2.x.0",
            "hub version 2.40.0",
            "version 2.40.0",
        ] {
            assert_eq!(parse_git_version(output), None, "{output:?}");
        }
    }

    #[test]
    fn compares_against_the_minimum() {
        assert!(GitVersion::new(2, 39, 5) < MIN_GIT_VERSION);
        assert!(GitVersion::new(2, 40, 0) >= MIN_GIT_VERSION);
        assert!(GitVersion::new(3, 0, 0) > MIN_GIT_VERSION);
        assert_eq!(MIN_GIT_VERSION.to_string(), "2.40.0");
    }
}
