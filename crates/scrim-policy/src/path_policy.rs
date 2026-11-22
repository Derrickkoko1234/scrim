//! Path visibility rules and compiled path policies.
//!
//! Each [`PathRule`] maps a `.gitattributes`-compatible path glob to the single
//! group whose key encrypts matching files. Patterns containing `/` are
//! anchored to the repository root, while patterns without `/` match both at
//! the repository root and inside any subdirectory (matching Git's
//! `.gitattributes` semantics).

use std::collections::{BTreeMap, BTreeSet};

use globset::{GlobBuilder, GlobSet, GlobSetBuilder};

use crate::PolicyError;
use crate::path_glob::{
    MAX_PATH_RULES, is_protected_metadata_path, normalize_repo_path, validate_group_name,
    validate_path_glob,
};

/// Maps every repository-relative path matching `pattern` to `group`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathRule {
    /// Repo-relative `.gitattributes`-compatible path glob; see
    /// [`validate_path_glob`].
    pub pattern: String,
    /// Group whose key protects files matching `pattern`; see
    /// [`validate_group_name`].
    pub group: String,
}

impl PathRule {
    /// Builds a rule after validating `pattern` and `group`.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::InvalidPathGlob`] or [`PolicyError::GlobCompile`]
    /// when `pattern` fails [`validate_path_glob`], or
    /// [`PolicyError::InvalidGroupName`] when `group` fails
    /// [`validate_group_name`].
    pub fn new(pattern: impl Into<String>, group: impl Into<String>) -> Result<Self, PolicyError> {
        let pattern = pattern.into();
        let group = group.into();
        if let Err(error) = validate_path_glob(&pattern) {
            return Err(error);
        }
        if let Err(error) = validate_group_name(&group) {
            return Err(error);
        }
        Ok(Self { pattern, group })
    }
}

/// A compiled set of [`PathRule`]s.
///
/// Rules are stored sorted deterministically by `pattern` so `.scrim/paths.toml`
/// and `.gitattributes` generation remain stable across runs. Paths not matched
/// by any rule (as well as protected repository metadata) are public (`Ok(None)`).
/// When multiple rules match the same path, every matching rule must name the
/// same group; otherwise lookup fails closed with
/// [`PolicyError::AmbiguousPathRule`].
#[derive(Debug, Clone)]
pub struct PathPolicy {
    /// Sorted by `pattern` for deterministic serialization and inspection.
    rules: Vec<PathRule>,
    glob_set: GlobSet,
    /// Maps each compiled entry index in `glob_set` back to its index in `rules`.
    matcher_to_rule: Vec<usize>,
}

impl PathPolicy {
    /// Validates and compiles `rules`.
    ///
    /// Rules are sorted deterministically by `pattern`. Exact duplicate
    /// patterns are rejected with [`PolicyError::DuplicatePathRule`], and
    /// exceeding [`MAX_PATH_RULES`] returns [`PolicyError::TooManyPathRules`].
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::InvalidPathGlob`], [`PolicyError::InvalidGroupName`],
    /// [`PolicyError::GlobCompile`], [`PolicyError::DuplicatePathRule`], or
    /// [`PolicyError::TooManyPathRules`].
    pub fn compile(rules: impl IntoIterator<Item = PathRule>) -> Result<Self, PolicyError> {
        let mut count = 0usize;
        let mut rules_by_pattern: BTreeMap<String, String> = BTreeMap::new();

        for rule in rules {
            count += 1;
            if count > MAX_PATH_RULES {
                return Err(PolicyError::TooManyPathRules {
                    max: MAX_PATH_RULES,
                });
            }
            if let Err(error) = validate_path_glob(&rule.pattern) {
                return Err(error);
            }
            if let Err(error) = validate_group_name(&rule.group) {
                return Err(error);
            }
            if rules_by_pattern.contains_key(&rule.pattern) {
                return Err(PolicyError::DuplicatePathRule {
                    pattern: rule.pattern,
                });
            }
            rules_by_pattern.insert(rule.pattern, rule.group);
        }

        let mut builder = GlobSetBuilder::new();
        let mut matcher_to_rule = Vec::new();
        let mut compiled_rules = Vec::with_capacity(rules_by_pattern.len());

        for (rule_idx, (pattern, group)) in rules_by_pattern.into_iter().enumerate() {
            let root_glob = match GlobBuilder::new(&pattern).literal_separator(true).build() {
                Ok(glob) => glob,
                Err(source) => return Err(PolicyError::GlobCompile { pattern, source }),
            };
            builder.add(root_glob);
            matcher_to_rule.push(rule_idx);

            // `.gitattributes` patterns without `/` match at any directory depth.
            if !pattern.contains('/') {
                let nested_pattern = format!("**/{pattern}");
                let nested_glob = match GlobBuilder::new(&nested_pattern)
                    .literal_separator(true)
                    .build()
                {
                    Ok(glob) => glob,
                    Err(source) => return Err(PolicyError::GlobCompile { pattern, source }),
                };
                builder.add(nested_glob);
                matcher_to_rule.push(rule_idx);
            }

            compiled_rules.push(PathRule { pattern, group });
        }

        let glob_set = match builder.build() {
            Ok(glob_set) => glob_set,
            Err(source) => {
                return Err(PolicyError::GlobCompile {
                    pattern: String::new(),
                    source,
                });
            }
        };

        Ok(Self {
            rules: compiled_rules,
            glob_set,
            matcher_to_rule,
        })
    }

    /// Returns `true` when the policy contains no path rules.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Returns the compiled rules in deterministic `pattern`-sorted order.
    pub fn rules(&self) -> &[PathRule] {
        &self.rules
    }

    /// Returns the sorted set of distinct group names referenced by this policy.
    pub fn groups(&self) -> BTreeSet<&str> {
        self.rules.iter().map(|rule| rule.group.as_str()).collect()
    }

    /// Resolves the single group protecting `repo_relative_path`, if any.
    ///
    /// Invalid paths (where [`normalize_repo_path`] returns `None`) and
    /// protected metadata paths (where [`is_protected_metadata_path`] is
    /// `true`) always return `Ok(None)`. If multiple rules match and belong to
    /// the same group, `Ok(Some(group))` is returned.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::AmbiguousPathRule`] when rules from two or more
    /// distinct groups match `repo_relative_path`, failing closed so an
    /// overlap never silently picks the wrong key.
    pub fn group_for_path(&self, repo_relative_path: &str) -> Result<Option<&str>, PolicyError> {
        let Some(path) = normalize_repo_path(repo_relative_path) else {
            return Ok(None);
        };
        if is_protected_metadata_path(path) || self.rules.is_empty() {
            return Ok(None);
        }

        let mut matching_groups: BTreeSet<&str> = BTreeSet::new();
        for glob_idx in self.glob_set.matches(path) {
            if let Some(&rule_idx) = self.matcher_to_rule.get(glob_idx)
                && let Some(rule) = self.rules.get(rule_idx)
            {
                matching_groups.insert(rule.group.as_str());
            }
        }

        match matching_groups.len() {
            0 => Ok(None),
            1 => Ok(matching_groups.into_iter().next()),
            _ => Err(PolicyError::AmbiguousPathRule {
                path: path.to_owned(),
                groups: matching_groups.into_iter().map(str::to_owned).collect(),
            }),
        }
    }

    /// Reports whether `repo_relative_path` is protected by a path rule.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::AmbiguousPathRule`] when rules from multiple
    /// distinct groups match `repo_relative_path`.
    pub fn is_path_private(&self, repo_relative_path: &str) -> Result<bool, PolicyError> {
        match self.group_for_path(repo_relative_path) {
            Ok(Some(_)) => Ok(true),
            Ok(None) => Ok(false),
            Err(error) => Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(pattern: &str, group: &str) -> PathRule {
        match PathRule::new(pattern, group) {
            Ok(rule) => rule,
            Err(error) => panic!("rule ({pattern:?}, {group:?}) should be valid: {error}"),
        }
    }

    fn compile(rules: Vec<PathRule>) -> PathPolicy {
        match PathPolicy::compile(rules) {
            Ok(policy) => policy,
            Err(error) => panic!("path policy should compile: {error}"),
        }
    }

    #[test]
    fn new_validates_pattern_and_group() {
        assert!(matches!(
            PathRule::new("/bad/path", "core"),
            Err(PolicyError::InvalidPathGlob { .. })
        ));
        assert!(matches!(
            PathRule::new("config/**", "-bad-group"),
            Err(PolicyError::InvalidGroupName { .. })
        ));
        assert!(matches!(
            PathRule::new("config/[unclosed", "core"),
            Err(PolicyError::GlobCompile { .. })
        ));
    }

    #[test]
    fn compile_revalidates_public_fields() {
        let bad_pattern = PathRule {
            pattern: ".scrim/**".to_owned(),
            group: "core".to_owned(),
        };
        assert!(matches!(
            PathPolicy::compile([bad_pattern]),
            Err(PolicyError::InvalidPathGlob { .. })
        ));

        let bad_group = PathRule {
            pattern: "config/**".to_owned(),
            group: "bad group".to_owned(),
        };
        assert!(matches!(
            PathPolicy::compile([bad_group]),
            Err(PolicyError::InvalidGroupName { .. })
        ));
    }

    #[test]
    fn compile_sorts_rules_and_reports_groups() {
        let policy = compile(vec![
            rule("z/secret.txt", "ops"),
            rule("a/*.secret", "billing"),
            rule("m/data/**", "ops"),
        ]);

        assert!(!policy.is_empty());
        let patterns: Vec<&str> = policy.rules().iter().map(|r| r.pattern.as_str()).collect();
        assert_eq!(patterns, ["a/*.secret", "m/data/**", "z/secret.txt"]);

        let groups: Vec<&str> = policy.groups().into_iter().collect();
        assert_eq!(groups, ["billing", "ops"]);
    }

    #[test]
    fn compile_rejects_duplicate_patterns() {
        let result = PathPolicy::compile([
            rule("config/billing/**", "billing"),
            rule("config/billing/**", "core"),
        ]);
        assert!(matches!(
            result,
            Err(PolicyError::DuplicatePathRule { ref pattern }) if pattern == "config/billing/**"
        ));
    }

    #[test]
    fn compile_enforces_max_path_rules() {
        let max_rules: Vec<PathRule> = (0..MAX_PATH_RULES)
            .map(|i| rule(&format!("dir/file-{i}.txt"), "core"))
            .collect();
        assert!(PathPolicy::compile(max_rules).is_ok());

        let too_many: Vec<PathRule> = (0..=MAX_PATH_RULES)
            .map(|i| rule(&format!("dir/file-{i}.txt"), "core"))
            .collect();
        assert!(matches!(
            PathPolicy::compile(too_many),
            Err(PolicyError::TooManyPathRules { max }) if max == MAX_PATH_RULES
        ));
    }

    #[test]
    fn matches_anchored_and_unanchored_patterns_like_gitattributes() {
        let policy = compile(vec![
            rule("config/billing/**", "billing"),
            rule("docs/internal/*.md", "core"),
            rule("*.secret", "security"),
            rule("foo/bar.txt", "ops"),
        ]);

        // Pattern with '/' is anchored to repo root.
        assert_eq!(
            policy.group_for_path("config/billing/keys.json").ok(),
            Some(Some("billing"))
        );
        assert_eq!(
            policy.group_for_path("config/billing/sub/keys.json").ok(),
            Some(Some("billing"))
        );
        assert_eq!(
            policy.group_for_path("other/config/billing/keys.json").ok(),
            Some(None)
        );
        assert_eq!(
            policy.group_for_path("docs/internal/plan.md").ok(),
            Some(Some("core"))
        );
        // Single '*' does not cross '/'.
        assert_eq!(
            policy.group_for_path("docs/internal/nested/plan.md").ok(),
            Some(None)
        );
        assert_eq!(policy.group_for_path("foo/bar.txt").ok(), Some(Some("ops")));
        assert_eq!(policy.group_for_path("sub/foo/bar.txt").ok(), Some(None));

        // Pattern without '/' matches at root and in any subdirectory.
        assert_eq!(
            policy.group_for_path("root.secret").ok(),
            Some(Some("security"))
        );
        assert_eq!(
            policy.group_for_path("a/b/c/deep.secret").ok(),
            Some(Some("security"))
        );
        assert_eq!(policy.group_for_path("README.md").ok(), Some(None));
    }

    #[test]
    fn same_group_overlap_succeeds_and_distinct_group_overlap_fails_closed() {
        let policy = compile(vec![
            rule("config/billing/**", "billing"),
            rule("*.billing", "billing"),
            rule("docs/internal/*.md", "core"),
            rule("*.secret", "security"),
        ]);

        // Both `config/billing/**` and `*.billing` match, both in `billing`.
        assert_eq!(
            policy.group_for_path("config/billing/keys.billing").ok(),
            Some(Some("billing"))
        );
        assert_eq!(
            policy.is_path_private("config/billing/keys.billing").ok(),
            Some(true)
        );

        // `config/billing/**` (billing) and `*.secret` (security) both match.
        let err = match policy.group_for_path("config/billing/api.secret") {
            Err(error) => error,
            Ok(other) => panic!("expected AmbiguousPathRule, got Ok({other:?})"),
        };
        assert!(matches!(
            err,
            PolicyError::AmbiguousPathRule { ref path, ref groups }
                if path == "config/billing/api.secret"
                    && groups == &vec!["billing".to_owned(), "security".to_owned()]
        ));

        assert!(matches!(
            policy.is_path_private("config/billing/api.secret"),
            Err(PolicyError::AmbiguousPathRule { .. })
        ));
    }

    #[test]
    fn invalid_and_protected_paths_return_ok_none() {
        let policy = compile(vec![rule("*.secret", "security")]);

        for path in [
            "",
            "/a.secret",
            "dir/a.secret/",
            "dir\\a.secret",
            "dir/../a.secret",
            ".gitattributes",
            ".git",
            ".git/config",
            ".scrim",
            ".scrim/paths.toml",
            ".scrim/keys/dev.toml",
        ] {
            assert_eq!(policy.group_for_path(path).ok(), Some(None), "{path:?}");
            assert_eq!(policy.is_path_private(path).ok(), Some(false), "{path:?}");
        }
    }

    #[test]
    fn empty_policy_reports_everything_public() {
        let policy = compile(Vec::new());
        assert!(policy.is_empty());
        assert!(policy.rules().is_empty());
        assert!(policy.groups().is_empty());
        assert_eq!(policy.group_for_path("secrets.json").ok(), Some(None));
        assert_eq!(policy.is_path_private("secrets.json").ok(), Some(false));
    }
}
