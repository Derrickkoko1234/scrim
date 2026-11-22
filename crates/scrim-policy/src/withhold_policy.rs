//! Server-enforced path withholding rules and compiled withholding policies.
//!
//! Each [`WithholdRule`] maps a `.gitattributes`-compatible path glob to the
//! set of groups whose members may receive matching blob bytes from
//! `scrim-server`. Patterns containing `/` are anchored to the repository root,
//! while patterns without `/` match at any directory depth (matching
//! [`crate::PathPolicy`] and Git's `.gitattributes` / non-cone sparse-checkout
//! rules).
//!
//! Unlike encrypted [`crate::PathPolicy`] rules (where a single group's key
//! encrypts each file), server-side withholding supports multiple allowed
//! groups per rule and composes overlapping rules by intersection: a path
//! matched by several rules is visible only to members allowed by every one of
//! them.

use std::collections::{BTreeMap, BTreeSet};

use globset::{GlobBuilder, GlobSet, GlobSetBuilder};

use crate::PolicyError;
use crate::path_glob::{
    MAX_PATH_RULES, is_protected_metadata_path, normalize_repo_path, validate_group_name,
    validate_path_glob,
};

/// Restricts every repository path matching `pattern` to members of
/// `allowed_groups`.
///
/// A rule with an empty `allowed_groups` set withholds matching paths from
/// everyone (fail-closed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WithholdRule {
    /// Repo-relative `.gitattributes`-compatible path glob; see
    /// [`validate_path_glob`].
    pub pattern: String,
    /// Groups whose members may receive blob bytes for paths matching
    /// `pattern`; each group name satisfies [`validate_group_name`].
    pub allowed_groups: BTreeSet<String>,
}

impl WithholdRule {
    /// Builds a withholding rule after validating `pattern` and every group
    /// name in `allowed_groups`.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::InvalidPathGlob`] or [`PolicyError::GlobCompile`]
    /// when `pattern` fails [`validate_path_glob`], or
    /// [`PolicyError::InvalidGroupName`] when any group fails
    /// [`validate_group_name`].
    pub fn new(
        pattern: impl Into<String>,
        allowed_groups: impl IntoIterator<Item = String>,
    ) -> Result<Self, PolicyError> {
        let pattern = pattern.into();
        if let Err(error) = validate_path_glob(&pattern) {
            return Err(error);
        }
        let mut groups = BTreeSet::new();
        for group in allowed_groups {
            if let Err(error) = validate_group_name(&group) {
                return Err(error);
            }
            groups.insert(group);
        }
        Ok(Self {
            pattern,
            allowed_groups: groups,
        })
    }
}

/// A compiled set of server-enforced [`WithholdRule`]s.
///
/// Rules are stored sorted deterministically by `pattern`. Paths not matched by
/// any rule (as well as protected repository metadata such as `.gitattributes`,
/// `.git/**`, and `.scrim/**`) are visible to every member. When multiple rules
/// match the same path, the member must belong to at least one allowed group of
/// every matching rule; adding a rule can only withhold more, never expose
/// more.
#[derive(Debug, Clone)]
pub struct WithholdPolicy {
    /// Sorted by `pattern` for deterministic listing and sparse-checkout output.
    rules: Vec<WithholdRule>,
    glob_set: GlobSet,
    /// Same globs compiled with ASCII case-insensitive matching for push-time
    /// path guards on case-insensitive filesystems.
    case_insensitive_glob_set: GlobSet,
    /// Maps each matcher index in both `GlobSet`s back to its index in `rules`.
    matcher_to_rule: Vec<usize>,
}

impl WithholdPolicy {
    /// Returns an empty policy that withholds no paths.
    pub fn empty() -> Self {
        Self {
            rules: Vec::new(),
            glob_set: GlobSet::empty(),
            case_insensitive_glob_set: GlobSet::empty(),
            matcher_to_rule: Vec::new(),
        }
    }

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
    pub fn compile(rules: impl IntoIterator<Item = WithholdRule>) -> Result<Self, PolicyError> {
        let mut count = 0usize;
        let mut rules_by_pattern: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

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
            for group in &rule.allowed_groups {
                if let Err(error) = validate_group_name(group) {
                    return Err(error);
                }
            }
            if rules_by_pattern.contains_key(&rule.pattern) {
                return Err(PolicyError::DuplicatePathRule {
                    pattern: rule.pattern,
                });
            }
            rules_by_pattern.insert(rule.pattern, rule.allowed_groups);
        }

        if rules_by_pattern.is_empty() {
            return Ok(Self::empty());
        }

        let mut sensitive_builder = GlobSetBuilder::new();
        let mut insensitive_builder = GlobSetBuilder::new();
        let mut matcher_to_rule = Vec::new();
        let mut compiled_rules = Vec::with_capacity(rules_by_pattern.len());

        for (rule_idx, (pattern, allowed_groups)) in rules_by_pattern.into_iter().enumerate() {
            if let Err(error) = add_pattern_matchers(
                &pattern,
                &mut sensitive_builder,
                &mut insensitive_builder,
                &mut matcher_to_rule,
                rule_idx,
            ) {
                return Err(error);
            }
            compiled_rules.push(WithholdRule {
                pattern,
                allowed_groups,
            });
        }

        let glob_set = match sensitive_builder.build() {
            Ok(glob_set) => glob_set,
            Err(source) => {
                return Err(PolicyError::GlobCompile {
                    pattern: String::new(),
                    source,
                });
            }
        };
        let case_insensitive_glob_set = match insensitive_builder.build() {
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
            case_insensitive_glob_set,
            matcher_to_rule,
        })
    }

    /// Returns `true` when the policy contains no withholding rules.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Returns the compiled rules in deterministic `pattern`-sorted order.
    pub fn rules(&self) -> &[WithholdRule] {
        &self.rules
    }

    /// Returns `true` if at least one rule in this policy is not satisfied by
    /// `member_groups`.
    ///
    /// Callers can use this as a fast path: when it returns `false`, the member
    /// is allowed to read every file in the repository and no withholding walk
    /// or sparse-checkout exclusion is required.
    pub fn has_withheld_rules(&self, member_groups: &BTreeSet<String>) -> bool {
        self.rules
            .iter()
            .any(|rule| !rule_allows_member(rule, member_groups))
    }

    /// Reports whether `repo_relative_path` is withheld from a member belonging
    /// to `member_groups`.
    ///
    /// When [`Self::has_withheld_rules`] is `false`, every path is visible
    /// (`false`). Otherwise:
    /// - malformed or non-normalized paths fail closed (`true`);
    /// - protected metadata paths (`.gitattributes`, `.git/**`, `.scrim/**`)
    ///   are never withheld (`false`);
    /// - any path matched by at least one rule whose `allowed_groups` is
    ///   disjoint from `member_groups` is withheld (`true`).
    pub fn is_path_withheld(
        &self,
        repo_relative_path: &str,
        member_groups: &BTreeSet<String>,
    ) -> bool {
        self.is_path_withheld_with_matcher(&self.glob_set, repo_relative_path, member_groups)
    }

    /// Like [`Self::is_path_withheld`], but matches rules ignoring ASCII case.
    ///
    /// Intended for push-time write authorization so a restricted member cannot
    /// write to a case-variant of a withheld path (such as `CONFIG/billing/a`)
    /// that collides on case-insensitive filesystems.
    pub fn is_path_withheld_case_insensitive(
        &self,
        repo_relative_path: &str,
        member_groups: &BTreeSet<String>,
    ) -> bool {
        self.is_path_withheld_with_matcher(
            &self.case_insensitive_glob_set,
            repo_relative_path,
            member_groups,
        )
    }

    /// Returns the sorted path glob patterns of every rule not satisfied by
    /// `member_groups`.
    pub fn withheld_patterns(&self, member_groups: &BTreeSet<String>) -> Vec<&str> {
        self.rules
            .iter()
            .filter(|rule| !rule_allows_member(rule, member_groups))
            .map(|rule| rule.pattern.as_str())
            .collect()
    }

    /// Builds Git non-cone sparse-checkout patterns that include everything
    /// except paths withheld from `member_groups`.
    ///
    /// Returns an empty vector when [`Self::has_withheld_rules`] is `false`.
    /// Otherwise starts with `"/*"` followed by one negated pattern per
    /// withheld rule: `!/<pattern>` for root-anchored patterns containing `/`,
    /// and `!<pattern>` for unanchored patterns without `/`.
    pub fn sparse_checkout_patterns(&self, member_groups: &BTreeSet<String>) -> Vec<String> {
        let withheld = self.withheld_patterns(member_groups);
        if withheld.is_empty() {
            return Vec::new();
        }
        let mut patterns = Vec::with_capacity(withheld.len() + 1);
        patterns.push("/*".to_owned());
        for pattern in withheld {
            if pattern.contains('/') {
                patterns.push(format!("!/{pattern}"));
            } else {
                patterns.push(format!("!{pattern}"));
            }
        }
        patterns
    }

    fn is_path_withheld_with_matcher(
        &self,
        matcher: &GlobSet,
        repo_relative_path: &str,
        member_groups: &BTreeSet<String>,
    ) -> bool {
        if !self.has_withheld_rules(member_groups) {
            return false;
        }
        let Some(path) = normalize_repo_path(repo_relative_path) else {
            // Fail closed when the member has restricted paths and a tree entry
            // carries an unnormalized or unsafe path.
            return true;
        };
        if is_protected_metadata_path(path) {
            return false;
        }

        for glob_idx in matcher.matches(path) {
            if let Some(&rule_idx) = self.matcher_to_rule.get(glob_idx)
                && let Some(rule) = self.rules.get(rule_idx)
                && !rule_allows_member(rule, member_groups)
            {
                return true;
            }
        }
        false
    }
}

impl Default for WithholdPolicy {
    fn default() -> Self {
        Self::empty()
    }
}

/// Reports whether `member_groups` satisfies `rule`.
fn rule_allows_member(rule: &WithholdRule, member_groups: &BTreeSet<String>) -> bool {
    !rule.allowed_groups.is_disjoint(member_groups)
}

/// Adds both root and (for unanchored patterns without `/`) nested `**/` globs
/// into the case-sensitive and case-insensitive `GlobSetBuilder`s.
fn add_pattern_matchers(
    pattern: &str,
    sensitive_builder: &mut GlobSetBuilder,
    insensitive_builder: &mut GlobSetBuilder,
    matcher_to_rule: &mut Vec<usize>,
    rule_idx: usize,
) -> Result<(), PolicyError> {
    let build_pair = |expr: &str| -> Result<(globset::Glob, globset::Glob), PolicyError> {
        let sensitive = match GlobBuilder::new(expr).literal_separator(true).build() {
            Ok(glob) => glob,
            Err(source) => {
                return Err(PolicyError::GlobCompile {
                    pattern: pattern.to_owned(),
                    source,
                });
            }
        };
        let insensitive = match GlobBuilder::new(expr)
            .literal_separator(true)
            .case_insensitive(true)
            .build()
        {
            Ok(glob) => glob,
            Err(source) => {
                return Err(PolicyError::GlobCompile {
                    pattern: pattern.to_owned(),
                    source,
                });
            }
        };
        Ok((sensitive, insensitive))
    };

    let (root_sensitive, root_insensitive) = match build_pair(pattern) {
        Ok(pair) => pair,
        Err(error) => return Err(error),
    };
    sensitive_builder.add(root_sensitive);
    insensitive_builder.add(root_insensitive);
    matcher_to_rule.push(rule_idx);

    // Patterns without `/` match at the repository root and in any subdirectory.
    if !pattern.contains('/') {
        let nested_expr = format!("**/{pattern}");
        let (nested_sensitive, nested_insensitive) = match build_pair(&nested_expr) {
            Ok(pair) => pair,
            Err(error) => return Err(error),
        };
        sensitive_builder.add(nested_sensitive);
        insensitive_builder.add(nested_insensitive);
        matcher_to_rule.push(rule_idx);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn groups(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|&name| name.to_owned()).collect()
    }

    fn rule(pattern: &str, allowed: &[&str]) -> WithholdRule {
        match WithholdRule::new(pattern, groups(allowed)) {
            Ok(rule) => rule,
            Err(error) => panic!("rule ({pattern:?}, {allowed:?}) should be valid: {error}"),
        }
    }

    fn compile(rules: Vec<WithholdRule>) -> WithholdPolicy {
        match WithholdPolicy::compile(rules) {
            Ok(policy) => policy,
            Err(error) => panic!("withhold policy should compile: {error}"),
        }
    }

    #[test]
    fn new_validates_pattern_and_groups() {
        assert!(matches!(
            WithholdRule::new("/bad/path", groups(&["core"])),
            Err(PolicyError::InvalidPathGlob { .. })
        ));
        assert!(matches!(
            WithholdRule::new("config/**", groups(&["core", "-bad"])),
            Err(PolicyError::InvalidGroupName { .. })
        ));
        assert!(matches!(
            WithholdRule::new("config/[unclosed", groups(&["core"])),
            Err(PolicyError::GlobCompile { .. })
        ));
    }

    #[test]
    fn compile_revalidates_public_fields_and_rejects_duplicates() {
        let bad_pattern = WithholdRule {
            pattern: ".scrim/**".to_owned(),
            allowed_groups: groups(&["core"]),
        };
        assert!(matches!(
            WithholdPolicy::compile([bad_pattern]),
            Err(PolicyError::InvalidPathGlob { .. })
        ));

        let bad_group = WithholdRule {
            pattern: "config/**".to_owned(),
            allowed_groups: groups(&["bad group"]),
        };
        assert!(matches!(
            WithholdPolicy::compile([bad_group]),
            Err(PolicyError::InvalidGroupName { .. })
        ));

        let dup = WithholdPolicy::compile([
            rule("config/billing/**", &["finance"]),
            rule("config/billing/**", &["core"]),
        ]);
        assert!(matches!(
            dup,
            Err(PolicyError::DuplicatePathRule { ref pattern }) if pattern == "config/billing/**"
        ));
    }

    #[test]
    fn compile_enforces_max_path_rules() {
        let max_rules: Vec<WithholdRule> = (0..MAX_PATH_RULES)
            .map(|i| rule(&format!("dir/file-{i}.txt"), &["core"]))
            .collect();
        assert!(WithholdPolicy::compile(max_rules).is_ok());

        let too_many: Vec<WithholdRule> = (0..=MAX_PATH_RULES)
            .map(|i| rule(&format!("dir/file-{i}.txt"), &["core"]))
            .collect();
        assert!(matches!(
            WithholdPolicy::compile(too_many),
            Err(PolicyError::TooManyPathRules { max }) if max == MAX_PATH_RULES
        ));
    }

    #[test]
    fn empty_policy_withholds_nothing() {
        let policy = WithholdPolicy::empty();
        let nobody = groups(&[]);
        assert!(policy.is_empty());
        assert!(!policy.has_withheld_rules(&nobody));
        assert!(!policy.is_path_withheld("config/billing/keys.json", &nobody));
        assert!(!policy.is_path_withheld("../invalid", &nobody));
        assert!(policy.withheld_patterns(&nobody).is_empty());
        assert!(policy.sparse_checkout_patterns(&nobody).is_empty());
    }

    #[test]
    fn multi_group_rules_and_overlapping_intersection() {
        let policy = compile(vec![
            rule("config/billing/**", &["finance", "admins"]),
            rule("*.secret", &["security"]),
            rule("vault/**", &[]),
        ]);

        let contractor = groups(&["contractors"]);
        let finance = groups(&["finance"]);
        let finance_and_security = groups(&["finance", "security"]);

        assert!(policy.has_withheld_rules(&contractor));
        assert!(policy.has_withheld_rules(&finance_and_security)); // vault/** has no groups

        // Public path is visible to everyone.
        assert!(!policy.is_path_withheld("README.md", &contractor));
        assert!(!policy.is_path_withheld("config/public.json", &contractor));

        // Billing path is withheld from contractors, visible to finance.
        assert!(policy.is_path_withheld("config/billing/keys.json", &contractor));
        assert!(!policy.is_path_withheld("config/billing/keys.json", &finance));

        // Overlap: `config/billing/api.secret` matches both `config/billing/**`
        // (finance|admins) and `*.secret` (security), so finance alone is still
        // withheld while finance+security sees it.
        assert!(policy.is_path_withheld("config/billing/api.secret", &finance));
        assert!(!policy.is_path_withheld("config/billing/api.secret", &finance_and_security));

        // Empty allowed_groups withholds from everyone.
        assert!(policy.is_path_withheld("vault/master.bin", &finance_and_security));
    }

    #[test]
    fn unanchored_anchored_case_insensitive_and_protected_paths() {
        let policy = compile(vec![
            rule("config/billing/**", &["finance"]),
            rule("*.secret", &["security"]),
            rule("foo/bar.txt", &["ops"]),
        ]);
        let contractor = groups(&["contractors"]);
        let all_allowed = groups(&["finance", "security", "ops"]);

        assert!(!policy.has_withheld_rules(&all_allowed));
        assert!(!policy.is_path_withheld("config/billing/a.json", &all_allowed));
        assert!(!policy.is_path_withheld("sub/deep.secret", &all_allowed));

        // Anchored vs unanchored matching.
        assert!(policy.is_path_withheld("foo/bar.txt", &contractor));
        assert!(!policy.is_path_withheld("sub/foo/bar.txt", &contractor));
        assert!(policy.is_path_withheld("root.secret", &contractor));
        assert!(policy.is_path_withheld("a/b/deep.secret", &contractor));

        // Case-sensitive vs case-insensitive.
        assert!(!policy.is_path_withheld("CONFIG/Billing/a.json", &contractor));
        assert!(policy.is_path_withheld_case_insensitive("CONFIG/Billing/a.json", &contractor));
        assert!(policy.is_path_withheld_case_insensitive("a/b/DEEP.SECRET", &contractor));

        // Protected metadata paths are never withheld.
        for protected in [
            ".gitattributes",
            ".git/config",
            ".scrim/paths.toml",
            ".scrim/keys/dev.toml",
        ] {
            assert!(
                !policy.is_path_withheld(protected, &contractor),
                "{protected}"
            );
        }

        // Malformed paths fail closed when the member has withheld rules.
        for bad in ["", "/config/a", "config//a", "a\\b", "a/../b", "config/a/"] {
            assert!(policy.is_path_withheld(bad, &contractor), "{bad:?}");
            assert!(!policy.is_path_withheld(bad, &all_allowed), "{bad:?}");
        }
    }

    #[test]
    fn sparse_checkout_patterns_are_sorted_and_properly_anchored() {
        let policy = compile(vec![
            rule("docs/internal/*.md", &["core"]),
            rule("config/billing/**", &["finance"]),
            rule("*.secret", &["security"]),
            rule(".billing/**", &["finance"]),
        ]);

        let contractor = groups(&["contractors"]);
        assert_eq!(
            policy.withheld_patterns(&contractor),
            vec![
                "*.secret",
                ".billing/**",
                "config/billing/**",
                "docs/internal/*.md",
            ]
        );
        assert_eq!(
            policy.sparse_checkout_patterns(&contractor),
            vec![
                "/*",
                "!*.secret",
                "!/.billing/**",
                "!/config/billing/**",
                "!/docs/internal/*.md",
            ]
        );

        let finance = groups(&["finance"]);
        assert_eq!(
            policy.sparse_checkout_patterns(&finance),
            vec!["/*", "!*.secret", "!/docs/internal/*.md"]
        );

        let full = groups(&["core", "finance", "security"]);
        assert!(policy.sparse_checkout_patterns(&full).is_empty());
    }
}
