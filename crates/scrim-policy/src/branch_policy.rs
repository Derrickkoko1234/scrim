//! Branch rules, their compiled form, and `transfer.hideRefs` planning.
//!
//! Git's `transfer.hideRefs` does not take globs: each value hides the ref with
//! exactly that name plus every ref below it (`refs/heads/a` hides
//! `refs/heads/a` and `refs/heads/a/b`), trailing slashes are ignored, and a
//! value starting with `!` re-exposes refs, with later values winning. This
//! module turns glob rules into values with those semantics, statically where
//! possible and from the repository's ref list otherwise.

use std::collections::{BTreeMap, BTreeSet};

use globset::{GlobBuilder, GlobMatcher};

use crate::PolicyError;
use crate::ref_glob::validate_ref_glob;

/// Characters that make a pattern a glob rather than a literal ref name.
const GLOB_METACHARACTERS: [char; 6] = ['*', '?', '[', ']', '{', '}'];

/// Most symbolic-ref hops [`BranchPolicy::is_ref_chain_visible`] follows
/// before failing closed. Git itself gives up after 5.
const MAX_SYMREF_DEPTH: usize = 16;

/// Restricts every ref matching `pattern` to members of `allowed_groups`.
///
/// A rule with no allowed groups hides matching refs from everyone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BranchRule {
    /// Ref glob such as `refs/heads/private/*`; see [`validate_ref_glob`].
    pub pattern: String,
    /// Groups whose members may see refs matching `pattern`.
    pub allowed_groups: BTreeSet<String>,
}

impl BranchRule {
    /// Builds a rule after validating `pattern`.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::InvalidRefGlob`] when `pattern` fails
    /// [`validate_ref_glob`].
    pub fn new(
        pattern: impl Into<String>,
        allowed_groups: impl IntoIterator<Item = String>,
    ) -> Result<Self, PolicyError> {
        let pattern = pattern.into();
        if let Err(error) = validate_ref_glob(&pattern) {
            return Err(error);
        }
        Ok(Self {
            pattern,
            allowed_groups: allowed_groups.into_iter().collect(),
        })
    }
}

/// How a rule can be expressed as `transfer.hideRefs` values.
#[derive(Clone, Debug, PartialEq, Eq)]
enum RuleKind {
    /// `prefix*` or `prefix**` where `prefix` ends with `/` and is literal:
    /// hiding `prefix` hides exactly the refs the glob matches.
    PrefixGlob(String),
    /// A literal ref name. Hiding it in Git also hides refs below it, so a
    /// visible descendant needs a `!` negation found by listing refs.
    ExactRef(String),
    /// Any other glob; the hidden refs must be found by listing refs.
    ComplexGlob,
}

/// A validated rule ready for matching.
#[derive(Clone, Debug)]
struct CompiledRule {
    allowed_groups: BTreeSet<String>,
    matcher: GlobMatcher,
    kind: RuleKind,
}

/// A compiled set of [`BranchRule`]s.
///
/// Refs no rule matches are visible to everyone. A ref matched by several
/// rules is visible only to members allowed by every one of them, so adding a
/// rule can only hide more, never expose more.
#[derive(Clone, Debug)]
pub struct BranchPolicy {
    /// Ordered by pattern so planning output is deterministic.
    rules: Vec<CompiledRule>,
}

impl BranchPolicy {
    /// Validates and compiles `rules`.
    ///
    /// Rules with the same `pattern` are merged by taking the union of their
    /// allowed groups, so several grants on one glob combine. Rules with
    /// different patterns that match the same ref are not merged: each must
    /// allow the member (see [`BranchPolicy::is_ref_visible`]).
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::InvalidRefGlob`] when a pattern fails
    /// [`validate_ref_glob`] (fields are public, so rules are re-checked
    /// here), or [`PolicyError::GlobCompile`] when `globset` rejects it.
    pub fn compile(rules: impl IntoIterator<Item = BranchRule>) -> Result<Self, PolicyError> {
        let mut groups_by_pattern: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for rule in rules {
            if let Err(error) = validate_ref_glob(&rule.pattern) {
                return Err(error);
            }
            groups_by_pattern
                .entry(rule.pattern)
                .or_default()
                .extend(rule.allowed_groups);
        }

        let mut compiled_rules = Vec::with_capacity(groups_by_pattern.len());
        for (pattern, allowed_groups) in groups_by_pattern {
            // `literal_separator(false)` lets `*` match `/`, so
            // `refs/heads/private/*` also matches nested names such as
            // `refs/heads/private/alice/wip`. That matches Git's ref-glob
            // semantics and `transfer.hideRefs=refs/heads/private/`, which is
            // what makes a `PrefixGlob` rule exactly expressible in Git.
            let glob = match GlobBuilder::new(&pattern).literal_separator(false).build() {
                Ok(glob) => glob,
                Err(source) => return Err(PolicyError::GlobCompile { pattern, source }),
            };
            compiled_rules.push(CompiledRule {
                allowed_groups,
                matcher: glob.compile_matcher(),
                kind: classify_pattern(&pattern),
            });
        }
        Ok(Self {
            rules: compiled_rules,
        })
    }

    /// Returns `true` when the policy has no rules, so every ref is visible.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Reports whether a member of `member_groups` may see `ref_name`.
    ///
    /// Returns `true` when no rule matches. Otherwise returns `true` only if
    /// every matching rule shares at least one group with `member_groups`;
    /// a matching rule with no allowed groups hides the ref from everyone.
    pub fn is_ref_visible(&self, ref_name: &str, member_groups: &BTreeSet<String>) -> bool {
        self.rules
            .iter()
            .filter(|rule| rule.matcher.is_match(ref_name))
            .all(|rule| !rule.allowed_groups.is_disjoint(member_groups))
    }

    /// Reports whether a member of `member_groups` may see `ref_name` and
    /// every ref it leads to through `symrefs` (symbolic ref name -> target).
    ///
    /// Each hop must pass [`BranchPolicy::is_ref_visible`]: a visible symbolic
    /// ref pointing at a hidden branch would otherwise advertise the hidden
    /// branch's commit. Fails closed (returns `false`) on a cycle or a chain
    /// longer than 16 hops.
    pub fn is_ref_chain_visible(
        &self,
        ref_name: &str,
        symrefs: &BTreeMap<&str, &str>,
        member_groups: &BTreeSet<String>,
    ) -> bool {
        let mut visited = BTreeSet::new();
        let mut current = ref_name;
        for _ in 0..=MAX_SYMREF_DEPTH {
            if !visited.insert(current) || !self.is_ref_visible(current, member_groups) {
                return false;
            }
            match symrefs.get(current) {
                Some(target) => current = target,
                None => return true,
            }
        }
        false
    }

    /// Plans the `transfer.hideRefs` values for a member of `member_groups`.
    ///
    /// Only rules the member does not satisfy contribute. A [`HiddenRefPlan`]
    /// that does not need ref enumeration can be passed straight to Git via
    /// [`HiddenRefPlan::static_hide_refs`]; otherwise list the repository's
    /// refs and call [`HiddenRefPlan::resolve_hide_refs`].
    pub fn hidden_ref_plan(&self, member_groups: &BTreeSet<String>) -> HiddenRefPlan {
        let mut prefix_patterns = BTreeSet::new();
        let mut exact_refs = BTreeSet::new();
        let mut needs_ref_enumeration = false;
        let mut has_unsatisfied_rules = false;

        for rule in &self.rules {
            if !rule.allowed_groups.is_disjoint(member_groups) {
                continue;
            }
            has_unsatisfied_rules = true;
            match &rule.kind {
                // Sound without listing refs: every ref under the prefix
                // matches this rule, and one unsatisfied rule hides a ref.
                RuleKind::PrefixGlob(prefix) => {
                    prefix_patterns.insert(prefix.clone());
                }
                // Git would also hide visible refs below this name, so those
                // need `!` negations that only a ref listing can supply.
                RuleKind::ExactRef(ref_name) => {
                    exact_refs.insert(ref_name.clone());
                    needs_ref_enumeration = true;
                }
                RuleKind::ComplexGlob => needs_ref_enumeration = true,
            }
        }

        HiddenRefPlan {
            prefix_patterns: prefix_patterns.into_iter().collect(),
            exact_refs: exact_refs.into_iter().collect(),
            needs_ref_enumeration,
            has_unsatisfied_rules,
        }
    }
}

/// The `transfer.hideRefs` values one member needs, from
/// [`BranchPolicy::hidden_ref_plan`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HiddenRefPlan {
    /// Sorted, deduplicated prefixes ending in `/`, from `PrefixGlob` rules.
    prefix_patterns: Vec<String>,
    /// Sorted, deduplicated literal ref names, from `ExactRef` rules.
    exact_refs: Vec<String>,
    needs_ref_enumeration: bool,
    has_unsatisfied_rules: bool,
}

impl HiddenRefPlan {
    /// Returns `true` when [`HiddenRefPlan::static_hide_refs`] alone is not
    /// enough and the caller must list the repository's refs and call
    /// [`HiddenRefPlan::resolve_hide_refs`].
    pub fn needs_ref_enumeration(&self) -> bool {
        self.needs_ref_enumeration
    }

    /// Returns `true` when at least one rule is not satisfied by the member's
    /// groups, so some refs may be hidden from them.
    ///
    /// This holds even for a glob that matches none of the repository's
    /// current refs (and so yields no hide values): the member must still be
    /// served in the restricted mode, because such a ref may appear at any
    /// time. When `false`, every ref is visible to the member.
    pub fn has_unsatisfied_rules(&self) -> bool {
        self.has_unsatisfied_rules
    }

    /// Returns the hide values known without listing refs: one prefix ending
    /// in `/` per unsatisfied prefix rule, sorted.
    ///
    /// When [`HiddenRefPlan::needs_ref_enumeration`] is `false`, these can be
    /// passed to Git as-is, without running `git for-each-ref`. Git ignores
    /// the trailing `/`, so a ref named exactly like the prefix (for example
    /// `refs/heads/private` for rule `refs/heads/private/*`) is also hidden;
    /// that over-hides but never exposes.
    pub fn static_hide_refs(&self) -> &[String] {
        &self.prefix_patterns
    }

    /// Computes the full, ordered `transfer.hideRefs` values from the
    /// repository's current refs.
    ///
    /// `policy` and `member_groups` must be the ones this plan came from. The
    /// result lists the prefix patterns, then the exact refs and policy-hidden
    /// `repo_refs` not already covered by them (sorted), then a `!<ref>`
    /// negation (sorted) for each visible ref that a non-prefix entry would
    /// otherwise hide because it lies below it. Git lets later values win, so
    /// the negations come last. There are no duplicates.
    ///
    /// Refs created after `repo_refs` was listed are only hidden if a prefix
    /// or exact entry covers them, so list refs as close as possible to
    /// starting `git upload-pack`.
    ///
    /// Symbolic refs are judged by their own name only; use
    /// [`HiddenRefPlan::resolve_hide_refs_with_symrefs`] when the repository
    /// may contain symbolic refs.
    pub fn resolve_hide_refs<'a>(
        &self,
        policy: &BranchPolicy,
        member_groups: &BTreeSet<String>,
        repo_refs: impl IntoIterator<Item = &'a str>,
    ) -> Vec<String> {
        self.resolve_hide_refs_with_symrefs(policy, member_groups, repo_refs, &BTreeMap::new())
    }

    /// Like [`HiddenRefPlan::resolve_hide_refs`], but a ref counts as visible
    /// only if [`BranchPolicy::is_ref_chain_visible`] holds for it given
    /// `symrefs` (symbolic ref name -> target, from the same listing as
    /// `repo_refs`).
    ///
    /// A symbolic ref pointing at a hidden ref is therefore hidden by name and
    /// never re-exposed by a `!` negation, so Git cannot advertise it with the
    /// hidden ref's commit.
    pub fn resolve_hide_refs_with_symrefs<'a>(
        &self,
        policy: &BranchPolicy,
        member_groups: &BTreeSet<String>,
        repo_refs: impl IntoIterator<Item = &'a str>,
        symrefs: &BTreeMap<&str, &str>,
    ) -> Vec<String> {
        let is_covered_by_plan = |ref_name: &str| {
            self.prefix_patterns
                .iter()
                .chain(&self.exact_refs)
                .any(|hide_entry| git_hide_entry_matches(hide_entry, ref_name))
        };

        // Entries without a trailing `/`: the ones that can shadow a visible
        // ref below them. (A visible ref can never be below a prefix entry,
        // since the prefix rule matches it and the member fails that rule.)
        let mut hidden_ref_names = BTreeSet::new();
        for exact_ref in &self.exact_refs {
            let is_under_prefix = self
                .prefix_patterns
                .iter()
                .any(|prefix| git_hide_entry_matches(prefix, exact_ref));
            if !is_under_prefix {
                hidden_ref_names.insert(exact_ref.clone());
            }
        }

        let mut visible_refs = BTreeSet::new();
        for ref_name in repo_refs {
            if policy.is_ref_chain_visible(ref_name, symrefs, member_groups) {
                visible_refs.insert(ref_name);
            } else if !is_covered_by_plan(ref_name) {
                hidden_ref_names.insert(ref_name.to_owned());
            }
        }

        let negations: Vec<String> = visible_refs
            .into_iter()
            .filter(|visible_ref| {
                hidden_ref_names
                    .iter()
                    .any(|hidden_ref| is_strictly_below(visible_ref, hidden_ref))
            })
            .map(|visible_ref| format!("!{visible_ref}"))
            .collect();

        let mut hide_refs = self.prefix_patterns.clone();
        hide_refs.extend(hidden_ref_names);
        hide_refs.extend(negations);
        hide_refs
    }
}

/// Sorts a validated pattern into the [`RuleKind`] that decides how it is
/// expressed in `transfer.hideRefs`.
fn classify_pattern(pattern: &str) -> RuleKind {
    if !pattern.contains(GLOB_METACHARACTERS) {
        return RuleKind::ExactRef(pattern.to_owned());
    }
    // Try `**` before `*`, otherwise `prefix/**` would leave `prefix/*`.
    let prefix = match pattern.strip_suffix("**") {
        Some(stripped) if stripped.ends_with('/') => Some(stripped),
        _ => match pattern.strip_suffix('*') {
            Some(stripped) if stripped.ends_with('/') => Some(stripped),
            _ => None,
        },
    };
    match prefix {
        Some(prefix) if !prefix.contains(GLOB_METACHARACTERS) => {
            RuleKind::PrefixGlob(prefix.to_owned())
        }
        _ => RuleKind::ComplexGlob,
    }
}

/// Mirrors Git's `ref_is_hidden` for one positive `transfer.hideRefs` value:
/// trailing slashes are ignored, and the value matches the ref with that
/// exact name or any ref below it.
fn git_hide_entry_matches(hide_entry: &str, ref_name: &str) -> bool {
    let trimmed_entry = hide_entry.trim_end_matches('/');
    match ref_name.strip_prefix(trimmed_entry) {
        Some(rest) => rest.is_empty() || rest.starts_with('/'),
        None => false,
    }
}

/// Returns `true` when `ref_name` lies strictly below `ancestor` in the ref
/// hierarchy, such as `refs/heads/a/b` below `refs/heads/a`.
fn is_strictly_below(ref_name: &str, ancestor: &str) -> bool {
    ref_name.starts_with(ancestor) && ref_name.as_bytes().get(ancestor.len()) == Some(&b'/')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(pattern: &str, allowed_groups: &[&str]) -> BranchRule {
        let groups = allowed_groups.iter().map(|group| (*group).to_owned());
        match BranchRule::new(pattern, groups) {
            Ok(rule) => rule,
            Err(error) => panic!("rule {pattern:?} should be valid: {error}"),
        }
    }

    fn compile(rules: Vec<BranchRule>) -> BranchPolicy {
        match BranchPolicy::compile(rules) {
            Ok(policy) => policy,
            Err(error) => panic!("policy should compile: {error}"),
        }
    }

    fn groups(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|name| (*name).to_owned()).collect()
    }

    /// Simulates Git's `ref_is_hidden`: the last matching value wins.
    fn is_hidden_by_git(hide_refs: &[String], ref_name: &str) -> bool {
        for hide_entry in hide_refs.iter().rev() {
            let (is_negation, pattern) = match hide_entry.strip_prefix('!') {
                Some(pattern) => (true, pattern),
                None => (false, hide_entry.as_str()),
            };
            if git_hide_entry_matches(pattern, ref_name) {
                return !is_negation;
            }
        }
        false
    }

    #[test]
    fn classifies_patterns() {
        let cases = [
            (
                "refs/heads/private/*",
                RuleKind::PrefixGlob("refs/heads/private/".to_owned()),
            ),
            (
                "refs/heads/private/**",
                RuleKind::PrefixGlob("refs/heads/private/".to_owned()),
            ),
            (
                "refs/heads/secret",
                RuleKind::ExactRef("refs/heads/secret".to_owned()),
            ),
            ("refs/heads/*/secret", RuleKind::ComplexGlob),
            ("refs/heads/private-*", RuleKind::ComplexGlob),
            ("refs/heads/*/*", RuleKind::ComplexGlob),
            ("refs/heads/[ab]/*", RuleKind::ComplexGlob),
            ("refs/heads/private/***", RuleKind::ComplexGlob),
        ];
        for (pattern, expected) in cases {
            assert_eq!(classify_pattern(pattern), expected, "pattern {pattern:?}");
        }
    }

    #[test]
    fn new_rejects_invalid_pattern() {
        let result = BranchRule::new("heads/main", Vec::new());
        assert!(matches!(result, Err(PolicyError::InvalidRefGlob { .. })));
    }

    #[test]
    fn compile_revalidates_public_fields() {
        let invalid_rule = BranchRule {
            pattern: "refs/heads/../main".to_owned(),
            allowed_groups: BTreeSet::new(),
        };
        let result = BranchPolicy::compile([invalid_rule]);
        assert!(matches!(result, Err(PolicyError::InvalidRefGlob { .. })));
    }

    #[test]
    fn compile_reports_glob_errors() {
        let result = BranchPolicy::compile([rule("refs/heads/[abc", &[])]);
        assert!(matches!(result, Err(PolicyError::GlobCompile { .. })));
    }

    #[test]
    fn empty_policy_shows_everything() {
        let policy = compile(Vec::new());
        assert!(policy.is_empty());
        assert!(policy.is_ref_visible("refs/heads/main", &groups(&[])));
        let plan = policy.hidden_ref_plan(&groups(&[]));
        assert!(!plan.needs_ref_enumeration());
        assert!(plan.static_hide_refs().is_empty());
    }

    #[test]
    fn star_matches_nested_refs() {
        let policy = compile(vec![rule("refs/heads/private/*", &["core"])]);
        let outsider = groups(&["guests"]);
        assert!(!policy.is_ref_visible("refs/heads/private/wip", &outsider));
        assert!(!policy.is_ref_visible("refs/heads/private/alice/wip", &outsider));
        assert!(policy.is_ref_visible("refs/heads/private/alice/wip", &groups(&["core"])));
        assert!(policy.is_ref_visible("refs/heads/main", &outsider));
        assert!(policy.is_ref_visible("refs/heads/privateer", &outsider));
    }

    #[test]
    fn duplicate_patterns_merge_groups() {
        let policy = compile(vec![
            rule("refs/heads/private/*", &["core"]),
            rule("refs/heads/private/*", &["security"]),
        ]);
        assert_eq!(policy.rules.len(), 1);
        assert!(policy.is_ref_visible("refs/heads/private/x", &groups(&["core"])));
        assert!(policy.is_ref_visible("refs/heads/private/x", &groups(&["security"])));
        assert!(!policy.is_ref_visible("refs/heads/private/x", &groups(&["guests"])));
    }

    #[test]
    fn overlapping_rules_require_every_match() {
        let policy = compile(vec![
            rule("refs/heads/private/*", &["core"]),
            rule("refs/heads/*/secret", &["security"]),
        ]);
        let ref_name = "refs/heads/private/secret";
        assert!(!policy.is_ref_visible(ref_name, &groups(&["core"])));
        assert!(!policy.is_ref_visible(ref_name, &groups(&["security"])));
        assert!(policy.is_ref_visible(ref_name, &groups(&["core", "security"])));
    }

    #[test]
    fn rule_without_groups_hides_from_everyone() {
        let policy = compile(vec![rule("refs/heads/frozen", &[])]);
        assert!(!policy.is_ref_visible("refs/heads/frozen", &groups(&["core"])));
        assert!(policy.is_ref_visible("refs/heads/frozen/child", &groups(&["core"])));
    }

    #[test]
    fn prefix_only_plan_is_static_and_sorted() {
        let policy = compile(vec![
            rule("refs/heads/zeta/**", &["core"]),
            rule("refs/heads/alpha/*", &["core"]),
            rule("refs/heads/alpha/**", &["core"]),
            rule("refs/heads/shared/*", &["guests"]),
        ]);
        let plan = policy.hidden_ref_plan(&groups(&["guests"]));
        assert!(!plan.needs_ref_enumeration());
        assert_eq!(
            plan.static_hide_refs(),
            ["refs/heads/alpha/", "refs/heads/zeta/"]
        );
        // Members of every group get nothing hidden.
        let insider_plan = policy.hidden_ref_plan(&groups(&["core", "guests"]));
        assert_eq!(insider_plan, HiddenRefPlan::default());
    }

    #[test]
    fn exact_and_complex_rules_need_enumeration() {
        let exact_policy = compile(vec![rule("refs/heads/secret", &["core"])]);
        assert!(
            exact_policy
                .hidden_ref_plan(&groups(&[]))
                .needs_ref_enumeration()
        );
        let complex_policy = compile(vec![rule("refs/heads/*/secret", &["core"])]);
        let plan = complex_policy.hidden_ref_plan(&groups(&[]));
        assert!(plan.needs_ref_enumeration());
        assert!(plan.static_hide_refs().is_empty());
        // A satisfied rule never forces enumeration.
        assert!(
            !complex_policy
                .hidden_ref_plan(&groups(&["core"]))
                .needs_ref_enumeration()
        );
    }

    #[test]
    fn resolve_negates_visible_refs_below_exact_rule() {
        let policy = compile(vec![rule("refs/heads/secret", &["core"])]);
        let member = groups(&["guests"]);
        let plan = policy.hidden_ref_plan(&member);
        let repo_refs = ["refs/heads/main", "refs/heads/secret/public"];
        let hide_refs = plan.resolve_hide_refs(&policy, &member, repo_refs);
        assert_eq!(
            hide_refs,
            ["refs/heads/secret", "!refs/heads/secret/public"]
        );
    }

    #[test]
    fn resolve_skips_entries_covered_by_prefixes() {
        let policy = compile(vec![
            rule("refs/heads/private/*", &["core"]),
            rule("refs/heads/private/frozen", &["core"]),
            rule("refs/heads/*-wip", &["core"]),
        ]);
        let member = groups(&["guests"]);
        let plan = policy.hidden_ref_plan(&member);
        let repo_refs = [
            "refs/heads/private/a-wip",
            "refs/heads/feature-wip",
            "refs/heads/feature-wip",
            "refs/heads/main",
        ];
        let hide_refs = plan.resolve_hide_refs(&policy, &member, repo_refs);
        assert_eq!(hide_refs, ["refs/heads/private/", "refs/heads/feature-wip"]);
    }

    /// Checks that the resolved values make Git hide exactly the refs the
    /// policy hides, across a mix of rule kinds and members.
    #[test]
    fn resolved_values_match_policy_under_git_semantics() {
        let policy = compile(vec![
            rule("refs/heads/private/*", &["core"]),
            rule("refs/heads/secret", &["core"]),
            rule("refs/heads/*/secret", &["security"]),
            rule("refs/heads/release-*", &["release"]),
            rule("refs/tags/internal/**", &[]),
        ]);
        let repo_refs = [
            "refs/heads/main",
            "refs/heads/private/wip",
            "refs/heads/private/alice/wip",
            "refs/heads/secret/public",
            "refs/heads/team/secret",
            "refs/heads/team/open",
            "refs/heads/release-1",
            "refs/heads/released",
            "refs/tags/internal/v1",
            "refs/tags/v1",
        ];
        let members = [
            groups(&[]),
            groups(&["core"]),
            groups(&["security"]),
            groups(&["release"]),
            groups(&["core", "security", "release"]),
        ];
        for member in &members {
            let plan = policy.hidden_ref_plan(member);
            let hide_refs = plan.resolve_hide_refs(&policy, member, repo_refs);
            for ref_name in repo_refs {
                assert_eq!(
                    is_hidden_by_git(&hide_refs, ref_name),
                    !policy.is_ref_visible(ref_name, member),
                    "ref {ref_name:?} for member {member:?} with {hide_refs:?}"
                );
            }
            // Exact refs stay hidden even if absent from the listing.
            if !member.contains("core") {
                assert!(is_hidden_by_git(&hide_refs, "refs/heads/secret"));
                assert!(is_hidden_by_git(&hide_refs, "refs/heads/private/new"));
            }
        }
    }

    #[test]
    fn unsatisfied_complex_glob_is_reported_even_without_matching_refs() {
        let policy = compile(vec![rule("refs/heads/*-hidden", &["core"])]);
        let outsider = groups(&["guests"]);
        let plan = policy.hidden_ref_plan(&outsider);
        assert!(plan.has_unsatisfied_rules());
        assert!(
            plan.resolve_hide_refs(&policy, &outsider, std::iter::empty())
                .is_empty()
        );
        assert!(
            !policy
                .hidden_ref_plan(&groups(&["core"]))
                .has_unsatisfied_rules()
        );
        assert!(
            !compile(Vec::new())
                .hidden_ref_plan(&outsider)
                .has_unsatisfied_rules()
        );
    }

    #[test]
    fn ref_chain_visibility_checks_every_hop() {
        let policy = compile(vec![rule("refs/heads/private/*", &["core"])]);
        let outsider = groups(&["guests"]);
        let symrefs = BTreeMap::from([
            ("refs/heads/alias", "refs/heads/private/wip"),
            ("refs/heads/default", "refs/heads/alias"),
            ("refs/heads/public-alias", "refs/heads/main"),
            ("refs/heads/loop-a", "refs/heads/loop-b"),
            ("refs/heads/loop-b", "refs/heads/loop-a"),
        ]);
        assert!(policy.is_ref_chain_visible("refs/heads/main", &symrefs, &outsider));
        assert!(policy.is_ref_chain_visible("refs/heads/public-alias", &symrefs, &outsider));
        assert!(!policy.is_ref_chain_visible("refs/heads/alias", &symrefs, &outsider));
        assert!(!policy.is_ref_chain_visible("refs/heads/default", &symrefs, &outsider));
        assert!(!policy.is_ref_chain_visible("refs/heads/loop-a", &symrefs, &outsider));
        assert!(policy.is_ref_chain_visible("refs/heads/default", &symrefs, &groups(&["core"])));

        // A chain longer than the limit fails closed.
        let names: Vec<String> = (0..=MAX_SYMREF_DEPTH + 1)
            .map(|index| format!("refs/heads/hop{index}"))
            .collect();
        let long_chain: BTreeMap<&str, &str> = names
            .windows(2)
            .map(|pair| (pair[0].as_str(), pair[1].as_str()))
            .collect();
        assert!(!policy.is_ref_chain_visible(&names[0], &long_chain, &outsider));
    }

    #[test]
    fn symref_to_hidden_ref_is_hidden_and_never_negated() {
        let policy = compile(vec![
            rule("refs/heads/private/*", &["core"]),
            rule("refs/heads/secret", &["core"]),
        ]);
        let outsider = groups(&["guests"]);
        let plan = policy.hidden_ref_plan(&outsider);
        let repo_refs = [
            "refs/heads/main",
            "refs/heads/private/wip",
            "refs/heads/alias",
            "refs/heads/secret/alias",
            "refs/heads/secret/public",
        ];
        let symrefs = BTreeMap::from([
            ("refs/heads/alias", "refs/heads/private/wip"),
            ("refs/heads/secret/alias", "refs/heads/private/wip"),
        ]);
        let hide_refs =
            plan.resolve_hide_refs_with_symrefs(&policy, &outsider, repo_refs, &symrefs);
        assert_eq!(
            hide_refs,
            [
                "refs/heads/private/",
                "refs/heads/alias",
                // Also covers `refs/heads/secret/alias`, which gets no `!`.
                "refs/heads/secret",
                "!refs/heads/secret/public",
            ]
        );
        for ref_name in repo_refs {
            assert_eq!(
                is_hidden_by_git(&hide_refs, ref_name),
                !policy.is_ref_chain_visible(ref_name, &symrefs, &outsider),
                "ref {ref_name:?} with {hide_refs:?}"
            );
        }
    }

    #[test]
    fn git_hide_entry_matching_follows_git() {
        assert!(git_hide_entry_matches("refs/heads/a", "refs/heads/a"));
        assert!(git_hide_entry_matches("refs/heads/a", "refs/heads/a/b"));
        assert!(git_hide_entry_matches("refs/heads/a/", "refs/heads/a/b"));
        assert!(git_hide_entry_matches("refs/heads/a/", "refs/heads/a"));
        assert!(!git_hide_entry_matches("refs/heads/a", "refs/heads/ab"));
        assert!(!git_hide_entry_matches("refs/heads/a/", "refs/heads/ab"));
    }
}
