//! Fuzzes ref/path glob and group-name validation, policy compilation and
//! every lookup on the compiled branch, path and withholding policies.
//!
//! The input's lines are split into rule lines (`<pattern> <group>...`) and
//! query lines: everything before the first empty line is rules.

#![no_main]
// The `?` operator and the unwrap/expect family are deliberately forbidden in
// this codebase; clippy's suggestion to use `?` is allowed away accordingly.
#![allow(clippy::question_mark)]

use std::collections::{BTreeMap, BTreeSet};

use libfuzzer_sys::fuzz_target;
use scrim_policy::{
    BranchPolicy, BranchRule, PathPolicy, PathRule, WithholdPolicy, WithholdRule,
    is_protected_metadata_path, normalize_repo_path, validate_group_name, validate_path_glob,
    validate_ref_glob,
};

/// Bounds compile time per input; real policies hold far fewer rules.
const MAX_RULES: usize = 32;

fuzz_target!(|input: &str| {
    let (rule_text, query_text) = match input.split_once("\n\n") {
        Some((rules, queries)) => (rules, queries),
        None => (input, input),
    };

    let mut branch_rules = Vec::new();
    let mut path_rules = Vec::new();
    let mut withhold_rules = Vec::new();
    for line in rule_text.lines().take(MAX_RULES) {
        let mut words = line.split(' ');
        let pattern = match words.next() {
            Some(pattern) => pattern,
            None => continue,
        };
        let groups: Vec<String> = words.map(str::to_owned).collect();
        let _ = validate_ref_glob(pattern);
        let _ = validate_path_glob(pattern);
        for group in &groups {
            let _ = validate_group_name(group);
        }
        if let Ok(rule) = BranchRule::new(pattern, groups.clone()) {
            branch_rules.push(rule);
        }
        if let Some(group) = groups.first()
            && let Ok(rule) = PathRule::new(pattern, group.clone())
        {
            path_rules.push(rule);
        }
        if let Ok(rule) = WithholdRule::new(pattern, groups) {
            withhold_rules.push(rule);
        }
    }

    let queries: Vec<&str> = query_text.lines().take(MAX_RULES).collect();
    let member_groups: BTreeSet<String> = match queries.first() {
        Some(first) => first.split(' ').map(str::to_owned).collect(),
        None => BTreeSet::new(),
    };
    let symrefs: BTreeMap<&str, &str> = queries
        .iter()
        .filter_map(|query| query.split_once(" -> "))
        .collect();

    if let Ok(policy) = BranchPolicy::compile(branch_rules) {
        let plan = policy.hidden_ref_plan(&member_groups);
        let _ = plan.static_hide_refs();
        let _ = plan.resolve_hide_refs(&policy, &member_groups, queries.iter().copied());
        let _ = plan.resolve_hide_refs_with_symrefs(
            &policy,
            &member_groups,
            queries.iter().copied(),
            &symrefs,
        );
        for query in &queries {
            let _ = policy.is_ref_visible(query, &member_groups);
            let _ = policy.is_ref_visible_case_insensitive(query, &member_groups);
            let _ = policy.is_ref_chain_visible(query, &symrefs, &member_groups);
            if let Some(other) = queries.last() {
                let _ = policy.is_ref_at_least_as_visible_as(query, other);
                let _ = policy.is_ref_chain_at_least_as_visible_as(query, &symrefs, other);
            }
        }
    }

    let path_policy = PathPolicy::compile(path_rules);
    let withhold_policy = WithholdPolicy::compile(withhold_rules);
    for query in &queries {
        let _ = normalize_repo_path(query);
        let _ = is_protected_metadata_path(query);
        if let Ok(policy) = &path_policy {
            let _ = policy.group_for_path(query);
            let _ = policy.is_path_private(query);
        }
        if let Ok(policy) = &withhold_policy {
            let _ = policy.is_path_withheld(query, &member_groups);
            let _ = policy.is_path_withheld_case_insensitive(query, &member_groups);
        }
    }
    if let Ok(policy) = &path_policy {
        let _ = policy.groups();
    }
    if let Ok(policy) = &withhold_policy {
        let _ = policy.has_withheld_rules(&member_groups);
        let _ = policy.withheld_patterns(&member_groups);
        let _ = policy.sparse_checkout_patterns(&member_groups);
    }
});
