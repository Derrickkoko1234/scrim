//! Criterion benchmarks for branch, path and withholding policy evaluation:
//! the per-ref and per-path checks the server runs on every fetch and push.

// The `?` operator and the unwrap/expect family are deliberately forbidden in
// this codebase; clippy's suggestion to use `?` is allowed away accordingly.
#![allow(clippy::question_mark)]

use std::collections::BTreeSet;
use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use scrim_policy::{BranchPolicy, BranchRule, PathPolicy, PathRule, WithholdPolicy, WithholdRule};

/// Number of rules in every benchmarked policy.
const RULE_COUNT: usize = 20;
/// Number of refs the branch benchmarks evaluate.
const REF_COUNT: usize = 200;
/// Number of paths the path benchmarks evaluate.
const PATH_COUNT: usize = 200;

/// Unwraps a setup result, panicking with `context` on failure.
fn must<T, E: std::fmt::Display>(result: Result<T, E>, context: &str) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("{context}: {error}"),
    }
}

/// The group names `g<index>` for each of `names`.
fn groups(names: &[usize]) -> BTreeSet<String> {
    names.iter().map(|index| format!("g{index}")).collect()
}

/// A mix of prefix globs, exact refs and complex globs, as a repository with
/// several restricted teams would configure.
fn branch_policy() -> BranchPolicy {
    let rules = (0..RULE_COUNT).map(|index| {
        let pattern = match index % 4 {
            0 => format!("refs/heads/team{index}/*"),
            1 => format!("refs/heads/release-{index}"),
            2 => format!("refs/tags/internal-{index}-*"),
            _ => format!("refs/heads/feature/*/team{index}"),
        };
        must(
            BranchRule::new(pattern, groups(&[index % 5, 5])),
            "branch rule",
        )
    });
    must(BranchPolicy::compile(rules), "compile branch policy")
}

/// Refs that hit every rule kind plus refs no rule restricts.
fn repo_refs() -> Vec<String> {
    (0..REF_COUNT)
        .map(|index| {
            let team = index % RULE_COUNT;
            match index % 5 {
                0 => format!("refs/heads/team{team}/work-{index}"),
                1 => format!("refs/heads/release-{team}"),
                2 => format!("refs/tags/internal-{team}-v{index}"),
                3 => format!("refs/heads/feature/x{index}/team{team}"),
                _ => format!("refs/heads/public-{index}"),
            }
        })
        .collect()
}

/// Path rules over disjoint directories so no path is ambiguous.
fn path_policy() -> PathPolicy {
    let rules = (0..RULE_COUNT).map(|index| {
        let pattern = match index % 2 {
            0 => format!("services/team{index}/config/**"),
            _ => format!("services/team{index}/keys/*.toml"),
        };
        must(
            PathRule::new(pattern, format!("g{}", index % 5)),
            "path rule",
        )
    });
    must(PathPolicy::compile(rules), "compile path policy")
}

/// Withholding rules, some overlapping, so intersection logic is exercised.
fn withhold_policy() -> WithholdPolicy {
    let rules = (0..RULE_COUNT).map(|index| {
        let pattern = match index % 3 {
            0 => format!("services/team{index}/**"),
            1 => format!("services/team{index}/config/*.toml"),
            _ => format!("*.team{index}"),
        };
        must(
            WithholdRule::new(pattern, groups(&[index % 5])),
            "withhold rule",
        )
    });
    must(WithholdPolicy::compile(rules), "compile withhold policy")
}

/// Paths under protected directories and unrestricted source files.
fn repo_paths() -> Vec<String> {
    (0..PATH_COUNT)
        .map(|index| {
            let team = index % RULE_COUNT;
            match index % 4 {
                0 => format!("services/team{team}/config/app-{index}.toml"),
                1 => format!("services/team{team}/keys/key-{index}.toml"),
                2 => format!("src/module{index}/lib.rs"),
                _ => format!("docs/notes-{index}.team{team}"),
            }
        })
        .collect()
}

fn branch_policy_visibility_and_hide_refs_plan(criterion: &mut Criterion) {
    let policy = branch_policy();
    let refs = repo_refs();
    let member = groups(&[1, 3]);
    let mut group = criterion.benchmark_group("branch_policy_visibility_and_hide_refs_plan");
    group.bench_function("is_ref_visible_200_refs", |bencher| {
        bencher.iter(|| {
            let mut visible = 0_usize;
            for ref_name in &refs {
                if policy.is_ref_visible(black_box(ref_name), black_box(&member)) {
                    visible += 1;
                }
            }
            black_box(visible)
        });
    });
    group.bench_function("resolve_hide_refs_200_refs", |bencher| {
        bencher.iter(|| {
            let plan = policy.hidden_ref_plan(black_box(&member));
            black_box(plan.resolve_hide_refs(&policy, &member, refs.iter().map(String::as_str)))
        });
    });
    group.finish();
}

fn path_policy_and_withhold_policy(criterion: &mut Criterion) {
    let path_policy = path_policy();
    let withhold_policy = withhold_policy();
    let paths = repo_paths();
    let member = groups(&[2]);
    let mut group = criterion.benchmark_group("path_policy_and_withhold_policy");
    group.bench_function("group_for_path_200_paths", |bencher| {
        bencher.iter(|| {
            let mut protected = 0_usize;
            for path in &paths {
                if let Ok(Some(_)) = path_policy.group_for_path(black_box(path)) {
                    protected += 1;
                }
            }
            black_box(protected)
        });
    });
    group.bench_function("is_path_withheld_200_paths", |bencher| {
        bencher.iter(|| {
            let mut withheld = 0_usize;
            for path in &paths {
                if withhold_policy.is_path_withheld(black_box(path), black_box(&member)) {
                    withheld += 1;
                }
            }
            black_box(withheld)
        });
    });
    group.bench_function("sparse_checkout_patterns", |bencher| {
        bencher.iter(|| black_box(withhold_policy.sparse_checkout_patterns(black_box(&member))));
    });
    group.finish();
}

criterion_group!(
    benches,
    branch_policy_visibility_and_hide_refs_plan,
    path_policy_and_withhold_policy
);
criterion_main!(benches);
