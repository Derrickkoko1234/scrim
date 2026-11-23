//! Criterion benchmark for the `pack-objects` hook's object selection, the
//! gix graph walk that leaves withheld blobs out of every fetch.
//!
//! Setup seeds one temporary bare repository (5 commits, 50 files split
//! between a public and a withheld directory) with the `git` CLI; only the
//! selection itself is measured.
//!
//! # Large repository (opt-in)
//!
//! Set `SCRIM_BENCH_REPO` to the path of a local bare repository (for
//! example `git clone --bare https://github.com/git/git.git`) to also run the
//! `compute_allowed_pack_objects_large_repo` group against it. The repository
//! is only read. A restricted member (in no group) fetches through rules that
//! default to the git/git layout and can be overridden:
//!
//! - `SCRIM_BENCH_WITHHOLD`: comma-separated path globs withheld from
//!   everyone outside the `internal` group (default `t/**,contrib/**`).
//! - `SCRIM_BENCH_HIDE_REFS`: comma-separated ref globs visible only to the
//!   `core` group (default hides git/git's integration branches and the
//!   `v1.*` and `gitgui-*` tags, and `junio-gpg-pub`, a tag naming a blob,
//!   which a withholding fetch refuses).
//! - `SCRIM_BENCH_INCREMENTAL_COMMITS`: how many first-parent commits the
//!   incremental fetch is behind (default 25).
//!
//! The clone walk wants every visible ref; the incremental walk wants the
//! default branch tip and has the commit that many first-parents back. Each
//! walk is compared with a plain `git pack-objects --revs --stdout` for the
//! same request, which is what an unrestricted member's fetch runs.

// The `?` operator and the unwrap/expect family are deliberately forbidden in
// this codebase; clippy's suggestion to use `?` is allowed away accordingly.
#![allow(clippy::question_mark)]

use std::collections::BTreeSet;
use std::hint::black_box;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};
use scrim_policy::{BranchPolicy, BranchRule, WithholdPolicy, WithholdRule};
use scrim_server::bench_support::compute_allowed_pack_objects_for_bench;

const COMMIT_COUNT: usize = 5;
/// Files per commit's tree: half public, half under the withheld directory.
const FILE_COUNT: usize = 50;
/// The hook arguments `git upload-pack` passes for a protocol v2 fetch.
const PACK_ARGS: [&str; 5] = ["git", "pack-objects", "--revs", "--thin", "--stdout"];

/// Names the local bare repository for the opt-in large-repository group.
const LARGE_REPO_ENV: &str = "SCRIM_BENCH_REPO";
/// Comma-separated withheld path globs for the large repository.
const WITHHOLD_ENV: &str = "SCRIM_BENCH_WITHHOLD";
/// Comma-separated hidden ref globs for the large repository.
const HIDE_REFS_ENV: &str = "SCRIM_BENCH_HIDE_REFS";
/// First-parent commits the incremental fetch is behind.
const INCREMENTAL_COMMITS_ENV: &str = "SCRIM_BENCH_INCREMENTAL_COMMITS";
/// Default rules, written for git/git.
const DEFAULT_WITHHOLD: &str = "t/**,contrib/**";
const DEFAULT_HIDE_REFS: &str = "refs/heads/next,refs/heads/seen,refs/heads/jch,refs/heads/test,refs/heads/bisect,refs/heads/todo,refs/tags/v1.*,refs/tags/gitgui-*,refs/tags/junio-gpg-pub";
const DEFAULT_INCREMENTAL_COMMITS: u32 = 25;

/// Runs `git <args>` in `dir` with an isolated config and returns its trimmed
/// stdout, panicking on failure.
fn git(dir: &Path, args: &[&str]) -> String {
    let mut command = Command::new("git");
    command
        .args(args)
        .current_dir(dir)
        .env_clear()
        .stdin(Stdio::null());
    if let Some(path) = std::env::var_os("PATH") {
        command.env("PATH", path);
    }
    command
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_AUTHOR_NAME", "Scrim Bench")
        .env("GIT_AUTHOR_EMAIL", "bench@scrim.invalid")
        .env("GIT_COMMITTER_NAME", "Scrim Bench")
        .env("GIT_COMMITTER_EMAIL", "bench@scrim.invalid");
    let output = match command.output() {
        Ok(output) => output,
        Err(error) => panic!("failed to run git {args:?}: {error}"),
    };
    if !output.status.success() {
        panic!(
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    match String::from_utf8(output.stdout) {
        Ok(stdout) => stdout.trim().to_owned(),
        Err(error) => panic!("git {args:?} printed non-UTF-8 output: {error}"),
    }
}

/// Writes `contents` to `root/path`, creating parent directories.
fn write_file(root: &Path, path: &str, contents: &str) {
    let full_path = root.join(path);
    if let Some(parent) = full_path.parent()
        && let Err(error) = std::fs::create_dir_all(parent)
    {
        panic!("failed to create {}: {error}", parent.display());
    }
    if let Err(error) = std::fs::write(&full_path, contents) {
        panic!("failed to write {path}: {error}");
    }
}

/// The seeded bare repository plus the commit IDs the benchmarks fetch.
struct SeededRepo {
    _root: tempfile::TempDir,
    bare_dir: PathBuf,
    head: String,
    parent: String,
}

/// Builds the repository: every commit rewrites a fifth of the files so each
/// incremental fetch has new public and withheld blobs to classify.
fn seed_repo() -> SeededRepo {
    let root = match tempfile::tempdir() {
        Ok(root) => root,
        Err(error) => panic!("failed to create temp dir: {error}"),
    };
    let work = root.path().join("work");
    if let Err(error) = std::fs::create_dir_all(&work) {
        panic!("failed to create work dir: {error}");
    }
    git(&work, &["init", "--quiet", "--initial-branch=main"]);
    for commit in 0..COMMIT_COUNT {
        for file in 0..FILE_COUNT {
            if commit > 0 && file % COMMIT_COUNT != commit {
                continue;
            }
            let directory = if file % 2 == 0 {
                "public/src"
            } else {
                "config/billing"
            };
            write_file(
                &work,
                &format!("{directory}/file-{file:02}.txt"),
                &format!("file {file} at commit {commit}\n{}\n", "data ".repeat(40)),
            );
        }
        git(&work, &["add", "--all"]);
        git(
            &work,
            &["commit", "--quiet", "-m", &format!("commit {commit}")],
        );
    }
    let bare_dir = root.path().join("bare.git");
    let Some(bare_path) = bare_dir.to_str() else {
        panic!("temp dir path is not UTF-8");
    };
    git(
        root.path(),
        &["clone", "--quiet", "--bare", "work", bare_path],
    );
    let head = git(&bare_dir, &["rev-parse", "HEAD"]);
    let parent = git(&bare_dir, &["rev-parse", "HEAD~1"]);
    SeededRepo {
        _root: root,
        bare_dir,
        head,
        parent,
    }
}

/// Withholds `config/billing/**` from everyone outside `billing`.
fn billing_policy() -> WithholdPolicy {
    let rule = match WithholdRule::new("config/billing/**", ["billing".to_owned()]) {
        Ok(rule) => rule,
        Err(error) => panic!("rule should be valid: {error}"),
    };
    match WithholdPolicy::compile([rule]) {
        Ok(policy) => policy,
        Err(error) => panic!("policy should compile: {error}"),
    }
}

fn compute_allowed_pack_objects(criterion: &mut Criterion) {
    let repo = seed_repo();
    let policy = billing_policy();
    let member_groups: BTreeSet<String> = ["engineering".to_owned()].into_iter().collect();
    let pack_args: Vec<String> = PACK_ARGS.iter().map(|arg| (*arg).to_owned()).collect();
    let no_tags: Vec<String> = Vec::new();
    let clone_stdin = format!("{}\n", repo.head);
    let fetch_stdin = format!("{}\n--not\n{}\n", repo.head, repo.parent);

    // Fail fast if setup is wrong instead of benchmarking an error path.
    for stdin in [&clone_stdin, &fetch_stdin] {
        if let Err(error) = compute_allowed_pack_objects_for_bench(
            &repo.bare_dir,
            &pack_args,
            stdin.as_bytes(),
            &policy,
            &member_groups,
            &no_tags,
        ) {
            panic!("selection failed for {stdin:?}: {error}");
        }
    }

    let mut group = criterion.benchmark_group("compute_allowed_pack_objects");
    for (name, stdin) in [
        ("initial_clone_walk", &clone_stdin),
        ("incremental_fetch_walk", &fetch_stdin),
    ] {
        group.bench_function(name, |bencher| {
            bencher.iter(|| {
                black_box(compute_allowed_pack_objects_for_bench(
                    &repo.bare_dir,
                    &pack_args,
                    black_box(stdin.as_bytes()),
                    &policy,
                    &member_groups,
                    &no_tags,
                ))
            });
        });
    }
    group.finish();
}

/// Splits the comma-separated environment variable `name`, using `default`
/// when it is unset.
fn comma_separated_env(name: &str, default: &str) -> Vec<String> {
    let value = match std::env::var(name) {
        Ok(value) => value,
        Err(_) => default.to_owned(),
    };
    value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Runs plain `git pack-objects --revs --stdout` in `repo_dir` with `stdin`,
/// discarding the pack: the work an unrestricted member's fetch costs.
fn plain_pack_objects(repo_dir: &Path, stdin: &[u8]) {
    let mut command = Command::new("git");
    command
        .args(["pack-objects", "--revs", "--thin", "--stdout", "--quiet"])
        .current_dir(repo_dir)
        .env_clear()
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Some(path) = std::env::var_os("PATH") {
        command.env("PATH", path);
    }
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => panic!("failed to spawn git pack-objects: {error}"),
    };
    if let Some(mut child_stdin) = child.stdin.take()
        && let Err(error) = child_stdin.write_all(stdin)
    {
        panic!("failed to feed git pack-objects: {error}");
    }
    match child.wait() {
        Ok(status) if status.success() => {}
        Ok(status) => panic!("git pack-objects failed: {status}"),
        Err(error) => panic!("failed to wait for git pack-objects: {error}"),
    }
}

/// Selection walk and plain `git pack-objects` against `SCRIM_BENCH_REPO`, if
/// set; does nothing otherwise.
fn compute_allowed_pack_objects_large_repo(criterion: &mut Criterion) {
    let Some(repo_dir) = std::env::var_os(LARGE_REPO_ENV).map(PathBuf::from) else {
        return;
    };
    let mut withhold_rules: Vec<WithholdRule> = Vec::new();
    for pattern in comma_separated_env(WITHHOLD_ENV, DEFAULT_WITHHOLD) {
        match WithholdRule::new(pattern.clone(), ["internal".to_owned()]) {
            Ok(rule) => withhold_rules.push(rule),
            Err(error) => panic!("invalid {WITHHOLD_ENV} glob {pattern:?}: {error}"),
        }
    }
    let policy = match WithholdPolicy::compile(withhold_rules) {
        Ok(policy) => policy,
        Err(error) => panic!("policy should compile: {error}"),
    };
    let mut branch_rules: Vec<BranchRule> = Vec::new();
    for pattern in comma_separated_env(HIDE_REFS_ENV, DEFAULT_HIDE_REFS) {
        match BranchRule::new(pattern.clone(), ["core".to_owned()]) {
            Ok(rule) => branch_rules.push(rule),
            Err(error) => panic!("invalid {HIDE_REFS_ENV} glob {pattern:?}: {error}"),
        }
    }
    let branch_policy = match BranchPolicy::compile(branch_rules) {
        Ok(policy) => policy,
        Err(error) => panic!("branch policy should compile: {error}"),
    };
    // The restricted member the benchmark fetches as: in neither group.
    let member_groups: BTreeSet<String> = BTreeSet::new();

    let refs = git(
        &repo_dir,
        &["for-each-ref", "--format=%(objectname) %(refname)"],
    );
    let mut visible_wants: BTreeSet<String> = BTreeSet::new();
    let mut visible_tag_refs: Vec<String> = Vec::new();
    let mut hidden_ref_count = 0_usize;
    for line in refs.lines() {
        let Some((object_id, ref_name)) = line.split_once(' ') else {
            panic!("unexpected for-each-ref line: {line:?}");
        };
        if !branch_policy.is_ref_visible(ref_name, &member_groups) {
            hidden_ref_count += 1;
            continue;
        }
        visible_wants.insert(object_id.to_owned());
        if ref_name.starts_with("refs/tags/") {
            visible_tag_refs.push(ref_name.to_owned());
        }
    }
    let default_branch = git(&repo_dir, &["symbolic-ref", "HEAD"]);
    let behind_commits = match std::env::var(INCREMENTAL_COMMITS_ENV) {
        Ok(value) => match value.parse::<u32>() {
            Ok(commits) => commits,
            Err(error) => panic!("{INCREMENTAL_COMMITS_ENV} must be a number: {error}"),
        },
        Err(_) => DEFAULT_INCREMENTAL_COMMITS,
    };
    let tip = git(&repo_dir, &["rev-parse", &default_branch]);
    let behind = git(
        &repo_dir,
        &["rev-parse", &format!("{default_branch}~{behind_commits}")],
    );
    let clone_stdin: String = visible_wants.iter().map(|id| format!("{id}\n")).collect();
    let fetch_stdin = format!("{tip}\n--not\n{behind}\n");
    eprintln!(
        "large repo {}: {} visible want(s), {hidden_ref_count} hidden ref(s), {} visible tag(s), incremental fetch {behind_commits} commit(s) behind {default_branch}",
        repo_dir.display(),
        visible_wants.len(),
        visible_tag_refs.len(),
    );

    let pack_args: Vec<String> = PACK_ARGS.iter().map(|arg| (*arg).to_owned()).collect();
    let mut group = criterion.benchmark_group("compute_allowed_pack_objects_large_repo");
    // One walk takes seconds on a large history: keep sample counts low.
    group
        .sample_size(10)
        .measurement_time(Duration::from_secs(30));
    for (name, stdin) in [
        ("initial_clone_walk", &clone_stdin),
        ("incremental_fetch_walk", &fetch_stdin),
    ] {
        match compute_allowed_pack_objects_for_bench(
            &repo_dir,
            &pack_args,
            stdin.as_bytes(),
            &policy,
            &member_groups,
            &visible_tag_refs,
        ) {
            Ok(selected) => eprintln!("large repo {name}: {selected} object(s) selected"),
            Err(error) => panic!("selection failed for {name}: {error}"),
        }
        group.bench_function(name, |bencher| {
            bencher.iter(|| {
                black_box(compute_allowed_pack_objects_for_bench(
                    &repo_dir,
                    &pack_args,
                    black_box(stdin.as_bytes()),
                    &policy,
                    &member_groups,
                    &visible_tag_refs,
                ))
            });
        });
    }
    for (name, stdin) in [
        ("plain_pack_objects_initial_clone", &clone_stdin),
        ("plain_pack_objects_incremental_fetch", &fetch_stdin),
    ] {
        group.bench_function(name, |bencher| {
            bencher.iter(|| plain_pack_objects(&repo_dir, black_box(stdin.as_bytes())));
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    compute_allowed_pack_objects,
    compute_allowed_pack_objects_large_repo
);
criterion_main!(benches);
