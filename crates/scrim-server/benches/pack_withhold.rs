//! Criterion benchmark for the `pack-objects` hook's object selection, the
//! gix graph walk that leaves withheld blobs out of every fetch.
//!
//! Setup seeds one temporary bare repository (5 commits, 50 files split
//! between a public and a withheld directory) with the `git` CLI; only the
//! selection itself is measured.

// The `?` operator and the unwrap/expect family are deliberately forbidden in
// this codebase; clippy's suggestion to use `?` is allowed away accordingly.
#![allow(clippy::question_mark)]

use std::collections::BTreeSet;
use std::hint::black_box;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use criterion::{Criterion, criterion_group, criterion_main};
use scrim_policy::{WithholdPolicy, WithholdRule};
use scrim_server::bench_support::compute_allowed_pack_objects_for_bench;

const COMMIT_COUNT: usize = 5;
/// Files per commit's tree: half public, half under the withheld directory.
const FILE_COUNT: usize = 50;
/// The hook arguments `git upload-pack` passes for a protocol v2 fetch.
const PACK_ARGS: [&str; 5] = ["git", "pack-objects", "--revs", "--thin", "--stdout"];

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

criterion_group!(benches, compute_allowed_pack_objects);
criterion_main!(benches);
