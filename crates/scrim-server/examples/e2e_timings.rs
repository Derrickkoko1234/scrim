//! End-to-end clone and fetch timings through an in-process `scrim-server`,
//! compared with plain `git` against the same repository.
//!
//! This is an opt-in harness, not a test: it is an example (so it is never
//! run by `cargo test`, and, being compiled in release mode on demand, times
//! optimized code) and does nothing unless `SCRIM_E2E_REPO` names a local
//! bare repository. It needs no `tests/common` helpers and uses only crates
//! the server already depends on or has as dev-dependencies.
//!
//! ```text
//! git clone --bare https://github.com/git/git.git "$TMPDIR/scrim-bench/git.git"
//! cargo build --release -p scrim-server --bin scrim-server
//! SCRIM_E2E_REPO="$TMPDIR/scrim-bench/git.git" \
//!     cargo run --release -p scrim-server --example e2e_timings
//! ```
//!
//! The pack-objects hook is the `scrim-server` binary, so build it first (the
//! harness looks next to `examples/`, or at `SCRIM_HOOK_BIN`).
//!
//! # Setup
//!
//! The repository is copied (hardlinked, read-only use of the source) to
//! `team.git` in a temporary repo root served over smart HTTP and SSH on
//! loopback ports by a [`MemoryPolicyStore`]:
//!
//! - `alice` is in `core` and `internal`: sees every ref and path.
//! - `bob` is in no group: the path rules withhold `SCRIM_E2E_WITHHOLD`
//!   (default `t/**,contrib/**`) from him and the ref rules hide
//!   `SCRIM_E2E_HIDE_REFS` (defaults suit git/git, including
//!   its one tag that names a blob, which a withholding fetch refuses).
//!
//! # Measurements
//!
//! Every scenario clones with `git clone --no-checkout` (checkout cost is
//! identical with or without Scrim, and `scrim clone` checks out afterwards),
//! `SCRIM_E2E_RUNS` times (default 3), into fresh directories. Then five new
//! commits (each touching one public and one withheld file) are pushed straight
//! into the repository and every clone runs a timed `git fetch`. Scenarios:
//!
//! 1. baseline: plain `git clone file://<bare>`,
//! 2. smart HTTP, `alice`, full clone,
//! 3. smart HTTP, `bob`, partial clone with
//!    `--filter=blob:limit=2147483647` (as `scrim clone` does),
//! 4. SSH, `alice`, full clone,
//! 5. SSH, `bob`, partial clone.
//!
//! The report (Markdown, on stdout) gives median, minimum and maximum
//! wall-clock times, the clone's pack size, and how many objects a restricted
//! clone is missing, so the rules are shown to have applied.
//!
//! # Hang safety
//!
//! Every `git` runs with no stdin, `GIT_TERMINAL_PROMPT=0`, an isolated
//! `HOME` and global config, and a hard timeout. Every `ssh` runs with
//! `-F /dev/null`, `IdentitiesOnly`, `IdentityAgent=none`, `BatchMode`, no
//! host-key checking and no known-hosts file, and commands inside partial
//! clones set `GIT_NO_LAZY_FETCH=1` so git never lazily spawns a plain `ssh`.

// The `?` operator and the unwrap/expect family are deliberately forbidden in
// this codebase; clippy's suggestion to use `?` is allowed away accordingly.
#![allow(clippy::question_mark)]

use std::{
    fmt::Write as _,
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};

use scrim_policy::{BranchRule, WithholdRule};
use scrim_server::{
    AuthenticatedMember, MemoryPolicyStore, PolicyStore, SharedHookDir, SshServerConfig,
    load_or_create_ssh_host_key, router_with_hook_dir, serve_ssh,
};
use tempfile::TempDir;

/// Names the local bare repository to benchmark; the harness is inert
/// without it.
const REPO_ENV: &str = "SCRIM_E2E_REPO";
/// Timed runs per scenario.
const RUNS_ENV: &str = "SCRIM_E2E_RUNS";
/// Comma-separated path globs withheld from members outside `internal`.
const WITHHOLD_ENV: &str = "SCRIM_E2E_WITHHOLD";
/// Comma-separated ref globs visible only to members of `core`.
const HIDE_REFS_ENV: &str = "SCRIM_E2E_HIDE_REFS";
/// Defaults written for git/git.
const DEFAULT_WITHHOLD: &str = "t/**,contrib/**";
const DEFAULT_HIDE_REFS: &str = "refs/heads/next,refs/heads/seen,refs/heads/jch,refs/heads/test,refs/heads/bisect,refs/heads/todo,refs/tags/v1.*,refs/tags/gitgui-*,refs/tags/junio-gpg-pub";
const DEFAULT_RUNS: usize = 3;
/// New commits pushed before the timed fetches.
const NEW_COMMIT_COUNT: usize = 5;
/// One git command may not run longer than this.
const COMMAND_TIMEOUT: Duration = Duration::from_secs(900);
/// The partial-clone filter `scrim clone` uses.
const PARTIAL_CLONE_FILTER: &str = "--filter=blob:limit=2147483647";
/// A public file and a withheld file (under the default rules) that the new
/// commits append to; both exist in git/git.
const PUBLIC_FILE: &str = "README.md";
const WITHHELD_FILE: &str = "t/README";

const ALICE_TOKEN: &str = "alice-token-0123456789abcdef";
const BOB_TOKEN: &str = "bob-token-0123456789abcdef";
const ALICE_KEY: &str = "alice_ed25519";
const BOB_KEY: &str = "bob_ed25519";

/// How a scenario reaches the repository and who it acts as.
#[derive(Clone)]
enum Access {
    /// A `file://` URL: plain git with no Scrim in the path.
    File,
    /// Smart HTTP with a bearer token.
    Http { token: &'static str },
    /// SSH with the key file `key` in the key directory.
    Ssh { key: &'static str },
}

/// One row of the report.
#[derive(Clone)]
struct Scenario {
    name: &'static str,
    access: Access,
    /// Clone as a partial clone, as a restricted member's `scrim clone` does.
    partial: bool,
}

/// Timings and facts gathered for one scenario.
struct Measurement {
    clone_times: Vec<Duration>,
    fetch_times: Vec<Duration>,
    pack_kib: u64,
    objects_in_pack: u64,
    /// `None` for full clones.
    missing_objects: Option<u64>,
    refs_received: usize,
}

/// A git command's outcome.
struct GitOutput {
    elapsed: Duration,
    stdout: String,
}

/// Runs git (and ssh through it) in an isolated, non-interactive
/// environment.
struct GitRunner {
    home: TempDir,
    key_dir: PathBuf,
}

impl GitRunner {
    /// The `ssh` command line for the key file `key`, safe against agents,
    /// user config, prompts and host-key files.
    fn ssh_command(&self, key: &str) -> String {
        let key_path = self.key_dir.join(key);
        [
            "-F",
            "/dev/null",
            "-i",
            utf8(&key_path),
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "IdentityAgent=none",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "LogLevel=ERROR",
        ]
        .iter()
        .fold(String::from("ssh"), |command, option| {
            format!("{command} '{option}'")
        })
    }

    /// Runs `git <args>` in `dir` with `extra_env`, killing it after
    /// [`COMMAND_TIMEOUT`] and panicking with its stderr on any failure.
    fn git(&self, dir: &Path, args: &[&str], extra_env: &[(&str, &str)]) -> GitOutput {
        let mut stdout_file = match tempfile::tempfile() {
            Ok(file) => file,
            Err(error) => panic!("failed to create a stdout capture file: {error}"),
        };
        let mut stderr_file = match tempfile::tempfile() {
            Ok(file) => file,
            Err(error) => panic!("failed to create a stderr capture file: {error}"),
        };
        let stdout_handle = match stdout_file.try_clone() {
            Ok(file) => file,
            Err(error) => panic!("failed to clone the stdout capture file: {error}"),
        };
        let stderr_handle = match stderr_file.try_clone() {
            Ok(file) => file,
            Err(error) => panic!("failed to clone the stderr capture file: {error}"),
        };
        let path = match std::env::var_os("PATH") {
            Some(path) => path,
            None => panic!("PATH is not set"),
        };
        let started = Instant::now();
        let mut child = match Command::new("git")
            .args([
                "-c",
                "user.name=Scrim Bench",
                "-c",
                "user.email=bench@scrim.invalid",
            ])
            .args(args)
            .current_dir(dir)
            .env_clear()
            .env("PATH", path)
            .env("HOME", self.home.path())
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_TERMINAL_PROMPT", "0")
            .envs(extra_env.iter().copied())
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout_handle))
            .stderr(Stdio::from(stderr_handle))
            .spawn()
        {
            Ok(child) => child,
            Err(error) => panic!("failed to run git {args:?}: {error}"),
        };
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) => {}
                Err(error) => panic!("failed to wait for git {args:?}: {error}"),
            }
            if started.elapsed() > COMMAND_TIMEOUT {
                if let Err(error) = child.kill() {
                    eprintln!("failed to kill timed-out git: {error}");
                }
                if let Err(error) = child.wait() {
                    eprintln!("failed to reap timed-out git: {error}");
                }
                panic!(
                    "git {args:?} timed out after {COMMAND_TIMEOUT:?}: {}",
                    read_capture(&mut stderr_file)
                );
            }
            std::thread::sleep(Duration::from_millis(1));
        };
        let elapsed = started.elapsed();
        if !status.success() {
            panic!(
                "git {args:?} failed ({status}): {}",
                read_capture(&mut stderr_file)
            );
        }
        GitOutput {
            elapsed,
            stdout: read_capture(&mut stdout_file).trim().to_owned(),
        }
    }
}

/// Reads a capture file from the start.
fn read_capture(file: &mut std::fs::File) -> String {
    if let Err(error) = file.seek(SeekFrom::Start(0)) {
        panic!("failed to rewind a capture file: {error}");
    }
    let mut contents = Vec::new();
    if let Err(error) = file.read_to_end(&mut contents) {
        panic!("failed to read a capture file: {error}");
    }
    String::from_utf8_lossy(&contents).into_owned()
}

fn utf8(path: &Path) -> &str {
    match path.to_str() {
        Some(path) => path,
        None => panic!("path is not UTF-8: {}", path.display()),
    }
}

fn temp_dir() -> TempDir {
    match TempDir::new() {
        Ok(dir) => dir,
        Err(error) => panic!("failed to create a temporary directory: {error}"),
    }
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

/// Generates an Ed25519 key pair at `<dir>/<name>` and returns the public
/// key line.
fn generate_ssh_key(dir: &Path, name: &str) -> String {
    let path = dir.join(name);
    let output = match Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-C"])
        .arg(format!("{name}@bench"))
        .arg("-f")
        .arg(&path)
        .stdin(Stdio::null())
        .output()
    {
        Ok(output) => output,
        Err(error) => panic!("failed to run ssh-keygen: {error}"),
    };
    assert!(
        output.status.success(),
        "ssh-keygen failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    match std::fs::read_to_string(path.with_extension("pub")) {
        Ok(public_key) => public_key,
        Err(error) => panic!("failed to read {name}.pub: {error}"),
    }
}

/// Median of `times`; the mean of the two middle values for an even count.
fn median(times: &[Duration]) -> Duration {
    let mut sorted = times.to_vec();
    sorted.sort();
    let middle = sorted.len() / 2;
    match (
        sorted.get(middle),
        middle.checked_sub(1).and_then(|i| sorted.get(i)),
    ) {
        (Some(upper), Some(lower)) if sorted.len().is_multiple_of(2) => (*upper + *lower) / 2,
        (Some(upper), _) => *upper,
        (None, _) => Duration::ZERO,
    }
}

/// `median (min-max)` in seconds, or `-` when nothing was measured.
fn format_times(times: &[Duration]) -> String {
    let (Some(min), Some(max)) = (times.iter().min(), times.iter().max()) else {
        return "-".to_owned();
    };
    format!(
        "{:.2} s ({:.2}-{:.2})",
        median(times).as_secs_f64(),
        min.as_secs_f64(),
        max.as_secs_f64()
    )
}

/// The served repository, both transports, and the scratch space.
struct Harness {
    git: GitRunner,
    scratch: TempDir,
    /// Bare repository the servers serve (`<repo root>/team.git`).
    served_repo: PathBuf,
    /// Working clone the new commits are made in.
    work: PathBuf,
    branch: String,
    http_url: String,
    ssh_url: String,
    // Keep the repo root and key directory alive.
    _root: TempDir,
    _keys: TempDir,
}

impl Harness {
    /// Copies `source` and starts both servers on the current runtime.
    async fn start(source: &Path) -> Self {
        let root = temp_dir();
        let scratch = temp_dir();
        let keys = temp_dir();
        let git = GitRunner {
            home: temp_dir(),
            key_dir: keys.path().to_path_buf(),
        };

        let served_repo = root.path().join("team.git");
        git.git(
            root.path(),
            &[
                "clone",
                "--quiet",
                "--bare",
                utf8(source),
                utf8(&served_repo),
            ],
            &[],
        );
        let branch = git
            .git(&served_repo, &["symbolic-ref", "--short", "HEAD"], &[])
            .stdout;
        let work = scratch.path().join("work");
        git.git(
            scratch.path(),
            &["clone", "--quiet", utf8(&served_repo), utf8(&work)],
            &[],
        );

        let mut store = MemoryPolicyStore::new();
        for (id, name, token) in [(1, "alice", ALICE_TOKEN), (2, "bob", BOB_TOKEN)] {
            store.insert_member(
                AuthenticatedMember {
                    id,
                    name: name.to_owned(),
                    is_admin: false,
                },
                token.as_bytes(),
            );
        }
        store.insert_group_membership(1, "core");
        store.insert_group_membership(1, "internal");
        for pattern in comma_separated_env(WITHHOLD_ENV, DEFAULT_WITHHOLD) {
            match WithholdRule::new(pattern.clone(), ["internal".to_owned()]) {
                Ok(rule) => store.insert_path_rule("team.git", rule),
                Err(error) => panic!("invalid {WITHHOLD_ENV} glob {pattern:?}: {error}"),
            }
        }
        for pattern in comma_separated_env(HIDE_REFS_ENV, DEFAULT_HIDE_REFS) {
            match BranchRule::new(pattern.clone(), ["core".to_owned()]) {
                Ok(rule) => store.insert_branch_rule("team.git", rule),
                Err(error) => panic!("invalid {HIDE_REFS_ENV} glob {pattern:?}: {error}"),
            }
        }
        for (name, key) in [("alice", ALICE_KEY), ("bob", BOB_KEY)] {
            let public_key = generate_ssh_key(keys.path(), key);
            if let Err(error) = store
                .add_member_ssh_key(None, name, &public_key, "bench")
                .await
            {
                panic!("registering {name}'s SSH key failed: {error}");
            }
        }

        let repo_root = match root.path().canonicalize() {
            Ok(repo_root) => repo_root,
            Err(error) => panic!("failed to resolve the repo root: {error}"),
        };
        let policy_store: Arc<dyn PolicyStore> = Arc::new(store);
        let hook_dir = SharedHookDir::default();

        let http_listener = bind_loopback().await;
        let http_port = port_of(&http_listener);
        let router = router_with_hook_dir(
            repo_root.clone(),
            Arc::clone(&policy_store),
            hook_dir.clone(),
        );
        tokio::spawn(async move {
            if let Err(error) = axum_serve(http_listener, router).await {
                panic!("HTTP server failed: {error}");
            }
        });

        let ssh_listener = bind_loopback().await;
        let ssh_port = port_of(&ssh_listener);
        let host_key = match load_or_create_ssh_host_key(&keys.path().join("host_key")) {
            Ok(host_key) => host_key,
            Err(error) => panic!("creating the SSH host key failed: {error}"),
        };
        let config = SshServerConfig {
            repo_root,
            policy_store,
            host_key,
            hook_dir,
        };
        tokio::spawn(async move {
            if let Err(error) = serve_ssh(ssh_listener, config, std::future::pending()).await {
                panic!("SSH server failed: {error}");
            }
        });

        Self {
            git,
            scratch,
            served_repo,
            work,
            branch,
            http_url: format!("http://127.0.0.1:{http_port}/team.git"),
            ssh_url: format!("ssh://git@127.0.0.1:{ssh_port}/team.git"),
            _root: root,
            _keys: keys,
        }
    }

    /// The remote URL for `access`.
    fn url(&self, access: &Access) -> String {
        match access {
            Access::File => format!("file://{}", utf8(&self.served_repo)),
            Access::Http { .. } => self.http_url.clone(),
            Access::Ssh { .. } => self.ssh_url.clone(),
        }
    }

    /// Runs `git <args>` for `scenario` in `dir`: protocol v2, its credentials
    /// and, in a partial clone, no lazy fetching.
    fn scenario_git(&self, scenario: &Scenario, dir: &Path, args: &[&str]) -> GitOutput {
        let mut full_args: Vec<String> = vec!["-c".to_owned(), "protocol.version=2".to_owned()];
        if let Access::Http { token } = &scenario.access {
            full_args.push("-c".to_owned());
            full_args.push(format!("http.extraHeader=Authorization: Bearer {token}"));
        }
        full_args.extend(args.iter().map(|arg| (*arg).to_owned()));
        let ssh_command = match &scenario.access {
            Access::Ssh { key } => Some(self.git.ssh_command(key)),
            _ => None,
        };
        let mut env: Vec<(&str, &str)> = Vec::new();
        if let Some(ssh_command) = &ssh_command {
            env.push(("GIT_SSH_COMMAND", ssh_command));
            env.push(("GIT_SSH_VARIANT", "ssh"));
        }
        if scenario.partial {
            env.push(("GIT_NO_LAZY_FETCH", "1"));
        }
        let borrowed_args: Vec<&str> = full_args.iter().map(String::as_str).collect();
        self.git.git(dir, &borrowed_args, &env)
    }

    /// Pushes [`NEW_COMMIT_COUNT`] commits, each touching a public and a
    /// withheld file, straight into the served repository.
    fn push_new_commits(&self) {
        for index in 0..NEW_COMMIT_COUNT {
            for file in [PUBLIC_FILE, WITHHELD_FILE] {
                let path = self.work.join(file);
                let mut contents = match std::fs::read_to_string(&path) {
                    Ok(contents) => contents,
                    Err(error) => panic!("failed to read {file}: {error}"),
                };
                contents.push_str(&format!("\nbench edit {index} of {file}\n"));
                if let Err(error) = std::fs::write(&path, contents) {
                    panic!("failed to write {file}: {error}");
                }
            }
            self.git.git(
                &self.work,
                &["commit", "--quiet", "--all", "-m", "bench commit"],
                &[],
            );
        }
        let refspec = format!("HEAD:refs/heads/{}", self.branch);
        self.git.git(
            &self.work,
            &["push", "--quiet", utf8(&self.served_repo), &refspec],
            &[],
        );
    }

    /// Clones `runs` times, pushes new commits, then fetches in each clone,
    /// timing both.
    fn measure(&self, scenario: &Scenario, runs: usize) -> Measurement {
        eprintln!("== {} ({runs} run(s))", scenario.name);
        let directory = self
            .scratch
            .path()
            .join(scenario.name.replace([' ', ','], "_"));
        if let Err(error) = std::fs::create_dir_all(&directory) {
            panic!("failed to create {}: {error}", directory.display());
        }
        let url = self.url(&scenario.access);
        let mut clone_times = Vec::new();
        let mut clones = Vec::new();
        for run in 0..runs {
            let target = directory.join(format!("clone-{run}"));
            let mut args = vec!["clone", "--quiet", "--no-checkout"];
            if scenario.partial {
                args.push(PARTIAL_CLONE_FILTER);
            }
            args.push(&url);
            args.push(utf8(&target));
            let output = self.scenario_git(scenario, &directory, &args);
            eprintln!("   clone {run}: {:.2} s", output.elapsed.as_secs_f64());
            clone_times.push(output.elapsed);
            clones.push(target);
        }

        let first = match clones.first() {
            Some(first) => first.as_path(),
            None => panic!("at least one run is required"),
        };
        let (pack_kib, objects_in_pack) = self.pack_stats(scenario, first);
        let missing_objects = scenario.partial.then(|| {
            // Count objects the partial clone is missing, without letting git
            // lazily fetch them (which would also spawn a plain `ssh`).
            let listing = self
                .scenario_git(
                    scenario,
                    first,
                    &["rev-list", "--objects", "--missing=print", "--all"],
                )
                .stdout;
            listing.lines().filter(|line| line.starts_with('?')).count() as u64
        });
        let refs_received = self
            .scenario_git(scenario, first, &["for-each-ref"])
            .stdout
            .lines()
            .count();

        self.push_new_commits();
        let expected_tip = self
            .git
            .git(&self.served_repo, &["rev-parse", &self.branch], &[])
            .stdout;
        let mut fetch_times = Vec::new();
        for (run, clone) in clones.iter().enumerate() {
            let output = self.scenario_git(scenario, clone, &["fetch", "--quiet", "origin"]);
            eprintln!("   fetch {run}: {:.2} s", output.elapsed.as_secs_f64());
            fetch_times.push(output.elapsed);
            let remote_branch = format!("refs/remotes/origin/{}", self.branch);
            let fetched_tip = self
                .scenario_git(scenario, clone, &["rev-parse", &remote_branch])
                .stdout;
            assert_eq!(
                fetched_tip, expected_tip,
                "{}: fetch did not bring in the new commits",
                scenario.name
            );
        }
        if let Err(error) = std::fs::remove_dir_all(&directory) {
            eprintln!("failed to remove {}: {error}", directory.display());
        }
        Measurement {
            clone_times,
            fetch_times,
            pack_kib,
            objects_in_pack,
            missing_objects,
            refs_received,
        }
    }

    /// `size-pack` (KiB) and `in-pack` from `git count-objects -v` in `clone`.
    fn pack_stats(&self, scenario: &Scenario, clone: &Path) -> (u64, u64) {
        let output = self.scenario_git(scenario, clone, &["count-objects", "-v"]);
        let field = |name: &str| -> u64 {
            let value = output
                .stdout
                .lines()
                .find_map(|line| line.strip_prefix(name));
            match value {
                Some(value) => match value.trim().parse::<u64>() {
                    Ok(number) => number,
                    Err(error) => panic!("git count-objects printed {name} {value:?}: {error}"),
                },
                None => panic!("git count-objects did not print {name}"),
            }
        };
        (field("size-pack:"), field("in-pack:"))
    }
}

/// Binds an ephemeral loopback port.
async fn bind_loopback() -> tokio::net::TcpListener {
    match tokio::net::TcpListener::bind("127.0.0.1:0").await {
        Ok(listener) => listener,
        Err(error) => panic!("failed to bind a loopback listener: {error}"),
    }
}

fn port_of(listener: &tokio::net::TcpListener) -> u16 {
    match listener.local_addr() {
        Ok(address) => address.port(),
        Err(error) => panic!("failed to read a listener address: {error}"),
    }
}

/// Serves `router` on `listener` until the runtime ends.
async fn axum_serve(
    listener: tokio::net::TcpListener,
    router: axum::Router,
) -> std::io::Result<()> {
    axum::serve(listener, router).await
}

/// The one-line `uptime` load averages, to record how busy the machine was.
fn load_snapshot() -> String {
    match Command::new("uptime").output() {
        Ok(output) => String::from_utf8_lossy(&output.stdout).trim().to_owned(),
        Err(error) => format!("uptime unavailable: {error}"),
    }
}

/// Whether the `pack-objects` hook binary can be found, so a missing build
/// fails here with instructions instead of as a failed clone.
fn check_hook_binary() {
    if std::env::var_os("SCRIM_HOOK_BIN").is_some() {
        return;
    }
    let sibling = std::env::current_exe().ok().and_then(|exe| {
        exe.parent()
            .and_then(Path::parent)
            .map(|profile_dir| profile_dir.join("scrim-server"))
    });
    match sibling {
        Some(binary) if binary.is_file() => {}
        _ => panic!(
            "scrim-server binary not found next to the example; run `cargo build --release -p scrim-server --bin scrim-server` or set SCRIM_HOOK_BIN"
        ),
    }
}

fn main() {
    let Some(source) = std::env::var_os(REPO_ENV).map(PathBuf::from) else {
        eprintln!(
            "e2e_timings is opt-in: set {REPO_ENV} to a local bare repository (see the file header)."
        );
        return;
    };
    if !source.is_dir() {
        panic!("{REPO_ENV} is not a directory: {}", source.display());
    }
    if cfg!(debug_assertions) {
        eprintln!("warning: debug build; run with --release for meaningful numbers");
    }
    check_hook_binary();
    let runs = match std::env::var(RUNS_ENV) {
        Ok(value) => match value.parse::<usize>() {
            Ok(runs) if runs > 0 => runs,
            _ => panic!("{RUNS_ENV} must be a positive number, got {value:?}"),
        },
        Err(_) => DEFAULT_RUNS,
    };

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => panic!("failed to start the async runtime: {error}"),
    };
    // The servers keep running on the runtime's worker threads while the
    // timing code below blocks this thread on git.
    let harness = runtime.block_on(Harness::start(&source));

    let load_before = load_snapshot();
    let scenarios = [
        Scenario {
            name: "baseline git clone (file://)",
            access: Access::File,
            partial: false,
        },
        Scenario {
            name: "HTTP alice, full",
            access: Access::Http { token: ALICE_TOKEN },
            partial: false,
        },
        Scenario {
            name: "HTTP bob, partial + rules",
            access: Access::Http { token: BOB_TOKEN },
            partial: true,
        },
        Scenario {
            name: "SSH alice, full",
            access: Access::Ssh { key: ALICE_KEY },
            partial: false,
        },
        Scenario {
            name: "SSH bob, partial + rules",
            access: Access::Ssh { key: BOB_KEY },
            partial: true,
        },
    ];
    let measurements: Vec<(Scenario, Measurement)> = scenarios
        .iter()
        .map(|scenario| (scenario.clone(), harness.measure(scenario, runs)))
        .collect();
    let load_after = load_snapshot();

    let mut report = String::new();
    let commit_count = harness
        .git
        .git(&harness.served_repo, &["rev-list", "--count", "--all"], &[])
        .stdout;
    let git_version = harness.git.git(&harness.work, &["--version"], &[]).stdout;
    let _ = writeln!(
        report,
        "\n{git_version}; {runs} run(s) per scenario; {commit_count} commits; {NEW_COMMIT_COUNT} new commits before each fetch."
    );
    let _ = writeln!(report, "Load before: {load_before}");
    let _ = writeln!(report, "Load after:  {load_after}\n");
    let _ = writeln!(
        report,
        "| Scenario | Clone median (min-max) | Fetch median (min-max) | Clone pack | Objects in pack | Objects missing | Refs received |"
    );
    let _ = writeln!(report, "|---|---|---|---|---|---|---|");
    for (scenario, measurement) in &measurements {
        let missing = match measurement.missing_objects {
            Some(count) => count.to_string(),
            None => "-".to_owned(),
        };
        let _ = writeln!(
            report,
            "| {} | {} | {} | {:.1} MiB | {} | {} | {} |",
            scenario.name,
            format_times(&measurement.clone_times),
            format_times(&measurement.fetch_times),
            measurement.pack_kib as f64 / 1024.0,
            measurement.objects_in_pack,
            missing,
            measurement.refs_received,
        );
    }
    if let Some((_, baseline)) = measurements.first() {
        let baseline_clone = median(&baseline.clone_times).as_secs_f64();
        let baseline_fetch = median(&baseline.fetch_times).as_secs_f64();
        let _ = writeln!(report, "\nMedian time relative to the baseline (1.0x):\n");
        let _ = writeln!(report, "| Scenario | Clone | Fetch |");
        let _ = writeln!(report, "|---|---|---|");
        for (scenario, measurement) in measurements.iter().skip(1) {
            let _ = writeln!(
                report,
                "| {} | {:.2}x | {:.2}x |",
                scenario.name,
                median(&measurement.clone_times).as_secs_f64() / baseline_clone,
                median(&measurement.fetch_times).as_secs_f64() / baseline_fetch,
            );
        }
    }
    println!("{report}");
}
