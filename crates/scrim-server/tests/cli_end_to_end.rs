//! End-to-end tests driving `scrim-cli` against a live `scrim-server` and real
//! `git` clients.

#![allow(clippy::question_mark)]

mod common;

use std::{
    collections::BTreeMap,
    io::{BufReader, Cursor},
    path::{Path, PathBuf},
    sync::Arc,
};

use common::{GitSandbox, TEST_TOKEN, spawn_server, spawn_server_with_store, test_auth};
use scrim_cli::{CliEnv, client::ScrimClient, run_from};
use scrim_server::{MemoryPolicyStore, PolicyStore, SecretString};
use secrecy::ExposeSecret;
use tempfile::TempDir;

/// Captures the stdout, stderr, and exit outcome of a single CLI invocation.
struct CliOutput {
    stdout: String,
    stderr: String,
}

/// Runs `scrim_cli::run_from` inside an isolated [`CliEnv`] with the given
/// working directory, `SCRIM_CONFIG` path, and optional stdin bytes.
fn run_cli(
    cwd: &Path,
    config_path: &Path,
    stdin_bytes: &[u8],
    args: &[&str],
) -> Result<CliOutput, (anyhow::Error, CliOutput)> {
    let mut env_vars = BTreeMap::new();
    env_vars.insert(
        "SCRIM_CONFIG".to_owned(),
        config_path.to_string_lossy().into_owned(),
    );

    let mut stdin = BufReader::new(Cursor::new(stdin_bytes));
    let mut stdout_buf = Vec::new();
    let mut stderr_buf = Vec::new();
    let mut env = CliEnv {
        cwd: cwd.to_path_buf(),
        env_vars,
        stdin: &mut stdin,
        stdout: &mut stdout_buf,
        stderr: &mut stderr_buf,
    };

    let result = run_from(args.iter().copied(), &mut env);
    let output = CliOutput {
        stdout: String::from_utf8_lossy(&stdout_buf).into_owned(),
        stderr: String::from_utf8_lossy(&stderr_buf).into_owned(),
    };
    match result {
        Ok(()) => Ok(output),
        Err(err) => Err((err, output)),
    }
}

/// Runs `scrim_cli::run_from` and panics with diagnostics if it fails.
fn cli_ok(cwd: &Path, config_path: &Path, stdin_bytes: &[u8], args: &[&str]) -> CliOutput {
    match run_cli(cwd, config_path, stdin_bytes, args) {
        Ok(output) => output,
        Err((err, output)) => panic!(
            "CLI command {args:?} failed: {err:#}\nstdout:\n{}\nstderr:\n{}",
            output.stdout, output.stderr
        ),
    }
}

/// Runs `scrim_cli::run_from` and asserts it fails, returning the formatted
/// error message.
fn cli_err(cwd: &Path, config_path: &Path, stdin_bytes: &[u8], args: &[&str]) -> String {
    match run_cli(cwd, config_path, stdin_bytes, args) {
        Ok(output) => panic!(
            "CLI command {args:?} unexpectedly succeeded.\nstdout:\n{}\nstderr:\n{}",
            output.stdout, output.stderr
        ),
        Err((err, _output)) => format!("{err:#}"),
    }
}

/// Extracts the newly issued plaintext token from `scrim access grant` or
/// `scrim access token` stdout.
fn extract_issued_token(stdout: &str) -> String {
    for line in stdout.lines() {
        if let Some((_, token)) = line.split_once("(shown only once): ") {
            let trimmed = token.trim();
            assert!(!trimmed.is_empty(), "empty token in CLI output:\n{stdout}");
            return trimmed.to_owned();
        }
    }
    panic!("no issued token found in CLI output:\n{stdout}");
}

/// Runs `git` with `-c credential.helper=...` and `-c protocol.version=...`.
fn try_git_as(
    sandbox: &GitSandbox,
    dir: &Path,
    member_name: &str,
    token: &str,
    protocol: &str,
    args: &[&str],
) -> std::process::Output {
    let helper = sandbox.credential_helper_config(member_name, token);
    let proto = format!("protocol.version={protocol}");
    let mut full_args = Vec::with_capacity(4 + args.len());
    full_args.push("-c");
    full_args.push(&helper);
    full_args.push("-c");
    full_args.push(&proto);
    full_args.extend_from_slice(args);
    sandbox.try_git(dir, &full_args)
}

/// Like [`try_git_as`], panicking with stderr if `git` fails.
fn git_as(
    sandbox: &GitSandbox,
    dir: &Path,
    member_name: &str,
    token: &str,
    protocol: &str,
    args: &[&str],
) -> std::process::Output {
    let output = try_git_as(sandbox, dir, member_name, token, protocol, args);
    assert!(
        output.status.success(),
        "git {args:?} as {member_name} (protocol v{protocol}) failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

/// Runs `git ls-remote <url>` as `member_name` under `protocol` and returns stdout.
fn ls_remote_as(
    sandbox: &GitSandbox,
    dir: &Path,
    member_name: &str,
    token: &str,
    protocol: &str,
    url: &str,
) -> String {
    let output = git_as(
        sandbox,
        dir,
        member_name,
        token,
        protocol,
        &["ls-remote", url],
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// Writes `contents` to `dir/filename`, stages, and commits it.
fn commit_file(sandbox: &GitSandbox, dir: &Path, filename: &str, contents: &str, message: &str) {
    if let Err(err) = std::fs::write(dir.join(filename), contents) {
        panic!("failed to write {}: {err}", dir.join(filename).display());
    }
    sandbox.git(dir, &["add", filename]);
    sandbox.git(dir, &["commit", "--quiet", "-m", message]);
}

/// Creates a `TempDir`, panicking on failure.
fn temp_dir(label: &str) -> TempDir {
    match TempDir::new() {
        Ok(dir) => dir,
        Err(err) => panic!("failed to create temp dir ({label}): {err}"),
    }
}

/// Creates a directory tree, panicking on failure.
fn create_dir(path: &Path) {
    if let Err(err) = std::fs::create_dir_all(path) {
        panic!("failed to create directory {}: {err}", path.display());
    }
}

/// Reads a single local git config value using `GitSandbox`.
fn local_git_config(sandbox: &GitSandbox, dir: &Path, key: &str) -> String {
    let out = sandbox.git(dir, &["config", "--local", "--get", key]);
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

/// Awaits a `JoinHandle` from `tokio::task::spawn_blocking`.
async fn join_blocking<T>(handle: tokio::task::JoinHandle<T>) -> T {
    match handle.await {
        Ok(value) => value,
        Err(err) => panic!("blocking task panicked: {err}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_manages_private_branches_enforced_by_git() {
    let repo_root = temp_dir("repo-root");
    let store = MemoryPolicyStore::new();
    let bootstrap = match store.bootstrap_admin("root", "bootstrap").await {
        Ok(created) => created,
        Err(err) => panic!("bootstrap_admin failed: {err}"),
    };
    let root_token = bootstrap.token.expose_secret().to_owned();
    let base_url =
        spawn_server_with_store(repo_root.path().to_path_buf(), Arc::new(store.clone())).await;

    let work_dir = temp_dir("work");
    let configs_dir = temp_dir("configs");
    let root_config = configs_dir.path().join("root").join("config.toml");
    let alice_config = configs_dir.path().join("alice").join("config.toml");
    let work_root = work_dir.path().to_path_buf();
    let repo_url = format!("{base_url}/my-app.git");

    let (alice_token, alice_token_2, carol_token) = join_blocking(tokio::task::spawn_blocking({
        let root_token = root_token.clone();
        let base_url = base_url.clone();
        let root_config = root_config.clone();
        let alice_config = alice_config.clone();
        move || {
            let sandbox = GitSandbox::new();
            let scratch = work_root.join("scratch");
            create_dir(&scratch);

            // 1. Login as root with --token-stdin and verify config permissions & whoami.
            let login_stdin = format!("{root_token}\n");
            let login_out = cli_ok(
                &scratch,
                &root_config,
                login_stdin.as_bytes(),
                &["scrim", "login", "--server", &base_url, "--token-stdin"],
            );
            assert!(
                login_out.stdout.contains("Logged in as root (admin)"),
                "{}",
                login_out.stdout
            );
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let metadata = match std::fs::metadata(&root_config) {
                    Ok(meta) => meta,
                    Err(err) => panic!("failed to stat config.toml: {err}"),
                };
                assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
            }

            let whoami_out = cli_ok(&scratch, &root_config, b"", &["scrim", "whoami"]);
            assert!(
                whoami_out.stdout.contains("Member: root (admin)"),
                "{}",
                whoami_out.stdout
            );

            // 2. Initialize local repo `my-app` and connect it via `scrim init`.
            let my_app = work_root.join("my-app");
            create_dir(&my_app);
            sandbox.git(&my_app, &["init", "--quiet", "--initial-branch=main"]);
            let init_out = cli_ok(&my_app, &root_config, b"", &["scrim", "init"]);
            assert!(
                init_out.stdout.contains("Repository: my-app.git"),
                "{}",
                init_out.stdout
            );
            assert_eq!(local_git_config(&sandbox, &my_app, "scrim.repo"), "my-app.git");
            assert_eq!(
                local_git_config(&sandbox, &my_app, "scrim.server"),
                base_url
            );
            let origin_out = sandbox.git(&my_app, &["remote", "get-url", "origin"]);
            assert_eq!(String::from_utf8_lossy(&origin_out.stdout).trim(), repo_url);

            // 3. Push initial `main` and `private/wip` branches as root.
            commit_file(&sandbox, &my_app, "README.md", "public\n", "initial public");
            git_as(
                &sandbox,
                &my_app,
                "root",
                &root_token,
                "2",
                &["push", "--quiet", "origin", "HEAD:refs/heads/main"],
            );

            sandbox.git(&my_app, &["checkout", "--quiet", "-b", "private/wip"]);
            commit_file(&sandbox, &my_app, "secret.txt", "top secret\n", "secret wip");
            let initial_private_commit = String::from_utf8_lossy(
                &sandbox.git(&my_app, &["rev-parse", "HEAD"]).stdout,
            )
            .trim()
            .to_owned();
            git_as(
                &sandbox,
                &my_app,
                "root",
                &root_token,
                "2",
                &["push", "--quiet", "origin", "HEAD:refs/heads/private/wip"],
            );

            // 4. Create groups, grant alice & carol, and add branch rule (no --repo flag).
            cli_ok(&scratch, &root_config, b"", &["scrim", "group", "create", "core"]);
            cli_ok(
                &scratch,
                &root_config,
                b"",
                &["scrim", "group", "create", "contractors"],
            );

            let alice_grant = cli_ok(
                &scratch,
                &root_config,
                b"",
                &["scrim", "access", "grant", "alice", "--group", "core"],
            );
            let alice_token = extract_issued_token(&alice_grant.stdout);

            let carol_grant = cli_ok(
                &scratch,
                &root_config,
                b"",
                &["scrim", "access", "grant", "carol", "--group", "contractors"],
            );
            let carol_token = extract_issued_token(&carol_grant.stdout);

            let rule_out = cli_ok(
                &my_app,
                &root_config,
                b"",
                &["scrim", "branch", "private", "refs/heads/private/*", "--group", "core"],
            );
            assert!(
                rule_out.stdout.contains("refs/heads/private/*")
                    && rule_out.stdout.contains("my-app.git"),
                "{}",
                rule_out.stdout
            );
            let list_out = cli_ok(&my_app, &root_config, b"", &["scrim", "branch", "list"]);
            assert!(
                list_out.stdout.contains("refs/heads/private/*: core"),
                "{}",
                list_out.stdout
            );

            // 5. Real git enforcement under both protocol v0 and v2.
            for protocol in ["0", "2"] {
                let alice_refs = ls_remote_as(
                    &sandbox,
                    &scratch,
                    "alice",
                    &alice_token,
                    protocol,
                    &repo_url,
                );
                assert!(
                    alice_refs.contains("\trefs/heads/private/wip\n"),
                    "alice should see private/wip under protocol v{protocol}:\n{alice_refs}"
                );
            }

            // Alice fetches and pushes a new commit to private/wip.
            let alice_clone = work_root.join("alice-clone");
            git_as(
                &sandbox,
                &work_root,
                "alice",
                &alice_token,
                "2",
                &["clone", "--quiet", &repo_url, "alice-clone"],
            );
            git_as(
                &sandbox,
                &alice_clone,
                "alice",
                &alice_token,
                "0",
                &["fetch", "--quiet", "origin", "refs/heads/private/wip"],
            );
            sandbox.git(
                &alice_clone,
                &["checkout", "--quiet", "-b", "wip", "origin/private/wip"],
            );
            commit_file(&sandbox, &alice_clone, "alice.txt", "alice wip\n", "alice wip");
            let latest_private_commit = String::from_utf8_lossy(
                &sandbox.git(&alice_clone, &["rev-parse", "HEAD"]).stdout,
            )
            .trim()
            .to_owned();
            git_as(
                &sandbox,
                &alice_clone,
                "alice",
                &alice_token,
                "2",
                &["push", "--quiet", "origin", "HEAD:refs/heads/private/wip"],
            );

            // Carol cannot list, fetch by hash, or push to private branches under v0 or v2.
            let carol_clone = work_root.join("carol-clone");
            git_as(
                &sandbox,
                &work_root,
                "carol",
                &carol_token,
                "2",
                &["clone", "--quiet", &repo_url, "carol-clone"],
            );
            commit_file(&sandbox, &carol_clone, "carol.txt", "carol\n", "carol commit");
            for protocol in ["0", "2"] {
                let carol_refs = ls_remote_as(
                    &sandbox,
                    &scratch,
                    "carol",
                    &carol_token,
                    protocol,
                    &repo_url,
                );
                assert!(
                    carol_refs.contains("\trefs/heads/main\n"),
                    "carol should see main (v{protocol}):\n{carol_refs}"
                );
                assert!(
                    !carol_refs.contains("refs/heads/private/wip"),
                    "carol must not see private/wip (v{protocol}):\n{carol_refs}"
                );
                assert!(
                    !carol_refs.contains(&initial_private_commit)
                        && !carol_refs.contains(&latest_private_commit),
                    "carol must not see private commit hash (v{protocol}):\n{carol_refs}"
                );

                let fetch_by_id = try_git_as(
                    &sandbox,
                    &carol_clone,
                    "carol",
                    &carol_token,
                    protocol,
                    &["fetch", "origin", &latest_private_commit],
                );
                assert!(
                    !fetch_by_id.status.success(),
                    "carol fetched hidden commit by ID under protocol v{protocol}"
                );

                let push_hidden = try_git_as(
                    &sandbox,
                    &carol_clone,
                    "carol",
                    &carol_token,
                    protocol,
                    &["push", "origin", "HEAD:refs/heads/private/new"],
                );
                assert!(
                    !push_hidden.status.success(),
                    "carol pushed to private/new under protocol v{protocol}"
                );
            }

            // Merge-leak guard: Alice merges origin/private/wip into main and pushes -> rejected.
            sandbox.git(&alice_clone, &["checkout", "--quiet", "main"]);
            sandbox.git(
                &alice_clone,
                &["merge", "--quiet", "--no-ff", "--no-edit", "origin/private/wip"],
            );
            let merge_push = try_git_as(
                &sandbox,
                &alice_clone,
                "alice",
                &alice_token,
                "2",
                &["push", "origin", "HEAD:refs/heads/main"],
            );
            let merge_stderr = String::from_utf8_lossy(&merge_push.stderr);
            assert!(
                !merge_push.status.success()
                    && merge_stderr.contains("introduces commits reachable only from more-restricted branches"),
                "merge leak was not rejected by pre-receive guard:\n{merge_stderr}"
            );

            // 6. Group membership changes take effect immediately for Carol.
            cli_ok(
                &scratch,
                &root_config,
                b"",
                &["scrim", "group", "add", "core", "carol"],
            );
            for protocol in ["0", "2"] {
                let refs = ls_remote_as(
                    &sandbox,
                    &scratch,
                    "carol",
                    &carol_token,
                    protocol,
                    &repo_url,
                );
                assert!(
                    refs.contains("\trefs/heads/private/wip\n"),
                    "carol should immediately see private/wip after group add (v{protocol}):\n{refs}"
                );
            }

            cli_ok(
                &scratch,
                &root_config,
                b"",
                &["scrim", "group", "remove", "core", "carol"],
            );
            for protocol in ["0", "2"] {
                let refs = ls_remote_as(
                    &sandbox,
                    &scratch,
                    "carol",
                    &carol_token,
                    protocol,
                    &repo_url,
                );
                assert!(
                    !refs.contains("refs/heads/private/wip"),
                    "carol should immediately lose access after group remove (v{protocol}):\n{refs}"
                );
            }

            // 7. Issue second token for Alice, verify non-admin whoami & 403, then revoke.
            let second_token_out = cli_ok(
                &scratch,
                &root_config,
                b"",
                &["scrim", "access", "token", "alice", "--label", "laptop"],
            );
            let alice_token_2 = extract_issued_token(&second_token_out.stdout);

            let alice_login_stdin = format!("{alice_token_2}\n");
            cli_ok(
                &scratch,
                &alice_config,
                alice_login_stdin.as_bytes(),
                &["scrim", "login", "--server", &base_url, "--token-stdin"],
            );
            let alice_whoami = cli_ok(&scratch, &alice_config, b"", &["scrim", "whoami"]);
            assert!(
                alice_whoami.stdout.contains("Member: alice (member)"),
                "{}",
                alice_whoami.stdout
            );
            assert!(
                alice_whoami.stdout.contains("Groups: core"),
                "{}",
                alice_whoami.stdout
            );

            let forbidden_err = cli_err(
                &scratch,
                &alice_config,
                b"",
                &["scrim", "group", "create", "forbidden"],
            );
            assert!(
                forbidden_err.contains("403 Forbidden"),
                "expected 403 for non-admin alice, got: {forbidden_err}"
            );

            // Revoke alice: both tokens fail `scrim whoami` and `git ls-remote`.
            cli_ok(
                &scratch,
                &root_config,
                b"",
                &["scrim", "access", "revoke", "alice"],
            );
            for revoked_tok in [&alice_token, &alice_token_2] {
                let whoami_err = cli_err(
                    &scratch,
                    &alice_config,
                    b"",
                    &["scrim", "--token", revoked_tok, "whoami"],
                );
                assert!(
                    whoami_err.contains("401 Unauthorized"),
                    "revoked token still accepted by whoami: {whoami_err}"
                );

                let git_res =
                    try_git_as(&sandbox, &scratch, "alice", revoked_tok, "2", &["ls-remote", &repo_url]);
                assert!(
                    !git_res.status.success(),
                    "revoked token still accepted by git ls-remote"
                );
            }

            // 8. Remove branch rule (auto-detecting repo in my-app) -> Carol sees private/wip again.
            cli_ok(
                &my_app,
                &root_config,
                b"",
                &["scrim", "branch", "rm", "refs/heads/private/*"],
            );
            for protocol in ["0", "2"] {
                let refs = ls_remote_as(
                    &sandbox,
                    &scratch,
                    "carol",
                    &carol_token,
                    protocol,
                    &repo_url,
                );
                assert!(
                    refs.contains("\trefs/heads/private/wip\n"),
                    "carol should see private/wip after branch rule removal (v{protocol}):\n{refs}"
                );
            }

            (alice_token, alice_token_2, carol_token)
        }
    }))
    .await;

    // 9. Verify audit log recorded every admin action and zero plaintext tokens.
    let entries = store.audit_entries();
    let actions: Vec<&str> = entries.iter().map(|entry| entry.action.as_str()).collect();
    for expected_action in [
        "member.bootstrap_admin",
        "repository.register",
        "group.create",
        "member.grant",
        "branch_rule.set",
        "group.member_add",
        "group.member_remove",
        "member.token_issue",
        "member.revoke",
        "branch_rule.remove",
    ] {
        assert!(
            actions.contains(&expected_action),
            "missing audit action {expected_action:?} in {actions:?}"
        );
    }

    let rendered = format!("{entries:?}");
    for secret in [&root_token, &alice_token, &alice_token_2, &carol_token] {
        assert!(
            !rendered.contains(secret.as_str()),
            "plaintext token leaked into audit log"
        );
    }
    assert!(
        !rendered.contains("scrim_"),
        "token prefix leaked into audit log"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_surfaces_admin_errors_last_admin_protection_and_static_mode() {
    // Part A: MemoryPolicyStore server with a single bootstrapped admin `root`.
    let mem_root = temp_dir("mem-root");
    let store = MemoryPolicyStore::new();
    let bootstrap = match store.bootstrap_admin("root", "bootstrap").await {
        Ok(created) => created,
        Err(err) => panic!("bootstrap_admin failed: {err}"),
    };
    let root_token = bootstrap.token.expose_secret().to_owned();
    let mem_url = spawn_server_with_store(mem_root.path().to_path_buf(), Arc::new(store)).await;

    // Part B: StaticPolicyStore server.
    let static_root = temp_dir("static-root");
    let static_url = spawn_server(static_root.path().to_path_buf(), test_auth()).await;

    let scratch = temp_dir("cli-errors-scratch");
    let configs = temp_dir("cli-errors-configs");
    let mem_config = configs.path().join("mem-config.toml");
    let static_config = configs.path().join("static-config.toml");
    let scratch_path: PathBuf = scratch.path().to_path_buf();

    join_blocking(tokio::task::spawn_blocking(move || {
        // Login to MemoryPolicyStore server as `root`.
        cli_ok(
            &scratch_path,
            &mem_config,
            format!("{root_token}\n").as_bytes(),
            &["scrim", "login", "--server", &mem_url, "--token-stdin"],
        );

        // Last active admin protection.
        let revoke_root_err = cli_err(
            &scratch_path,
            &mem_config,
            b"",
            &["scrim", "access", "revoke", "root"],
        );
        assert!(
            revoke_root_err.contains("last active admin"),
            "unexpected error for revoking last admin: {revoke_root_err}"
        );

        // Unregistered repository / missing group error.
        let branch_err = cli_err(
            &scratch_path,
            &mem_config,
            b"",
            &[
                "scrim",
                "branch",
                "private",
                "refs/heads/private/*",
                "--group",
                "missing",
                "--repo",
                "my-app.git",
            ],
        );
        assert!(
            branch_err.contains("not registered")
                || branch_err.to_ascii_lowercase().contains("not found"),
            "unexpected error for missing repo/group: {branch_err}"
        );

        // `scrim access list` vs `scrim access list --all` after creating and revoking `bob`.
        cli_ok(
            &scratch_path,
            &mem_config,
            b"",
            &["scrim", "access", "grant", "bob"],
        );
        cli_ok(
            &scratch_path,
            &mem_config,
            b"",
            &["scrim", "access", "revoke", "bob"],
        );

        let active_list = cli_ok(
            &scratch_path,
            &mem_config,
            b"",
            &["scrim", "access", "list"],
        );
        assert!(
            active_list.stdout.contains("root: admin"),
            "{}",
            active_list.stdout
        );
        assert!(
            !active_list.stdout.contains("bob:"),
            "revoked member should not appear without --all:\n{}",
            active_list.stdout
        );

        let all_list = cli_ok(
            &scratch_path,
            &mem_config,
            b"",
            &["scrim", "access", "list", "--all"],
        );
        assert!(
            all_list.stdout.contains("bob: member, user, revoked"),
            "revoked member missing from --all:\n{}",
            all_list.stdout
        );
        assert!(
            all_list.stdout.contains("root: admin, user, active"),
            "{}",
            all_list.stdout
        );

        // StaticPolicyStore server: login + whoami succeed, admin endpoints return 501.
        let static_login = cli_ok(
            &scratch_path,
            &static_config,
            b"",
            &[
                "scrim",
                "login",
                "--server",
                &static_url,
                "--token",
                TEST_TOKEN,
            ],
        );
        assert!(
            static_login.stdout.contains("static-token"),
            "{}",
            static_login.stdout
        );

        let static_whoami = cli_ok(&scratch_path, &static_config, b"", &["scrim", "whoami"]);
        assert!(
            static_whoami
                .stdout
                .contains("Member: static-token (admin)"),
            "{}",
            static_whoami.stdout
        );

        let static_group_err = cli_err(
            &scratch_path,
            &static_config,
            b"",
            &["scrim", "group", "create", "core"],
        );
        assert!(
            static_group_err.contains("501 Not Implemented")
                && static_group_err.contains("not backed by a database"),
            "unexpected static-mode error: {static_group_err}"
        );
    }))
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repository_registration_preserves_existing_parent_casing() {
    let repo_root = temp_dir("casing-root");
    create_dir(&repo_root.path().join("Team"));
    let is_case_insensitive = repo_root.path().join("team").exists();

    let store = MemoryPolicyStore::new();
    let bootstrap = match store.bootstrap_admin("root", "bootstrap").await {
        Ok(created) => created,
        Err(err) => panic!("bootstrap_admin failed: {err}"),
    };
    let root_token = bootstrap.token.expose_secret().to_owned();
    let base_url = spawn_server_with_store(repo_root.path().to_path_buf(), Arc::new(store)).await;

    let scratch = temp_dir("casing-scratch");
    let config_dir = temp_dir("casing-config");
    let config_path = config_dir.path().join("config.toml");
    let scratch_path = scratch.path().to_path_buf();

    join_blocking(tokio::task::spawn_blocking(move || {
        cli_ok(
            &scratch_path,
            &config_path,
            format!("{root_token}\n").as_bytes(),
            &["scrim", "login", "--server", &base_url, "--token-stdin"],
        );

        let first = cli_ok(
            &scratch_path,
            &config_path,
            b"",
            &["scrim", "init", "Team/app.git", "--no-remote"],
        );
        assert!(
            first.stdout.contains("Repository: Team/app.git"),
            "{}",
            first.stdout
        );

        let client = match ScrimClient::new(&base_url, SecretString::from(root_token)) {
            Ok(client) => client,
            Err(err) => panic!("failed to create ScrimClient: {err}"),
        };
        let listed = match client.list_repositories() {
            Ok(resp) => resp,
            Err(err) => panic!("list_repositories failed: {err}"),
        };
        let paths: Vec<String> = listed
            .repositories
            .into_iter()
            .map(|repo| repo.path)
            .collect();
        assert!(paths.contains(&"Team/app.git".to_owned()), "{paths:?}");

        if is_case_insensitive {
            let second = cli_ok(
                &scratch_path,
                &config_path,
                b"",
                &["scrim", "init", "team/second.git", "--no-remote"],
            );
            assert!(
                second.stdout.contains("Repository: Team/second.git"),
                "expected canonical casing Team/second.git, got:\n{}",
                second.stdout
            );
            let listed = match client.list_repositories() {
                Ok(resp) => resp,
                Err(err) => panic!("list_repositories failed: {err}"),
            };
            let paths: Vec<String> = listed
                .repositories
                .into_iter()
                .map(|repo| repo.path)
                .collect();
            assert!(
                paths.contains(&"Team/second.git".to_owned()),
                "canonical key Team/second.git missing: {paths:?}"
            );
            assert!(
                !paths.contains(&"team/second.git".to_owned()),
                "non-canonical key team/second.git should not be registered: {paths:?}"
            );
        }
    }))
    .await;
}
