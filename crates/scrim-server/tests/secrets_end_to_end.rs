//! Milestone M2 end-to-end tests for encrypted repo-versioned secrets,
//! offline decryption, CI `SCRIM_KEY` usage, revocation key rotation, and
//! `pre-receive` plaintext secret / credential scanning.

#![allow(clippy::question_mark)]

mod common;

use std::{
    collections::BTreeMap,
    io::{BufReader, Cursor},
    path::{Path, PathBuf},
    sync::Arc,
};

use common::{GitSandbox, spawn_server_with_store};
use scrim_cli::{CliEnv, run_from};
use scrim_server::{MemoryPolicyStore, PolicyStore};
use secrecy::ExposeSecret;
use tempfile::TempDir;

/// Captures stdout and stderr from a CLI invocation.
struct CliOutput {
    stdout: String,
    stderr: String,
}

/// Runs `scrim_cli::run_from` with an explicit environment variable map.
fn run_cli_with_env(
    cwd: &Path,
    env_vars: BTreeMap<String, String>,
    stdin_bytes: &[u8],
    args: &[&str],
) -> Result<CliOutput, (anyhow::Error, CliOutput)> {
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

/// Runs `scrim_cli::run_from` with `SCRIM_CONFIG` set to `config_path`.
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
    run_cli_with_env(cwd, env_vars, stdin_bytes, args)
}

/// Runs `scrim_cli::run_from` with `SCRIM_CONFIG` and panics on error.
fn cli_ok(cwd: &Path, config_path: &Path, stdin_bytes: &[u8], args: &[&str]) -> CliOutput {
    match run_cli(cwd, config_path, stdin_bytes, args) {
        Ok(output) => output,
        Err((err, output)) => panic!(
            "CLI command {args:?} failed: {err:#}\nstdout:\n{}\nstderr:\n{}",
            output.stdout, output.stderr
        ),
    }
}

/// Runs `scrim_cli::run_from` with `SCRIM_CONFIG` and asserts failure.
fn cli_err(cwd: &Path, config_path: &Path, stdin_bytes: &[u8], args: &[&str]) -> String {
    match run_cli(cwd, config_path, stdin_bytes, args) {
        Ok(output) => panic!(
            "CLI command {args:?} unexpectedly succeeded.\nstdout:\n{}\nstderr:\n{}",
            output.stdout, output.stderr
        ),
        Err((err, _output)) => format!("{err:#}"),
    }
}

/// Runs `scrim_cli::run_from` with explicit `env_vars` and panics on error.
fn cli_ok_env(
    cwd: &Path,
    env_vars: BTreeMap<String, String>,
    stdin_bytes: &[u8],
    args: &[&str],
) -> CliOutput {
    match run_cli_with_env(cwd, env_vars, stdin_bytes, args) {
        Ok(output) => output,
        Err((err, output)) => panic!(
            "CLI command {args:?} failed: {err:#}\nstdout:\n{}\nstderr:\n{}",
            output.stdout, output.stderr
        ),
    }
}

/// Extracts the value after `prefix` on a matching line of CLI stdout.
fn extract_prefixed_line_value(stdout: &str, prefix: &str) -> String {
    for line in stdout.lines() {
        if let Some((_, value)) = line.split_once(prefix) {
            let trimmed = value.trim();
            assert!(
                !trimmed.is_empty(),
                "empty value for prefix {prefix:?} in CLI output:\n{stdout}"
            );
            return trimmed.to_owned();
        }
    }
    panic!("prefix {prefix:?} not found in CLI output:\n{stdout}");
}

/// Extracts the newly issued plaintext token from `scrim access grant` stdout.
fn extract_issued_token(stdout: &str) -> String {
    extract_prefixed_line_value(stdout, "Token (shown only once): ")
}

/// Extracts the newly generated `SCRIM_KEY` from `scrim access grant --machine` stdout.
fn extract_issued_scrim_key(stdout: &str) -> String {
    extract_prefixed_line_value(stdout, "SCRIM_KEY (shown only once): ")
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

/// Writes `contents` to `dir/filename`, stages, and commits it.
fn commit_file(sandbox: &GitSandbox, dir: &Path, filename: &str, contents: &str, message: &str) {
    let target = dir.join(filename);
    if let Err(err) = std::fs::write(&target, contents) {
        panic!("failed to write {}: {err}", target.display());
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

/// Reads a file to string, panicking on failure.
fn read_to_string(path: &Path) -> String {
    match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) => panic!("failed to read {}: {err}", path.display()),
    }
}

/// Awaits a `JoinHandle` from `tokio::task::spawn_blocking`.
async fn join_blocking<T>(handle: tokio::task::JoinHandle<T>) -> T {
    match handle.await {
        Ok(value) => value,
        Err(err) => panic!("blocking task panicked: {err}"),
    }
}

/// Verifies that `identity.age` next to `config_path` exists with `0o600` mode on Unix.
fn assert_identity_permissions(config_path: &Path) {
    let parent = match config_path.parent() {
        Some(dir) => dir,
        None => panic!("config path has no parent: {}", config_path.display()),
    };
    let identity_path = parent.join("identity.age");
    let metadata = match std::fs::metadata(&identity_path) {
        Ok(meta) => meta,
        Err(err) => panic!(
            "failed to stat identity file {}: {err}",
            identity_path.display()
        ),
    };
    assert!(metadata.is_file());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    }
}

/// Returns the parent directory of `config_path`, panicking if absent.
fn config_parent(config_path: &Path) -> PathBuf {
    match config_path.parent() {
        Some(dir) => dir.to_path_buf(),
        None => panic!("config path has no parent: {}", config_path.display()),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn team_secrets_workflow_ci_and_revocation_end_to_end() {
    let repo_root = temp_dir("secrets-repo-root");
    let store = MemoryPolicyStore::new();
    let bootstrap = match store.bootstrap_admin("root", "bootstrap").await {
        Ok(created) => created,
        Err(err) => panic!("bootstrap_admin failed: {err}"),
    };
    let root_token = bootstrap.token.expose_secret().to_owned();
    let base_url =
        spawn_server_with_store(repo_root.path().to_path_buf(), Arc::new(store.clone())).await;

    let work_dir = temp_dir("secrets-work");
    let configs_dir = temp_dir("secrets-configs");
    let root_config = configs_dir.path().join("root").join("config.toml");
    let alice_config = configs_dir.path().join("alice").join("config.toml");
    let bob_config = configs_dir.path().join("bob").join("config.toml");
    let carol_config = configs_dir.path().join("carol").join("config.toml");
    let work_root = work_dir.path().to_path_buf();
    let repo_url = format!("{base_url}/my-app.git");

    let (alice_token, bob_token, carol_token, ci_token, ci_scrim_key) =
        join_blocking(tokio::task::spawn_blocking({
            let root_token = root_token.clone();
            let base_url = base_url.clone();
            let root_config = root_config.clone();
            let alice_config = alice_config.clone();
            let bob_config = bob_config.clone();
            let carol_config = carol_config.clone();
            move || {
                let sandbox = GitSandbox::new();
                let scratch = work_root.join("scratch");
                create_dir(&scratch);

                // 1. Login as root, initialize `my-app`, and create groups/members.
                cli_ok(
                    &scratch,
                    &root_config,
                    format!("{root_token}\n").as_bytes(),
                    &["scrim", "login", "--server", &base_url, "--token-stdin"],
                );

                let my_app = work_root.join("my-app");
                create_dir(&my_app);
                sandbox.git(&my_app, &["init", "--quiet", "--initial-branch=main"]);
                cli_ok(&my_app, &root_config, b"", &["scrim", "init"]);

                cli_ok(
                    &scratch,
                    &root_config,
                    b"",
                    &["scrim", "group", "create", "core"],
                );
                cli_ok(
                    &scratch,
                    &root_config,
                    b"",
                    &["scrim", "group", "create", "contractors"],
                );
                cli_ok(
                    &scratch,
                    &root_config,
                    b"",
                    &["scrim", "group", "add", "core", "root"],
                );

                let alice_grant = cli_ok(
                    &scratch,
                    &root_config,
                    b"",
                    &["scrim", "access", "grant", "alice", "--group", "core"],
                );
                let alice_token = extract_issued_token(&alice_grant.stdout);

                let bob_grant = cli_ok(
                    &scratch,
                    &root_config,
                    b"",
                    &["scrim", "access", "grant", "bob", "--group", "core"],
                );
                let bob_token = extract_issued_token(&bob_grant.stdout);

                let carol_grant = cli_ok(
                    &scratch,
                    &root_config,
                    b"",
                    &[
                        "scrim",
                        "access",
                        "grant",
                        "carol",
                        "--group",
                        "contractors",
                    ],
                );
                let carol_token = extract_issued_token(&carol_grant.stdout);

                let ci_grant = cli_ok(
                    &scratch,
                    &root_config,
                    b"",
                    &[
                        "scrim",
                        "access",
                        "grant",
                        "ci-bot",
                        "--machine",
                        "--group",
                        "core",
                    ],
                );
                let ci_token = extract_issued_token(&ci_grant.stdout);
                let ci_scrim_key = extract_issued_scrim_key(&ci_grant.stdout);

                // 2. Login alice, bob, carol and generate age keys for all human members.
                for (cfg, tok) in [
                    (&alice_config, &alice_token),
                    (&bob_config, &bob_token),
                    (&carol_config, &carol_token),
                ] {
                    cli_ok(
                        &scratch,
                        cfg,
                        format!("{tok}\n").as_bytes(),
                        &["scrim", "login", "--server", &base_url, "--token-stdin"],
                    );
                }

                for cfg in [&root_config, &alice_config, &bob_config, &carol_config] {
                    let keygen_out = cli_ok(&scratch, cfg, b"", &["scrim", "keygen"]);
                    assert!(
                        keygen_out.stdout.contains("Public key: age1"),
                        "{}",
                        keygen_out.stdout
                    );
                    assert_identity_permissions(cfg);

                    let whoami_out = cli_ok(&scratch, cfg, b"", &["scrim", "whoami"]);
                    assert!(
                        whoami_out.stdout.contains("Public key: age1"),
                        "{}",
                        whoami_out.stdout
                    );
                }

                // 3. Configure secret scope `dev` for group `core` and verify non-member 403.
                let scope_set = cli_ok(
                    &my_app,
                    &root_config,
                    b"",
                    &["scrim", "secrets", "scope", "set", "dev", "--group", "core"],
                );
                assert!(
                    scope_set
                        .stdout
                        .contains("Configured secret scope 'dev' in my-app.git for groups: core"),
                    "{}",
                    scope_set.stdout
                );

                let scope_list = cli_ok(
                    &my_app,
                    &root_config,
                    b"",
                    &["scrim", "secrets", "scope", "list"],
                );
                assert!(
                    scope_list.stdout.contains("dev: core"),
                    "{}",
                    scope_list.stdout
                );

                // Carol (in `contractors`, not `core`) gets 403 when attempting to resolve `dev`.
                let carol_probe_repo = work_root.join("carol-probe");
                create_dir(&carol_probe_repo);
                sandbox.git(
                    &carol_probe_repo,
                    &["init", "--quiet", "--initial-branch=main"],
                );
                let carol_scope_err = cli_err(
                    &carol_probe_repo,
                    &carol_config,
                    b"",
                    &[
                        "scrim",
                        "secrets",
                        "set",
                        "FOO=bar",
                        "--scope",
                        "dev",
                        "--repo",
                        "my-app.git",
                    ],
                );
                assert!(
                    carol_scope_err.contains("403"),
                    "expected 403 for non-member carol resolving scope dev, got: {carol_scope_err}"
                );

                // 4. Push initial README.md commit on main as root.
                commit_file(
                    &sandbox,
                    &my_app,
                    "README.md",
                    "hello scrim\n",
                    "initial commit",
                );
                git_as(
                    &sandbox,
                    &my_app,
                    "root",
                    &root_token,
                    "2",
                    &["push", "--quiet", "-u", "origin", "main"],
                );

                // 5. Alice clones, configures local scrim settings, sets secrets, and pushes.
                let alice_clone = work_root.join("alice-clone");
                git_as(
                    &sandbox,
                    &work_root,
                    "alice",
                    &alice_token,
                    "2",
                    &["clone", "--quiet", &repo_url, "alice-clone"],
                );
                sandbox.git(
                    &alice_clone,
                    &["config", "--local", "scrim.repo", "my-app.git"],
                );
                sandbox.git(
                    &alice_clone,
                    &["config", "--local", "scrim.server", &base_url],
                );

                cli_ok(
                    &alice_clone,
                    &alice_config,
                    b"",
                    &[
                        "scrim",
                        "secrets",
                        "set",
                        "DATABASE_URL=postgres://user:p=w@db/dev",
                        "--scope",
                        "dev",
                    ],
                );
                cli_ok(
                    &alice_clone,
                    &alice_config,
                    b"super_secret_value\n",
                    &[
                        "scrim",
                        "secrets",
                        "set",
                        "API_KEY",
                        "--scope",
                        "dev",
                        "--value-stdin",
                    ],
                );

                let enc_contents =
                    read_to_string(&alice_clone.join(".scrim").join("secrets").join("dev.enc"));
                assert!(
                    !enc_contents.contains("postgres://user:p=w@db/dev")
                        && !enc_contents.contains("super_secret_value"),
                    "plaintext secret found in dev.enc:\n{enc_contents}"
                );

                sandbox.git(&alice_clone, &["add", ".scrim"]);
                sandbox.git(
                    &alice_clone,
                    &["commit", "--quiet", "-m", "add dev secrets"],
                );
                git_as(
                    &sandbox,
                    &alice_clone,
                    "alice",
                    &alice_token,
                    "2",
                    &["push", "--quiet", "origin", "main"],
                );

                // 6. Bob clones and operates completely OFFLINE (unreachable SCRIM_SERVER).
                let bob_clone = work_root.join("bob-clone");
                git_as(
                    &sandbox,
                    &work_root,
                    "bob",
                    &bob_token,
                    "2",
                    &["clone", "--quiet", &repo_url, "bob-clone"],
                );

                let mut bob_offline_env = BTreeMap::new();
                bob_offline_env.insert(
                    "SCRIM_CONFIG".to_owned(),
                    bob_config.to_string_lossy().into_owned(),
                );
                bob_offline_env.insert("SCRIM_SERVER".to_owned(), "http://127.0.0.1:1".to_owned());

                let bob_list = cli_ok_env(
                    &bob_clone,
                    bob_offline_env.clone(),
                    b"",
                    &["scrim", "secrets", "list", "--scope", "dev"],
                );
                assert_eq!(bob_list.stdout, "API_KEY\nDATABASE_URL\n");
                assert!(
                    !bob_list.stdout.contains("postgres://")
                        && !bob_list.stdout.contains("super_secret_value"),
                    "secrets list leaked values:\n{}",
                    bob_list.stdout
                );

                let bob_get = cli_ok_env(
                    &bob_clone,
                    bob_offline_env.clone(),
                    b"",
                    &["scrim", "secrets", "get", "DATABASE_URL", "--scope", "dev"],
                );
                assert_eq!(bob_get.stdout, "postgres://user:p=w@db/dev\n");

                let bob_export = cli_ok_env(
                    &bob_clone,
                    bob_offline_env.clone(),
                    b"",
                    &[
                        "scrim", "secrets", "export", "--scope", "dev", "--format", "dotenv",
                    ],
                );
                assert!(
                    bob_export.stdout.contains("API_KEY=super_secret_value\n")
                        && bob_export
                            .stdout
                            .contains("DATABASE_URL=postgres://user:p=w@db/dev\n"),
                    "unexpected dotenv export:\n{}",
                    bob_export.stdout
                );

                let bob_run = cli_ok_env(
                    &bob_clone,
                    bob_offline_env,
                    b"",
                    &[
                        "scrim",
                        "run",
                        "--scope",
                        "dev",
                        "--",
                        "sh",
                        "-c",
                        "printf \"%s|%s\" \"$DATABASE_URL\" \"$API_KEY\"",
                    ],
                );
                assert_eq!(
                    bob_run.stdout,
                    "postgres://user:p=w@db/dev|super_secret_value"
                );
                assert!(
                    !bob_clone.join(".env").exists(),
                    "scrim run must not create .env on disk"
                );

                // 7. Carol clones and cannot decrypt or run secrets.
                let carol_clone = work_root.join("carol-clone");
                git_as(
                    &sandbox,
                    &work_root,
                    "carol",
                    &carol_token,
                    "2",
                    &["clone", "--quiet", &repo_url, "carol-clone"],
                );
                let _carol_get_err = cli_err(
                    &carol_clone,
                    &carol_config,
                    b"",
                    &["scrim", "secrets", "get", "DATABASE_URL", "--scope", "dev"],
                );
                let _carol_run_err = cli_err(
                    &carol_clone,
                    &carol_config,
                    b"",
                    &["scrim", "run", "--scope", "dev", "--", "true"],
                );

                // 8. CI machine identity runs in a bare environment with ONLY `SCRIM_KEY`.
                let mut ci_env = BTreeMap::new();
                ci_env.insert("SCRIM_KEY".to_owned(), ci_scrim_key.clone());

                let ci_get = cli_ok_env(
                    &bob_clone,
                    ci_env.clone(),
                    b"",
                    &["scrim", "secrets", "get", "DATABASE_URL", "--scope", "dev"],
                );
                assert_eq!(ci_get.stdout, "postgres://user:p=w@db/dev\n");

                let ci_run = cli_ok_env(
                    &bob_clone,
                    ci_env.clone(),
                    b"",
                    &[
                        "scrim",
                        "run",
                        "--scope",
                        "dev",
                        "--",
                        "sh",
                        "-c",
                        "printf \"%s\" \"$API_KEY\"",
                    ],
                );
                assert_eq!(ci_run.stdout, "super_secret_value");

                // 9. Revocation proof: root pulls main, revokes bob, sets generation-2 secret, pushes.
                git_as(
                    &sandbox,
                    &my_app,
                    "root",
                    &root_token,
                    "2",
                    &["pull", "--quiet", "origin", "main"],
                );
                let revoke_out = cli_ok(
                    &my_app,
                    &root_config,
                    b"",
                    &["scrim", "access", "revoke", "bob"],
                );
                assert!(
                    revoke_out.stdout.contains("Revoked access for bob"),
                    "{}",
                    revoke_out.stdout
                );
                assert!(
                    revoke_out
                        .stdout
                        .contains("Rotated scope 'dev' to generation 2"),
                    "{}",
                    revoke_out.stdout
                );
                assert!(
                    revoke_out
                        .stdout
                        .contains("Secrets to rotate at their source:"),
                    "{}",
                    revoke_out.stdout
                );
                assert!(
                    revoke_out.stdout.contains("API_KEY")
                        && revoke_out.stdout.contains("DATABASE_URL"),
                    "{}",
                    revoke_out.stdout
                );
                assert!(
                    revoke_out
                        .stdout
                        .contains("Remember to commit and push the updated .scrim/ files."),
                    "{}",
                    revoke_out.stdout
                );

                cli_ok(
                    &my_app,
                    &root_config,
                    b"",
                    &[
                        "scrim",
                        "secrets",
                        "set",
                        "NEW_SECRET=rotated_value_gen2",
                        "--scope",
                        "dev",
                    ],
                );
                sandbox.git(&my_app, &["add", ".scrim"]);
                sandbox.git(
                    &my_app,
                    &[
                        "commit",
                        "--quiet",
                        "-m",
                        "rotate dev scope after bob revocation",
                    ],
                );
                git_as(
                    &sandbox,
                    &my_app,
                    "root",
                    &root_token,
                    "2",
                    &["push", "--quiet", "origin", "main"],
                );

                // Bob's git token is now rejected.
                let bob_ls_remote = try_git_as(
                    &sandbox,
                    &bob_clone,
                    "bob",
                    &bob_token,
                    "2",
                    &["ls-remote", &repo_url],
                );
                assert!(
                    !bob_ls_remote.status.success(),
                    "revoked member bob still accepted by git ls-remote"
                );

                // Even with out-of-band access to the generation-2 working tree (`my_app`),
                // bob's identity.age cannot decrypt generation 2.
                let _bob_gen2_new_err = cli_err(
                    &my_app,
                    &bob_config,
                    b"",
                    &["scrim", "secrets", "get", "NEW_SECRET", "--scope", "dev"],
                );
                let _bob_gen2_db_err = cli_err(
                    &my_app,
                    &bob_config,
                    b"",
                    &["scrim", "secrets", "get", "DATABASE_URL", "--scope", "dev"],
                );

                // Alice pulls via real git pull and decrypts NEW_SECRET.
                git_as(
                    &sandbox,
                    &alice_clone,
                    "alice",
                    &alice_token,
                    "2",
                    &["pull", "--quiet", "origin", "main"],
                );
                let alice_gen2_get = cli_ok(
                    &alice_clone,
                    &alice_config,
                    b"",
                    &["scrim", "secrets", "get", "NEW_SECRET", "--scope", "dev"],
                );
                assert_eq!(alice_gen2_get.stdout, "rotated_value_gen2\n");

                // CI bot via SCRIM_KEY decrypts NEW_SECRET on the updated tree.
                let ci_gen2_get = cli_ok_env(
                    &alice_clone,
                    ci_env,
                    b"",
                    &["scrim", "secrets", "get", "NEW_SECRET", "--scope", "dev"],
                );
                assert_eq!(ci_gen2_get.stdout, "rotated_value_gen2\n");

                // Sanity-check that none of the human identity directories were touched by ci_env.
                assert!(config_parent(&alice_config).join("identity.age").is_file());

                (alice_token, bob_token, carol_token, ci_token, ci_scrim_key)
            }
        }))
        .await;

    // 10. Audit log checks: expected actions present and zero secret leakage.
    let entries = store.audit_entries();
    let actions: Vec<&str> = entries.iter().map(|entry| entry.action.as_str()).collect();
    for expected_action in [
        "member.public_key_set",
        "secret_scope.set",
        "member.grant",
        "member.revoke",
    ] {
        assert!(
            actions.contains(&expected_action),
            "missing audit action {expected_action:?} in {actions:?}"
        );
    }

    let rendered = format!("{entries:?}");
    for sensitive in [
        root_token.as_str(),
        alice_token.as_str(),
        bob_token.as_str(),
        carol_token.as_str(),
        ci_token.as_str(),
        ci_scrim_key.as_str(),
        "scrim_",
        "AGE-SECRET-KEY-1",
        "postgres://user:p=w@db/dev",
        "super_secret_value",
        "rotated_value_gen2",
    ] {
        assert!(
            !rendered.contains(sensitive),
            "sensitive material {sensitive:?} leaked into audit log"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pre_receive_rejects_plaintext_dotenv_and_leaked_credentials_end_to_end() {
    let repo_root = temp_dir("scan-repo-root");
    let store = MemoryPolicyStore::new();
    let bootstrap = match store.bootstrap_admin("root", "bootstrap").await {
        Ok(created) => created,
        Err(err) => panic!("bootstrap_admin failed: {err}"),
    };
    let root_token = bootstrap.token.expose_secret().to_owned();
    let base_url =
        spawn_server_with_store(repo_root.path().to_path_buf(), Arc::new(store.clone())).await;

    let work_dir = temp_dir("scan-work");
    let configs_dir = temp_dir("scan-configs");
    let root_config = configs_dir.path().join("root").join("config.toml");
    let work_root = work_dir.path().to_path_buf();

    let (ci_token, ci_scrim_key) = join_blocking(tokio::task::spawn_blocking({
        let root_token = root_token.clone();
        let base_url = base_url.clone();
        let root_config = root_config.clone();
        move || {
            let sandbox = GitSandbox::new();
            let scratch = work_root.join("scratch");
            create_dir(&scratch);

            cli_ok(
                &scratch,
                &root_config,
                format!("{root_token}\n").as_bytes(),
                &["scrim", "login", "--server", &base_url, "--token-stdin"],
            );

            let app = work_root.join("app");
            create_dir(&app);
            sandbox.git(&app, &["init", "--quiet", "--initial-branch=main"]);
            cli_ok(&app, &root_config, b"", &["scrim", "init"]);
            cli_ok(
                &scratch,
                &root_config,
                b"",
                &["scrim", "group", "create", "core"],
            );

            let ci_grant = cli_ok(
                &scratch,
                &root_config,
                b"",
                &[
                    "scrim",
                    "access",
                    "grant",
                    "ci-bot",
                    "--machine",
                    "--group",
                    "core",
                ],
            );
            let ci_token = extract_issued_token(&ci_grant.stdout);
            let ci_scrim_key = extract_issued_scrim_key(&ci_grant.stdout);

            // 1. Clean commit on main succeeds.
            commit_file(
                &sandbox,
                &app,
                "README.md",
                "clean repo\n",
                "initial clean commit",
            );
            git_as(
                &sandbox,
                &app,
                "root",
                &root_token,
                "2",
                &["push", "--quiet", "-u", "origin", "main"],
            );

            // 2. Commit adding `.env` is rejected by pre-receive.
            commit_file(&sandbox, &app, ".env", "DB_PASS=plaintext\n", "add dotenv");
            let dotenv_push = try_git_as(
                &sandbox,
                &app,
                "root",
                &root_token,
                "2",
                &["push", "origin", "main"],
            );
            let dotenv_stderr = String::from_utf8_lossy(&dotenv_push.stderr);
            assert!(
                !dotenv_push.status.success() && dotenv_stderr.contains(".env"),
                "expected .env rejection in stderr, got:\n{dotenv_stderr}"
            );
            sandbox.git(&app, &["reset", "--quiet", "--hard", "origin/main"]);

            // 3. Commit adding runtime-generated `ci_scrim_key` is rejected without echoing the key.
            commit_file(
                &sandbox,
                &app,
                "leaked_key.txt",
                &format!("key={ci_scrim_key}\n"),
                "leak age key",
            );
            let key_push = try_git_as(
                &sandbox,
                &app,
                "root",
                &root_token,
                "2",
                &["push", "origin", "main"],
            );
            let key_stderr = String::from_utf8_lossy(&key_push.stderr);
            assert!(
                !key_push.status.success(),
                "leaked age secret key was not rejected:\n{key_stderr}"
            );
            assert!(
                !key_stderr.contains(&ci_scrim_key),
                "pre-receive echoed leaked SCRIM_KEY in stderr:\n{key_stderr}"
            );
            sandbox.git(&app, &["reset", "--quiet", "--hard", "origin/main"]);

            // 4. Commit adding runtime-generated `ci_token` is rejected without echoing the token.
            commit_file(
                &sandbox,
                &app,
                "leaked_tok.txt",
                &format!("token={ci_token}\n"),
                "leak bearer token",
            );
            let tok_push = try_git_as(
                &sandbox,
                &app,
                "root",
                &root_token,
                "2",
                &["push", "origin", "main"],
            );
            let tok_stderr = String::from_utf8_lossy(&tok_push.stderr);
            assert!(
                !tok_push.status.success(),
                "leaked scrim token was not rejected:\n{tok_stderr}"
            );
            assert!(
                !tok_stderr.contains(&ci_token),
                "pre-receive echoed leaked token in stderr:\n{tok_stderr}"
            );
            sandbox.git(&app, &["reset", "--quiet", "--hard", "origin/main"]);

            // 5. Commit adding `.env.example` is accepted.
            commit_file(
                &sandbox,
                &app,
                ".env.example",
                "DATABASE_URL=postgres://localhost/example\n",
                "add dotenv template",
            );
            git_as(
                &sandbox,
                &app,
                "root",
                &root_token,
                "2",
                &["push", "--quiet", "origin", "main"],
            );

            // 6. Commit adding `.env` with `-o scrim.allow-secret-scan=true` is accepted.
            commit_file(
                &sandbox,
                &app,
                ".env",
                "OVERRIDE_TEST=1\n",
                "override dotenv",
            );
            git_as(
                &sandbox,
                &app,
                "root",
                &root_token,
                "2",
                &[
                    "push",
                    "--quiet",
                    "-o",
                    "scrim.allow-secret-scan=true",
                    "origin",
                    "main",
                ],
            );

            (ci_token, ci_scrim_key)
        }
    }))
    .await;

    let entries = store.audit_entries();
    let actions: Vec<&str> = entries.iter().map(|entry| entry.action.as_str()).collect();
    assert!(
        actions.contains(&"secret_scan.override"),
        "missing secret_scan.override audit action in {actions:?}"
    );

    let rendered = format!("{entries:?}");
    for sensitive in [
        root_token.as_str(),
        ci_token.as_str(),
        ci_scrim_key.as_str(),
        "scrim_",
        "AGE-SECRET-KEY-1",
    ] {
        assert!(
            !rendered.contains(sensitive),
            "sensitive material {sensitive:?} leaked into audit log"
        );
    }
}
