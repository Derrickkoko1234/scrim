//! Milestone M3 end-to-end integration and leak tests for encrypted private
//! files (`scrim filter-process`, placeholders, `scrim private` commands,
//! plain-bare-remote / GitHub-style workflow, and revocation key rotation).

#![allow(clippy::question_mark)]

mod common;

use std::{
    collections::BTreeMap,
    ffi::OsString,
    io::{BufReader, Cursor},
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::{Arc, OnceLock},
};

use common::{GitSandbox, spawn_server_with_store};
use scrim_cli::{CliEnv, run_from};
use scrim_crypto::{ENCRYPTED_FILE_MAGIC, parse_encrypted_file_header};
use scrim_server::{MemoryPolicyStore, PolicyStore};
use secrecy::ExposeSecret;
use tempfile::TempDir;

const GEN1_SECRET: &str = "billing_secret_gen1_value";
const GEN2_SECRET: &str = "post_revocation_gen2_secret";
const PLACEHOLDER_PREFIX: &str = "# scrim: encrypted private file";

/// Captures stdout and stderr from a CLI invocation.
struct CliOutput {
    stdout: String,
    stderr: String,
}

/// Ensures the workspace-built `scrim` binary is on disk and returns its parent
/// directory so Git's `filter.scrim.process` can invoke `scrim filter-process`.
fn ensure_scrim_bin_dir() -> &'static Path {
    static SCRIM_BIN_DIR: OnceLock<PathBuf> = OnceLock::new();
    SCRIM_BIN_DIR
        .get_or_init(|| {
            let server_exe = Path::new(env!("CARGO_BIN_EXE_scrim-server"));
            let server_bin_dir = match server_exe.parent() {
                Some(dir) => dir,
                None => panic!(
                    "CARGO_BIN_EXE_scrim-server has no parent: {}",
                    server_exe.display()
                ),
            };
            let scrim_name = if cfg!(windows) { "scrim.exe" } else { "scrim" };
            if server_bin_dir.join(scrim_name).is_file() {
                return server_bin_dir.to_path_buf();
            }

            let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
            let workspace_root = match manifest_dir.parent().and_then(Path::parent) {
                Some(root) => root,
                None => panic!(
                    "failed to resolve workspace root from {}",
                    manifest_dir.display()
                ),
            };
            let target_dir = temp_dir("scrim-cli-bin").keep();
            let cargo_bin = match std::env::var_os("CARGO") {
                Some(cargo) if !cargo.is_empty() => cargo,
                _ => OsString::from("cargo"),
            };
            let output = match Command::new(cargo_bin)
                .arg("build")
                .arg("--manifest-path")
                .arg(workspace_root.join("Cargo.toml"))
                .args(["-p", "scrim-cli", "--bin", "scrim", "--target-dir"])
                .arg(&target_dir)
                .output()
            {
                Ok(out) => out,
                Err(err) => panic!("failed to invoke cargo build for scrim binary: {err}"),
            };
            assert!(
                output.status.success(),
                "cargo build -p scrim-cli --bin scrim failed:\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            let built_dir = target_dir.join("debug");
            assert!(
                built_dir.join(scrim_name).is_file(),
                "built scrim binary missing at {}",
                built_dir.join(scrim_name).display()
            );
            built_dir
        })
        .as_path()
}

/// Returns `PATH` with [`ensure_scrim_bin_dir`] prepended.
fn augmented_path_env() -> String {
    let bin_dir = ensure_scrim_bin_dir().to_path_buf();
    let mut entries = vec![bin_dir];
    if let Some(existing) = std::env::var_os("PATH") {
        entries.extend(std::env::split_paths(&existing));
    }
    match std::env::join_paths(entries) {
        Ok(joined) => joined.to_string_lossy().into_owned(),
        Err(err) => panic!("failed to join PATH entries: {err}"),
    }
}

/// Runs `scrim_cli::run_from` with an explicit environment variable map,
/// ensuring the freshly built `scrim` binary directory is prepended to `PATH`.
fn run_cli_with_env(
    cwd: &Path,
    mut env_vars: BTreeMap<String, String>,
    stdin_bytes: &[u8],
    args: &[&str],
) -> Result<CliOutput, (anyhow::Error, CliOutput)> {
    env_vars
        .entry("PATH".to_owned())
        .or_insert_with(augmented_path_env);
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
    env_vars.insert("PATH".to_owned(), augmented_path_env());
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

/// Runs `git` with `SCRIM_CONFIG` and augmented `PATH` so `filter.scrim.process`
/// invokes the freshly built `scrim` binary hermetically.
fn try_git_with_config(
    sandbox: &GitSandbox,
    dir: &Path,
    config_path: &Path,
    args: &[&str],
) -> Output {
    let path_env = augmented_path_env();
    let cfg = config_path.to_string_lossy();
    sandbox.try_git_with_env(
        dir,
        args,
        &[("PATH", &path_env), ("SCRIM_CONFIG", cfg.as_ref())],
    )
}

/// Like [`try_git_with_config`], panicking with stderr if `git` fails.
fn git_with_config(sandbox: &GitSandbox, dir: &Path, config_path: &Path, args: &[&str]) -> Output {
    let output = try_git_with_config(sandbox, dir, config_path, args);
    assert!(
        output.status.success(),
        "git {args:?} failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

/// Runs `git` against `scrim-server` with `-c credential.helper=...`,
/// `-c protocol.version=2`, augmented `PATH`, and `extra_env`.
fn git_as_with_env(
    sandbox: &GitSandbox,
    dir: &Path,
    member_name: &str,
    token: &str,
    extra_env: &[(&str, &str)],
    args: &[&str],
) -> Output {
    let helper = sandbox.credential_helper_config(member_name, token);
    let mut full_args = Vec::with_capacity(4 + args.len());
    full_args.push("-c");
    full_args.push(&helper);
    full_args.push("-c");
    full_args.push("protocol.version=2");
    full_args.extend_from_slice(args);
    let path_env = augmented_path_env();
    let mut env = vec![("PATH", path_env.as_str())];
    env.extend_from_slice(extra_env);
    sandbox.git_with_env(dir, &full_args, &env)
}

/// Like [`git_as_with_env`], using `SCRIM_CONFIG`.
fn git_as(
    sandbox: &GitSandbox,
    dir: &Path,
    member_name: &str,
    token: &str,
    config_path: &Path,
    args: &[&str],
) -> Output {
    let cfg = config_path.to_string_lossy();
    git_as_with_env(
        sandbox,
        dir,
        member_name,
        token,
        &[("SCRIM_CONFIG", cfg.as_ref())],
        args,
    )
}

/// Writes `contents` to `dir/filename` (creating parent directories).
fn write_file(dir: &Path, filename: &str, contents: &str) {
    let target = dir.join(filename);
    if let Some(parent) = target.parent() {
        create_dir(parent);
    }
    if let Err(err) = std::fs::write(&target, contents) {
        panic!("failed to write {}: {err}", target.display());
    }
}

/// Writes `contents` to `dir/filename`, stages, and commits it.
fn commit_file(sandbox: &GitSandbox, dir: &Path, filename: &str, contents: &str, message: &str) {
    write_file(dir, filename, contents);
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

/// Reads a file to raw bytes, panicking on failure.
fn read_bytes(path: &Path) -> Vec<u8> {
    match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(err) => panic!("failed to read {}: {err}", path.display()),
    }
}

/// Returns whether `needle` appears anywhere inside `haystack`.
fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// Asserts that `git status --porcelain` is clean in `dir`.
fn assert_git_clean(sandbox: &GitSandbox, dir: &Path, config_path: &Path) {
    let status = git_with_config(sandbox, dir, config_path, &["status", "--porcelain"]);
    let text = String::from_utf8_lossy(&status.stdout);
    assert_eq!(text, "", "expected clean git status in {}", dir.display());
}

/// Awaits a `JoinHandle` from `tokio::task::spawn_blocking`.
async fn join_blocking<T>(handle: tokio::task::JoinHandle<T>) -> T {
    match handle.await {
        Ok(value) => value,
        Err(err) => panic!("blocking task panicked: {err}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn private_files_team_workflow_and_revocation_end_to_end() {
    let repo_root = temp_dir("private-files-repo-root");
    let store = MemoryPolicyStore::new();
    let bootstrap = match store.bootstrap_admin("root", "bootstrap").await {
        Ok(created) => created,
        Err(err) => panic!("bootstrap_admin failed: {err}"),
    };
    let root_token = bootstrap.token.expose_secret().to_owned();
    let base_url =
        spawn_server_with_store(repo_root.path().to_path_buf(), Arc::new(store.clone())).await;

    let work_dir = temp_dir("private-files-work");
    let configs_dir = temp_dir("private-files-configs");
    let root_config = configs_dir.path().join("root").join("config.toml");
    let alice_config = configs_dir.path().join("alice").join("config.toml");
    let bob_config = configs_dir.path().join("bob").join("config.toml");
    let carol_config = configs_dir.path().join("carol").join("config.toml");
    let work_root = work_dir.path().to_path_buf();
    let server_repo_dir = repo_root.path().join("my-app.git");
    let repo_url = format!("{base_url}/my-app.git");

    join_blocking(tokio::task::spawn_blocking(move || {
        let sandbox = GitSandbox::new();
        let scratch = work_root.join("scratch");
        create_dir(&scratch);

        // 1. Login as root, initialize `my-app`, create groups, and grant access.
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
            &["scrim", "group", "create", "finance"],
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
            &["scrim", "group", "add", "finance", "root"],
        );

        let alice_grant = cli_ok(
            &scratch,
            &root_config,
            b"",
            &["scrim", "access", "grant", "alice", "--group", "finance"],
        );
        let alice_token = extract_issued_token(&alice_grant.stdout);

        let bob_grant = cli_ok(
            &scratch,
            &root_config,
            b"",
            &["scrim", "access", "grant", "bob", "--group", "finance"],
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
                "finance",
            ],
        );
        let ci_token = extract_issued_token(&ci_grant.stdout);
        let ci_scrim_key = extract_issued_scrim_key(&ci_grant.stdout);

        // 2. Login alice, bob, carol and generate age identities for all humans.
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
        }

        // 3. Push initial README.md on main as root.
        commit_file(
            &sandbox,
            &my_app,
            "README.md",
            "hello scrim private files\n",
            "initial commit",
        );
        git_as(
            &sandbox,
            &my_app,
            "root",
            &root_token,
            &root_config,
            &["push", "--quiet", "-u", "origin", "main"],
        );

        // 4. Non-member carol gets 403 when adding private rule for `finance`.
        let carol_probe = work_root.join("carol-probe");
        create_dir(&carol_probe);
        sandbox.git(&carol_probe, &["init", "--quiet", "--initial-branch=main"]);
        let carol_add_err = cli_err(
            &carol_probe,
            &carol_config,
            b"",
            &[
                "scrim",
                "private",
                "add",
                "config/billing/**",
                "--group",
                "finance",
            ],
        );
        assert!(
            carol_add_err.contains("403"),
            "expected 403 for non-member carol, got: {carol_add_err}"
        );

        // 5. Alice clones, adds two private path rules (one dotdir sorting before `.scrim/`),
        //    writes private files, commits, and pushes to scrim-server.
        git_as(
            &sandbox,
            &work_root,
            "alice",
            &alice_token,
            &alice_config,
            &["clone", "--quiet", &repo_url, "alice-clone"],
        );
        let alice_clone = work_root.join("alice-clone");
        sandbox.git(
            &alice_clone,
            &["config", "--local", "scrim.repo", "my-app.git"],
        );
        sandbox.git(
            &alice_clone,
            &["config", "--local", "scrim.server", &base_url],
        );

        let add_billing = cli_ok(
            &alice_clone,
            &alice_config,
            b"",
            &[
                "scrim",
                "private",
                "add",
                "config/billing/**",
                "--group",
                "finance",
            ],
        );
        assert!(
            add_billing
                .stdout
                .contains("Created group key 'finance' (generation 1"),
            "{}",
            add_billing.stdout
        );
        let add_dot = cli_ok(
            &alice_clone,
            &alice_config,
            b"",
            &[
                "scrim",
                "private",
                "add",
                ".billing/**",
                "--group",
                "finance",
            ],
        );
        assert!(
            !add_dot.stdout.contains("Created group key"),
            "second rule should reuse existing finance key:\n{}",
            add_dot.stdout
        );

        write_file(
            &alice_clone,
            "config/billing/keys.json",
            &format!("{{\"billing\":\"{GEN1_SECRET}\"}}\n"),
        );
        write_file(
            &alice_clone,
            ".billing/tax.txt",
            &format!("tax_token={GEN1_SECRET}\n"),
        );
        git_with_config(
            &sandbox,
            &alice_clone,
            &alice_config,
            &[
                "add",
                ".gitattributes",
                ".scrim",
                "config/billing/keys.json",
                ".billing/tax.txt",
            ],
        );
        git_with_config(
            &sandbox,
            &alice_clone,
            &alice_config,
            &["commit", "--quiet", "-m", "add private billing files"],
        );
        git_as(
            &sandbox,
            &alice_clone,
            "alice",
            &alice_token,
            &alice_config,
            &["push", "--quiet", "origin", "main"],
        );

        // 6. Verify server bare repo stores SCRIMFILE\0 generation-1 ciphertext only.
        for path in ["config/billing/keys.json", ".billing/tax.txt"] {
            let blob = sandbox.git(
                &server_repo_dir,
                &["cat-file", "blob", &format!("main:{path}")],
            );
            assert!(
                blob.stdout.starts_with(ENCRYPTED_FILE_MAGIC),
                "{path} on server missing SCRIMFILE\\0 header"
            );
            let header = match parse_encrypted_file_header(&blob.stdout) {
                Ok(header) => header,
                Err(err) => panic!("failed to parse header for {path}: {err}"),
            };
            assert_eq!(header.group, "finance");
            assert_eq!(header.generation, 1);
            assert!(
                !contains_bytes(&blob.stdout, GEN1_SECRET.as_bytes()),
                "plaintext secret leaked into server blob {path}"
            );
        }

        // 7. Bob clones without filter (raw ciphertext), runs `scrim private setup`,
        //    and decrypts both files cleanly.
        git_as(
            &sandbox,
            &work_root,
            "bob",
            &bob_token,
            &bob_config,
            &["clone", "--quiet", &repo_url, "bob-clone"],
        );
        let bob_clone = work_root.join("bob-clone");
        for path in ["config/billing/keys.json", ".billing/tax.txt"] {
            let raw = read_bytes(&bob_clone.join(path));
            assert!(
                raw.starts_with(ENCRYPTED_FILE_MAGIC),
                "expected raw SCRIMFILE\\0 before setup for {path}"
            );
        }
        let bob_setup = cli_ok(&bob_clone, &bob_config, b"", &["scrim", "private", "setup"]);
        assert!(
            bob_setup.stdout.contains("Refreshed 2 private file(s)"),
            "{}",
            bob_setup.stdout
        );
        for path in ["config/billing/keys.json", ".billing/tax.txt"] {
            let text = read_to_string(&bob_clone.join(path));
            assert!(text.contains(GEN1_SECRET), "{path} not decrypted:\n{text}");
        }
        assert_git_clean(&sandbox, &bob_clone, &bob_config);

        let bob_status = cli_ok(
            &bob_clone,
            &bob_config,
            b"",
            &["scrim", "private", "status"],
        );
        assert!(
            bob_status.stdout.contains("Filter: configured")
                && bob_status.stdout.contains("access: yes")
                && bob_status.stdout.contains("decrypted"),
            "unexpected bob private status:\n{}",
            bob_status.stdout
        );

        // 8. Verify `scrim init --no-create --no-remote my-app.git` configures the filter.
        git_as(
            &sandbox,
            &work_root,
            "root",
            &root_token,
            &root_config,
            &["clone", "--quiet", &repo_url, "init-check-clone"],
        );
        let init_check = work_root.join("init-check-clone");
        cli_ok(
            &init_check,
            &root_config,
            b"",
            &["scrim", "init", "--no-create", "--no-remote", "my-app.git"],
        );
        let filter_proc = sandbox.git(
            &init_check,
            &["config", "--local", "--get", "filter.scrim.process"],
        );
        assert_eq!(
            String::from_utf8_lossy(&filter_proc.stdout).trim(),
            "scrim filter-process"
        );
        let filter_req = sandbox.git(
            &init_check,
            &["config", "--local", "--get", "filter.scrim.required"],
        );
        assert_eq!(String::from_utf8_lossy(&filter_req.stdout).trim(), "true");

        // 9. Carol (non-member) clones, runs `scrim private setup`, sees placeholders,
        //    commits unrelated `notes.txt` and pushes without altering server ciphertext,
        //    and cannot `git add` an edited placeholder.
        git_as(
            &sandbox,
            &work_root,
            "carol",
            &carol_token,
            &carol_config,
            &["clone", "--quiet", &repo_url, "carol-clone"],
        );
        let carol_clone = work_root.join("carol-clone");
        cli_ok(
            &carol_clone,
            &carol_config,
            b"",
            &["scrim", "private", "setup"],
        );
        for path in ["config/billing/keys.json", ".billing/tax.txt"] {
            let text = read_to_string(&carol_clone.join(path));
            assert!(
                text.starts_with(PLACEHOLDER_PREFIX),
                "expected placeholder for {path}, got:\n{text}"
            );
            assert!(
                !text.contains(GEN1_SECRET),
                "plaintext leaked to carol in {path}"
            );
        }
        assert_git_clean(&sandbox, &carol_clone, &carol_config);

        let oid_before = String::from_utf8_lossy(
            &sandbox
                .git(
                    &server_repo_dir,
                    &["rev-parse", "main:config/billing/keys.json"],
                )
                .stdout,
        )
        .trim()
        .to_owned();
        write_file(&carol_clone, "notes.txt", "public contractor notes\n");
        git_with_config(&sandbox, &carol_clone, &carol_config, &["add", "notes.txt"]);
        git_with_config(
            &sandbox,
            &carol_clone,
            &carol_config,
            &["commit", "--quiet", "-m", "carol adds public notes"],
        );
        git_as(
            &sandbox,
            &carol_clone,
            "carol",
            &carol_token,
            &carol_config,
            &["push", "--quiet", "origin", "main"],
        );
        let oid_after = String::from_utf8_lossy(
            &sandbox
                .git(
                    &server_repo_dir,
                    &["rev-parse", "main:config/billing/keys.json"],
                )
                .stdout,
        )
        .trim()
        .to_owned();
        assert_eq!(
            oid_before, oid_after,
            "non-member push changed server private blob OID"
        );

        let carol_placeholder = read_to_string(&carol_clone.join("config/billing/keys.json"));
        write_file(
            &carol_clone,
            "config/billing/keys.json",
            &format!("{carol_placeholder}tampered\n"),
        );
        let carol_tamper_add = try_git_with_config(
            &sandbox,
            &carol_clone,
            &carol_config,
            &["add", "config/billing/keys.json"],
        );
        assert!(
            !carol_tamper_add.status.success(),
            "editing placeholder must be rejected by git add"
        );

        // 10. CI bot clones with filter flags and ONLY `SCRIM_KEY` + `PATH` -> immediate plaintext.
        git_as_with_env(
            &sandbox,
            &work_root,
            "ci-bot",
            &ci_token,
            &[("SCRIM_KEY", &ci_scrim_key)],
            &[
                "clone",
                "--quiet",
                "-c",
                "filter.scrim.process=scrim filter-process",
                "-c",
                "filter.scrim.required=true",
                &repo_url,
                "ci-clone",
            ],
        );
        let ci_clone = work_root.join("ci-clone");
        for path in ["config/billing/keys.json", ".billing/tax.txt"] {
            let text = read_to_string(&ci_clone.join(path));
            assert!(text.contains(GEN1_SECRET), "CI failed to decrypt {path}");
        }
        let path_env = augmented_path_env();
        let ci_status = sandbox.git_with_env(
            &ci_clone,
            &["status", "--porcelain"],
            &[("PATH", &path_env), ("SCRIM_KEY", &ci_scrim_key)],
        );
        assert_eq!(String::from_utf8_lossy(&ci_status.stdout), "");

        // 11. Revocation leak test: root pulls, runs setup, revokes bob, writes gen-2 secret, pushes.
        git_as(
            &sandbox,
            &my_app,
            "root",
            &root_token,
            &root_config,
            &["pull", "--quiet", "origin", "main"],
        );
        cli_ok(&my_app, &root_config, b"", &["scrim", "private", "setup"]);

        let revoke_out = cli_ok(
            &my_app,
            &root_config,
            b"",
            &["scrim", "access", "revoke", "bob"],
        );
        for expected in [
            "Revoked access for bob",
            "Rotated group key 'finance' to generation 2",
            "config/billing/keys.json",
            ".billing/tax.txt",
            "Remember to commit and push the updated .scrim/ files.",
        ] {
            assert!(
                revoke_out.stdout.contains(expected),
                "revoke output missing {expected:?}:\n{}",
                revoke_out.stdout
            );
        }

        write_file(
            &my_app,
            "config/billing/keys.json",
            &format!("{{\"billing\":\"{GEN2_SECRET}\"}}\n"),
        );
        git_with_config(&sandbox, &my_app, &root_config, &["add", "-A"]);
        git_with_config(
            &sandbox,
            &my_app,
            &root_config,
            &[
                "commit",
                "--quiet",
                "-m",
                "rotate finance after bob revocation",
            ],
        );
        git_as(
            &sandbox,
            &my_app,
            "root",
            &root_token,
            &root_config,
            &["push", "--quiet", "origin", "main"],
        );

        for path in ["config/billing/keys.json", ".billing/tax.txt"] {
            let blob = sandbox.git(
                &server_repo_dir,
                &["cat-file", "blob", &format!("main:{path}")],
            );
            let header = match parse_encrypted_file_header(&blob.stdout) {
                Ok(header) => header,
                Err(err) => panic!("failed to parse gen2 header for {path}: {err}"),
            };
            assert_eq!(header.group, "finance");
            assert_eq!(header.generation, 2);
            assert!(
                !contains_bytes(&blob.stdout, GEN2_SECRET.as_bytes()),
                "gen2 plaintext leaked into server blob {path}"
            );
            assert!(
                !contains_bytes(&blob.stdout, GEN1_SECRET.as_bytes()),
                "gen1 plaintext leaked into server blob {path}"
            );
        }

        // Out-of-band clone of the bare server repo from disk with bob's identity cannot decrypt gen 2.
        let bare_path_str = server_repo_dir.to_string_lossy().into_owned();
        sandbox.git(
            &work_root,
            &["clone", "--quiet", &bare_path_str, "bob-oob-gen2"],
        );
        let bob_oob = work_root.join("bob-oob-gen2");
        cli_ok(&bob_oob, &bob_config, b"", &["scrim", "private", "setup"]);
        let bob_oob_keys = read_to_string(&bob_oob.join("config/billing/keys.json"));
        assert!(
            bob_oob_keys.starts_with(PLACEHOLDER_PREFIX),
            "revoked bob should see placeholder for gen 2, got:\n{bob_oob_keys}"
        );
        assert!(
            !bob_oob_keys.contains(GEN2_SECRET),
            "revoked bob decrypted post-revocation secret!"
        );

        // Alice pulls via real git pull and sees the generation-2 secret cleanly.
        git_as(
            &sandbox,
            &alice_clone,
            "alice",
            &alice_token,
            &alice_config,
            &["pull", "--quiet", "origin", "main"],
        );
        let alice_gen2 = read_to_string(&alice_clone.join("config/billing/keys.json"));
        assert!(
            alice_gen2.contains(GEN2_SECRET),
            "alice failed to decrypt gen2 secret:\n{alice_gen2}"
        );
        assert_git_clean(&sandbox, &alice_clone, &alice_config);
    }))
    .await;
}

#[test]
fn private_files_work_against_plain_bare_remote_like_github() {
    let work_dir = temp_dir("plain-remote-work");
    let configs_dir = temp_dir("plain-remote-configs");
    let work_root = work_dir.path();
    let alice_config = configs_dir.path().join("alice").join("config.toml");
    let bob_config = configs_dir.path().join("bob").join("config.toml");

    let sandbox = GitSandbox::new();
    let bare_remote = work_root.join("remote.git");
    sandbox.init_bare(&bare_remote);
    let remote_url = bare_remote.to_string_lossy().into_owned();

    // Alice generates an offline key and initializes a local repo with a plain bare remote.
    cli_ok(
        work_root,
        &alice_config,
        b"",
        &["scrim", "keygen", "--local-only"],
    );

    let alice_repo = work_root.join("alice-repo");
    create_dir(&alice_repo);
    sandbox.git(&alice_repo, &["init", "--quiet", "--initial-branch=main"]);
    sandbox.git(&alice_repo, &["remote", "add", "origin", &remote_url]);

    cli_ok(
        &alice_repo,
        &alice_config,
        b"",
        &[
            "scrim",
            "private",
            "add",
            "config/billing/**",
            "--group",
            "finance",
            "--offline",
        ],
    );
    write_file(&alice_repo, "README.md", "plain bare remote test\n");
    write_file(
        &alice_repo,
        "config/billing/keys.json",
        &format!("{{\"stripe\":\"{GEN1_SECRET}\"}}\n"),
    );
    git_with_config(&sandbox, &alice_repo, &alice_config, &["add", "-A"]);
    git_with_config(
        &sandbox,
        &alice_repo,
        &alice_config,
        &["commit", "--quiet", "-m", "initial private commit"],
    );
    git_with_config(
        &sandbox,
        &alice_repo,
        &alice_config,
        &["push", "--quiet", "-u", "origin", "main"],
    );

    // Bare remote stores only SCRIMFILE\0 ciphertext.
    let remote_blob = sandbox.git(
        &bare_remote,
        &["cat-file", "blob", "main:config/billing/keys.json"],
    );
    assert!(remote_blob.stdout.starts_with(ENCRYPTED_FILE_MAGIC));
    assert!(!contains_bytes(&remote_blob.stdout, GEN1_SECRET.as_bytes()));

    // Non-member Bob (no key, no server) clones, runs setup, sees placeholder,
    // commits `docs.md`, and pushes back to the plain bare remote.
    sandbox.git(work_root, &["clone", "--quiet", &remote_url, "bob-clone"]);
    let bob_clone = work_root.join("bob-clone");
    cli_ok(&bob_clone, &bob_config, b"", &["scrim", "private", "setup"]);
    let bob_view = read_to_string(&bob_clone.join("config/billing/keys.json"));
    assert!(bob_view.starts_with(PLACEHOLDER_PREFIX), "{bob_view}");
    assert!(!bob_view.contains(GEN1_SECRET));
    assert_git_clean(&sandbox, &bob_clone, &bob_config);

    write_file(&bob_clone, "docs.md", "public documentation\n");
    git_with_config(&sandbox, &bob_clone, &bob_config, &["add", "docs.md"]);
    git_with_config(
        &sandbox,
        &bob_clone,
        &bob_config,
        &["commit", "--quiet", "-m", "add docs"],
    );
    git_with_config(
        &sandbox,
        &bob_clone,
        &bob_config,
        &["push", "--quiet", "origin", "main"],
    );

    // Alice pulls from the plain bare remote: receives docs.md, keeps plaintext intact, clean status.
    git_with_config(
        &sandbox,
        &alice_repo,
        &alice_config,
        &["pull", "--quiet", "origin", "main"],
    );
    assert_eq!(
        read_to_string(&alice_repo.join("docs.md")),
        "public documentation\n"
    );
    assert!(read_to_string(&alice_repo.join("config/billing/keys.json")).contains(GEN1_SECRET));
    assert_git_clean(&sandbox, &alice_repo, &alice_config);

    // Alice clones fresh with filter enabled -> plaintext immediately and clean status.
    let path_env = augmented_path_env();
    let alice_cfg_str = alice_config.to_string_lossy();
    sandbox.git_with_env(
        work_root,
        &[
            "clone",
            "--quiet",
            "-c",
            "filter.scrim.process=scrim filter-process",
            "-c",
            "filter.scrim.required=true",
            &remote_url,
            "alice-fresh",
        ],
        &[
            ("PATH", &path_env),
            ("SCRIM_CONFIG", alice_cfg_str.as_ref()),
        ],
    );
    let alice_fresh = work_root.join("alice-fresh");
    assert!(read_to_string(&alice_fresh.join("config/billing/keys.json")).contains(GEN1_SECRET));
    assert_git_clean(&sandbox, &alice_fresh, &alice_config);
}

#[test]
fn private_files_overlap_fails_closed_and_rm_guards_placeholders() {
    let work_dir = temp_dir("overlap-rm-work");
    let configs_dir = temp_dir("overlap-rm-configs");
    let work_root = work_dir.path();
    let alice_config = configs_dir.path().join("alice").join("config.toml");
    let bob_config = configs_dir.path().join("bob").join("config.toml");

    let sandbox = GitSandbox::new();
    cli_ok(
        work_root,
        &alice_config,
        b"",
        &["scrim", "keygen", "--local-only"],
    );

    let repo = work_root.join("repo");
    create_dir(&repo);
    sandbox.git(&repo, &["init", "--quiet", "--initial-branch=main"]);
    commit_file(
        &sandbox,
        &repo,
        "config/billing/api.secret",
        &format!("API_SECRET={GEN1_SECRET}\n"),
        "track api.secret",
    );

    cli_ok(
        &repo,
        &alice_config,
        b"",
        &[
            "scrim",
            "private",
            "add",
            "config/billing/**",
            "--group",
            "finance",
            "--offline",
        ],
    );
    git_with_config(&sandbox, &repo, &alice_config, &["add", "-A"]);
    git_with_config(
        &sandbox,
        &repo,
        &alice_config,
        &["commit", "--quiet", "-m", "protect billing"],
    );

    let paths_before = read_to_string(&repo.join(".scrim/paths.toml"));
    let attrs_before = read_to_string(&repo.join(".gitattributes"));

    // Overlapping rule for a different group fails closed without modifying policy files.
    let overlap_err = cli_err(
        &repo,
        &alice_config,
        b"",
        &[
            "scrim",
            "private",
            "add",
            "*.secret",
            "--group",
            "security",
            "--offline",
        ],
    );
    assert!(
        overlap_err.contains("ambiguous path rule")
            && overlap_err.contains("config/billing/api.secret"),
        "expected ambiguous path error, got: {overlap_err}"
    );
    assert_eq!(
        read_to_string(&repo.join(".scrim/paths.toml")),
        paths_before
    );
    assert_eq!(read_to_string(&repo.join(".gitattributes")), attrs_before);
    assert!(!repo.join(".scrim/group-keys/security.toml").exists());

    // Non-member clone with placeholder cannot run `scrim private rm`.
    let repo_url = repo.to_string_lossy().into_owned();
    sandbox.git(work_root, &["clone", "--quiet", &repo_url, "bob-clone"]);
    let bob_clone = work_root.join("bob-clone");
    cli_ok(&bob_clone, &bob_config, b"", &["scrim", "private", "setup"]);
    assert!(
        read_to_string(&bob_clone.join("config/billing/api.secret"))
            .starts_with(PLACEHOLDER_PREFIX)
    );

    let bob_rm_err = cli_err(
        &bob_clone,
        &bob_config,
        b"",
        &["scrim", "private", "rm", "config/billing/**"],
    );
    assert!(
        bob_rm_err.contains("cannot unprotect") && bob_rm_err.contains("placeholder"),
        "expected placeholder guard on private rm, got: {bob_rm_err}"
    );
    assert_eq!(
        read_to_string(&bob_clone.join(".scrim/paths.toml")),
        paths_before
    );
    assert_eq!(
        read_to_string(&bob_clone.join(".gitattributes")),
        attrs_before
    );

    // Authorized member unprotects and commits -> Git object store holds plaintext again.
    cli_ok(
        &repo,
        &alice_config,
        b"",
        &["scrim", "private", "rm", "config/billing/**"],
    );
    git_with_config(&sandbox, &repo, &alice_config, &["add", "-A"]);
    git_with_config(
        &sandbox,
        &repo,
        &alice_config,
        &["commit", "--quiet", "-m", "unprotect billing"],
    );

    let blob = sandbox.git(
        &repo,
        &["cat-file", "blob", "HEAD:config/billing/api.secret"],
    );
    assert!(!blob.stdout.starts_with(ENCRYPTED_FILE_MAGIC));
    assert!(contains_bytes(&blob.stdout, GEN1_SECRET.as_bytes()));
    assert_git_clean(&sandbox, &repo, &alice_config);
}
