#![allow(clippy::question_mark)]

//! End-to-end tests for serverless/offline team recipient management using the
//! real `scrim` binary, real `git`, and a plain bare Git repository (no
//! `scrim-server` involved).

use std::fmt::Display;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use scrim_crypto::parse_encrypted_file_header;

fn must<T, E: Display>(res: Result<T, E>, context: &str) -> T {
    match res {
        Ok(val) => val,
        Err(err) => panic!("{context}: {err}"),
    }
}

fn must_some<T>(opt: Option<T>, context: &str) -> T {
    match opt {
        Some(val) => val,
        None => panic!("expected Some for {context}"),
    }
}

fn scrim_bin() -> &'static str {
    env!("CARGO_BIN_EXE_scrim")
}

fn stdout_str(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr_str(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn assert_success(out: &Output, what: &str) {
    assert!(
        out.status.success(),
        "{what} failed\nstdout:\n{}\nstderr:\n{}",
        stdout_str(out),
        stderr_str(out)
    );
}

fn assert_failure(out: &Output, what: &str) {
    assert!(
        !out.status.success(),
        "{what} unexpectedly succeeded\nstdout:\n{}\nstderr:\n{}",
        stdout_str(out),
        stderr_str(out)
    );
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// Isolated harness that puts the built `scrim` binary on `PATH` and isolates
/// Git from any global or system config and Scrim from any inherited env vars.
struct OfflineHarness {
    path_env: String,
    global_config: String,
}

impl OfflineHarness {
    fn new(tmp: &Path) -> Self {
        let bin_dir = must_some(Path::new(scrim_bin()).parent(), "scrim binary directory");
        let path_env = match std::env::var("PATH") {
            Ok(inherited) if !inherited.is_empty() => format!("{}:{inherited}", bin_dir.display()),
            _ => bin_dir.display().to_string(),
        };
        let global_config = tmp.join("empty-gitconfig");
        must(
            fs::write(&global_config, ""),
            "write empty global gitconfig",
        );
        Self {
            path_env,
            global_config: global_config.to_string_lossy().into_owned(),
        }
    }

    fn run(
        &self,
        program: &str,
        args: &[&str],
        cwd: &Path,
        config_path: &Path,
        extra_env: &[(&str, &str)],
    ) -> Output {
        let mut cmd = Command::new(program);
        cmd.args(args)
            .current_dir(cwd)
            .env("PATH", &self.path_env)
            .env("GIT_CONFIG_GLOBAL", &self.global_config)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("SCRIM_CONFIG", config_path)
            .env_remove("SCRIM_CONFIG_DIR")
            .env_remove("SCRIM_SERVER")
            .env_remove("SCRIM_TOKEN")
            .env_remove("SCRIM_KEY")
            .env_remove("SCRIM_KEY_FILE")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (key, value) in extra_env {
            cmd.env(key, value);
        }
        must(cmd.output(), &format!("spawn {program} {args:?}"))
    }

    fn scrim(
        &self,
        args: &[&str],
        cwd: &Path,
        config_path: &Path,
        extra_env: &[(&str, &str)],
    ) -> Output {
        self.run(scrim_bin(), args, cwd, config_path, extra_env)
    }

    fn git_ok(
        &self,
        args: &[&str],
        cwd: &Path,
        config_path: &Path,
        extra_env: &[(&str, &str)],
    ) -> Output {
        let out = self.run("git", args, cwd, config_path, extra_env);
        assert_success(&out, &format!("git {args:?}"));
        out
    }

    fn init_bare(&self, parent: &Path, name: &str, config_path: &Path) -> PathBuf {
        let bare = parent.join(name);
        must(fs::create_dir_all(&bare), "create bare repo dir");
        self.git_ok(
            &["init", "-q", "--bare", "-b", "main"],
            &bare,
            config_path,
            &[],
        );
        bare
    }

    fn init_working_repo(
        &self,
        parent: &Path,
        name: &str,
        remote_url: &str,
        config_path: &Path,
    ) -> PathBuf {
        let repo = parent.join(name);
        must(fs::create_dir_all(&repo), "create working repo dir");
        self.git_ok(&["init", "-q", "-b", "main"], &repo, config_path, &[]);
        self.configure_git_user(&repo, config_path);
        self.git_ok(
            &["remote", "add", "origin", remote_url],
            &repo,
            config_path,
            &[],
        );
        repo
    }

    fn configure_git_user(&self, repo: &Path, config_path: &Path) {
        self.git_ok(&["config", "user.name", "Test"], repo, config_path, &[]);
        self.git_ok(
            &["config", "user.email", "test@example.com"],
            repo,
            config_path,
            &[],
        );
        self.git_ok(
            &["config", "commit.gpgsign", "false"],
            repo,
            config_path,
            &[],
        );
    }

    /// Runs `scrim keygen --local-only` for a member and returns `(config_path, public_key)`.
    fn keygen_member(&self, parent: &Path, name: &str) -> (PathBuf, String) {
        let cfg_dir = parent.join(format!("{name}-cfg"));
        must(fs::create_dir_all(&cfg_dir), "create member cfg dir");
        let config_path = cfg_dir.join("config.toml");
        let out = self.scrim(&["keygen", "--local-only"], parent, &config_path, &[]);
        assert_success(&out, &format!("scrim keygen --local-only ({name})"));
        let stdout = stdout_str(&out);
        let pub_key = must_some(
            stdout
                .lines()
                .find_map(|line| line.strip_prefix("Public key: "))
                .map(str::trim)
                .map(str::to_owned),
            &format!("Public key line in keygen output for {name}: {stdout}"),
        );
        assert!(
            pub_key.starts_with("age1"),
            "expected canonical age1... key for {name}, got {pub_key}"
        );
        (config_path, pub_key)
    }
}

#[test]
fn offline_team_secrets_recipients_workflow_over_plain_bare_git() {
    let tmp = must(tempfile::tempdir(), "create tempdir");
    let harness = OfflineHarness::new(tmp.path());

    let (alice_cfg, alice_pub) = harness.keygen_member(tmp.path(), "alice");
    let (bob_cfg, bob_pub) = harness.keygen_member(tmp.path(), "bob");
    let (carol_cfg, carol_pub) = harness.keygen_member(tmp.path(), "carol");

    // Empty config dir with NO identity file, to verify `recipients list` needs no private key.
    let no_key_dir = tmp.path().join("nokey-cfg");
    must(fs::create_dir_all(&no_key_dir), "mkdir nokey-cfg");
    let no_key_cfg = no_key_dir.join("config.toml");

    let bare = harness.init_bare(tmp.path(), "origin.git", &alice_cfg);
    let bare_url = bare.to_string_lossy().into_owned();
    let alice_repo = harness.init_working_repo(tmp.path(), "alice-repo", &bare_url, &alice_cfg);

    // 1. Alice creates an offline scope and stores DB_PASS=s3cr3t.
    let set_out = harness.scrim(
        &[
            "secrets",
            "set",
            "DB_PASS=s3cr3t",
            "--scope",
            "prod",
            "--offline",
        ],
        &alice_repo,
        &alice_cfg,
        &[],
    );
    assert_success(&set_out, "alice secrets set --offline");

    // 2. Listing recipients works completely offline and without any private key.
    let list_initial = harness.scrim(
        &["secrets", "recipients", "list", "--scope", "prod"],
        &alice_repo,
        &no_key_cfg,
        &[],
    );
    assert_success(&list_initial, "secrets recipients list without identity");
    let list_initial_out = stdout_str(&list_initial);
    assert!(list_initial_out.contains("Scope 'prod' (generation 1, 1 recipient(s)):"));
    assert!(list_initial_out.contains(&format!("  self: {alice_pub}")));

    // 3. Alice adds Bob to scope prod; generation stays 1.
    let add_bob = harness.scrim(
        &[
            "secrets",
            "recipients",
            "add",
            "bob",
            &bob_pub,
            "--scope",
            "prod",
        ],
        &alice_repo,
        &alice_cfg,
        &[],
    );
    assert_success(&add_bob, "alice secrets recipients add bob");
    assert!(
        stdout_str(&add_bob)
            .contains("Added recipient 'bob' to scope 'prod' (generation 1, 2 recipient(s))")
    );

    // Verify deterministic sorted list output without private key.
    let list_two = harness.scrim(
        &["secrets", "recipients", "list", "--scope", "prod"],
        &alice_repo,
        &no_key_cfg,
        &[],
    );
    assert_success(&list_two, "secrets recipients list (2 recipients)");
    let list_two_out = stdout_str(&list_two);
    assert!(list_two_out.contains("Scope 'prod' (generation 1, 2 recipient(s)):"));
    let bob_pos = must_some(
        list_two_out.find(&format!("  bob: {bob_pub}")),
        "bob line in recipients list",
    );
    let self_pos = must_some(
        list_two_out.find(&format!("  self: {alice_pub}")),
        "self line in recipients list",
    );
    assert!(bob_pos < self_pos, "recipients should be sorted by name");

    // 4. Error handling checks: duplicate add, invalid member, invalid key,
    // unauthorized actor, missing member rm.
    let dup_add = harness.scrim(
        &[
            "secrets",
            "recipients",
            "add",
            "bob",
            &bob_pub,
            "--scope",
            "prod",
        ],
        &alice_repo,
        &alice_cfg,
        &[],
    );
    assert_failure(&dup_add, "duplicate secrets recipients add");
    assert!(stderr_str(&dup_add).contains("already exists"));

    let bad_member = harness.scrim(
        &[
            "secrets",
            "recipients",
            "add",
            "../evil",
            &carol_pub,
            "--scope",
            "prod",
        ],
        &alice_repo,
        &alice_cfg,
        &[],
    );
    assert_failure(&bad_member, "invalid member name");

    let bad_key = harness.scrim(
        &[
            "secrets",
            "recipients",
            "add",
            "carol",
            "not-an-age-key",
            "--scope",
            "prod",
        ],
        &alice_repo,
        &alice_cfg,
        &[],
    );
    assert_failure(&bad_key, "invalid age public key");

    let unauth_add = harness.scrim(
        &[
            "secrets",
            "recipients",
            "add",
            "carol",
            &carol_pub,
            "--scope",
            "prod",
        ],
        &alice_repo,
        &carol_cfg,
        &[],
    );
    assert_failure(&unauth_add, "unauthorized secrets recipients add");

    let missing_rm = harness.scrim(
        &["secrets", "recipients", "rm", "nobody", "--scope", "prod"],
        &alice_repo,
        &alice_cfg,
        &[],
    );
    assert_failure(&missing_rm, "missing member secrets recipients rm");
    assert!(stderr_str(&missing_rm).contains("not found"));

    // 5. Alice commits and pushes to the plain bare Git repository.
    harness.git_ok(&["add", "-A"], &alice_repo, &alice_cfg, &[]);
    harness.git_ok(
        &["commit", "-q", "-m", "add prod secrets for alice and bob"],
        &alice_repo,
        &alice_cfg,
        &[],
    );
    harness.git_ok(
        &["push", "-q", "origin", "main"],
        &alice_repo,
        &alice_cfg,
        &[],
    );

    // 6. Bob clones from the plain bare Git repo and decrypts offline.
    harness.git_ok(
        &["clone", "-q", &bare_url, "bob-repo"],
        tmp.path(),
        &bob_cfg,
        &[],
    );
    let bob_repo = tmp.path().join("bob-repo");

    let bob_get = harness.scrim(
        &["secrets", "get", "DB_PASS", "--scope", "prod"],
        &bob_repo,
        &bob_cfg,
        &[],
    );
    assert_success(&bob_get, "bob secrets get DB_PASS");
    assert_eq!(stdout_str(&bob_get), "s3cr3t\n");

    #[cfg(unix)]
    let bob_run = harness.scrim(
        &[
            "run",
            "--scope",
            "prod",
            "--",
            "sh",
            "-c",
            "printf %s \"$DB_PASS\"",
        ],
        &bob_repo,
        &bob_cfg,
        &[],
    );
    #[cfg(windows)]
    let bob_run = harness.scrim(
        &[
            "run",
            "--scope",
            "prod",
            "--",
            "cmd",
            "/C",
            "echo %DB_PASS%",
        ],
        &bob_repo,
        &bob_cfg,
        &[],
    );
    assert_success(&bob_run, "bob scrim run --scope prod");
    assert_eq!(stdout_str(&bob_run).trim(), "s3cr3t");

    // 7. Alice removes Bob -> rotates scope key to generation 2 and lists DB_PASS.
    let rm_bob = harness.scrim(
        &["secrets", "recipients", "rm", "bob", "--scope", "prod"],
        &alice_repo,
        &alice_cfg,
        &[],
    );
    assert_success(&rm_bob, "alice secrets recipients rm bob");
    let rm_bob_out = stdout_str(&rm_bob);
    assert!(rm_bob_out.contains("rotated to generation 2 (1 recipient(s))"));
    assert!(rm_bob_out.contains("Secrets to rotate at their source:"));
    assert!(rm_bob_out.contains("  DB_PASS"));

    // 8. Removing the last remaining recipient is rejected.
    let rm_last = harness.scrim(
        &["secrets", "recipients", "rm", "self", "--scope", "prod"],
        &alice_repo,
        &alice_cfg,
        &[],
    );
    assert_failure(&rm_last, "removing last recipient from scope");
    assert!(stderr_str(&rm_last).contains("cannot remove the last recipient"));

    // 9. Alice sets a new secret NEW_KEY=v2, commits and pushes.
    let set_v2 = harness.scrim(
        &["secrets", "set", "NEW_KEY=v2", "--scope", "prod"],
        &alice_repo,
        &alice_cfg,
        &[],
    );
    assert_success(&set_v2, "alice secrets set NEW_KEY=v2");

    harness.git_ok(&["add", "-A"], &alice_repo, &alice_cfg, &[]);
    harness.git_ok(
        &["commit", "-q", "-m", "revoke bob and add NEW_KEY"],
        &alice_repo,
        &alice_cfg,
        &[],
    );
    harness.git_ok(
        &["push", "-q", "origin", "main"],
        &alice_repo,
        &alice_cfg,
        &[],
    );

    // Alice can still decrypt both secrets at generation 2.
    let alice_get_new = harness.scrim(
        &["secrets", "get", "NEW_KEY", "--scope", "prod"],
        &alice_repo,
        &alice_cfg,
        &[],
    );
    assert_success(&alice_get_new, "alice secrets get NEW_KEY");
    assert_eq!(stdout_str(&alice_get_new), "v2\n");

    // 10. Bob pulls and can no longer decrypt generation 2 secrets.
    harness.git_ok(&["pull", "-q", "origin", "main"], &bob_repo, &bob_cfg, &[]);

    let bob_get_new = harness.scrim(
        &["secrets", "get", "NEW_KEY", "--scope", "prod"],
        &bob_repo,
        &bob_cfg,
        &[],
    );
    assert_failure(&bob_get_new, "bob secrets get NEW_KEY after removal");

    let bob_get_old = harness.scrim(
        &["secrets", "get", "DB_PASS", "--scope", "prod"],
        &bob_repo,
        &bob_cfg,
        &[],
    );
    assert_failure(&bob_get_old, "bob secrets get DB_PASS after removal");
}

#[test]
fn offline_team_private_files_recipients_workflow_over_plain_bare_git() {
    let tmp = must(tempfile::tempdir(), "create tempdir");
    let harness = OfflineHarness::new(tmp.path());

    let (alice_cfg, alice_pub) = harness.keygen_member(tmp.path(), "alice");
    let (bob_cfg, bob_pub) = harness.keygen_member(tmp.path(), "bob");
    let (carol_cfg, carol_pub) = harness.keygen_member(tmp.path(), "carol");

    let no_key_dir = tmp.path().join("nokey-cfg");
    must(fs::create_dir_all(&no_key_dir), "mkdir nokey-cfg");
    let no_key_cfg = no_key_dir.join("config.toml");

    let bare = harness.init_bare(tmp.path(), "origin.git", &alice_cfg);
    let bare_url = bare.to_string_lossy().into_owned();
    let alice_repo = harness.init_working_repo(tmp.path(), "alice-repo", &bare_url, &alice_cfg);

    // 1. Alice protects billing/** offline for group finance and creates billing/plan.txt.
    let add_rule = harness.scrim(
        &[
            "private",
            "add",
            "billing/**",
            "--group",
            "finance",
            "--offline",
        ],
        &alice_repo,
        &alice_cfg,
        &[],
    );
    assert_success(&add_rule, "alice private add --offline");

    must(
        fs::create_dir_all(alice_repo.join("billing")),
        "mkdir billing",
    );
    must(
        fs::write(alice_repo.join("billing/plan.txt"), "quarterly-plan-v1\n"),
        "write billing/plan.txt",
    );
    must(
        fs::write(alice_repo.join("README.md"), "public readme\n"),
        "write README.md",
    );

    // 2. Alice adds Bob to group finance; generation stays 1.
    let add_bob = harness.scrim(
        &[
            "private",
            "recipients",
            "add",
            "bob",
            &bob_pub,
            "--group",
            "finance",
        ],
        &alice_repo,
        &alice_cfg,
        &[],
    );
    assert_success(&add_bob, "alice private recipients add bob");
    assert!(
        stdout_str(&add_bob)
            .contains("Added recipient 'bob' to group 'finance' (generation 1, 2 recipient(s))")
    );

    // Verify `private recipients list` works without any private key and sorts recipients.
    let list_out = harness.scrim(
        &["private", "recipients", "list", "--group", "finance"],
        &alice_repo,
        &no_key_cfg,
        &[],
    );
    assert_success(&list_out, "private recipients list without identity");
    let list_text = stdout_str(&list_out);
    assert!(list_text.contains("Group 'finance' (generation 1, 2 recipient(s)):"));
    let bob_pos = must_some(
        list_text.find(&format!("  bob: {bob_pub}")),
        "bob in private recipients list",
    );
    let self_pos = must_some(
        list_text.find(&format!("  self: {alice_pub}")),
        "self in private recipients list",
    );
    assert!(bob_pos < self_pos, "recipients should be sorted by name");

    // Verify duplicate add, invalid member, unauthorized add, and missing rm rejections.
    let dup_add = harness.scrim(
        &[
            "private",
            "recipients",
            "add",
            "bob",
            &bob_pub,
            "--group",
            "finance",
        ],
        &alice_repo,
        &alice_cfg,
        &[],
    );
    assert_failure(&dup_add, "duplicate private recipients add");
    assert!(stderr_str(&dup_add).contains("already exists"));

    let unauth_add = harness.scrim(
        &[
            "private",
            "recipients",
            "add",
            "carol",
            &carol_pub,
            "--group",
            "finance",
        ],
        &alice_repo,
        &carol_cfg,
        &[],
    );
    assert_failure(&unauth_add, "unauthorized private recipients add");

    let missing_rm = harness.scrim(
        &[
            "private",
            "recipients",
            "rm",
            "nobody",
            "--group",
            "finance",
        ],
        &alice_repo,
        &alice_cfg,
        &[],
    );
    assert_failure(&missing_rm, "missing member private recipients rm");
    assert!(stderr_str(&missing_rm).contains("not found"));

    // 3. Alice commits and pushes to the plain bare Git repo.
    harness.git_ok(&["add", "-A"], &alice_repo, &alice_cfg, &[]);
    harness.git_ok(
        &["commit", "-q", "-m", "add private billing plan v1"],
        &alice_repo,
        &alice_cfg,
        &[],
    );
    harness.git_ok(
        &["push", "-q", "origin", "main"],
        &alice_repo,
        &alice_cfg,
        &[],
    );

    // Verify the bare repo stores ciphertext at generation 1, never plaintext.
    let bare_blob = harness.git_ok(
        &["cat-file", "blob", "main:billing/plan.txt"],
        &bare,
        &alice_cfg,
        &[],
    );
    assert!(bare_blob.stdout.starts_with(b"SCRIMFILE\0"));
    assert!(!contains_bytes(&bare_blob.stdout, b"quarterly-plan-v1"));
    let hdr_v1 = must(
        parse_encrypted_file_header(&bare_blob.stdout),
        "parse gen 1 header",
    );
    assert_eq!(hdr_v1.group, "finance");
    assert_eq!(hdr_v1.generation, 1);

    // 4. Bob clones and runs `scrim private setup` -> sees plaintext and clean `git status`.
    harness.git_ok(
        &["clone", "-q", &bare_url, "bob-repo"],
        tmp.path(),
        &bob_cfg,
        &[],
    );
    let bob_repo = tmp.path().join("bob-repo");
    harness.configure_git_user(&bob_repo, &bob_cfg);

    let bob_setup = harness.scrim(&["private", "setup"], &bob_repo, &bob_cfg, &[]);
    assert_success(&bob_setup, "bob scrim private setup");

    let bob_plan = must(
        fs::read_to_string(bob_repo.join("billing/plan.txt")),
        "read bob billing/plan.txt",
    );
    assert_eq!(bob_plan, "quarterly-plan-v1\n");
    let bob_status = harness.git_ok(&["status", "--porcelain"], &bob_repo, &bob_cfg, &[]);
    assert_eq!(stdout_str(&bob_status), "");

    // 5. Carol (not a recipient) clones and runs `scrim private setup` -> sees placeholder.
    harness.git_ok(
        &["clone", "-q", &bare_url, "carol-repo"],
        tmp.path(),
        &carol_cfg,
        &[],
    );
    let carol_repo = tmp.path().join("carol-repo");
    let carol_setup = harness.scrim(&["private", "setup"], &carol_repo, &carol_cfg, &[]);
    assert_success(&carol_setup, "carol scrim private setup");

    let carol_plan = must(
        fs::read_to_string(carol_repo.join("billing/plan.txt")),
        "read carol billing/plan.txt",
    );
    assert!(
        carol_plan.starts_with("# scrim: encrypted private file"),
        "expected placeholder for carol, got: {carol_plan}"
    );
    assert!(!carol_plan.contains("quarterly-plan-v1"));
    let carol_status = harness.git_ok(&["status", "--porcelain"], &carol_repo, &carol_cfg, &[]);
    assert_eq!(stdout_str(&carol_status), "");

    // 6. Alice removes Bob from group finance -> rotates group key to gen 2 and re-encrypts billing/plan.txt.
    let rm_bob = harness.scrim(
        &["private", "recipients", "rm", "bob", "--group", "finance"],
        &alice_repo,
        &alice_cfg,
        &[],
    );
    assert_success(&rm_bob, "alice private recipients rm bob");
    let rm_bob_out = stdout_str(&rm_bob);
    assert!(rm_bob_out.contains("rotated to generation 2 (1 recipient(s))"));
    assert!(rm_bob_out.contains("billing/plan.txt"));

    // Verify staged blob is already re-encrypted at generation 2 before any edit.
    let staged_blob = harness.git_ok(
        &["cat-file", "blob", ":billing/plan.txt"],
        &alice_repo,
        &alice_cfg,
        &[],
    );
    let staged_hdr = must(
        parse_encrypted_file_header(&staged_blob.stdout),
        "parse staged gen 2 header",
    );
    assert_eq!(staged_hdr.generation, 2);

    // Removing the last recipient is rejected.
    let rm_last = harness.scrim(
        &["private", "recipients", "rm", "self", "--group", "finance"],
        &alice_repo,
        &alice_cfg,
        &[],
    );
    assert_failure(&rm_last, "removing last recipient from group");
    assert!(stderr_str(&rm_last).contains("cannot remove the last recipient"));

    // 7. Alice edits billing/plan.txt, commits, and pushes.
    must(
        fs::write(
            alice_repo.join("billing/plan.txt"),
            "quarterly-plan-v2-secret\n",
        ),
        "update billing/plan.txt",
    );
    harness.git_ok(&["add", "-A"], &alice_repo, &alice_cfg, &[]);
    harness.git_ok(
        &[
            "commit",
            "-q",
            "-m",
            "rotate finance key and update plan v2",
        ],
        &alice_repo,
        &alice_cfg,
        &[],
    );
    harness.git_ok(
        &["push", "-q", "origin", "main"],
        &alice_repo,
        &alice_cfg,
        &[],
    );

    let bare_blob_v2 = harness.git_ok(
        &["cat-file", "blob", "main:billing/plan.txt"],
        &bare,
        &alice_cfg,
        &[],
    );
    let hdr_v2 = must(
        parse_encrypted_file_header(&bare_blob_v2.stdout),
        "parse gen 2 header",
    );
    assert_eq!(hdr_v2.generation, 2);
    assert!(!contains_bytes(
        &bare_blob_v2.stdout,
        b"quarterly-plan-v2-secret"
    ));

    // 8. Bob pulls -> sees placeholder on the generation-2 commit and cannot decrypt.
    harness.git_ok(&["pull", "-q", "origin", "main"], &bob_repo, &bob_cfg, &[]);

    let bob_plan_v2 = must(
        fs::read_to_string(bob_repo.join("billing/plan.txt")),
        "read bob billing/plan.txt after revocation",
    );
    assert!(
        bob_plan_v2.starts_with("# scrim: encrypted private file"),
        "expected placeholder for bob after removal, got: {bob_plan_v2}"
    );
    assert!(!bob_plan_v2.contains("quarterly-plan-v2-secret"));
    let bob_status_v2 = harness.git_ok(&["status", "--porcelain"], &bob_repo, &bob_cfg, &[]);
    assert_eq!(stdout_str(&bob_status_v2), "");

    let bob_priv_status = harness.scrim(&["private", "status"], &bob_repo, &bob_cfg, &[]);
    assert_success(&bob_priv_status, "bob private status after removal");
    let bob_priv_status_out = stdout_str(&bob_priv_status);
    assert!(bob_priv_status_out.contains("finance: generation 2, 1 recipient(s), access: no"));
    assert!(bob_priv_status_out.contains("billing/plan.txt [finance]: placeholder (no access)"));
}
