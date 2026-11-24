//! End-to-end tests for `scrim clone` over Git-over-SSH.
//!
//! Spins up a real `scrim-server` serving both HTTP (for `/api/v1/path-rules/me`
//! and key/policy management) and SSH (`serve_ssh` on loopback), then runs the
//! real `scrim` binary with `GIT_SSH_COMMAND` to verify:
//! - `scrim clone ssh://...` and `scrim clone <repo_key> --ssh ssh://...`
//! - SSH remote URL in `.git/config`, no bearer token leaked into `.git`
//! - M4 sparse-checkout exclusion & missing withheld blobs in `.git/objects`
//! - M3 private-file decryption for authorized members and placeholders for
//!   non-members, with a clean `git status`

mod common;

use std::{
    ffi::OsString,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::{Arc, OnceLock},
};

use common::GitSandbox;
use scrim_crypto::ENCRYPTED_FILE_MAGIC;

const PLACEHOLDER_PREFIX: &str = "# scrim: encrypted private file";
use scrim_policy::{BranchRule, WithholdRule};
use scrim_server::{
    AuthenticatedMember, MemoryPolicyStore, PolicyStore, SharedHookDir, SshServerConfig,
    load_or_create_ssh_host_key, serve_ssh,
};
use tempfile::TempDir;

#[derive(Clone, Copy)]
struct Member {
    name: &'static str,
    key_file: &'static str,
    token: &'static str,
}

const ADMIN: Member = Member {
    name: "admin",
    key_file: "admin_ed25519",
    token: "admin-token-0123456789abcdef",
};
const ALICE: Member = Member {
    name: "alice",
    key_file: "alice_ed25519",
    token: "alice-token-0123456789abcdef",
};
const CAROL: Member = Member {
    name: "carol",
    key_file: "carol_ed25519",
    token: "carol-token-0123456789abcdef",
};

fn temp_dir(prefix: &str) -> TempDir {
    match tempfile::Builder::new().prefix(prefix).tempdir() {
        Ok(dir) => dir,
        Err(error) => panic!("failed to create temporary directory: {error}"),
    }
}

fn utf8_path(path: &Path) -> &str {
    match path.to_str() {
        Some(path) => path,
        None => panic!("path is not UTF-8: {}", path.display()),
    }
}

fn stdout_text(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

fn stderr_text(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn read_bytes(path: &Path) -> Vec<u8> {
    match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) => panic!("failed to read {}: {error}", path.display()),
    }
}

fn read_to_string(path: &Path) -> String {
    match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) => panic!("failed to read {}: {error}", path.display()),
    }
}

fn write_file(dir: &Path, rel_path: &str, contents: &str) {
    let full_path = dir.join(rel_path);
    if let Some(parent) = full_path.parent()
        && let Err(error) = std::fs::create_dir_all(parent)
    {
        panic!("failed to create {}: {error}", parent.display());
    }
    if let Err(error) = std::fs::write(&full_path, contents) {
        panic!("failed to write {rel_path}: {error}");
    }
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn assert_no_bytes_in_dir(dir: &Path, needle: &[u8]) {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) => panic!("failed to read {}: {error}", dir.display()),
    };
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => panic!("failed to read dir entry in {}: {error}", dir.display()),
        };
        let path = entry.path();
        if path.is_dir() {
            assert_no_bytes_in_dir(&path, needle);
        } else if path.is_file() {
            let bytes = read_bytes(&path);
            assert!(
                !contains_bytes(&bytes, needle),
                "unexpected secret bytes found in {}",
                path.display()
            );
        }
    }
}

/// Ensures the workspace-built `scrim` binary is on disk and returns its parent
/// directory so both test invocations and Git's `filter.scrim.process` find it.
fn ensure_scrim_bin_dir() -> &'static Path {
    static SCRIM_BIN_DIR: OnceLock<PathBuf> = OnceLock::new();
    SCRIM_BIN_DIR.get_or_init(|| {
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
            stdout_text(&output),
            stderr_text(&output)
        );
        let built_dir = target_dir.join("debug");
        assert!(
            built_dir.join(scrim_name).is_file(),
            "expected built scrim binary at {}",
            built_dir.join(scrim_name).display()
        );
        built_dir
    })
}

fn scrim_bin_path() -> PathBuf {
    let scrim_name = if cfg!(windows) { "scrim.exe" } else { "scrim" };
    ensure_scrim_bin_dir().join(scrim_name)
}

fn path_with_scrim_bin() -> OsString {
    let bin_dir = ensure_scrim_bin_dir();
    match std::env::var_os("PATH") {
        Some(existing) => {
            let mut paths = vec![bin_dir.to_path_buf()];
            paths.extend(std::env::split_paths(&existing));
            match std::env::join_paths(paths) {
                Ok(joined) => joined,
                Err(error) => panic!("failed to join PATH: {error}"),
            }
        }
        None => bin_dir.as_os_str().to_os_string(),
    }
}

fn generate_ssh_key(dir: &Path, name: &str) -> String {
    let path = dir.join(name);
    let output = match Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-C"])
        .arg(format!("{name}@test"))
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
        stderr_text(&output)
    );
    match std::fs::read_to_string(path.with_extension("pub")) {
        Ok(public_key) => public_key,
        Err(error) => panic!("failed to read {name}.pub: {error}"),
    }
}

struct SshCloneFixture {
    sandbox: GitSandbox,
    root: TempDir,
    scratch: TempDir,
    keys: TempDir,
    http_url: String,
    ssh_port: u16,
}

impl SshCloneFixture {
    async fn start() -> Self {
        let sandbox = GitSandbox::new();
        let root = temp_dir("scrim-ssh-clone-root");
        let scratch = temp_dir("scrim-ssh-clone-scratch");
        let keys = temp_dir("scrim-ssh-clone-keys");

        let bare = root.path().join("team.git");
        sandbox.init_bare(&bare);

        let mut store = MemoryPolicyStore::new();
        for (id, member, is_admin) in [(1, ADMIN, true), (2, ALICE, false), (3, CAROL, false)] {
            store.insert_member(
                AuthenticatedMember {
                    id,
                    name: member.name.to_owned(),
                    is_admin,
                },
                member.token.as_bytes(),
            );
        }
        store.insert_group_membership(1, "core");
        store.insert_group_membership(1, "billing");
        store.insert_group_membership(2, "core");
        store.insert_group_membership(2, "billing");
        match BranchRule::new("refs/heads/private/*", ["core".to_owned()]) {
            Ok(rule) => store.insert_branch_rule("team.git", rule),
            Err(error) => panic!("branch rule should be valid: {error}"),
        }
        match WithholdRule::new("config/billing/**", ["billing".to_owned()]) {
            Ok(rule) => store.insert_path_rule("team.git", rule),
            Err(error) => panic!("path rule should be valid: {error}"),
        }

        for member in [ADMIN, ALICE, CAROL] {
            let pubkey = generate_ssh_key(keys.path(), member.key_file);
            if let Err(error) = store
                .add_member_ssh_key(None, member.name, &pubkey, "test")
                .await
            {
                panic!("registering {}'s SSH key failed: {error}", member.name);
            }
        }

        let host_key = match load_or_create_ssh_host_key(&keys.path().join("host_key")) {
            Ok(key) => key,
            Err(error) => panic!("creating SSH host key failed: {error}"),
        };
        let repo_root = match root.path().canonicalize() {
            Ok(path) => path,
            Err(error) => panic!("failed to canonicalize repo root: {error}"),
        };

        let shared_store: Arc<dyn PolicyStore> = Arc::new(store);
        let http_url =
            common::spawn_server_with_store(repo_root.clone(), shared_store.clone()).await;

        let listener = match tokio::net::TcpListener::bind("127.0.0.1:0").await {
            Ok(listener) => listener,
            Err(error) => panic!("failed to bind SSH listener: {error}"),
        };
        let ssh_port = match listener.local_addr() {
            Ok(addr) => addr.port(),
            Err(error) => panic!("failed to read SSH listener address: {error}"),
        };
        let ssh_config = SshServerConfig {
            repo_root,
            policy_store: shared_store,
            host_key,
            hook_dir: SharedHookDir::default(),
        };
        tokio::spawn(async move {
            if let Err(error) = serve_ssh(listener, ssh_config, std::future::pending()).await {
                panic!("SSH server failed: {error}");
            }
        });

        Self {
            sandbox,
            root,
            scratch,
            keys,
            http_url,
            ssh_port,
        }
    }

    fn ssh_base_url(&self) -> String {
        format!("ssh://git@127.0.0.1:{}", self.ssh_port)
    }

    fn ssh_repo_url(&self, repo: &str) -> String {
        format!("{}/{repo}", self.ssh_base_url())
    }

    fn ssh_command(&self, member: Member) -> String {
        let key = self.keys.path().join(member.key_file);
        let options = [
            "-F",
            "/dev/null",
            "-i",
            utf8_path(&key),
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
        ];
        format!(
            "ssh {}",
            options
                .iter()
                .map(|option| format!("'{option}'"))
                .collect::<Vec<_>>()
                .join(" ")
        )
    }

    fn config_path(&self, member: Member) -> PathBuf {
        self.scratch.path().join(format!("{}.toml", member.name))
    }

    fn key_path(&self, member: Member) -> PathBuf {
        self.keys.path().join(format!("{}.age", member.name))
    }

    fn run_scrim(&self, cwd: &Path, member: Option<Member>, args: &[&str]) -> Output {
        let mut cmd = Command::new(scrim_bin_path());
        cmd.current_dir(cwd)
            .args(args)
            .env("PATH", path_with_scrim_bin())
            .env("HOME", self.scratch.path().join("home"))
            .env_remove("SCRIM_SERVER")
            .env_remove("SCRIM_TOKEN")
            .env_remove("SCRIM_KEY")
            .env_remove("SCRIM_KEY_FILE");

        if let Some(member) = member {
            cmd.env("SCRIM_CONFIG", self.config_path(member))
                .env("GIT_SSH_COMMAND", self.ssh_command(member))
                .env("GIT_SSH_VARIANT", "ssh");
        } else {
            let empty_config = self.scratch.path().join("missing-config.toml");
            cmd.env("SCRIM_CONFIG", empty_config);
        }

        match cmd.stdin(Stdio::null()).output() {
            Ok(output) => output,
            Err(error) => panic!("failed to run scrim {args:?}: {error}"),
        }
    }

    fn scrim_ok(&self, cwd: &Path, member: Member, args: &[&str]) -> Output {
        let output = self.run_scrim(cwd, Some(member), args);
        assert!(
            output.status.success(),
            "scrim {args:?} as {} failed:\nstdout:\n{}\nstderr:\n{}",
            member.name,
            stdout_text(&output),
            stderr_text(&output)
        );
        output
    }

    fn login_member(&self, member: Member, generate_m3_key: bool) {
        self.scrim_ok(
            self.scratch.path(),
            member,
            &["login", "--server", &self.http_url, "--token", member.token],
        );
        if generate_m3_key {
            let key_file = self.key_path(member);
            self.scrim_ok(
                self.scratch.path(),
                member,
                &["--key-file", utf8_path(&key_file), "keygen"],
            );
        }
    }

    fn is_missing_locally(&self, dir: &Path, object: &str) -> bool {
        let output = self.sandbox.git_with_env(
            dir,
            &["rev-list", "--objects", "--missing=print", "--all"],
            &[("GIT_NO_LAZY_FETCH", "1")],
        );
        let marker = format!("?{object}");
        stdout_text(&output)
            .lines()
            .any(|line| line == marker || line.starts_with(&format!("{marker} ")))
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scrim_clone_over_ssh_enforces_withholding_and_m3_encryption() {
    let fixture = SshCloneFixture::start().await;

    // 1. Log in admin + alice (with M3 keys) and carol (token only, no groups).
    fixture.login_member(ADMIN, true);
    fixture.login_member(ALICE, true);
    fixture.login_member(CAROL, false);

    // 2. Seed `team.git` with public, M3 encrypted, and M4 withheld files.
    let seed = fixture.scratch.path().join("seed");
    if let Err(error) = std::fs::create_dir_all(&seed) {
        panic!("failed to create seed dir: {error}");
    }
    fixture
        .sandbox
        .git(&seed, &["init", "--quiet", "--initial-branch=main"]);
    fixture.scrim_ok(&seed, ADMIN, &["init", "team.git"]);
    let admin_key = utf8_path(&fixture.key_path(ADMIN)).to_owned();
    fixture.scrim_ok(
        &seed,
        ADMIN,
        &[
            "--key-file",
            &admin_key,
            "private",
            "add",
            "docs/encrypted/**",
            "--group",
            "core",
        ],
    );
    fixture.scrim_ok(
        &seed,
        ADMIN,
        &[
            "--key-file",
            &admin_key,
            "private",
            "add",
            "config/billing/**",
            "--group",
            "billing",
            "--withhold",
        ],
    );

    let encrypted_sentinel = b"ENCRYPTED_SSH_MEMO_SENTINEL_1122";
    let withheld_sentinel = "WITHHELD_SSH_BILLING_SENTINEL_3344";
    write_file(&seed, "public/readme.txt", "public readme v1\n");
    write_file(
        &seed,
        "docs/encrypted/memo.txt",
        "ENCRYPTED_SSH_MEMO_SENTINEL_1122\n",
    );
    write_file(
        &seed,
        "config/billing/secret.txt",
        &format!("{withheld_sentinel}\n"),
    );

    let admin_config = utf8_path(&fixture.config_path(ADMIN)).to_owned();
    let admin_key = utf8_path(&fixture.key_path(ADMIN)).to_owned();
    let path_env = path_with_scrim_bin();
    let path_str = match path_env.to_str() {
        Some(s) => s,
        None => panic!("PATH is not UTF-8"),
    };
    fixture.sandbox.git_with_env(
        &seed,
        &["add", "--all"],
        &[
            ("PATH", path_str),
            ("SCRIM_CONFIG", &admin_config),
            ("SCRIM_KEY_FILE", &admin_key),
        ],
    );
    fixture.sandbox.git_with_env(
        &seed,
        &["commit", "--quiet", "-m", "seed repo"],
        &[
            ("PATH", path_str),
            ("SCRIM_CONFIG", &admin_config),
            ("SCRIM_KEY_FILE", &admin_key),
        ],
    );

    let bare = fixture.root.path().join("team.git");
    fixture
        .sandbox
        .git(&seed, &["push", "--quiet", utf8_path(&bare), "main"]);

    // Verify M3 blob is stored encrypted on the bare repo.
    let server_memo = fixture
        .sandbox
        .git(&bare, &["cat-file", "blob", "main:docs/encrypted/memo.txt"]);
    assert!(
        server_memo.stdout.starts_with(ENCRYPTED_FILE_MAGIC),
        "expected encrypted M3 blob on server"
    );
    assert!(!contains_bytes(&server_memo.stdout, encrypted_sentinel));

    let withheld_secret_blob = stdout_text(
        &fixture
            .sandbox
            .git(&bare, &["rev-parse", "main:config/billing/secret.txt"]),
    );

    let ssh_repo_url = fixture.ssh_repo_url("team.git");
    let ssh_base_url = fixture.ssh_base_url();
    let work_root = fixture.scratch.path().join("work");
    if let Err(error) = std::fs::create_dir_all(&work_root) {
        panic!("failed to create work dir: {error}");
    }

    // 3. Error case: `scrim clone ssh://...` without configured HTTP server fails clearly.
    let missing_server = fixture.run_scrim(&work_root, None, &["clone", &ssh_repo_url, "no-srv"]);
    assert!(
        !missing_server.status.success(),
        "expected clone without HTTP server to fail"
    );
    let missing_err = stderr_text(&missing_server);
    assert!(
        missing_err.contains("--server") || missing_err.contains("scrim login"),
        "expected error mentioning --server or scrim login, got: {missing_err}"
    );

    // 4. Restricted non-member `carol` clones via direct `ssh://` URL.
    let carol_out = fixture.scrim_ok(&work_root, CAROL, &["clone", &ssh_repo_url, "carol-direct"]);
    let carol_stdout = stdout_text(&carol_out);
    assert!(
        carol_stdout.contains("Partial clone: enabled"),
        "expected partial clone for carol:\n{carol_stdout}"
    );
    assert!(
        carol_stdout.contains(&format!("Remote (origin): {ssh_repo_url}")),
        "expected SSH remote in output:\n{carol_stdout}"
    );

    let carol_work = work_root.join("carol-direct");
    assert_eq!(
        stdout_text(&fixture.sandbox.git(
            &carol_work,
            &["config", "--local", "--get", "remote.origin.url"]
        )),
        ssh_repo_url
    );
    assert_eq!(
        stdout_text(
            &fixture
                .sandbox
                .git(&carol_work, &["config", "--local", "--get", "scrim.repo"])
        ),
        "team.git"
    );
    assert_eq!(
        stdout_text(
            &fixture
                .sandbox
                .git(&carol_work, &["config", "--local", "--get", "scrim.server"])
        ),
        fixture.http_url
    );
    assert_eq!(
        stdout_text(&fixture.sandbox.git(
            &carol_work,
            &["config", "--local", "--get", "remote.origin.promisor"]
        )),
        "true"
    );
    assert_no_bytes_in_dir(&carol_work.join(".git"), CAROL.token.as_bytes());

    assert_eq!(
        read_to_string(&carol_work.join("public/readme.txt")),
        "public readme v1\n"
    );
    assert!(
        !carol_work.join("config/billing/secret.txt").exists(),
        "withheld path must not exist on disk"
    );
    assert!(
        fixture.is_missing_locally(&carol_work, &withheld_secret_blob),
        "withheld blob must be missing from local .git/objects"
    );
    let carol_memo = read_bytes(&carol_work.join("docs/encrypted/memo.txt"));
    assert!(
        carol_memo.starts_with(PLACEHOLDER_PREFIX.as_bytes()),
        "expected M3 placeholder for non-member, got:\n{}",
        String::from_utf8_lossy(&carol_memo)
    );
    assert!(!contains_bytes(&carol_memo, encrypted_sentinel));
    let carol_config = utf8_path(&fixture.config_path(CAROL)).to_owned();
    assert_eq!(
        stdout_text(&fixture.sandbox.git_with_env(
            &carol_work,
            &["status", "--porcelain"],
            &[("PATH", path_str), ("SCRIM_CONFIG", &carol_config)],
        )),
        ""
    );

    // 5. Authorized member `alice` clones via `scrim clone <repo_key> --ssh <SSH_BASE_URL>`.
    let alice_key = fixture.key_path(ALICE);
    let alice_out = fixture.scrim_ok(
        &work_root,
        ALICE,
        &[
            "--key-file",
            utf8_path(&alice_key),
            "clone",
            "team.git",
            "--ssh",
            &ssh_base_url,
            "alice-flag",
        ],
    );
    let alice_stdout = stdout_text(&alice_out);
    assert!(
        alice_stdout.contains("Partial clone: not needed"),
        "expected full clone for alice:\n{alice_stdout}"
    );

    let alice_work = work_root.join("alice-flag");
    assert_eq!(
        stdout_text(&fixture.sandbox.git(
            &alice_work,
            &["config", "--local", "--get", "remote.origin.url"]
        )),
        ssh_repo_url
    );
    assert_no_bytes_in_dir(&alice_work.join(".git"), ALICE.token.as_bytes());
    assert_eq!(
        read_to_string(&alice_work.join("public/readme.txt")),
        "public readme v1\n"
    );
    assert_eq!(
        read_to_string(&alice_work.join("config/billing/secret.txt")),
        format!("{withheld_sentinel}\n")
    );
    assert_eq!(
        read_to_string(&alice_work.join("docs/encrypted/memo.txt")),
        "ENCRYPTED_SSH_MEMO_SENTINEL_1122\n"
    );
    let alice_config = utf8_path(&fixture.config_path(ALICE)).to_owned();
    let alice_key_str = utf8_path(&alice_key).to_owned();
    assert_eq!(
        stdout_text(&fixture.sandbox.git_with_env(
            &alice_work,
            &["status", "--porcelain"],
            &[
                ("PATH", path_str),
                ("SCRIM_CONFIG", &alice_config),
                ("SCRIM_KEY_FILE", &alice_key_str),
            ],
        )),
        ""
    );
}
