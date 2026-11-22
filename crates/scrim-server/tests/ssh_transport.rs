//! Git over SSH end to end: real OpenSSH (`ssh`, `ssh-keygen`) and `git`
//! clients talk to the embedded SSH server, which must enforce exactly what
//! smart HTTP enforces.
//!
//! `alice` is in `core` and `billing`; `carol` is in no group. `team.git` has
//! the branch rule `refs/heads/private/*` -> `core` and the path rule
//! `config/billing/**` -> `billing`. `main` holds `public/readme.txt` and
//! `config/billing/secret.txt`; `private/wip` adds one commit on top.

mod common;

use std::{
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::Arc,
};

use common::GitSandbox;
use scrim_policy::{BranchRule, WithholdRule};
use scrim_server::{
    AuthenticatedMember, MemoryPolicyStore, PolicyStore, SharedHookDir, SshServerConfig,
    load_or_create_ssh_host_key, serve_ssh,
};
use tempfile::TempDir;

/// The partial-clone filter `scrim clone` uses, spelled out.
const PARTIAL_CLONE_FILTER: &str = "--filter=blob:limit=2147483647";

/// A member a test acts as, identified by their SSH key file name.
#[derive(Clone, Copy)]
struct Member {
    name: &'static str,
    key: &'static str,
}

const ALICE: Member = Member {
    name: "alice",
    key: "alice_ed25519",
};
const CAROL: Member = Member {
    name: "carol",
    key: "carol_ed25519",
};
/// A key registered to nobody.
const STRANGER: Member = Member {
    name: "stranger",
    key: "stranger_ed25519",
};

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

fn write_file(dir: &Path, path: &str, contents: &str) {
    let full_path = dir.join(path);
    if let Some(parent) = full_path.parent()
        && let Err(error) = std::fs::create_dir_all(parent)
    {
        panic!("failed to create {}: {error}", parent.display());
    }
    if let Err(error) = std::fs::write(&full_path, contents) {
        panic!("failed to write {path}: {error}");
    }
}

fn temp_dir() -> TempDir {
    match TempDir::new() {
        Ok(dir) => dir,
        Err(error) => panic!("failed to create a temporary directory: {error}"),
    }
}

/// Generates an Ed25519 key pair at `<dir>/<name>` with `ssh-keygen` and
/// returns the public key line.
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

/// Runs `future` to completion from a scenario's blocking thread.
fn block_on<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Handle::current().block_on(future)
}

struct Fixture {
    sandbox: GitSandbox,
    root: TempDir,
    scratch: TempDir,
    keys: TempDir,
    port: u16,
    store: MemoryPolicyStore,
    alice_key_id: i64,
    private_commit: String,
    secret_blob: String,
}

impl Fixture {
    async fn start() -> Self {
        let sandbox = GitSandbox::new();
        let root = temp_dir();
        let scratch = temp_dir();
        let keys = temp_dir();

        let bare = root.path().join("team.git");
        sandbox.init_bare(&bare);
        let seed = scratch.path().join("seed");
        if let Err(error) = std::fs::create_dir_all(&seed) {
            panic!("failed to create seed dir: {error}");
        }
        sandbox.git(&seed, &["init", "--quiet", "--initial-branch=main"]);
        write_file(&seed, "public/readme.txt", "hello\n");
        write_file(
            &seed,
            "config/billing/secret.txt",
            "billing-api-key: do-not-share-0123456789\n",
        );
        sandbox.git(&seed, &["add", "--all"]);
        sandbox.git(&seed, &["commit", "--quiet", "-m", "base"]);
        let secret_blob =
            stdout_text(&sandbox.git(&seed, &["rev-parse", "HEAD:config/billing/secret.txt"]));
        sandbox.git(&seed, &["checkout", "--quiet", "-b", "private/wip"]);
        write_file(&seed, "public/wip.txt", "work in progress\n");
        sandbox.git(&seed, &["add", "--all"]);
        sandbox.git(&seed, &["commit", "--quiet", "-m", "wip"]);
        let private_commit = stdout_text(&sandbox.git(&seed, &["rev-parse", "HEAD"]));
        sandbox.git(
            &seed,
            &["push", "--quiet", utf8_path(&bare), "main", "private/wip"],
        );

        let mut store = MemoryPolicyStore::new();
        for (id, member) in [(1, ALICE), (3, CAROL)] {
            store.insert_member(
                AuthenticatedMember {
                    id,
                    name: member.name.to_owned(),
                    is_admin: false,
                },
                format!("{}-token-0123456789abcdef", member.name).as_bytes(),
            );
        }
        store.insert_group_membership(1, "core");
        store.insert_group_membership(1, "billing");
        match BranchRule::new("refs/heads/private/*", ["core".to_owned()]) {
            Ok(rule) => store.insert_branch_rule("team.git", rule),
            Err(error) => panic!("branch rule should be valid: {error}"),
        }
        match WithholdRule::new("config/billing/**", ["billing".to_owned()]) {
            Ok(rule) => store.insert_path_rule("team.git", rule),
            Err(error) => panic!("path rule should be valid: {error}"),
        }

        let alice_public_key = generate_ssh_key(keys.path(), ALICE.key);
        let carol_public_key = generate_ssh_key(keys.path(), CAROL.key);
        generate_ssh_key(keys.path(), STRANGER.key);
        let alice_key_id = match store
            .add_member_ssh_key(None, ALICE.name, &alice_public_key, "laptop")
            .await
        {
            Ok(record) => record.id,
            Err(error) => panic!("registering alice's key failed: {error}"),
        };
        if let Err(error) = store
            .add_member_ssh_key(None, CAROL.name, &carol_public_key, "")
            .await
        {
            panic!("registering carol's key failed: {error}");
        }

        let host_key = match load_or_create_ssh_host_key(&keys.path().join("host_key")) {
            Ok(host_key) => host_key,
            Err(error) => panic!("creating the host key failed: {error}"),
        };
        let repo_root = match root.path().canonicalize() {
            Ok(repo_root) => repo_root,
            Err(error) => panic!("failed to resolve the repo root: {error}"),
        };
        let listener = match tokio::net::TcpListener::bind("127.0.0.1:0").await {
            Ok(listener) => listener,
            Err(error) => panic!("failed to bind the SSH listener: {error}"),
        };
        let port = match listener.local_addr() {
            Ok(address) => address.port(),
            Err(error) => panic!("failed to read the SSH listener address: {error}"),
        };
        let policy_store: Arc<dyn PolicyStore> = Arc::new(store.clone());
        let config = SshServerConfig {
            repo_root,
            policy_store,
            host_key,
            hook_dir: SharedHookDir::default(),
        };
        tokio::spawn(async move {
            if let Err(error) = serve_ssh(listener, config, std::future::pending()).await {
                panic!("SSH server failed: {error}");
            }
        });

        Self {
            sandbox,
            root,
            scratch,
            keys,
            port,
            store,
            alice_key_id,
            private_commit,
            secret_blob,
        }
    }

    fn url(&self, repo: &str) -> String {
        format!("ssh://git@127.0.0.1:{}/{repo}", self.port)
    }

    /// The `ssh` options every client uses: only `member`'s key, no user
    /// configuration, no host key prompts.
    fn ssh_options(&self, member: Member) -> Vec<String> {
        let key = self.keys.path().join(member.key);
        vec![
            "-F".to_owned(),
            "/dev/null".to_owned(),
            "-i".to_owned(),
            utf8_path(&key).to_owned(),
            "-o".to_owned(),
            "IdentitiesOnly=yes".to_owned(),
            "-o".to_owned(),
            "IdentityAgent=none".to_owned(),
            "-o".to_owned(),
            "BatchMode=yes".to_owned(),
            "-o".to_owned(),
            "StrictHostKeyChecking=no".to_owned(),
            "-o".to_owned(),
            "UserKnownHostsFile=/dev/null".to_owned(),
            "-o".to_owned(),
            "LogLevel=ERROR".to_owned(),
        ]
    }

    /// Runs `git -c protocol.version=<protocol> <args>` in `dir` over SSH as
    /// `member`, without asserting success.
    fn try_git_as(&self, member: Member, protocol: &str, dir: &Path, args: &[&str]) -> Output {
        self.try_git_as_with_env(member, protocol, dir, args, &[])
    }

    /// Like [`Fixture::try_git_as`] with extra environment variables.
    fn try_git_as_with_env(
        &self,
        member: Member,
        protocol: &str,
        dir: &Path,
        args: &[&str],
        extra_env: &[(&str, &str)],
    ) -> Output {
        let ssh_command = format!(
            "ssh {}",
            self.ssh_options(member)
                .iter()
                .map(|option| format!("'{option}'"))
                .collect::<Vec<_>>()
                .join(" ")
        );
        let protocol = format!("protocol.version={protocol}");
        let mut full_args = vec!["-c", &protocol];
        full_args.extend_from_slice(args);
        let mut env = vec![
            ("GIT_SSH_COMMAND", ssh_command.as_str()),
            ("GIT_SSH_VARIANT", "ssh"),
        ];
        env.extend_from_slice(extra_env);
        self.sandbox.try_git_with_env(dir, &full_args, &env)
    }

    fn git_as(&self, member: Member, protocol: &str, dir: &Path, args: &[&str]) -> Output {
        let output = self.try_git_as(member, protocol, dir, args);
        assert!(
            output.status.success(),
            "git {args:?} as {} failed: {}",
            member.name,
            stderr_text(&output)
        );
        output
    }

    /// Runs `ssh <options> git@127.0.0.1 <command>` as `member`.
    fn raw_ssh(&self, member: Member, extra_args: &[&str], command: Option<&str>) -> Output {
        let mut ssh = Command::new("ssh");
        ssh.args(self.ssh_options(member))
            .arg("-p")
            .arg(self.port.to_string())
            .args(extra_args)
            .arg("git@127.0.0.1");
        if let Some(command) = command {
            ssh.arg(command);
        }
        match ssh
            .env("HOME", self.sandbox_home())
            .stdin(Stdio::null())
            .output()
        {
            Ok(output) => output,
            Err(error) => panic!("failed to run ssh: {error}"),
        }
    }

    fn sandbox_home(&self) -> PathBuf {
        self.scratch.path().join("home")
    }

    fn ls_remote(&self, member: Member, protocol: &str) -> String {
        let output = self.git_as(
            member,
            protocol,
            self.scratch.path(),
            &["ls-remote", &self.url("team.git")],
        );
        stdout_text(&output)
    }

    /// Whether git spoke protocol v2 for `member`'s `ls-remote -c
    /// protocol.version=2`, from git's packet trace.
    fn speaks_protocol_v2(&self, member: Member) -> bool {
        let output = self.try_git_as_with_env(
            member,
            "2",
            self.scratch.path(),
            &["ls-remote", &self.url("team.git")],
            &[("GIT_TRACE_PACKET", "1")],
        );
        assert!(output.status.success(), "{}", stderr_text(&output));
        stderr_text(&output).contains("< version 2")
    }

    fn clone_as(&self, member: Member, protocol: &str, name: &str, options: &[&str]) -> PathBuf {
        let url = self.url("team.git");
        let mut args = vec!["clone", "--quiet"];
        args.extend_from_slice(options);
        args.push(&url);
        args.push(name);
        self.git_as(member, protocol, self.scratch.path(), &args);
        self.scratch.path().join(name)
    }

    /// A full local copy of the server repository (made without the
    /// server), with the server as remote `scrim`.
    fn local_copy(&self, name: &str) -> PathBuf {
        let bare = self.root.path().join("team.git");
        self.sandbox.git(
            self.scratch.path(),
            &["clone", "--quiet", utf8_path(&bare), name],
        );
        let dir = self.scratch.path().join(name);
        self.sandbox
            .git(&dir, &["remote", "add", "scrim", &self.url("team.git")]);
        dir
    }

    fn server_ref(&self, ref_name: &str) -> Option<String> {
        let output = self.sandbox.try_git(
            &self.root.path().join("team.git"),
            &["rev-parse", "--verify", "--quiet", ref_name],
        );
        output.status.success().then(|| stdout_text(&output))
    }

    fn is_missing_locally(&self, dir: &Path, object: &str) -> bool {
        let output = self.sandbox.git_with_env(
            dir,
            &["rev-list", "--objects", "--missing=print", "--all"],
            &[("GIT_NO_LAZY_FETCH", "1")],
        );
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .any(|line| line == format!("?{object}"))
    }
}

/// Runs `scenario` on a blocking thread so the synchronous `git` and `ssh`
/// processes never stall the server's runtime.
async fn with_fixture(scenario: fn(&Fixture)) {
    let fixture = Fixture::start().await;
    let join_result = tokio::task::spawn_blocking(move || scenario(&fixture)).await;
    if let Err(error) = join_result {
        panic!("scenario failed: {error}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn authorized_member_clones_pushes_and_fetches_over_ssh() {
    with_fixture(|fixture| {
        for protocol in ["0", "2"] {
            let refs = fixture.ls_remote(ALICE, protocol);
            assert!(refs.contains("refs/heads/main"), "{refs}");
            assert!(refs.contains("refs/heads/private/wip"), "{refs}");
        }
        // `GIT_PROTOCOL` reaches git through the SSH `env` request.
        assert!(fixture.speaks_protocol_v2(ALICE));

        let clone = fixture.clone_as(ALICE, "2", "alice", &[]);
        assert!(clone.join("config/billing/secret.txt").is_file());
        fixture
            .sandbox
            .git(&clone, &["cat-file", "-e", &fixture.private_commit]);

        write_file(&clone, "public/notes.txt", "notes\n");
        fixture.sandbox.git(&clone, &["add", "--all"]);
        fixture
            .sandbox
            .git(&clone, &["commit", "--quiet", "-m", "notes"]);
        let pushed = stdout_text(&fixture.sandbox.git(&clone, &["rev-parse", "HEAD"]));
        fixture.git_as(ALICE, "0", &clone, &["push", "--quiet", "origin", "main"]);
        assert_eq!(fixture.server_ref("refs/heads/main"), Some(pushed.clone()));
        fixture.git_as(
            ALICE,
            "2",
            &clone,
            &["push", "--quiet", "origin", "HEAD:refs/heads/private/alice"],
        );
        assert_eq!(
            fixture.server_ref("refs/heads/private/alice"),
            Some(pushed.clone())
        );

        let second = fixture.clone_as(ALICE, "0", "alice-second", &[]);
        write_file(&second, "public/more.txt", "more\n");
        fixture.sandbox.git(&second, &["add", "--all"]);
        fixture
            .sandbox
            .git(&second, &["commit", "--quiet", "-m", "more"]);
        fixture.git_as(ALICE, "2", &second, &["push", "--quiet", "origin", "main"]);
        let latest = stdout_text(&fixture.sandbox.git(&second, &["rev-parse", "HEAD"]));

        for protocol in ["0", "2"] {
            fixture.git_as(ALICE, protocol, &clone, &["fetch", "--quiet", "origin"]);
            assert_eq!(
                stdout_text(&fixture.sandbox.git(&clone, &["rev-parse", "origin/main"])),
                latest
            );
        }
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn private_branches_are_hidden_from_non_members_over_ssh() {
    with_fixture(|fixture| {
        for protocol in ["0", "2"] {
            let refs = fixture.ls_remote(CAROL, protocol);
            assert!(refs.contains("refs/heads/main"), "{refs}");
            assert!(!refs.contains("private"), "{refs}");
            assert!(!refs.contains(&fixture.private_commit), "{refs}");
        }
        // Restricted members are held to protocol v0, whose wants are
        // limited to advertised tips.
        assert!(!fixture.speaks_protocol_v2(CAROL));

        // Fetching the hidden commit by its ID is refused under v0 and v2.
        for protocol in ["0", "2"] {
            let dir = fixture
                .scratch
                .path()
                .join(format!("carol-by-id-v{protocol}"));
            if let Err(error) = std::fs::create_dir_all(&dir) {
                panic!("failed to create {}: {error}", dir.display());
            }
            fixture
                .sandbox
                .git(&dir, &["init", "--quiet", "--initial-branch=main"]);
            let by_id = fixture.try_git_as(
                CAROL,
                protocol,
                &dir,
                &[
                    "fetch",
                    PARTIAL_CLONE_FILTER,
                    &fixture.url("team.git"),
                    &fixture.private_commit,
                ],
            );
            let stderr = stderr_text(&by_id);
            assert!(
                !by_id.status.success()
                    && (stderr.contains("unadvertised object") || stderr.contains("not our ref")),
                "carol fetched the private commit by ID under protocol {protocol}: {stderr}"
            );
            // Disable lazy promisor fetches so `cat-file -e` only inspects
            // local objects and never spawns an unconfigured `ssh` against the
            // promisor remote that `git fetch --filter=...` recorded.
            let has_object = fixture.sandbox.try_git_with_env(
                &dir,
                &["cat-file", "-e", &fixture.private_commit],
                &[("GIT_NO_LAZY_FETCH", "1")],
            );
            assert!(!has_object.status.success());
        }

        // Pushing to a hidden ref is refused.
        let carol = fixture.clone_as(
            CAROL,
            "0",
            "carol",
            &[PARTIAL_CLONE_FILTER, "--no-checkout"],
        );

        // `deepen-not` is refused identically for hidden and missing refs.
        for excluded in ["refs/heads/private/wip", "refs/heads/does-not-exist"] {
            let shallow_exclude = format!("--shallow-exclude={excluded}");
            let output = fixture.try_git_as(
                CAROL,
                "2",
                &carol,
                &[
                    "fetch",
                    PARTIAL_CLONE_FILTER,
                    &shallow_exclude,
                    "origin",
                    "main",
                ],
            );
            assert!(!output.status.success(), "deepen-not {excluded} was served");
            assert!(
                stderr_text(&output).contains("invalid upload-pack request"),
                "{excluded}: {}",
                stderr_text(&output)
            );
        }
        let push_hidden = fixture.try_git_as(
            CAROL,
            "0",
            &carol,
            &["push", "origin", "origin/main:refs/heads/private/carol"],
        );
        assert!(
            !push_hidden.status.success(),
            "pushing a hidden ref succeeded"
        );
        assert_eq!(fixture.server_ref("refs/heads/private/carol"), None);

        // A member merging a private branch into a public one is refused.
        let alice = fixture.clone_as(ALICE, "2", "alice-leak", &[]);
        let main_before = fixture.server_ref("refs/heads/main");
        fixture.sandbox.git(
            &alice,
            &[
                "merge",
                "--quiet",
                "--no-ff",
                "--no-edit",
                "origin/private/wip",
            ],
        );
        let leak = fixture.try_git_as(ALICE, "0", &alice, &["push", "origin", "HEAD:main"]);
        let stderr = stderr_text(&leak);
        assert!(!leak.status.success(), "the merge-leak push succeeded");
        assert!(stderr.contains("squash"), "{stderr}");
        assert!(!stderr.contains("private/wip"), "{stderr}");
        assert_eq!(fixture.server_ref("refs/heads/main"), main_before);
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn withheld_blobs_stay_on_the_server_over_ssh() {
    with_fixture(|fixture| {
        // A plain clone cannot complete without the withheld blob, and says
        // how to clone instead.
        let plain = fixture.try_git_as(
            CAROL,
            "2",
            fixture.scratch.path(),
            &["clone", "--quiet", &fixture.url("team.git"), "carol-plain"],
        );
        assert!(!plain.status.success(), "a plain clone should fail");
        assert!(
            stderr_text(&plain).contains("scrim clone"),
            "stderr: {}",
            stderr_text(&plain)
        );

        for protocol in ["0", "2"] {
            let name = format!("carol-v{protocol}");
            let clone = fixture.clone_as(
                CAROL,
                protocol,
                &name,
                &[PARTIAL_CLONE_FILTER, "--no-checkout"],
            );
            assert!(fixture.is_missing_locally(&clone, &fixture.secret_blob));
            fixture.sandbox.git_with_env(
                &clone,
                &[
                    "sparse-checkout",
                    "set",
                    "--no-cone",
                    "/*",
                    "!/config/billing/",
                ],
                &[("GIT_NO_LAZY_FETCH", "1")],
            );
            fixture.sandbox.git_with_env(
                &clone,
                &["checkout", "--quiet", "main"],
                &[("GIT_NO_LAZY_FETCH", "1")],
            );
            assert!(clone.join("public/readme.txt").is_file());
            assert!(!clone.join("config/billing/secret.txt").exists());
            let status = fixture.sandbox.git_with_env(
                &clone,
                &["status", "--porcelain"],
                &[("GIT_NO_LAZY_FETCH", "1")],
            );
            assert_eq!(stdout_text(&status), "");

            // Nor can the blob be fetched by its ID.
            let by_id = fixture.try_git_as(
                CAROL,
                protocol,
                &clone,
                &["fetch", "--quiet", "origin", &fixture.secret_blob],
            );
            assert!(!by_id.status.success());
            assert!(fixture.is_missing_locally(&clone, &fixture.secret_blob));
        }

        // Check 6: modifying a withheld path is refused.
        let carol = fixture.local_copy("carol-edit");
        let before = fixture.server_ref("refs/heads/main");
        write_file(&carol, "config/billing/secret.txt", "overwritten\n");
        fixture
            .sandbox
            .git(&carol, &["commit", "--quiet", "-am", "edit"]);
        let edit = fixture.try_git_as(CAROL, "0", &carol, &["push", "scrim", "HEAD:main"]);
        assert!(!edit.status.success(), "editing a withheld path succeeded");
        assert!(
            stderr_text(&edit)
                .contains("do not have access to modify withheld path config/billing/secret.txt"),
            "stderr: {}",
            stderr_text(&edit)
        );
        assert_eq!(fixture.server_ref("refs/heads/main"), before);
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn revoked_keys_and_members_are_refused_over_ssh() {
    with_fixture(|fixture| {
        let denied = |member: Member| {
            let output = fixture.try_git_as(
                member,
                "2",
                fixture.scratch.path(),
                &["ls-remote", &fixture.url("team.git")],
            );
            assert!(
                !output.status.success(),
                "{} still authenticated",
                member.name
            );
            assert!(
                stderr_text(&output).contains("Permission denied"),
                "stderr: {}",
                stderr_text(&output)
            );
        };

        denied(STRANGER);

        fixture.ls_remote(ALICE, "2");
        let revoked = block_on(fixture.store.revoke_member_ssh_key(
            None,
            ALICE.name,
            fixture.alice_key_id,
        ));
        assert!(matches!(revoked, Ok(true)), "{revoked:?}");
        denied(ALICE);

        fixture.ls_remote(CAROL, "0");
        if let Err(error) = block_on(fixture.store.revoke_member(None, CAROL.name)) {
            panic!("revoking carol failed: {error}");
        }
        denied(CAROL);
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn arbitrary_commands_and_traversal_are_refused_over_ssh() {
    with_fixture(|fixture| {
        if let Err(error) = std::fs::create_dir_all(fixture.sandbox_home()) {
            panic!("failed to create the ssh home: {error}");
        }
        let marker = fixture.scratch.path().join("pwned");
        let commands = [
            "sh -c id".to_owned(),
            "id".to_owned(),
            format!("touch {}", utf8_path(&marker)),
            format!("git-upload-pack 'team.git'; touch {}", utf8_path(&marker)),
            "git-upload-pack $(id)".to_owned(),
            "git upload-pack 'team.git'".to_owned(),
            "git-upload-archive 'team.git'".to_owned(),
        ];
        for command in &commands {
            let output = fixture.raw_ssh(ALICE, &[], Some(command));
            assert!(!output.status.success(), "{command:?} succeeded");
            assert!(output.stdout.is_empty(), "{command:?} printed output");
            assert!(
                stderr_text(&output).contains("only git-upload-pack and git-receive-pack"),
                "{command:?}: {}",
                stderr_text(&output)
            );
        }
        assert!(!marker.exists(), "a command ran on the server");

        for path in [
            "'../etc'",
            "'/../etc'",
            "'team.git/../team.git'",
            "'/etc'",
            "'missing.git'",
        ] {
            let command = format!("git-upload-pack {path}");
            let output = fixture.raw_ssh(ALICE, &[], Some(&command));
            assert!(!output.status.success(), "{command:?} succeeded");
            assert!(output.stdout.is_empty(), "{command:?} printed output");
            assert!(
                stderr_text(&output).contains("repository not found"),
                "{command:?}: {}",
                stderr_text(&output)
            );
        }

        // Shells, subsystems and port forwarding are refused too.
        let shell = fixture.raw_ssh(ALICE, &["-T"], None);
        assert!(!shell.status.success(), "a shell was granted");
        let subsystem = fixture.raw_ssh(ALICE, &["-s"], Some("sftp"));
        assert!(!subsystem.status.success(), "a subsystem was granted");
        let forward = fixture.raw_ssh(
            ALICE,
            &[
                "-N",
                "-o",
                "ExitOnForwardFailure=yes",
                "-R",
                "0:127.0.0.1:22",
            ],
            None,
        );
        assert!(!forward.status.success(), "a port forward was granted");
    })
    .await;
}
