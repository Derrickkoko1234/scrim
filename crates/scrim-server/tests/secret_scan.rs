//! The pre-receive secret scan (check 5) end to end: real `git` clients push
//! plaintext dotenv files and credentials to a live server, which refuses them
//! without echoing the secrets, accepts them with the audited override, and
//! only ever scans newly pushed content.
//!
//! `app.git` has the rule `refs/heads/private/*` -> `core`. `alice` is an
//! admin in `core` (the scan applies to admins too); `carol` is in no group.

mod common;

use std::{path::Path, process::Output, sync::Arc};

use common::{GitSandbox, spawn_server_with_store};
use scrim_policy::BranchRule;
use scrim_server::{
    ALLOW_MERGE_LEAK_PUSH_OPTION, ALLOW_SECRET_SCAN_PUSH_OPTION, AuditLogEntry,
    AuthenticatedMember, MemberRepoPolicy, MemoryPolicyStore, PolicyStore, PolicyStoreError,
    PolicyStoreFuture,
};
use tempfile::TempDir;

const ALICE_TOKEN: &str = "alice-token-0123456789abcdef";
const CAROL_TOKEN: &str = "carol-token-0123456789abcdef";

/// A member a test pushes as.
#[derive(Clone, Copy)]
struct Member {
    name: &'static str,
    token: &'static str,
}

const ALICE: Member = Member {
    name: "alice",
    token: ALICE_TOKEN,
};
const CAROL: Member = Member {
    name: "carol",
    token: CAROL_TOKEN,
};

// Fake secrets are assembled at run time so this file contains no literal
// that a secret scanner would flag.
fn scrim_token() -> String {
    format!("{}_{}", "scrim", "0123456789abcdef".repeat(4))
}

fn age_secret_key() -> String {
    format!(
        "{}-1{}",
        "AGE-SECRET-KEY",
        "QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L".repeat(2)
    )
    .chars()
    .take("AGE-SECRET-KEY-1".len() + 58)
    .collect()
}

fn aws_key_id() -> String {
    format!("{}{}", "AK", "IAQWERTYUIOP234567")
}

fn github_pat() -> String {
    format!("{}_{}", "ghp", "Zx9".repeat(12))
}

/// A PEM private key header followed by a recognizable fake body line.
fn pem_private_key() -> (String, &'static str) {
    let body = "MIIEowIBAAKCAQEAfakefakefakefakefakefakefakefake";
    (
        format!(
            "-----{} RSA PRIVATE KEY-----\n{body}\n-----END RSA PRIVATE KEY-----\n",
            "BEGIN"
        ),
        body,
    )
}

fn member(id: i64, name: &str, is_admin: bool) -> AuthenticatedMember {
    AuthenticatedMember {
        id,
        name: name.to_owned(),
        is_admin,
    }
}

fn build_store() -> MemoryPolicyStore {
    let mut store = MemoryPolicyStore::new();
    store.insert_member(member(1, "alice", true), ALICE_TOKEN.as_bytes());
    store.insert_member(member(3, "carol", false), CAROL_TOKEN.as_bytes());
    store.insert_group_membership(1, "core");
    match BranchRule::new("refs/heads/private/*", ["core".to_owned()]) {
        Ok(rule) => store.insert_branch_rule("app.git", rule),
        Err(error) => panic!("invalid test rule: {error}"),
    }
    store
}

fn utf8_path(path: &Path) -> &str {
    match path.to_str() {
        Some(path) => path,
        None => panic!("path is not valid UTF-8: {}", path.display()),
    }
}

fn stdout_text(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

fn write_file(dir: &Path, relative_path: &str, contents: &[u8]) {
    let path = dir.join(relative_path);
    if let Some(parent) = path.parent()
        && let Err(error) = std::fs::create_dir_all(parent)
    {
        panic!("failed to create {}: {error}", parent.display());
    }
    if let Err(error) = std::fs::write(&path, contents) {
        panic!("failed to write {}: {error}", path.display());
    }
}

/// `app.git` (one commit on `main`, one on `private/wip`) served by a live
/// server backed by [`build_store`].
struct Fixture {
    root: TempDir,
    scratch: TempDir,
    sandbox: GitSandbox,
    base_url: String,
    /// Shares its audit log with the store the server uses.
    store: MemoryPolicyStore,
}

impl Fixture {
    async fn start() -> Self {
        Self::start_with_store(|store| -> Arc<dyn PolicyStore> { Arc::new(store) }).await
    }

    async fn start_with_store(wrap_store: fn(MemoryPolicyStore) -> Arc<dyn PolicyStore>) -> Self {
        let root = match TempDir::new() {
            Ok(root) => root,
            Err(error) => panic!("failed to create root dir: {error}"),
        };
        let scratch = match TempDir::new() {
            Ok(scratch) => scratch,
            Err(error) => panic!("failed to create scratch dir: {error}"),
        };
        let sandbox = GitSandbox::new();
        let bare = root.path().join("app.git");
        sandbox.init_bare_with_commit(&bare);
        let seed = scratch.path().join("seed");
        sandbox.git(
            scratch.path(),
            &["clone", "--quiet", utf8_path(&bare), "seed"],
        );
        write_file(&seed, "wip.txt", b"private work\n");
        sandbox.git(&seed, &["add", "wip.txt"]);
        sandbox.git(&seed, &["commit", "--quiet", "-m", "wip"]);
        sandbox.git(
            &seed,
            &["push", "--quiet", "origin", "HEAD:refs/heads/private/wip"],
        );

        let store = build_store();
        let base_url =
            spawn_server_with_store(root.path().to_path_buf(), wrap_store(store.clone())).await;
        Self {
            root,
            scratch,
            sandbox,
            base_url,
            store,
        }
    }

    /// Runs `git <args>` in `dir` with `member`'s credentials, without
    /// asserting success.
    fn try_git_as(&self, member: Member, dir: &Path, args: &[&str]) -> Output {
        let credential_helper = self
            .sandbox
            .credential_helper_config(member.name, member.token);
        let mut full_args = vec!["-c", &credential_helper];
        full_args.extend_from_slice(args);
        self.sandbox.try_git(dir, &full_args)
    }

    fn git_as(&self, member: Member, dir: &Path, args: &[&str]) -> Output {
        let output = self.try_git_as(member, dir, args);
        assert!(
            output.status.success(),
            "git {args:?} as {} failed: {}",
            member.name,
            String::from_utf8_lossy(&output.stderr)
        );
        output
    }

    /// Clones `app.git` as `member` into a new directory named `name`.
    fn clone_as(&self, member: Member, name: &str) -> std::path::PathBuf {
        let url = format!("{}/app.git", self.base_url);
        self.git_as(
            member,
            self.scratch.path(),
            &["clone", "--quiet", &url, name],
        );
        self.scratch.path().join(name)
    }

    /// Commits `contents` at `relative_path` on top of the current branch.
    fn commit_file(&self, dir: &Path, relative_path: &str, contents: &[u8]) {
        write_file(dir, relative_path, contents);
        self.sandbox.git(dir, &["add", "--", relative_path]);
        self.sandbox
            .git(dir, &["commit", "--quiet", "-m", relative_path]);
    }

    /// Checks out a new branch `name` at `origin/main`.
    fn start_branch(&self, dir: &Path, name: &str) {
        self.sandbox
            .git(dir, &["checkout", "--quiet", "-b", name, "origin/main"]);
    }

    /// The object `ref_name` points at on the server, or `None`.
    fn server_ref(&self, ref_name: &str) -> Option<String> {
        let output = self.sandbox.try_git(
            &self.root.path().join("app.git"),
            &["rev-parse", "--verify", "--quiet", ref_name],
        );
        if output.status.success() {
            Some(stdout_text(&output))
        } else {
            None
        }
    }

    /// Pushes with `args` as `member`, asserts git reports a declined hook,
    /// and returns stderr.
    fn assert_push_rejected(&self, member: Member, dir: &Path, args: &[&str]) -> String {
        let mut full_args = vec!["push"];
        full_args.extend_from_slice(args);
        let output = self.try_git_as(member, dir, &full_args);
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        assert!(
            !output.status.success(),
            "push {args:?} succeeded: {stderr}"
        );
        assert!(stderr.contains("pre-receive hook declined"), "{stderr}");
        stderr
    }
}

/// Runs `scenario` on a blocking thread so the synchronous `git` processes
/// never stall the server's runtime.
async fn run_scenario(fixture: Fixture, scenario: fn(&Fixture)) {
    let join_result = tokio::task::spawn_blocking(move || scenario(&fixture)).await;
    if let Err(error) = join_result {
        panic!("scenario failed: {error}");
    }
}

async fn with_fixture(scenario: fn(&Fixture)) {
    run_scenario(Fixture::start().await, scenario).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn plaintext_dotenv_files_are_rejected_and_templates_accepted() {
    with_fixture(|fixture| {
        let dir = fixture.clone_as(ALICE, "dotenv");
        let main_before = fixture.server_ref("refs/heads/main");
        let secret_value = "hunter2-database-password";

        for path in [".env", "config/.env.production"] {
            fixture.start_branch(&dir, &format!("branch-{}", path.replace('/', "-")));
            fixture.commit_file(
                &dir,
                path,
                format!("DB_PASSWORD={secret_value}\n").as_bytes(),
            );
            let stderr =
                fixture.assert_push_rejected(ALICE, &dir, &["origin", "HEAD:refs/heads/main"]);
            assert!(stderr.contains("plaintext secrets found"), "{stderr}");
            assert!(
                stderr.contains(&format!("{path}: plaintext-dotenv-file")),
                "{stderr}"
            );
            assert!(stderr.contains("scrim secrets set"), "{stderr}");
            assert!(stderr.contains(ALLOW_SECRET_SCAN_PUSH_OPTION), "{stderr}");
            assert!(!stderr.contains(secret_value), "{stderr}");
            assert_eq!(fixture.server_ref("refs/heads/main"), main_before);
        }

        fixture.start_branch(&dir, "template");
        fixture.commit_file(&dir, ".env.example", b"DB_PASSWORD=changeme\n");
        fixture.commit_file(&dir, "README.md", b"# App\n\nCopy .env.example to .env.\n");
        fixture.git_as(
            ALICE,
            &dir,
            &["push", "--quiet", "origin", "HEAD:refs/heads/main"],
        );
        assert!(fixture.store.audit_entries().is_empty());
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn credentials_are_rejected_without_being_echoed() {
    with_fixture(|fixture| {
        let dir = fixture.clone_as(ALICE, "credentials");
        let main_before = fixture.server_ref("refs/heads/main");
        let (pem, pem_body) = pem_private_key();
        let cases = [
            (
                "ci.sh",
                format!("#!/bin/sh\n\nexport SCRIM_TOKEN={}\n", scrim_token()),
                "scrim-api-token",
                3,
                scrim_token(),
            ),
            (
                "keys/dev.txt",
                format!("# age identity\n{}\n", age_secret_key()),
                "age-secret-key",
                2,
                age_secret_key(),
            ),
            (
                "aws.ini",
                format!("[default]\naws_access_key_id = {}\n", aws_key_id()),
                "aws-access-key-id",
                2,
                aws_key_id(),
            ),
            (
                "deploy.yml",
                format!("token: {}\n", github_pat()),
                "github-token",
                1,
                github_pat(),
            ),
            (
                "id_rsa",
                pem.clone(),
                "private-key-pem",
                1,
                pem_body.to_owned(),
            ),
        ];
        for (index, (path, contents, rule, line, secret)) in cases.iter().enumerate() {
            fixture.start_branch(&dir, &format!("case-{index}"));
            fixture.commit_file(&dir, path, contents.as_bytes());
            let stderr =
                fixture.assert_push_rejected(ALICE, &dir, &["origin", "HEAD:refs/heads/main"]);
            assert!(
                stderr.contains(&format!("{path}: {rule} (line {line})")),
                "{stderr}"
            );
            assert!(!stderr.contains(secret.as_str()), "{stderr}");
            assert_eq!(fixture.server_ref("refs/heads/main"), main_before);
        }

        // A secret near the top of a file larger than the scan limit is
        // still found.
        fixture.start_branch(&dir, "large");
        let mut large = format!("config\n\nkey = {}\n", aws_key_id()).into_bytes();
        large.resize(2 * 1024 * 1024 + 17, b'x');
        fixture.commit_file(&dir, "large.txt", &large);
        let stderr = fixture.assert_push_rejected(ALICE, &dir, &["origin", "HEAD:refs/heads/main"]);
        assert!(
            stderr.contains("large.txt: aws-access-key-id (line 3)"),
            "{stderr}"
        );

        // A tag pointed straight at a blob is scanned too.
        write_file(&dir, "loose.txt", format!("{}\n", aws_key_id()).as_bytes());
        let blob = stdout_text(
            &fixture
                .sandbox
                .git(&dir, &["hash-object", "-w", "loose.txt"]),
        );
        fixture.sandbox.git(&dir, &["tag", "blob-tag", &blob]);
        let stderr = fixture.assert_push_rejected(
            ALICE,
            &dir,
            &["origin", "refs/tags/blob-tag:refs/tags/blob-tag"],
        );
        assert!(
            stderr.contains("refs/tags/blob-tag: aws-access-key-id (line 1)"),
            "{stderr}"
        );
        assert_eq!(fixture.server_ref("refs/tags/blob-tag"), None);
        assert!(fixture.store.audit_entries().is_empty());
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn override_is_audited_and_only_new_commits_are_scanned() {
    with_fixture(|fixture| {
        let dir = fixture.clone_as(ALICE, "override");
        // A clean side branch started before the override lands.
        fixture.start_branch(&dir, "side");
        fixture.commit_file(&dir, "side.txt", b"side\n");
        fixture.git_as(
            ALICE,
            &dir,
            &["push", "--quiet", "origin", "HEAD:refs/heads/side"],
        );

        fixture.start_branch(&dir, "flagged");
        fixture.commit_file(&dir, ".env", b"PLACEHOLDER=1\n");
        fixture.commit_file(
            &dir,
            "docs/aws.md",
            format!("Example: {}\n", aws_key_id()).as_bytes(),
        );
        fixture.git_as(
            ALICE,
            &dir,
            &[
                "push",
                "--quiet",
                "-o",
                ALLOW_SECRET_SCAN_PUSH_OPTION,
                "origin",
                "HEAD:refs/heads/main",
            ],
        );
        let flagged_head = stdout_text(&fixture.sandbox.git(&dir, &["rev-parse", "HEAD"]));
        assert_eq!(
            fixture.server_ref("refs/heads/main"),
            Some(flagged_head.clone())
        );

        let audit_entries = fixture.store.audit_entries();
        assert_eq!(audit_entries.len(), 1, "{audit_entries:?}");
        let entry = &audit_entries[0];
        assert_eq!(entry.actor_member_id, Some(1));
        assert_eq!(entry.action, "secret_scan.override");
        assert_eq!(entry.target_type, "repository");
        assert_eq!(entry.target_name, "app.git");
        assert_eq!(entry.details["total_findings"], 2);
        assert_eq!(entry.details["findings"][0]["path"], ".env");
        assert_eq!(
            entry.details["findings"][0]["rule"],
            "plaintext-dotenv-file"
        );
        assert_eq!(entry.details["findings"][1]["path"], "docs/aws.md");
        assert_eq!(entry.details["findings"][1]["rule"], "aws-access-key-id");
        assert_eq!(entry.details["findings"][1]["line"], 1);
        assert_eq!(
            entry.details["findings"][1]["commit"],
            flagged_head.as_str()
        );
        let details = entry.details.to_string();
        assert!(!details.contains(&aws_key_id()), "{details}");
        assert!(!details.contains("PLACEHOLDER"), "{details}");

        // A clean commit on top, and a merge of the older side branch (whose
        // diff against it re-adds nothing new), need no override.
        fixture.commit_file(&dir, "notes.txt", b"clean\n");
        fixture.sandbox.git(
            &dir,
            &["merge", "--quiet", "--no-ff", "--no-edit", "origin/side"],
        );
        fixture.git_as(
            ALICE,
            &dir,
            &["push", "--quiet", "origin", "HEAD:refs/heads/main"],
        );
        // So does a new branch pointing at the already-accepted commit.
        fixture.git_as(
            ALICE,
            &dir,
            &[
                "push",
                "--quiet",
                "origin",
                &format!("{flagged_head}:refs/heads/copy"),
            ],
        );
        assert_eq!(fixture.store.audit_entries().len(), 1);
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn too_many_new_commits_fail_closed_unless_overridden() {
    with_fixture(|fixture| {
        let dir = fixture.clone_as(ALICE, "many");
        // 4097 tiny commits via fast-import, on top of origin/main.
        let parent = stdout_text(&fixture.sandbox.git(&dir, &["rev-parse", "origin/main"]));
        let mut stream = String::new();
        for index in 0..4097 {
            stream.push_str(
                "commit refs/heads/many\n\
                 committer Scrim Test <test@example.invalid> 1700000000 +0000\n\
                 data 1\nx\n",
            );
            if index == 0 {
                stream.push_str(&format!("from {parent}\n"));
            }
            stream.push_str(&format!(
                "M 100644 inline n.txt\ndata {}\n{index}\n\n",
                index.to_string().len() + 1
            ));
        }
        let stream_path = fixture.scratch.path().join("many.fi");
        if let Err(error) = std::fs::write(&stream_path, stream) {
            panic!("failed to write fast-import stream: {error}");
        }
        // GitSandbox runs only git, so a shell alias feeds the stream in.
        fixture.sandbox.git(
            &dir,
            &[
                "-c",
                "alias.import-stream=!f() { git fast-import --quiet < \"$1\"; }; f",
                "import-stream",
                utf8_path(&stream_path),
            ],
        );
        let stderr = fixture.assert_push_rejected(ALICE, &dir, &["origin", "many:refs/heads/many"]);
        assert!(stderr.contains("too many to scan"), "{stderr}");
        assert_eq!(fixture.server_ref("refs/heads/many"), None);

        fixture.git_as(
            ALICE,
            &dir,
            &[
                "push",
                "--quiet",
                "-o",
                ALLOW_SECRET_SCAN_PUSH_OPTION,
                "origin",
                "many:refs/heads/many",
            ],
        );
        let audit_entries = fixture.store.audit_entries();
        assert_eq!(audit_entries.len(), 1, "{audit_entries:?}");
        assert_eq!(audit_entries[0].details["commit_limit_exceeded"], true);
    })
    .await;
}

/// The override relaxes only the secret scan, never ref authorization or the
/// merge-leak check.
#[tokio::test(flavor = "multi_thread")]
async fn override_does_not_bypass_access_or_merge_leak_checks() {
    with_fixture(|fixture| {
        let carol_dir = fixture.clone_as(CAROL, "carol");
        fixture.commit_file(&carol_dir, "carol.txt", b"carol\n");
        // git's own hidden-ref denial and the hook both refuse this push.
        let output = fixture.try_git_as(
            CAROL,
            &carol_dir,
            &[
                "push",
                "-o",
                ALLOW_SECRET_SCAN_PUSH_OPTION,
                "origin",
                "HEAD:refs/heads/private/carol",
            ],
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!output.status.success(), "{stderr}");
        assert!(stderr.contains("you do not have access"), "{stderr}");
        assert_eq!(fixture.server_ref("refs/heads/private/carol"), None);

        let dir = fixture.clone_as(ALICE, "leak");
        let main_before = fixture.server_ref("refs/heads/main");
        fixture.start_branch(&dir, "merged");
        fixture.sandbox.git(
            &dir,
            &[
                "merge",
                "--quiet",
                "--no-ff",
                "--no-edit",
                "origin/private/wip",
            ],
        );
        let stderr = fixture.assert_push_rejected(
            ALICE,
            &dir,
            &[
                "-o",
                ALLOW_SECRET_SCAN_PUSH_OPTION,
                "origin",
                "HEAD:refs/heads/main",
            ],
        );
        assert!(stderr.contains(ALLOW_MERGE_LEAK_PUSH_OPTION), "{stderr}");
        assert_eq!(fixture.server_ref("refs/heads/main"), main_before);
        assert!(fixture.store.audit_entries().is_empty());
    })
    .await;
}

/// Delegates to a [`MemoryPolicyStore`] but cannot write audit entries.
struct AuditFailingPolicyStore {
    inner: MemoryPolicyStore,
}

impl PolicyStore for AuditFailingPolicyStore {
    fn authenticate_token_hash<'a>(
        &'a self,
        token_hash: &'a [u8; 32],
    ) -> PolicyStoreFuture<'a, Option<AuthenticatedMember>> {
        self.inner.authenticate_token_hash(token_hash)
    }

    fn load_member_repo_policy<'a>(
        &'a self,
        member_id: i64,
        repo_key: &'a str,
    ) -> PolicyStoreFuture<'a, MemberRepoPolicy> {
        self.inner.load_member_repo_policy(member_id, repo_key)
    }

    fn record_audit_event<'a>(&'a self, _entry: AuditLogEntry) -> PolicyStoreFuture<'a, ()> {
        Box::pin(async { Err(PolicyStoreError::Internal("audit log offline".to_owned())) })
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn override_is_refused_when_it_cannot_be_audited() {
    let fixture = Fixture::start_with_store(|store| -> Arc<dyn PolicyStore> {
        Arc::new(AuditFailingPolicyStore { inner: store })
    })
    .await;
    run_scenario(fixture, |fixture| {
        let dir = fixture.clone_as(ALICE, "unaudited");
        let main_before = fixture.server_ref("refs/heads/main");
        fixture.commit_file(&dir, ".env", b"PLACEHOLDER=1\n");
        let stderr = fixture.assert_push_rejected(
            ALICE,
            &dir,
            &[
                "-o",
                ALLOW_SECRET_SCAN_PUSH_OPTION,
                "origin",
                "HEAD:refs/heads/main",
            ],
        );
        assert!(stderr.contains("internal error"), "{stderr}");
        assert_eq!(fixture.server_ref("refs/heads/main"), main_before);

        // Clean pushes need no audit entry and still work.
        fixture
            .sandbox
            .git(&dir, &["reset", "--quiet", "--hard", "origin/main"]);
        fixture.commit_file(&dir, "clean.txt", b"clean\n");
        fixture.git_as(
            ALICE,
            &dir,
            &["push", "--quiet", "origin", "HEAD:refs/heads/main"],
        );
    })
    .await;
}
