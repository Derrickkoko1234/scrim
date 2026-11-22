//! Multi-member private branches end to end: real `git` clients talk to the
//! server backed by a [`MemoryPolicyStore`], and each member sees, fetches and
//! pushes only the refs the branch rules allow them.
//!
//! Members: `alice` is in `core`; `bob` is in `core` and `security`; `carol` is
//! in `contractors`. `team.git` has the rules
//!
//! - `refs/heads/private/*` -> `core` (prefix rule)
//! - `refs/heads/*/secret` -> `security` (overlaps the prefix rule)
//! - `refs/heads/secret` -> `core` (exact rule with no such branch: git cannot
//!   hold `refs/heads/secret` next to `refs/heads/secret/public`, and hiding
//!   the exact name must not hide `refs/heads/secret/public` below it)
//! - `refs/heads/vault` -> `core` (exact rule on an existing branch)
//! - `refs/heads/release-*` -> `core` (complex glob)
//!
//! `symref.git` and `chained.git` hide `refs/heads/private/*` behind symbolic
//! refs, and `complex.git` has a complex-glob rule no current ref matches.
//!
//! The pre-receive guard tests at the end push with real `git` clients and
//! with hand-written `git-receive-pack` requests (empty packs, thin packs
//! with a hidden delta base, non-UTF-8 ref names) that a normal client would
//! never send.

mod common;

use std::{collections::BTreeMap, path::Path, process::Output, sync::Arc};

use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use common::{
    GitSandbox, PackEntry, bearer_header, build_pack, delta_size, object_id, pack_push_request,
    pkt_line_bytes, raw_object_id, spawn_server_with_store,
};
use http_body_util::BodyExt;
use scrim_policy::BranchRule;
use scrim_server::{
    ALLOW_MERGE_LEAK_PUSH_OPTION, AuditLogEntry, AuthenticatedMember, MemberRepoPolicy,
    MemoryPolicyStore, PolicyStore, PolicyStoreError, PolicyStoreFuture,
};
use tempfile::TempDir;
use tower::ServiceExt;

const ALICE_TOKEN: &str = "alice-token-0123456789abcdef";
const BOB_TOKEN: &str = "bob-token-0123456789abcdef";
const CAROL_TOKEN: &str = "carol-token-0123456789abcdef";

/// Branches of `team.git`, each pointing at its own commit (a child of the
/// initial commit on `main`), so a commit is reachable only from its branch.
const TEAM_BRANCHES: [&str; 7] = [
    "private/wip",
    "private/secret",
    "feature/secret",
    "vault",
    "secret/public",
    "release-1",
    "contrib-base",
];

/// Branches `carol` (in `contractors` only) must never see in `team.git`.
const HIDDEN_FROM_CAROL: [&str; 5] = [
    "private/wip",
    "private/secret",
    "feature/secret",
    "vault",
    "release-1",
];

/// A member a test acts as.
#[derive(Clone, Copy)]
struct Member {
    name: &'static str,
    token: &'static str,
}

const ALICE: Member = Member {
    name: "alice",
    token: ALICE_TOKEN,
};
const BOB: Member = Member {
    name: "bob",
    token: BOB_TOKEN,
};
const CAROL: Member = Member {
    name: "carol",
    token: CAROL_TOKEN,
};

fn branch_rule(pattern: &str, groups: &[&str]) -> BranchRule {
    match BranchRule::new(pattern, groups.iter().map(|group| (*group).to_owned())) {
        Ok(rule) => rule,
        Err(error) => panic!("invalid test rule {pattern:?}: {error}"),
    }
}

fn member(id: i64, name: &str) -> AuthenticatedMember {
    AuthenticatedMember {
        id,
        name: name.to_owned(),
        is_admin: false,
    }
}

/// The members, groups and rules described in the module documentation, plus
/// a `refs/heads/private/*` -> `core` rule on `secret.git`, `headhidden.git`,
/// `detached.git`, `symref.git` and `chained.git`, and a
/// `refs/heads/*-hidden` -> `core` rule on `complex.git`.
fn build_store() -> MemoryPolicyStore {
    let mut store = MemoryPolicyStore::new();
    store.insert_member(member(1, "alice"), ALICE_TOKEN.as_bytes());
    store.insert_member(member(2, "bob"), BOB_TOKEN.as_bytes());
    store.insert_member(member(3, "carol"), CAROL_TOKEN.as_bytes());
    store.insert_group_membership(1, "core");
    store.insert_group_membership(2, "core");
    store.insert_group_membership(2, "security");
    store.insert_group_membership(3, "contractors");

    store.insert_branch_rule("team.git", branch_rule("refs/heads/private/*", &["core"]));
    store.insert_branch_rule(
        "team.git",
        branch_rule("refs/heads/*/secret", &["security"]),
    );
    store.insert_branch_rule("team.git", branch_rule("refs/heads/secret", &["core"]));
    store.insert_branch_rule("team.git", branch_rule("refs/heads/vault", &["core"]));
    store.insert_branch_rule("team.git", branch_rule("refs/heads/release-*", &["core"]));
    for repo in [
        "secret.git",
        "headhidden.git",
        "detached.git",
        "symref.git",
        "chained.git",
    ] {
        store.insert_branch_rule(repo, branch_rule("refs/heads/private/*", &["core"]));
    }
    store.insert_branch_rule("complex.git", branch_rule("refs/heads/*-hidden", &["core"]));
    store
}

fn utf8_path(path: &Path) -> &str {
    match path.to_str() {
        Some(path) => path,
        None => panic!("path is not valid UTF-8: {}", path.display()),
    }
}

fn stdout_text(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// Creates a bare repository at `bare_path` whose `main` has one commit, plus
/// one branch per entry of `branches` with its own commit on top of `main`.
/// Returns every branch's commit ID, keyed by short branch name.
fn seed_repo(
    sandbox: &GitSandbox,
    bare_path: &Path,
    branches: &[&str],
) -> BTreeMap<String, String> {
    sandbox.init_bare_with_commit(bare_path);
    let work = match TempDir::new() {
        Ok(work) => work,
        Err(error) => panic!("failed to create work dir: {error}"),
    };
    let bare = utf8_path(bare_path);
    sandbox.git(work.path(), &["clone", "--quiet", bare, "."]);

    let mut commits = BTreeMap::new();
    let main_commit = sandbox.git(work.path(), &["rev-parse", "HEAD"]);
    commits.insert(
        "main".to_owned(),
        stdout_text(&main_commit).trim().to_owned(),
    );
    for branch in branches {
        sandbox.git(work.path(), &["checkout", "--quiet", "-B", "seed", "main"]);
        let file_name = format!("{}.txt", branch.replace('/', "_"));
        if let Err(error) = std::fs::write(work.path().join(&file_name), *branch) {
            panic!("failed to write {file_name}: {error}");
        }
        sandbox.git(work.path(), &["add", &file_name]);
        sandbox.git(work.path(), &["commit", "--quiet", "-m", branch]);
        let commit = sandbox.git(work.path(), &["rev-parse", "HEAD"]);
        commits.insert((*branch).to_owned(), stdout_text(&commit).trim().to_owned());
        sandbox.git(
            work.path(),
            &[
                "push",
                "--quiet",
                "origin",
                &format!("HEAD:refs/heads/{branch}"),
            ],
        );
    }
    commits
}

/// Repositories under one root, served by one server.
struct Fixture {
    root: TempDir,
    scratch: TempDir,
    sandbox: GitSandbox,
    base_url: String,
    /// Commit IDs of `team.git` branches.
    team_commits: BTreeMap<String, String>,
    /// Commit IDs of `secret.git` branches.
    secret_commits: BTreeMap<String, String>,
    /// Commit IDs of `headhidden.git` branches.
    head_hidden_commits: BTreeMap<String, String>,
    /// Commit IDs of `detached.git` branches; `HEAD` is detached at
    /// `private/wip`.
    detached_commits: BTreeMap<String, String>,
    /// Commit IDs of `symref.git` branches; `refs/heads/alias` is a symbolic
    /// ref to `refs/heads/private/wip`.
    symref_commits: BTreeMap<String, String>,
    /// Commit IDs of `chained.git` branches; `HEAD` -> `refs/heads/default`
    /// -> `refs/heads/private/wip`.
    chained_commits: BTreeMap<String, String>,
    /// Commit IDs of `complex.git` branches; `HEAD` is detached at `main`.
    complex_commits: BTreeMap<String, String>,
    /// Shares its audit log with the store the server uses.
    store: MemoryPolicyStore,
}

impl Fixture {
    async fn start() -> Self {
        Self::start_with_store(|store| -> Arc<dyn PolicyStore> { Arc::new(store) }).await
    }

    /// Like [`Fixture::start`], serving the store `wrap_store` builds around
    /// [`build_store`]'s store.
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

        let team_commits = seed_repo(&sandbox, &root.path().join("team.git"), &TEAM_BRANCHES);
        let secret_commits = seed_repo(&sandbox, &root.path().join("secret.git"), &["private/wip"]);
        #[cfg(unix)]
        if let Err(error) = std::os::unix::fs::symlink("secret.git", root.path().join("alias.git"))
        {
            panic!("failed to create alias.git symlink: {error}");
        }

        let head_hidden_path = root.path().join("headhidden.git");
        let head_hidden_commits = seed_repo(&sandbox, &head_hidden_path, &["private/main"]);
        sandbox.git(
            &head_hidden_path,
            &["symbolic-ref", "HEAD", "refs/heads/private/main"],
        );

        let detached_path = root.path().join("detached.git");
        let detached_commits = seed_repo(&sandbox, &detached_path, &["private/wip"]);
        let Some(detached_commit) = detached_commits.get("private/wip") else {
            panic!("detached.git has no private/wip commit");
        };
        if let Err(error) =
            std::fs::write(detached_path.join("HEAD"), format!("{detached_commit}\n"))
        {
            panic!("failed to detach HEAD: {error}");
        }

        let symref_path = root.path().join("symref.git");
        let symref_commits = seed_repo(&sandbox, &symref_path, &["private/wip"]);
        sandbox.git(
            &symref_path,
            &["symbolic-ref", "refs/heads/alias", "refs/heads/private/wip"],
        );

        let chained_path = root.path().join("chained.git");
        let chained_commits = seed_repo(&sandbox, &chained_path, &["private/wip"]);
        sandbox.git(
            &chained_path,
            &[
                "symbolic-ref",
                "refs/heads/default",
                "refs/heads/private/wip",
            ],
        );
        sandbox.git(
            &chained_path,
            &["symbolic-ref", "HEAD", "refs/heads/default"],
        );

        let complex_path = root.path().join("complex.git");
        let complex_commits = seed_repo(&sandbox, &complex_path, &[]);
        let complex_main = Self::commit(&complex_commits, "main");
        if let Err(error) = std::fs::write(complex_path.join("HEAD"), format!("{complex_main}\n")) {
            panic!("failed to detach HEAD: {error}");
        }

        let store = build_store();
        let base_url =
            spawn_server_with_store(root.path().to_path_buf(), wrap_store(store.clone())).await;
        Self {
            root,
            scratch,
            sandbox,
            base_url,
            team_commits,
            secret_commits,
            head_hidden_commits,
            detached_commits,
            symref_commits,
            chained_commits,
            complex_commits,
            store,
        }
    }

    fn url(&self, repo: &str) -> String {
        format!("{}/{repo}", self.base_url)
    }

    fn commit(commits: &BTreeMap<String, String>, branch: &str) -> String {
        match commits.get(branch) {
            Some(commit) => commit.clone(),
            None => panic!("no commit seeded for {branch}"),
        }
    }

    /// Runs `git -c protocol.version=<protocol> <args>` in `dir` as `member`,
    /// without asserting success.
    fn try_git_as(&self, member: Member, protocol: &str, dir: &Path, args: &[&str]) -> Output {
        let credential_helper = self
            .sandbox
            .credential_helper_config(member.name, member.token);
        let protocol = format!("protocol.version={protocol}");
        let mut full_args = vec!["-c", &credential_helper, "-c", &protocol];
        full_args.extend_from_slice(args);
        self.sandbox.try_git(dir, &full_args)
    }

    /// Like [`Fixture::try_git_as`], panicking with git's stderr on failure.
    fn git_as(&self, member: Member, protocol: &str, dir: &Path, args: &[&str]) -> Output {
        let output = self.try_git_as(member, protocol, dir, args);
        assert!(
            output.status.success(),
            "git {args:?} as {} failed: {}",
            member.name,
            String::from_utf8_lossy(&output.stderr)
        );
        output
    }

    /// `git ls-remote <repo>` as `member`, returning its stdout.
    fn ls_remote(&self, member: Member, protocol: &str, repo: &str) -> String {
        let output = self.git_as(
            member,
            protocol,
            self.scratch.path(),
            &["ls-remote", &self.url(repo)],
        );
        stdout_text(&output)
    }

    /// Creates an empty local repository with `origin` set to `repo`.
    fn empty_clone(&self, name: &str, repo: &str) -> std::path::PathBuf {
        let dir = self.scratch.path().join(name);
        if let Err(error) = std::fs::create_dir_all(&dir) {
            panic!("failed to create {}: {error}", dir.display());
        }
        self.sandbox
            .git(&dir, &["init", "--quiet", "--initial-branch=main"]);
        self.sandbox
            .git(&dir, &["remote", "add", "origin", &self.url(repo)]);
        dir
    }

    /// The commit `ref_name` points at in the server-side bare `repo`.
    fn server_ref(&self, repo: &str, ref_name: &str) -> String {
        let output = self
            .sandbox
            .git(&self.root.path().join(repo), &["rev-parse", ref_name]);
        stdout_text(&output).trim().to_owned()
    }
}

/// Runs `scenario` against a fresh [`Fixture`] on a blocking thread so the
/// synchronous `git` processes never stall the server's runtime.
async fn with_fixture(scenario: fn(&Fixture)) {
    run_scenario(Fixture::start().await, scenario).await;
}

/// Runs `scenario` against `fixture` on a blocking thread.
async fn run_scenario(fixture: Fixture, scenario: fn(&Fixture)) {
    let join_result = tokio::task::spawn_blocking(move || scenario(&fixture)).await;
    if let Err(error) = join_result {
        panic!("scenario failed: {error}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn core_member_sees_clones_fetches_and_pushes_private_branches() {
    with_fixture(|fixture| {
        for protocol in ["0", "1", "2"] {
            let refs = fixture.ls_remote(ALICE, protocol, "team.git");
            for visible in ["main", "private/wip", "vault", "secret/public", "release-1"] {
                assert!(
                    refs.contains(&format!("\trefs/heads/{visible}\n")),
                    "alice should see {visible} (protocol {protocol}):\n{refs}"
                );
            }
            // Overlapping rules intersect: alice is in `core` but not
            // `security`, so `private/secret` stays hidden from her.
            for hidden in ["private/secret", "feature/secret"] {
                assert!(
                    !refs.contains(&format!("refs/heads/{hidden}")),
                    "alice must not see {hidden} (protocol {protocol}):\n{refs}"
                );
                assert!(!refs.contains(&Fixture::commit(&fixture.team_commits, hidden)));
            }
        }

        let clone_dir = fixture.scratch.path().join("alice-clone");
        fixture.git_as(
            ALICE,
            "2",
            fixture.scratch.path(),
            &["clone", "--quiet", &fixture.url("team.git"), "alice-clone"],
        );
        let wip = fixture.git_as(
            ALICE,
            "2",
            &clone_dir,
            &["rev-parse", "refs/remotes/origin/private/wip"],
        );
        assert_eq!(
            stdout_text(&wip).trim(),
            Fixture::commit(&fixture.team_commits, "private/wip")
        );

        fixture.git_as(
            ALICE,
            "2",
            &clone_dir,
            &["checkout", "--quiet", "-b", "wip", "origin/private/wip"],
        );
        if let Err(error) = std::fs::write(clone_dir.join("alice.txt"), "alice\n") {
            panic!("failed to write alice.txt: {error}");
        }
        fixture.sandbox.git(&clone_dir, &["add", "alice.txt"]);
        fixture
            .sandbox
            .git(&clone_dir, &["commit", "--quiet", "-m", "alice"]);
        fixture.git_as(
            ALICE,
            "2",
            &clone_dir,
            &["push", "--quiet", "origin", "HEAD:refs/heads/private/wip"],
        );
        let pushed = fixture.sandbox.git(&clone_dir, &["rev-parse", "HEAD"]);
        assert_eq!(
            fixture.server_ref("team.git", "refs/heads/private/wip"),
            stdout_text(&pushed).trim()
        );
        fixture.git_as(ALICE, "0", &clone_dir, &["fetch", "--quiet", "origin"]);
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn member_of_every_overlapping_group_sees_everything() {
    with_fixture(|fixture| {
        let refs = fixture.ls_remote(BOB, "2", "team.git");
        for branch in TEAM_BRANCHES {
            assert!(
                refs.contains(&format!("\trefs/heads/{branch}\n")),
                "bob should see {branch}:\n{refs}"
            );
        }
        let dir = fixture.empty_clone("bob-fetch", "team.git");
        let secret = Fixture::commit(&fixture.team_commits, "private/secret");
        fixture.git_as(
            BOB,
            "2",
            &dir,
            &["fetch", "--quiet", "origin", "refs/heads/private/secret"],
        );
        let fetched = fixture.sandbox.git(&dir, &["rev-parse", "FETCH_HEAD"]);
        assert_eq!(stdout_text(&fetched).trim(), secret);
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn non_member_never_sees_hidden_refs_under_any_protocol() {
    with_fixture(|fixture| {
        for protocol in ["0", "1", "2"] {
            let refs = fixture.ls_remote(CAROL, protocol, "team.git");
            for visible in ["main", "secret/public", "contrib-base"] {
                assert!(
                    refs.contains(&format!("\trefs/heads/{visible}\n")),
                    "carol should see {visible} (protocol {protocol}):\n{refs}"
                );
            }
            for hidden in HIDDEN_FROM_CAROL {
                assert!(
                    !refs.contains(&format!("\trefs/heads/{hidden}\n")),
                    "carol must not see {hidden} (protocol {protocol}):\n{refs}"
                );
                let hidden_commit = Fixture::commit(&fixture.team_commits, hidden);
                assert!(
                    !refs.contains(&hidden_commit),
                    "carol must not see {hidden}'s commit (protocol {protocol}):\n{refs}"
                );
            }
        }
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn non_member_clones_and_fetches_visible_branches() {
    with_fixture(|fixture| {
        fixture.git_as(
            CAROL,
            "2",
            fixture.scratch.path(),
            &["clone", "--quiet", &fixture.url("team.git"), "carol-clone"],
        );
        let clone_dir = fixture.scratch.path().join("carol-clone");
        let head = fixture.sandbox.git(&clone_dir, &["rev-parse", "HEAD"]);
        assert_eq!(
            stdout_text(&head).trim(),
            Fixture::commit(&fixture.team_commits, "main")
        );
        let remote_branches = fixture.sandbox.git(&clone_dir, &["branch", "-r"]);
        let remote_branches = stdout_text(&remote_branches);
        assert!(remote_branches.contains("origin/secret/public"));
        for hidden in HIDDEN_FROM_CAROL {
            assert!(
                !remote_branches.contains(&format!("origin/{hidden}\n")),
                "carol's clone must not contain {hidden}:\n{remote_branches}"
            );
        }

        for protocol in ["0", "2"] {
            fixture.git_as(
                CAROL,
                protocol,
                &clone_dir,
                &["fetch", "--quiet", "origin", "refs/heads/secret/public"],
            );
            let fetched = fixture
                .sandbox
                .git(&clone_dir, &["rev-parse", "FETCH_HEAD"]);
            assert_eq!(
                stdout_text(&fetched).trim(),
                Fixture::commit(&fixture.team_commits, "secret/public")
            );
        }
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn non_member_cannot_fetch_hidden_commits_by_id() {
    with_fixture(|fixture| {
        for protocol in ["0", "2"] {
            let dir = fixture.empty_clone(&format!("carol-by-id-v{protocol}"), "team.git");
            for hidden in HIDDEN_FROM_CAROL {
                let hidden_commit = Fixture::commit(&fixture.team_commits, hidden);
                let output =
                    fixture.try_git_as(CAROL, protocol, &dir, &["fetch", "origin", &hidden_commit]);
                // The server advertises no SHA-in-want capability, so git
                // refuses the unadvertised object before sending it; a raw
                // `want` is refused server-side ("not our ref", covered by
                // the git_service unit tests).
                let stderr = String::from_utf8_lossy(&output.stderr);
                assert!(
                    !output.status.success()
                        && (stderr.contains("unadvertised object")
                            || stderr.contains("not our ref")),
                    "carol fetched {hidden} by ID under protocol {protocol}: {stderr}"
                );
                let has_object = fixture
                    .sandbox
                    .try_git(&dir, &["cat-file", "-e", &hidden_commit]);
                assert!(!has_object.status.success());
            }
        }
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn non_member_cannot_push_to_or_delete_hidden_refs() {
    with_fixture(|fixture| {
        fixture.git_as(
            CAROL,
            "0",
            fixture.scratch.path(),
            &["clone", "--quiet", &fixture.url("team.git"), "carol-push"],
        );
        let clone_dir = fixture.scratch.path().join("carol-push");
        if let Err(error) = std::fs::write(clone_dir.join("carol.txt"), "carol\n") {
            panic!("failed to write carol.txt: {error}");
        }
        fixture.sandbox.git(&clone_dir, &["add", "carol.txt"]);
        fixture
            .sandbox
            .git(&clone_dir, &["commit", "--quiet", "-m", "carol"]);

        for target in ["private/wip", "vault", "private/new"] {
            let refspec = format!("+HEAD:refs/heads/{target}");
            let output = fixture.try_git_as(CAROL, "0", &clone_dir, &["push", "origin", &refspec]);
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                !output.status.success() && stderr.contains("deny updating a hidden ref"),
                "carol pushed to hidden {target}: {stderr}"
            );
        }
        for target in ["private/wip", "vault"] {
            let output = fixture.try_git_as(
                CAROL,
                "0",
                &clone_dir,
                &[
                    "push",
                    "origin",
                    "--delete",
                    &format!("refs/heads/{target}"),
                ],
            );
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                !output.status.success() && stderr.contains("deny deleting a hidden ref"),
                "carol deleted hidden {target}: {stderr}"
            );
            assert_eq!(
                fixture.server_ref("team.git", &format!("refs/heads/{target}")),
                Fixture::commit(&fixture.team_commits, target),
                "{target} changed on the server"
            );
        }
        let created = fixture.sandbox.try_git(
            &fixture.root.path().join("team.git"),
            &["rev-parse", "--verify", "--quiet", "refs/heads/private/new"],
        );
        assert!(!created.status.success(), "carol created private/new");

        // Visible refs stay writable.
        fixture.git_as(
            CAROL,
            "0",
            &clone_dir,
            &["push", "--quiet", "origin", "HEAD:refs/heads/contrib"],
        );
        let pushed = fixture.sandbox.git(&clone_dir, &["rev-parse", "HEAD"]);
        assert_eq!(
            fixture.server_ref("team.git", "refs/heads/contrib"),
            stdout_text(&pushed).trim()
        );
    })
    .await;
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn symlinked_alias_enforces_the_target_repository_rules() {
    with_fixture(|fixture| {
        let wip_commit = Fixture::commit(&fixture.secret_commits, "private/wip");
        let carol_refs = fixture.ls_remote(CAROL, "2", "alias.git");
        assert!(carol_refs.contains("\trefs/heads/main\n"));
        assert!(!carol_refs.contains("private/wip"), "{carol_refs}");
        assert!(!carol_refs.contains(&wip_commit));

        let dir = fixture.empty_clone("carol-alias", "alias.git");
        let output = fixture.try_git_as(CAROL, "2", &dir, &["fetch", "origin", &wip_commit]);
        assert!(!output.status.success(), "carol fetched via alias.git");

        let alice_refs = fixture.ls_remote(ALICE, "2", "alias.git");
        assert!(alice_refs.contains("\trefs/heads/private/wip\n"));
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn hidden_symbolic_head_works_for_members_and_is_forbidden_for_others() {
    with_fixture(|fixture| {
        let private_main = Fixture::commit(&fixture.head_hidden_commits, "private/main");
        fixture.git_as(
            ALICE,
            "2",
            fixture.scratch.path(),
            &[
                "clone",
                "--quiet",
                &fixture.url("headhidden.git"),
                "alice-head",
            ],
        );
        let head = fixture.sandbox.git(
            &fixture.scratch.path().join("alice-head"),
            &["rev-parse", "HEAD"],
        );
        assert_eq!(stdout_text(&head).trim(), private_main);

        let output = fixture.try_git_as(
            CAROL,
            "2",
            fixture.scratch.path(),
            &["ls-remote", &fixture.url("headhidden.git")],
        );
        assert!(!output.status.success());
        assert!(!stdout_text(&output).contains(&private_main));
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("403"), "expected 403, got: {stderr}");
    })
    .await;
}

/// Sends `GET /<repo>/info/refs?service=git-upload-pack` as `token` directly
/// to a router and returns the status and body.
async fn advertisement(
    root: &Path,
    policy_store: Arc<dyn PolicyStore>,
    repo: &str,
    token: &str,
) -> (StatusCode, String) {
    advertisement_with_protocol(root, policy_store, repo, token, None).await
}

/// Like [`advertisement`], sending `Git-Protocol: <git_protocol>` if given.
async fn advertisement_with_protocol(
    root: &Path,
    policy_store: Arc<dyn PolicyStore>,
    repo: &str,
    token: &str,
    git_protocol: Option<&str>,
) -> (StatusCode, String) {
    let mut builder = Request::builder()
        .uri(format!("/{repo}/info/refs?service=git-upload-pack"))
        .header(header::AUTHORIZATION, bearer_header(token));
    if let Some(git_protocol) = git_protocol {
        builder = builder.header("git-protocol", git_protocol);
    }
    let request = match builder.body(Body::empty()) {
        Ok(request) => request,
        Err(error) => panic!("failed to build request: {error}"),
    };
    let router = scrim_server::router_with_policy_store(root.to_path_buf(), policy_store);
    let response = match router.oneshot(request).await {
        Ok(response) => response,
        Err(error) => panic!("router call failed: {error}"),
    };
    let status = response.status();
    let body = match response.into_body().collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(error) => panic!("failed to read body: {error}"),
    };
    (status, String::from_utf8_lossy(&body).into_owned())
}

#[tokio::test(flavor = "multi_thread")]
async fn hidden_symbolic_head_leaks_neither_commit_nor_branch_name() {
    let fixture = Fixture::start().await;
    let private_main = Fixture::commit(&fixture.head_hidden_commits, "private/main");
    let store: Arc<dyn PolicyStore> = Arc::new(build_store());

    let (status, body) = advertisement(
        fixture.root.path(),
        Arc::clone(&store),
        "headhidden.git",
        CAROL_TOKEN,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body, "forbidden");

    let (status, body) =
        advertisement(fixture.root.path(), store, "headhidden.git", ALICE_TOKEN).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("symref=HEAD:refs/heads/private/main"));
    assert!(body.contains(&private_main));
}

#[tokio::test(flavor = "multi_thread")]
async fn detached_head_is_hidden_when_any_ref_is_hidden() {
    with_fixture(|fixture| {
        let detached_commit = Fixture::commit(&fixture.detached_commits, "private/wip");
        for protocol in ["0", "2"] {
            let carol_refs = fixture.ls_remote(CAROL, protocol, "detached.git");
            assert!(carol_refs.contains("\trefs/heads/main\n"), "{carol_refs}");
            assert!(!carol_refs.contains("\tHEAD\n"), "{carol_refs}");
            assert!(!carol_refs.contains(&detached_commit), "{carol_refs}");

            let alice_refs = fixture.ls_remote(ALICE, protocol, "detached.git");
            assert!(
                alice_refs.contains(&format!("{detached_commit}\tHEAD\n")),
                "{alice_refs}"
            );
        }
    })
    .await;
}

/// Authenticates through an inner store but fails policy loads (or, with
/// `fail_authentication`, authentication too), as if the database dropped.
struct FailingPolicyStore {
    inner: MemoryPolicyStore,
    fail_authentication: bool,
}

impl PolicyStore for FailingPolicyStore {
    fn authenticate_token_hash<'a>(
        &'a self,
        token_hash: &'a [u8; 32],
    ) -> PolicyStoreFuture<'a, Option<AuthenticatedMember>> {
        if self.fail_authentication {
            return Box::pin(async {
                Err(PolicyStoreError::Internal("database offline".to_owned()))
            });
        }
        self.inner.authenticate_token_hash(token_hash)
    }

    fn load_member_repo_policy<'a>(
        &'a self,
        _member_id: i64,
        _repo_key: &'a str,
    ) -> PolicyStoreFuture<'a, MemberRepoPolicy> {
        Box::pin(async { Err(PolicyStoreError::Internal("database offline".to_owned())) })
    }

    fn record_audit_event<'a>(&'a self, _entry: AuditLogEntry) -> PolicyStoreFuture<'a, ()> {
        Box::pin(async { Err(PolicyStoreError::Internal("database offline".to_owned())) })
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn failing_policy_store_fails_closed() {
    let fixture = Fixture::start().await;
    for fail_authentication in [true, false] {
        let store = Arc::new(FailingPolicyStore {
            inner: build_store(),
            fail_authentication,
        });
        let (status, body) =
            advertisement(fixture.root.path(), store, "team.git", ALICE_TOKEN).await;
        assert_eq!(
            status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "fail_authentication = {fail_authentication}"
        );
        assert!(!body.contains("refs/heads"));
    }
}

/// Encodes `payload` as a single pkt-line.
fn pkt_line(payload: &str) -> String {
    format!("{:04x}{payload}", payload.len() + 4)
}

/// POSTs `request_body` to `/<repo>/git-upload-pack` as `token` directly to a
/// router and returns the response body, or `None` if the stream failed (how
/// git exiting with an error, or a rejected request, surfaces).
async fn upload_pack_rpc(
    root: &Path,
    policy_store: Arc<dyn PolicyStore>,
    repo: &str,
    token: &str,
    git_protocol: Option<&str>,
    request_body: String,
) -> Option<Vec<u8>> {
    let mut builder = Request::builder()
        .method("POST")
        .uri(format!("/{repo}/git-upload-pack"))
        .header(header::AUTHORIZATION, bearer_header(token))
        .header(
            header::CONTENT_TYPE,
            "application/x-git-upload-pack-request",
        );
    if let Some(git_protocol) = git_protocol {
        builder = builder.header("git-protocol", git_protocol);
    }
    let request = match builder.body(Body::from(request_body)) {
        Ok(request) => request,
        Err(error) => panic!("failed to build request: {error}"),
    };
    let router = scrim_server::router_with_policy_store(root.to_path_buf(), policy_store);
    let response = match router.oneshot(request).await {
        Ok(response) => response,
        Err(error) => panic!("router call failed: {error}"),
    };
    assert_eq!(response.status(), StatusCode::OK);
    match response.into_body().collect().await {
        Ok(collected) => Some(collected.to_bytes().to_vec()),
        Err(_) => None,
    }
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// Unlike the `git` client, which refuses to ask for unadvertised objects, a
/// hand-written request sends the `want` anyway: the RPC endpoint must apply
/// the same hidden refs as the advertisement and refuse it.
#[tokio::test(flavor = "multi_thread")]
async fn raw_want_for_hidden_commit_is_refused_by_the_rpc_endpoint() {
    let fixture = Fixture::start().await;
    let store: Arc<dyn PolicyStore> = Arc::new(build_store());
    let wip_commit = Fixture::commit(&fixture.team_commits, "private/wip");
    let v0_request = format!(
        "{}0000{}",
        pkt_line(&format!("want {wip_commit}\n")),
        pkt_line("done\n")
    );
    let v2_request = format!(
        "{}0001{}{}0000",
        pkt_line("command=fetch\n"),
        pkt_line(&format!("want {wip_commit}\n")),
        pkt_line("done\n")
    );

    // Control: alice may see `private/wip`, so the same request yields a pack.
    let allowed = upload_pack_rpc(
        fixture.root.path(),
        Arc::clone(&store),
        "team.git",
        ALICE_TOKEN,
        None,
        v0_request.clone(),
    )
    .await;
    assert!(matches!(allowed, Some(body) if contains_bytes(&body, b"PACK")));

    for (git_protocol, request_body) in [(None, v0_request), (Some("version=2"), v2_request)] {
        let refused = upload_pack_rpc(
            fixture.root.path(),
            Arc::clone(&store),
            "team.git",
            CAROL_TOKEN,
            git_protocol,
            request_body,
        )
        .await;
        if let Some(refused) = refused {
            assert!(
                !contains_bytes(&refused, b"PACK") && !contains_bytes(&refused, b"packfile"),
                "hidden commit was served to carol under {git_protocol:?}"
            );
        }
    }
}

/// `deepen-not <ref>` makes git resolve `<ref>` regardless of
/// `transfer.hideRefs`, so its outcome would reveal whether a hidden branch
/// exists. Restricted members get the same abort for hidden and missing refs.
#[tokio::test(flavor = "multi_thread")]
async fn deepen_not_is_refused_identically_for_hidden_and_missing_refs() {
    let fixture = Fixture::start().await;
    let store: Arc<dyn PolicyStore> = Arc::new(build_store());
    let deepen_not_request = |want: &str, deepen_not_ref: &str| {
        format!(
            "{}{}0000{}",
            pkt_line(&format!("want {want}\n")),
            pkt_line(&format!("deepen-not {deepen_not_ref}\n")),
            pkt_line("done\n")
        )
    };
    // Not an ancestor of `private/wip`, so without the filter `deepen-not
    // refs/heads/private/wip` would succeed while a missing ref fails.
    let visible_commit = Fixture::commit(&fixture.team_commits, "contrib-base");

    let mut carol_results = Vec::new();
    for deepen_not_ref in ["refs/heads/private/wip", "refs/heads/does-not-exist"] {
        let result = upload_pack_rpc(
            fixture.root.path(),
            Arc::clone(&store),
            "team.git",
            CAROL_TOKEN,
            None,
            deepen_not_request(&visible_commit, deepen_not_ref),
        )
        .await;
        assert!(
            result.is_none(),
            "carol's deepen-not {deepen_not_ref} was served"
        );
        carol_results.push(result);
    }
    assert_eq!(carol_results[0], carol_results[1]);

    // Bob sees every ref of team.git, so his requests are not filtered.
    let wip_commit = Fixture::commit(&fixture.team_commits, "private/wip");
    let bob_result = upload_pack_rpc(
        fixture.root.path(),
        store,
        "team.git",
        BOB_TOKEN,
        None,
        deepen_not_request(&wip_commit, "refs/heads/main"),
    )
    .await;
    assert!(
        matches!(&bob_result, Some(body) if contains_bytes(body, b"PACK")),
        "bob's deepen-not request failed: {bob_result:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn symref_to_hidden_branch_is_hidden_from_non_members() {
    with_fixture(|fixture| {
        let wip_commit = Fixture::commit(&fixture.symref_commits, "private/wip");
        for protocol in ["0", "1", "2"] {
            let carol_refs = fixture.ls_remote(CAROL, protocol, "symref.git");
            assert!(carol_refs.contains("\trefs/heads/main\n"), "{carol_refs}");
            assert!(!carol_refs.contains("refs/heads/alias"), "{carol_refs}");
            assert!(!carol_refs.contains(&wip_commit), "{carol_refs}");

            let alice_refs = fixture.ls_remote(ALICE, protocol, "symref.git");
            assert!(
                alice_refs.contains(&format!("{wip_commit}\trefs/heads/alias\n")),
                "{alice_refs}"
            );
        }
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn head_chained_to_hidden_branch_is_forbidden_for_non_members() {
    with_fixture(|fixture| {
        let wip_commit = Fixture::commit(&fixture.chained_commits, "private/wip");
        for protocol in ["0", "2"] {
            let output = fixture.try_git_as(
                CAROL,
                protocol,
                fixture.scratch.path(),
                &["ls-remote", &fixture.url("chained.git")],
            );
            assert!(!output.status.success());
            assert!(!stdout_text(&output).contains(&wip_commit));
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(stderr.contains("403"), "expected 403, got: {stderr}");
        }

        let clone_name = "alice-chained";
        fixture.git_as(
            ALICE,
            "2",
            fixture.scratch.path(),
            &["clone", "--quiet", &fixture.url("chained.git"), clone_name],
        );
        let head = fixture.sandbox.git(
            &fixture.scratch.path().join(clone_name),
            &["rev-parse", "HEAD"],
        );
        assert_eq!(stdout_text(&head).trim(), wip_commit);
    })
    .await;
}

/// A complex-glob rule matching no current ref still marks the member as
/// restricted: protocol v2 stays off and a detached `HEAD` stays hidden.
#[tokio::test(flavor = "multi_thread")]
async fn unsatisfied_rule_matching_no_ref_still_restricts() {
    let fixture = Fixture::start().await;
    let store: Arc<dyn PolicyStore> = Arc::new(build_store());
    let main_commit = Fixture::commit(&fixture.complex_commits, "main");

    let (status, body) = advertisement_with_protocol(
        fixture.root.path(),
        Arc::clone(&store),
        "complex.git",
        CAROL_TOKEN,
        Some("version=2"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(!body.contains("version 2"), "{body}");
    assert!(body.contains("# service=git-upload-pack"), "{body}");
    assert!(
        body.contains(&format!("{main_commit} refs/heads/main")),
        "{body}"
    );
    assert!(!body.contains(" HEAD"), "{body}");

    let (status, body) = advertisement_with_protocol(
        fixture.root.path(),
        store,
        "complex.git",
        ALICE_TOKEN,
        Some("version=2"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("version 2"), "{body}");
}

/// Repositories whose refs or objects may come from elsewhere are not served.
#[tokio::test(flavor = "multi_thread")]
async fn repos_with_reftable_or_alternates_are_not_found() {
    let root = match TempDir::new() {
        Ok(root) => root,
        Err(error) => panic!("failed to create root dir: {error}"),
    };
    let sandbox = GitSandbox::new();
    let store: Arc<dyn PolicyStore> = Arc::new(build_store());

    sandbox.init_bare_with_commit(&root.path().join("plain.git"));
    let (status, _) =
        advertisement(root.path(), Arc::clone(&store), "plain.git", ALICE_TOKEN).await;
    assert_eq!(status, StatusCode::OK);

    let plain_objects = root.path().join("plain.git").join("objects");
    let alternates_target = format!("{}\n", utf8_path(&plain_objects));
    let cases: [(&str, &str, &str); 4] = [
        ("reftable.git", "reftable/tables.list", ""),
        ("invalidhead.git", "HEAD", "ref: refs/heads/.invalid\n"),
        (
            "alternates.git",
            "objects/info/alternates",
            &alternates_target,
        ),
        (
            "httpalternates.git",
            "objects/info/http-alternates",
            "http://example.invalid/objects\n",
        ),
    ];
    for (repo, file, contents) in cases {
        let repo_dir = root.path().join(repo);
        sandbox.init_bare_with_commit(&repo_dir);
        let file_path = repo_dir.join(file);
        if let Some(parent) = file_path.parent()
            && let Err(error) = std::fs::create_dir_all(parent)
        {
            panic!("failed to create {}: {error}", parent.display());
        }
        if let Err(error) = std::fs::write(&file_path, contents) {
            panic!("failed to write {}: {error}", file_path.display());
        }
        let (status, body) =
            advertisement(root.path(), Arc::clone(&store), repo, ALICE_TOKEN).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{repo}: {body}");
    }

    // A real reftable repository, where the installed git supports one.
    let reftable_dir = root.path().join("real-reftable.git");
    if let Err(error) = std::fs::create_dir_all(&reftable_dir) {
        panic!("failed to create {}: {error}", reftable_dir.display());
    }
    let init = sandbox.try_git(&reftable_dir, &["init", "--bare", "--ref-format=reftable"]);
    if init.status.success() {
        let (status, _) = advertisement(root.path(), store, "real-reftable.git", ALICE_TOKEN).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }
}

/// Clones `team.git` as `member` into a new directory `name` of the scratch
/// directory and returns its path.
fn clone_team_as(fixture: &Fixture, member: Member, name: &str) -> std::path::PathBuf {
    fixture.git_as(
        member,
        "0",
        fixture.scratch.path(),
        &["clone", "--quiet", &fixture.url("team.git"), name],
    );
    fixture.scratch.path().join(name)
}

/// Writes `file_name` with `contents` in `dir` and commits it.
fn commit_file(fixture: &Fixture, dir: &Path, file_name: &str, contents: &str) {
    if let Err(error) = std::fs::write(dir.join(file_name), contents) {
        panic!("failed to write {file_name}: {error}");
    }
    fixture.sandbox.git(dir, &["add", file_name]);
    fixture
        .sandbox
        .git(dir, &["commit", "--quiet", "-m", file_name]);
}

/// Whether `ref_name` exists in the server-side bare `repo`.
fn server_ref_exists(fixture: &Fixture, repo: &str, ref_name: &str) -> bool {
    fixture
        .sandbox
        .try_git(
            &fixture.root.path().join(repo),
            &["rev-parse", "--verify", "--quiet", ref_name],
        )
        .status
        .success()
}

/// Runs `git push <args>` in `dir` as `member` and asserts that it failed,
/// returning git's stderr.
fn assert_push_rejected(fixture: &Fixture, member: Member, dir: &Path, args: &[&str]) -> String {
    let mut push_args = vec!["push"];
    push_args.extend_from_slice(args);
    let output = fixture.try_git_as(member, "0", dir, &push_args);
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        !output.status.success(),
        "push {args:?} as {} should fail: {stderr}",
        member.name
    );
    stderr
}

#[tokio::test(flavor = "multi_thread")]
async fn non_member_cannot_create_update_or_delete_glob_matched_refs() {
    with_fixture(|fixture| {
        let carol_dir = clone_team_as(fixture, CAROL, "carol-globs");
        commit_file(fixture, &carol_dir, "carol.txt", "carol\n");

        // `release-99` matches the complex glob `refs/heads/release-*` and
        // `team/secret` matches `refs/heads/*/secret`; neither exists yet, so
        // `transfer.hideRefs` cannot cover them and only the guard stops them.
        for target in ["release-99", "team/secret"] {
            let stderr = assert_push_rejected(
                fixture,
                CAROL,
                &carol_dir,
                &["origin", &format!("HEAD:refs/heads/{target}")],
            );
            assert!(
                stderr.contains(&format!(
                    "you do not have access to ref refs/heads/{target}"
                )),
                "{stderr}"
            );
            for group in ["core", "security"] {
                assert!(!stderr.contains(group), "group name leaked: {stderr}");
            }
            assert!(!server_ref_exists(
                fixture,
                "team.git",
                &format!("refs/heads/{target}")
            ));
        }
        // Prefix and exact rules (already hidden by `transfer.hideRefs`).
        for target in ["private/new", "secret"] {
            assert_push_rejected(
                fixture,
                CAROL,
                &carol_dir,
                &["origin", &format!("HEAD:refs/heads/{target}")],
            );
            assert!(!server_ref_exists(
                fixture,
                "team.git",
                &format!("refs/heads/{target}")
            ));
        }

        // Overlapping rules intersect: alice is in `core`, not `security`.
        let alice_dir = clone_team_as(fixture, ALICE, "alice-globs");
        commit_file(fixture, &alice_dir, "alice.txt", "alice\n");
        let stderr = assert_push_rejected(
            fixture,
            ALICE,
            &alice_dir,
            &["origin", "HEAD:refs/heads/team/secret"],
        );
        assert!(
            stderr.contains("you do not have access to ref refs/heads/team/secret"),
            "{stderr}"
        );

        // Bob may create both; carol may then neither update nor delete them.
        let bob_dir = clone_team_as(fixture, BOB, "bob-globs");
        let mut bob_commits = BTreeMap::new();
        for target in ["release-99", "team/secret"] {
            fixture.sandbox.git(
                &bob_dir,
                &["checkout", "--quiet", "-B", "work", "origin/main"],
            );
            commit_file(fixture, &bob_dir, &target.replace('/', "_"), target);
            fixture.git_as(
                BOB,
                "0",
                &bob_dir,
                &[
                    "push",
                    "--quiet",
                    "origin",
                    &format!("HEAD:refs/heads/{target}"),
                ],
            );
            bob_commits.insert(
                target,
                fixture.server_ref("team.git", &format!("refs/heads/{target}")),
            );
        }
        for (target, bob_commit) in &bob_commits {
            let ref_name = format!("refs/heads/{target}");
            assert_push_rejected(
                fixture,
                CAROL,
                &carol_dir,
                &["origin", &format!("+HEAD:{ref_name}")],
            );
            assert_push_rejected(
                fixture,
                CAROL,
                &carol_dir,
                &["origin", "--delete", &ref_name],
            );
            assert_eq!(&fixture.server_ref("team.git", &ref_name), bob_commit);
        }
    })
    .await;
}

/// The all-zero object ID used for ref creation.
const ZERO_OID: &str = "0000000000000000000000000000000000000000";

/// A version 2 pack with no objects, followed by its SHA-1 checksum.
const EMPTY_PACK: [u8; 32] = [
    b'P', b'A', b'C', b'K', 0, 0, 0, 2, 0, 0, 0, 0, 0x02, 0x9d, 0x08, 0x82, 0x3b, 0xd8, 0xa8, 0xea,
    0xb5, 0x10, 0xad, 0x6a, 0xc7, 0x5c, 0x82, 0x3c, 0xfd, 0x3e, 0xd3, 0x1e,
];

/// Builds a `git-receive-pack` request creating each `(new_oid, ref_name)`
/// with an empty pack, i.e. without sending a single object.
fn empty_pack_push_request(creations: &[(&str, &[u8])], push_options: &[&str]) -> Vec<u8> {
    let mut request = Vec::new();
    for (index, (new_oid, ref_name)) in creations.iter().enumerate() {
        let mut command = format!("{ZERO_OID} {new_oid} ").into_bytes();
        command.extend_from_slice(ref_name);
        if index == 0 {
            command.extend_from_slice(b"\0report-status");
            if !push_options.is_empty() {
                command.extend_from_slice(b" push-options");
            }
        }
        command.push(b'\n');
        request.extend_from_slice(&pkt_line_bytes(&command));
    }
    request.extend_from_slice(b"0000");
    if !push_options.is_empty() {
        for push_option in push_options {
            request.extend_from_slice(&pkt_line_bytes(push_option.as_bytes()));
        }
        request.extend_from_slice(b"0000");
    }
    request.extend_from_slice(&EMPTY_PACK);
    request
}

/// POSTs `request_body` to `/team.git/git-receive-pack` of `fixture`'s
/// repositories as `token` and returns git's status report, or `None` if the
/// response stream failed.
async fn receive_pack_rpc(
    fixture: &Fixture,
    store: Arc<dyn PolicyStore>,
    token: &str,
    request_body: Vec<u8>,
) -> Option<Vec<u8>> {
    let request = match Request::builder()
        .method("POST")
        .uri("/team.git/git-receive-pack")
        .header(header::AUTHORIZATION, bearer_header(token))
        .header(
            header::CONTENT_TYPE,
            "application/x-git-receive-pack-request",
        )
        .body(Body::from(request_body))
    {
        Ok(request) => request,
        Err(error) => panic!("failed to build request: {error}"),
    };
    let router = scrim_server::router_with_policy_store(fixture.root.path().to_path_buf(), store);
    let response = match router.oneshot(request).await {
        Ok(response) => response,
        Err(error) => panic!("router call failed: {error}"),
    };
    assert_eq!(response.status(), StatusCode::OK);
    match response.into_body().collect().await {
        Ok(collected) => Some(collected.to_bytes().to_vec()),
        Err(_) => None,
    }
}

/// Asserts that git's status report refused every update of a push because
/// the pre-receive hook declined it.
fn assert_hook_declined(report: Option<Vec<u8>>, description: &str) {
    let Some(report) = report else {
        panic!("{description}: receive-pack failed instead of declining");
    };
    assert!(
        contains_bytes(&report, b"pre-receive hook declined"),
        "{description}: {}",
        String::from_utf8_lossy(&report)
    );
}

/// `H1`: an empty pack naming a hidden object ID passes git's connectivity
/// check (the object exists on the server) and would publish it.
#[tokio::test(flavor = "multi_thread")]
async fn empty_pack_push_of_hidden_objects_is_rejected() {
    let fixture = Fixture::start().await;
    let store: Arc<dyn PolicyStore> = Arc::new(fixture.store.clone());
    let hidden_commit = Fixture::commit(&fixture.team_commits, "private/wip");
    let hidden_blob = stdout_text(&fixture.sandbox.git(
        &fixture.root.path().join("team.git"),
        &["rev-parse", "refs/heads/private/wip:private_wip.txt"],
    ))
    .trim()
    .to_owned();

    let cases: [(&str, &str, &[u8]); 2] = [
        ("hidden commit", &hidden_commit, b"refs/heads/steal"),
        ("hidden blob", &hidden_blob, b"refs/tags/steal-blob"),
    ];
    for (description, hidden_oid, ref_name) in cases {
        let report = receive_pack_rpc(
            &fixture,
            Arc::clone(&store),
            CAROL_TOKEN,
            empty_pack_push_request(&[(hidden_oid, ref_name)], &[]),
        )
        .await;
        assert_hook_declined(report, description);
        let ref_name = String::from_utf8_lossy(ref_name);
        assert!(
            !server_ref_exists(&fixture, "team.git", &ref_name),
            "{ref_name} was created"
        );
    }

    // Control: the same request naming a visible commit is accepted.
    let main_commit = Fixture::commit(&fixture.team_commits, "main");
    let report = receive_pack_rpc(
        &fixture,
        store,
        CAROL_TOKEN,
        empty_pack_push_request(&[(&main_commit, b"refs/heads/carol-copy")], &[]),
    )
    .await;
    let Some(report) = report else {
        panic!("visible empty-pack push failed");
    };
    assert!(
        contains_bytes(&report, b"ok refs/heads/carol-copy"),
        "{}",
        String::from_utf8_lossy(&report)
    );
    assert_eq!(
        fixture.server_ref("team.git", "refs/heads/carol-copy"),
        main_commit
    );
}

/// `L4`: git itself would accept a ref name with invalid UTF-8.
#[tokio::test(flavor = "multi_thread")]
async fn non_utf8_ref_name_push_is_rejected() {
    let fixture = Fixture::start().await;
    let store: Arc<dyn PolicyStore> = Arc::new(fixture.store.clone());
    let main_commit = Fixture::commit(&fixture.team_commits, "main");
    let report = receive_pack_rpc(
        &fixture,
        store,
        BOB_TOKEN,
        empty_pack_push_request(&[(&main_commit, b"refs/heads/caf\xff")], &[]),
    )
    .await;
    assert_hook_declined(report, "non-UTF-8 ref name");
    let refs = fixture
        .sandbox
        .git(&fixture.root.path().join("team.git"), &["for-each-ref"]);
    assert!(
        !contains_bytes(&refs.stdout, b"refs/heads/caf"),
        "{}",
        stdout_text(&refs)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn merge_leak_guard_rejects_private_merges_and_audits_overrides() {
    with_fixture(|fixture| {
        let dir = clone_team_as(fixture, ALICE, "alice-leak");
        let main_before = fixture.server_ref("team.git", "refs/heads/main");

        // A merge of `private/wip` into `main` is refused with advice.
        fixture.sandbox.git(
            &dir,
            &["checkout", "--quiet", "-b", "merged", "origin/main"],
        );
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
        let stderr =
            assert_push_rejected(fixture, ALICE, &dir, &["origin", "HEAD:refs/heads/main"]);
        assert!(stderr.contains("refs/heads/main"), "{stderr}");
        assert!(stderr.contains("squash"), "{stderr}");
        assert!(
            stderr.contains(&format!("-o {ALLOW_MERGE_LEAK_PUSH_OPTION}")),
            "{stderr}"
        );
        assert!(!stderr.contains("private/wip"), "{stderr}");
        // Neither the leaked commit nor how many there are is revealed.
        let wip_commit = Fixture::commit(&fixture.team_commits, "private/wip");
        assert!(!stderr.contains(&wip_commit[..7]), "{stderr}");
        assert!(!stderr.contains("commit(s)"), "{stderr}");
        assert_eq!(
            fixture.server_ref("team.git", "refs/heads/main"),
            main_before
        );

        // So is fast-forwarding a new public branch to it.
        assert_push_rejected(
            fixture,
            ALICE,
            &dir,
            &[
                "origin",
                "refs/remotes/origin/private/wip:refs/heads/public-copy",
            ],
        );
        assert!(!server_ref_exists(
            fixture,
            "team.git",
            "refs/heads/public-copy"
        ));

        // A squash merge creates new commits and is accepted.
        fixture.sandbox.git(
            &dir,
            &["checkout", "--quiet", "-b", "squashed", "origin/main"],
        );
        fixture.sandbox.git(
            &dir,
            &["merge", "--quiet", "--squash", "origin/private/wip"],
        );
        fixture
            .sandbox
            .git(&dir, &["commit", "--quiet", "-m", "squashed wip"]);
        fixture.git_as(
            ALICE,
            "0",
            &dir,
            &["push", "--quiet", "origin", "HEAD:refs/heads/main"],
        );
        assert!(fixture.store.audit_entries().is_empty());

        // The override lands a real merge and is audited.
        fixture.sandbox.git(
            &dir,
            &["checkout", "--quiet", "-b", "override", "origin/main"],
        );
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
        fixture.git_as(
            ALICE,
            "0",
            &dir,
            &[
                "push",
                "--quiet",
                "-o",
                ALLOW_MERGE_LEAK_PUSH_OPTION,
                "origin",
                "HEAD:refs/heads/main",
            ],
        );
        let pushed = stdout_text(&fixture.sandbox.git(&dir, &["rev-parse", "HEAD"]))
            .trim()
            .to_owned();
        assert_eq!(fixture.server_ref("team.git", "refs/heads/main"), pushed);
        let audit_entries = fixture.store.audit_entries();
        assert_eq!(audit_entries.len(), 1, "{audit_entries:?}");
        let entry = &audit_entries[0];
        assert_eq!(entry.actor_member_id, Some(1));
        assert_eq!(entry.action, "branch.merge_leak_override");
        assert_eq!(entry.target_type, "repository_ref");
        assert_eq!(entry.target_name, "team.git:refs/heads/main");
        assert_eq!(entry.details["leaked_commit_count"], 1);
        assert_eq!(entry.details["new_oid"], pushed.as_str());
        assert_eq!(
            entry.details["sample_leaked_commits"][0],
            Fixture::commit(&fixture.team_commits, "private/wip").as_str()
        );

        // Merging the wider `main` into the narrower `private/wip` never leaks.
        fixture.sandbox.git(
            &dir,
            &[
                "checkout",
                "--quiet",
                "-b",
                "narrowing",
                "origin/private/wip",
            ],
        );
        fixture.sandbox.git(
            &dir,
            &["merge", "--quiet", "--no-ff", "--no-edit", "origin/main"],
        );
        fixture.git_as(
            ALICE,
            "0",
            &dir,
            &["push", "--quiet", "origin", "HEAD:refs/heads/private/wip"],
        );
        assert_eq!(fixture.store.audit_entries().len(), 1);
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn one_push_cannot_carry_a_new_private_commit_into_main() {
    with_fixture(|fixture| {
        let dir = clone_team_as(fixture, ALICE, "alice-atomic");
        let main_before = fixture.server_ref("team.git", "refs/heads/main");
        let wip_before = fixture.server_ref("team.git", "refs/heads/private/wip");

        fixture.sandbox.git(
            &dir,
            &["checkout", "--quiet", "-b", "wip", "origin/private/wip"],
        );
        commit_file(fixture, &dir, "new-private.txt", "private\n");
        fixture.sandbox.git(
            &dir,
            &["checkout", "--quiet", "-b", "merged", "origin/main"],
        );
        fixture
            .sandbox
            .git(&dir, &["merge", "--quiet", "--no-ff", "--no-edit", "wip"]);

        assert_push_rejected(
            fixture,
            ALICE,
            &dir,
            &[
                "origin",
                "wip:refs/heads/private/wip",
                "merged:refs/heads/main",
            ],
        );
        assert_eq!(
            fixture.server_ref("team.git", "refs/heads/main"),
            main_before
        );
        assert_eq!(
            fixture.server_ref("team.git", "refs/heads/private/wip"),
            wip_before
        );
        assert!(fixture.store.audit_entries().is_empty());
    })
    .await;
}

/// The override only relaxes the merge-leak check, never ref authorization
/// or the hidden-object check.
#[tokio::test(flavor = "multi_thread")]
async fn merge_leak_override_does_not_bypass_access_checks() {
    let fixture = Fixture::start().await;
    let store: Arc<dyn PolicyStore> = Arc::new(fixture.store.clone());
    let hidden_commit = Fixture::commit(&fixture.team_commits, "private/wip");
    let report = receive_pack_rpc(
        &fixture,
        store,
        CAROL_TOKEN,
        empty_pack_push_request(
            &[(&hidden_commit, b"refs/heads/steal")],
            &[ALLOW_MERGE_LEAK_PUSH_OPTION],
        ),
    )
    .await;
    assert_hook_declined(report, "hidden commit with override");
    assert!(!server_ref_exists(&fixture, "team.git", "refs/heads/steal"));

    run_scenario(fixture, |fixture| {
        let dir = clone_team_as(fixture, CAROL, "carol-override");
        commit_file(fixture, &dir, "carol.txt", "carol\n");
        for target in ["private/new", "release-99"] {
            assert_push_rejected(
                fixture,
                CAROL,
                &dir,
                &[
                    "-o",
                    ALLOW_MERGE_LEAK_PUSH_OPTION,
                    "origin",
                    &format!("HEAD:refs/heads/{target}"),
                ],
            );
            assert!(!server_ref_exists(
                fixture,
                "team.git",
                &format!("refs/heads/{target}")
            ));
        }
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
async fn merge_leak_override_is_refused_when_it_cannot_be_audited() {
    let fixture = Fixture::start_with_store(|store| -> Arc<dyn PolicyStore> {
        Arc::new(AuditFailingPolicyStore { inner: store })
    })
    .await;
    run_scenario(fixture, |fixture| {
        let dir = clone_team_as(fixture, ALICE, "alice-unaudited");
        let main_before = fixture.server_ref("team.git", "refs/heads/main");
        fixture.sandbox.git(
            &dir,
            &["checkout", "--quiet", "-b", "merged", "origin/main"],
        );
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
        assert_push_rejected(
            fixture,
            ALICE,
            &dir,
            &[
                "-o",
                ALLOW_MERGE_LEAK_PUSH_OPTION,
                "origin",
                "HEAD:refs/heads/main",
            ],
        );
        assert_eq!(
            fixture.server_ref("team.git", "refs/heads/main"),
            main_before
        );
    })
    .await;
}

/// Finding #1: a thin pack whose `REF_DELTA` names a hidden blob as its base
/// makes `index-pack --fix-thin` copy that blob from the repository into the
/// quarantined pack, so the blob looks "sent". A tree in the same pack
/// pointing at it must not publish it on `main`.
#[tokio::test(flavor = "multi_thread")]
async fn thin_pack_delta_base_cannot_smuggle_a_hidden_blob() {
    let fixture = Fixture::start().await;
    let store: Arc<dyn PolicyStore> = Arc::new(fixture.store.clone());
    let team_dir = fixture.root.path().join("team.git");
    let hidden_blob = stdout_text(&fixture.sandbox.git(
        &team_dir,
        &["rev-parse", "refs/heads/private/wip:private_wip.txt"],
    ))
    .trim()
    .to_owned();
    // An attacker can learn the size through the delta error oracle
    // documented in pre_receive.rs; the test simply reads it.
    let hidden_size_text = stdout_text(
        &fixture
            .sandbox
            .git(&team_dir, &["cat-file", "-s", &hidden_blob]),
    );
    let Ok(hidden_size) = hidden_size_text.trim().parse::<usize>() else {
        panic!("unexpected blob size {hidden_size_text:?}");
    };
    let main_before = Fixture::commit(&fixture.team_commits, "main");

    let mut tree = b"100644 leak.txt\0".to_vec();
    tree.extend_from_slice(&raw_object_id(&hidden_blob));
    let tree_id = object_id("tree", &tree);
    let commit = format!(
        "tree {tree_id}\nparent {main_before}\n\
         author Carol <carol@example.com> 1700000000 +0000\n\
         committer Carol <carol@example.com> 1700000000 +0000\n\nsmuggle\n"
    )
    .into_bytes();
    let commit_id = object_id("commit", &commit);
    // A delta valid for any base of the hidden blob's size: one literal
    // insert of `result`, no copies.
    let result = b"smuggled\n";
    let mut delta = delta_size(hidden_size);
    delta.extend_from_slice(&delta_size(result.len()));
    delta.push(result.len() as u8);
    delta.extend_from_slice(result);
    let pack = build_pack(&[
        PackEntry::Whole(1, commit),
        PackEntry::Whole(2, tree),
        PackEntry::RefDelta(hidden_blob.clone(), delta),
    ]);

    let report = receive_pack_rpc(
        &fixture,
        store,
        CAROL_TOKEN,
        pack_push_request(&main_before, &commit_id, "refs/heads/main", &pack),
    )
    .await;
    assert_hook_declined(report, "thin pack with a hidden delta base");
    assert_eq!(
        fixture.server_ref("team.git", "refs/heads/main"),
        main_before
    );
}

/// Re-adding a deleted file with the same bytes reuses a blob that is in the
/// repository and reachable from `main`'s history (though not from its tip):
/// the thin-pack defense must still accept it.
#[tokio::test(flavor = "multi_thread")]
async fn non_member_can_restore_content_from_visible_history() {
    with_fixture(|fixture| {
        let dir = clone_team_as(fixture, CAROL, "carol-revert");
        commit_file(fixture, &dir, "old.txt", "old visible content\n");
        fixture.sandbox.git(&dir, &["rm", "--quiet", "old.txt"]);
        fixture
            .sandbox
            .git(&dir, &["commit", "--quiet", "-m", "remove old.txt"]);
        fixture.git_as(
            CAROL,
            "0",
            &dir,
            &["push", "--quiet", "origin", "HEAD:refs/heads/main"],
        );

        commit_file(fixture, &dir, "old.txt", "old visible content\n");
        fixture.git_as(
            CAROL,
            "0",
            &dir,
            &["push", "--quiet", "origin", "HEAD:refs/heads/main"],
        );
        let pushed = fixture.sandbox.git(&dir, &["rev-parse", "HEAD"]);
        assert_eq!(
            fixture.server_ref("team.git", "refs/heads/main"),
            stdout_text(&pushed).trim()
        );
    })
    .await;
}

/// Finding #4: on a case-insensitive file system `refs/heads/VAULT` is the
/// loose ref file of `refs/heads/vault`, so a write to it must be judged by
/// the rules of `refs/heads/vault`. Refs are packed first, as `git gc` would,
/// so no loose file blocks the create and a missing check would overwrite the
/// hidden ref there.
#[tokio::test(flavor = "multi_thread")]
async fn non_member_cannot_write_hidden_refs_through_case_variants() {
    with_fixture(|fixture| {
        fixture.sandbox.git(
            &fixture.root.path().join("team.git"),
            &["pack-refs", "--all"],
        );
        let dir = clone_team_as(fixture, CAROL, "carol-case");
        commit_file(fixture, &dir, "carol.txt", "carol\n");

        for target in ["refs/heads/Private/wip", "refs/heads/VAULT"] {
            let stderr = assert_push_rejected(
                fixture,
                CAROL,
                &dir,
                &["origin", &format!("+HEAD:{target}")],
            );
            assert!(
                stderr.contains(&format!("you do not have access to ref {target}")),
                "{stderr}"
            );
        }
        // A case variant of a visible ref is refused without echoing the
        // existing spelling.
        let stderr =
            assert_push_rejected(fixture, CAROL, &dir, &["origin", "+HEAD:refs/heads/Main"]);
        assert!(
            stderr.contains("ref name conflicts with an existing ref"),
            "{stderr}"
        );

        for hidden in ["private/wip", "vault"] {
            assert_eq!(
                fixture.server_ref("team.git", &format!("refs/heads/{hidden}")),
                Fixture::commit(&fixture.team_commits, hidden),
                "{hidden} changed on the server"
            );
        }
        assert_eq!(
            fixture.server_ref("team.git", "refs/heads/main"),
            Fixture::commit(&fixture.team_commits, "main")
        );
    })
    .await;
}
