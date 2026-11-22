//! Server-side path withholding end to end: real `git` clients fetch and push
//! through the server, whose `team.git` withholds `config/billing/**` from
//! everyone outside the `billing` group.
//!
//! `alice` is in `billing`; `carol` is in no group. `team.git` starts with
//! `base` (only `public/readme.txt`) and then `main`, which adds
//! `config/billing/secret.txt`.

#![allow(clippy::question_mark)]

mod common;

use std::{
    collections::{BTreeMap, HashSet},
    ffi::OsString,
    io::{BufReader, Cursor, Write},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::{Arc, Mutex, OnceLock},
};

use axum::{
    body::Body,
    extract::State,
    http::{Method, Request, StatusCode, header},
    middleware::{self, Next},
    response::Response,
};
use common::{
    GitSandbox, PackEntry, bearer_header, build_pack, delta_size, object_id, pkt_line_bytes,
    raw_object_id, spawn_server_with_store,
};
use http_body_util::BodyExt;
use scrim_cli::{CliEnv, run_from};
use scrim_crypto::ENCRYPTED_FILE_MAGIC;
use scrim_policy::WithholdRule;
use scrim_server::{AuthenticatedMember, MemoryPolicyStore, PolicyStore};
use secrecy::ExposeSecret;
use tempfile::TempDir;
use tower::ServiceExt;

const ALICE_TOKEN: &str = "alice-token-0123456789abcdef";
const CAROL_TOKEN: &str = "carol-token-0123456789abcdef";

/// The partial-clone filter `scrim clone` uses.
const PARTIAL_CLONE_FILTER: &str = "--filter=blob:limit=2g";

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
const CAROL: Member = Member {
    name: "carol",
    token: CAROL_TOKEN,
};

struct Fixture {
    sandbox: GitSandbox,
    root: TempDir,
    scratch: TempDir,
    base_url: String,
    base_commit: String,
    secret_blob: String,
    store: MemoryPolicyStore,
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

impl Fixture {
    async fn start() -> Self {
        let sandbox = GitSandbox::new();
        let root = match TempDir::new() {
            Ok(root) => root,
            Err(error) => panic!("failed to create repo root: {error}"),
        };
        let scratch = match TempDir::new() {
            Ok(scratch) => scratch,
            Err(error) => panic!("failed to create scratch dir: {error}"),
        };
        let bare = root.path().join("team.git");
        sandbox.init_bare(&bare);
        let seed = scratch.path().join("seed");
        if let Err(error) = std::fs::create_dir_all(&seed) {
            panic!("failed to create seed dir: {error}");
        }
        sandbox.git(&seed, &["init", "--quiet", "--initial-branch=main"]);
        write_file(&seed, "public/readme.txt", "hello\n");
        sandbox.git(&seed, &["add", "--all"]);
        sandbox.git(&seed, &["commit", "--quiet", "-m", "base"]);
        let base_commit = stdout_text(&sandbox.git(&seed, &["rev-parse", "HEAD"]));
        write_file(
            &seed,
            "config/billing/secret.txt",
            "billing-api-key: do-not-share-0123456789\n",
        );
        sandbox.git(&seed, &["add", "--all"]);
        sandbox.git(&seed, &["commit", "--quiet", "-m", "billing"]);
        let secret_blob =
            stdout_text(&sandbox.git(&seed, &["rev-parse", "HEAD:config/billing/secret.txt"]));
        sandbox.git(&seed, &["push", "--quiet", utf8_path(&bare), "main"]);

        let mut store = MemoryPolicyStore::new();
        store.insert_member(
            AuthenticatedMember {
                id: 1,
                name: ALICE.name.to_owned(),
                is_admin: false,
            },
            ALICE_TOKEN.as_bytes(),
        );
        store.insert_member(
            AuthenticatedMember {
                id: 3,
                name: CAROL.name.to_owned(),
                is_admin: false,
            },
            CAROL_TOKEN.as_bytes(),
        );
        store.insert_group_membership(1, "billing");
        match WithholdRule::new("config/billing/**", ["billing".to_owned()]) {
            Ok(rule) => store.insert_path_rule("team.git", rule),
            Err(error) => panic!("rule should be valid: {error}"),
        }
        let base_url =
            spawn_server_with_store(root.path().to_path_buf(), Arc::new(store.clone())).await;
        Self {
            sandbox,
            root,
            scratch,
            base_url,
            base_commit,
            secret_blob,
            store,
        }
    }

    fn url(&self) -> String {
        format!("{}/team.git", self.base_url)
    }

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

    /// Clones `team.git` over HTTP as `member` with extra clone `options`.
    fn clone_as(&self, member: Member, name: &str, options: &[&str]) -> PathBuf {
        let url = self.url();
        let mut args = vec!["clone", "--quiet"];
        args.extend_from_slice(options);
        args.push(&url);
        args.push(name);
        self.git_as(member, self.scratch.path(), &args);
        self.scratch.path().join(name)
    }

    /// A full local copy of the server repository (made without the
    /// server), with the server as remote `scrim`, so a test can craft
    /// pushes that reference objects a restricted member never received.
    fn local_copy(&self, name: &str) -> PathBuf {
        let bare = self.root.path().join("team.git");
        self.sandbox.git(
            self.scratch.path(),
            &["clone", "--quiet", utf8_path(&bare), name],
        );
        let dir = self.scratch.path().join(name);
        self.sandbox
            .git(&dir, &["remote", "add", "scrim", &self.url()]);
        dir
    }

    /// Whether `object` is missing from the local repository `dir`, checked
    /// without lazy fetching.
    fn is_missing_locally(&self, dir: &Path, object: &str) -> bool {
        let output = self
            .sandbox
            .git(dir, &["rev-list", "--objects", "--missing=print", "--all"]);
        stdout_text(&output)
            .lines()
            .any(|line| line == format!("?{object}"))
    }

    fn server_main(&self) -> String {
        stdout_text(
            &self
                .sandbox
                .git(&self.root.path().join("team.git"), &["rev-parse", "main"]),
        )
    }
}

/// Asserts that `output` is a failed push whose stderr contains `reason`.
fn assert_rejected(output: &Output, reason: &str) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "push should be rejected");
    assert!(stderr.contains(reason), "expected {reason:?} in: {stderr}");
}

/// Runs `scenario` on a blocking thread so the synchronous `git` processes
/// never stall the server's runtime.
async fn with_fixture(scenario: fn(&Fixture)) {
    let fixture = Fixture::start().await;
    let join_result = tokio::task::spawn_blocking(move || scenario(&fixture)).await;
    if let Err(error) = join_result {
        panic!("scenario failed: {error}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn allowed_member_clones_everything() {
    with_fixture(|fixture| {
        let clone = fixture.clone_as(ALICE, "alice", &[]);
        let contents = match std::fs::read_to_string(clone.join("config/billing/secret.txt")) {
            Ok(contents) => contents,
            Err(error) => panic!("alice should have the billing file: {error}"),
        };
        assert!(contents.contains("billing-api-key"));
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn restricted_member_gets_a_partial_clone_without_withheld_blobs() {
    with_fixture(|fixture| {
        // A plain clone cannot complete without the withheld blob, and says
        // how to clone instead.
        let plain = fixture.try_git_as(
            CAROL,
            fixture.scratch.path(),
            &["clone", "--quiet", &fixture.url(), "carol-plain"],
        );
        assert!(!plain.status.success(), "a plain clone should fail");
        assert!(
            String::from_utf8_lossy(&plain.stderr).contains("scrim clone"),
            "stderr: {}",
            String::from_utf8_lossy(&plain.stderr)
        );

        let clone = fixture.clone_as(CAROL, "carol", &[PARTIAL_CLONE_FILTER, "--no-checkout"]);
        assert!(fixture.is_missing_locally(&clone, &fixture.secret_blob));
        // History and trees are complete.
        fixture
            .sandbox
            .git(&clone, &["cat-file", "-e", &fixture.base_commit]);
        fixture
            .sandbox
            .git(&clone, &["cat-file", "-e", "origin/main:config/billing"]);
        fixture.sandbox.git(
            &clone,
            &[
                "sparse-checkout",
                "set",
                "--no-cone",
                "/*",
                "!/config/billing/",
            ],
        );
        fixture
            .sandbox
            .git(&clone, &["checkout", "--quiet", "main"]);
        assert!(clone.join("public/readme.txt").is_file());
        assert!(!clone.join("config/billing/secret.txt").exists());

        // The withheld blob cannot be fetched by its ID either.
        let by_id = fixture.try_git_as(
            CAROL,
            &clone,
            &["fetch", "--quiet", "origin", &fixture.secret_blob],
        );
        assert!(!by_id.status.success());
        assert!(fixture.is_missing_locally(&clone, &fixture.secret_blob));

        // Other filters (which could probe blob IDs) are refused.
        let sparse_oid = format!("--filter=sparse:oid={}", fixture.secret_blob);
        let probe = fixture.try_git_as(
            CAROL,
            fixture.scratch.path(),
            &[
                "clone",
                "--quiet",
                "--no-checkout",
                &sparse_oid,
                &fixture.url(),
                "probe",
            ],
        );
        assert!(!probe.status.success());
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn blob_moved_to_a_visible_path_reaches_the_restricted_member() {
    with_fixture(|fixture| {
        let carol = fixture.clone_as(CAROL, "carol", &[PARTIAL_CLONE_FILTER, "--no-checkout"]);
        assert!(fixture.is_missing_locally(&carol, &fixture.secret_blob));

        let alice = fixture.clone_as(ALICE, "alice", &[]);
        fixture.sandbox.git(
            &alice,
            &["mv", "config/billing/secret.txt", "public/secret.txt"],
        );
        fixture
            .sandbox
            .git(&alice, &["commit", "--quiet", "-m", "publish"]);
        fixture.git_as(ALICE, &alice, &["push", "--quiet", "origin", "main"]);

        fixture.git_as(CAROL, &carol, &["fetch", "--quiet", "origin"]);
        assert!(!fixture.is_missing_locally(&carol, &fixture.secret_blob));
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn restricted_member_cannot_modify_withheld_paths() {
    with_fixture(|fixture| {
        let carol = fixture.local_copy("carol");
        let before = fixture.server_main();

        write_file(&carol, "config/billing/secret.txt", "overwritten\n");
        fixture
            .sandbox
            .git(&carol, &["commit", "--quiet", "-am", "edit"]);
        let edit = fixture.try_git_as(CAROL, &carol, &["push", "scrim", "HEAD:main"]);
        assert!(!edit.status.success());
        assert!(
            String::from_utf8_lossy(&edit.stderr)
                .contains("do not have access to modify withheld path config/billing/secret.txt"),
            "stderr: {}",
            String::from_utf8_lossy(&edit.stderr)
        );

        // A case variant of the withheld path is refused too.
        fixture
            .sandbox
            .git(&carol, &["reset", "--quiet", "--hard", "origin/main"]);
        // Staged through the index: a case-insensitive file system would
        // fold the path into the existing `config/` directory.
        write_file(&carol, "new.txt", "x\n");
        let blob = stdout_text(
            &fixture
                .sandbox
                .git(&carol, &["hash-object", "-w", "new.txt"]),
        );
        let cacheinfo = format!("100644,{blob},CONFIG/billing/new.txt");
        fixture.sandbox.git(
            &carol,
            &["update-index", "--add", "--cacheinfo", &cacheinfo],
        );
        fixture
            .sandbox
            .git(&carol, &["commit", "--quiet", "-m", "case"]);
        if let Err(error) = std::fs::remove_file(carol.join("new.txt")) {
            panic!("failed to remove new.txt: {error}");
        }
        let case = fixture.try_git_as(CAROL, &carol, &["push", "scrim", "HEAD:main"]);
        assert_rejected(&case, "withheld path CONFIG/billing/new.txt");

        // Deleting it is a modification as well.
        fixture
            .sandbox
            .git(&carol, &["reset", "--quiet", "--hard", "origin/main"]);
        fixture
            .sandbox
            .git(&carol, &["rm", "--quiet", "config/billing/secret.txt"]);
        fixture
            .sandbox
            .git(&carol, &["commit", "--quiet", "-m", "rm"]);
        let delete = fixture.try_git_as(CAROL, &carol, &["push", "scrim", "HEAD:main"]);
        assert_rejected(&delete, "withheld path config/billing/secret.txt");

        // Changes elsewhere are fine.
        fixture
            .sandbox
            .git(&carol, &["reset", "--quiet", "--hard", "origin/main"]);
        write_file(&carol, "public/notes.txt", "notes\n");
        fixture.sandbox.git(&carol, &["add", "--all"]);
        fixture
            .sandbox
            .git(&carol, &["commit", "--quiet", "-m", "notes"]);
        fixture.git_as(CAROL, &carol, &["push", "--quiet", "scrim", "HEAD:main"]);
        assert_ne!(fixture.server_main(), before);
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn restricted_member_cannot_republish_a_withheld_blob() {
    with_fixture(|fixture| {
        let carol = fixture.local_copy("carol");
        let before = fixture.server_main();

        // Copy the withheld blob to a visible path by its ID.
        let cacheinfo = format!("100644,{},public/stolen.txt", fixture.secret_blob);
        fixture.sandbox.git(
            &carol,
            &["update-index", "--add", "--cacheinfo", &cacheinfo],
        );
        fixture
            .sandbox
            .git(&carol, &["commit", "--quiet", "-m", "copy"]);
        let copy = fixture.try_git_as(CAROL, &carol, &["push", "scrim", "HEAD:main"]);
        assert!(!copy.status.success());
        assert!(
            String::from_utf8_lossy(&copy.stderr).contains("withheld from you"),
            "stderr: {}",
            String::from_utf8_lossy(&copy.stderr)
        );

        // Copying the whole withheld directory's tree is the same.
        fixture
            .sandbox
            .git(&carol, &["reset", "--quiet", "--hard", "origin/main"]);
        fixture.sandbox.git(
            &carol,
            &[
                "read-tree",
                "--prefix=public/copy/",
                "origin/main:config/billing",
            ],
        );
        fixture
            .sandbox
            .git(&carol, &["commit", "--quiet", "-m", "tree"]);
        let tree = fixture.try_git_as(CAROL, &carol, &["push", "scrim", "HEAD:main"]);
        assert_rejected(&tree, "withheld from you");

        // Pointing a ref straight at it is refused.
        let blob_ref = format!("{}:refs/tags/stolen", fixture.secret_blob);
        let direct = fixture.try_git_as(CAROL, &carol, &["push", "scrim", &blob_ref]);
        assert_rejected(&direct, "withheld from you");

        assert_eq!(fixture.server_main(), before);
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn merges_may_only_take_withheld_paths_cleanly() {
    with_fixture(|fixture| {
        let carol = fixture.local_copy("carol");
        let base = fixture.base_commit.clone();

        // A side branch from before the billing file existed.
        fixture
            .sandbox
            .git(&carol, &["checkout", "--quiet", "-b", "side", &base]);
        write_file(&carol, "public/side.txt", "side\n");
        fixture.sandbox.git(&carol, &["add", "--all"]);
        fixture
            .sandbox
            .git(&carol, &["commit", "--quiet", "-m", "side"]);

        // `-s ours` keeps the side's tree and so drops the billing file.
        fixture.sandbox.git(
            &carol,
            &[
                "merge",
                "--quiet",
                "-s",
                "ours",
                "-m",
                "ours",
                "origin/main",
            ],
        );
        let ours = fixture.try_git_as(CAROL, &carol, &["push", "scrim", "HEAD:main"]);
        assert!(!ours.status.success());
        assert!(
            String::from_utf8_lossy(&ours.stderr).contains("withheld path"),
            "stderr: {}",
            String::from_utf8_lossy(&ours.stderr)
        );

        // A normal merge takes the billing file unchanged and is accepted.
        fixture
            .sandbox
            .git(&carol, &["reset", "--quiet", "--hard", "HEAD^"]);
        fixture.sandbox.git(
            &carol,
            &[
                "merge",
                "--quiet",
                "--no-edit",
                "-m",
                "merge",
                "origin/main",
            ],
        );
        fixture.git_as(CAROL, &carol, &["push", "--quiet", "scrim", "HEAD:main"]);
    })
    .await;
}

/// A thin pack whose `REF_DELTA` names the withheld blob as its base makes
/// `index-pack --fix-thin` copy that blob into the quarantine; a new blob
/// built from it at a visible path must not be published.
#[tokio::test(flavor = "multi_thread")]
async fn thin_pack_delta_base_cannot_smuggle_a_withheld_blob() {
    let fixture = Fixture::start().await;
    let team_dir = fixture.root.path().join("team.git");
    let main_before = fixture.server_main();
    let secret_content = b"billing-api-key: do-not-share-0123456789\n";
    let secret_size = secret_content.len();
    let readme_blob = stdout_text(
        &fixture
            .sandbox
            .git(&team_dir, &["rev-parse", "main:public/readme.txt"]),
    );
    let billing_tree = stdout_text(
        &fixture
            .sandbox
            .git(&team_dir, &["rev-parse", "main:config/billing"]),
    );

    // The new blob copies the whole base and appends a line, so it holds the
    // withheld content under a new ID.
    let appended = b"leaked\n";
    let mut delta = delta_size(secret_size);
    delta.extend_from_slice(&delta_size(secret_size + appended.len()));
    // Copy `secret_size` bytes from offset 0, then insert `appended`.
    let Ok(copy_size) = u8::try_from(secret_size) else {
        panic!("secret too large for a one-byte copy size");
    };
    delta.extend_from_slice(&[0x90, copy_size]);
    delta.push(appended.len() as u8);
    delta.extend_from_slice(appended);
    let mut leaked_content = secret_content.to_vec();
    leaked_content.extend_from_slice(appended);
    let leaked_blob = object_id("blob", &leaked_content);

    let mut public_tree = b"100644 leak.txt\0".to_vec();
    public_tree.extend_from_slice(&raw_object_id(&leaked_blob));
    public_tree.extend_from_slice(b"100644 readme.txt\0");
    public_tree.extend_from_slice(&raw_object_id(&readme_blob));
    let public_tree_id = object_id("tree", &public_tree);
    let mut config_tree = b"40000 billing\0".to_vec();
    config_tree.extend_from_slice(&raw_object_id(&billing_tree));
    let config_tree_id = object_id("tree", &config_tree);
    let mut root_tree = b"40000 config\0".to_vec();
    root_tree.extend_from_slice(&raw_object_id(&config_tree_id));
    root_tree.extend_from_slice(b"40000 public\0");
    root_tree.extend_from_slice(&raw_object_id(&public_tree_id));
    let root_tree_id = object_id("tree", &root_tree);
    let commit = format!(
        "tree {root_tree_id}\nparent {main_before}\n\
         author Carol <carol@example.com> 1700000000 +0000\n\
         committer Carol <carol@example.com> 1700000000 +0000\n\nsmuggle\n"
    )
    .into_bytes();
    let commit_id = object_id("commit", &commit);
    let pack = build_pack(&[
        PackEntry::Whole(1, commit),
        PackEntry::Whole(2, root_tree),
        PackEntry::Whole(2, config_tree),
        PackEntry::Whole(2, public_tree),
        PackEntry::RefDelta(fixture.secret_blob.clone(), delta),
    ]);

    // Side band 2 carries the hook's message back in the response.
    let command =
        format!("{main_before} {commit_id} refs/heads/main\0report-status side-band-64k\n");
    let mut push_request = pkt_line_bytes(command.as_bytes());
    push_request.extend_from_slice(b"0000");
    push_request.extend_from_slice(&pack);
    let request = match Request::builder()
        .method("POST")
        .uri("/team.git/git-receive-pack")
        .header(header::AUTHORIZATION, bearer_header(CAROL_TOKEN))
        .header(
            header::CONTENT_TYPE,
            "application/x-git-receive-pack-request",
        )
        .body(Body::from(push_request))
    {
        Ok(request) => request,
        Err(error) => panic!("failed to build request: {error}"),
    };
    let router = scrim_server::router_with_policy_store(
        fixture.root.path().to_path_buf(),
        Arc::new(fixture.store.clone()),
    );
    let response = match router.oneshot(request).await {
        Ok(response) => response,
        Err(error) => panic!("router call failed: {error}"),
    };
    assert_eq!(response.status(), StatusCode::OK);
    let report = match response.into_body().collect().await {
        Ok(collected) => collected.to_bytes().to_vec(),
        Err(error) => panic!("receive-pack failed instead of declining: {error}"),
    };
    let report = String::from_utf8_lossy(&report);
    assert!(
        report.contains("pre-receive hook declined"),
        "report: {report}"
    );
    assert!(report.contains("withheld from you"), "report: {report}");
    assert_eq!(fixture.server_main(), main_before);
}

// ============================================================================
// Milestone M4 wire-capture leak tests & full CLI-to-server end-to-end tests
// ============================================================================

const PLACEHOLDER_PREFIX: &str = "# scrim: encrypted private file";

#[derive(Clone)]
struct CapturedResponse {
    status: StatusCode,
    path: String,
    body: Vec<u8>,
}

#[derive(Default)]
struct CapturedTraffic {
    upload_pack: Vec<CapturedResponse>,
    info_refs: Vec<CapturedResponse>,
}

#[derive(Clone)]
struct WireCapture {
    inner: Arc<Mutex<CapturedTraffic>>,
}

impl WireCapture {
    fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(CapturedTraffic::default())),
        }
    }

    fn clear(&self) {
        match self.inner.lock() {
            Ok(mut guard) => {
                guard.upload_pack.clear();
                guard.info_refs.clear();
            }
            Err(error) => panic!("wire capture mutex poisoned: {error}"),
        }
    }

    fn upload_pack_responses(&self) -> Vec<CapturedResponse> {
        match self.inner.lock() {
            Ok(guard) => guard.upload_pack.clone(),
            Err(error) => panic!("wire capture mutex poisoned: {error}"),
        }
    }

    fn info_refs_responses(&self) -> Vec<CapturedResponse> {
        match self.inner.lock() {
            Ok(guard) => guard.info_refs.clone(),
            Err(error) => panic!("wire capture mutex poisoned: {error}"),
        }
    }
}

async fn capture_wire_middleware(
    State(capture): State<WireCapture>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let path_and_query = match request.uri().path_and_query() {
        Some(pq) => pq.as_str().to_owned(),
        None => path.clone(),
    };
    let is_upload_pack = method == Method::POST && path.ends_with("/git-upload-pack");
    let is_info_refs = method == Method::GET && path.ends_with("/info/refs");

    let response = next.run(request).await;
    if !is_upload_pack && !is_info_refs {
        return response;
    }

    let status = response.status();
    let (parts, body) = response.into_parts();
    let bytes = match body.collect().await {
        Ok(collected) => collected.to_bytes().to_vec(),
        Err(error) => panic!("failed to collect response body for {path}: {error}"),
    };
    let captured = CapturedResponse {
        status,
        path: path_and_query,
        body: bytes.clone(),
    };
    match capture.inner.lock() {
        Ok(mut guard) => {
            if is_upload_pack {
                guard.upload_pack.push(captured);
            } else {
                guard.info_refs.push(captured);
            }
        }
        Err(error) => panic!("wire capture mutex poisoned: {error}"),
    }
    Response::from_parts(parts, Body::from(bytes))
}

/// Spawns `scrim_server::router_with_policy_store` wrapped with an HTTP
/// wire-capturing middleware over loopback TCP.
async fn spawn_wire_capturing_server(
    repo_root: PathBuf,
    policy_store: Arc<dyn PolicyStore>,
) -> (String, WireCapture) {
    let capture = WireCapture::new();
    let router = scrim_server::router_with_policy_store(repo_root, policy_store).layer(
        middleware::from_fn_with_state(capture.clone(), capture_wire_middleware),
    );
    let listener = match tokio::net::TcpListener::bind("127.0.0.1:0").await {
        Ok(listener) => listener,
        Err(error) => panic!("failed to bind wire-capturing server listener: {error}"),
    };
    let address = match listener.local_addr() {
        Ok(address) => address,
        Err(error) => panic!("failed to read wire-capturing server address: {error}"),
    };
    tokio::spawn(async move {
        if let Err(error) = axum::serve(listener, router).await {
            panic!("wire-capturing server failed: {error}");
        }
    });
    (format!("http://{address}"), capture)
}

/// Parses Git pkt-line framing and side-band packets (band 1 = pack data,
/// band 2 = progress, band 3 = error; also handles raw `PACK` without
/// side-band) from a `POST */git-upload-pack` HTTP response body and returns
/// the concatenated wire `PACK` stream.
fn extract_pack_from_upload_pack_response(response_bytes: &[u8]) -> Vec<u8> {
    if response_bytes.starts_with(b"PACK") {
        return response_bytes.to_vec();
    }
    let mut pack = Vec::new();
    let mut offset = 0usize;
    while offset < response_bytes.len() {
        if response_bytes[offset..].starts_with(b"PACK") {
            pack.extend_from_slice(&response_bytes[offset..]);
            break;
        }
        let Some(len_bytes) = response_bytes.get(offset..offset + 4) else {
            panic!(
                "truncated pkt-line header at offset {offset} of {} bytes",
                response_bytes.len()
            );
        };
        let len_str = match std::str::from_utf8(len_bytes) {
            Ok(s) => s,
            Err(error) => panic!("non-UTF-8 pkt-line length at offset {offset}: {error}"),
        };
        let len = match usize::from_str_radix(len_str, 16) {
            Ok(len) => len,
            Err(error) => {
                panic!("invalid hex pkt-line length {len_str:?} at offset {offset}: {error}")
            }
        };
        if len <= 2 {
            // 0000 flush, 0001 delim, 0002 response-end.
            offset += 4;
            continue;
        }
        if len < 4 || offset + len > response_bytes.len() {
            panic!(
                "invalid pkt-line length {len} at offset {offset} (total {} bytes)",
                response_bytes.len()
            );
        }
        let payload = &response_bytes[offset + 4..offset + len];
        offset += len;
        match payload.first() {
            Some(1) => pack.extend_from_slice(&payload[1..]),
            Some(2 | 3) => {}
            _ => {}
        }
    }
    pack
}

fn git_with_stdin(dir: &Path, args: &[&str], stdin_bytes: &[u8]) -> Output {
    let path = match std::env::var_os("PATH") {
        Some(path) => path,
        None => panic!("PATH is not set"),
    };
    let mut command = Command::new("git");
    command
        .args([
            "-c",
            "user.name=Scrim Test",
            "-c",
            "user.email=test@example.invalid",
        ])
        .args(args)
        .current_dir(dir)
        .env_clear()
        .env("PATH", path)
        .env("HOME", utf8_path(dir))
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => panic!("failed to spawn git {args:?}: {error}"),
    };
    if let Some(mut stdin) = child.stdin.take()
        && let Err(error) = stdin.write_all(stdin_bytes)
    {
        panic!("failed to write stdin to git {args:?}: {error}");
    }
    let output = match child.wait_with_output() {
        Ok(output) => output,
        Err(error) => panic!("failed to wait for git {args:?}: {error}"),
    };
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

/// Indexes `pack_bytes` into a fresh empty bare repository WITHOUT
/// `--fix-thin` (proving the pack is self-contained with zero withheld delta
/// bases) and extracts every object OID and its decompressed object bytes.
fn inspect_wire_pack_objects(pack_bytes: &[u8]) -> (HashSet<String>, Vec<Vec<u8>>) {
    assert!(!pack_bytes.is_empty(), "wire pack bytes cannot be empty");
    assert!(
        pack_bytes.starts_with(b"PACK"),
        "wire pack does not start with PACK header"
    );
    let sandbox = GitSandbox::new();
    let temp = temp_dir("wire-pack-inspect");
    sandbox.init_bare(temp.path());

    // Index and verify the wire pack without `--fix-thin` (proving the pack is
    // self-contained with zero missing delta bases) and without `--strict`
    // (trees legitimately reference withheld blobs intentionally omitted from
    // the pack).
    git_with_stdin(temp.path(), &["index-pack", "--stdin"], pack_bytes);

    let batch_check = sandbox.git(
        temp.path(),
        &["cat-file", "--batch-all-objects", "--batch-check"],
    );
    let expected_count = String::from_utf8_lossy(&batch_check.stdout)
        .lines()
        .filter(|line| !line.is_empty())
        .count();

    let batch = sandbox.git(temp.path(), &["cat-file", "--batch-all-objects", "--batch"]);
    let raw = &batch.stdout;
    let mut oids = HashSet::new();
    let mut objects = Vec::new();
    let mut pos = 0usize;
    while pos < raw.len() {
        let rel_nl = match raw[pos..].iter().position(|&byte| byte == b'\n') {
            Some(idx) => idx,
            None => panic!("malformed cat-file --batch header at offset {pos}"),
        };
        let header = match std::str::from_utf8(&raw[pos..pos + rel_nl]) {
            Ok(line) => line,
            Err(error) => panic!("non-UTF-8 cat-file header: {error}"),
        };
        let mut parts = header.split_ascii_whitespace();
        let oid = match parts.next() {
            Some(oid) => oid.to_owned(),
            None => panic!("missing OID in cat-file header: {header:?}"),
        };
        let _kind = match parts.next() {
            Some(kind) => kind,
            None => panic!("missing type in cat-file header: {header:?}"),
        };
        let size = match parts.next().and_then(|s| s.parse::<usize>().ok()) {
            Some(size) => size,
            None => panic!("invalid size in cat-file header: {header:?}"),
        };
        let data_start = pos + rel_nl + 1;
        let data_end = data_start + size;
        assert!(
            data_end <= raw.len(),
            "truncated object payload for {oid} (expected {size} bytes at {data_start}, total {})",
            raw.len()
        );
        oids.insert(oid);
        objects.push(raw[data_start..data_end].to_vec());
        pos = data_end;
        if raw.get(pos) == Some(&b'\n') {
            pos += 1;
        }
    }
    assert_eq!(
        oids.len(),
        expected_count,
        "mismatch between --batch-check count ({expected_count}) and --batch parsed objects ({})",
        oids.len()
    );
    (oids, objects)
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// Verifies every captured `GET */info/refs` and `POST */git-upload-pack`
/// response:
/// - none of `forbidden_sentinels` appear anywhere in raw HTTP wire bytes or
///   in any decompressed wire pack object;
/// - none of `forbidden_oids` appear in any wire pack;
/// - at least one pack was transmitted and contains all `required_oids`.
fn assert_wire_capture_excludes(
    capture: &WireCapture,
    forbidden_oids: &[&str],
    forbidden_sentinels: &[&[u8]],
    required_oids: &[&str],
) -> HashSet<String> {
    let info_refs = capture.info_refs_responses();
    assert!(
        info_refs.iter().any(|resp| resp.status == StatusCode::OK),
        "expected at least one 200 OK GET */info/refs response"
    );
    for resp in &info_refs {
        assert!(
            resp.status == StatusCode::OK || resp.status == StatusCode::UNAUTHORIZED,
            "unexpected info/refs status {} for {}",
            resp.status,
            resp.path
        );
        for sentinel in forbidden_sentinels {
            assert!(
                !contains_bytes(&resp.body, sentinel),
                "forbidden sentinel leaked in info/refs response for {}",
                resp.path
            );
        }
    }

    let responses = capture.upload_pack_responses();
    assert!(
        !responses.is_empty(),
        "expected at least one captured POST */git-upload-pack response"
    );
    let mut all_oids = HashSet::new();
    let mut pack_count = 0usize;
    for resp in &responses {
        assert_eq!(
            resp.status,
            StatusCode::OK,
            "unexpected upload-pack status {} for {}",
            resp.status,
            resp.path
        );
        for sentinel in forbidden_sentinels {
            assert!(
                !contains_bytes(&resp.body, sentinel),
                "forbidden sentinel leaked in raw HTTP wire bytes for {}",
                resp.path
            );
        }
        let pack = extract_pack_from_upload_pack_response(&resp.body);
        if pack.is_empty() {
            continue;
        }
        pack_count += 1;
        let (oids, objects) = inspect_wire_pack_objects(&pack);
        for oid in forbidden_oids {
            assert!(
                !oids.contains(*oid),
                "withheld blob OID {oid} present in wire pack for {}",
                resp.path
            );
        }
        for obj in &objects {
            for sentinel in forbidden_sentinels {
                assert!(
                    !contains_bytes(obj, sentinel),
                    "withheld sentinel leaked in decompressed wire pack object for {}",
                    resp.path
                );
            }
        }
        all_oids.extend(oids);
    }
    assert!(
        pack_count >= 1,
        "expected at least one upload-pack response containing a PACK"
    );
    for oid in required_oids {
        assert!(
            all_oids.contains(*oid),
            "expected public blob OID {oid} in captured wire pack(s)"
        );
    }
    all_oids
}

fn temp_dir(label: &str) -> TempDir {
    match TempDir::new() {
        Ok(dir) => dir,
        Err(error) => panic!("failed to create temp dir ({label}): {error}"),
    }
}

fn create_dir(path: &Path) {
    if let Err(error) = std::fs::create_dir_all(path) {
        panic!("failed to create directory {}: {error}", path.display());
    }
}

fn read_to_string(path: &Path) -> String {
    match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) => panic!("failed to read {}: {error}", path.display()),
    }
}

fn read_bytes(path: &Path) -> Vec<u8> {
    match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) => panic!("failed to read {}: {error}", path.display()),
    }
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
                Err(error) => panic!("failed to invoke cargo build for scrim binary: {error}"),
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

fn augmented_path_env() -> String {
    let bin_dir = ensure_scrim_bin_dir().to_path_buf();
    let mut entries = vec![bin_dir];
    if let Some(existing) = std::env::var_os("PATH") {
        entries.extend(std::env::split_paths(&existing));
    }
    match std::env::join_paths(entries) {
        Ok(joined) => joined.to_string_lossy().into_owned(),
        Err(error) => panic!("failed to join PATH entries: {error}"),
    }
}

struct CliOutput {
    stdout: String,
    stderr: String,
}

fn cli_ok(cwd: &Path, config_path: &Path, stdin_bytes: &[u8], args: &[&str]) -> CliOutput {
    let mut env_vars = BTreeMap::new();
    env_vars.insert(
        "SCRIM_CONFIG".to_owned(),
        config_path.to_string_lossy().into_owned(),
    );
    env_vars.insert("PATH".to_owned(), augmented_path_env());
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
        Ok(()) => output,
        Err(error) => panic!(
            "CLI command {args:?} failed: {error:#}\nstdout:\n{}\nstderr:\n{}",
            output.stdout, output.stderr
        ),
    }
}

fn extract_issued_token(stdout: &str) -> String {
    let prefix = "Token (shown only once): ";
    for line in stdout.lines() {
        if let Some((_, value)) = line.split_once(prefix) {
            let trimmed = value.trim();
            assert!(
                !trimmed.is_empty(),
                "empty token value in CLI output:\n{stdout}"
            );
            return trimmed.to_owned();
        }
    }
    panic!("prefix {prefix:?} not found in CLI output:\n{stdout}");
}

fn git_with_config(sandbox: &GitSandbox, dir: &Path, config_path: &Path, args: &[&str]) -> Output {
    let path_env = augmented_path_env();
    let cfg = config_path.to_string_lossy();
    sandbox.git_with_env(
        dir,
        args,
        &[("PATH", &path_env), ("SCRIM_CONFIG", cfg.as_ref())],
    )
}

fn git_as_with_config(
    sandbox: &GitSandbox,
    dir: &Path,
    member_name: &str,
    token: &str,
    config_path: &Path,
    args: &[&str],
) -> Output {
    let helper = sandbox.credential_helper_config(member_name, token);
    let mut full_args = vec!["-c", &helper];
    full_args.extend_from_slice(args);
    let path_env = augmented_path_env();
    let cfg = config_path.to_string_lossy();
    sandbox.git_with_env(
        dir,
        &full_args,
        &[("PATH", &path_env), ("SCRIM_CONFIG", cfg.as_ref())],
    )
}

fn assert_git_clean(sandbox: &GitSandbox, dir: &Path, config_path: &Path) {
    let status = git_with_config(sandbox, dir, config_path, &["status", "--porcelain"]);
    let text = String::from_utf8_lossy(&status.stdout);
    assert_eq!(text, "", "expected clean git status in {}", dir.display());
}

fn is_missing_locally(sandbox: &GitSandbox, dir: &Path, object: &str) -> bool {
    let output = sandbox.git(dir, &["rev-list", "--objects", "--missing=print", "--all"]);
    stdout_text(&output)
        .lines()
        .any(|line| line == format!("?{object}"))
}

fn assert_no_bytes_in_dir(dir: &Path, needle: &[u8]) {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) => panic!("failed to read directory {}: {error}", dir.display()),
    };
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => panic!("failed to read dir entry under {}: {error}", dir.display()),
        };
        let path = entry.path();
        let meta = match std::fs::symlink_metadata(&path) {
            Ok(meta) => meta,
            Err(error) => panic!("failed to stat {}: {error}", path.display()),
        };
        if meta.is_dir() {
            assert_no_bytes_in_dir(&path, needle);
        } else if meta.is_file() {
            let bytes = read_bytes(&path);
            assert!(
                !contains_bytes(&bytes, needle),
                "bearer token unexpectedly written to {}",
                path.display()
            );
        }
    }
}

async fn join_blocking<T>(handle: tokio::task::JoinHandle<T>) -> T {
    match handle.await {
        Ok(value) => value,
        Err(error) => panic!("blocking task panicked: {error}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn wire_capture_proves_zero_withheld_blob_bytes_across_v0_and_v2() {
    let root = temp_dir("wire-v0-v2-root");
    let scratch = temp_dir("wire-v0-v2-scratch");
    let sandbox = GitSandbox::new();
    let bare = root.path().join("team.git");
    sandbox.init_bare(&bare);

    let ledger_sentinel = b"WITHHELD_BILLING_LEDGER_SENTINEL_9911";
    let invoice_sentinel = b"WITHHELD_INVOICE_SENTINEL_8822";
    let secret_sentinel = b"WITHHELD_NESTED_SECRET_SENTINEL_7733";

    let seed = scratch.path().join("seed");
    create_dir(&seed);
    sandbox.git(&seed, &["init", "--quiet", "--initial-branch=main"]);
    write_file(&seed, "public/readme.txt", "public readme contents\n");
    write_file(&seed, "config/public.json", "{\"public\":true}\n");
    write_file(
        &seed,
        "config/billing/ledger.txt",
        "WITHHELD_BILLING_LEDGER_SENTINEL_9911\n",
    );
    write_file(
        &seed,
        "config/billing/sub/invoice.txt",
        "WITHHELD_INVOICE_SENTINEL_8822\n",
    );
    write_file(
        &seed,
        "nested/top.secret",
        "WITHHELD_NESTED_SECRET_SENTINEL_7733\n",
    );
    sandbox.git(&seed, &["add", "--all"]);
    sandbox.git(&seed, &["commit", "--quiet", "-m", "seed repo"]);
    let public_readme_blob =
        stdout_text(&sandbox.git(&seed, &["rev-parse", "HEAD:public/readme.txt"]));
    let public_json_blob =
        stdout_text(&sandbox.git(&seed, &["rev-parse", "HEAD:config/public.json"]));
    let ledger_blob =
        stdout_text(&sandbox.git(&seed, &["rev-parse", "HEAD:config/billing/ledger.txt"]));
    let invoice_blob =
        stdout_text(&sandbox.git(&seed, &["rev-parse", "HEAD:config/billing/sub/invoice.txt"]));
    let top_secret_blob =
        stdout_text(&sandbox.git(&seed, &["rev-parse", "HEAD:nested/top.secret"]));
    sandbox.git(&seed, &["push", "--quiet", utf8_path(&bare), "main"]);

    let mut store = MemoryPolicyStore::new();
    store.insert_member(
        AuthenticatedMember {
            id: 1,
            name: ALICE.name.to_owned(),
            is_admin: false,
        },
        ALICE_TOKEN.as_bytes(),
    );
    store.insert_member(
        AuthenticatedMember {
            id: 3,
            name: CAROL.name.to_owned(),
            is_admin: false,
        },
        CAROL_TOKEN.as_bytes(),
    );
    store.insert_group_membership(1, "billing");
    store.insert_group_membership(1, "security");
    match WithholdRule::new("config/billing/**", ["billing".to_owned()]) {
        Ok(rule) => store.insert_path_rule("team.git", rule),
        Err(error) => panic!("billing rule should be valid: {error}"),
    }
    match WithholdRule::new("*.secret", ["security".to_owned()]) {
        Ok(rule) => store.insert_path_rule("team.git", rule),
        Err(error) => panic!("security rule should be valid: {error}"),
    }

    let (base_url, capture) =
        spawn_wire_capturing_server(root.path().to_path_buf(), Arc::new(store)).await;
    let repo_url = format!("{base_url}/team.git");

    join_blocking(tokio::task::spawn_blocking(move || {
        let forbidden_oids = [
            ledger_blob.as_str(),
            invoice_blob.as_str(),
            top_secret_blob.as_str(),
        ];
        let forbidden_sentinels: [&[u8]; 3] = [ledger_sentinel, invoice_sentinel, secret_sentinel];
        let required_oids = [public_readme_blob.as_str(), public_json_blob.as_str()];

        for (label, proto_flag) in [("v0", "protocol.version=0"), ("v2", "protocol.version=2")] {
            capture.clear();
            let dir_name = format!("carol-{label}");
            let carol_helper = sandbox.credential_helper_config(CAROL.name, CAROL.token);
            sandbox.git(
                scratch.path(),
                &[
                    "-c",
                    &carol_helper,
                    "-c",
                    proto_flag,
                    "clone",
                    "--quiet",
                    PARTIAL_CLONE_FILTER,
                    "--no-checkout",
                    &repo_url,
                    &dir_name,
                ],
            );
            let clone_dir = scratch.path().join(&dir_name);
            sandbox.git(
                &clone_dir,
                &[
                    "-c",
                    &carol_helper,
                    "-c",
                    proto_flag,
                    "sparse-checkout",
                    "set",
                    "--no-cone",
                    "--",
                    "/*",
                    "!/config/billing/**",
                    "!*.secret",
                ],
            );
            sandbox.git(
                &clone_dir,
                &[
                    "-c",
                    &carol_helper,
                    "-c",
                    proto_flag,
                    "checkout",
                    "--quiet",
                    "main",
                ],
            );

            let status = sandbox.git(&clone_dir, &["status", "--porcelain"]);
            assert_eq!(
                String::from_utf8_lossy(&status.stdout),
                "",
                "expected clean git status for carol ({label})"
            );
            assert!(clone_dir.join("public/readme.txt").is_file());
            assert!(clone_dir.join("config/public.json").is_file());
            assert!(!clone_dir.join("config/billing/ledger.txt").exists());
            assert!(!clone_dir.join("config/billing/sub/invoice.txt").exists());
            assert!(!clone_dir.join("nested/top.secret").exists());

            for oid in forbidden_oids {
                assert!(
                    is_missing_locally(&sandbox, &clone_dir, oid),
                    "withheld oid {oid} unexpectedly present locally for {label}"
                );
            }

            assert_wire_capture_excludes(
                &capture,
                &forbidden_oids,
                &forbidden_sentinels,
                &required_oids,
            );
        }

        // Authorized member `alice` (billing + security) receives all blobs and files.
        capture.clear();
        let alice_helper = sandbox.credential_helper_config(ALICE.name, ALICE.token);
        sandbox.git(
            scratch.path(),
            &[
                "-c",
                &alice_helper,
                "clone",
                "--quiet",
                &repo_url,
                "alice-full",
            ],
        );
        let alice_dir = scratch.path().join("alice-full");
        assert!(
            read_to_string(&alice_dir.join("config/billing/ledger.txt"))
                .contains("WITHHELD_BILLING_LEDGER_SENTINEL_9911")
        );
        assert!(
            read_to_string(&alice_dir.join("config/billing/sub/invoice.txt"))
                .contains("WITHHELD_INVOICE_SENTINEL_8822")
        );
        assert!(
            read_to_string(&alice_dir.join("nested/top.secret"))
                .contains("WITHHELD_NESTED_SECRET_SENTINEL_7733")
        );
        let alice_wire_oids = assert_wire_capture_excludes(&capture, &[], &[], &required_oids);
        for oid in forbidden_oids {
            assert!(
                alice_wire_oids.contains(oid),
                "authorized member alice wire pack missing expected blob {oid}"
            );
        }
    }))
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scrim_cli_withhold_clone_pull_push_and_wire_capture_end_to_end() {
    let repo_root = temp_dir("cli-withhold-repo-root");
    let work_dir = temp_dir("cli-withhold-work");
    let configs_dir = temp_dir("cli-withhold-configs");

    let store = MemoryPolicyStore::new();
    let bootstrap = match store.bootstrap_admin("root", "bootstrap").await {
        Ok(created) => created,
        Err(error) => panic!("bootstrap_admin failed: {error}"),
    };
    let root_token = bootstrap.token.expose_secret().to_owned();
    let (proxy_url, capture) =
        spawn_wire_capturing_server(repo_root.path().to_path_buf(), Arc::new(store)).await;

    let root_config = configs_dir.path().join("root").join("config.toml");
    let alice_config = configs_dir.path().join("alice").join("config.toml");
    let carol_config = configs_dir.path().join("carol").join("config.toml");
    let work_root = work_dir.path().to_path_buf();
    let repo_url = format!("{proxy_url}/team.git");

    join_blocking(tokio::task::spawn_blocking(move || {
        let sandbox = GitSandbox::new();
        let scratch = work_root.join("scratch");
        create_dir(&scratch);

        // 1. Admin `root` logs in, initializes `team`, creates groups, and grants access.
        cli_ok(
            &scratch,
            &root_config,
            format!("{root_token}\n").as_bytes(),
            &["scrim", "login", "--server", &proxy_url, "--token-stdin"],
        );
        let team_dir = work_root.join("team");
        create_dir(&team_dir);
        sandbox.git(&team_dir, &["init", "--quiet", "--initial-branch=main"]);
        cli_ok(&team_dir, &root_config, b"", &["scrim", "init"]);

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
        let alice_grant = cli_ok(
            &scratch,
            &root_config,
            b"",
            &["scrim", "access", "grant", "alice", "--group", "finance"],
        );
        let alice_token = extract_issued_token(&alice_grant.stdout);
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

        cli_ok(
            &scratch,
            &alice_config,
            format!("{alice_token}\n").as_bytes(),
            &["scrim", "login", "--server", &proxy_url, "--token-stdin"],
        );
        cli_ok(
            &scratch,
            &carol_config,
            format!("{carol_token}\n").as_bytes(),
            &["scrim", "login", "--server", &proxy_url, "--token-stdin"],
        );

        // 2. Push initial public and sensitive files.
        let rates_v1_sentinel = b"WITHHELD_RATES_V1_SENTINEL_1122";
        let keys_secret_sentinel = b"WITHHELD_KEYS_SECRET_SENTINEL_2233";
        let dot_billing_sentinel = b"WITHHELD_DOT_BILLING_SENTINEL_3344";

        write_file(&team_dir, "public/app.txt", "public app v1\n");
        write_file(
            &team_dir,
            "config/billing/rates.txt",
            "WITHHELD_RATES_V1_SENTINEL_1122\n",
        );
        write_file(
            &team_dir,
            "ops/keys.secret",
            "WITHHELD_KEYS_SECRET_SENTINEL_2233\n",
        );
        write_file(
            &team_dir,
            ".billing/private.txt",
            "WITHHELD_DOT_BILLING_SENTINEL_3344\n",
        );
        sandbox.git(&team_dir, &["add", "--all"]);
        sandbox.git(&team_dir, &["commit", "--quiet", "-m", "initial seed"]);

        let app_v1_blob =
            stdout_text(&sandbox.git(&team_dir, &["rev-parse", "HEAD:public/app.txt"]));
        let rates_v1_blob =
            stdout_text(&sandbox.git(&team_dir, &["rev-parse", "HEAD:config/billing/rates.txt"]));
        let keys_secret_blob =
            stdout_text(&sandbox.git(&team_dir, &["rev-parse", "HEAD:ops/keys.secret"]));
        let dot_billing_blob =
            stdout_text(&sandbox.git(&team_dir, &["rev-parse", "HEAD:.billing/private.txt"]));

        git_as_with_config(
            &sandbox,
            &team_dir,
            "root",
            &root_token,
            &root_config,
            &["push", "--quiet", "-u", "origin", "main"],
        );

        // 3. Configure server-side withholding rules via `scrim private add --withhold`.
        cli_ok(
            &team_dir,
            &root_config,
            b"",
            &[
                "scrim",
                "private",
                "add",
                "config/billing/**",
                "--group",
                "finance",
                "--withhold",
            ],
        );
        cli_ok(
            &team_dir,
            &root_config,
            b"",
            &[
                "scrim",
                "private",
                "add",
                "*.secret",
                "--group",
                "finance",
                "--withhold",
            ],
        );
        cli_ok(
            &team_dir,
            &root_config,
            b"",
            &[
                "scrim",
                "private",
                "add",
                ".billing/**",
                "--group",
                "finance",
                "--withhold",
            ],
        );

        let status_out = cli_ok(
            &team_dir,
            &root_config,
            b"",
            &["scrim", "private", "status", "--withhold"],
        );
        for expected in ["config/billing/**", "*.secret", ".billing/**", "finance"] {
            assert!(
                status_out.stdout.contains(expected),
                "withhold status missing {expected:?}:\n{}",
                status_out.stdout
            );
        }

        // 4. Non-member `carol` runs `scrim clone <proxy_url>/team.git carol-work`.
        capture.clear();
        let carol_clone_out = cli_ok(
            &work_root,
            &carol_config,
            b"",
            &["scrim", "clone", &repo_url, "carol-work"],
        );
        assert!(
            carol_clone_out.stdout.contains("Partial clone: enabled"),
            "unexpected clone output:\n{}",
            carol_clone_out.stdout
        );
        let carol_work = work_root.join("carol-work");
        assert_git_clean(&sandbox, &carol_work, &carol_config);
        assert_eq!(
            read_to_string(&carol_work.join("public/app.txt")),
            "public app v1\n"
        );
        for withheld_path in [
            "config/billing/rates.txt",
            "ops/keys.secret",
            ".billing/private.txt",
        ] {
            assert!(
                !carol_work.join(withheld_path).exists(),
                "withheld path {withheld_path} should not exist on disk"
            );
        }
        for oid in [&rates_v1_blob, &keys_secret_blob, &dot_billing_blob] {
            assert!(
                is_missing_locally(&sandbox, &carol_work, oid),
                "withheld blob {oid} should be missing locally"
            );
        }

        assert_eq!(
            stdout_text(&sandbox.git(&carol_work, &["config", "--local", "--get", "scrim.repo"])),
            "team.git"
        );
        assert_eq!(
            stdout_text(&sandbox.git(&carol_work, &["config", "--local", "--get", "scrim.server"])),
            proxy_url
        );
        assert_eq!(
            stdout_text(&sandbox.git(
                &carol_work,
                &["config", "--local", "--get", "remote.origin.promisor"]
            )),
            "true"
        );
        assert_no_bytes_in_dir(&carol_work.join(".git"), carol_token.as_bytes());

        assert_wire_capture_excludes(
            &capture,
            &[
                rates_v1_blob.as_str(),
                keys_secret_blob.as_str(),
                dot_billing_blob.as_str(),
            ],
            &[
                rates_v1_sentinel,
                keys_secret_sentinel,
                dot_billing_sentinel,
            ],
            &[app_v1_blob.as_str()],
        );

        // 5. Carol edits `public/app.txt`, commits, and pushes cleanly.
        write_file(&carol_work, "public/app.txt", "public app by carol\n");
        sandbox.git(&carol_work, &["add", "public/app.txt"]);
        sandbox.git(&carol_work, &["commit", "--quiet", "-m", "carol edit"]);
        git_as_with_config(
            &sandbox,
            &carol_work,
            "carol",
            &carol_token,
            &carol_config,
            &["push", "--quiet", "origin", "main"],
        );

        // 6. Authorized `alice` runs `scrim clone`, gets a full clone, updates both
        //    `public/app.txt` and `config/billing/rates.txt`, and pushes.
        let alice_clone_out = cli_ok(
            &work_root,
            &alice_config,
            b"",
            &["scrim", "clone", &repo_url, "alice-work"],
        );
        assert!(
            alice_clone_out.stdout.contains("Partial clone: not needed"),
            "expected full clone for alice:\n{}",
            alice_clone_out.stdout
        );
        let alice_work = work_root.join("alice-work");
        assert_eq!(
            read_to_string(&alice_work.join("public/app.txt")),
            "public app by carol\n"
        );
        assert!(
            read_to_string(&alice_work.join("config/billing/rates.txt"))
                .contains("WITHHELD_RATES_V1_SENTINEL_1122")
        );
        assert!(
            read_to_string(&alice_work.join("ops/keys.secret"))
                .contains("WITHHELD_KEYS_SECRET_SENTINEL_2233")
        );
        assert!(
            read_to_string(&alice_work.join(".billing/private.txt"))
                .contains("WITHHELD_DOT_BILLING_SENTINEL_3344")
        );

        let rates_v2_sentinel = b"WITHHELD_RATES_V2_SENTINEL_4455";
        write_file(&alice_work, "public/app.txt", "public app by alice v2\n");
        write_file(
            &alice_work,
            "config/billing/rates.txt",
            "WITHHELD_RATES_V2_SENTINEL_4455\n",
        );
        sandbox.git(&alice_work, &["add", "--all"]);
        sandbox.git(&alice_work, &["commit", "--quiet", "-m", "alice update"]);
        let app_v2_blob =
            stdout_text(&sandbox.git(&alice_work, &["rev-parse", "HEAD:public/app.txt"]));
        let rates_v2_blob =
            stdout_text(&sandbox.git(&alice_work, &["rev-parse", "HEAD:config/billing/rates.txt"]));
        git_as_with_config(
            &sandbox,
            &alice_work,
            "alice",
            &alice_token,
            &alice_config,
            &["push", "--quiet", "origin", "main"],
        );

        // 7. Carol runs `git pull --ff-only`; wire capture proves v2 sentinel and
        //    blob OID never crossed the wire while `public/app.txt` updated cleanly.
        capture.clear();
        git_as_with_config(
            &sandbox,
            &carol_work,
            "carol",
            &carol_token,
            &carol_config,
            &["pull", "--quiet", "--ff-only"],
        );
        assert_eq!(
            read_to_string(&carol_work.join("public/app.txt")),
            "public app by alice v2\n"
        );
        assert!(!carol_work.join("config/billing/rates.txt").exists());
        assert!(is_missing_locally(&sandbox, &carol_work, &rates_v2_blob));
        assert_wire_capture_excludes(
            &capture,
            &[rates_v2_blob.as_str()],
            &[rates_v2_sentinel],
            &[app_v2_blob.as_str()],
        );

        // 8. Admin removes `*.secret`; Carol runs `scrim private setup --withhold`
        //    and gets `ops/keys.secret` while `config/billing/**` and `.billing/**`
        //    remain excluded.
        cli_ok(
            &team_dir,
            &root_config,
            b"",
            &["scrim", "private", "rm", "*.secret", "--withhold"],
        );
        let after_rm_status = cli_ok(
            &team_dir,
            &root_config,
            b"",
            &["scrim", "private", "status", "--withhold"],
        );
        assert!(
            !after_rm_status.stdout.contains("*.secret"),
            "removed rule still listed:\n{}",
            after_rm_status.stdout
        );
        assert!(after_rm_status.stdout.contains("config/billing/**"));
        assert!(after_rm_status.stdout.contains(".billing/**"));

        cli_ok(
            &carol_work,
            &carol_config,
            b"",
            &["scrim", "private", "setup", "--withhold"],
        );
        let sparse_file = read_to_string(&carol_work.join(".git/info/sparse-checkout"));
        assert!(
            !sparse_file.contains("*.secret"),
            "sparse-checkout still excludes *.secret:\n{sparse_file}"
        );
        assert!(sparse_file.contains("!/config/billing/**"));
        assert!(sparse_file.contains("!/.billing/**"));
        assert!(
            read_to_string(&carol_work.join("ops/keys.secret"))
                .contains("WITHHELD_KEYS_SECRET_SENTINEL_2233")
        );
        assert!(!carol_work.join("config/billing/rates.txt").exists());
        assert!(!carol_work.join(".billing/private.txt").exists());
        assert_git_clean(&sandbox, &carol_work, &carol_config);
    }))
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scrim_clone_combines_m3_encrypted_and_m4_withheld_paths() {
    let repo_root = temp_dir("m3-m4-repo-root");
    let work_dir = temp_dir("m3-m4-work");
    let configs_dir = temp_dir("m3-m4-configs");

    let store = MemoryPolicyStore::new();
    let bootstrap = match store.bootstrap_admin("root", "bootstrap").await {
        Ok(created) => created,
        Err(error) => panic!("bootstrap_admin failed: {error}"),
    };
    let root_token = bootstrap.token.expose_secret().to_owned();
    let (proxy_url, capture) =
        spawn_wire_capturing_server(repo_root.path().to_path_buf(), Arc::new(store)).await;

    let root_config = configs_dir.path().join("root").join("config.toml");
    let alice_config = configs_dir.path().join("alice").join("config.toml");
    let carol_config = configs_dir.path().join("carol").join("config.toml");
    let work_root = work_dir.path().to_path_buf();
    let server_repo_dir = repo_root.path().join("team.git");
    let repo_url = format!("{proxy_url}/team.git");

    join_blocking(tokio::task::spawn_blocking(move || {
        let sandbox = GitSandbox::new();
        let scratch = work_root.join("scratch");
        create_dir(&scratch);

        // 1. Login root, init `team`, create `core` + `finance`, grant alice & carol, keygen.
        cli_ok(
            &scratch,
            &root_config,
            format!("{root_token}\n").as_bytes(),
            &["scrim", "login", "--server", &proxy_url, "--token-stdin"],
        );
        let team_dir = work_root.join("team");
        create_dir(&team_dir);
        sandbox.git(&team_dir, &["init", "--quiet", "--initial-branch=main"]);
        cli_ok(&team_dir, &root_config, b"", &["scrim", "init"]);

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
            &["scrim", "group", "create", "finance"],
        );
        cli_ok(
            &scratch,
            &root_config,
            b"",
            &["scrim", "group", "add", "core", "root"],
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
            &[
                "scrim", "access", "grant", "alice", "--group", "core", "--group", "finance",
            ],
        );
        let alice_token = extract_issued_token(&alice_grant.stdout);
        let carol_grant = cli_ok(
            &scratch,
            &root_config,
            b"",
            &["scrim", "access", "grant", "carol"],
        );
        let carol_token = extract_issued_token(&carol_grant.stdout);

        cli_ok(
            &scratch,
            &alice_config,
            format!("{alice_token}\n").as_bytes(),
            &["scrim", "login", "--server", &proxy_url, "--token-stdin"],
        );
        cli_ok(
            &scratch,
            &carol_config,
            format!("{carol_token}\n").as_bytes(),
            &["scrim", "login", "--server", &proxy_url, "--token-stdin"],
        );
        for cfg in [&root_config, &alice_config, &carol_config] {
            cli_ok(&scratch, cfg, b"", &["scrim", "keygen"]);
        }

        // 2. Add BOTH an M3 encrypted rule (`docs/encrypted/**` -> `core`) and
        //    an M4 withholding rule (`config/billing/**` -> `finance`).
        cli_ok(
            &team_dir,
            &root_config,
            b"",
            &[
                "scrim",
                "private",
                "add",
                "docs/encrypted/**",
                "--group",
                "core",
            ],
        );
        cli_ok(
            &team_dir,
            &root_config,
            b"",
            &[
                "scrim",
                "private",
                "add",
                "config/billing/**",
                "--group",
                "finance",
                "--withhold",
            ],
        );

        let encrypted_sentinel = b"ENCRYPTED_CORE_MEMO_SENTINEL_5566";
        let withheld_sentinel = b"WITHHELD_BILLING_SECRET_SENTINEL_6677";

        write_file(&team_dir, "public/readme.txt", "public readme v1\n");
        write_file(
            &team_dir,
            "docs/encrypted/memo.txt",
            "ENCRYPTED_CORE_MEMO_SENTINEL_5566\n",
        );
        write_file(
            &team_dir,
            "config/billing/secret.txt",
            "WITHHELD_BILLING_SECRET_SENTINEL_6677\n",
        );
        git_with_config(&sandbox, &team_dir, &root_config, &["add", "--all"]);
        git_with_config(
            &sandbox,
            &team_dir,
            &root_config,
            &["commit", "--quiet", "-m", "m3 encrypted and m4 withheld"],
        );
        git_as_with_config(
            &sandbox,
            &team_dir,
            "root",
            &root_token,
            &root_config,
            &["push", "--quiet", "-u", "origin", "main"],
        );

        let server_memo = sandbox.git(
            &server_repo_dir,
            &["cat-file", "blob", "main:docs/encrypted/memo.txt"],
        );
        assert!(
            server_memo.stdout.starts_with(ENCRYPTED_FILE_MAGIC),
            "expected encrypted M3 blob on server"
        );
        assert!(!contains_bytes(&server_memo.stdout, encrypted_sentinel));

        let readme_blob =
            stdout_text(&sandbox.git(&server_repo_dir, &["rev-parse", "main:public/readme.txt"]));
        let withheld_secret_blob = stdout_text(&sandbox.git(
            &server_repo_dir,
            &["rev-parse", "main:config/billing/secret.txt"],
        ));

        // 3. Non-member `carol` runs `scrim clone`:
        //    - public file is plaintext
        //    - M3 file is a canonical placeholder (not plaintext, not raw SCRIMFILE\0)
        //    - M4 file is excluded by sparse-checkout and absent from wire capture
        //    - `git status` is clean
        capture.clear();
        cli_ok(
            &work_root,
            &carol_config,
            b"",
            &["scrim", "clone", &repo_url, "carol-work"],
        );
        let carol_work = work_root.join("carol-work");
        assert_eq!(
            read_to_string(&carol_work.join("public/readme.txt")),
            "public readme v1\n"
        );
        let memo_bytes = read_bytes(&carol_work.join("docs/encrypted/memo.txt"));
        assert!(
            memo_bytes.starts_with(PLACEHOLDER_PREFIX.as_bytes()),
            "expected canonical Scrim M3 placeholder, got:\n{}",
            String::from_utf8_lossy(&memo_bytes)
        );
        assert!(!contains_bytes(&memo_bytes, encrypted_sentinel));
        assert!(!memo_bytes.starts_with(ENCRYPTED_FILE_MAGIC));

        assert!(!carol_work.join("config/billing/secret.txt").exists());
        assert!(is_missing_locally(
            &sandbox,
            &carol_work,
            &withheld_secret_blob
        ));
        assert_git_clean(&sandbox, &carol_work, &carol_config);

        assert_wire_capture_excludes(
            &capture,
            &[withheld_secret_blob.as_str()],
            &[withheld_sentinel, encrypted_sentinel],
            &[readme_blob.as_str()],
        );

        // 4. Authorized `alice` runs `scrim clone` and sees both decrypted M3 and M4 plaintext.
        cli_ok(
            &work_root,
            &alice_config,
            b"",
            &["scrim", "clone", &repo_url, "alice-work"],
        );
        let alice_work = work_root.join("alice-work");
        assert_eq!(
            read_to_string(&alice_work.join("public/readme.txt")),
            "public readme v1\n"
        );
        assert_eq!(
            read_to_string(&alice_work.join("docs/encrypted/memo.txt")),
            "ENCRYPTED_CORE_MEMO_SENTINEL_5566\n"
        );
        assert_eq!(
            read_to_string(&alice_work.join("config/billing/secret.txt")),
            "WITHHELD_BILLING_SECRET_SENTINEL_6677\n"
        );
        assert_git_clean(&sandbox, &alice_work, &alice_config);
    }))
    .await;
}
