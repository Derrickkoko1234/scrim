//! End-to-end tests for SHA-256 Git repositories (`--object-format=sha256`):
//! server-side blob withholding, `pre-receive` Check 6 (including the SHA-256
//! empty blob exemption), and private branch visibility.

mod common;

use std::{
    collections::HashSet,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::{Arc, Mutex},
};

use axum::{
    body::Body,
    extract::State,
    http::{Method, Request, StatusCode, header},
    middleware::{self, Next},
    response::Response,
};
use common::{GitSandbox, bearer_header, pkt_line_bytes, spawn_server_with_store};
use http_body_util::BodyExt;
use scrim_policy::{BranchRule, WithholdRule};
use scrim_server::{AuthenticatedMember, MemoryPolicyStore, PolicyStore};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tower::ServiceExt;

const ALICE_TOKEN: &str = "alice-sha256-token-0123456789abcdef";
const CAROL_TOKEN: &str = "carol-sha256-token-0123456789abcdef";

/// The partial-clone filter `scrim clone` uses.
const PARTIAL_CLONE_FILTER: &str = "--filter=blob:limit=2g";

/// The empty blob in a SHA-256 Git repository (`sha256("blob 0\0")`).
const EMPTY_SHA256_BLOB_ID: &str =
    "473a0f4c3be8a93681a267e3b1e9a7dcda1185436fe141f7749120a303721813";

/// 64-hex zero OID used for SHA-256 ref creation.
const SHA256_ZERO: &str = "0000000000000000000000000000000000000000000000000000000000000000";

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

fn utf8_path(path: &Path) -> &str {
    match path.to_str() {
        Some(path) => path,
        None => panic!("path is not valid UTF-8: {}", path.display()),
    }
}

fn stdout_text(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

fn read_to_string(path: &Path) -> String {
    match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) => panic!("failed to read {}: {error}", path.display()),
    }
}

fn write_file(dir: &Path, path: &str, contents: &str) {
    let full_path = dir.join(path);
    if let Some(parent) = full_path.parent() {
        create_dir(parent);
    }
    if let Err(error) = std::fs::write(&full_path, contents) {
        panic!("failed to write {path}: {error}");
    }
}

fn init_bare_sha256(sandbox: &GitSandbox, path: &Path) {
    create_dir(path);
    sandbox.git(
        path,
        &[
            "init",
            "--bare",
            "--object-format=sha256",
            "--initial-branch=main",
        ],
    );
}

fn init_work_sha256(sandbox: &GitSandbox, path: &Path) {
    create_dir(path);
    sandbox.git(
        path,
        &[
            "init",
            "--quiet",
            "--object-format=sha256",
            "--initial-branch=main",
        ],
    );
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

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
        if let Some(1) = payload.first() {
            pack.extend_from_slice(&payload[1..]);
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

/// Indexes `pack_bytes` into a fresh empty SHA-256 bare repository without
/// `--fix-thin` and extracts every 64-hex object OID and decompressed payload.
fn inspect_wire_pack_objects_sha256(pack_bytes: &[u8]) -> (HashSet<String>, Vec<Vec<u8>>) {
    assert!(!pack_bytes.is_empty(), "wire pack bytes cannot be empty");
    assert!(
        pack_bytes.starts_with(b"PACK"),
        "wire pack does not start with PACK header"
    );
    let sandbox = GitSandbox::new();
    let temp = temp_dir("sha256-wire-pack-inspect");
    init_bare_sha256(&sandbox, temp.path());

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
        assert_eq!(
            oid.len(),
            64,
            "expected 64-hex SHA-256 OID in wire pack, got {oid:?}"
        );
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
    assert_eq!(oids.len(), expected_count);
    (oids, objects)
}

fn assert_wire_capture_excludes_sha256(
    capture: &WireCapture,
    forbidden_oids: &[&str],
    forbidden_sentinels: &[&[u8]],
    required_oids: &[&str],
) {
    let info_refs = capture.info_refs_responses();
    assert!(
        info_refs.iter().any(|resp| resp.status == StatusCode::OK),
        "expected at least one 200 OK GET */info/refs response"
    );
    for resp in &info_refs {
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
        assert_eq!(resp.status, StatusCode::OK);
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
        let (oids, objects) = inspect_wire_pack_objects_sha256(&pack);
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
}

struct WithholdFixture {
    sandbox: GitSandbox,
    root: TempDir,
    scratch: TempDir,
    base_url: String,
    capture: WireCapture,
    public_blob: String,
    secret_blob: String,
}

impl WithholdFixture {
    async fn start() -> Self {
        let sandbox = GitSandbox::new();
        let root = temp_dir("sha256-withhold-root");
        let scratch = temp_dir("sha256-withhold-scratch");
        let bare = root.path().join("team.git");
        init_bare_sha256(&sandbox, &bare);

        let seed = scratch.path().join("seed");
        init_work_sha256(&sandbox, &seed);
        write_file(&seed, "public/readme.txt", "hello sha256\n");
        sandbox.git(&seed, &["add", "--all"]);
        sandbox.git(&seed, &["commit", "--quiet", "-m", "base"]);

        write_file(
            &seed,
            "config/billing/secret.txt",
            "SHA256_WITHHELD_BILLING_SECRET_98765\n",
        );
        // Include a 0-byte file at a withheld path so Check 6 tests prove the
        // SHA-256 empty blob is exempted even when present under withheld paths.
        write_file(&seed, "config/billing/empty.txt", "");
        sandbox.git(&seed, &["add", "--all"]);
        sandbox.git(&seed, &["commit", "--quiet", "-m", "billing"]);

        let public_blob =
            stdout_text(&sandbox.git(&seed, &["rev-parse", "HEAD:public/readme.txt"]));
        let secret_blob =
            stdout_text(&sandbox.git(&seed, &["rev-parse", "HEAD:config/billing/secret.txt"]));
        let empty_blob =
            stdout_text(&sandbox.git(&seed, &["rev-parse", "HEAD:config/billing/empty.txt"]));
        assert_eq!(public_blob.len(), 64);
        assert_eq!(secret_blob.len(), 64);
        assert_eq!(empty_blob, EMPTY_SHA256_BLOB_ID);

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
            Err(error) => panic!("withhold rule should be valid: {error}"),
        }

        let (base_url, capture) =
            spawn_wire_capturing_server(root.path().to_path_buf(), Arc::new(store)).await;

        Self {
            sandbox,
            root,
            scratch,
            base_url,
            capture,
            public_blob,
            secret_blob,
        }
    }

    fn url(&self) -> String {
        format!("{}/team.git", self.base_url)
    }

    fn try_git_as(&self, member: Member, dir: &Path, args: &[&str]) -> Output {
        let helper = self
            .sandbox
            .credential_helper_config(member.name, member.token);
        let mut full_args = vec!["-c", &helper];
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

    fn clone_as(&self, member: Member, name: &str, options: &[&str]) -> PathBuf {
        let url = self.url();
        let mut args = vec!["clone", "--quiet"];
        args.extend_from_slice(options);
        args.push(&url);
        args.push(name);
        self.git_as(member, self.scratch.path(), &args);
        self.scratch.path().join(name)
    }

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

fn assert_rejected(output: &Output, reason: &str) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "operation should be rejected");
    assert!(stderr.contains(reason), "expected {reason:?} in: {stderr}");
}

async fn with_withhold_fixture(scenario: fn(&WithholdFixture)) {
    let fixture = WithholdFixture::start().await;
    let joined = tokio::task::spawn_blocking(move || scenario(&fixture)).await;
    if let Err(error) = joined {
        panic!("scenario failed: {error}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn sha256_restricted_member_clones_without_withheld_blobs() {
    with_withhold_fixture(|fixture| {
        let carol = fixture.clone_as(CAROL, "carol", &[PARTIAL_CLONE_FILTER, "--no-checkout"]);
        assert_eq!(
            stdout_text(
                &fixture
                    .sandbox
                    .git(&carol, &["rev-parse", "--show-object-format"])
            ),
            "sha256"
        );
        assert!(fixture.is_missing_locally(&carol, &fixture.secret_blob));

        fixture.sandbox.git(
            &carol,
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
            .git(&carol, &["checkout", "--quiet", "main"]);
        assert_eq!(
            read_to_string(&carol.join("public/readme.txt")),
            "hello sha256\n"
        );
        assert!(!carol.join("config/billing/secret.txt").exists());
        assert!(!carol.join("config/billing/empty.txt").exists());

        assert_wire_capture_excludes_sha256(
            &fixture.capture,
            &[&fixture.secret_blob],
            &[b"SHA256_WITHHELD_BILLING_SECRET_98765"],
            &[&fixture.public_blob],
        );

        // Authorized member `alice` receives everything including withheld blobs.
        let alice = fixture.clone_as(ALICE, "alice", &[]);
        assert!(
            read_to_string(&alice.join("config/billing/secret.txt"))
                .contains("SHA256_WITHHELD_BILLING_SECRET_98765")
        );
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn sha256_moving_withheld_file_to_visible_path_fetches_on_pull() {
    with_withhold_fixture(|fixture| {
        let carol = fixture.clone_as(CAROL, "carol", &[PARTIAL_CLONE_FILTER, "--no-checkout"]);
        fixture.sandbox.git(
            &carol,
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
            .git(&carol, &["checkout", "--quiet", "main"]);
        assert!(fixture.is_missing_locally(&carol, &fixture.secret_blob));

        let alice = fixture.clone_as(ALICE, "alice", &[]);
        fixture.sandbox.git(
            &alice,
            &["mv", "config/billing/secret.txt", "public/secret.txt"],
        );
        fixture
            .sandbox
            .git(&alice, &["commit", "--quiet", "-m", "publish secret"]);
        fixture.git_as(ALICE, &alice, &["push", "--quiet", "origin", "main"]);

        fixture.git_as(
            CAROL,
            &carol,
            &["-c", "pull.ff=only", "pull", "--quiet", "origin", "main"],
        );
        assert!(!fixture.is_missing_locally(&carol, &fixture.secret_blob));
        assert_eq!(
            read_to_string(&carol.join("public/secret.txt")),
            "SHA256_WITHHELD_BILLING_SECRET_98765\n"
        );
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn sha256_restricted_member_cannot_modify_withheld_paths() {
    with_withhold_fixture(|fixture| {
        let carol = fixture.local_copy("carol");
        let before = fixture.server_main();

        write_file(&carol, "config/billing/secret.txt", "tampered\n");
        fixture
            .sandbox
            .git(&carol, &["commit", "--quiet", "-am", "edit withheld"]);
        let edit = fixture.try_git_as(CAROL, &carol, &["push", "scrim", "HEAD:main"]);
        assert_rejected(
            &edit,
            "do not have access to modify withheld path config/billing/secret.txt",
        );

        // A case variant is rejected too.
        fixture
            .sandbox
            .git(&carol, &["reset", "--quiet", "--hard", "origin/main"]);
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
            .git(&carol, &["commit", "--quiet", "-m", "case withheld"]);
        if let Err(error) = std::fs::remove_file(carol.join("new.txt")) {
            panic!("failed to remove new.txt: {error}");
        }
        let case = fixture.try_git_as(CAROL, &carol, &["push", "scrim", "HEAD:main"]);
        assert_rejected(&case, "withheld path CONFIG/billing/new.txt");

        assert_eq!(fixture.server_main(), before);

        // Changes to visible paths succeed.
        fixture
            .sandbox
            .git(&carol, &["reset", "--quiet", "--hard", "origin/main"]);
        write_file(&carol, "public/notes.txt", "visible notes\n");
        fixture.sandbox.git(&carol, &["add", "--all"]);
        fixture
            .sandbox
            .git(&carol, &["commit", "--quiet", "-m", "visible edit"]);
        fixture.git_as(CAROL, &carol, &["push", "--quiet", "scrim", "HEAD:main"]);
        assert_ne!(fixture.server_main(), before);
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn sha256_check6_rejects_republished_blob_but_allows_empty_blob() {
    with_withhold_fixture(|fixture| {
        let carol = fixture.local_copy("carol");
        let before = fixture.server_main();

        // 1. Republishing the withheld blob at a visible path is rejected.
        let cacheinfo = format!("100644,{},public/stolen.txt", fixture.secret_blob);
        fixture.sandbox.git(
            &carol,
            &["update-index", "--add", "--cacheinfo", &cacheinfo],
        );
        fixture
            .sandbox
            .git(&carol, &["commit", "--quiet", "-m", "copy blob"]);
        let copy = fixture.try_git_as(CAROL, &carol, &["push", "scrim", "HEAD:main"]);
        assert_rejected(&copy, "withheld from you");

        // 2. Copying the withheld subtree into a visible path is rejected.
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
            .git(&carol, &["commit", "--quiet", "-m", "copy tree"]);
        let tree = fixture.try_git_as(CAROL, &carol, &["push", "scrim", "HEAD:main"]);
        assert_rejected(&tree, "withheld from you");

        // 3. Pointing a ref straight at the 64-hex withheld blob OID is rejected.
        let blob_ref = format!("{}:refs/tags/stolen", fixture.secret_blob);
        let direct = fixture.try_git_as(CAROL, &carol, &["push", "scrim", &blob_ref]);
        assert_rejected(&direct, "withheld from you");
        assert_eq!(fixture.server_main(), before);

        // 4. Pushing an empty file at a visible path IS allowed even though
        // `config/billing/empty.txt` also holds `EMPTY_SHA256_BLOB_ID`.
        fixture
            .sandbox
            .git(&carol, &["reset", "--quiet", "--hard", "origin/main"]);
        write_file(&carol, "public/empty.txt", "");
        fixture.sandbox.git(&carol, &["add", "public/empty.txt"]);
        fixture
            .sandbox
            .git(&carol, &["commit", "--quiet", "-m", "add empty file"]);
        assert_eq!(
            stdout_text(
                &fixture
                    .sandbox
                    .git(&carol, &["rev-parse", "HEAD:public/empty.txt"])
            ),
            EMPTY_SHA256_BLOB_ID
        );
        fixture.git_as(CAROL, &carol, &["push", "--quiet", "scrim", "HEAD:main"]);
        assert_ne!(fixture.server_main(), before);
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn sha256_private_branches_hide_refs_and_block_direct_oid_fetches_and_pushes() {
    let sandbox = GitSandbox::new();
    let root = temp_dir("sha256-private-branches-root");
    let scratch = temp_dir("sha256-private-branches-scratch");
    let bare = root.path().join("team.git");
    init_bare_sha256(&sandbox, &bare);

    let seed = scratch.path().join("seed");
    init_work_sha256(&sandbox, &seed);
    write_file(&seed, "readme.txt", "public\n");
    sandbox.git(&seed, &["add", "--all"]);
    sandbox.git(&seed, &["commit", "--quiet", "-m", "main"]);
    let main_commit = stdout_text(&sandbox.git(&seed, &["rev-parse", "HEAD"]));
    assert_eq!(main_commit.len(), 64);
    sandbox.git(&seed, &["push", "--quiet", utf8_path(&bare), "main"]);

    sandbox.git(&seed, &["checkout", "--quiet", "-b", "private/secret"]);
    write_file(&seed, "secret.txt", "top secret branch\n");
    sandbox.git(&seed, &["add", "--all"]);
    sandbox.git(&seed, &["commit", "--quiet", "-m", "private commit"]);
    let private_commit = stdout_text(&sandbox.git(&seed, &["rev-parse", "HEAD"]));
    assert_eq!(private_commit.len(), 64);
    sandbox.git(
        &seed,
        &[
            "push",
            "--quiet",
            utf8_path(&bare),
            "HEAD:refs/heads/private/secret",
        ],
    );

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
    store.insert_group_membership(1, "core");
    let branch_rule = match BranchRule::new("refs/heads/private/*", ["core".to_owned()]) {
        Ok(rule) => rule,
        Err(error) => panic!("branch rule should be valid: {error}"),
    };
    store.insert_branch_rule("team.git", branch_rule);

    let router =
        scrim_server::router_with_policy_store(root.path().to_path_buf(), Arc::new(store.clone()));
    let base_url = spawn_server_with_store(root.path().to_path_buf(), Arc::new(store)).await;
    let url = format!("{base_url}/team.git");

    let carol_helper = sandbox.credential_helper_config(CAROL.name, CAROL.token);
    let alice_helper = sandbox.credential_helper_config(ALICE.name, ALICE.token);

    let clone_dir = scratch.path().join("carol-clone");
    let scratch_path = scratch.path().to_path_buf();

    let private_commit_clone = private_commit.clone();
    let carol_helper_clone = carol_helper.clone();
    let alice_helper_clone = alice_helper.clone();
    let url_clone = url.clone();
    let clone_dir_clone = clone_dir.clone();

    let blocking = tokio::task::spawn_blocking(move || {
        // 1. `ls-remote` as Carol hides `refs/heads/private/secret`; Alice sees it.
        let carol_ls = sandbox.git(
            &scratch_path,
            &["-c", &carol_helper_clone, "ls-remote", &url_clone],
        );
        let carol_refs = stdout_text(&carol_ls);
        assert!(carol_refs.contains("refs/heads/main"));
        assert!(
            !carol_refs.contains("refs/heads/private/secret"),
            "hidden ref leaked in ls-remote: {carol_refs}"
        );
        assert!(
            !carol_refs.contains(&private_commit_clone),
            "hidden commit OID leaked in ls-remote: {carol_refs}"
        );

        let alice_ls = sandbox.git(
            &scratch_path,
            &["-c", &alice_helper_clone, "ls-remote", &url_clone],
        );
        let alice_refs = stdout_text(&alice_ls);
        assert!(alice_refs.contains("refs/heads/private/secret"));
        assert!(alice_refs.contains(&private_commit_clone));

        // 2. Carol clones `team.git` and cannot fetch the hidden commit by its 64-hex OID.
        sandbox.git(
            &scratch_path,
            &[
                "-c",
                &carol_helper_clone,
                "clone",
                "--quiet",
                &url_clone,
                utf8_path(&clone_dir_clone),
            ],
        );
        let fetch_by_oid = sandbox.try_git(
            &clone_dir_clone,
            &[
                "-c",
                &carol_helper_clone,
                "fetch",
                "--quiet",
                "origin",
                &private_commit_clone,
            ],
        );
        assert!(
            !fetch_by_oid.status.success(),
            "fetching hidden 64-hex commit OID should fail"
        );
        let has_private_commit =
            sandbox.try_git(&clone_dir_clone, &["cat-file", "-e", &private_commit_clone]);
        assert!(
            !has_private_commit.status.success(),
            "hidden commit should not exist in Carol's clone"
        );

        // 3. Carol cannot push to a hidden ref.
        let push_hidden = sandbox.try_git(
            &clone_dir_clone,
            &[
                "-c",
                &carol_helper_clone,
                "push",
                "origin",
                "HEAD:refs/heads/private/new",
            ],
        );
        assert_rejected(
            &push_hidden,
            "do not have access to ref refs/heads/private/new",
        );

        let push_existing_hidden = sandbox.try_git(
            &clone_dir_clone,
            &[
                "-c",
                &carol_helper_clone,
                "push",
                "--force",
                "origin",
                "HEAD:refs/heads/private/secret",
            ],
        );
        assert_rejected(
            &push_existing_hidden,
            "do not have access to ref refs/heads/private/secret",
        );
    })
    .await;
    if let Err(error) = blocking {
        panic!("blocking task failed: {error}");
    }

    // 4. An empty SHA-256 pack attempting to point a visible ref at the hidden
    // 64-hex commit OID is rejected by Check 3.
    let mut empty_pack = b"PACK".to_vec();
    empty_pack.extend_from_slice(&2_u32.to_be_bytes());
    empty_pack.extend_from_slice(&0_u32.to_be_bytes());
    let trailer = Sha256::digest(&empty_pack);
    empty_pack.extend_from_slice(trailer.as_slice());

    let command = format!(
        "{SHA256_ZERO} {private_commit} refs/heads/stolen-branch\0report-status side-band-64k object-format=sha256\n"
    );
    let mut push_body = pkt_line_bytes(command.as_bytes());
    push_body.extend_from_slice(b"0000");
    push_body.extend_from_slice(&empty_pack);
    let request = match Request::builder()
        .method("POST")
        .uri("/team.git/git-receive-pack")
        .header(header::AUTHORIZATION, bearer_header(CAROL_TOKEN))
        .header(
            header::CONTENT_TYPE,
            "application/x-git-receive-pack-request",
        )
        .body(Body::from(push_body))
    {
        Ok(request) => request,
        Err(error) => panic!("failed to build request: {error}"),
    };
    let response = match router.oneshot(request).await {
        Ok(response) => response,
        Err(error) => panic!("router call failed: {error}"),
    };
    assert_eq!(response.status(), StatusCode::OK);
    let report = match response.into_body().collect().await {
        Ok(collected) => collected.to_bytes().to_vec(),
        Err(error) => panic!("failed to collect response body: {error}"),
    };
    let report = String::from_utf8_lossy(&report);
    assert!(
        report.contains("pre-receive hook declined"),
        "report: {report}"
    );
    assert!(
        report.contains("not reachable from visible refs"),
        "report: {report}"
    );
}
