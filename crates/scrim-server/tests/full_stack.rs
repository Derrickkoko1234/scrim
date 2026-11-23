//! Full-stack end to end: the server wired as `scrim-server serve` wires it in
//! production (PostgreSQL policy store behind the Redis policy cache, smart
//! HTTP and SSH sharing one hook directory), administered through the real
//! admin HTTP API, and exercised by real `git` and `ssh` clients acting as
//! members with different access.
//!
//! Ignored by default; run with both services available, e.g.
//! `DATABASE_URL=postgres://scrim:scrim@localhost/scrim
//! REDIS_URL=redis://localhost:6379 cargo test -p scrim-server --test
//! full_stack -- --ignored`.
//!
//! Every test gets a PostgreSQL schema of its own (so each can bootstrap its
//! own admin) and a repository path unique to it. The Redis policy cache keys
//! entries by member ID and repository path, and member IDs repeat across
//! schemas, so the unique repository path is what keeps concurrent tests from
//! reading one another's cached policies. The epoch key is shared: another
//! test's mutation only invalidates entries early, which is always safe.
//!
//! The cast, set up through the admin API:
//! - `alice` is in `core` and `billing`, `bob` only in `core`, `carol` in
//!   neither, and `stranger` holds an SSH key registered to nobody;
//! - the repository's branch rule hides `refs/heads/private/*` from everyone
//!   outside `core`, and its path rule withholds `config/billing/**` from
//!   everyone outside `billing`;
//! - `main` holds `public/readme.txt` and `config/billing/secret.txt`;
//!   `private/wip` adds one commit on top.

#![allow(clippy::question_mark)]

mod common;

use std::{
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use common::{GitSandbox, spawn_server_with_hook_dir};
use reqwest::Method;
use scrim_server::{
    CachedPolicyStore, PgPolicyStore, PolicyCacheBackend, PolicyStore, RedisPolicyCache,
    SharedHookDir, SshServerConfig, load_or_create_ssh_host_key, policy_cache_key, serve_ssh,
};
use secrecy::ExposeSecret;
use serde_json::{Value, json};
use sqlx::{
    PgPool,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use tempfile::TempDir;

/// The partial-clone filter `scrim clone` uses, spelled out.
const PARTIAL_CLONE_FILTER: &str = "--filter=blob:limit=2147483647";

/// Environment for git commands that must only look at local objects.
/// `GIT_NO_LAZY_FETCH` (Git 2.44+) stops a partial clone from fetching a
/// missing object; on older Git, `GIT_SSH_COMMAND=false` makes such a fetch
/// over SSH fail at once instead of spawning a plain `ssh` that can wait on a
/// host key prompt, and the credential-less HTTP fetch fails without a prompt.
const LOCAL_ONLY_ENV: [(&str, &str); 2] =
    [("GIT_NO_LAZY_FETCH", "1"), ("GIT_SSH_COMMAND", "false")];

const PROTOCOLS: [&str; 2] = ["0", "2"];

/// How a git client reaches the server.
#[derive(Clone, Copy, Debug)]
enum Transport {
    Http,
    Ssh,
}

const TRANSPORTS: [Transport; 2] = [Transport::Http, Transport::Ssh];

impl Transport {
    fn label(self) -> &'static str {
        match self {
            Transport::Http => "http",
            Transport::Ssh => "ssh",
        }
    }
}

/// A member a test acts as. Their SSH key file is `<name>_ed25519`.
#[derive(Clone, Copy)]
struct Member {
    name: &'static str,
}

const ALICE: Member = Member { name: "alice" };
const BOB: Member = Member { name: "bob" };
const CAROL: Member = Member { name: "carol" };
/// An SSH key registered to nobody.
const STRANGER: Member = Member { name: "stranger" };

/// Members created through the admin API and the groups they start in.
const CAST: [(Member, &[&str]); 3] = [
    (ALICE, &["core", "billing"]),
    (BOB, &["core"]),
    (CAROL, &[]),
];

/// What the admin API issued for a member.
struct Credentials {
    id: i64,
    token: String,
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

/// Reads an environment variable the test cannot run without.
fn required_env(name: &str) -> String {
    match std::env::var(name) {
        Ok(value) => value,
        Err(_) => panic!("{name} must be set to run the full-stack tests"),
    }
}

/// Returns a suffix no other test (in this or a concurrent run) uses; only
/// ASCII digits and `-`.
fn unique_suffix() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(elapsed) => elapsed.as_nanos(),
        Err(_) => 0,
    };
    format!(
        "{}-{nanos}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

/// Runs `future` to completion from a scenario's blocking thread.
fn block_on<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Handle::current().block_on(future)
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

/// A running production-shaped server plus everything a scenario needs to
/// administer and exercise it.
struct Stack {
    sandbox: GitSandbox,
    /// The server's repository root.
    root: TempDir,
    scratch: TempDir,
    keys: TempDir,
    http: reqwest::Client,
    http_url: String,
    ssh_port: u16,
    /// This test's repository path, such as `fs-123-456-0.git`.
    repo: String,
    admin_token: String,
    credentials: Vec<(&'static str, Credentials)>,
    /// The same Redis the server caches in, to observe the cache directly.
    redis: Arc<RedisPolicyCache>,
    pool: PgPool,
    admin_pool: PgPool,
    schema: String,
    main_commit: String,
    private_commit: String,
    secret_blob: String,
}

impl Stack {
    /// Builds the stack: schema, migrations, bootstrap admin, caching store,
    /// HTTP and SSH servers; then provisions groups, members, SSH keys, the
    /// repository and its rules through the admin API.
    async fn start() -> Self {
        let database_url = required_env("DATABASE_URL");
        let redis_url = required_env("REDIS_URL");
        let suffix = unique_suffix();

        // A schema of its own, so this test can bootstrap its own admin.
        let admin_pool = match PgPool::connect(&database_url).await {
            Ok(pool) => pool,
            Err(error) => panic!("failed to connect to PostgreSQL: {error}"),
        };
        // `unique_suffix` is digits and `-`, so this is a safe identifier.
        let schema = format!("scrim_full_stack_{}", suffix.replace('-', "_"));
        if let Err(error) = sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
            .execute(&admin_pool)
            .await
        {
            panic!("failed to create schema {schema}: {error}");
        }
        let options = match PgConnectOptions::from_str(&database_url) {
            Ok(options) => options.options([("search_path", schema.as_str())]),
            Err(error) => panic!("invalid DATABASE_URL: {error}"),
        };
        let pool = match PgPoolOptions::new().connect_with(options).await {
            Ok(pool) => pool,
            Err(error) => panic!("failed to connect to schema {schema}: {error}"),
        };
        let postgres_store = PgPolicyStore::from_pool(pool.clone());
        if let Err(error) = postgres_store.migrate().await {
            panic!("failed to migrate schema {schema}: {error}");
        }
        // The first admin, as `scrim-server bootstrap-admin` creates it.
        let admin_token = match postgres_store.bootstrap_admin("root", "bootstrap").await {
            Ok(created) => created.token.expose_secret().to_owned(),
            Err(error) => panic!("bootstrapping the admin failed: {error}"),
        };

        // The policy store exactly as `scrim-server serve` builds it.
        let mut store: Arc<dyn PolicyStore> = Arc::new(postgres_store);
        let redis = match RedisPolicyCache::connect(&redis_url).await {
            Ok(redis) => Arc::new(redis),
            Err(error) => panic!("cannot connect to the Redis policy cache: {error}"),
        };
        store = Arc::new(CachedPolicyStore::new(store, redis.clone()));

        let sandbox = GitSandbox::new();
        let root = temp_dir();
        let scratch = temp_dir();
        let keys = temp_dir();
        let repo_root = match root.path().canonicalize() {
            Ok(repo_root) => repo_root,
            Err(error) => panic!("failed to resolve the repo root: {error}"),
        };

        // One hook directory for both transports.
        let hook_dir = SharedHookDir::default();
        let http_url =
            spawn_server_with_hook_dir(repo_root.clone(), Arc::clone(&store), hook_dir.clone())
                .await;

        let host_key = match load_or_create_ssh_host_key(&keys.path().join("host_key")) {
            Ok(host_key) => host_key,
            Err(error) => panic!("creating the SSH host key failed: {error}"),
        };
        let ssh_listener = match tokio::net::TcpListener::bind("127.0.0.1:0").await {
            Ok(listener) => listener,
            Err(error) => panic!("failed to bind the SSH listener: {error}"),
        };
        let ssh_port = match ssh_listener.local_addr() {
            Ok(address) => address.port(),
            Err(error) => panic!("failed to read the SSH listener address: {error}"),
        };
        let ssh_config = SshServerConfig {
            repo_root,
            policy_store: store,
            host_key,
            hook_dir,
        };
        tokio::spawn(async move {
            if let Err(error) = serve_ssh(ssh_listener, ssh_config, std::future::pending()).await {
                panic!("SSH server failed: {error}");
            }
        });

        let http = match reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(30))
            .build()
        {
            Ok(http) => http,
            Err(error) => panic!("failed to build the HTTP client: {error}"),
        };

        let mut stack = Self {
            sandbox,
            root,
            scratch,
            keys,
            http,
            http_url,
            ssh_port,
            repo: format!("fs-{suffix}.git"),
            admin_token,
            credentials: Vec::new(),
            redis,
            pool,
            admin_pool,
            schema,
            main_commit: String::new(),
            private_commit: String::new(),
            secret_blob: String::new(),
        };
        stack.provision().await;
        stack
    }

    /// Creates groups, members, SSH keys, the repository (with its seed
    /// history) and its rules, all through the admin API.
    async fn provision(&mut self) {
        for group in ["core", "billing"] {
            self.api(Method::POST, "/groups", Some(json!({ "name": group })), 201)
                .await;
        }

        for (member, groups) in CAST {
            let created = self
                .api(
                    Method::POST,
                    "/members",
                    Some(json!({
                        "name": member.name,
                        "groups": groups,
                        "token_label": "full-stack",
                    })),
                    201,
                )
                .await;
            let token = match created["token"].as_str() {
                Some(token) => token.to_owned(),
                None => panic!("no token issued for {}: {created}", member.name),
            };
            let id = match created["member"]["id"].as_i64() {
                Some(id) => id,
                None => panic!("no member ID returned for {}: {created}", member.name),
            };
            self.credentials
                .push((member.name, Credentials { id, token }));

            let public_key = generate_ssh_key(self.keys.path(), &ssh_key_file(member));
            self.api(
                Method::POST,
                &format!("/members/{}/ssh-keys", member.name),
                Some(json!({ "public_key": public_key, "label": "laptop" })),
                201,
            )
            .await;
        }
        // Registered to nobody.
        generate_ssh_key(self.keys.path(), &ssh_key_file(STRANGER));

        // The server creates the bare repository; the seed history goes in
        // on disk, before any rule exists to hide it from the seeder.
        let registered = self
            .api(
                Method::POST,
                "/repositories",
                Some(json!({ "path": self.repo, "create_bare": true })),
                201,
            )
            .await;
        assert_eq!(registered["path"], json!(self.repo), "{registered}");
        self.seed_repository();

        self.api(
            Method::PUT,
            "/branch-rules",
            Some(json!({
                "repository": self.repo,
                "pattern": "refs/heads/private/*",
                "groups": ["core"],
            })),
            200,
        )
        .await;
        self.api(
            Method::PUT,
            "/path-rules",
            Some(json!({
                "repository": self.repo,
                "pattern": "config/billing/**",
                "groups": ["billing"],
            })),
            200,
        )
        .await;
    }

    /// Pushes `main` and `private/wip` into the server's bare repository
    /// directly, and records the IDs the scenarios look for.
    fn seed_repository(&mut self) {
        let bare = self.root.path().join(&self.repo);
        let seed = self.scratch.path().join("seed");
        if let Err(error) = std::fs::create_dir_all(&seed) {
            panic!("failed to create the seed dir: {error}");
        }
        let git = |args: &[&str]| self.sandbox.git(&seed, args);
        git(&["init", "--quiet", "--initial-branch=main"]);
        write_file(&seed, "public/readme.txt", "hello\n");
        write_file(
            &seed,
            "config/billing/secret.txt",
            "billing-api-key: do-not-share-0123456789\n",
        );
        git(&["add", "--all"]);
        git(&["commit", "--quiet", "-m", "base"]);
        let main_commit = stdout_text(&git(&["rev-parse", "HEAD"]));
        let secret_blob = stdout_text(&git(&["rev-parse", "HEAD:config/billing/secret.txt"]));
        git(&["checkout", "--quiet", "-b", "private/wip"]);
        write_file(&seed, "public/wip.txt", "work in progress\n");
        git(&["add", "--all"]);
        git(&["commit", "--quiet", "-m", "wip"]);
        let private_commit = stdout_text(&git(&["rev-parse", "HEAD"]));
        git(&["push", "--quiet", utf8_path(&bare), "main", "private/wip"]);
        self.main_commit = main_commit;
        self.secret_blob = secret_blob;
        self.private_commit = private_commit;
    }

    /// Drops the schema (skipped when a test panics, leaving it to inspect).
    async fn drop_schema(&self) {
        self.pool.close().await;
        if let Err(error) = sqlx::query(sqlx::AssertSqlSafe(format!(
            "DROP SCHEMA {} CASCADE",
            self.schema
        )))
        .execute(&self.admin_pool)
        .await
        {
            panic!("failed to drop schema {}: {error}", self.schema);
        }
    }

    // ---- the admin API ----

    /// Calls `<method> /api/v1<path>` as the admin, requires `expected` as the
    /// status, and returns the JSON answer.
    async fn api(&self, method: Method, path: &str, body: Option<Value>, expected: u16) -> Value {
        let url = format!("{}/api/v1{path}", self.http_url);
        let mut request = self
            .http
            .request(method.clone(), &url)
            .bearer_auth(&self.admin_token);
        if let Some(body) = body {
            request = request
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body.to_string());
        }
        let response = match request.send().await {
            Ok(response) => response,
            Err(error) => panic!("{method} {path} failed: {error}"),
        };
        let status = response.status().as_u16();
        let text = match response.text().await {
            Ok(text) => text,
            Err(error) => panic!("{method} {path}: cannot read the answer: {error}"),
        };
        assert_eq!(status, expected, "{method} {path}: {text}");
        match serde_json::from_str::<Value>(&text) {
            Ok(value) => value,
            Err(_) => Value::String(text),
        }
    }

    /// [`Stack::api`] for scenarios, which run on a blocking thread.
    fn admin(&self, method: Method, path: &str, body: Option<Value>, expected: u16) -> Value {
        block_on(self.api(method, path, body, expected))
    }

    /// The status of `GET <http_url>/<path>` without any credentials.
    fn anonymous_status(&self, path: &str) -> u16 {
        let url = format!("{}/{path}", self.http_url);
        match block_on(self.http.get(&url).send()) {
            Ok(response) => response.status().as_u16(),
            Err(error) => panic!("GET {path} failed: {error}"),
        }
    }

    fn credentials(&self, member: Member) -> &Credentials {
        match self
            .credentials
            .iter()
            .find(|(name, _)| *name == member.name)
        {
            Some((_, credentials)) => credentials,
            None => panic!("{} has no credentials", member.name),
        }
    }

    // ---- git clients ----

    fn url(&self, transport: Transport) -> String {
        match transport {
            Transport::Http => format!("{}/{}", self.http_url, self.repo),
            Transport::Ssh => format!("ssh://git@127.0.0.1:{}/{}", self.ssh_port, self.repo),
        }
    }

    /// The `ssh` options every client uses: only `member`'s key, no user
    /// configuration, no agent, no host key prompts, never interactive.
    fn ssh_options(&self, member: Member) -> Vec<String> {
        let key = self.keys.path().join(ssh_key_file(member));
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

    /// Runs `git -c protocol.version=<protocol> <args>` in `dir` as `member`
    /// over `transport`, without asserting success.
    fn try_git_as(
        &self,
        transport: Transport,
        member: Member,
        protocol: &str,
        dir: &Path,
        args: &[&str],
    ) -> Output {
        let protocol_setting = format!("protocol.version={protocol}");
        match transport {
            Transport::Http => {
                let credential_helper = self
                    .sandbox
                    .credential_helper_config(member.name, &self.credentials(member).token);
                let mut full_args = vec!["-c", &credential_helper, "-c", &protocol_setting];
                full_args.extend_from_slice(args);
                self.sandbox.try_git(dir, &full_args)
            }
            Transport::Ssh => {
                let ssh_command = format!(
                    "ssh {}",
                    self.ssh_options(member)
                        .iter()
                        .map(|option| format!("'{option}'"))
                        .collect::<Vec<_>>()
                        .join(" ")
                );
                let mut full_args = vec!["-c", &protocol_setting];
                full_args.extend_from_slice(args);
                self.sandbox.try_git_with_env(
                    dir,
                    &full_args,
                    &[
                        ("GIT_SSH_COMMAND", ssh_command.as_str()),
                        ("GIT_SSH_VARIANT", "ssh"),
                    ],
                )
            }
        }
    }

    fn git_as(
        &self,
        transport: Transport,
        member: Member,
        protocol: &str,
        dir: &Path,
        args: &[&str],
    ) -> Output {
        let output = self.try_git_as(transport, member, protocol, dir, args);
        assert!(
            output.status.success(),
            "git {args:?} as {} over {} failed: {}",
            member.name,
            transport.label(),
            stderr_text(&output)
        );
        output
    }

    /// Runs a git command that must not touch the network (see
    /// [`LOCAL_ONLY_ENV`]) without asserting success.
    fn try_local_git(&self, dir: &Path, args: &[&str]) -> Output {
        self.sandbox.try_git_with_env(dir, args, &LOCAL_ONLY_ENV)
    }

    /// Like [`Stack::try_local_git`], panicking on failure.
    fn local_git(&self, dir: &Path, args: &[&str]) -> Output {
        self.sandbox.git_with_env(dir, args, &LOCAL_ONLY_ENV)
    }

    fn ls_remote(&self, transport: Transport, member: Member, protocol: &str) -> String {
        let output = self.git_as(
            transport,
            member,
            protocol,
            self.scratch.path(),
            &["ls-remote", &self.url(transport)],
        );
        stdout_text(&output)
    }

    /// Clones the repository into `<scratch>/<name>` with extra `options`.
    fn clone_as(
        &self,
        transport: Transport,
        member: Member,
        protocol: &str,
        name: &str,
        options: &[&str],
    ) -> PathBuf {
        let url = self.url(transport);
        let mut args = vec!["clone", "--quiet"];
        args.extend_from_slice(options);
        args.push(&url);
        args.push(name);
        self.git_as(transport, member, protocol, self.scratch.path(), &args);
        self.scratch.path().join(name)
    }

    /// An empty local repository to fetch single objects into.
    fn empty_repo(&self, name: &str) -> PathBuf {
        let dir = self.scratch.path().join(name);
        if let Err(error) = std::fs::create_dir_all(&dir) {
            panic!("failed to create {}: {error}", dir.display());
        }
        self.local_git(&dir, &["init", "--quiet", "--initial-branch=main"]);
        dir
    }

    /// Where `ref_name` points on the server's disk, if it exists.
    fn server_ref(&self, ref_name: &str) -> Option<String> {
        let output = self.sandbox.try_git(
            &self.root.path().join(&self.repo),
            &["rev-parse", "--verify", "--quiet", ref_name],
        );
        output.status.success().then(|| stdout_text(&output))
    }

    /// Whether `object` is a missing (promised, never received) object of
    /// the partial clone at `dir`.
    fn is_missing_locally(&self, dir: &Path, object: &str) -> bool {
        let output = self.local_git(dir, &["rev-list", "--objects", "--missing=print", "--all"]);
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .any(|line| line == format!("?{object}"))
    }

    /// Commits `contents` as `path` in the clone at `dir`.
    fn commit_file(&self, dir: &Path, path: &str, contents: &str, message: &str) {
        write_file(dir, path, contents);
        self.local_git(dir, &["add", "--all"]);
        self.local_git(dir, &["commit", "--quiet", "-m", message]);
    }

    // ---- the Redis policy cache ----

    fn redis_epoch(&self) -> u64 {
        match block_on(self.redis.get_epoch()) {
            Ok(epoch) => epoch,
            Err(error) => panic!("cannot read the Redis policy epoch: {error}"),
        }
    }

    /// Asserts that a request by `member` leaves their policy for this
    /// repository in Redis, proving the cache is in the request path rather
    /// than silently bypassed. Retries because another test's mutation can
    /// advance the shared epoch between the request and the lookup.
    fn assert_policy_cached(&self, member: Member) {
        let member_id = self.credentials(member).id;
        for _ in 0..10 {
            self.ls_remote(Transport::Http, member, "2");
            let key = policy_cache_key(self.redis_epoch(), member_id, &self.repo);
            match block_on(self.redis.get_bytes(&key)) {
                Ok(Some(_)) => return,
                Ok(None) => {}
                Err(error) => panic!("cannot read the Redis policy cache: {error}"),
            }
        }
        panic!("{}'s policy never appeared in the Redis cache", member.name);
    }
}

fn ssh_key_file(member: Member) -> String {
    format!("{}_ed25519", member.name)
}

/// Runs `scenario` on a blocking thread so the synchronous `git` and `ssh`
/// processes never stall the server's runtime, then drops the test schema.
async fn with_stack(scenario: fn(&Stack)) {
    let stack = Arc::new(Stack::start().await);
    let for_scenario = Arc::clone(&stack);
    let joined = tokio::task::spawn_blocking(move || scenario(&for_scenario)).await;
    if let Err(error) = joined {
        panic!("scenario failed: {error}");
    }
    stack.drop_schema().await;
}

/// Asserts that `output` is a failed git command and returns its stderr.
fn assert_failed(output: &Output, what: &str) -> String {
    let stderr = stderr_text(output);
    assert!(!output.status.success(), "{what} succeeded: {stderr}");
    stderr
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires DATABASE_URL and REDIS_URL"]
async fn authorized_members_read_and_write_over_http_and_ssh() {
    with_stack(|stack| {
        // Without credentials, or with an unregistered key, nothing is served.
        assert_eq!(
            stack.anonymous_status(&format!("{}/info/refs?service=git-upload-pack", stack.repo)),
            401
        );
        let stranger = stack.try_git_as(
            Transport::Ssh,
            STRANGER,
            "2",
            stack.scratch.path(),
            &["ls-remote", &stack.url(Transport::Ssh)],
        );
        let stderr = assert_failed(&stranger, "an unregistered SSH key");
        assert!(stderr.contains("Permission denied"), "{stderr}");

        for transport in TRANSPORTS {
            let label = transport.label();

            // `alice` is in every group: she gets everything, withheld blob
            // and private branch included, and may write.
            let alice = stack.clone_as(transport, ALICE, "2", &format!("alice-{label}"), &[]);
            assert!(alice.join("config/billing/secret.txt").is_file());
            stack.local_git(&alice, &["cat-file", "-e", &stack.private_commit]);
            stack.commit_file(
                &alice,
                &format!("public/notes-{label}.txt"),
                "notes\n",
                "notes",
            );
            let pushed = stdout_text(&stack.local_git(&alice, &["rev-parse", "HEAD"]));
            stack.git_as(
                transport,
                ALICE,
                "0",
                &alice,
                &["push", "--quiet", "origin", "main"],
            );
            assert_eq!(stack.server_ref("refs/heads/main"), Some(pushed.clone()));
            let private_ref = format!("refs/heads/private/alice-{label}");
            stack.git_as(
                transport,
                ALICE,
                "2",
                &alice,
                &["push", "--quiet", "origin", &format!("HEAD:{private_ref}")],
            );
            assert_eq!(stack.server_ref(&private_ref), Some(pushed.clone()));

            // `bob` is in `core` only: the private branches, but not the
            // billing blob.
            for protocol in PROTOCOLS {
                let refs = stack.ls_remote(transport, BOB, protocol);
                assert!(refs.contains(&private_ref), "{refs}");
                assert!(refs.contains("refs/heads/private/wip"), "{refs}");
            }
            let bob = stack.clone_as(
                transport,
                BOB,
                "0",
                &format!("bob-{label}"),
                &[PARTIAL_CLONE_FILTER, "--no-checkout"],
            );
            assert!(stack.is_missing_locally(&bob, &stack.secret_blob));
            stack.local_git(&bob, &["cat-file", "-e", &stack.private_commit]);

            // `carol` is in no group: neither.
            let refs = stack.ls_remote(transport, CAROL, "2");
            assert!(!refs.contains("private"), "{refs}");
            assert!(refs.contains(&pushed), "{refs}");
        }
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires DATABASE_URL and REDIS_URL"]
async fn hidden_refs_are_not_listed_to_non_members_over_http_and_ssh() {
    with_stack(|stack| {
        for transport in TRANSPORTS {
            for protocol in PROTOCOLS {
                for member in [ALICE, BOB] {
                    let refs = stack.ls_remote(transport, member, protocol);
                    assert!(refs.contains("refs/heads/main"), "{refs}");
                    assert!(refs.contains("refs/heads/private/wip"), "{refs}");
                    assert!(refs.contains(&stack.private_commit), "{refs}");
                }
                let refs = stack.ls_remote(transport, CAROL, protocol);
                assert!(refs.contains("refs/heads/main"), "{refs}");
                assert!(!refs.contains("private"), "{refs}");
                assert!(!refs.contains(&stack.private_commit), "{refs}");
            }
        }
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires DATABASE_URL and REDIS_URL"]
async fn hidden_commits_cannot_be_fetched_by_hash_over_http_and_ssh() {
    with_stack(|stack| {
        for transport in TRANSPORTS {
            for protocol in PROTOCOLS {
                let dir =
                    stack.empty_repo(&format!("carol-by-id-{}-v{protocol}", transport.label()));
                let by_id = stack.try_git_as(
                    transport,
                    CAROL,
                    protocol,
                    &dir,
                    &[
                        "fetch",
                        PARTIAL_CLONE_FILTER,
                        &stack.url(transport),
                        &stack.private_commit,
                    ],
                );
                let stderr = assert_failed(&by_id, "fetching the private commit by ID");
                assert!(
                    stderr.contains("unadvertised object") || stderr.contains("not our ref"),
                    "carol fetched the private commit by ID over {} under protocol {protocol}: \
                     {stderr}",
                    transport.label()
                );
                let has_object =
                    stack.try_local_git(&dir, &["cat-file", "-e", &stack.private_commit]);
                assert!(
                    !has_object.status.success(),
                    "the private commit reached carol's repository"
                );
            }
        }
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires DATABASE_URL and REDIS_URL"]
async fn non_members_cannot_push_create_or_delete_hidden_refs() {
    with_stack(|stack| {
        for transport in TRANSPORTS {
            let label = transport.label();
            // A partial clone, since `carol` cannot receive the billing blob.
            let carol = stack.clone_as(
                transport,
                CAROL,
                "0",
                &format!("carol-push-{label}"),
                &[PARTIAL_CLONE_FILTER, "--no-checkout"],
            );

            // Creating a hidden ref.
            let created = stack.try_git_as(
                transport,
                CAROL,
                "0",
                &carol,
                &["push", "origin", "origin/main:refs/heads/private/carol"],
            );
            let stderr = assert_failed(&created, "creating a hidden ref");
            assert!(stderr.contains("hidden ref"), "{stderr}");
            assert_eq!(stack.server_ref("refs/heads/private/carol"), None);

            // Overwriting an existing hidden ref.
            let updated = stack.try_git_as(
                transport,
                CAROL,
                "0",
                &carol,
                &["push", "origin", "+origin/main:refs/heads/private/wip"],
            );
            let stderr = assert_failed(&updated, "overwriting a hidden ref");
            assert!(stderr.contains("hidden ref"), "{stderr}");
            assert_eq!(
                stack.server_ref("refs/heads/private/wip"),
                Some(stack.private_commit.clone())
            );

            // Deleting an existing hidden ref.
            let deleted = stack.try_git_as(
                transport,
                CAROL,
                "0",
                &carol,
                &["push", "origin", "--delete", "refs/heads/private/wip"],
            );
            assert_failed(&deleted, "deleting a hidden ref");
            assert_eq!(
                stack.server_ref("refs/heads/private/wip"),
                Some(stack.private_commit.clone())
            );

            // `bob` is in `core`, so he may create a private ref; `carol` can
            // then neither overwrite nor delete it.
            let bob = stack.clone_as(
                transport,
                BOB,
                "0",
                &format!("bob-push-{label}"),
                &[PARTIAL_CLONE_FILTER, "--no-checkout"],
            );
            let bobs_ref = format!("refs/heads/private/bob-{label}");
            stack.git_as(
                transport,
                BOB,
                "0",
                &bob,
                &[
                    "push",
                    "--quiet",
                    "origin",
                    &format!("origin/main:{bobs_ref}"),
                ],
            );
            assert_eq!(stack.server_ref(&bobs_ref), Some(stack.main_commit.clone()));
            let deleted = stack.try_git_as(
                transport,
                CAROL,
                "0",
                &carol,
                &["push", "origin", "--delete", &bobs_ref],
            );
            assert_failed(&deleted, "deleting bob's private ref");
            assert_eq!(stack.server_ref(&bobs_ref), Some(stack.main_commit.clone()));
        }
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires DATABASE_URL and REDIS_URL"]
async fn merging_a_private_branch_into_a_visible_branch_is_rejected() {
    with_stack(|stack| {
        for transport in TRANSPORTS {
            let label = transport.label();
            let alice = stack.clone_as(transport, ALICE, "2", &format!("alice-leak-{label}"), &[]);
            let main_before = stack.server_ref("refs/heads/main");
            assert_eq!(main_before.as_deref(), Some(stack.main_commit.as_str()));

            stack.local_git(
                &alice,
                &[
                    "merge",
                    "--quiet",
                    "--no-ff",
                    "--no-edit",
                    "origin/private/wip",
                ],
            );
            let leak = stack.try_git_as(
                transport,
                ALICE,
                "0",
                &alice,
                &["push", "origin", "HEAD:main"],
            );
            let stderr = assert_failed(&leak, "the merge-leak push");
            assert!(stderr.contains("squash"), "{stderr}");
            assert!(!stderr.contains("private/wip"), "{stderr}");
            assert_eq!(stack.server_ref("refs/heads/main"), main_before);

            // So is fast-forwarding a new public branch to the private tip.
            let copy = stack.try_git_as(
                transport,
                ALICE,
                "0",
                &alice,
                &[
                    "push",
                    "origin",
                    "refs/remotes/origin/private/wip:refs/heads/public-copy",
                ],
            );
            assert_failed(&copy, "publishing the private tip");
            assert_eq!(stack.server_ref("refs/heads/public-copy"), None);

            // A squash merge makes new commits and is accepted.
            stack.local_git(
                &alice,
                &["checkout", "--quiet", "-b", "squashed", "origin/main"],
            );
            stack.local_git(
                &alice,
                &["merge", "--quiet", "--squash", "origin/private/wip"],
            );
            stack.local_git(&alice, &["commit", "--quiet", "-m", "squashed wip"]);
            let squashed = stdout_text(&stack.local_git(&alice, &["rev-parse", "HEAD"]));
            let squashed_ref = format!("refs/heads/squashed-{label}");
            stack.git_as(
                transport,
                ALICE,
                "0",
                &alice,
                &["push", "--quiet", "origin", &format!("HEAD:{squashed_ref}")],
            );
            assert_eq!(stack.server_ref(&squashed_ref), Some(squashed));
        }
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires DATABASE_URL and REDIS_URL"]
async fn plaintext_env_files_are_rejected_over_http_and_ssh() {
    with_stack(|stack| {
        for transport in TRANSPORTS {
            let label = transport.label();
            let alice = stack.clone_as(transport, ALICE, "2", &format!("alice-env-{label}"), &[]);

            stack.local_git(
                &alice,
                &["checkout", "--quiet", "-b", "dotenv", "origin/main"],
            );
            stack.commit_file(&alice, ".env", "DB_PASS=plaintext\n", "add dotenv");
            let dotenv_ref = format!("refs/heads/dotenv-{label}");
            let rejected = stack.try_git_as(
                transport,
                ALICE,
                "0",
                &alice,
                &["push", "origin", &format!("HEAD:{dotenv_ref}")],
            );
            let stderr = assert_failed(&rejected, "pushing a plaintext .env");
            assert!(stderr.contains(".env"), "{stderr}");
            assert_eq!(stack.server_ref(&dotenv_ref), None);

            // A template without secrets is fine.
            stack.local_git(
                &alice,
                &["checkout", "--quiet", "-b", "template", "origin/main"],
            );
            stack.commit_file(&alice, ".env.example", "DB_PASS=\n", "add dotenv template");
            let template_ref = format!("refs/heads/template-{label}");
            stack.git_as(
                transport,
                ALICE,
                "0",
                &alice,
                &["push", "--quiet", "origin", &format!("HEAD:{template_ref}")],
            );
            assert!(stack.server_ref(&template_ref).is_some());
        }
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires DATABASE_URL and REDIS_URL"]
async fn withheld_blobs_are_never_served_to_non_members_over_http_and_ssh() {
    with_stack(|stack| {
        for transport in TRANSPORTS {
            let label = transport.label();

            // A plain clone cannot complete without the withheld blob, and
            // says how to clone instead.
            let plain = stack.try_git_as(
                transport,
                CAROL,
                "2",
                stack.scratch.path(),
                &[
                    "clone",
                    "--quiet",
                    &stack.url(transport),
                    &format!("carol-plain-{label}"),
                ],
            );
            let stderr = assert_failed(&plain, "a plain clone without the billing group");
            assert!(stderr.contains("scrim clone"), "{stderr}");

            // `bob` (in `core`, not `billing`) and `carol` (in no group) are
            // both held back from the blob, under both protocol versions.
            for member in [BOB, CAROL] {
                for protocol in PROTOCOLS {
                    let name = format!("{}-{label}-v{protocol}", member.name);
                    let clone = stack.clone_as(
                        transport,
                        member,
                        protocol,
                        &name,
                        &[PARTIAL_CLONE_FILTER, "--no-checkout"],
                    );
                    assert!(
                        stack.is_missing_locally(&clone, &stack.secret_blob),
                        "{name} received the withheld blob"
                    );
                    // History and trees are complete.
                    stack.local_git(&clone, &["cat-file", "-e", &stack.main_commit]);
                    stack.local_git(&clone, &["cat-file", "-e", "origin/main:config/billing"]);

                    stack.local_git(
                        &clone,
                        &[
                            "sparse-checkout",
                            "set",
                            "--no-cone",
                            "/*",
                            "!/config/billing/",
                        ],
                    );
                    stack.local_git(&clone, &["checkout", "--quiet", "main"]);
                    assert!(clone.join("public/readme.txt").is_file());
                    assert!(!clone.join("config/billing/secret.txt").exists());
                    let status = stack.local_git(&clone, &["status", "--porcelain"]);
                    assert_eq!(stdout_text(&status), "");

                    // Nor can the blob be fetched by its ID.
                    let by_id = stack.try_git_as(
                        transport,
                        member,
                        protocol,
                        &clone,
                        &["fetch", "--quiet", "origin", &stack.secret_blob],
                    );
                    assert_failed(&by_id, "fetching the withheld blob by ID");
                    assert!(
                        stack.is_missing_locally(&clone, &stack.secret_blob),
                        "{name} received the withheld blob by ID"
                    );
                }
            }

            // A filter that could probe blob IDs is refused outright.
            let probe = stack.try_git_as(
                transport,
                CAROL,
                "2",
                stack.scratch.path(),
                &[
                    "clone",
                    "--quiet",
                    "--no-checkout",
                    &format!("--filter=sparse:oid={}", stack.secret_blob),
                    &stack.url(transport),
                    &format!("carol-probe-{label}"),
                ],
            );
            assert_failed(&probe, "a sparse:oid filter clone");

            // `alice` is in `billing` and receives it.
            let alice = stack.clone_as(transport, ALICE, "2", &format!("alice-blob-{label}"), &[]);
            assert!(alice.join("config/billing/secret.txt").is_file());
        }
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires DATABASE_URL and REDIS_URL"]
async fn access_changes_apply_to_the_very_next_fetch() {
    with_stack(|stack| {
        let sees_private = |transport: Transport, member: Member| {
            stack
                .ls_remote(transport, member, "2")
                .contains("refs/heads/private/wip")
        };

        // Baseline, and proof that Redis really holds the policy.
        for transport in TRANSPORTS {
            assert!(sees_private(transport, BOB));
        }
        stack.assert_policy_cached(BOB);

        // Removing `bob` from `core` bumps the shared epoch, and his very
        // next request over either transport sees the new policy.
        let epoch_before = stack.redis_epoch();
        let removed = stack.admin(Method::DELETE, "/groups/core/members/bob", None, 200);
        assert_eq!(removed["removed"], json!(true), "{removed}");
        assert!(
            stack.redis_epoch() > epoch_before,
            "the policy cache epoch did not advance"
        );
        for transport in TRANSPORTS {
            assert!(!sees_private(transport, BOB), "bob still sees private/wip");
            assert!(sees_private(transport, ALICE));
        }

        // Adding him back restores it at once.
        let added = stack.admin(
            Method::POST,
            "/groups/core/members",
            Some(json!({ "member": "bob" })),
            200,
        );
        assert_eq!(added["added"], json!(true), "{added}");
        for transport in TRANSPORTS {
            assert!(sees_private(transport, BOB));
        }

        // Changing the branch rule applies at once too: only `billing` may
        // see private branches, then `core` again.
        let set_rule = |groups: Value| {
            stack.admin(
                Method::PUT,
                "/branch-rules",
                Some(json!({
                    "repository": stack.repo,
                    "pattern": "refs/heads/private/*",
                    "groups": groups,
                })),
                200,
            );
        };
        set_rule(json!(["billing"]));
        for transport in TRANSPORTS {
            assert!(!sees_private(transport, BOB), "bob still sees private/wip");
            assert!(sees_private(transport, ALICE));
        }
        set_rule(json!(["core"]));
        for transport in TRANSPORTS {
            assert!(sees_private(transport, BOB));
        }

        // Path rules follow the same epoch: while in `billing`, `alice`'s
        // plain clone carries the secret; the moment she leaves, it is
        // refused.
        for transport in TRANSPORTS {
            let name = format!("alice-in-billing-{}", transport.label());
            let alice = stack.clone_as(transport, ALICE, "2", &name, &[]);
            assert!(alice.join("config/billing/secret.txt").is_file());
        }
        let removed = stack.admin(Method::DELETE, "/groups/billing/members/alice", None, 200);
        assert_eq!(removed["removed"], json!(true), "{removed}");
        for transport in TRANSPORTS {
            let name = format!("alice-left-billing-{}", transport.label());
            let plain = stack.try_git_as(
                transport,
                ALICE,
                "2",
                stack.scratch.path(),
                &["clone", "--quiet", &stack.url(transport), &name],
            );
            let stderr = assert_failed(&plain, "a plain clone after leaving billing");
            assert!(stderr.contains("scrim clone"), "{stderr}");
        }

        // Revoking a member ends their access over both transports.
        let revoked = stack.admin(Method::DELETE, "/members/bob", None, 200);
        assert_eq!(revoked["revoked"], json!(true), "{revoked}");
        for transport in TRANSPORTS {
            let denied = stack.try_git_as(
                transport,
                BOB,
                "2",
                stack.scratch.path(),
                &["ls-remote", &stack.url(transport)],
            );
            assert_failed(&denied, "a revoked member's ls-remote");
        }
    })
    .await;
}
