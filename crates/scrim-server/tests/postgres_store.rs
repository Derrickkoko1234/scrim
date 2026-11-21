//! `PgPolicyStore` against a real PostgreSQL server.
//!
//! Ignored by default; run with `DATABASE_URL` set, e.g.
//! `DATABASE_URL=postgres://postgres:postgres@localhost/scrim cargo test -p
//! scrim-server --test postgres_store -- --ignored`. Every test seeds rows with
//! names unique to the test run, so tests can share one database and run in
//! parallel.

mod common;

use std::{
    collections::BTreeSet,
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use common::{GitSandbox, bearer_header};
use http_body_util::BodyExt;
use scrim_server::{
    AuditLogEntry, AuthenticatedMember, CreateMemberRequest, CreatedMember, PgPolicyStore,
    PolicyStore, PolicyStoreError,
};
use secrecy::ExposeSecret;
use sha2::{Digest, Sha256};
use sqlx::{
    PgPool,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use tempfile::TempDir;
use tower::ServiceExt;

/// Returns a suffix no other test (in this or a concurrent run) uses.
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

fn token_hash(token: &str) -> [u8; 32] {
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&Sha256::digest(token.as_bytes()));
    hash
}

fn group_set(groups: &[&str]) -> BTreeSet<String> {
    groups.iter().map(|group| (*group).to_owned()).collect()
}

/// Connects to `DATABASE_URL`, applies the migrations, and returns a pool for
/// seeding alongside the store under test.
async fn connect() -> (PgPool, PgPolicyStore) {
    let database_url = match std::env::var("DATABASE_URL") {
        Ok(database_url) => database_url,
        Err(_) => panic!("DATABASE_URL must point to PostgreSQL to run these tests"),
    };
    let store = match PgPolicyStore::connect(&database_url).await {
        Ok(store) => store,
        Err(error) => panic!("failed to connect: {error}"),
    };
    if let Err(error) = store.migrate().await {
        panic!("failed to migrate: {error}");
    }
    let pool = match PgPool::connect(&database_url).await {
        Ok(pool) => pool,
        Err(error) => panic!("failed to open seeding pool: {error}"),
    };
    (pool, store)
}

/// Runs a seeding `INSERT ... RETURNING id` that binds one text value.
async fn insert_named(pool: &PgPool, sql: &'static str, name: &str) -> i64 {
    match sqlx::query_scalar::<_, i64>(sql)
        .bind(name)
        .fetch_one(pool)
        .await
    {
        Ok(id) => id,
        Err(error) => panic!("seeding failed ({sql}): {error}"),
    }
}

async fn insert_member(pool: &PgPool, name: &str) -> i64 {
    insert_named(
        pool,
        "INSERT INTO members (name) VALUES ($1) RETURNING id",
        name,
    )
    .await
}

async fn insert_group(pool: &PgPool, name: &str) -> i64 {
    insert_named(
        pool,
        "INSERT INTO groups (name) VALUES ($1) RETURNING id",
        name,
    )
    .await
}

async fn insert_repository(pool: &PgPool, path: &str) -> i64 {
    insert_named(
        pool,
        "INSERT INTO repositories (path) VALUES ($1) RETURNING id",
        path,
    )
    .await
}

async fn insert_token(pool: &PgPool, member_id: i64, token: &str) -> i64 {
    match sqlx::query_scalar::<_, i64>(
        "INSERT INTO member_tokens (member_id, token_hash) VALUES ($1, $2) RETURNING id",
    )
    .bind(member_id)
    .bind(token_hash(token).as_slice())
    .fetch_one(pool)
    .await
    {
        Ok(id) => id,
        Err(error) => panic!("failed to insert token: {error}"),
    }
}

/// Runs `sql` (one `BIGINT` parameter, no result), e.g. a revocation.
async fn execute_with_id(pool: &PgPool, sql: &'static str, id: i64) {
    if let Err(error) = sqlx::query(sql).bind(id).execute(pool).await {
        panic!("seeding failed ({sql}): {error}");
    }
}

async fn insert_membership(pool: &PgPool, group_id: i64, member_id: i64) {
    if let Err(error) =
        sqlx::query("INSERT INTO group_memberships (group_id, member_id) VALUES ($1, $2)")
            .bind(group_id)
            .bind(member_id)
            .execute(pool)
            .await
    {
        panic!("failed to insert membership: {error}");
    }
}

/// Inserts a `branch_rules` row without granting it to any group.
async fn try_insert_rule_row(
    pool: &PgPool,
    repository_id: i64,
    ref_glob: &str,
) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar::<_, i64>(
        "INSERT INTO branch_rules (repository_id, ref_glob) VALUES ($1, $2) RETURNING id",
    )
    .bind(repository_id)
    .bind(ref_glob)
    .fetch_one(pool)
    .await
}

/// Adds rule `ref_glob` to `repository_id`, granting it to `group_ids`.
async fn insert_rule(pool: &PgPool, repository_id: i64, ref_glob: &str, group_ids: &[i64]) {
    let rule_id = match try_insert_rule_row(pool, repository_id, ref_glob).await {
        Ok(id) => id,
        Err(error) => panic!("failed to insert rule {ref_glob}: {error}"),
    };
    for group_id in group_ids {
        if let Err(error) =
            sqlx::query("INSERT INTO branch_rule_groups (branch_rule_id, group_id) VALUES ($1, $2)")
                .bind(rule_id)
                .bind(group_id)
                .execute(pool)
                .await
        {
            panic!("failed to grant rule {ref_glob}: {error}");
        }
    }
}

async fn authenticate(store: &PgPolicyStore, token: &str) -> Option<AuthenticatedMember> {
    match store.authenticate_token_hash(&token_hash(token)).await {
        Ok(member) => member,
        Err(error) => panic!("authentication query failed: {error}"),
    }
}

#[tokio::test]
#[ignore = "requires DATABASE_URL pointing to PostgreSQL"]
async fn authenticates_only_active_tokens_of_active_members() {
    let (pool, store) = connect().await;
    let suffix = unique_suffix();

    let member_name = format!("member-{suffix}");
    let member_id = insert_member(&pool, &member_name).await;
    let active_token = format!("active-{suffix}");
    insert_token(&pool, member_id, &active_token).await;
    let revoked_token = format!("revoked-{suffix}");
    let revoked_token_id = insert_token(&pool, member_id, &revoked_token).await;
    execute_with_id(
        &pool,
        "UPDATE member_tokens SET revoked_at = NOW() WHERE id = $1",
        revoked_token_id,
    )
    .await;

    let revoked_member_id = insert_member(&pool, &format!("revoked-member-{suffix}")).await;
    let revoked_member_token = format!("revoked-member-token-{suffix}");
    insert_token(&pool, revoked_member_id, &revoked_member_token).await;
    execute_with_id(
        &pool,
        "UPDATE members SET revoked_at = NOW() WHERE id = $1",
        revoked_member_id,
    )
    .await;

    assert_eq!(
        authenticate(&store, &active_token).await,
        Some(AuthenticatedMember {
            id: member_id,
            name: member_name,
            is_admin: false,
        })
    );
    assert_eq!(authenticate(&store, &format!("wrong-{suffix}")).await, None);
    assert_eq!(authenticate(&store, &revoked_token).await, None);
    assert_eq!(authenticate(&store, &revoked_member_token).await, None);
}

#[tokio::test]
#[ignore = "requires DATABASE_URL pointing to PostgreSQL"]
async fn loads_groups_and_fail_closed_branch_rules() {
    let (pool, store) = connect().await;
    let suffix = unique_suffix();
    let core = format!("core-{suffix}");
    let security = format!("security-{suffix}");

    let member_id = insert_member(&pool, &format!("member-{suffix}")).await;
    let core_id = insert_group(&pool, &core).await;
    let security_id = insert_group(&pool, &security).await;
    insert_group(&pool, &format!("unrelated-{suffix}")).await;
    insert_membership(&pool, core_id, member_id).await;
    insert_membership(&pool, security_id, member_id).await;

    let repo_key = format!("team-{suffix}.git");
    let repository_id = insert_repository(&pool, &repo_key).await;
    insert_rule(&pool, repository_id, "refs/heads/private/*", &[core_id]).await;
    insert_rule(&pool, repository_id, "refs/heads/*/secret", &[security_id]).await;
    // A rule granted to no group must hide its refs from everyone.
    insert_rule(&pool, repository_id, "refs/heads/locked/*", &[]).await;

    let policy = match store.load_member_repo_policy(member_id, &repo_key).await {
        Ok(policy) => policy,
        Err(error) => panic!("failed to load policy: {error}"),
    };
    assert_eq!(policy.member_groups, group_set(&[&core, &security]));

    let branch_policy = &policy.branch_policy;
    let core_only = group_set(&[&core]);
    let both = group_set(&[&core, &security]);
    assert!(branch_policy.is_ref_visible("refs/heads/main", &BTreeSet::new()));
    assert!(branch_policy.is_ref_visible("refs/heads/private/wip", &core_only));
    assert!(!branch_policy.is_ref_visible("refs/heads/private/wip", &BTreeSet::new()));
    // Overlapping rules intersect.
    assert!(!branch_policy.is_ref_visible("refs/heads/private/secret", &core_only));
    assert!(branch_policy.is_ref_visible("refs/heads/private/secret", &both));
    assert!(!branch_policy.is_ref_visible("refs/heads/locked/x", &both));

    let unregistered = match store
        .load_member_repo_policy(member_id, &format!("unregistered-{suffix}.git"))
        .await
    {
        Ok(policy) => policy,
        Err(error) => panic!("failed to load policy: {error}"),
    };
    assert!(unregistered.branch_policy.is_empty());
    assert_eq!(unregistered.member_groups, group_set(&[&core, &security]));
}

#[tokio::test]
#[ignore = "requires DATABASE_URL pointing to PostgreSQL"]
async fn invalid_stored_rule_fails_the_whole_policy() {
    let (pool, store) = connect().await;
    let suffix = unique_suffix();
    let member_id = insert_member(&pool, &format!("member-{suffix}")).await;
    let repo_key = format!("broken-{suffix}.git");
    let repository_id = insert_repository(&pool, &repo_key).await;
    insert_rule(&pool, repository_id, "refs/heads/private/*", &[]).await;

    // The schema's CHECK rejects globs outside `refs/` outright...
    match try_insert_rule_row(&pool, repository_id, "heads/not-a-ref-glob").await {
        Err(sqlx::Error::Database(error)) => {
            // 23514 is PostgreSQL's `check_violation`.
            assert_eq!(error.code().as_deref(), Some("23514"), "{error}");
        }
        Err(error) => panic!("unexpected error: {error}"),
        Ok(_) => panic!("the schema must reject a rule outside refs/"),
    }
    // ...but only full validation on load catches this one.
    insert_rule(&pool, repository_id, "refs/heads/../bad", &[]).await;

    match store.load_member_repo_policy(member_id, &repo_key).await {
        Err(PolicyStoreError::InvalidBranchRule { repository, .. }) => {
            assert_eq!(repository, repo_key);
        }
        Err(error) => panic!("unexpected error: {error}"),
        Ok(_) => panic!("an invalid stored rule must not yield a policy"),
    }
}

/// Creates a commit in the bare `repo_dir` whose parent is `main` and whose
/// tree is `main`'s, and returns its object ID.
fn commit_on_main(sandbox: &GitSandbox, repo_dir: &std::path::Path, message: &str) -> String {
    let output = sandbox.git(
        repo_dir,
        &[
            "commit-tree",
            "refs/heads/main^{tree}",
            "-p",
            "refs/heads/main",
            "-m",
            message,
        ],
    );
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

/// Sends `GET /<repo>/info/refs?service=git-upload-pack` with `authorization`.
async fn advertisement(
    router: axum::Router,
    repo: &str,
    authorization: &str,
) -> (StatusCode, String) {
    let request = match Request::builder()
        .uri(format!("/{repo}/info/refs?service=git-upload-pack"))
        .header(header::AUTHORIZATION, authorization)
        .body(Body::empty())
    {
        Ok(request) => request,
        Err(error) => panic!("failed to build request: {error}"),
    };
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

#[tokio::test]
#[ignore = "requires DATABASE_URL pointing to PostgreSQL"]
async fn router_hides_private_branches_using_postgres_policy() {
    let (pool, store) = connect().await;
    let suffix = unique_suffix();

    let core_id = insert_group(&pool, &format!("core-{suffix}")).await;
    let insider_id = insert_member(&pool, &format!("insider-{suffix}")).await;
    let outsider_id = insert_member(&pool, &format!("outsider-{suffix}")).await;
    insert_membership(&pool, core_id, insider_id).await;
    let insider_token = format!("insider-token-{suffix}");
    let outsider_token = format!("outsider-token-{suffix}");
    insert_token(&pool, insider_id, &insider_token).await;
    insert_token(&pool, outsider_id, &outsider_token).await;

    let repo_key = format!("team-{suffix}.git");
    let repository_id = insert_repository(&pool, &repo_key).await;
    insert_rule(&pool, repository_id, "refs/heads/private/*", &[core_id]).await;
    // Granted to no group: hidden from insider and outsider alike.
    insert_rule(&pool, repository_id, "refs/heads/locked/*", &[]).await;

    let root = match TempDir::new() {
        Ok(root) => root,
        Err(error) => panic!("failed to create repository root: {error}"),
    };
    let sandbox = GitSandbox::new();
    let repo_dir = root.path().join(&repo_key);
    sandbox.init_bare_with_commit(&repo_dir);
    // Each hidden branch gets its own commit, so a leaked object ID is
    // detectable and not just `main`'s.
    let wip_commit = commit_on_main(&sandbox, &repo_dir, "wip");
    sandbox.git(
        &repo_dir,
        &["update-ref", "refs/heads/private/wip", &wip_commit],
    );
    let locked_commit = commit_on_main(&sandbox, &repo_dir, "locked");
    sandbox.git(
        &repo_dir,
        &["update-ref", "refs/heads/locked/x", &locked_commit],
    );

    let store: Arc<dyn PolicyStore> = Arc::new(store);
    let router = scrim_server::router_with_policy_store(root.path().to_path_buf(), store);

    let (status, body) =
        advertisement(router.clone(), &repo_key, &bearer_header(&insider_token)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("refs/heads/private/wip"), "{body}");
    assert!(body.contains(&wip_commit), "{body}");
    assert!(!body.contains("refs/heads/locked/x"), "{body}");
    assert!(!body.contains(&locked_commit), "{body}");

    let (status, body) =
        advertisement(router.clone(), &repo_key, &bearer_header(&outsider_token)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("refs/heads/main"), "{body}");
    assert!(!body.contains("refs/heads/private/wip"), "{body}");
    assert!(!body.contains(&wip_commit), "{body}");
    assert!(!body.contains("refs/heads/locked/x"), "{body}");
    assert!(!body.contains(&locked_commit), "{body}");

    let (status, _) = advertisement(
        router,
        &repo_key,
        &bearer_header(&format!("wrong-token-{suffix}")),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// One `audit_log` row as read back: actor, action, target type, target name
/// and details.
type AuditLogRow = (
    Option<i64>,
    String,
    String,
    String,
    sqlx::types::Json<serde_json::Value>,
);

/// Reads back the single `audit_log` row whose `target_name` is `target_name`.
async fn fetch_audit_row(pool: &PgPool, target_name: &str) -> AuditLogRow {
    match sqlx::query_as::<_, AuditLogRow>(
        "SELECT actor_member_id, action, target_type, target_name, details \
         FROM audit_log WHERE target_name = $1",
    )
    .bind(target_name)
    .fetch_one(pool)
    .await
    {
        Ok(row) => row,
        Err(error) => panic!("failed to read audit row for {target_name}: {error}"),
    }
}

#[tokio::test]
#[ignore = "requires DATABASE_URL pointing to PostgreSQL"]
async fn records_audit_events_with_and_without_actor() {
    let (pool, store) = connect().await;
    let suffix = unique_suffix();
    let member_id = insert_member(&pool, &format!("auditor-{suffix}")).await;

    for actor_member_id in [Some(member_id), None] {
        let target_name = format!("team-{suffix}.git:refs/heads/main:{actor_member_id:?}");
        let details = serde_json::json!({ "leaked_refs": ["refs/heads/private/x"], "count": 1 });
        let entry = AuditLogEntry {
            actor_member_id,
            action: "branch.merge_leak_override".to_owned(),
            target_type: "repository_ref".to_owned(),
            target_name: target_name.clone(),
            details: details.clone(),
        };
        if let Err(error) = store.record_audit_event(entry).await {
            panic!("failed to record audit event: {error}");
        }

        let (stored_actor, action, target_type, stored_target_name, stored_details) =
            fetch_audit_row(&pool, &target_name).await;
        assert_eq!(stored_actor, actor_member_id);
        assert_eq!(action, "branch.merge_leak_override");
        assert_eq!(target_type, "repository_ref");
        assert_eq!(stored_target_name, target_name);
        assert_eq!(stored_details.0, details);
    }
}

/// A [`PgPolicyStore`] confined to a schema of its own, so admin tests can
/// count admins and members without seeing other tests' rows.
struct IsolatedStore {
    pool: PgPool,
    store: PgPolicyStore,
    admin_pool: PgPool,
    schema: String,
}

impl IsolatedStore {
    async fn new() -> Self {
        let database_url = match std::env::var("DATABASE_URL") {
            Ok(database_url) => database_url,
            Err(_) => panic!("DATABASE_URL must point to PostgreSQL to run these tests"),
        };
        let admin_pool = match PgPool::connect(&database_url).await {
            Ok(pool) => pool,
            Err(error) => panic!("failed to connect: {error}"),
        };
        // `unique_suffix` is digits and `-`, so this is a safe identifier.
        let schema = format!("scrim_test_{}", unique_suffix().replace('-', "_"));
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
        let store = PgPolicyStore::from_pool(pool.clone());
        if let Err(error) = store.migrate().await {
            panic!("failed to migrate schema {schema}: {error}");
        }
        Self {
            pool,
            store,
            admin_pool,
            schema,
        }
    }

    /// Drops the schema (skipped when a test panics, leaving it to inspect).
    async fn drop_schema(self) {
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

    /// `(action, target_type, target_name)` of every audit row, oldest first.
    async fn audit_rows(&self) -> Vec<(String, String, String)> {
        match sqlx::query_as::<_, (String, String, String)>(
            "SELECT action, target_type, target_name FROM audit_log ORDER BY id",
        )
        .fetch_all(&self.pool)
        .await
        {
            Ok(rows) => rows,
            Err(error) => panic!("failed to read audit rows: {error}"),
        }
    }

    /// Every audit column rendered as text, to search for leaked secrets.
    async fn audit_text(&self) -> String {
        match sqlx::query_scalar::<_, String>(
            "SELECT COALESCE(string_agg(audit_log::text, '\n'), '') FROM audit_log",
        )
        .fetch_one(&self.pool)
        .await
        {
            Ok(text) => text,
            Err(error) => panic!("failed to read audit log: {error}"),
        }
    }

    async fn count(&self, sql: &'static str) -> i64 {
        match sqlx::query_scalar::<_, i64>(sql)
            .fetch_one(&self.pool)
            .await
        {
            Ok(count) => count,
            Err(error) => panic!("count query failed ({sql}): {error}"),
        }
    }
}

fn member_request(name: &str, is_admin: bool, groups: &[&str]) -> CreateMemberRequest {
    CreateMemberRequest {
        name: name.to_owned(),
        is_admin,
        is_machine: false,
        groups: group_set(groups),
        token_label: format!("{name}-laptop"),
    }
}

async fn create_member_ok(store: &PgPolicyStore, request: CreateMemberRequest) -> CreatedMember {
    match store.create_member(None, request).await {
        Ok(created) => created,
        Err(error) => panic!("create_member failed: {error}"),
    }
}

fn assert_conflict<T>(result: Result<T, PolicyStoreError>, expected: &str) {
    match result {
        Err(PolicyStoreError::Conflict(message)) => assert_eq!(message, expected),
        Err(error) => panic!("expected a conflict ({expected}), got: {error}"),
        Ok(_) => panic!("expected a conflict ({expected}), but it succeeded"),
    }
}

fn assert_not_found<T>(result: Result<T, PolicyStoreError>) {
    match result {
        Err(PolicyStoreError::NotFound(_)) => {}
        Err(error) => panic!("expected not found, got: {error}"),
        Ok(_) => panic!("expected not found, but it succeeded"),
    }
}

#[tokio::test]
#[ignore = "requires DATABASE_URL pointing to PostgreSQL"]
async fn bootstraps_exactly_one_admin_even_concurrently() {
    let isolated = IsolatedStore::new().await;
    let store = &isolated.store;
    let attempts = futures_util::future::join_all(
        ["first", "second", "third", "fourth"]
            .into_iter()
            .map(|name| store.bootstrap_admin(name, "bootstrap")),
    )
    .await;
    let mut created = Vec::new();
    for attempt in attempts {
        match attempt {
            Ok(member) => created.push(member),
            Err(PolicyStoreError::Conflict(message)) => {
                assert_eq!(message, "an active admin already exists");
            }
            Err(error) => panic!("unexpected bootstrap error: {error}"),
        }
    }
    assert_eq!(created.len(), 1, "exactly one bootstrap may succeed");
    let Some(admin) = created.pop() else {
        panic!("no admin was created");
    };
    assert!(admin.member.is_admin);
    let token = admin.token.expose_secret().to_owned();
    assert!(token.starts_with("scrim_") && token.len() == 70);
    match authenticate(store, &token).await {
        Some(member) => {
            assert_eq!(member.name, admin.member.name);
            assert!(member.is_admin);
        }
        None => panic!("the bootstrap token does not authenticate"),
    }
    assert_conflict(
        store.bootstrap_admin("later", "bootstrap").await,
        "an active admin already exists",
    );

    // Only the digest is stored, and the audit row names no token.
    let stored_hash = match sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT token_hash FROM member_tokens WHERE label = 'bootstrap'",
    )
    .fetch_one(&isolated.pool)
    .await
    {
        Ok(hash) => hash,
        Err(error) => panic!("failed to read the token row: {error}"),
    };
    assert_eq!(stored_hash, token_hash(&token).to_vec());
    assert_eq!(
        isolated.audit_rows().await,
        [(
            "member.bootstrap_admin".to_owned(),
            "member".to_owned(),
            admin.member.name.clone()
        )]
    );
    assert!(!isolated.audit_text().await.contains(&token));
    isolated.drop_schema().await;
}

#[tokio::test]
#[ignore = "requires DATABASE_URL pointing to PostgreSQL"]
async fn administers_groups_members_and_tokens() {
    let isolated = IsolatedStore::new().await;
    let store = &isolated.store;
    let admin = match store.bootstrap_admin("root", "bootstrap").await {
        Ok(admin) => admin,
        Err(error) => panic!("bootstrap failed: {error}"),
    };
    let admin_id = Some(admin.member.id);

    for group in ["core", "security"] {
        if let Err(error) = store.create_group(admin_id, group).await {
            panic!("create_group {group} failed: {error}");
        }
    }
    assert_conflict(
        store.create_group(admin_id, "core").await,
        "group already exists",
    );

    // A missing group rolls the whole grant back.
    assert_not_found(
        store
            .create_member(
                admin_id,
                member_request("alice", false, &["core", "ghosts"]),
            )
            .await,
    );
    assert_eq!(
        isolated
            .count("SELECT COUNT(*) FROM members WHERE name = 'alice'")
            .await,
        0
    );
    let alice = create_member_ok(store, member_request("alice", false, &["core"])).await;
    assert_eq!(alice.member.groups, ["core"]);
    assert_conflict(
        store
            .create_member(admin_id, member_request("alice", false, &[]))
            .await,
        "member already exists",
    );
    let first_token = alice.token.expose_secret().to_owned();
    match authenticate(store, &first_token).await {
        Some(member) => assert_eq!(member.name, "alice"),
        None => panic!("alice's token does not authenticate"),
    }
    let second = match store.issue_member_token(admin_id, "alice", "ci").await {
        Ok(issued) => issued,
        Err(error) => panic!("issue_member_token failed: {error}"),
    };
    let second_token = second.token.expose_secret().to_owned();
    assert_ne!(first_token, second_token);
    assert!(authenticate(store, &second_token).await.is_some());

    for (expected, call) in [
        (true, "add"),
        (false, "add"),
        (true, "remove"),
        (false, "remove"),
    ] {
        let change = if call == "add" {
            store.add_group_member(admin_id, "security", "alice").await
        } else {
            store
                .remove_group_member(admin_id, "security", "alice")
                .await
        };
        match change {
            Ok(change) => assert_eq!(change.changed, expected, "{call}"),
            Err(error) => panic!("{call} failed: {error}"),
        }
    }
    assert_not_found(store.add_group_member(admin_id, "ghosts", "alice").await);
    assert_not_found(store.add_group_member(admin_id, "core", "nobody").await);

    let groups = match store.list_groups().await {
        Ok(groups) => groups,
        Err(error) => panic!("list_groups failed: {error}"),
    };
    let summary: Vec<(String, Vec<String>)> = groups
        .into_iter()
        .map(|group| (group.name, group.members))
        .collect();
    assert_eq!(
        summary,
        [
            ("core".to_owned(), vec!["alice".to_owned()]),
            ("security".to_owned(), Vec::new()),
        ]
    );

    match store.revoke_member(admin_id, "alice").await {
        Ok(result) => assert!(result.revoked),
        Err(error) => panic!("revoke failed: {error}"),
    }
    assert!(authenticate(store, &first_token).await.is_none());
    assert!(authenticate(store, &second_token).await.is_none());
    assert_eq!(
        isolated
            .count("SELECT COUNT(*) FROM member_tokens mt JOIN members m ON m.id = mt.member_id WHERE m.name = 'alice' AND mt.revoked_at IS NULL")
            .await,
        0
    );
    match store.revoke_member(admin_id, "alice").await {
        Ok(result) => assert!(!result.revoked),
        Err(error) => panic!("second revoke failed: {error}"),
    }
    assert_not_found(store.issue_member_token(admin_id, "alice", "again").await);
    let active = match store.list_members(false).await {
        Ok(members) => members,
        Err(error) => panic!("list_members failed: {error}"),
    };
    assert_eq!(
        active
            .iter()
            .map(|member| member.name.as_str())
            .collect::<Vec<_>>(),
        ["root"]
    );
    let everyone = match store.list_members(true).await {
        Ok(members) => members,
        Err(error) => panic!("list_members failed: {error}"),
    };
    assert_eq!(everyone.len(), 2);
    assert!(
        everyone
            .iter()
            .any(|member| member.name == "alice" && member.revoked)
    );

    // The last active admin is protected, also against two racing
    // revocations of the only two admins.
    assert_conflict(
        store.revoke_member(admin_id, "root").await,
        "cannot revoke the last active admin",
    );
    create_member_ok(store, member_request("root2", true, &[])).await;
    let (first, second) = tokio::join!(
        store.revoke_member(admin_id, "root"),
        store.revoke_member(admin_id, "root2"),
    );
    let outcomes = [first, second];
    let revoked_count = outcomes
        .iter()
        .filter(|outcome| matches!(outcome, Ok(result) if result.revoked))
        .count();
    let conflict_count = outcomes
        .iter()
        .filter(|outcome| matches!(outcome, Err(PolicyStoreError::Conflict(_))))
        .count();
    assert_eq!((revoked_count, conflict_count), (1, 1));
    assert_eq!(
        isolated
            .count("SELECT COUNT(*) FROM members WHERE is_admin AND revoked_at IS NULL")
            .await,
        1
    );

    let actions: Vec<String> = isolated
        .audit_rows()
        .await
        .into_iter()
        .map(|(action, _, _)| action)
        .collect();
    assert_eq!(
        actions,
        [
            "member.bootstrap_admin",
            "group.create",
            "group.create",
            "member.grant",
            "member.token_issue",
            "group.member_add",
            "group.member_remove",
            "member.revoke",
            "member.grant",
            "member.revoke",
        ]
    );
    let audit_text = isolated.audit_text().await;
    for token in [&first_token, &second_token] {
        assert!(!audit_text.contains(token.as_str()));
    }
    isolated.drop_schema().await;
}

#[tokio::test]
#[ignore = "requires DATABASE_URL pointing to PostgreSQL"]
async fn administers_repositories_and_branch_rules() {
    let isolated = IsolatedStore::new().await;
    let store = &isolated.store;
    let alice = create_member_ok(store, member_request("alice", false, &[])).await;
    for group in ["core", "security"] {
        if let Err(error) = store.create_group(None, group).await {
            panic!("create_group failed: {error}");
        }
    }
    if let Err(error) = store.add_group_member(None, "core", "alice").await {
        panic!("add_group_member failed: {error}");
    }

    let registered = match store.register_repository(None, "team/app.git").await {
        Ok(registered) => registered,
        Err(error) => panic!("register failed: {error}"),
    };
    assert!(registered.created);
    match store.register_repository(None, "team/app.git").await {
        Ok(again) => {
            assert!(!again.created);
            assert_eq!(again.repository.id, registered.repository.id);
        }
        Err(error) => panic!("second register failed: {error}"),
    }
    for invalid in ["api/app.git", "../app.git", ""] {
        match store.register_repository(None, invalid).await {
            Err(PolicyStoreError::InvalidInput(_)) => {}
            Err(error) => panic!("unexpected error for {invalid:?}: {error}"),
            Ok(_) => panic!("{invalid:?} was registered"),
        }
    }
    if let Err(error) = store.register_repository(None, "alpha.git").await {
        panic!("register failed: {error}");
    }
    match store.list_repositories().await {
        Ok(repositories) => assert_eq!(
            repositories
                .iter()
                .map(|repository| repository.path.as_str())
                .collect::<Vec<_>>(),
            ["alpha.git", "team/app.git"]
        ),
        Err(error) => panic!("list_repositories failed: {error}"),
    }

    let pattern = "refs/heads/private/*";
    assert_not_found(
        store
            .set_branch_rule(None, "missing.git", pattern, group_set(&["core"]))
            .await,
    );
    assert_not_found(
        store
            .set_branch_rule(None, "team/app.git", pattern, group_set(&["ghosts"]))
            .await,
    );
    match store
        .set_branch_rule(None, "team/app.git", "heads/*", group_set(&["core"]))
        .await
    {
        Err(PolicyStoreError::InvalidInput(_)) => {}
        Err(error) => panic!("unexpected error: {error}"),
        Ok(_) => panic!("an invalid glob was stored"),
    }

    if let Err(error) = store
        .set_branch_rule(None, "team/app.git", pattern, group_set(&["core"]))
        .await
    {
        panic!("set_branch_rule failed: {error}");
    }
    let policy = match store
        .load_member_repo_policy(alice.member.id, "team/app.git")
        .await
    {
        Ok(policy) => policy,
        Err(error) => panic!("load failed: {error}"),
    };
    assert!(
        policy
            .branch_policy
            .is_ref_visible("refs/heads/private/x", &policy.member_groups)
    );

    // Replacing the groups takes effect for the next policy load.
    if let Err(error) = store
        .set_branch_rule(None, "team/app.git", pattern, group_set(&["security"]))
        .await
    {
        panic!("updating the rule failed: {error}");
    }
    let policy = match store
        .load_member_repo_policy(alice.member.id, "team/app.git")
        .await
    {
        Ok(policy) => policy,
        Err(error) => panic!("load failed: {error}"),
    };
    assert!(
        !policy
            .branch_policy
            .is_ref_visible("refs/heads/private/x", &policy.member_groups)
    );
    match store.list_branch_rules("team/app.git").await {
        Ok(rules) => {
            assert_eq!(rules.len(), 1);
            assert_eq!(
                rules
                    .first()
                    .map(|rule| (rule.pattern.as_str(), rule.groups.clone())),
                Some((pattern, vec!["security".to_owned()]))
            );
        }
        Err(error) => panic!("list_branch_rules failed: {error}"),
    }
    match store.list_branch_rules("alpha.git").await {
        Ok(rules) => assert!(rules.is_empty()),
        Err(error) => panic!("list_branch_rules failed: {error}"),
    }
    assert_not_found(store.list_branch_rules("missing.git").await);

    match store
        .remove_branch_rule(None, "team/app.git", pattern)
        .await
    {
        Ok(removed) => assert!(removed),
        Err(error) => panic!("remove_branch_rule failed: {error}"),
    }
    assert_not_found(
        store
            .remove_branch_rule(None, "team/app.git", pattern)
            .await,
    );
    assert_eq!(
        isolated
            .count("SELECT COUNT(*) FROM branch_rule_groups")
            .await,
        0
    );

    let target = format!("team/app.git:{pattern}");
    let rows = isolated.audit_rows().await;
    let rule_rows: Vec<(String, String, String)> = rows
        .into_iter()
        .filter(|(_, target_type, _)| target_type != "group" && target_type != "group_membership")
        .filter(|(action, _, _)| action != "member.grant")
        .collect();
    assert_eq!(
        rule_rows,
        [
            (
                "repository.register".to_owned(),
                "repository".to_owned(),
                "team/app.git".to_owned()
            ),
            (
                "repository.register".to_owned(),
                "repository".to_owned(),
                "alpha.git".to_owned()
            ),
            (
                "branch_rule.set".to_owned(),
                "branch_rule".to_owned(),
                target.clone()
            ),
            (
                "branch_rule.set".to_owned(),
                "branch_rule".to_owned(),
                target.clone()
            ),
            (
                "branch_rule.remove".to_owned(),
                "branch_rule".to_owned(),
                target
            ),
        ]
    );
    isolated.drop_schema().await;
}
