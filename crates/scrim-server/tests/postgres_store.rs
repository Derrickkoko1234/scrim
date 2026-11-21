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
    AuditLogEntry, AuthenticatedMember, PgPolicyStore, PolicyStore, PolicyStoreError,
};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
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
