//! The admin API under `/api/v1`, end to end through the router: members,
//! tokens, groups, repositories and branch rules managed over HTTP against a
//! [`MemoryPolicyStore`] (and a [`StaticPolicyStore`] server), with real
//! `git` clients showing that rule changes take effect immediately. Also
//! covers argument parsing of `scrim-server bootstrap-admin`.

mod common;

use std::{path::Path, process::Command, sync::Arc};

use axum::{
    Router,
    body::Body,
    http::{HeaderMap, Method, Request, StatusCode, header},
};
use common::{GitSandbox, TEST_TOKEN, bearer_header, spawn_server_with_store, test_auth};
use http_body_util::BodyExt;
use scrim_server::{
    AuthenticatedMember, MAX_ADMIN_BODY_BYTES, MemoryPolicyStore, PolicyStore, PolicyStoreError,
};
use secrecy::ExposeSecret;
use serde_json::{Value, json};
use tempfile::TempDir;
use tower::ServiceExt;

const ADMIN_TOKEN: &str = "admin-token-0123456789abcdef";
const DEV_TOKEN: &str = "dev-token-0123456789abcdef";
const TEST_AGE_KEY_1: &str = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p";
const TEST_AGE_KEY_2: &str = "age1zqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqerzwta";
const TEST_AGE_KEY_3: &str = "age1pqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqxpnvqe";
const TEST_AGE_KEY_ALL_ZERO: &str =
    "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq5cu47z";

/// A router over a [`MemoryPolicyStore`] holding the admin `root` (ID 1) and
/// the non-admin `dev` (ID 2), with a handle on the shared store.
struct Api {
    root: TempDir,
    store: MemoryPolicyStore,
    router: Router,
}

impl Api {
    fn new() -> Self {
        let root = match TempDir::new() {
            Ok(root) => root,
            Err(error) => panic!("failed to create repo root: {error}"),
        };
        let mut store = MemoryPolicyStore::new();
        store.insert_member(
            AuthenticatedMember {
                id: 1,
                name: "root".to_owned(),
                is_admin: true,
            },
            ADMIN_TOKEN.as_bytes(),
        );
        store.insert_member(
            AuthenticatedMember {
                id: 2,
                name: "dev".to_owned(),
                is_admin: false,
            },
            DEV_TOKEN.as_bytes(),
        );
        let router = scrim_server::router_with_policy_store(
            root.path().to_path_buf(),
            Arc::new(store.clone()),
        );
        Self {
            root,
            store,
            router,
        }
    }

    async fn call(
        &self,
        method: Method,
        uri: &str,
        token: Option<&str>,
        body: Option<Value>,
    ) -> Reply {
        send(&self.router, method, uri, token, body).await
    }

    async fn admin(&self, method: Method, uri: &str, body: Option<Value>) -> Reply {
        self.call(method, uri, Some(ADMIN_TOKEN), body).await
    }

    /// Asserts an admin request answers `status` and returns its JSON.
    async fn admin_expect(
        &self,
        method: Method,
        uri: &str,
        body: Option<Value>,
        status: StatusCode,
    ) -> Value {
        let reply = self.admin(method.clone(), uri, body).await;
        assert_eq!(reply.status, status, "{method} {uri}: {}", reply.json);
        reply.json
    }

    /// Creates `name` with `groups` and returns their token.
    async fn create_member(&self, name: &str, groups: &[&str]) -> String {
        let created = self
            .admin_expect(
                Method::POST,
                "/api/v1/members",
                Some(json!({ "name": name, "groups": groups })),
                StatusCode::CREATED,
            )
            .await;
        string_field(&created, "token")
    }

    async fn create_group(&self, name: &str) {
        self.admin_expect(
            Method::POST,
            "/api/v1/groups",
            Some(json!({ "name": name })),
            StatusCode::CREATED,
        )
        .await;
    }
}

/// One answered request.
struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    /// The body as JSON, or as a JSON string if it is not JSON.
    json: Value,
}

impl Reply {
    fn error(&self) -> String {
        string_field(&self.json, "error")
    }
}

async fn send(
    router: &Router,
    method: Method,
    uri: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> Reply {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(token) = token {
        builder = builder.header(header::AUTHORIZATION, bearer_header(token));
    }
    let request_body = match body {
        Some(body) => {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
            Body::from(body.to_string())
        }
        None => Body::empty(),
    };
    send_request(router, builder.body(request_body)).await
}

async fn send_request(router: &Router, request: Result<Request<Body>, axum::http::Error>) -> Reply {
    let request = match request {
        Ok(request) => request,
        Err(error) => panic!("failed to build request: {error}"),
    };
    let response = match router.clone().oneshot(request).await {
        Ok(response) => response,
        Err(error) => panic!("router failed: {error}"),
    };
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = match response.into_body().collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(error) => panic!("failed to read response body: {error}"),
    };
    let json = match serde_json::from_slice(&bytes) {
        Ok(json) => json,
        Err(_) => Value::String(String::from_utf8_lossy(&bytes).into_owned()),
    };
    Reply {
        status,
        headers,
        json,
    }
}

fn string_field(value: &Value, field: &str) -> String {
    match value.get(field).and_then(Value::as_str) {
        Some(text) => text.to_owned(),
        None => panic!("expected string field {field:?} in {value}"),
    }
}

fn names(value: &Value, list: &str, field: &str) -> Vec<String> {
    match value.get(list).and_then(Value::as_array) {
        Some(items) => items.iter().map(|item| string_field(item, field)).collect(),
        None => panic!("expected array {list:?} in {value}"),
    }
}

fn assert_no_store(reply: &Reply) {
    assert_eq!(
        reply
            .headers
            .get(header::CACHE_CONTROL)
            .map(|value| value.as_bytes()),
        Some(&b"no-store"[..])
    );
    assert_eq!(
        reply
            .headers
            .get(header::PRAGMA)
            .map(|value| value.as_bytes()),
        Some(&b"no-cache"[..])
    );
}

/// Every admin-only route with a body that would otherwise be valid.
fn admin_routes() -> Vec<(Method, &'static str, Option<Value>)> {
    vec![
        (
            Method::POST,
            "/api/v1/repositories",
            Some(json!({ "path": "new.git" })),
        ),
        (Method::GET, "/api/v1/repositories", None),
        (
            Method::POST,
            "/api/v1/groups",
            Some(json!({ "name": "core" })),
        ),
        (Method::GET, "/api/v1/groups", None),
        (
            Method::POST,
            "/api/v1/groups/core/members",
            Some(json!({ "member": "dev" })),
        ),
        (Method::DELETE, "/api/v1/groups/core/members/dev", None),
        (
            Method::POST,
            "/api/v1/members",
            Some(json!({ "name": "eve" })),
        ),
        (Method::POST, "/api/v1/members/dev/tokens", Some(json!({}))),
        (Method::DELETE, "/api/v1/members/root", None),
        (Method::GET, "/api/v1/members", None),
        (
            Method::PUT,
            "/api/v1/branch-rules",
            Some(json!({
                "repository": "new.git",
                "pattern": "refs/heads/private/*",
                "groups": ["core"],
            })),
        ),
        (Method::GET, "/api/v1/branch-rules?repo=new.git", None),
        (
            Method::DELETE,
            "/api/v1/branch-rules?repo=new.git&pattern=refs%2Fheads%2Fprivate%2F*",
            None,
        ),
        (
            Method::PUT,
            "/api/v1/members/dev/public-key",
            Some(json!({ "public_key": TEST_AGE_KEY_1 })),
        ),
        (
            Method::PUT,
            "/api/v1/secret-scopes",
            Some(json!({
                "repository": "new.git",
                "scope": "dev",
                "groups": ["core"],
            })),
        ),
        (Method::GET, "/api/v1/secret-scopes?repo=new.git", None),
        (
            Method::DELETE,
            "/api/v1/secret-scopes?repo=new.git&scope=dev",
            None,
        ),
    ]
}

#[tokio::test]
async fn whoami_reports_the_authenticated_member() {
    let mut api = Api::new();
    // Clones share state, so the router's store sees this membership.
    api.store.insert_group_membership(2, "core");

    let admin = api.admin(Method::GET, "/api/v1/whoami", None).await;
    assert_eq!(admin.status, StatusCode::OK);
    assert_no_store(&admin);
    assert_eq!(
        admin.json,
        json!({ "id": 1, "name": "root", "is_admin": true, "groups": [], "public_key": null })
    );

    let dev = api
        .call(Method::GET, "/api/v1/whoami", Some(DEV_TOKEN), None)
        .await;
    assert_eq!(dev.status, StatusCode::OK);
    assert_eq!(
        dev.json,
        json!({ "id": 2, "name": "dev", "is_admin": false, "groups": ["core"], "public_key": null })
    );
}

#[tokio::test]
async fn whoami_works_with_the_static_token() {
    let root = match TempDir::new() {
        Ok(root) => root,
        Err(error) => panic!("failed to create repo root: {error}"),
    };
    let router = scrim_server::router(root.path().to_path_buf(), test_auth());
    let reply = send(
        &router,
        Method::GET,
        "/api/v1/whoami",
        Some(TEST_TOKEN),
        None,
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(
        reply.json,
        json!({ "id": 0, "name": "static-token", "is_admin": true, "groups": [], "public_key": null })
    );
}

#[tokio::test]
async fn static_store_answers_administration_with_not_implemented() {
    let root = match TempDir::new() {
        Ok(root) => root,
        Err(error) => panic!("failed to create repo root: {error}"),
    };
    let router = scrim_server::router(root.path().to_path_buf(), test_auth());
    let mut routes = admin_routes();
    routes.push((
        Method::PUT,
        "/api/v1/me/public-key",
        Some(json!({ "public_key": TEST_AGE_KEY_1 })),
    ));
    routes.push((
        Method::GET,
        "/api/v1/secret-scopes/recipients?repo=new.git&scope=dev",
        None,
    ));
    routes.push((Method::GET, "/api/v1/groups/core/recipients", None));
    for (method, uri, body) in routes {
        let reply = send(&router, method.clone(), uri, Some(TEST_TOKEN), body).await;
        assert_eq!(
            reply.status,
            StatusCode::NOT_IMPLEMENTED,
            "{method} {uri}: {}",
            reply.json
        );
        assert!(reply.error().contains("not backed by a database"));
    }
    // The repository is registered before it is created, so nothing was
    // written to disk for the store that cannot register it.
    assert!(!root.path().join("new.git").exists());
}

#[tokio::test]
async fn admin_api_requires_authentication() {
    let api = Api::new();
    for uri in ["/api/v1/whoami", "/api/v1/members", "/api/v1/unknown"] {
        let anonymous = api.call(Method::GET, uri, None, None).await;
        assert_eq!(anonymous.status, StatusCode::UNAUTHORIZED, "{uri}");
        let wrong = api
            .call(Method::GET, uri, Some("wrong-token-0123456789abcdef"), None)
            .await;
        assert_eq!(wrong.status, StatusCode::UNAUTHORIZED, "{uri}");
    }
}

#[tokio::test]
async fn admin_routes_reject_non_admins() {
    let api = Api::new();
    for (method, uri, body) in admin_routes() {
        let reply = api.call(method.clone(), uri, Some(DEV_TOKEN), body).await;
        assert_eq!(
            reply.status,
            StatusCode::FORBIDDEN,
            "{method} {uri}: {}",
            reply.json
        );
        assert_eq!(reply.error(), "admin privileges required");
        assert_no_store(&reply);
    }
    // Even an invalid body is refused as forbidden, before it is parsed.
    let reply = api
        .call(
            Method::POST,
            "/api/v1/groups",
            Some(DEV_TOKEN),
            Some(json!({ "bogus": true })),
        )
        .await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert!(api.store.audit_entries().is_empty());
    assert!(!api.root.path().join("new.git").exists());
}

#[tokio::test]
async fn unknown_api_paths_and_methods_get_json_errors() {
    let api = Api::new();
    for uri in [
        "/api/v1/nope",
        "/api/v1",
        "/api/v1/",
        "/api/v1/members/a/b/c",
    ] {
        let reply = api.admin(Method::GET, uri, None).await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND, "{uri}");
        assert_eq!(reply.json, json!({ "error": "not found" }), "{uri}");
        assert_no_store(&reply);
    }
    let reply = api.admin(Method::PATCH, "/api/v1/groups", None).await;
    assert_eq!(reply.status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(reply.json, json!({ "error": "method not allowed" }));
    assert_no_store(&reply);
}

#[tokio::test]
async fn members_tokens_and_groups_lifecycle() {
    let api = Api::new();
    api.create_group("core").await;
    api.create_group("security").await;
    let duplicate = api
        .admin(
            Method::POST,
            "/api/v1/groups",
            Some(json!({ "name": "core" })),
        )
        .await;
    assert_eq!(duplicate.status, StatusCode::CONFLICT);
    assert_eq!(duplicate.error(), "group already exists");

    let created = api
        .admin_expect(
            Method::POST,
            "/api/v1/members",
            Some(json!({
                "name": "alice",
                "groups": ["core"],
                "token_label": "laptop",
            })),
            StatusCode::CREATED,
        )
        .await;
    let first_token = string_field(&created, "token");
    assert_eq!(first_token.len(), 70);
    assert!(first_token.starts_with("scrim_"));
    let Some(member) = created.get("member") else {
        panic!("missing member in {created}");
    };
    assert_eq!(member.get("name"), Some(&json!("alice")));
    assert_eq!(member.get("is_admin"), Some(&json!(false)));
    assert_eq!(member.get("is_machine"), Some(&json!(false)));
    assert_eq!(member.get("groups"), Some(&json!(["core"])));
    assert_eq!(member.get("revoked"), Some(&json!(false)));

    // The granted token authenticates immediately, as a non-admin.
    let whoami = api
        .call(Method::GET, "/api/v1/whoami", Some(&first_token), None)
        .await;
    assert_eq!(whoami.status, StatusCode::OK);
    assert_eq!(whoami.json.get("name"), Some(&json!("alice")));
    assert_eq!(whoami.json.get("groups"), Some(&json!(["core"])));
    let forbidden = api
        .call(Method::GET, "/api/v1/members", Some(&first_token), None)
        .await;
    assert_eq!(forbidden.status, StatusCode::FORBIDDEN);

    let issued = api
        .admin_expect(
            Method::POST,
            "/api/v1/members/alice/tokens",
            Some(json!({ "label": "ci" })),
            StatusCode::CREATED,
        )
        .await;
    assert_eq!(issued.get("member"), Some(&json!("alice")));
    assert_eq!(issued.get("label"), Some(&json!("ci")));
    let second_token = string_field(&issued, "token");
    assert_ne!(first_token, second_token);
    for token in [&first_token, &second_token] {
        let reply = api
            .call(Method::GET, "/api/v1/whoami", Some(token), None)
            .await;
        assert_eq!(reply.status, StatusCode::OK);
    }

    let added = api
        .admin_expect(
            Method::POST,
            "/api/v1/groups/security/members",
            Some(json!({ "member": "alice" })),
            StatusCode::OK,
        )
        .await;
    assert_eq!(
        added,
        json!({ "group": "security", "member": "alice", "added": true })
    );
    let added_again = api
        .admin_expect(
            Method::POST,
            "/api/v1/groups/security/members",
            Some(json!({ "member": "alice" })),
            StatusCode::OK,
        )
        .await;
    assert_eq!(added_again.get("added"), Some(&json!(false)));
    let groups = api
        .admin_expect(Method::GET, "/api/v1/groups", None, StatusCode::OK)
        .await;
    let Some(group_list) = groups.get("groups").and_then(Value::as_array) else {
        panic!("missing groups in {groups}");
    };
    let summary: Vec<(String, Value)> = group_list
        .iter()
        .map(|group| {
            (
                string_field(group, "name"),
                value_or_null(group.get("members")),
            )
        })
        .collect();
    assert_eq!(
        summary,
        vec![
            ("core".to_owned(), json!(["alice"])),
            ("security".to_owned(), json!(["alice"])),
        ]
    );

    let removed = api
        .admin_expect(
            Method::DELETE,
            "/api/v1/groups/security/members/alice",
            None,
            StatusCode::OK,
        )
        .await;
    assert_eq!(
        removed,
        json!({ "group": "security", "member": "alice", "removed": true })
    );
    let removed_again = api
        .admin_expect(
            Method::DELETE,
            "/api/v1/groups/security/members/alice",
            None,
            StatusCode::OK,
        )
        .await;
    assert_eq!(removed_again.get("removed"), Some(&json!(false)));
    for (method, uri, body) in [
        (
            Method::POST,
            "/api/v1/groups/nope/members",
            Some(json!({ "member": "alice" })),
        ),
        (
            Method::POST,
            "/api/v1/groups/core/members",
            Some(json!({ "member": "nobody" })),
        ),
        (Method::DELETE, "/api/v1/groups/nope/members/alice", None),
        (Method::DELETE, "/api/v1/groups/core/members/nobody", None),
        (
            Method::POST,
            "/api/v1/members/nobody/tokens",
            Some(json!({})),
        ),
        (Method::DELETE, "/api/v1/members/nobody", None),
    ] {
        let reply = api.admin(method.clone(), uri, body).await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND, "{method} {uri}");
    }

    let members = api
        .admin_expect(Method::GET, "/api/v1/members", None, StatusCode::OK)
        .await;
    assert_eq!(names(&members, "members", "name"), ["alice", "dev", "root"]);

    let revoked = api
        .admin_expect(
            Method::DELETE,
            "/api/v1/members/alice",
            None,
            StatusCode::OK,
        )
        .await;
    assert_eq!(revoked, json!({ "name": "alice", "revoked": true }));
    // Every token of a revoked member stops working at once.
    for token in [&first_token, &second_token] {
        let reply = api
            .call(Method::GET, "/api/v1/whoami", Some(token), None)
            .await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    }
    let revoked_again = api
        .admin_expect(
            Method::DELETE,
            "/api/v1/members/alice",
            None,
            StatusCode::OK,
        )
        .await;
    assert_eq!(revoked_again, json!({ "name": "alice", "revoked": false }));

    let active = api
        .admin_expect(Method::GET, "/api/v1/members", None, StatusCode::OK)
        .await;
    assert_eq!(names(&active, "members", "name"), ["dev", "root"]);
    let everyone = api
        .admin_expect(
            Method::GET,
            "/api/v1/members?include_revoked=true",
            None,
            StatusCode::OK,
        )
        .await;
    assert_eq!(
        names(&everyone, "members", "name"),
        ["alice", "dev", "root"]
    );
    let Some(alice) = everyone
        .get("members")
        .and_then(Value::as_array)
        .and_then(|members| members.first())
    else {
        panic!("missing members in {everyone}");
    };
    assert_eq!(alice.get("revoked"), Some(&json!(true)));
    assert_eq!(alice.get("groups"), Some(&json!(["core"])));
    let groups = api
        .admin_expect(Method::GET, "/api/v1/groups", None, StatusCode::OK)
        .await;
    assert_eq!(
        groups.pointer("/groups/0/members"),
        Some(&json!([])),
        "revoked members are not listed in groups"
    );

    // A revoked member cannot be given tokens or groups, and their name
    // stays taken.
    let token_for_revoked = api
        .admin(
            Method::POST,
            "/api/v1/members/alice/tokens",
            Some(json!({})),
        )
        .await;
    assert_eq!(token_for_revoked.status, StatusCode::NOT_FOUND);
    let group_for_revoked = api
        .admin(
            Method::POST,
            "/api/v1/groups/core/members",
            Some(json!({ "member": "alice" })),
        )
        .await;
    assert_eq!(group_for_revoked.status, StatusCode::NOT_FOUND);
    let recreate = api
        .admin(
            Method::POST,
            "/api/v1/members",
            Some(json!({ "name": "alice" })),
        )
        .await;
    assert_eq!(recreate.status, StatusCode::CONFLICT);
    assert_eq!(recreate.error(), "member already exists");

    let unknown_group = api
        .admin(
            Method::POST,
            "/api/v1/members",
            Some(json!({ "name": "bob", "groups": ["core", "ghosts"] })),
        )
        .await;
    assert_eq!(unknown_group.status, StatusCode::NOT_FOUND);
    assert_eq!(unknown_group.error(), "group not found: ghosts");
    let machine = api
        .admin_expect(
            Method::POST,
            "/api/v1/members",
            Some(json!({ "name": "ci-bot", "is_machine": true, "is_admin": true })),
            StatusCode::CREATED,
        )
        .await;
    assert_eq!(machine.pointer("/member/is_machine"), Some(&json!(true)));
    assert_eq!(machine.pointer("/member/is_admin"), Some(&json!(true)));
}

fn value_or_null(value: Option<&Value>) -> Value {
    match value {
        Some(value) => value.clone(),
        None => Value::Null,
    }
}

#[tokio::test]
async fn the_last_active_admin_cannot_be_revoked() {
    let api = Api::new();
    let refused = api
        .admin(Method::DELETE, "/api/v1/members/root", None)
        .await;
    assert_eq!(refused.status, StatusCode::CONFLICT);
    assert_eq!(refused.error(), "cannot revoke the last active admin");

    let second_admin = api
        .admin_expect(
            Method::POST,
            "/api/v1/members",
            Some(json!({ "name": "root2", "is_admin": true })),
            StatusCode::CREATED,
        )
        .await;
    let second_token = string_field(&second_admin, "token");
    let revoked = api
        .call(
            Method::DELETE,
            "/api/v1/members/root",
            Some(&second_token),
            None,
        )
        .await;
    assert_eq!(revoked.status, StatusCode::OK);
    let old_admin = api.admin(Method::GET, "/api/v1/whoami", None).await;
    assert_eq!(old_admin.status, StatusCode::UNAUTHORIZED);
    let self_revoke = api
        .call(
            Method::DELETE,
            "/api/v1/members/root2",
            Some(&second_token),
            None,
        )
        .await;
    assert_eq!(self_revoke.status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn repositories_are_created_or_registered_safely() {
    let api = Api::new();
    let sandbox = GitSandbox::new();
    let root = api.root.path();

    let created = api
        .admin_expect(
            Method::POST,
            "/api/v1/repositories",
            Some(json!({ "path": "team/app.git" })),
            StatusCode::CREATED,
        )
        .await;
    assert_eq!(created.get("path"), Some(&json!("team/app.git")));
    assert_eq!(created.get("created"), Some(&json!(true)));
    assert_eq!(created.get("bare_initialized"), Some(&json!(true)));
    match std::fs::read_to_string(root.join("team/app.git/HEAD")) {
        Ok(head) => assert_eq!(head, "ref: refs/heads/main\n"),
        Err(error) => panic!("created repository has no HEAD: {error}"),
    }
    let again = api
        .admin_expect(
            Method::POST,
            "/api/v1/repositories",
            Some(json!({ "path": "team/app.git" })),
            StatusCode::OK,
        )
        .await;
    assert_eq!(again.get("id"), created.get("id"));
    assert_eq!(again.get("created"), Some(&json!(false)));
    assert_eq!(again.get("bare_initialized"), Some(&json!(false)));

    sandbox.init_bare_with_commit(&root.join("existing.git"));
    let registered = api
        .admin_expect(
            Method::POST,
            "/api/v1/repositories",
            Some(json!({ "path": "existing.git", "create_bare": false })),
            StatusCode::CREATED,
        )
        .await;
    assert_eq!(registered.get("created"), Some(&json!(true)));
    assert_eq!(registered.get("bare_initialized"), Some(&json!(false)));

    let missing = api
        .admin(
            Method::POST,
            "/api/v1/repositories",
            Some(json!({ "path": "missing.git", "create_bare": false })),
        )
        .await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
    assert!(!root.join("missing.git").exists());

    for invalid in [
        "",
        "api",
        "api/app.git",
        "../escape.git",
        "team//app.git",
        ".hidden.git",
        "/abs.git",
        "team/%2e%2e/app.git",
    ] {
        let reply = api
            .admin(
                Method::POST,
                "/api/v1/repositories",
                Some(json!({ "path": invalid })),
            )
            .await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{invalid:?}");
    }
    assert!(!root.join("api").exists());

    // Nothing that is not a valid bare repository is ever clobbered.
    if let Err(error) = std::fs::create_dir(root.join("plain")) {
        panic!("failed to create plain dir: {error}");
    }
    if let Err(error) = std::fs::write(root.join("plain/keep.txt"), "keep") {
        panic!("failed to write file: {error}");
    }
    if let Err(error) = std::fs::write(root.join("file.git"), "not a repo") {
        panic!("failed to write file: {error}");
    }
    for occupied in ["plain", "file.git", "file.git/below.git"] {
        let reply = api
            .admin(
                Method::POST,
                "/api/v1/repositories",
                Some(json!({ "path": occupied })),
            )
            .await;
        assert_eq!(reply.status, StatusCode::CONFLICT, "{occupied}");
    }
    assert!(root.join("plain/keep.txt").is_file());

    // Symlinks never lead a new repository out of the root.
    let outside = match TempDir::new() {
        Ok(outside) => outside,
        Err(error) => panic!("failed to create outside dir: {error}"),
    };
    sandbox.init_bare(&outside.path().join("victim.git"));
    #[cfg(unix)]
    {
        for (link, target) in [
            ("escape", outside.path().to_path_buf()),
            ("link.git", outside.path().join("victim.git")),
        ] {
            if let Err(error) = std::os::unix::fs::symlink(&target, root.join(link)) {
                panic!("failed to create symlink: {error}");
            }
        }
        for through_link in ["escape/new.git", "escape/victim.git", "link.git"] {
            let reply = api
                .admin(
                    Method::POST,
                    "/api/v1/repositories",
                    Some(json!({ "path": through_link })),
                )
                .await;
            assert_eq!(reply.status, StatusCode::CONFLICT, "{through_link}");
        }
        assert!(!outside.path().join("new.git").exists());
    }

    let listed = api
        .admin_expect(Method::GET, "/api/v1/repositories", None, StatusCode::OK)
        .await;
    assert_eq!(
        names(&listed, "repositories", "path"),
        ["existing.git", "team/app.git"]
    );
}

#[tokio::test]
async fn invalid_admin_input_is_rejected() {
    let api = Api::new();
    api.create_group("core").await;
    api.admin_expect(
        Method::POST,
        "/api/v1/repositories",
        Some(json!({ "path": "app.git" })),
        StatusCode::CREATED,
    )
    .await;

    let rule = |repository: &str, pattern: &str, groups: Value| {
        Some(json!({ "repository": repository, "pattern": pattern, "groups": groups }))
    };
    let cases: Vec<(Method, &str, Option<Value>, StatusCode)> = vec![
        (
            Method::POST,
            "/api/v1/groups",
            Some(json!({ "name": "-core" })),
            StatusCode::BAD_REQUEST,
        ),
        (
            Method::POST,
            "/api/v1/groups",
            Some(json!({ "name": "a".repeat(65) })),
            StatusCode::BAD_REQUEST,
        ),
        (
            Method::POST,
            "/api/v1/members",
            Some(json!({ "name": "has space" })),
            StatusCode::BAD_REQUEST,
        ),
        (
            Method::POST,
            "/api/v1/members",
            Some(json!({ "name": "eve", "token_label": "line\nbreak" })),
            StatusCode::BAD_REQUEST,
        ),
        (
            Method::POST,
            "/api/v1/members",
            Some(json!({ "name": "eve", "groups": ["bad group"] })),
            StatusCode::BAD_REQUEST,
        ),
        (
            Method::POST,
            "/api/v1/members",
            Some(json!({ "name": "eve", "admin": true })),
            StatusCode::BAD_REQUEST,
        ),
        (
            Method::POST,
            "/api/v1/members",
            Some(json!({ "is_admin": true })),
            StatusCode::BAD_REQUEST,
        ),
        (
            Method::PUT,
            "/api/v1/branch-rules",
            rule("app.git", "heads/private/*", json!(["core"])),
            StatusCode::BAD_REQUEST,
        ),
        (
            Method::PUT,
            "/api/v1/branch-rules",
            rule("app.git", "refs/heads/[oops", json!(["core"])),
            StatusCode::BAD_REQUEST,
        ),
        (
            Method::PUT,
            "/api/v1/branch-rules",
            rule("app.git", "refs/heads/private/*", json!([])),
            StatusCode::BAD_REQUEST,
        ),
        (
            Method::PUT,
            "/api/v1/branch-rules",
            rule("app.git", "refs/heads/private/*", json!(["ghosts"])),
            StatusCode::NOT_FOUND,
        ),
        (
            Method::PUT,
            "/api/v1/branch-rules",
            rule("other.git", "refs/heads/private/*", json!(["core"])),
            StatusCode::NOT_FOUND,
        ),
        (
            Method::PUT,
            "/api/v1/branch-rules",
            rule("../app.git", "refs/heads/private/*", json!(["core"])),
            StatusCode::BAD_REQUEST,
        ),
        (
            Method::GET,
            "/api/v1/branch-rules?repo=other.git",
            None,
            StatusCode::NOT_FOUND,
        ),
        (
            Method::GET,
            "/api/v1/branch-rules",
            None,
            StatusCode::BAD_REQUEST,
        ),
        (
            Method::DELETE,
            "/api/v1/branch-rules?repo=app.git&pattern=refs%2Fheads%2Fnone",
            None,
            StatusCode::NOT_FOUND,
        ),
        (
            Method::GET,
            "/api/v1/members?include_revoked=maybe",
            None,
            StatusCode::BAD_REQUEST,
        ),
    ];
    for (method, uri, body, status) in cases {
        let reply = api.admin(method.clone(), uri, body.clone()).await;
        assert_eq!(
            reply.status, status,
            "{method} {uri} {body:?}: {}",
            reply.json
        );
        assert!(
            reply.json.get("error").is_some_and(Value::is_string),
            "{method} {uri}: {}",
            reply.json
        );
    }

    // Malformed JSON and a missing content type are refused too.
    let malformed = send_request(
        &api.router,
        Request::builder()
            .method(Method::POST)
            .uri("/api/v1/groups")
            .header(header::AUTHORIZATION, bearer_header(ADMIN_TOKEN))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from("{\"name\":")),
    )
    .await;
    assert_eq!(malformed.status, StatusCode::BAD_REQUEST);
    let untyped = send_request(
        &api.router,
        Request::builder()
            .method(Method::POST)
            .uri("/api/v1/groups")
            .header(header::AUTHORIZATION, bearer_header(ADMIN_TOKEN))
            .body(Body::from("{\"name\":\"core2\"}")),
    )
    .await;
    assert_eq!(untyped.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert!(untyped.json.get("error").is_some());

    // Only the group and repository set up above were recorded.
    assert_eq!(api.store.audit_entries().len(), 2);
}

#[tokio::test]
async fn oversized_bodies_are_rejected() {
    let api = Api::new();
    let oversized = json!({ "name": "x".repeat(MAX_ADMIN_BODY_BYTES) });
    let reply = api
        .admin(Method::POST, "/api/v1/groups", Some(oversized))
        .await;
    assert_eq!(reply.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert!(reply.json.get("error").is_some_and(Value::is_string));
    assert_no_store(&reply);
}

#[tokio::test]
async fn every_change_is_audited_without_tokens() {
    let api = Api::new();
    api.create_group("core").await;
    let alice_token = api.create_member("alice", &["core"]).await;
    let issued = api
        .admin_expect(
            Method::POST,
            "/api/v1/members/alice/tokens",
            Some(json!({ "label": "second" })),
            StatusCode::CREATED,
        )
        .await;
    let second_token = string_field(&issued, "token");
    api.admin_expect(
        Method::POST,
        "/api/v1/groups/core/members",
        Some(json!({ "member": "dev" })),
        StatusCode::OK,
    )
    .await;
    // Idempotent no-ops are not audited.
    api.admin_expect(
        Method::POST,
        "/api/v1/groups/core/members",
        Some(json!({ "member": "dev" })),
        StatusCode::OK,
    )
    .await;
    api.admin_expect(
        Method::DELETE,
        "/api/v1/groups/core/members/dev",
        None,
        StatusCode::OK,
    )
    .await;
    api.admin_expect(
        Method::POST,
        "/api/v1/repositories",
        Some(json!({ "path": "app.git" })),
        StatusCode::CREATED,
    )
    .await;
    api.admin_expect(
        Method::POST,
        "/api/v1/repositories",
        Some(json!({ "path": "app.git" })),
        StatusCode::OK,
    )
    .await;
    api.admin_expect(
        Method::PUT,
        "/api/v1/branch-rules",
        Some(json!({
            "repository": "app.git",
            "pattern": "refs/heads/private/*",
            "groups": ["core"],
        })),
        StatusCode::OK,
    )
    .await;
    api.admin_expect(
        Method::DELETE,
        "/api/v1/branch-rules?repo=app.git&pattern=refs%2Fheads%2Fprivate%2F*",
        None,
        StatusCode::OK,
    )
    .await;
    api.admin_expect(
        Method::DELETE,
        "/api/v1/members/alice",
        None,
        StatusCode::OK,
    )
    .await;
    api.admin_expect(
        Method::DELETE,
        "/api/v1/members/alice",
        None,
        StatusCode::OK,
    )
    .await;

    let entries = api.store.audit_entries();
    let summary: Vec<(&str, &str, &str)> = entries
        .iter()
        .map(|entry| {
            (
                entry.action.as_str(),
                entry.target_type.as_str(),
                entry.target_name.as_str(),
            )
        })
        .collect();
    assert_eq!(
        summary,
        vec![
            ("group.create", "group", "core"),
            ("member.grant", "member", "alice"),
            ("member.token_issue", "member", "alice"),
            ("group.member_add", "group_membership", "core:dev"),
            ("group.member_remove", "group_membership", "core:dev"),
            ("repository.register", "repository", "app.git"),
            (
                "branch_rule.set",
                "branch_rule",
                "app.git:refs/heads/private/*"
            ),
            (
                "branch_rule.remove",
                "branch_rule",
                "app.git:refs/heads/private/*"
            ),
            ("member.revoke", "member", "alice"),
        ]
    );
    assert!(entries.iter().all(|entry| entry.actor_member_id == Some(1)));
    let Some(grant) = entries.get(1) else {
        panic!("missing grant entry");
    };
    assert_eq!(
        grant.details,
        json!({
            "is_admin": false,
            "is_machine": false,
            "has_public_key": false,
            "groups": ["core"],
            "token_label": "",
        })
    );
    let everything = format!("{entries:?}");
    for secret in [&alice_token, &second_token] {
        assert!(!everything.contains(secret.as_str()));
    }
    assert!(!everything.contains("scrim_"));
}

#[tokio::test]
async fn memory_store_bootstraps_exactly_one_admin() {
    let store = MemoryPolicyStore::new();
    let created = match store.bootstrap_admin("first", "bootstrap").await {
        Ok(created) => created,
        Err(error) => panic!("bootstrap failed: {error}"),
    };
    assert!(created.member.is_admin);
    assert!(created.token.expose_secret().starts_with("scrim_"));
    match store.bootstrap_admin("second", "bootstrap").await {
        Err(PolicyStoreError::Conflict(message)) => {
            assert_eq!(message, "an active admin already exists");
        }
        Err(error) => panic!("unexpected error: {error}"),
        Ok(_) => panic!("a second admin was bootstrapped"),
    }
    match store.bootstrap_admin("bad name", "bootstrap").await {
        Err(PolicyStoreError::InvalidInput(_)) => {}
        Err(error) => panic!("unexpected error: {error}"),
        Ok(_) => panic!("an invalid name was accepted"),
    }

    let root = match TempDir::new() {
        Ok(root) => root,
        Err(error) => panic!("failed to create repo root: {error}"),
    };
    let router =
        scrim_server::router_with_policy_store(root.path().to_path_buf(), Arc::new(store.clone()));
    let reply = send(
        &router,
        Method::GET,
        "/api/v1/whoami",
        Some(created.token.expose_secret()),
        None,
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.json.get("name"), Some(&json!("first")));
    assert_eq!(reply.json.get("is_admin"), Some(&json!(true)));
    let actions: Vec<String> = store
        .audit_entries()
        .into_iter()
        .map(|entry| entry.action)
        .collect();
    assert_eq!(actions, ["member.bootstrap_admin"]);
}

/// Lists the branches `token`'s member can see in `repo` on the server at
/// `base_url`.
async fn visible_branches(
    sandbox: &Arc<GitSandbox>,
    base_url: &str,
    repo: &str,
    token: &str,
) -> Vec<String> {
    let sandbox = Arc::clone(sandbox);
    let url = format!("{base_url}/{repo}");
    let header_config = format!("http.extraHeader=Authorization: {}", bearer_header(token));
    let output = tokio::task::spawn_blocking(move || {
        let Ok(cwd) = std::env::current_dir() else {
            panic!("no current directory");
        };
        sandbox.git(&cwd, &["-c", &header_config, "ls-remote", "--heads", &url])
    })
    .await;
    let output = match output {
        Ok(output) => output,
        Err(error) => panic!("ls-remote task failed: {error}"),
    };
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.split('\t').nth(1))
        .filter_map(|name| name.strip_prefix("refs/heads/"))
        .map(str::to_owned)
        .collect()
}

/// Pushes a commit to `main` and `private/wip` of the bare repository at
/// `repo_dir` straight through the filesystem.
fn populate(sandbox: &GitSandbox, repo_dir: &Path) {
    let work = match TempDir::new() {
        Ok(work) => work,
        Err(error) => panic!("failed to create work dir: {error}"),
    };
    sandbox.git(work.path(), &["init", "--quiet", "--initial-branch=main"]);
    if let Err(error) = std::fs::write(work.path().join("readme.txt"), "hello\n") {
        panic!("failed to write file: {error}");
    }
    sandbox.git(work.path(), &["add", "readme.txt"]);
    sandbox.git(work.path(), &["commit", "--quiet", "-m", "first"]);
    let Some(repo_dir) = repo_dir.to_str() else {
        panic!("repository path is not UTF-8");
    };
    sandbox.git(
        work.path(),
        &[
            "push",
            "--quiet",
            repo_dir,
            "HEAD:refs/heads/main",
            "HEAD:refs/heads/private/wip",
        ],
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn branch_rules_change_git_visibility_immediately() {
    let api = Api::new();
    let sandbox = Arc::new(GitSandbox::new());
    let base_url =
        spawn_server_with_store(api.root.path().to_path_buf(), Arc::new(api.store.clone())).await;

    api.admin_expect(
        Method::POST,
        "/api/v1/repositories",
        Some(json!({ "path": "team.git" })),
        StatusCode::CREATED,
    )
    .await;
    populate(&sandbox, &api.root.path().join("team.git"));
    api.create_group("core").await;
    api.create_group("security").await;
    let alice = api.create_member("alice", &["core"]).await;
    let bob = api.create_member("bob", &[]).await;
    let everything = ["main".to_owned(), "private/wip".to_owned()];
    let main_only = ["main".to_owned()];

    assert_eq!(
        visible_branches(&sandbox, &base_url, "team.git", &bob).await,
        everything
    );

    let rule = api
        .admin_expect(
            Method::PUT,
            "/api/v1/branch-rules",
            Some(json!({
                "repository": "team.git",
                "pattern": "refs/heads/private/*",
                "groups": ["core"],
            })),
            StatusCode::OK,
        )
        .await;
    assert_eq!(
        rule,
        json!({
            "repository": "team.git",
            "pattern": "refs/heads/private/*",
            "groups": ["core"],
        })
    );
    assert_eq!(
        visible_branches(&sandbox, &base_url, "team.git", &bob).await,
        main_only
    );
    assert_eq!(
        visible_branches(&sandbox, &base_url, "team.git", &alice).await,
        everything
    );

    let listed = api
        .admin_expect(
            Method::GET,
            "/api/v1/branch-rules?repo=team.git",
            None,
            StatusCode::OK,
        )
        .await;
    assert_eq!(
        listed,
        json!({
            "repository": "team.git",
            "rules": [{ "pattern": "refs/heads/private/*", "groups": ["core"] }],
        })
    );

    api.admin_expect(
        Method::POST,
        "/api/v1/groups/core/members",
        Some(json!({ "member": "bob" })),
        StatusCode::OK,
    )
    .await;
    assert_eq!(
        visible_branches(&sandbox, &base_url, "team.git", &bob).await,
        everything
    );
    api.admin_expect(
        Method::DELETE,
        "/api/v1/groups/core/members/bob",
        None,
        StatusCode::OK,
    )
    .await;
    assert_eq!(
        visible_branches(&sandbox, &base_url, "team.git", &bob).await,
        main_only
    );

    // Replacing the rule's groups takes the branch away from `core`.
    api.admin_expect(
        Method::PUT,
        "/api/v1/branch-rules",
        Some(json!({
            "repository": "team.git",
            "pattern": "refs/heads/private/*",
            "groups": ["security"],
        })),
        StatusCode::OK,
    )
    .await;
    assert_eq!(
        visible_branches(&sandbox, &base_url, "team.git", &alice).await,
        main_only
    );

    let removed = api
        .admin_expect(
            Method::DELETE,
            "/api/v1/branch-rules?repo=team.git&pattern=refs%2Fheads%2Fprivate%2F*",
            None,
            StatusCode::OK,
        )
        .await;
    assert_eq!(
        removed,
        json!({ "repository": "team.git", "pattern": "refs/heads/private/*", "removed": true })
    );
    assert_eq!(
        visible_branches(&sandbox, &base_url, "team.git", &bob).await,
        everything
    );
    let listed = api
        .admin_expect(
            Method::GET,
            "/api/v1/branch-rules?repo=team.git",
            None,
            StatusCode::OK,
        )
        .await;
    assert_eq!(listed.get("rules"), Some(&json!([])));
}

fn scrim_server_command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_scrim-server"));
    command
        .env_remove("SCRIM_TOKEN")
        .env_remove("SCRIM_TOKEN_FILE")
        .env_remove("DATABASE_URL")
        .env_remove("SCRIM_REPO_ROOT")
        .env_remove("SCRIM_LISTEN")
        .env("NO_COLOR", "1");
    command
}

fn run_failing(command: &mut Command) -> String {
    let output = match command.output() {
        Ok(output) => output,
        Err(error) => panic!("failed to run scrim-server: {error}"),
    };
    assert!(!output.status.success(), "expected scrim-server to fail");
    assert!(output.stdout.is_empty(), "nothing may be printed to stdout");
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn bootstrap_admin_requires_a_database_url() {
    let stderr = run_failing(scrim_server_command().args(["bootstrap-admin", "--name", "root"]));
    assert!(stderr.contains("--database-url"), "{stderr}");
}

#[test]
fn bootstrap_admin_requires_a_name() {
    let stderr = run_failing(scrim_server_command().args([
        "bootstrap-admin",
        "--database-url",
        "postgres://scrim:hunter2@127.0.0.1:1/scrim",
    ]));
    assert!(stderr.contains("--name"), "{stderr}");
    assert!(!stderr.contains("hunter2"), "{stderr}");
}

#[test]
fn bootstrap_admin_is_listed_and_serving_still_needs_its_arguments() {
    let output = match scrim_server_command().arg("--help").output() {
        Ok(output) => output,
        Err(error) => panic!("failed to run scrim-server: {error}"),
    };
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("bootstrap-admin"));

    let stderr = run_failing(scrim_server_command().args(["--listen", "127.0.0.1:0"]));
    assert!(stderr.contains("--repo-root"), "{stderr}");
}

#[tokio::test]
async fn member_public_key_lifecycle() {
    let api = Api::new();
    api.create_group("core").await;

    let dev_whoami = api
        .call(Method::GET, "/api/v1/whoami", Some(DEV_TOKEN), None)
        .await;
    assert_eq!(dev_whoami.status, StatusCode::OK);
    assert_eq!(dev_whoami.json.get("public_key"), Some(&json!(null)));

    // Non-admin can update their own public key.
    let updated_own = api
        .call(
            Method::PUT,
            "/api/v1/me/public-key",
            Some(DEV_TOKEN),
            Some(json!({ "public_key": TEST_AGE_KEY_1 })),
        )
        .await;
    assert_eq!(updated_own.status, StatusCode::OK);
    assert_no_store(&updated_own);
    assert_eq!(
        updated_own.json,
        json!({ "name": "dev", "public_key": TEST_AGE_KEY_1 })
    );

    let dev_whoami = api
        .call(Method::GET, "/api/v1/whoami", Some(DEV_TOKEN), None)
        .await;
    assert_eq!(dev_whoami.status, StatusCode::OK);
    assert_eq!(
        dev_whoami.json.get("public_key"),
        Some(&json!(TEST_AGE_KEY_1))
    );

    // Non-admin cannot set another member's public key.
    let forbidden = api
        .call(
            Method::PUT,
            "/api/v1/members/root/public-key",
            Some(DEV_TOKEN),
            Some(json!({ "public_key": TEST_AGE_KEY_2 })),
        )
        .await;
    assert_eq!(forbidden.status, StatusCode::FORBIDDEN);
    assert_eq!(forbidden.error(), "admin privileges required");

    // Admin can set public_key at member creation and update it later.
    let alice = api
        .admin_expect(
            Method::POST,
            "/api/v1/members",
            Some(json!({
                "name": "alice",
                "groups": ["core"],
                "public_key": TEST_AGE_KEY_2,
            })),
            StatusCode::CREATED,
        )
        .await;
    let alice_token = string_field(&alice, "token");
    assert_eq!(
        alice.pointer("/member/public_key"),
        Some(&json!(TEST_AGE_KEY_2))
    );

    let alice_whoami = api
        .call(Method::GET, "/api/v1/whoami", Some(&alice_token), None)
        .await;
    assert_eq!(alice_whoami.status, StatusCode::OK);
    assert_eq!(
        alice_whoami.json.get("public_key"),
        Some(&json!(TEST_AGE_KEY_2))
    );

    let updated_alice = api
        .admin_expect(
            Method::PUT,
            "/api/v1/members/alice/public-key",
            Some(json!({ "public_key": TEST_AGE_KEY_3 })),
            StatusCode::OK,
        )
        .await;
    assert_eq!(
        updated_alice,
        json!({ "name": "alice", "public_key": TEST_AGE_KEY_3 })
    );

    let members = api
        .admin_expect(Method::GET, "/api/v1/members", None, StatusCode::OK)
        .await;
    let Some(member_list) = members.get("members").and_then(Value::as_array) else {
        panic!("missing members in {members}");
    };
    let alice_entry = member_list
        .iter()
        .find(|entry| entry.get("name") == Some(&json!("alice")));
    assert_eq!(
        alice_entry.and_then(|entry| entry.get("public_key")),
        Some(&json!(TEST_AGE_KEY_3))
    );

    // Invalid age public keys fail with 400 Bad Request everywhere.
    let mut bad_checksum = TEST_AGE_KEY_1.to_owned();
    bad_checksum.pop();
    bad_checksum.push('q');
    for invalid_key in [
        "not-a-key",
        bad_checksum.as_str(),
        TEST_AGE_KEY_ALL_ZERO,
        "",
    ] {
        let create_bad = api
            .admin(
                Method::POST,
                "/api/v1/members",
                Some(json!({ "name": "badkey", "public_key": invalid_key })),
            )
            .await;
        assert_eq!(
            create_bad.status,
            StatusCode::BAD_REQUEST,
            "{invalid_key:?}"
        );

        let own_bad = api
            .call(
                Method::PUT,
                "/api/v1/me/public-key",
                Some(DEV_TOKEN),
                Some(json!({ "public_key": invalid_key })),
            )
            .await;
        assert_eq!(own_bad.status, StatusCode::BAD_REQUEST, "{invalid_key:?}");

        let admin_bad = api
            .admin(
                Method::PUT,
                "/api/v1/members/alice/public-key",
                Some(json!({ "public_key": invalid_key })),
            )
            .await;
        assert_eq!(admin_bad.status, StatusCode::BAD_REQUEST, "{invalid_key:?}");
    }

    // Unknown and revoked members return 404 Not Found.
    let missing_member = api
        .admin(
            Method::PUT,
            "/api/v1/members/nobody/public-key",
            Some(json!({ "public_key": TEST_AGE_KEY_1 })),
        )
        .await;
    assert_eq!(missing_member.status, StatusCode::NOT_FOUND);

    api.admin_expect(
        Method::DELETE,
        "/api/v1/members/alice",
        None,
        StatusCode::OK,
    )
    .await;
    let revoked_member = api
        .admin(
            Method::PUT,
            "/api/v1/members/alice/public-key",
            Some(json!({ "public_key": TEST_AGE_KEY_1 })),
        )
        .await;
    assert_eq!(revoked_member.status, StatusCode::NOT_FOUND);

    // Audit log records member.public_key_set and has_public_key.
    let entries = api.store.audit_entries();
    assert!(entries.iter().any(|entry| {
        entry.action == "member.public_key_set"
            && entry.actor_member_id == Some(2)
            && entry.target_type == "member"
            && entry.target_name == "dev"
            && entry.details == json!({ "public_key": TEST_AGE_KEY_1 })
    }));
    assert!(entries.iter().any(|entry| {
        entry.action == "member.public_key_set"
            && entry.actor_member_id == Some(1)
            && entry.target_type == "member"
            && entry.target_name == "alice"
            && entry.details == json!({ "public_key": TEST_AGE_KEY_3 })
    }));
    assert!(entries.iter().any(|entry| {
        entry.action == "member.grant"
            && entry.target_name == "alice"
            && entry.details.get("has_public_key") == Some(&json!(true))
    }));
}

#[tokio::test]
async fn secret_scopes_and_recipients_lifecycle() {
    let api = Api::new();
    api.create_group("core").await;
    api.create_group("security").await;
    api.create_group("ops").await;
    api.admin_expect(
        Method::POST,
        "/api/v1/repositories",
        Some(json!({ "path": "team/app.git" })),
        StatusCode::CREATED,
    )
    .await;

    let alice_created = api
        .admin_expect(
            Method::POST,
            "/api/v1/members",
            Some(json!({
                "name": "alice",
                "groups": ["core", "security"],
                "public_key": TEST_AGE_KEY_1,
            })),
            StatusCode::CREATED,
        )
        .await;
    let alice_token = string_field(&alice_created, "token");

    let _bob_token = api.create_member("bob", &["core"]).await;

    let charlie_created = api
        .admin_expect(
            Method::POST,
            "/api/v1/members",
            Some(json!({
                "name": "charlie",
                "groups": ["ops"],
                "public_key": TEST_AGE_KEY_2,
            })),
            StatusCode::CREATED,
        )
        .await;
    let charlie_token = string_field(&charlie_created, "token");

    let _revoked_token = api
        .admin_expect(
            Method::POST,
            "/api/v1/members",
            Some(json!({
                "name": "revoked_user",
                "groups": ["core"],
                "public_key": TEST_AGE_KEY_3,
            })),
            StatusCode::CREATED,
        )
        .await;
    api.admin_expect(
        Method::DELETE,
        "/api/v1/members/revoked_user",
        None,
        StatusCode::OK,
    )
    .await;

    // Validation and missing-target errors on secret scope admin endpoints.
    let invalid_cases = vec![
        (
            Method::PUT,
            "/api/v1/secret-scopes",
            Some(json!({ "repository": "team/app.git", "scope": "-bad", "groups": ["core"] })),
            StatusCode::BAD_REQUEST,
        ),
        (
            Method::PUT,
            "/api/v1/secret-scopes",
            Some(json!({ "repository": "team/app.git", "scope": "dev", "groups": [] })),
            StatusCode::BAD_REQUEST,
        ),
        (
            Method::PUT,
            "/api/v1/secret-scopes",
            Some(json!({ "repository": "../bad.git", "scope": "dev", "groups": ["core"] })),
            StatusCode::BAD_REQUEST,
        ),
        (
            Method::PUT,
            "/api/v1/secret-scopes",
            Some(json!({ "repository": "missing.git", "scope": "dev", "groups": ["core"] })),
            StatusCode::NOT_FOUND,
        ),
        (
            Method::PUT,
            "/api/v1/secret-scopes",
            Some(json!({ "repository": "team/app.git", "scope": "dev", "groups": ["ghosts"] })),
            StatusCode::NOT_FOUND,
        ),
        (
            Method::GET,
            "/api/v1/secret-scopes?repo=missing.git",
            None,
            StatusCode::NOT_FOUND,
        ),
        (
            Method::DELETE,
            "/api/v1/secret-scopes?repo=team/app.git&scope=missing",
            None,
            StatusCode::NOT_FOUND,
        ),
    ];
    for (method, uri, body, expected_status) in invalid_cases {
        let reply = api.admin(method.clone(), uri, body).await;
        assert_eq!(
            reply.status, expected_status,
            "{method} {uri}: {}",
            reply.json
        );
    }

    // Create scopes: `prod` then `dev`, then update `dev` groups.
    let prod = api
        .admin_expect(
            Method::PUT,
            "/api/v1/secret-scopes",
            Some(json!({
                "repository": "team/app.git",
                "scope": "prod",
                "groups": ["ops"],
            })),
            StatusCode::OK,
        )
        .await;
    assert_eq!(
        prod,
        json!({ "repository": "team/app.git", "scope": "prod", "groups": ["ops"] })
    );

    api.admin_expect(
        Method::PUT,
        "/api/v1/secret-scopes",
        Some(json!({
            "repository": "team/app.git",
            "scope": "dev",
            "groups": ["core"],
        })),
        StatusCode::OK,
    )
    .await;
    let dev_updated = api
        .admin_expect(
            Method::PUT,
            "/api/v1/secret-scopes",
            Some(json!({
                "repository": "team/app.git",
                "scope": "dev",
                "groups": ["security", "core"],
            })),
            StatusCode::OK,
        )
        .await;
    assert_eq!(
        dev_updated,
        json!({ "repository": "team/app.git", "scope": "dev", "groups": ["core", "security"] })
    );

    let listed = api
        .admin_expect(
            Method::GET,
            "/api/v1/secret-scopes?repo=team%2Fapp.git",
            None,
            StatusCode::OK,
        )
        .await;
    assert_eq!(
        listed,
        json!({
            "repository": "team/app.git",
            "scopes": [
                { "scope": "dev", "groups": ["core", "security"] },
                { "scope": "prod", "groups": ["ops"] },
            ],
        })
    );

    // Authorized non-admin (alice) can resolve `dev` recipients; `alice` is deduplicated
    // across `core` and `security`, `bob` is in `members_without_key`, and `revoked_user` is excluded.
    let alice_recipients = api
        .call(
            Method::GET,
            "/api/v1/secret-scopes/recipients?repo=team%2Fapp.git&scope=dev",
            Some(&alice_token),
            None,
        )
        .await;
    assert_eq!(alice_recipients.status, StatusCode::OK);
    assert_no_store(&alice_recipients);
    assert_eq!(
        alice_recipients.json,
        json!({
            "repository": "team/app.git",
            "scope": "dev",
            "groups": ["core", "security"],
            "recipients": [{ "member": "alice", "public_key": TEST_AGE_KEY_1 }],
            "members_without_key": ["bob"],
        })
    );

    // Unauthorized non-admin (charlie, only in `ops`) gets 403 for `dev`,
    // AND 403 (not 404) for non-existent scopes / unregistered repos to prevent enumeration.
    for uri in [
        "/api/v1/secret-scopes/recipients?repo=team%2Fapp.git&scope=dev",
        "/api/v1/secret-scopes/recipients?repo=team%2Fapp.git&scope=nonexistent",
        "/api/v1/secret-scopes/recipients?repo=unknown.git&scope=dev",
    ] {
        let forbidden = api.call(Method::GET, uri, Some(&charlie_token), None).await;
        assert_eq!(forbidden.status, StatusCode::FORBIDDEN, "{uri}");
        assert_eq!(
            forbidden.error(),
            "access to this secret scope is forbidden"
        );
    }

    // Admins can resolve any scope and get 404 for unknown scopes/repos.
    let admin_prod = api
        .admin_expect(
            Method::GET,
            "/api/v1/secret-scopes/recipients?repo=team%2Fapp.git&scope=prod",
            None,
            StatusCode::OK,
        )
        .await;
    assert_eq!(
        admin_prod,
        json!({
            "repository": "team/app.git",
            "scope": "prod",
            "groups": ["ops"],
            "recipients": [{ "member": "charlie", "public_key": TEST_AGE_KEY_2 }],
            "members_without_key": [],
        })
    );
    let admin_missing = api
        .admin(
            Method::GET,
            "/api/v1/secret-scopes/recipients?repo=team%2Fapp.git&scope=nonexistent",
            None,
        )
        .await;
    assert_eq!(admin_missing.status, StatusCode::NOT_FOUND);

    // Delete `prod` scope and verify it's removed and audited.
    let removed = api
        .admin_expect(
            Method::DELETE,
            "/api/v1/secret-scopes?repo=team%2Fapp.git&scope=prod",
            None,
            StatusCode::OK,
        )
        .await;
    assert_eq!(
        removed,
        json!({ "repository": "team/app.git", "scope": "prod", "removed": true })
    );
    let after_delete = api
        .admin(
            Method::GET,
            "/api/v1/secret-scopes/recipients?repo=team%2Fapp.git&scope=prod",
            None,
        )
        .await;
    assert_eq!(after_delete.status, StatusCode::NOT_FOUND);

    let entries = api.store.audit_entries();
    assert!(entries.iter().any(|entry| {
        entry.action == "secret_scope.set"
            && entry.target_type == "secret_scope"
            && entry.target_name == "team/app.git:dev"
            && entry.details
                == json!({
                    "repository": "team/app.git",
                    "scope": "dev",
                    "groups": ["core", "security"],
                })
    }));
    assert!(entries.iter().any(|entry| {
        entry.action == "secret_scope.remove"
            && entry.target_type == "secret_scope"
            && entry.target_name == "team/app.git:prod"
            && entry.details == json!({ "repository": "team/app.git", "scope": "prod" })
    }));
}

#[tokio::test]
async fn group_recipients_lifecycle_and_authorization() {
    let api = Api::new();
    api.create_group("core").await;
    api.create_group("ops").await;

    let alice_token = api.create_member("alice", &["core"]).await;
    let _bob_token = api.create_member("bob", &["core"]).await;
    let zoe_token = api.create_member("zoe", &["core"]).await;
    let charlie_token = api.create_member("charlie", &["ops"]).await;
    let _revoked_token = api.create_member("revoked_user", &["core"]).await;

    api.admin_expect(
        Method::PUT,
        "/api/v1/members/alice/public-key",
        Some(json!({ "public_key": TEST_AGE_KEY_1 })),
        StatusCode::OK,
    )
    .await;
    let zoe_key_reply = api
        .call(
            Method::PUT,
            "/api/v1/me/public-key",
            Some(&zoe_token),
            Some(json!({ "public_key": TEST_AGE_KEY_3 })),
        )
        .await;
    assert_eq!(zoe_key_reply.status, StatusCode::OK);
    api.admin_expect(
        Method::PUT,
        "/api/v1/members/charlie/public-key",
        Some(json!({ "public_key": TEST_AGE_KEY_2 })),
        StatusCode::OK,
    )
    .await;
    api.admin_expect(
        Method::PUT,
        "/api/v1/members/revoked_user/public-key",
        Some(json!({ "public_key": TEST_AGE_KEY_2 })),
        StatusCode::OK,
    )
    .await;
    api.admin_expect(
        Method::DELETE,
        "/api/v1/members/revoked_user",
        None,
        StatusCode::OK,
    )
    .await;

    // Authorized group member (alice in `core`) gets 200 with Cache-Control: no-store,
    // keyed recipients sorted ascending, `bob` in `members_without_key`, and revoked member excluded.
    let alice_reply = api
        .call(
            Method::GET,
            "/api/v1/groups/core/recipients",
            Some(&alice_token),
            None,
        )
        .await;
    assert_eq!(alice_reply.status, StatusCode::OK);
    assert_no_store(&alice_reply);
    assert_eq!(
        alice_reply.json,
        json!({
            "group": "core",
            "recipients": [
                { "member": "alice", "public_key": TEST_AGE_KEY_1 },
                { "member": "zoe", "public_key": TEST_AGE_KEY_3 },
            ],
            "members_without_key": ["bob"],
        })
    );

    // Unauthorized non-admin (charlie in `ops`) gets 403 for `core`
    // AND 403 (not 404) for nonexistent group `ghosts`.
    for uri in [
        "/api/v1/groups/core/recipients",
        "/api/v1/groups/ghosts/recipients",
    ] {
        let forbidden = api.call(Method::GET, uri, Some(&charlie_token), None).await;
        assert_eq!(forbidden.status, StatusCode::FORBIDDEN, "{uri}");
        assert_eq!(forbidden.error(), "access to this group is forbidden");
    }

    // Admin (not in `ops`) gets 200 for `ops`, 404 for nonexistent `ghosts`,
    // and 400 for an invalid group name.
    let admin_ops = api
        .admin_expect(
            Method::GET,
            "/api/v1/groups/ops/recipients",
            None,
            StatusCode::OK,
        )
        .await;
    assert_eq!(
        admin_ops,
        json!({
            "group": "ops",
            "recipients": [{ "member": "charlie", "public_key": TEST_AGE_KEY_2 }],
            "members_without_key": [],
        })
    );
    let admin_missing = api
        .admin(Method::GET, "/api/v1/groups/ghosts/recipients", None)
        .await;
    assert_eq!(admin_missing.status, StatusCode::NOT_FOUND);
    let admin_invalid = api
        .admin(Method::GET, "/api/v1/groups/.bad/recipients", None)
        .await;
    assert_eq!(admin_invalid.status, StatusCode::BAD_REQUEST);
}
