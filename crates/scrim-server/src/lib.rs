//! Pass-through Git smart-HTTP server for bare repositories.
//!
//! All requests require token authentication (`Authorization: Bearer <token>`
//! or `Authorization: Basic ...`) verified against a [`PolicyStore`] before
//! decompression or repository lookup. Each Git request then gets its own
//! `transfer.hideRefs` list, built from the repository's branch rules and the
//! member's groups, so refs the member may not see are neither advertised,
//! fetchable by object ID, nor pushable.

// The `?` operator and the unwrap/expect family are deliberately forbidden in
// this codebase; clippy's suggestion to use `?` is allowed away accordingly.
#![allow(clippy::question_mark)]

mod auth;
mod git_service;
mod policy_store;
mod repo_path;

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::Arc,
};

use axum::{
    Router,
    body::Body,
    extract::{Request, State},
    http::{HeaderValue, Method, StatusCode, header},
    middleware,
    response::{IntoResponse, Response},
};
use tower_http::{decompression::RequestDecompressionLayer, trace::TraceLayer};

pub use auth::{AuthConfigError, MAX_TOKEN_BYTES, TokenAuth};
use git_service::{
    GitService, GitVisibilityConfig, advertise_refs, list_repo_refs, sanitize_git_protocol,
    serve_rpc,
};
pub use policy_store::{
    AuthenticatedMember, MemberRepoPolicy, MemoryPolicyStore, PgPolicyStore, PolicyStore,
    PolicyStoreError, PolicyStoreFuture, StaticPolicyStore,
};
use repo_path::{RepoHead, read_valid_head, resolve_bare_repo};
pub use secrecy::SecretString;

/// Builds the router that serves the bare repositories found under `repo_root`
/// over Git smart HTTP (`info/refs`, `git-upload-pack`, `git-receive-pack`),
/// authenticating every request against the single shared token `auth`.
///
/// Equivalent to [`router_with_policy_store`] with a [`StaticPolicyStore`]:
/// there are no branch rules, so every ref is visible.
pub fn router(repo_root: PathBuf, auth: TokenAuth) -> Router {
    router_with_policy_store(repo_root, Arc::new(StaticPolicyStore::new(auth)))
}

/// Builds the router that serves the bare repositories found under `repo_root`
/// over Git smart HTTP, with members and branch rules from `policy_store`.
///
/// Incoming requests are traced (method and path only), authenticated against
/// `policy_store`, and (for gzip request bodies) decompressed transparently
/// before repository resolution. Any store failure is answered with `500`.
pub fn router_with_policy_store(repo_root: PathBuf, policy_store: Arc<dyn PolicyStore>) -> Router {
    let state = AppState {
        repo_root,
        policy_store: Arc::clone(&policy_store),
    };
    Router::new()
        // Axum wildcards cannot be followed by a literal suffix, so a single
        // fallback parses `<repo>/info/refs` and `<repo>/git-*-pack` itself.
        .fallback(handle_request)
        .with_state(state)
        .layer(RequestDecompressionLayer::new())
        .layer(middleware::from_fn_with_state(
            policy_store,
            auth::require_auth,
        ))
        .layer(
            TraceLayer::new_for_http().make_span_with(|request: &Request| {
                // Record only method and path so query strings or accidental
                // URI credentials are never written to logs.
                tracing::debug_span!(
                    "request",
                    method = %request.method(),
                    path = %request.uri().path(),
                )
            }),
        )
}

/// State shared by every request handler.
#[derive(Clone)]
struct AppState {
    repo_root: PathBuf,
    policy_store: Arc<dyn PolicyStore>,
}

/// The kind of smart-HTTP endpoint a request path addresses.
#[derive(Clone, Copy)]
enum Endpoint {
    InfoRefs,
    Rpc(GitService),
}

/// Splits a request path into the repository part and the endpoint suffix.
fn parse_path(path: &str) -> Option<(&str, Endpoint)> {
    let path = match path.strip_prefix('/') {
        Some(path) => path,
        None => return None,
    };
    [
        ("/info/refs", Endpoint::InfoRefs),
        ("/git-upload-pack", Endpoint::Rpc(GitService::UploadPack)),
        ("/git-receive-pack", Endpoint::Rpc(GitService::ReceivePack)),
    ]
    .into_iter()
    .find_map(|(suffix, endpoint)| path.strip_suffix(suffix).map(|repo| (repo, endpoint)))
}

async fn handle_request(State(state): State<AppState>, request: Request) -> Response {
    let mut response = route_request(&state.repo_root, state.policy_store.as_ref(), request).await;
    // Git responses must never be cached by clients or proxies.
    let headers = response.headers_mut();
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-cache, max-age=0, must-revalidate"),
    );
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    headers.insert(
        header::EXPIRES,
        HeaderValue::from_static("Fri, 01 Jan 1980 00:00:00 GMT"),
    );
    response
}

async fn route_request(
    repo_root: &Path,
    policy_store: &dyn PolicyStore,
    request: Request,
) -> Response {
    let (parts, body) = request.into_parts();

    // `require_auth` always inserts the member; its absence is a wiring bug,
    // and serving without knowing the member could expose hidden refs.
    let Some(member) = parts.extensions.get::<AuthenticatedMember>() else {
        tracing::error!("request reached the git handler without an authenticated member");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };

    // Same generic answer for malformed, missing and out-of-root repositories.
    let not_found = || (StatusCode::NOT_FOUND, "not found").into_response();
    let Some((repo, endpoint)) = parse_path(parts.uri.path()) else {
        return not_found();
    };
    let Some(resolved_repo) = resolve_bare_repo(repo_root, repo).await else {
        return not_found();
    };
    tracing::debug!(repository = %resolved_repo.canonical_key, "resolved repository");

    // Validate the request shape before touching the policy store or git.
    // `is_advertisement` distinguishes `info/refs` from the RPC endpoints.
    let (service, is_advertisement) = match endpoint {
        Endpoint::InfoRefs => {
            if parts.method != Method::GET {
                return StatusCode::METHOD_NOT_ALLOWED.into_response();
            }
            // Without a valid `service` this is a dumb-HTTP request, which is
            // not supported.
            let service = parts
                .uri
                .query()
                .and_then(|query| {
                    query
                        .split('&')
                        .find_map(|pair| pair.strip_prefix("service="))
                })
                .and_then(GitService::from_service_name);
            let Some(service) = service else {
                return (StatusCode::FORBIDDEN, "dumb HTTP is not supported").into_response();
            };
            (service, true)
        }
        Endpoint::Rpc(service) => {
            if parts.method != Method::POST {
                return StatusCode::METHOD_NOT_ALLOWED.into_response();
            }
            let expected_content_type = format!("application/x-{}-request", service.service_name());
            let has_expected_content_type = parts
                .headers
                .get(header::CONTENT_TYPE)
                .is_some_and(|value| value.as_bytes() == expected_content_type.as_bytes());
            if !has_expected_content_type {
                return StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response();
            }
            (service, false)
        }
    };

    // Policy is looked up by the canonical key, so a symlinked alias gets the
    // rules of the repository it points to.
    let policy = match policy_store
        .load_member_repo_policy(member.id, &resolved_repo.canonical_key)
        .await
    {
        Ok(policy) => policy,
        Err(error) => {
            tracing::error!(
                %error,
                repository = %resolved_repo.canonical_key,
                "failed to load repository policy"
            );
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let visibility = match compute_visibility(&policy, &resolved_repo.dir).await {
        Ok(Visibility::Allowed(visibility)) => visibility,
        Ok(Visibility::HeadHidden) => return (StatusCode::FORBIDDEN, "forbidden").into_response(),
        Ok(Visibility::HeadInvalid) => return not_found(),
        Err(error) => {
            tracing::error!(%error, "failed to list repository refs");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    // Only pass through a Git-Protocol value git can safely receive.
    let git_protocol = parts
        .headers
        .get("git-protocol")
        .and_then(|value| value.to_str().ok())
        .and_then(sanitize_git_protocol);

    let result = if is_advertisement {
        advertise_refs(service, &resolved_repo.dir, git_protocol, &visibility)
            .await
            .map(|body| (service, "advertisement", body))
    } else {
        serve_rpc(service, &resolved_repo.dir, git_protocol, &visibility, body)
            .map(|body| (service, "result", body))
    };

    match result {
        Ok((service, kind, body)) => git_response(service, kind, body),
        Err(error) => {
            tracing::error!(%error, "failed to run git");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// The outcome of [`compute_visibility`].
enum Visibility {
    /// Serve the request with this configuration.
    Allowed(GitVisibilityConfig),
    /// `HEAD` leads to a ref the member may not see.
    HeadHidden,
    /// `HEAD` became unreadable or invalid after the repository was resolved.
    HeadInvalid,
}

/// Decides what `policy`'s member may see in the repository at `repo_dir`.
///
/// A member who satisfies every rule sees everything, at no extra cost.
/// Otherwise the repository's refs are listed and `HEAD` is re-read (as close
/// to starting git as possible), and:
/// - a symbolic `HEAD` whose chain reaches a hidden ref is refused outright:
///   `transfer.hideRefs` cannot hide it, and git would still advertise its
///   object ID and `symref=HEAD:<target>`;
/// - a symbolic ref whose chain reaches a hidden ref is hidden by name, since
///   git would advertise it with the hidden ref's object ID;
/// - a detached `HEAD` is hidden, as it may point at a commit only reachable
///   from hidden refs.
async fn compute_visibility(
    policy: &MemberRepoPolicy,
    repo_dir: &Path,
) -> std::io::Result<Visibility> {
    let plan = policy.branch_policy.hidden_ref_plan(&policy.member_groups);
    if !plan.has_unsatisfied_rules() {
        return Ok(Visibility::Allowed(GitVisibilityConfig::default()));
    }

    let repo_refs = match list_repo_refs(repo_dir).await {
        Ok(repo_refs) => repo_refs,
        Err(error) => return Err(error),
    };
    let Some(head) = read_valid_head(&repo_dir.join("HEAD")).await else {
        return Ok(Visibility::HeadInvalid);
    };
    let symrefs: BTreeMap<&str, &str> = repo_refs
        .iter()
        .filter_map(|entry| {
            entry
                .symref_target
                .as_deref()
                .map(|target| (entry.name.as_str(), target))
        })
        .collect();

    if let RepoHead::Symbolic(head_target) = &head
        && !policy
            .branch_policy
            .is_ref_chain_visible(head_target, &symrefs, &policy.member_groups)
    {
        return Ok(Visibility::HeadHidden);
    }

    let mut hidden_refs = plan.resolve_hide_refs_with_symrefs(
        &policy.branch_policy,
        &policy.member_groups,
        repo_refs.iter().map(|entry| entry.name.as_str()),
        &symrefs,
    );
    if head == RepoHead::Detached {
        hidden_refs.push("HEAD".to_owned());
    }
    Ok(Visibility::Allowed(GitVisibilityConfig {
        hidden_refs,
        enforce_visibility: true,
    }))
}

fn git_response(service: GitService, kind: &str, body: Body) -> Response {
    let content_type = format!("application/x-{}-{kind}", service.service_name());
    ([(header::CONTENT_TYPE, content_type)], body).into_response()
}
