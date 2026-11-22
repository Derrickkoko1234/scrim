//! Pass-through Git smart-HTTP server for bare repositories.
//!
//! All requests require token authentication (`Authorization: Bearer <token>`
//! or `Authorization: Basic ...`) verified against a [`PolicyStore`] before
//! decompression or repository lookup. Each Git request then gets its own
//! `transfer.hideRefs` list, built from the repository's branch rules and the
//! member's groups, so refs the member may not see are neither advertised,
//! fetchable by object ID, nor pushable. Every push additionally passes the
//! server-owned `pre-receive` guard (see [`run_pre_receive_hook_process`]),
//! which authorizes each ref write exactly, refuses hidden objects smuggled in
//! by ID, blocks merges that would expose private commits, and rejects pushes
//! introducing plaintext `.env` files or high-confidence credentials.
//! Members with withheld paths fetch through the server-owned `pack-objects`
//! hook (see [`run_pack_objects_hook_process`]), which leaves out every blob
//! reached only at a withheld path, and the `pre-receive` guard keeps them
//! from writing withheld paths or republishing withheld blobs.
//!
//! The same authenticated router serves the admin API under `/api/v1` (see
//! [`MAX_ADMIN_BODY_BYTES`]), through which admins manage members, tokens,
//! groups, repositories and branch rules in the [`PolicyStore`].

// The `?` operator and the unwrap/expect family are deliberately forbidden in
// this codebase; clippy's suggestion to use `?` is allowed away accordingly.
#![allow(clippy::question_mark)]

mod admin_api;
mod auth;
mod git_service;
mod pack_withhold;
mod policy_store;
mod pre_receive;
mod repo_path;
mod secret_scan;

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

pub use admin_api::MAX_ADMIN_BODY_BYTES;
pub use auth::{AuthConfigError, MAX_TOKEN_BYTES, TokenAuth};
use git_service::{
    GitService, GitVisibilityConfig, advertise_refs, list_repo_refs, sanitize_git_protocol,
    serve_rpc,
};
pub use pack_withhold::{
    PACK_OBJECTS_HOOK_MODE, PACK_OBJECTS_HOOK_MODE_ENV, run_pack_objects_hook_process,
};
use pack_withhold::{PackWithholdContext, start_pack_withhold_session};
pub use policy_store::{
    API_TOKEN_PREFIX, AuditLogEntry, AuthenticatedMember, BranchRuleRecord, CreateMemberRequest,
    CreatedMember, GroupMembershipChange, GroupRecipientsRecord, GroupRecord, GroupWithMembers,
    IssuedToken, MAX_NAME_BYTES, MAX_REPOSITORY_PATH_BYTES, MAX_SCOPE_NAME_BYTES,
    MAX_TOKEN_LABEL_BYTES, MemberPublicKeyRecord, MemberRecord, MemberRepoPolicy,
    MemoryPolicyStore, PathRuleRecord, PgPolicyStore, PolicyStore, PolicyStoreError,
    PolicyStoreFuture, RegisterRepositoryResult, RepositoryRecord, RevokeMemberResult,
    ScopeRecipient, ScopeRecipientsRecord, SecretScopeRecord, StaticPolicyStore,
};
pub use pre_receive::{
    ALLOW_MERGE_LEAK_PUSH_OPTION, ALLOW_SECRET_SCAN_PUSH_OPTION, PRE_RECEIVE_HOOK_MODE,
    PRE_RECEIVE_HOOK_MODE_ENV, run_pre_receive_hook_process,
};
use pre_receive::{HookDir, PreReceiveContext, start_pre_receive_session};
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
///
/// Pushes run the scrim-server binary as git's `pre-receive` hook (see
/// [`run_pre_receive_hook_process`]); the hook directory is set up on the
/// first push, and set up again if it has gone missing, and a push is
/// answered with `500` if the binary cannot be found.
///
/// Paths under `/api/v1` are the admin API instead of Git; repository paths
/// starting with `api/` can therefore not be registered.
pub fn router_with_policy_store(repo_root: PathBuf, policy_store: Arc<dyn PolicyStore>) -> Router {
    let admin_router = admin_api::router(repo_root.clone(), Arc::clone(&policy_store));
    let state = AppState {
        repo_root,
        policy_store: Arc::clone(&policy_store),
        hook_dir: Arc::new(tokio::sync::Mutex::new(None)),
    };
    Router::new()
        // Axum wildcards cannot be followed by a literal suffix, so a single
        // fallback parses `<repo>/info/refs` and `<repo>/git-*-pack` itself.
        .fallback(handle_request)
        .with_state(state)
        // `nest` covers `/api/v1` and `/api/v1/<rest>` but not `/api/v1/`,
        // which goes to the admin router as is, for its JSON `404`.
        .route_service("/api/v1/", admin_router.clone().into_service())
        .nest("/api/v1", admin_router)
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
    /// Created on the first push (or fetch with withheld paths) rather than
    /// with the router, so routers that never need a hook (and `cargo test
    /// --lib`, where the server binary may not be built) do not need the hook
    /// binary. Replaced when
    /// its hook is no longer installed; see [`current_hook_dir`].
    hook_dir: Arc<tokio::sync::Mutex<Option<Arc<HookDir>>>>,
}

/// Returns the shared hook directory, creating it on first use and creating a
/// fresh one whenever the current one fails [`HookDir::verify_installed`]
/// (for example after a temporary-file cleaner deleted it), so the server
/// heals itself instead of refusing every push until restarted.
///
/// A replaced directory is deleted once the last push still using it ends.
async fn current_hook_dir(
    hook_dir: &tokio::sync::Mutex<Option<Arc<HookDir>>>,
) -> std::io::Result<Arc<HookDir>> {
    let mut current = hook_dir.lock().await;
    if let Some(dir) = current.as_ref()
        && dir.verify_installed().is_ok()
    {
        return Ok(Arc::clone(dir));
    }
    match HookDir::create() {
        Ok(created) => {
            let created = Arc::new(created);
            *current = Some(Arc::clone(&created));
            Ok(created)
        }
        Err(error) => Err(error),
    }
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
    let mut response = route_request(&state, request).await;
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

async fn route_request(state: &AppState, request: Request) -> Response {
    let repo_root = state.repo_root.as_path();
    let policy_store = state.policy_store.as_ref();
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
        let pack_withhold = if service == GitService::UploadPack
            && policy
                .withhold_policy
                .has_withheld_rules(&policy.member_groups)
        {
            let hook_dir = match current_hook_dir(&state.hook_dir).await {
                Ok(hook_dir) => hook_dir,
                Err(error) => {
                    tracing::error!(%error, "cannot set up the pack-objects hook");
                    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                }
            };
            let context = PackWithholdContext {
                repo_dir: resolved_repo.dir.clone(),
                policy: policy.clone(),
            };
            match start_pack_withhold_session(hook_dir, context).await {
                Ok(session) => Some(session),
                Err(error) => {
                    tracing::error!(%error, "cannot start the pack-objects callback");
                    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                }
            }
        } else {
            None
        };
        let pre_receive = if service == GitService::ReceivePack {
            let hook_dir = match current_hook_dir(&state.hook_dir).await {
                Ok(hook_dir) => hook_dir,
                Err(error) => {
                    tracing::error!(%error, "cannot set up the pre-receive hook");
                    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                }
            };
            let context = PreReceiveContext {
                repo_dir: resolved_repo.dir.clone(),
                canonical_key: resolved_repo.canonical_key.clone(),
                member: member.clone(),
                policy,
                policy_store: Arc::clone(&state.policy_store),
            };
            match start_pre_receive_session(hook_dir, context).await {
                Ok(session) => Some(session),
                Err(error) => {
                    tracing::error!(%error, "cannot start the pre-receive callback");
                    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                }
            }
        } else {
            None
        };
        serve_rpc(
            service,
            &resolved_repo.dir,
            git_protocol,
            &visibility,
            body,
            pre_receive,
            pack_withhold,
        )
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
/// A member who satisfies every branch and withholding rule sees everything,
/// at no extra cost. A member with withheld paths but no hidden refs gets
/// `enforce_visibility` alone: git then speaks protocol v0, whose wants are
/// limited to advertised tips, and `deepen-not` is refused. Otherwise the
/// repository's refs are listed and `HEAD` is re-read (as close
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
        let has_withheld_paths = policy
            .withhold_policy
            .has_withheld_rules(&policy.member_groups);
        return Ok(Visibility::Allowed(GitVisibilityConfig {
            hidden_refs: Vec::new(),
            enforce_visibility: has_withheld_paths,
        }));
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
