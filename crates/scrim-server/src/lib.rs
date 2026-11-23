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
//!
//! [`serve_ssh`] serves the same repositories over Git's SSH transport, with
//! members authenticated by their registered SSH keys and the same
//! visibility, withholding and `pre-receive` enforcement as smart HTTP.

// The `?` operator and the unwrap/expect family are deliberately forbidden in
// this codebase; clippy's suggestion to use `?` is allowed away accordingly.
#![allow(clippy::question_mark)]

mod admin_api;
mod auth;
mod backup;
mod git_service;
mod pack_withhold;
mod policy_cache;
mod policy_store;
mod pre_receive;
mod repo_path;
mod secret_scan;
mod ssh_server;

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
    routing::get,
};
use tower_http::{decompression::RequestDecompressionLayer, trace::TraceLayer};

pub use admin_api::MAX_ADMIN_BODY_BYTES;
pub use auth::{AuthConfigError, MAX_TOKEN_BYTES, TokenAuth};
pub use backup::{
    BACKUP_MANIFEST_VERSION, BackupArtifact, BackupConfig, BackupManifest, BackupRepoEntry,
    DEFAULT_R2_PREFIX, LatestBackupPointer, MAX_BACKUP_OBJECT_BYTES, R2Config, RestoreConfig,
    S3SigningRequest, run_backup, run_restore, sign_s3_request,
};
use git_service::{
    GitService, GitVisibilityConfig, RepoRefEntry, advertise_refs, list_repo_refs,
    sanitize_git_protocol, serve_rpc,
};
pub use pack_withhold::{
    PACK_OBJECTS_HOOK_MODE, PACK_OBJECTS_HOOK_MODE_ENV, run_pack_objects_hook_process,
};
use pack_withhold::{PackWithholdContext, PackWithholdSession, start_pack_withhold_session};
pub use policy_cache::{
    CachedPolicyStore, DEFAULT_POLICY_CACHE_TTL_SECONDS, MemoryPolicyCache, POLICY_CACHE_EPOCH_KEY,
    PolicyCacheBackend, RedisPolicyCache, policy_cache_key,
};
pub use policy_store::{
    API_TOKEN_PREFIX, AuditLogEntry, AuditLogPage, AuditLogQuery, AuditLogRecord,
    AuthenticatedMember, BranchRuleRecord, CreateMemberRequest, CreatedMember,
    DEFAULT_AUDIT_LOG_LIMIT, GroupMembershipChange, GroupRecipientsRecord, GroupRecord,
    GroupWithMembers, IssuedToken, MAX_AUDIT_LOG_LIMIT, MAX_NAME_BYTES, MAX_REPOSITORY_PATH_BYTES,
    MAX_SCOPE_NAME_BYTES, MAX_SSH_PUBLIC_KEY_BYTES, MAX_TOKEN_LABEL_BYTES, MemberPublicKeyRecord,
    MemberRecord, MemberRepoPolicy, MemberSshKeyRecord, MemoryPolicyStore, PathRuleRecord,
    PgPolicyStore, PolicyStore, PolicyStoreError, PolicyStoreFuture, RegisterRepositoryResult,
    RepositoryRecord, RevokeMemberResult, ScopeRecipient, ScopeRecipientsRecord, SecretScopeRecord,
    StaticPolicyStore,
};
pub use pre_receive::{
    ALLOW_MERGE_LEAK_PUSH_OPTION, ALLOW_SECRET_SCAN_PUSH_OPTION, PRE_RECEIVE_HOOK_MODE,
    PRE_RECEIVE_HOOK_MODE_ENV, run_pre_receive_hook_process,
};
use pre_receive::{HookDir, PreReceiveContext, PreReceiveSession, start_pre_receive_session};
use repo_path::{RepoHead, ResolvedRepo, read_valid_head, resolve_bare_repo};
pub use secrecy::SecretString;
pub use ssh_server::{SshServerConfig, load_or_create_ssh_host_key, serve_ssh};

/// Entry points for the `cargo-fuzz` targets in `fuzz/`. Not a stable API.
#[doc(hidden)]
pub mod fuzz_support {
    use crate::git_service::UploadPackRequestFilter;

    /// Most pack-objects arguments fed to the argument parser per input; git
    /// never passes more than a handful.
    const MAX_FUZZ_PACK_ARGS: usize = 64;

    /// Runs `data` through every untrusted-input parser of the server: the
    /// `upload-pack` request filter (in chunks sized by the first byte), the
    /// SSH `exec` command parser, the `pack-objects` hook argument and stdin
    /// parsers, the `pre-receive` ref update and `diff-tree` parsers, and the
    /// secret scanner. Results are discarded; only panics matter.
    pub fn fuzz_parsers(data: &[u8]) {
        let (chunk_size, request) = match data.split_first() {
            Some((first, rest)) => (usize::from(*first) + 1, rest),
            None => (1, data),
        };
        let mut request_filter = UploadPackRequestFilter::default();
        let mut is_rejected = false;
        for chunk in request.chunks(chunk_size) {
            if request_filter.filter_chunk(chunk).is_err() {
                is_rejected = true;
                break;
            }
        }
        if !is_rejected {
            let _ = request_filter.finish();
        }

        let _ = crate::ssh_server::parse_git_ssh_command(data);

        let pack_args: Vec<String> = String::from_utf8_lossy(data)
            .split(['\n', ' ', '\0'])
            .take(MAX_FUZZ_PACK_ARGS)
            .map(str::to_owned)
            .collect();
        let _ = crate::pack_withhold::parse_pack_args(&pack_args);
        let _ = crate::pack_withhold::parse_pack_stdin(data);

        let _ = crate::pre_receive::parse_ref_updates(data);
        let _ = crate::pre_receive::parse_raw_diff_entries(data);

        let _ = crate::secret_scan::scan_blob_bytes(data);
    }

    #[cfg(test)]
    mod tests {
        use super::fuzz_parsers;

        #[test]
        fn fuzz_parsers_survives_edge_case_inputs() {
            let zero_oid = "0".repeat(40);
            let one_oid = "1".repeat(40);
            let inputs: Vec<Vec<u8>> = vec![
                Vec::new(),
                vec![0],
                vec![0xff; 4096],
                b"\x000004000".to_vec(),
                b"\x030009deepen-not x\n0000".to_vec(),
                b"\x07fff0".to_vec(),
                b"git-upload-pack '/repo.git'".to_vec(),
                b"git-receive-pack 'a'\\''b'".to_vec(),
                b"git --shallow-file pack-objects --revs --filter=blob:limit=9999999999999g"
                    .to_vec(),
                format!("{one_oid}\n--not\n^{one_oid}\n--shallow {one_oid}\n").into_bytes(),
                format!("{zero_oid} {one_oid} refs/heads/main\n").into_bytes(),
                format!(":100644 100644 {zero_oid} {one_oid} M\0path\0").into_bytes(),
                b"::100644\0\0\0".to_vec(),
                b"AKIAABCDEFGHIJKLMNOP ghp_0123456789abcdefghijklmnopqrstuvwxyzAB\n-----BEGIN"
                    .to_vec(),
                "é\u{2028}\u{feff}".repeat(100).into_bytes(),
            ];
            for input in inputs {
                fuzz_parsers(&input);
            }
        }
    }
}

/// Entry points for the criterion benchmarks in `benches/`. Not a stable API.
#[doc(hidden)]
pub mod bench_support {
    use std::collections::BTreeSet;
    use std::path::Path;

    use scrim_policy::WithholdPolicy;

    /// Runs the `pack-objects` hook's object selection exactly as production
    /// does and returns the number of objects selected.
    ///
    /// # Errors
    ///
    /// Returns the same errors as the production selection (malformed
    /// arguments or object list, unreadable or unexpected objects).
    pub fn compute_allowed_pack_objects_for_bench(
        repo_dir: &Path,
        pack_args: &[String],
        stdin: &[u8],
        withhold_policy: &WithholdPolicy,
        member_groups: &BTreeSet<String>,
        visible_tag_refs: &[String],
    ) -> std::io::Result<usize> {
        match crate::pack_withhold::compute_allowed_pack_objects(
            repo_dir,
            pack_args,
            stdin,
            withhold_policy,
            member_groups,
            visible_tag_refs,
        ) {
            Ok(selection) => Ok(selection.objects.len()),
            Err(error) => Err(error),
        }
    }
}

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
    router_with_hook_dir(repo_root, policy_store, SharedHookDir::default())
}

/// Like [`router_with_policy_store`], but sets up git's server-owned hooks in
/// `hook_dir`, which an [`SshServerConfig`] may share so both transports use
/// one hook directory.
pub fn router_with_hook_dir(
    repo_root: PathBuf,
    policy_store: Arc<dyn PolicyStore>,
    hook_dir: SharedHookDir,
) -> Router {
    let admin_router = admin_api::router(repo_root.clone(), Arc::clone(&policy_store));
    let state = AppState {
        repo_root,
        policy_store: Arc::clone(&policy_store),
        hook_dir,
    };
    let authenticated_router = Router::new()
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
        ));

    Router::new()
        .route("/healthz", get(healthz))
        .merge(authenticated_router)
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

async fn healthz() -> Response {
    (
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            ),
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
        ],
        r#"{"status":"ok"}"#,
    )
        .into_response()
}

/// State shared by every request handler.
#[derive(Clone)]
struct AppState {
    repo_root: PathBuf,
    policy_store: Arc<dyn PolicyStore>,
    hook_dir: SharedHookDir,
}

/// The directory holding git's server-owned `pre-receive` and `pack-objects`
/// hooks, shareable between the HTTP router ([`router_with_hook_dir`]) and
/// the SSH server ([`SshServerConfig`]). Clones share one directory.
///
/// It is created on the first push (or fetch with withheld paths) rather than
/// up front, so servers that never need a hook (and `cargo test --lib`, where
/// the server binary may not be built) do not need the hook binary, and it is
/// replaced when its hook is no longer installed; see [`current_hook_dir`].
#[derive(Clone, Default)]
pub struct SharedHookDir(Arc<tokio::sync::Mutex<Option<Arc<HookDir>>>>);

/// Returns the shared hook directory, creating it on first use and creating a
/// fresh one whenever the current one fails [`HookDir::verify_installed`]
/// (for example after a temporary-file cleaner deleted it), so the server
/// heals itself instead of refusing every push until restarted.
///
/// A replaced directory is deleted once the last push still using it ends.
async fn current_hook_dir(hook_dir: &SharedHookDir) -> std::io::Result<Arc<HookDir>> {
    let mut current = hook_dir.0.lock().await;
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
        let (pre_receive, pack_withhold) = match start_hook_sessions(
            service,
            &state.hook_dir,
            &resolved_repo,
            member,
            policy,
            &state.policy_store,
        )
        .await
        {
            Ok(sessions) => sessions,
            Err(error) => {
                tracing::error!(%error, "cannot start the git hook session");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
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

/// Starts the server-owned hook sessions one git process for `service` runs
/// with: the `pre-receive` guard for every `receive-pack`, and the
/// `pack-objects` hook for an `upload-pack` by a member with withheld paths.
///
/// Fails if the hook directory cannot be set up (for example when the server
/// binary cannot be found) or a callback listener cannot be started.
async fn start_hook_sessions(
    service: GitService,
    hook_dir: &SharedHookDir,
    resolved_repo: &ResolvedRepo,
    member: &AuthenticatedMember,
    policy: MemberRepoPolicy,
    policy_store: &Arc<dyn PolicyStore>,
) -> std::io::Result<(Option<PreReceiveSession>, Option<PackWithholdSession>)> {
    match service {
        GitService::UploadPack => {
            if !policy
                .withhold_policy
                .has_withheld_rules(&policy.member_groups)
            {
                return Ok((None, None));
            }
            let hook_dir = match current_hook_dir(hook_dir).await {
                Ok(hook_dir) => hook_dir,
                Err(error) => return Err(error),
            };
            let context = PackWithholdContext {
                repo_dir: resolved_repo.dir.clone(),
                policy,
            };
            match start_pack_withhold_session(hook_dir, context).await {
                Ok(session) => Ok((None, Some(session))),
                Err(error) => Err(error),
            }
        }
        GitService::ReceivePack => {
            let hook_dir = match current_hook_dir(hook_dir).await {
                Ok(hook_dir) => hook_dir,
                Err(error) => return Err(error),
            };
            let context = PreReceiveContext {
                repo_dir: resolved_repo.dir.clone(),
                canonical_key: resolved_repo.canonical_key.clone(),
                member: member.clone(),
                policy,
                policy_store: Arc::clone(policy_store),
            };
            match start_pre_receive_session(hook_dir, context).await {
                Ok(session) => Ok((Some(session), None)),
                Err(error) => Err(error),
            }
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
/// at no extra cost. Otherwise the repository's refs are listed and `HEAD` is
/// re-read (as close to starting git as possible), git is made to speak
/// protocol v0 (whose wants are limited to advertised tips, and which refuses
/// `deepen-not`), and:
/// - a symbolic `HEAD` whose chain reaches a hidden ref is refused outright:
///   `transfer.hideRefs` cannot hide it, and git would still advertise its
///   object ID and `symref=HEAD:<target>`;
/// - a symbolic ref whose chain reaches a hidden ref is hidden by name, since
///   git would advertise it with the hidden ref's object ID;
/// - a detached `HEAD` is hidden, as it may point at a commit only reachable
///   from hidden refs, or (for a member with withheld paths) at a non-commit.
///
/// For a member with withheld paths, every ref that does not peel to a commit
/// (see [`leads_to_non_commit`]) is hidden too: the `pack-objects` hook
/// refuses such wants, since a bare blob or tree has no path to check, so
/// advertising one (such as a tag naming a blob) would make every clone fail.
async fn compute_visibility(
    policy: &MemberRepoPolicy,
    repo_dir: &Path,
) -> std::io::Result<Visibility> {
    let plan = policy.branch_policy.hidden_ref_plan(&policy.member_groups);
    let has_hidden_branches = plan.has_unsatisfied_rules();
    let has_withheld_paths = policy
        .withhold_policy
        .has_withheld_rules(&policy.member_groups);
    if !has_hidden_branches && !has_withheld_paths {
        return Ok(Visibility::Allowed(GitVisibilityConfig {
            hidden_refs: Vec::new(),
            enforce_visibility: false,
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
    let refs_by_name: BTreeMap<&str, &RepoRefEntry> = repo_refs
        .iter()
        .map(|entry| (entry.name.as_str(), entry))
        .collect();

    if let RepoHead::Symbolic(head_target) = &head {
        let is_branch_hidden = !policy.branch_policy.is_ref_chain_visible(
            head_target,
            &symrefs,
            &policy.member_groups,
        );
        if is_branch_hidden
            || (has_withheld_paths && leads_to_non_commit(head_target, &refs_by_name))
        {
            return Ok(Visibility::HeadHidden);
        }
    }

    let mut hidden_refs = if has_hidden_branches {
        plan.resolve_hide_refs_with_symrefs(
            &policy.branch_policy,
            &policy.member_groups,
            repo_refs.iter().map(|entry| entry.name.as_str()),
            &symrefs,
        )
    } else {
        Vec::new()
    };
    if has_withheld_paths {
        // Appended after the branch values, `!` negations included: git lets
        // later values win, so no negation can re-expose these. Refs the
        // branch rules hide are already hidden and never negated, so they are
        // skipped. A value also hides the refs below it, but git cannot store
        // both `refs/tags/x` and `refs/tags/x/y`, so that only matters for a
        // ref created after this listing, which is then hidden too (fails
        // closed).
        hidden_refs.extend(
            repo_refs
                .iter()
                .filter(|entry| {
                    leads_to_non_commit(&entry.name, &refs_by_name)
                        && policy.branch_policy.is_ref_chain_visible(
                            &entry.name,
                            &symrefs,
                            &policy.member_groups,
                        )
                })
                .map(|entry| entry.name.clone()),
        );
    }
    if head == RepoHead::Detached {
        hidden_refs.push("HEAD".to_owned());
    }
    Ok(Visibility::Allowed(GitVisibilityConfig {
        hidden_refs,
        enforce_visibility: true,
    }))
}

/// Most symbolic-ref hops [`leads_to_non_commit`] follows before failing
/// closed. Git itself gives up after 5.
const MAX_SYMREF_HOPS: usize = 16;

/// Whether `ref_name`, or any ref its symbolic chain in `refs_by_name` leads
/// to, names something that does not peel to a commit (see
/// [`RepoRefEntry::peels_to_commit`]).
///
/// An unlisted `ref_name` is an unborn branch (for example `HEAD` of an empty
/// repository), which git does not advertise, so it counts as `false`. A
/// listed symbolic ref whose target is unlisted (dangling, or deleted
/// concurrently), a cycle, or a chain longer than [`MAX_SYMREF_HOPS`] counts
/// as `true`, failing closed.
fn leads_to_non_commit(ref_name: &str, refs_by_name: &BTreeMap<&str, &RepoRefEntry>) -> bool {
    let mut current = ref_name;
    for _ in 0..=MAX_SYMREF_HOPS {
        let Some(entry) = refs_by_name.get(current) else {
            return current != ref_name;
        };
        if !entry.peels_to_commit() {
            return true;
        }
        match &entry.symref_target {
            Some(target) => current = target,
            None => return false,
        }
    }
    true
}

fn git_response(service: GitService, kind: &str, body: Body) -> Response {
    let content_type = format!("application/x-{}-{kind}", service.service_name());
    ([(header::CONTENT_TYPE, content_type)], body).into_response()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::leads_to_non_commit;
    use crate::git_service::{GitObjectType, RepoRefEntry};

    fn entry(
        name: &str,
        symref_target: Option<&str>,
        object_type: GitObjectType,
        peeled_object_type: Option<GitObjectType>,
    ) -> RepoRefEntry {
        RepoRefEntry {
            name: name.to_owned(),
            symref_target: symref_target.map(str::to_owned),
            object_type,
            peeled_object_type,
        }
    }

    #[test]
    fn non_commit_detection_follows_symref_chains_and_fails_closed() {
        let commit = GitObjectType::Commit;
        let blob = GitObjectType::Blob;
        let tag = GitObjectType::Tag;
        let refs = [
            entry("refs/heads/main", None, commit, None),
            entry("refs/tags/blob", None, blob, None),
            entry("refs/tags/ann-commit", None, tag, Some(commit)),
            entry("refs/tags/ann-blob", None, tag, Some(blob)),
            entry("refs/tags/one-level", None, tag, Some(tag)),
            entry("refs/heads/alias", Some("refs/heads/main"), commit, None),
            // Reported as a commit but pointing at a blob ref: the chain wins.
            entry(
                "refs/heads/stale-alias",
                Some("refs/tags/blob"),
                commit,
                None,
            ),
            entry("refs/heads/dangling", Some("refs/heads/gone"), commit, None),
            entry("refs/heads/loop-a", Some("refs/heads/loop-b"), commit, None),
            entry("refs/heads/loop-b", Some("refs/heads/loop-a"), commit, None),
        ];
        let refs_by_name: BTreeMap<&str, &RepoRefEntry> = refs
            .iter()
            .map(|entry| (entry.name.as_str(), entry))
            .collect();
        for (ref_name, expected) in [
            ("refs/heads/main", false),
            ("refs/tags/ann-commit", false),
            ("refs/heads/alias", false),
            ("refs/heads/unborn", false),
            ("refs/tags/blob", true),
            ("refs/tags/ann-blob", true),
            ("refs/tags/one-level", true),
            ("refs/heads/stale-alias", true),
            ("refs/heads/dangling", true),
            ("refs/heads/loop-a", true),
        ] {
            assert_eq!(
                leads_to_non_commit(ref_name, &refs_by_name),
                expected,
                "{ref_name}"
            );
        }
    }
}
