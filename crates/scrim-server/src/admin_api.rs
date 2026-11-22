//! The admin HTTP API served under `/api/v1`, which the `scrim` CLI talks to.
//!
//! Requests arrive already authenticated by [`crate::auth::require_auth`].
//! `GET /api/v1/whoami`, `PUT /api/v1/me/public-key`, `/api/v1/me/ssh-keys`
//! (list, add, revoke the member's own SSH keys), and
//! `GET /api/v1/path-rules/me` are open to every active member,
//! `GET /api/v1/groups/{group}/recipients` is open to members belonging to that
//! group (as well as admins), and `GET /api/v1/secret-scopes/recipients` is
//! open to members belonging to the scope's groups (as well as admins); every
//! other route requires an admin and answers `403` otherwise. Bodies are JSON
//! (at most [`MAX_ADMIN_BODY_BYTES`] after decompression), every response
//! carries `Cache-Control: no-store`, and every error is
//! `{"error": "<message>"}`. Internal failures are logged and answered with a
//! generic `500` message so no SQL or filesystem detail reaches the client.

use std::{collections::BTreeSet, path::PathBuf, sync::Arc};

use axum::{
    Json, Router,
    extract::{
        DefaultBodyLimit, FromRequest, FromRequestParts, Path, Query, Request, State,
        rejection::{JsonRejection, PathRejection, QueryRejection},
    },
    http::{HeaderValue, StatusCode, header, request::Parts},
    middleware,
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize, Serializer, de::DeserializeOwned};

use crate::{
    policy_store::{
        AuditLogQuery, AuditLogRecord, AuthenticatedMember, BranchRuleRecord, CreateMemberRequest,
        DEFAULT_AUDIT_LOG_LIMIT, MemberRecord, MemberSshKeyRecord, PathRuleRecord, PolicyStore,
        PolicyStoreError, ScopeRecipient, SecretScopeRecord, validate_repository_path,
    },
    repo_path::{
        BareRepoError, BareRepoLocation, create_bare_repo, locate_bare_repo, resolve_bare_repo,
    },
};

/// Largest accepted admin request body, in bytes.
pub const MAX_ADMIN_BODY_BYTES: usize = 64 * 1024;

/// State shared by the admin handlers.
#[derive(Clone)]
struct AdminState {
    repo_root: PathBuf,
    policy_store: Arc<dyn PolicyStore>,
}

/// Builds the admin API router, to be nested at `/api/v1` inside the
/// authentication layer.
pub(crate) fn router(repo_root: PathBuf, policy_store: Arc<dyn PolicyStore>) -> Router {
    Router::new()
        .route("/whoami", get(whoami))
        .route("/me/public-key", put(set_own_public_key))
        .route("/me/ssh-keys", get(list_own_ssh_keys).post(add_own_ssh_key))
        .route("/me/ssh-keys/{id}", delete(revoke_own_ssh_key))
        .route(
            "/repositories",
            get(list_repositories).post(register_repository),
        )
        .route("/groups", get(list_groups).post(create_group))
        .route("/groups/{group}/recipients", get(get_group_recipients))
        .route("/groups/{group}/members", post(add_group_member))
        .route(
            "/groups/{group}/members/{member}",
            delete(remove_group_member),
        )
        .route("/members", get(list_members).post(create_member))
        .route("/members/{name}", delete(revoke_member))
        .route("/members/{name}/tokens", post(issue_member_token))
        .route("/members/{name}/public-key", put(set_member_public_key))
        .route(
            "/members/{name}/ssh-keys",
            get(list_member_ssh_keys).post(add_member_ssh_key),
        )
        .route(
            "/members/{name}/ssh-keys/{id}",
            delete(revoke_member_ssh_key),
        )
        .route(
            "/branch-rules",
            get(list_branch_rules)
                .put(set_branch_rule)
                .delete(remove_branch_rule),
        )
        .route(
            "/path-rules",
            get(list_path_rules)
                .put(set_path_rule)
                .delete(remove_path_rule),
        )
        .route("/path-rules/me", get(get_my_withheld_paths))
        .route(
            "/secret-scopes",
            get(list_secret_scopes)
                .put(set_secret_scope)
                .delete(remove_secret_scope),
        )
        .route(
            "/secret-scopes/recipients",
            get(get_secret_scope_recipients),
        )
        .route("/audit-log", get(list_audit_log))
        .fallback(not_found)
        .method_not_allowed_fallback(method_not_allowed)
        .with_state(AdminState {
            repo_root,
            policy_store,
        })
        .layer(DefaultBodyLimit::max(MAX_ADMIN_BODY_BYTES))
        .layer(middleware::map_response(add_no_store_headers))
}

/// Admin responses carry member data and one-time tokens: never cache them.
async fn add_no_store_headers(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

/// An error answered as `{"error": message}` with `status`.
#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    fn internal() -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal server error")
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(serde_json::json!({ "error": self.message })),
        )
            .into_response()
    }
}

/// Maps a store error to its HTTP answer. Messages of the administrative
/// variants are written for the administrator; anything else is logged and
/// hidden behind a generic `500`.
fn store_error(error: PolicyStoreError) -> ApiError {
    match error {
        PolicyStoreError::NotFound(message) => ApiError::new(StatusCode::NOT_FOUND, message),
        PolicyStoreError::Conflict(message) => ApiError::new(StatusCode::CONFLICT, message),
        PolicyStoreError::InvalidInput(message) => ApiError::new(StatusCode::BAD_REQUEST, message),
        PolicyStoreError::Unsupported(message) => {
            ApiError::new(StatusCode::NOT_IMPLEMENTED, message)
        }
        error @ (PolicyStoreError::Database(_)
        | PolicyStoreError::InvalidBranchRule { .. }
        | PolicyStoreError::InvalidPathRule { .. }
        | PolicyStoreError::Internal(_)) => {
            tracing::error!(%error, "admin API policy store failure");
            ApiError::internal()
        }
    }
}

async fn not_found() -> ApiError {
    ApiError::new(StatusCode::NOT_FOUND, "not found")
}

async fn method_not_allowed() -> ApiError {
    ApiError::new(StatusCode::METHOD_NOT_ALLOWED, "method not allowed")
}

/// The authenticated member, as inserted by `require_auth`.
struct CurrentMember(AuthenticatedMember);

impl<S: Send + Sync> FromRequestParts<S> for CurrentMember {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        match parts.extensions.get::<AuthenticatedMember>() {
            Some(member) => Ok(Self(member.clone())),
            None => {
                // `require_auth` always inserts the member; this is a wiring bug.
                tracing::error!("admin request reached a handler without an authenticated member");
                Err(ApiError::internal())
            }
        }
    }
}

/// The authenticated member, who must be an admin (`403` otherwise). Checked
/// before the body is read, so non-admins learn nothing from validation.
struct AdminMember(AuthenticatedMember);

impl<S: Send + Sync> FromRequestParts<S> for AdminMember {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match CurrentMember::from_request_parts(parts, state).await {
            Ok(CurrentMember(member)) if member.is_admin => Ok(Self(member)),
            Ok(CurrentMember(_)) => Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "admin privileges required",
            )),
            Err(error) => Err(error),
        }
    }
}

/// [`Json`] whose rejections are answered as JSON errors.
struct ApiJson<T>(T);

impl<S: Send + Sync, T: DeserializeOwned> FromRequest<S> for ApiJson<T> {
    type Rejection = ApiError;

    async fn from_request(request: Request, state: &S) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(request, state).await {
            Ok(Json(value)) => Ok(Self(value)),
            Err(rejection) => Err(json_rejection_error(rejection)),
        }
    }
}

fn json_rejection_error(rejection: JsonRejection) -> ApiError {
    // axum answers well-formed JSON of the wrong shape with `422`; the API
    // reports every invalid body as `400` (keeping `413` and `415`).
    let status = match rejection.status() {
        StatusCode::UNPROCESSABLE_ENTITY => StatusCode::BAD_REQUEST,
        status => status,
    };
    ApiError::new(status, rejection.body_text())
}

/// [`Query`] whose rejections are answered as JSON errors.
struct ApiQuery<T>(T);

impl<S: Send + Sync, T: DeserializeOwned> FromRequestParts<S> for ApiQuery<T> {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match Query::<T>::from_request_parts(parts, state).await {
            Ok(Query(value)) => Ok(Self(value)),
            Err(rejection) => Err(query_rejection_error(rejection)),
        }
    }
}

fn query_rejection_error(rejection: QueryRejection) -> ApiError {
    ApiError::new(rejection.status(), rejection.body_text())
}

/// [`Path`] whose rejections are answered as JSON errors.
struct ApiPath<T>(T);

impl<S: Send + Sync, T: DeserializeOwned + Send> FromRequestParts<S> for ApiPath<T> {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match Path::<T>::from_request_parts(parts, state).await {
            Ok(Path(value)) => Ok(Self(value)),
            Err(rejection) => Err(path_rejection_error(rejection)),
        }
    }
}

fn path_rejection_error(rejection: PathRejection) -> ApiError {
    ApiError::new(rejection.status(), rejection.body_text())
}

/// Writes a token into a response body without an intermediate `String`.
fn serialize_secret<S: Serializer>(
    secret: &SecretString,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(secret.expose_secret())
}

type ApiResult<T> = Result<(StatusCode, Json<T>), ApiError>;

fn ok<T>(value: T) -> ApiResult<T> {
    Ok((StatusCode::OK, Json(value)))
}

fn created<T>(value: T) -> ApiResult<T> {
    Ok((StatusCode::CREATED, Json(value)))
}

#[derive(Serialize)]
struct WhoamiResponse {
    id: i64,
    name: String,
    is_admin: bool,
    groups: Vec<String>,
    public_key: Option<String>,
}

async fn whoami(
    State(state): State<AdminState>,
    CurrentMember(member): CurrentMember,
) -> ApiResult<WhoamiResponse> {
    let groups = match state.policy_store.list_member_groups(member.id).await {
        Ok(groups) => groups,
        Err(error) => return Err(store_error(error)),
    };
    let public_key = match state.policy_store.get_member_public_key(member.id).await {
        Ok(public_key) => public_key,
        Err(error) => return Err(store_error(error)),
    };
    ok(WhoamiResponse {
        id: member.id,
        name: member.name,
        is_admin: member.is_admin,
        groups: groups.into_iter().collect(),
        public_key,
    })
}

fn default_true() -> bool {
    true
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterRepositoryBody {
    path: String,
    #[serde(default = "default_true")]
    create_bare: bool,
}

#[derive(Serialize)]
struct RegisterRepositoryResponse {
    id: i64,
    path: String,
    created: bool,
    bare_initialized: bool,
}

fn bare_repo_error(error: BareRepoError) -> ApiError {
    match error {
        BareRepoError::InvalidPath => {
            ApiError::new(StatusCode::BAD_REQUEST, "invalid repository path")
        }
        BareRepoError::NotFound => ApiError::new(
            StatusCode::NOT_FOUND,
            "no bare repository exists at this path (set create_bare to create one)",
        ),
        BareRepoError::Conflict(message) => ApiError::new(StatusCode::CONFLICT, message),
        BareRepoError::Io(error) => {
            tracing::error!(%error, "cannot set up a bare repository");
            ApiError::internal()
        }
    }
}

/// Registers a repository, first creating it as an empty bare repository if
/// it does not exist and `create_bare` is set.
///
/// A new repository is registered before it is created, so a store that
/// cannot register (or a database failure) leaves the filesystem untouched.
async fn register_repository(
    State(state): State<AdminState>,
    AdminMember(member): AdminMember,
    ApiJson(body): ApiJson<RegisterRepositoryBody>,
) -> ApiResult<RegisterRepositoryResponse> {
    if let Err(error) = validate_repository_path(&body.path) {
        return Err(store_error(error));
    }
    let location = match locate_bare_repo(&state.repo_root, &body.path, body.create_bare).await {
        Ok(location) => location,
        Err(error) => return Err(bare_repo_error(error)),
    };
    // Both existing and creatable repositories use their canonical key: an
    // intra-root symlink alias registers the target it points to, and on
    // case-insensitive filesystems existing parent directories keep their
    // on-disk spelling so Git policy lookups always match.
    let (repo_key, should_create) = match location {
        BareRepoLocation::Existing(canonical_key) => (canonical_key, false),
        BareRepoLocation::Creatable(canonical_key) => (canonical_key, true),
    };
    let registered = match state
        .policy_store
        .register_repository(Some(member.id), &repo_key)
        .await
    {
        Ok(registered) => registered,
        Err(error) => return Err(store_error(error)),
    };
    let bare_initialized = if should_create {
        if let Err(error) = create_bare_repo(&state.repo_root, &repo_key).await {
            return Err(bare_repo_error(error));
        }
        true
    } else {
        false
    };
    let response = RegisterRepositoryResponse {
        id: registered.repository.id,
        path: registered.repository.path,
        created: registered.created,
        bare_initialized,
    };
    if registered.created {
        created(response)
    } else {
        ok(response)
    }
}

#[derive(Serialize)]
struct RepositoryResponse {
    id: i64,
    path: String,
}

#[derive(Serialize)]
struct RepositoriesResponse {
    repositories: Vec<RepositoryResponse>,
}

async fn list_repositories(
    State(state): State<AdminState>,
    AdminMember(_member): AdminMember,
) -> ApiResult<RepositoriesResponse> {
    match state.policy_store.list_repositories().await {
        Ok(repositories) => ok(RepositoriesResponse {
            repositories: repositories
                .into_iter()
                .map(|repository| RepositoryResponse {
                    id: repository.id,
                    path: repository.path,
                })
                .collect(),
        }),
        Err(error) => Err(store_error(error)),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateGroupBody {
    name: String,
}

#[derive(Serialize)]
struct GroupResponse {
    id: i64,
    name: String,
}

async fn create_group(
    State(state): State<AdminState>,
    AdminMember(member): AdminMember,
    ApiJson(body): ApiJson<CreateGroupBody>,
) -> ApiResult<GroupResponse> {
    match state
        .policy_store
        .create_group(Some(member.id), &body.name)
        .await
    {
        Ok(group) => created(GroupResponse {
            id: group.id,
            name: group.name,
        }),
        Err(error) => Err(store_error(error)),
    }
}

#[derive(Serialize)]
struct GroupWithMembersResponse {
    id: i64,
    name: String,
    members: Vec<String>,
}

#[derive(Serialize)]
struct GroupsResponse {
    groups: Vec<GroupWithMembersResponse>,
}

async fn list_groups(
    State(state): State<AdminState>,
    AdminMember(_member): AdminMember,
) -> ApiResult<GroupsResponse> {
    match state.policy_store.list_groups().await {
        Ok(groups) => ok(GroupsResponse {
            groups: groups
                .into_iter()
                .map(|group| GroupWithMembersResponse {
                    id: group.id,
                    name: group.name,
                    members: group.members,
                })
                .collect(),
        }),
        Err(error) => Err(store_error(error)),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AddGroupMemberBody {
    member: String,
}

#[derive(Serialize)]
struct GroupMemberAddedResponse {
    group: String,
    member: String,
    added: bool,
}

async fn add_group_member(
    State(state): State<AdminState>,
    AdminMember(actor): AdminMember,
    ApiPath(group): ApiPath<String>,
    ApiJson(body): ApiJson<AddGroupMemberBody>,
) -> ApiResult<GroupMemberAddedResponse> {
    match state
        .policy_store
        .add_group_member(Some(actor.id), &group, &body.member)
        .await
    {
        Ok(change) => ok(GroupMemberAddedResponse {
            group: change.group,
            member: change.member,
            added: change.changed,
        }),
        Err(error) => Err(store_error(error)),
    }
}

#[derive(Serialize)]
struct GroupMemberRemovedResponse {
    group: String,
    member: String,
    removed: bool,
}

async fn remove_group_member(
    State(state): State<AdminState>,
    AdminMember(actor): AdminMember,
    ApiPath((group, member)): ApiPath<(String, String)>,
) -> ApiResult<GroupMemberRemovedResponse> {
    match state
        .policy_store
        .remove_group_member(Some(actor.id), &group, &member)
        .await
    {
        Ok(change) => ok(GroupMemberRemovedResponse {
            group: change.group,
            member: change.member,
            removed: change.changed,
        }),
        Err(error) => Err(store_error(error)),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateMemberBody {
    name: String,
    #[serde(default)]
    is_admin: bool,
    #[serde(default)]
    is_machine: bool,
    #[serde(default)]
    public_key: Option<String>,
    #[serde(default)]
    groups: Vec<String>,
    #[serde(default)]
    token_label: String,
}

#[derive(Serialize)]
struct MemberResponse {
    id: i64,
    name: String,
    is_admin: bool,
    is_machine: bool,
    public_key: Option<String>,
    groups: Vec<String>,
    revoked: bool,
}

impl From<MemberRecord> for MemberResponse {
    fn from(member: MemberRecord) -> Self {
        Self {
            id: member.id,
            name: member.name,
            is_admin: member.is_admin,
            is_machine: member.is_machine,
            public_key: member.public_key,
            groups: member.groups,
            revoked: member.revoked,
        }
    }
}

#[derive(Serialize)]
struct CreatedMemberResponse {
    member: MemberResponse,
    #[serde(serialize_with = "serialize_secret")]
    token: SecretString,
}

async fn create_member(
    State(state): State<AdminState>,
    AdminMember(actor): AdminMember,
    ApiJson(body): ApiJson<CreateMemberBody>,
) -> ApiResult<CreatedMemberResponse> {
    let request = CreateMemberRequest {
        name: body.name,
        is_admin: body.is_admin,
        is_machine: body.is_machine,
        public_key: body.public_key,
        groups: body.groups.into_iter().collect(),
        token_label: body.token_label,
    };
    match state
        .policy_store
        .create_member(Some(actor.id), request)
        .await
    {
        Ok(created_member) => created(CreatedMemberResponse {
            member: MemberResponse::from(created_member.member),
            token: created_member.token,
        }),
        Err(error) => Err(store_error(error)),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IssueTokenBody {
    #[serde(default)]
    label: String,
}

#[derive(Serialize)]
struct IssuedTokenResponse {
    member: String,
    label: String,
    #[serde(serialize_with = "serialize_secret")]
    token: SecretString,
}

async fn issue_member_token(
    State(state): State<AdminState>,
    AdminMember(actor): AdminMember,
    ApiPath(name): ApiPath<String>,
    ApiJson(body): ApiJson<IssueTokenBody>,
) -> ApiResult<IssuedTokenResponse> {
    match state
        .policy_store
        .issue_member_token(Some(actor.id), &name, &body.label)
        .await
    {
        Ok(issued) => created(IssuedTokenResponse {
            member: issued.member,
            label: issued.label,
            token: issued.token,
        }),
        Err(error) => Err(store_error(error)),
    }
}

#[derive(Serialize)]
struct RevokeMemberResponse {
    name: String,
    revoked: bool,
}

async fn revoke_member(
    State(state): State<AdminState>,
    AdminMember(actor): AdminMember,
    ApiPath(name): ApiPath<String>,
) -> ApiResult<RevokeMemberResponse> {
    match state
        .policy_store
        .revoke_member(Some(actor.id), &name)
        .await
    {
        Ok(result) => ok(RevokeMemberResponse {
            name: result.name,
            revoked: result.revoked,
        }),
        Err(error) => Err(store_error(error)),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ListMembersQuery {
    #[serde(default)]
    include_revoked: bool,
}

#[derive(Serialize)]
struct MembersResponse {
    members: Vec<MemberResponse>,
}

async fn list_members(
    State(state): State<AdminState>,
    AdminMember(_actor): AdminMember,
    ApiQuery(query): ApiQuery<ListMembersQuery>,
) -> ApiResult<MembersResponse> {
    match state.policy_store.list_members(query.include_revoked).await {
        Ok(members) => ok(MembersResponse {
            members: members.into_iter().map(MemberResponse::from).collect(),
        }),
        Err(error) => Err(store_error(error)),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SetBranchRuleBody {
    repository: String,
    pattern: String,
    groups: Vec<String>,
}

#[derive(Serialize)]
struct BranchRuleResponse {
    repository: String,
    pattern: String,
    groups: Vec<String>,
}

async fn set_branch_rule(
    State(state): State<AdminState>,
    AdminMember(actor): AdminMember,
    ApiJson(body): ApiJson<SetBranchRuleBody>,
) -> ApiResult<BranchRuleResponse> {
    let groups: BTreeSet<String> = body.groups.into_iter().collect();
    match state
        .policy_store
        .set_branch_rule(Some(actor.id), &body.repository, &body.pattern, groups)
        .await
    {
        Ok(rule) => ok(BranchRuleResponse {
            repository: rule.repository,
            pattern: rule.pattern,
            groups: rule.groups,
        }),
        Err(error) => Err(store_error(error)),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ListBranchRulesQuery {
    repo: String,
}

#[derive(Serialize)]
struct BranchRuleSummary {
    pattern: String,
    groups: Vec<String>,
}

#[derive(Serialize)]
struct BranchRulesResponse {
    repository: String,
    rules: Vec<BranchRuleSummary>,
}

async fn list_branch_rules(
    State(state): State<AdminState>,
    AdminMember(_actor): AdminMember,
    ApiQuery(query): ApiQuery<ListBranchRulesQuery>,
) -> ApiResult<BranchRulesResponse> {
    match state.policy_store.list_branch_rules(&query.repo).await {
        Ok(rules) => ok(BranchRulesResponse {
            repository: query.repo,
            rules: rules
                .into_iter()
                .map(|rule: BranchRuleRecord| BranchRuleSummary {
                    pattern: rule.pattern,
                    groups: rule.groups,
                })
                .collect(),
        }),
        Err(error) => Err(store_error(error)),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RemoveBranchRuleQuery {
    repo: String,
    pattern: String,
}

#[derive(Serialize)]
struct BranchRuleRemovedResponse {
    repository: String,
    pattern: String,
    removed: bool,
}

async fn remove_branch_rule(
    State(state): State<AdminState>,
    AdminMember(actor): AdminMember,
    ApiQuery(query): ApiQuery<RemoveBranchRuleQuery>,
) -> ApiResult<BranchRuleRemovedResponse> {
    match state
        .policy_store
        .remove_branch_rule(Some(actor.id), &query.repo, &query.pattern)
        .await
    {
        Ok(removed) => ok(BranchRuleRemovedResponse {
            repository: query.repo,
            pattern: query.pattern,
            removed,
        }),
        Err(error) => Err(store_error(error)),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SetPublicKeyBody {
    public_key: String,
}

#[derive(Serialize)]
struct MemberPublicKeyResponse {
    name: String,
    public_key: String,
}

async fn set_own_public_key(
    State(state): State<AdminState>,
    CurrentMember(member): CurrentMember,
    ApiJson(body): ApiJson<SetPublicKeyBody>,
) -> ApiResult<MemberPublicKeyResponse> {
    match state
        .policy_store
        .set_member_public_key(Some(member.id), &member.name, &body.public_key)
        .await
    {
        Ok(record) => ok(MemberPublicKeyResponse {
            name: record.name,
            public_key: record.public_key,
        }),
        Err(error) => Err(store_error(error)),
    }
}

async fn set_member_public_key(
    State(state): State<AdminState>,
    AdminMember(actor): AdminMember,
    ApiPath(name): ApiPath<String>,
    ApiJson(body): ApiJson<SetPublicKeyBody>,
) -> ApiResult<MemberPublicKeyResponse> {
    match state
        .policy_store
        .set_member_public_key(Some(actor.id), &name, &body.public_key)
        .await
    {
        Ok(record) => ok(MemberPublicKeyResponse {
            name: record.name,
            public_key: record.public_key,
        }),
        Err(error) => Err(store_error(error)),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AddSshKeyBody {
    public_key: String,
    #[serde(default)]
    label: String,
}

#[derive(Serialize)]
struct SshKeyResponse {
    id: i64,
    fingerprint: String,
    public_key: String,
    label: String,
}

impl From<MemberSshKeyRecord> for SshKeyResponse {
    fn from(record: MemberSshKeyRecord) -> Self {
        Self {
            id: record.id,
            fingerprint: record.fingerprint,
            public_key: record.public_key,
            label: record.label,
        }
    }
}

#[derive(Serialize)]
struct SshKeysResponse {
    member: String,
    keys: Vec<SshKeyResponse>,
}

#[derive(Serialize)]
struct SshKeyAddedResponse {
    member: String,
    key: SshKeyResponse,
}

#[derive(Serialize)]
struct SshKeyRevokedResponse {
    member: String,
    id: i64,
    revoked: bool,
}

/// Lists `member_name`'s active SSH keys.
async fn list_ssh_keys(state: &AdminState, member_name: String) -> ApiResult<SshKeysResponse> {
    match state.policy_store.list_member_ssh_keys(&member_name).await {
        Ok(keys) => ok(SshKeysResponse {
            member: member_name,
            keys: keys.into_iter().map(SshKeyResponse::from).collect(),
        }),
        Err(error) => Err(store_error(error)),
    }
}

/// Registers `body`'s key for `member_name` on behalf of `actor`.
async fn add_ssh_key(
    state: &AdminState,
    actor: &AuthenticatedMember,
    member_name: &str,
    body: AddSshKeyBody,
) -> ApiResult<SshKeyAddedResponse> {
    match state
        .policy_store
        .add_member_ssh_key(Some(actor.id), member_name, &body.public_key, &body.label)
        .await
    {
        Ok(record) => created(SshKeyAddedResponse {
            member: record.member.clone(),
            key: SshKeyResponse::from(record),
        }),
        Err(error) => Err(store_error(error)),
    }
}

/// Revokes `member_name`'s key `key_id` on behalf of `actor`.
async fn revoke_ssh_key(
    state: &AdminState,
    actor: &AuthenticatedMember,
    member_name: String,
    key_id: i64,
) -> ApiResult<SshKeyRevokedResponse> {
    match state
        .policy_store
        .revoke_member_ssh_key(Some(actor.id), &member_name, key_id)
        .await
    {
        Ok(revoked) => ok(SshKeyRevokedResponse {
            member: member_name,
            id: key_id,
            revoked,
        }),
        Err(error) => Err(store_error(error)),
    }
}

async fn list_own_ssh_keys(
    State(state): State<AdminState>,
    CurrentMember(member): CurrentMember,
) -> ApiResult<SshKeysResponse> {
    list_ssh_keys(&state, member.name).await
}

async fn add_own_ssh_key(
    State(state): State<AdminState>,
    CurrentMember(member): CurrentMember,
    ApiJson(body): ApiJson<AddSshKeyBody>,
) -> ApiResult<SshKeyAddedResponse> {
    add_ssh_key(&state, &member, &member.name, body).await
}

async fn revoke_own_ssh_key(
    State(state): State<AdminState>,
    CurrentMember(member): CurrentMember,
    ApiPath(key_id): ApiPath<i64>,
) -> ApiResult<SshKeyRevokedResponse> {
    let member_name = member.name.clone();
    revoke_ssh_key(&state, &member, member_name, key_id).await
}

async fn list_member_ssh_keys(
    State(state): State<AdminState>,
    AdminMember(_actor): AdminMember,
    ApiPath(name): ApiPath<String>,
) -> ApiResult<SshKeysResponse> {
    list_ssh_keys(&state, name).await
}

async fn add_member_ssh_key(
    State(state): State<AdminState>,
    AdminMember(actor): AdminMember,
    ApiPath(name): ApiPath<String>,
    ApiJson(body): ApiJson<AddSshKeyBody>,
) -> ApiResult<SshKeyAddedResponse> {
    add_ssh_key(&state, &actor, &name, body).await
}

async fn revoke_member_ssh_key(
    State(state): State<AdminState>,
    AdminMember(actor): AdminMember,
    ApiPath((name, key_id)): ApiPath<(String, i64)>,
) -> ApiResult<SshKeyRevokedResponse> {
    revoke_ssh_key(&state, &actor, name, key_id).await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SetSecretScopeBody {
    repository: String,
    scope: String,
    groups: Vec<String>,
}

#[derive(Serialize)]
struct SecretScopeResponse {
    repository: String,
    scope: String,
    groups: Vec<String>,
}

async fn set_secret_scope(
    State(state): State<AdminState>,
    AdminMember(actor): AdminMember,
    ApiJson(body): ApiJson<SetSecretScopeBody>,
) -> ApiResult<SecretScopeResponse> {
    let groups: BTreeSet<String> = body.groups.into_iter().collect();
    match state
        .policy_store
        .set_secret_scope(Some(actor.id), &body.repository, &body.scope, groups)
        .await
    {
        Ok(record) => ok(SecretScopeResponse {
            repository: record.repository,
            scope: record.scope,
            groups: record.groups,
        }),
        Err(error) => Err(store_error(error)),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ListSecretScopesQuery {
    repo: String,
}

#[derive(Serialize)]
struct SecretScopeSummary {
    scope: String,
    groups: Vec<String>,
}

#[derive(Serialize)]
struct SecretScopesResponse {
    repository: String,
    scopes: Vec<SecretScopeSummary>,
}

async fn list_secret_scopes(
    State(state): State<AdminState>,
    AdminMember(_actor): AdminMember,
    ApiQuery(query): ApiQuery<ListSecretScopesQuery>,
) -> ApiResult<SecretScopesResponse> {
    match state.policy_store.list_secret_scopes(&query.repo).await {
        Ok(scopes) => ok(SecretScopesResponse {
            repository: query.repo,
            scopes: scopes
                .into_iter()
                .map(|record: SecretScopeRecord| SecretScopeSummary {
                    scope: record.scope,
                    groups: record.groups,
                })
                .collect(),
        }),
        Err(error) => Err(store_error(error)),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SecretScopeQuery {
    repo: String,
    scope: String,
}

#[derive(Serialize)]
struct SecretScopeRemovedResponse {
    repository: String,
    scope: String,
    removed: bool,
}

async fn remove_secret_scope(
    State(state): State<AdminState>,
    AdminMember(actor): AdminMember,
    ApiQuery(query): ApiQuery<SecretScopeQuery>,
) -> ApiResult<SecretScopeRemovedResponse> {
    match state
        .policy_store
        .remove_secret_scope(Some(actor.id), &query.repo, &query.scope)
        .await
    {
        Ok(removed) => ok(SecretScopeRemovedResponse {
            repository: query.repo,
            scope: query.scope,
            removed,
        }),
        Err(error) => Err(store_error(error)),
    }
}

#[derive(Serialize)]
struct ScopeRecipientResponse {
    member: String,
    public_key: String,
}

impl From<ScopeRecipient> for ScopeRecipientResponse {
    fn from(recipient: ScopeRecipient) -> Self {
        Self {
            member: recipient.member,
            public_key: recipient.public_key,
        }
    }
}

#[derive(Serialize)]
struct ScopeRecipientsResponse {
    repository: String,
    scope: String,
    groups: Vec<String>,
    recipients: Vec<ScopeRecipientResponse>,
    members_without_key: Vec<String>,
}

async fn get_secret_scope_recipients(
    State(state): State<AdminState>,
    CurrentMember(member): CurrentMember,
    ApiQuery(query): ApiQuery<SecretScopeQuery>,
) -> ApiResult<ScopeRecipientsResponse> {
    let record = match state
        .policy_store
        .resolve_secret_scope_recipients(&query.repo, &query.scope)
        .await
    {
        Ok(record) => record,
        Err(PolicyStoreError::NotFound(_)) if !member.is_admin => {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "access to this secret scope is forbidden",
            ));
        }
        Err(error) => return Err(store_error(error)),
    };
    if !member.is_admin {
        let member_groups = match state.policy_store.list_member_groups(member.id).await {
            Ok(groups) => groups,
            Err(error) => return Err(store_error(error)),
        };
        let is_authorized = record
            .groups
            .iter()
            .any(|group| member_groups.contains(group));
        if !is_authorized {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "access to this secret scope is forbidden",
            ));
        }
    }
    ok(ScopeRecipientsResponse {
        repository: record.repository,
        scope: record.scope,
        groups: record.groups,
        recipients: record
            .recipients
            .into_iter()
            .map(ScopeRecipientResponse::from)
            .collect(),
        members_without_key: record.members_without_key,
    })
}

#[derive(Serialize)]
struct GroupRecipientsResponse {
    group: String,
    recipients: Vec<ScopeRecipientResponse>,
    members_without_key: Vec<String>,
}

async fn get_group_recipients(
    State(state): State<AdminState>,
    CurrentMember(member): CurrentMember,
    ApiPath(group): ApiPath<String>,
) -> ApiResult<GroupRecipientsResponse> {
    let record = match state.policy_store.resolve_group_recipients(&group).await {
        Ok(record) => record,
        Err(PolicyStoreError::NotFound(_)) if !member.is_admin => {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "access to this group is forbidden",
            ));
        }
        Err(error) => return Err(store_error(error)),
    };
    if !member.is_admin {
        let member_groups = match state.policy_store.list_member_groups(member.id).await {
            Ok(groups) => groups,
            Err(error) => return Err(store_error(error)),
        };
        if !member_groups.contains(&record.group) {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "access to this group is forbidden",
            ));
        }
    }
    ok(GroupRecipientsResponse {
        group: record.group,
        recipients: record
            .recipients
            .into_iter()
            .map(ScopeRecipientResponse::from)
            .collect(),
        members_without_key: record.members_without_key,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SetPathRuleBody {
    repository: String,
    pattern: String,
    groups: Vec<String>,
}

#[derive(Serialize)]
struct PathRuleResponse {
    repository: String,
    pattern: String,
    groups: Vec<String>,
}

async fn set_path_rule(
    State(state): State<AdminState>,
    AdminMember(actor): AdminMember,
    ApiJson(body): ApiJson<SetPathRuleBody>,
) -> ApiResult<PathRuleResponse> {
    let groups: BTreeSet<String> = body.groups.into_iter().collect();
    match state
        .policy_store
        .set_path_rule(Some(actor.id), &body.repository, &body.pattern, groups)
        .await
    {
        Ok(rule) => ok(PathRuleResponse {
            repository: rule.repository,
            pattern: rule.pattern,
            groups: rule.groups,
        }),
        Err(error) => Err(store_error(error)),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ListPathRulesQuery {
    repo: String,
}

#[derive(Serialize)]
struct PathRuleSummary {
    pattern: String,
    groups: Vec<String>,
}

#[derive(Serialize)]
struct PathRulesResponse {
    repository: String,
    rules: Vec<PathRuleSummary>,
}

async fn list_path_rules(
    State(state): State<AdminState>,
    AdminMember(_actor): AdminMember,
    ApiQuery(query): ApiQuery<ListPathRulesQuery>,
) -> ApiResult<PathRulesResponse> {
    match state.policy_store.list_path_rules(&query.repo).await {
        Ok(rules) => ok(PathRulesResponse {
            repository: query.repo,
            rules: rules
                .into_iter()
                .map(|rule: PathRuleRecord| PathRuleSummary {
                    pattern: rule.pattern,
                    groups: rule.groups,
                })
                .collect(),
        }),
        Err(error) => Err(store_error(error)),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RemovePathRuleQuery {
    repo: String,
    pattern: String,
}

#[derive(Serialize)]
struct PathRuleRemovedResponse {
    repository: String,
    pattern: String,
    removed: bool,
}

async fn remove_path_rule(
    State(state): State<AdminState>,
    AdminMember(actor): AdminMember,
    ApiQuery(query): ApiQuery<RemovePathRuleQuery>,
) -> ApiResult<PathRuleRemovedResponse> {
    match state
        .policy_store
        .remove_path_rule(Some(actor.id), &query.repo, &query.pattern)
        .await
    {
        Ok(removed) => ok(PathRuleRemovedResponse {
            repository: query.repo,
            pattern: query.pattern,
            removed,
        }),
        Err(error) => Err(store_error(error)),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MyPathRulesQuery {
    repo: String,
}

#[derive(Serialize)]
struct MyPathRulesResponse {
    repository: String,
    withheld_patterns: Vec<String>,
    sparse_checkout_patterns: Vec<String>,
}

async fn get_my_withheld_paths(
    State(state): State<AdminState>,
    CurrentMember(member): CurrentMember,
    ApiQuery(query): ApiQuery<MyPathRulesQuery>,
) -> ApiResult<MyPathRulesResponse> {
    let Some(resolved) = resolve_bare_repo(&state.repo_root, &query.repo).await else {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "repository not found"));
    };
    let policy = match state
        .policy_store
        .load_member_repo_policy(member.id, &resolved.canonical_key)
        .await
    {
        Ok(policy) => policy,
        Err(error) => return Err(store_error(error)),
    };
    let withheld_patterns = policy
        .withhold_policy
        .withheld_patterns(&policy.member_groups)
        .into_iter()
        .map(str::to_owned)
        .collect();
    let sparse_checkout_patterns = policy
        .withhold_policy
        .sparse_checkout_patterns(&policy.member_groups);
    ok(MyPathRulesResponse {
        repository: resolved.canonical_key,
        withheld_patterns,
        sparse_checkout_patterns,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ListAuditLogQuery {
    actor: Option<String>,
    action: Option<String>,
    target_type: Option<String>,
    limit: Option<u32>,
    before_id: Option<i64>,
}

#[derive(Serialize)]
struct AuditLogRecordResponse {
    id: i64,
    occurred_at: String,
    actor_member_id: Option<i64>,
    actor_name: Option<String>,
    action: String,
    target_type: String,
    target_name: String,
    details: serde_json::Value,
}

impl From<AuditLogRecord> for AuditLogRecordResponse {
    fn from(record: AuditLogRecord) -> Self {
        Self {
            id: record.id,
            occurred_at: record.occurred_at,
            actor_member_id: record.actor_member_id,
            actor_name: record.actor_name,
            action: record.action,
            target_type: record.target_type,
            target_name: record.target_name,
            details: record.details,
        }
    }
}

#[derive(Serialize)]
struct AuditLogResponse {
    entries: Vec<AuditLogRecordResponse>,
    next_before_id: Option<i64>,
}

async fn list_audit_log(
    State(state): State<AdminState>,
    AdminMember(_actor): AdminMember,
    ApiQuery(query): ApiQuery<ListAuditLogQuery>,
) -> ApiResult<AuditLogResponse> {
    let limit = match query.limit {
        Some(limit) => limit,
        None => DEFAULT_AUDIT_LOG_LIMIT,
    };
    let store_query = AuditLogQuery {
        actor: query.actor,
        action: query.action,
        target_type: query.target_type,
        limit,
        before_id: query.before_id,
    };
    match state.policy_store.list_audit_log(store_query).await {
        Ok(page) => ok(AuditLogResponse {
            entries: page
                .entries
                .into_iter()
                .map(AuditLogRecordResponse::from)
                .collect(),
            next_before_id: page.next_before_id,
        }),
        Err(error) => Err(store_error(error)),
    }
}
