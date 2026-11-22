//! Where members, their tokens, group memberships and branch rules come from.
//!
//! The server only ever sees a [`PolicyStore`]: authentication hands it the
//! SHA-256 hash of the presented token, and every Git request asks it for the
//! member's groups and the repository's [`BranchPolicy`]. The admin API uses
//! the same trait to change members, groups, repositories and branch rules;
//! every change is validated here and recorded in the audit log in the same
//! transaction. Three stores exist: [`StaticPolicyStore`] keeps the single
//! shared token of Milestone M0 (and supports no administration),
//! [`MemoryPolicyStore`] holds everything in memory (for tests and embedding),
//! and [`PgPolicyStore`] reads and writes PostgreSQL.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    future::Future,
    pin::Pin,
    str::FromStr,
    sync::{Arc, Mutex, MutexGuard},
};

use scrim_policy::{
    BranchPolicy, BranchRule, MAX_PATH_RULES, PolicyError, WithholdPolicy, WithholdRule,
    validate_path_glob,
};
use secrecy::SecretString;
use sqlx::{
    PgConnection, PgPool, Postgres, Transaction,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::{
    auth::{TokenAuth, sha256_zeroizing},
    repo_path::is_valid_repo_path,
};

/// Maximum byte length of a member or group name.
pub const MAX_NAME_BYTES: usize = 64;

/// Maximum byte length of a secret scope name.
pub const MAX_SCOPE_NAME_BYTES: usize = 64;

/// Maximum byte length of a token label.
pub const MAX_TOKEN_LABEL_BYTES: usize = 128;

/// Maximum byte length of a registered repository path.
pub const MAX_REPOSITORY_PATH_BYTES: usize = 256;

/// Prefix of every API token the server issues.
pub const API_TOKEN_PREFIX: &str = "scrim_";

/// Number of random bytes behind each issued API token.
const API_TOKEN_RANDOM_BYTES: usize = 32;

/// Message of the [`PolicyStoreError::Unsupported`] error returned by stores
/// that cannot be administered.
const ADMINISTRATION_UNSUPPORTED: &str =
    "administration is not available: the server is not backed by a database";

/// Key of the transaction-scoped advisory lock that serializes
/// [`PolicyStore::bootstrap_admin`] calls across servers sharing a database.
const BOOTSTRAP_ADMIN_LOCK_KEY: i64 = 0x7363_7269_6d00_0001;

/// The member a request was authenticated as.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedMember {
    /// Database ID of the member (`0` for [`StaticPolicyStore`]).
    pub id: i64,
    /// Unique member name.
    pub name: String,
    /// Whether the member may administer the server.
    pub is_admin: bool,
}

/// What one member may see in one repository.
#[derive(Clone, Debug)]
pub struct MemberRepoPolicy {
    /// Names of the groups the member belongs to.
    pub member_groups: BTreeSet<String>,
    /// The repository's compiled branch rules (empty if it has none).
    pub branch_policy: BranchPolicy,
    /// The repository's compiled path withholding rules (empty if it has none).
    pub withhold_policy: WithholdPolicy,
}

/// One append-only entry written to `audit_log`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditLogEntry {
    /// ID of the acting member (`None` when not tied to a member row).
    pub actor_member_id: Option<i64>,
    /// Machine-readable action name, e.g. `branch.merge_leak_override`.
    pub action: String,
    /// Kind of target acted on, e.g. `repository_ref`.
    pub target_type: String,
    /// Human-readable target identifier, e.g. `team/app.git:refs/heads/main`.
    pub target_name: String,
    /// Structured JSON metadata stored in `audit_log.details`.
    pub details: serde_json::Value,
}

impl AuditLogEntry {
    fn new(
        actor_member_id: Option<i64>,
        action: &str,
        target_type: &str,
        target_name: String,
        details: serde_json::Value,
    ) -> Self {
        Self {
            actor_member_id,
            action: action.to_owned(),
            target_type: target_type.to_owned(),
            target_name,
            details,
        }
    }
}

/// A registered repository.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepositoryRecord {
    /// Database ID of the repository.
    pub id: i64,
    /// Canonical repository key relative to the repository root, e.g.
    /// `team/app.git`.
    pub path: String,
}

/// Outcome of [`PolicyStore::register_repository`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegisterRepositoryResult {
    /// The (new or existing) repository.
    pub repository: RepositoryRecord,
    /// Whether this call registered it (`false` if it already was).
    pub created: bool,
}

/// A group without its members.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupRecord {
    /// Database ID of the group.
    pub id: i64,
    /// Unique group name.
    pub name: String,
}

/// A group and the names of its active members, sorted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupWithMembers {
    /// Database ID of the group.
    pub id: i64,
    /// Unique group name.
    pub name: String,
    /// Names of the group's non-revoked members, sorted ascending.
    pub members: Vec<String>,
}

/// Outcome of [`PolicyStore::add_group_member`] and
/// [`PolicyStore::remove_group_member`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupMembershipChange {
    /// Name of the group.
    pub group: String,
    /// Name of the member.
    pub member: String,
    /// Whether the membership changed (`false` if it already was as asked).
    pub changed: bool,
}

/// A member as administrators see it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberRecord {
    /// Database ID of the member.
    pub id: i64,
    /// Unique member name.
    pub name: String,
    /// Whether the member may administer the server.
    pub is_admin: bool,
    /// Whether the member is a machine account (CI, bots).
    pub is_machine: bool,
    /// Optional `age` public key registered for the member.
    pub public_key: Option<String>,
    /// Names of the member's groups, sorted ascending.
    pub groups: Vec<String>,
    /// Whether the member has been revoked.
    pub revoked: bool,
}

/// What [`PolicyStore::create_member`] creates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreateMemberRequest {
    /// Unique member name; see [`MAX_NAME_BYTES`].
    pub name: String,
    /// Whether the member may administer the server.
    pub is_admin: bool,
    /// Whether the member is a machine account.
    pub is_machine: bool,
    /// Optional `age` public key to attach to the member at creation.
    pub public_key: Option<String>,
    /// Existing groups to add the member to.
    pub groups: BTreeSet<String>,
    /// Label of the member's first token; see [`MAX_TOKEN_LABEL_BYTES`].
    pub token_label: String,
}

/// Outcome of [`PolicyStore::set_member_public_key`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberPublicKeyRecord {
    /// Name of the member.
    pub name: String,
    /// Validated `age` public key stored for the member.
    pub public_key: String,
}

/// A newly created member and their first token.
#[derive(Debug)]
pub struct CreatedMember {
    /// The created member.
    pub member: MemberRecord,
    /// The plaintext token. Only its SHA-256 digest is stored, so this is the
    /// one chance to hand it to the member.
    pub token: SecretString,
}

/// A newly issued token for an existing member.
#[derive(Debug)]
pub struct IssuedToken {
    /// Name of the member owning the token.
    pub member: String,
    /// The token's label.
    pub label: String,
    /// The plaintext token, shown only once (only its digest is stored).
    pub token: SecretString,
}

/// Outcome of [`PolicyStore::revoke_member`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevokeMemberResult {
    /// Name of the member.
    pub name: String,
    /// Whether this call revoked the member (`false` if already revoked).
    pub revoked: bool,
}

/// One branch rule of a repository.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BranchRuleRecord {
    /// Canonical key of the repository the rule belongs to.
    pub repository: String,
    /// The rule's ref glob, e.g. `refs/heads/private/*`.
    pub pattern: String,
    /// Groups allowed to see matching refs, sorted ascending.
    pub groups: Vec<String>,
}

/// One server-enforced path withholding rule of a repository.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathRuleRecord {
    /// Canonical key of the repository the rule belongs to.
    pub repository: String,
    /// The rule's repo-relative path glob, e.g. `config/billing/**` or `*.secret`.
    pub pattern: String,
    /// Groups allowed to read matching paths, sorted ascending.
    pub groups: Vec<String>,
}

/// One secret scope of a repository.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretScopeRecord {
    /// Canonical key of the repository the scope belongs to.
    pub repository: String,
    /// Name of the secret scope (e.g. `dev`, `staging`, `prod`).
    pub scope: String,
    /// Groups allowed to access secrets in this scope, sorted ascending.
    pub groups: Vec<String>,
}

/// An active member and their registered `age` public key for a secret scope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScopeRecipient {
    /// Unique member name.
    pub member: String,
    /// Validated `age` public key.
    pub public_key: String,
}

/// Resolved recipients and missing-key members for a repository secret scope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScopeRecipientsRecord {
    /// Canonical key of the repository the scope belongs to.
    pub repository: String,
    /// Name of the secret scope.
    pub scope: String,
    /// Groups authorized for this scope, sorted ascending.
    pub groups: Vec<String>,
    /// Active members in those groups who have a public key, sorted by member name ascending.
    pub recipients: Vec<ScopeRecipient>,
    /// Active members in those groups without a public key, sorted ascending.
    pub members_without_key: Vec<String>,
}

/// Active members of one group, split into those with a registered `age`
/// public key and those without one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupRecipientsRecord {
    /// Name of the group.
    pub group: String,
    /// Active members in this group who have a public key, sorted by member name ascending.
    pub recipients: Vec<ScopeRecipient>,
    /// Active members in this group without a public key, sorted ascending.
    pub members_without_key: Vec<String>,
}

/// Errors a [`PolicyStore`] reports. Callers must treat every error as "deny".
///
/// No variant ever carries a token, a token hash, or database credentials.
#[derive(Debug)]
pub enum PolicyStoreError {
    /// The database could not be reached or a query failed.
    Database(sqlx::Error),
    /// A branch rule stored for `repository` failed validation, so the whole
    /// policy is rejected rather than served with a rule missing.
    InvalidBranchRule {
        /// Canonical key of the repository the rule belongs to.
        repository: String,
        /// Why the rule was rejected.
        source: PolicyError,
    },
    /// A path withholding rule stored for a repository failed validation, so
    /// the whole policy is rejected rather than served with a rule missing.
    InvalidPathRule {
        /// The offending path glob (or empty when the rule set failed policy compilation).
        path_glob: String,
        /// Why the rule was rejected.
        source: PolicyError,
    },
    /// Any other internal failure, described by the message.
    Internal(String),
    /// An administrative change names a member, group, repository or rule
    /// that does not exist. The message is safe to show the administrator.
    NotFound(String),
    /// An administrative change conflicts with existing state (a duplicate
    /// name, or revoking the last active admin). Safe to show.
    Conflict(String),
    /// An administrative change has invalid input. Safe to show.
    InvalidInput(String),
    /// The store does not support the operation (e.g. administering a
    /// [`StaticPolicyStore`]). Safe to show.
    Unsupported(String),
}

impl fmt::Display for PolicyStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database(error) => write!(f, "policy database error: {error}"),
            Self::InvalidBranchRule { repository, source } => {
                write!(
                    f,
                    "invalid branch rule for repository {repository:?}: {source}"
                )
            }
            Self::InvalidPathRule { path_glob, source } => {
                write!(f, "invalid path rule for glob {path_glob:?}: {source}")
            }
            Self::Internal(message) => write!(f, "policy store error: {message}"),
            Self::NotFound(message)
            | Self::Conflict(message)
            | Self::InvalidInput(message)
            | Self::Unsupported(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for PolicyStoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Database(error) => Some(error),
            Self::InvalidBranchRule { source, .. } | Self::InvalidPathRule { source, .. } => {
                Some(source)
            }
            Self::Internal(_)
            | Self::NotFound(_)
            | Self::Conflict(_)
            | Self::InvalidInput(_)
            | Self::Unsupported(_) => None,
        }
    }
}

/// The boxed future every [`PolicyStore`] method returns, which keeps the
/// trait object-safe without an `async-trait` dependency.
pub type PolicyStoreFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, PolicyStoreError>> + Send + 'a>>;

/// Wraps an already computed `result` in a [`PolicyStoreFuture`].
fn ready<'a, T: Send + 'a>(result: Result<T, PolicyStoreError>) -> PolicyStoreFuture<'a, T> {
    Box::pin(std::future::ready(result))
}

/// The answer of every administrative method a store does not implement.
fn unsupported<'a, T: Send + 'a>() -> PolicyStoreFuture<'a, T> {
    ready(Err(PolicyStoreError::Unsupported(
        ADMINISTRATION_UNSUPPORTED.to_owned(),
    )))
}

/// Source of members and repository policy, shared by all requests.
///
/// The administrative methods (everything after
/// [`PolicyStore::record_audit_event`]) default to
/// [`PolicyStoreError::Unsupported`], so a read-only store fails closed. Every
/// implemented mutation validates its input, fails with
/// [`PolicyStoreError::InvalidInput`], [`PolicyStoreError::NotFound`] or
/// [`PolicyStoreError::Conflict`] as documented, and records its audit entry
/// atomically with the change. Audit entries never contain tokens.
pub trait PolicyStore: Send + Sync + 'static {
    /// Returns the active member owning the token whose SHA-256 hash is
    /// `token_hash`, or `None` when no active token matches (including
    /// revoked tokens and revoked members).
    fn authenticate_token_hash<'a>(
        &'a self,
        token_hash: &'a [u8; 32],
    ) -> PolicyStoreFuture<'a, Option<AuthenticatedMember>>;

    /// Loads `member_id`'s groups and the branch and path withholding rules of
    /// the repository whose canonical key is `repo_key`. A repository without
    /// rules yields empty policies, so every ref and path stays visible.
    ///
    /// Fails with [`PolicyStoreError::InvalidBranchRule`] or
    /// [`PolicyStoreError::InvalidPathRule`] if any stored rule is invalid.
    fn load_member_repo_policy<'a>(
        &'a self,
        member_id: i64,
        repo_key: &'a str,
    ) -> PolicyStoreFuture<'a, MemberRepoPolicy>;

    /// Appends `entry` to the audit log. Callers guarding security overrides
    /// must fail closed if recording the audit event fails.
    fn record_audit_event<'a>(&'a self, entry: AuditLogEntry) -> PolicyStoreFuture<'a, ()>;

    /// Returns the names of `member_id`'s groups.
    fn list_member_groups<'a>(&'a self, member_id: i64) -> PolicyStoreFuture<'a, BTreeSet<String>> {
        let _ = member_id;
        unsupported()
    }

    /// Registers the repository with canonical key `repo_path` (see
    /// [`MAX_REPOSITORY_PATH_BYTES`]; `api` and `api/...` are reserved).
    /// Idempotent: an already registered repository is returned with
    /// `created == false` and nothing is audited.
    fn register_repository<'a>(
        &'a self,
        actor_member_id: Option<i64>,
        repo_path: &'a str,
    ) -> PolicyStoreFuture<'a, RegisterRepositoryResult> {
        let _ = (actor_member_id, repo_path);
        unsupported()
    }

    /// Lists every registered repository, sorted by path.
    fn list_repositories<'a>(&'a self) -> PolicyStoreFuture<'a, Vec<RepositoryRecord>> {
        unsupported()
    }

    /// Creates the group `name`; [`PolicyStoreError::Conflict`] if it exists.
    fn create_group<'a>(
        &'a self,
        actor_member_id: Option<i64>,
        name: &'a str,
    ) -> PolicyStoreFuture<'a, GroupRecord> {
        let _ = (actor_member_id, name);
        unsupported()
    }

    /// Lists every group (sorted by name) with its active members.
    fn list_groups<'a>(&'a self) -> PolicyStoreFuture<'a, Vec<GroupWithMembers>> {
        unsupported()
    }

    /// Adds the active member `member_name` to `group_name`. Idempotent:
    /// `changed == false` (and no audit entry) if already a member.
    fn add_group_member<'a>(
        &'a self,
        actor_member_id: Option<i64>,
        group_name: &'a str,
        member_name: &'a str,
    ) -> PolicyStoreFuture<'a, GroupMembershipChange> {
        let _ = (actor_member_id, group_name, member_name);
        unsupported()
    }

    /// Removes `member_name` from `group_name`. Idempotent: `changed ==
    /// false` (and no audit entry) if not a member.
    fn remove_group_member<'a>(
        &'a self,
        actor_member_id: Option<i64>,
        group_name: &'a str,
        member_name: &'a str,
    ) -> PolicyStoreFuture<'a, GroupMembershipChange> {
        let _ = (actor_member_id, group_name, member_name);
        unsupported()
    }

    /// Creates a member, their group memberships and a first token.
    ///
    /// [`PolicyStoreError::Conflict`] if the name is taken (even by a revoked
    /// member); [`PolicyStoreError::NotFound`] if a group does not exist.
    fn create_member<'a>(
        &'a self,
        actor_member_id: Option<i64>,
        request: CreateMemberRequest,
    ) -> PolicyStoreFuture<'a, CreatedMember> {
        let _ = (actor_member_id, request);
        unsupported()
    }

    /// Issues an additional token labelled `label` to the active member
    /// `member_name`.
    fn issue_member_token<'a>(
        &'a self,
        actor_member_id: Option<i64>,
        member_name: &'a str,
        label: &'a str,
    ) -> PolicyStoreFuture<'a, IssuedToken> {
        let _ = (actor_member_id, member_name, label);
        unsupported()
    }

    /// Revokes `member_name` and every token they hold. Idempotent:
    /// `revoked == false` if already revoked.
    ///
    /// [`PolicyStoreError::Conflict`] if the member is the last active admin.
    fn revoke_member<'a>(
        &'a self,
        actor_member_id: Option<i64>,
        member_name: &'a str,
    ) -> PolicyStoreFuture<'a, RevokeMemberResult> {
        let _ = (actor_member_id, member_name);
        unsupported()
    }

    /// Lists members sorted by name, skipping revoked ones unless
    /// `include_revoked`.
    fn list_members<'a>(
        &'a self,
        include_revoked: bool,
    ) -> PolicyStoreFuture<'a, Vec<MemberRecord>> {
        let _ = include_revoked;
        unsupported()
    }

    /// Creates or replaces the rule restricting refs matching `pattern` in
    /// `repository` to the (non-empty) `groups`.
    ///
    /// [`PolicyStoreError::NotFound`] if the repository is not registered or
    /// a group does not exist.
    fn set_branch_rule<'a>(
        &'a self,
        actor_member_id: Option<i64>,
        repository: &'a str,
        pattern: &'a str,
        groups: BTreeSet<String>,
    ) -> PolicyStoreFuture<'a, BranchRuleRecord> {
        let _ = (actor_member_id, repository, pattern, groups);
        unsupported()
    }

    /// Lists `repository`'s rules sorted by pattern;
    /// [`PolicyStoreError::NotFound`] if it is not registered.
    fn list_branch_rules<'a>(
        &'a self,
        repository: &'a str,
    ) -> PolicyStoreFuture<'a, Vec<BranchRuleRecord>> {
        let _ = repository;
        unsupported()
    }

    /// Removes the rule `pattern` from `repository`, returning `true`;
    /// [`PolicyStoreError::NotFound`] if either does not exist.
    fn remove_branch_rule<'a>(
        &'a self,
        actor_member_id: Option<i64>,
        repository: &'a str,
        pattern: &'a str,
    ) -> PolicyStoreFuture<'a, bool> {
        let _ = (actor_member_id, repository, pattern);
        unsupported()
    }

    /// Creates or replaces the path withholding rule restricting paths matching
    /// `pattern` in `repository` to the (non-empty) `groups`.
    ///
    /// [`PolicyStoreError::NotFound`] if the repository is not registered or
    /// a group does not exist; [`PolicyStoreError::InvalidInput`] if adding a
    /// new pattern would exceed [`MAX_PATH_RULES`].
    fn set_path_rule<'a>(
        &'a self,
        actor_member_id: Option<i64>,
        repository: &'a str,
        pattern: &'a str,
        groups: BTreeSet<String>,
    ) -> PolicyStoreFuture<'a, PathRuleRecord> {
        let _ = (actor_member_id, repository, pattern, groups);
        unsupported()
    }

    /// Lists `repository`'s path withholding rules sorted by pattern;
    /// [`PolicyStoreError::NotFound`] if it is not registered.
    fn list_path_rules<'a>(
        &'a self,
        repository: &'a str,
    ) -> PolicyStoreFuture<'a, Vec<PathRuleRecord>> {
        let _ = repository;
        unsupported()
    }

    /// Removes the path withholding rule `pattern` from `repository`, returning
    /// `true`; [`PolicyStoreError::NotFound`] if either does not exist.
    fn remove_path_rule<'a>(
        &'a self,
        actor_member_id: Option<i64>,
        repository: &'a str,
        pattern: &'a str,
    ) -> PolicyStoreFuture<'a, bool> {
        let _ = (actor_member_id, repository, pattern);
        unsupported()
    }

    /// Creates the first admin, `name`, with a token labelled `token_label`.
    ///
    /// [`PolicyStoreError::Conflict`] if any active admin already exists (or
    /// the name is taken); concurrent calls cannot create two admins.
    fn bootstrap_admin<'a>(
        &'a self,
        name: &'a str,
        token_label: &'a str,
    ) -> PolicyStoreFuture<'a, CreatedMember> {
        let _ = (name, token_label);
        unsupported()
    }

    /// Returns the `age` public key of the active member `member_id`, or `None`
    /// if none is registered.
    fn get_member_public_key<'a>(
        &'a self,
        member_id: i64,
    ) -> PolicyStoreFuture<'a, Option<String>> {
        let _ = member_id;
        unsupported()
    }

    /// Sets `member_name`'s `age` public key to `public_key`.
    ///
    /// Requires an active (non-revoked) member (`PolicyStoreError::NotFound` if
    /// missing or revoked).
    fn set_member_public_key<'a>(
        &'a self,
        actor_member_id: Option<i64>,
        member_name: &'a str,
        public_key: &'a str,
    ) -> PolicyStoreFuture<'a, MemberPublicKeyRecord> {
        let _ = (actor_member_id, member_name, public_key);
        unsupported()
    }

    /// Creates or replaces the secret scope `scope` in `repository`, granting
    /// access to the (non-empty) `groups`.
    ///
    /// [`PolicyStoreError::NotFound`] if the repository is not registered or
    /// any group does not exist.
    fn set_secret_scope<'a>(
        &'a self,
        actor_member_id: Option<i64>,
        repository: &'a str,
        scope: &'a str,
        groups: BTreeSet<String>,
    ) -> PolicyStoreFuture<'a, SecretScopeRecord> {
        let _ = (actor_member_id, repository, scope, groups);
        unsupported()
    }

    /// Lists `repository`'s secret scopes sorted by scope name ascending;
    /// [`PolicyStoreError::NotFound`] if the repository is not registered.
    fn list_secret_scopes<'a>(
        &'a self,
        repository: &'a str,
    ) -> PolicyStoreFuture<'a, Vec<SecretScopeRecord>> {
        let _ = repository;
        unsupported()
    }

    /// Removes the secret scope `scope` from `repository`, returning `true`;
    /// [`PolicyStoreError::NotFound`] if either does not exist.
    fn remove_secret_scope<'a>(
        &'a self,
        actor_member_id: Option<i64>,
        repository: &'a str,
        scope: &'a str,
    ) -> PolicyStoreFuture<'a, bool> {
        let _ = (actor_member_id, repository, scope);
        unsupported()
    }

    /// Resolves the authorized groups and active member recipients (split into
    /// keyed `recipients` and `members_without_key`) for `scope` in
    /// `repository`.
    ///
    /// [`PolicyStoreError::NotFound`] if the repository is not registered or
    /// the scope does not exist.
    fn resolve_secret_scope_recipients<'a>(
        &'a self,
        repository: &'a str,
        scope: &'a str,
    ) -> PolicyStoreFuture<'a, ScopeRecipientsRecord> {
        let _ = (repository, scope);
        unsupported()
    }

    /// Resolves active (non-revoked) members of `group`, split into keyed
    /// `recipients` and `members_without_key`, both sorted by member name.
    ///
    /// Returns [`PolicyStoreError::InvalidInput`] on invalid group name and
    /// [`PolicyStoreError::NotFound`] if `group` does not exist.
    fn resolve_group_recipients<'a>(
        &'a self,
        group: &'a str,
    ) -> PolicyStoreFuture<'a, GroupRecipientsRecord> {
        let _ = group;
        unsupported()
    }
}

/// Compiles `rules` for `repo_key`, mapping a rejected rule to
/// [`PolicyStoreError::InvalidBranchRule`].
fn compile_branch_policy(
    repo_key: &str,
    rules: impl IntoIterator<Item = BranchRule>,
) -> Result<BranchPolicy, PolicyStoreError> {
    match BranchPolicy::compile(rules) {
        Ok(branch_policy) => Ok(branch_policy),
        Err(source) => Err(PolicyStoreError::InvalidBranchRule {
            repository: repo_key.to_owned(),
            source,
        }),
    }
}

/// Validates and compiles `(pattern, allowed_groups)` pairs into a
/// [`WithholdPolicy`], mapping any rejected rule to
/// [`PolicyStoreError::InvalidPathRule`].
fn compile_withhold_policy(
    rules: impl IntoIterator<Item = (String, BTreeSet<String>)>,
) -> Result<WithholdPolicy, PolicyStoreError> {
    let mut compiled_input = Vec::new();
    for (pattern, allowed_groups) in rules {
        match WithholdRule::new(pattern.clone(), allowed_groups) {
            Ok(rule) => compiled_input.push(rule),
            Err(source) => {
                return Err(PolicyStoreError::InvalidPathRule {
                    path_glob: pattern,
                    source,
                });
            }
        }
    }
    match WithholdPolicy::compile(compiled_input) {
        Ok(policy) => Ok(policy),
        Err(source) => {
            let path_glob = match &source {
                PolicyError::InvalidPathGlob { pattern, .. }
                | PolicyError::DuplicatePathRule { pattern }
                | PolicyError::GlobCompile { pattern, .. } => pattern.clone(),
                PolicyError::InvalidRefGlob { .. }
                | PolicyError::InvalidGroupName { .. }
                | PolicyError::TooManyPathRules { .. }
                | PolicyError::AmbiguousPathRule { .. } => String::new(),
            };
            Err(PolicyStoreError::InvalidPathRule { path_glob, source })
        }
    }
}

/// Returns whether `name` is 1 to `max_bytes` ASCII bytes, starting with a
/// letter or digit, followed by letters, digits, `.`, `_` or `-`.
fn is_valid_identifier(name: &str, max_bytes: usize) -> bool {
    let Some((first, rest)) = name.as_bytes().split_first() else {
        return false;
    };
    name.len() <= max_bytes
        && first.is_ascii_alphanumeric()
        && rest
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

/// Explains the identifier rules of [`is_valid_identifier`] for `kind`.
fn invalid_name_error(kind: &str, max_bytes: usize) -> PolicyStoreError {
    PolicyStoreError::InvalidInput(format!(
        "invalid {kind} name: use 1 to {max_bytes} ASCII letters, digits, '.', '_' or '-', \
         starting with a letter or digit"
    ))
}

/// Validates a member name (see [`is_valid_identifier`]).
pub(crate) fn validate_member_name(name: &str) -> Result<(), PolicyStoreError> {
    if is_valid_identifier(name, MAX_NAME_BYTES) {
        Ok(())
    } else {
        Err(invalid_name_error("member", MAX_NAME_BYTES))
    }
}

/// Validates a group name (see [`is_valid_identifier`]).
pub(crate) fn validate_group_name(name: &str) -> Result<(), PolicyStoreError> {
    if is_valid_identifier(name, MAX_NAME_BYTES) {
        Ok(())
    } else {
        Err(invalid_name_error("group", MAX_NAME_BYTES))
    }
}

/// Validates a secret scope name (see [`is_valid_identifier`]).
pub(crate) fn validate_scope_name(scope: &str) -> Result<(), PolicyStoreError> {
    if is_valid_identifier(scope, MAX_SCOPE_NAME_BYTES) {
        Ok(())
    } else {
        Err(invalid_name_error("secret scope", MAX_SCOPE_NAME_BYTES))
    }
}

const AGE_PUBLIC_KEY_PREFIX: &str = "age1";
const AGE_PUBLIC_KEY_LEN: usize = 62;
const BECH32_CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
/// BIP-173 HRP expansion of `"age"`: `[c >> 5 for c in b"age"] ++ [0] ++ [c & 31 for c in b"age"]`.
const AGE_HRP_EXPANDED: [u8; 7] = [3, 3, 3, 0, 1, 7, 5];

fn bech32_decode_char(byte: u8) -> Option<u8> {
    for (idx, candidate) in BECH32_CHARSET.iter().enumerate() {
        if *candidate == byte {
            return u8::try_from(idx).ok();
        }
    }
    None
}

fn bech32_polymod(values: impl Iterator<Item = u8>) -> u32 {
    const GEN: [u32; 5] = [
        0x3b6a_57b2,
        0x2650_8e6d,
        0x1ea1_19fa,
        0x3d42_33dd,
        0x2a14_62b3,
    ];
    let mut chk: u32 = 1;
    for value in values {
        let top = chk >> 25;
        chk = ((chk & 0x01ff_ffff) << 5) ^ u32::from(value);
        for (i, generator) in GEN.iter().enumerate() {
            if (top >> i) & 1 != 0 {
                chk ^= *generator;
            }
        }
    }
    chk
}

/// Validates an `age` X25519 Bech32 public key (`age1...`, 62 lowercase chars,
/// zero padding bits in the final 5-bit group, and valid BIP-173 checksum).
pub(crate) fn validate_age_public_key(key: &str) -> Result<(), PolicyStoreError> {
    let invalid = || {
        PolicyStoreError::InvalidInput(
            "invalid age public key: expected a 62-character lowercase Bech32 'age1...' X25519 \
             public key"
                .to_owned(),
        )
    };
    if key.len() != AGE_PUBLIC_KEY_LEN {
        return Err(invalid());
    }
    let Some(encoded) = key.strip_prefix(AGE_PUBLIC_KEY_PREFIX) else {
        return Err(invalid());
    };
    let mut values = [0u8; 58];
    let bytes = encoded.as_bytes();
    if bytes.len() != values.len() {
        return Err(invalid());
    }
    for (slot, byte) in values.iter_mut().zip(bytes.iter()) {
        let Some(val) = bech32_decode_char(*byte) else {
            return Err(invalid());
        };
        *slot = val;
    }
    // 32 raw bytes = 256 bits; 52 5-bit groups = 260 bits, so the final data
    // group (index 51) has 4 low padding bits that must all be zero.
    if values[51] & 0x0f != 0 {
        return Err(invalid());
    }
    // Reject the degenerate all-zero X25519 public key (small-order point).
    if values[..52].iter().all(|&val| val == 0) {
        return Err(invalid());
    }
    let checksum = bech32_polymod(AGE_HRP_EXPANDED.into_iter().chain(values));
    if checksum != 1 {
        return Err(invalid());
    }
    Ok(())
}

/// Validates a token label: at most [`MAX_TOKEN_LABEL_BYTES`] printable ASCII
/// bytes (spaces allowed, control characters not).
pub(crate) fn validate_token_label(label: &str) -> Result<(), PolicyStoreError> {
    if label.len() <= MAX_TOKEN_LABEL_BYTES && label.bytes().all(|byte| matches!(byte, 0x20..=0x7e))
    {
        Ok(())
    } else {
        Err(PolicyStoreError::InvalidInput(format!(
            "invalid token label: use at most {MAX_TOKEN_LABEL_BYTES} printable ASCII characters"
        )))
    }
}

/// Validates a repository path: a valid request path (see
/// [`is_valid_repo_path`]) of at most [`MAX_REPOSITORY_PATH_BYTES`] bytes
/// that does not shadow the `/api/...` routes.
pub(crate) fn validate_repository_path(path: &str) -> Result<(), PolicyStoreError> {
    if path.len() > MAX_REPOSITORY_PATH_BYTES || !is_valid_repo_path(path) {
        return Err(PolicyStoreError::InvalidInput(format!(
            "invalid repository path: use at most {MAX_REPOSITORY_PATH_BYTES} bytes of \
             '/'-separated segments of ASCII letters, digits, '.', '_' or '-', none starting \
             with '.'"
        )));
    }
    if path == "api" || path.starts_with("api/") {
        return Err(PolicyStoreError::InvalidInput(
            "invalid repository path: 'api' is reserved for the admin API".to_owned(),
        ));
    }
    Ok(())
}

/// Validates `pattern` and `groups` as a branch rule and returns it.
fn validate_branch_rule(
    pattern: &str,
    groups: &BTreeSet<String>,
) -> Result<BranchRule, PolicyStoreError> {
    if groups.is_empty() {
        return Err(PolicyStoreError::InvalidInput(
            "a branch rule needs at least one group".to_owned(),
        ));
    }
    for group in groups {
        if let Err(error) = validate_group_name(group) {
            return Err(error);
        }
    }
    let rule = match BranchRule::new(pattern, groups.iter().cloned()) {
        Ok(rule) => rule,
        Err(error) => return Err(PolicyStoreError::InvalidInput(error.to_string())),
    };
    // `BranchRule::new` only validates the glob syntax; compiling also
    // catches globs `globset` rejects, such as an unclosed `[`.
    if let Err(error) = BranchPolicy::compile([rule.clone()]) {
        return Err(PolicyStoreError::InvalidInput(error.to_string()));
    }
    Ok(rule)
}

/// Validates `pattern` and `groups` as a path withholding rule and returns it.
fn validate_path_rule(
    pattern: &str,
    groups: &BTreeSet<String>,
) -> Result<WithholdRule, PolicyStoreError> {
    if groups.is_empty() {
        return Err(PolicyStoreError::InvalidInput(
            "a path rule needs at least one group".to_owned(),
        ));
    }
    for group in groups {
        if let Err(error) = validate_group_name(group) {
            return Err(error);
        }
    }
    if let Err(error) = validate_path_glob(pattern) {
        return Err(PolicyStoreError::InvalidInput(error.to_string()));
    }
    let rule = match WithholdRule::new(pattern, groups.iter().cloned()) {
        Ok(rule) => rule,
        Err(error) => return Err(PolicyStoreError::InvalidInput(error.to_string())),
    };
    if let Err(error) = WithholdPolicy::compile([rule.clone()]) {
        return Err(PolicyStoreError::InvalidInput(error.to_string()));
    }
    Ok(rule)
}

/// Validates `scope` and `groups` for a secret scope.
fn validate_secret_scope(scope: &str, groups: &BTreeSet<String>) -> Result<(), PolicyStoreError> {
    if let Err(error) = validate_scope_name(scope) {
        return Err(error);
    }
    if groups.is_empty() {
        return Err(PolicyStoreError::InvalidInput(
            "a secret scope needs at least one group".to_owned(),
        ));
    }
    for group in groups {
        if let Err(error) = validate_group_name(group) {
            return Err(error);
        }
    }
    Ok(())
}

/// Validates everything [`PolicyStore::create_member`] receives.
fn validate_create_member_request(request: &CreateMemberRequest) -> Result<(), PolicyStoreError> {
    if let Err(error) = validate_member_name(&request.name) {
        return Err(error);
    }
    if let Err(error) = validate_token_label(&request.token_label) {
        return Err(error);
    }
    if let Some(public_key) = &request.public_key
        && let Err(error) = validate_age_public_key(public_key)
    {
        return Err(error);
    }
    for group in &request.groups {
        if let Err(error) = validate_group_name(group) {
            return Err(error);
        }
    }
    Ok(())
}

/// A freshly generated API token and the SHA-256 digest stored for it.
struct GeneratedToken {
    token: SecretString,
    hash: Zeroizing<[u8; 32]>,
}

/// Generates an API token: [`API_TOKEN_PREFIX`] followed by 64 lowercase hex
/// digits encoding 32 bytes from the operating system's CSPRNG.
///
/// Fails with [`PolicyStoreError::Internal`] if no randomness is available.
fn generate_api_token() -> Result<GeneratedToken, PolicyStoreError> {
    const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut random_bytes = Zeroizing::new([0u8; API_TOKEN_RANDOM_BYTES]);
    if let Err(error) = getrandom::fill(random_bytes.as_mut_slice()) {
        return Err(PolicyStoreError::Internal(format!(
            "cannot generate a token: {error}"
        )));
    }
    // Sized up front so pushing never reallocates and leaves a copy behind.
    let mut token = Zeroizing::new(String::with_capacity(
        API_TOKEN_PREFIX.len() + 2 * API_TOKEN_RANDOM_BYTES,
    ));
    token.push_str(API_TOKEN_PREFIX);
    for byte in random_bytes.iter() {
        token.push(char::from(HEX_DIGITS[usize::from(*byte >> 4)]));
        token.push(char::from(HEX_DIGITS[usize::from(*byte & 0x0f)]));
    }
    let hash = sha256_zeroizing(token.as_bytes());
    Ok(GeneratedToken {
        token: SecretString::from(Box::<str>::from(token.as_str())),
        hash,
    })
}

/// Milestone M0 compatibility: one shared token that authenticates as a single
/// admin member, with no branch rules anywhere.
#[derive(Clone, Debug)]
pub struct StaticPolicyStore {
    auth: TokenAuth,
}

impl StaticPolicyStore {
    /// Name of the member every request authenticates as.
    pub const MEMBER_NAME: &'static str = "static-token";

    /// Wraps the shared-token verifier `auth`.
    pub fn new(auth: TokenAuth) -> Self {
        Self { auth }
    }
}

impl PolicyStore for StaticPolicyStore {
    fn authenticate_token_hash<'a>(
        &'a self,
        token_hash: &'a [u8; 32],
    ) -> PolicyStoreFuture<'a, Option<AuthenticatedMember>> {
        let is_valid = self.auth.verify_hash(token_hash);
        Box::pin(async move {
            Ok(is_valid.then(|| AuthenticatedMember {
                id: 0,
                name: Self::MEMBER_NAME.to_owned(),
                is_admin: true,
            }))
        })
    }

    fn load_member_repo_policy<'a>(
        &'a self,
        _member_id: i64,
        repo_key: &'a str,
    ) -> PolicyStoreFuture<'a, MemberRepoPolicy> {
        Box::pin(async move {
            match compile_branch_policy(repo_key, Vec::new()) {
                Ok(branch_policy) => Ok(MemberRepoPolicy {
                    member_groups: BTreeSet::new(),
                    branch_policy,
                    withhold_policy: WithholdPolicy::empty(),
                }),
                Err(error) => Err(error),
            }
        })
    }

    fn record_audit_event<'a>(&'a self, entry: AuditLogEntry) -> PolicyStoreFuture<'a, ()> {
        // M0 has no database, so the log output is the audit trail.
        tracing::info!(
            action = %entry.action,
            target_type = %entry.target_type,
            target_name = %entry.target_name,
            "audit event"
        );
        Box::pin(async { Ok(()) })
    }

    fn list_member_groups<'a>(
        &'a self,
        _member_id: i64,
    ) -> PolicyStoreFuture<'a, BTreeSet<String>> {
        // The shared-token member belongs to no group.
        ready(Ok(BTreeSet::new()))
    }

    fn get_member_public_key<'a>(
        &'a self,
        _member_id: i64,
    ) -> PolicyStoreFuture<'a, Option<String>> {
        // The shared-token member has no stored public key.
        ready(Ok(None))
    }
}

/// One member of a [`MemoryPolicyStore`].
#[derive(Clone, Debug)]
struct MemoryMember {
    id: i64,
    name: String,
    is_admin: bool,
    is_machine: bool,
    public_key: Option<String>,
    is_revoked: bool,
}

/// One token of a [`MemoryPolicyStore`]; only its hash is kept.
#[derive(Clone)]
struct MemoryToken {
    member_id: i64,
    token_hash: Zeroizing<[u8; 32]>,
    is_revoked: bool,
}

/// Everything a [`MemoryPolicyStore`] holds, behind one lock so that each
/// change and its audit entry happen atomically.
#[derive(Default)]
struct MemoryState {
    members: Vec<MemoryMember>,
    tokens: Vec<MemoryToken>,
    group_ids: BTreeMap<String, i64>,
    groups_by_member: BTreeMap<i64, BTreeSet<String>>,
    repository_ids: BTreeMap<String, i64>,
    rules_by_repository: BTreeMap<String, Vec<BranchRule>>,
    path_rules_by_repository: BTreeMap<String, Vec<WithholdRule>>,
    secret_scopes_by_repository: BTreeMap<String, BTreeMap<String, BTreeSet<String>>>,
    audit_log: Vec<AuditLogEntry>,
    /// Highest ID handed out (or inserted), shared by all kinds of rows.
    last_id: i64,
}

impl MemoryState {
    fn next_id(&mut self) -> i64 {
        self.last_id = self.last_id.saturating_add(1);
        self.last_id
    }

    fn member_by_name(&self, name: &str) -> Option<&MemoryMember> {
        self.members.iter().find(|member| member.name == name)
    }

    fn active_member_by_name(&self, name: &str) -> Option<&MemoryMember> {
        self.member_by_name(name)
            .filter(|member| !member.is_revoked)
    }

    fn member_groups(&self, member_id: i64) -> BTreeSet<String> {
        match self.groups_by_member.get(&member_id) {
            Some(groups) => groups.clone(),
            None => BTreeSet::new(),
        }
    }

    fn member_record(&self, member: &MemoryMember) -> MemberRecord {
        MemberRecord {
            id: member.id,
            name: member.name.clone(),
            is_admin: member.is_admin,
            is_machine: member.is_machine,
            public_key: member.public_key.clone(),
            groups: self.member_groups(member.id).into_iter().collect(),
            revoked: member.is_revoked,
        }
    }

    /// Fails with [`PolicyStoreError::NotFound`] naming every group in
    /// `groups` that does not exist.
    fn require_groups(&self, groups: &BTreeSet<String>) -> Result<(), PolicyStoreError> {
        let missing: Vec<&str> = groups
            .iter()
            .filter(|group| !self.group_ids.contains_key(group.as_str()))
            .map(String::as_str)
            .collect();
        if missing.is_empty() {
            Ok(())
        } else {
            Err(missing_groups_error(&missing))
        }
    }

    fn require_repository(&self, repository: &str) -> Result<(), PolicyStoreError> {
        if self.repository_ids.contains_key(repository) {
            Ok(())
        } else {
            Err(repository_not_registered_error())
        }
    }

    /// Generates and stores a token for `member_id`.
    fn issue_token(&mut self, member_id: i64) -> Result<SecretString, PolicyStoreError> {
        let generated = match generate_api_token() {
            Ok(generated) => generated,
            Err(error) => return Err(error),
        };
        self.tokens.push(MemoryToken {
            member_id,
            token_hash: generated.hash,
            is_revoked: false,
        });
        Ok(generated.token)
    }

    /// Creates a member with groups and a first token (all inputs validated
    /// by the caller), mirroring [`insert_member_with_token`].
    fn create_member(
        &mut self,
        request: &CreateMemberRequest,
    ) -> Result<CreatedMember, PolicyStoreError> {
        if self.member_by_name(&request.name).is_some() {
            return Err(member_exists_error());
        }
        if let Err(error) = self.require_groups(&request.groups) {
            return Err(error);
        }
        let member = MemoryMember {
            id: self.next_id(),
            name: request.name.clone(),
            is_admin: request.is_admin,
            is_machine: request.is_machine,
            public_key: request.public_key.clone(),
            is_revoked: false,
        };
        let token = match self.issue_token(member.id) {
            Ok(token) => token,
            Err(error) => return Err(error),
        };
        if !request.groups.is_empty() {
            self.groups_by_member
                .insert(member.id, request.groups.clone());
        }
        let record = self.member_record(&member);
        self.members.push(member);
        Ok(CreatedMember {
            member: record,
            token,
        })
    }
}

/// A [`PolicyStore`] held entirely in memory.
///
/// Clones share one state, so a test can keep a handle and inspect (or
/// change) what a server-owned clone sees and records.
#[derive(Clone, Default)]
pub struct MemoryPolicyStore {
    state: Arc<Mutex<MemoryState>>,
}

impl fmt::Debug for MemoryPolicyStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.setup_state();
        // Token hashes stay out of debug output.
        f.debug_struct("MemoryPolicyStore")
            .field("member_count", &state.members.len())
            .field("groups_by_member", &state.groups_by_member)
            .field("rules_by_repository", &state.rules_by_repository)
            .field("audit_entry_count", &state.audit_log.len())
            .finish()
    }
}

impl MemoryPolicyStore {
    /// Creates an empty store: no members, groups or rules.
    pub fn new() -> Self {
        Self::default()
    }

    /// Locks the state for the setup helpers and debug output, which cannot
    /// report errors: a poisoned lock still yields the state, which every
    /// operation leaves consistent before it can panic.
    fn setup_state(&self) -> MutexGuard<'_, MemoryState> {
        match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Runs `operation` on the locked state; a poisoned lock fails closed.
    fn with_state<T>(
        &self,
        operation: impl FnOnce(&mut MemoryState) -> Result<T, PolicyStoreError>,
    ) -> Result<T, PolicyStoreError> {
        match self.state.lock() {
            Ok(mut state) => operation(&mut state),
            Err(_) => Err(PolicyStoreError::Internal(
                "memory policy store mutex is poisoned".to_owned(),
            )),
        }
    }

    /// Adds the active, non-machine `member`, authenticated by `token` (only
    /// its SHA-256 hash is kept). The caller keeps IDs, names and tokens
    /// unique.
    pub fn insert_member(&mut self, member: AuthenticatedMember, token: &[u8]) {
        let mut state = self.setup_state();
        state.last_id = state.last_id.max(member.id);
        state.tokens.push(MemoryToken {
            member_id: member.id,
            token_hash: sha256_zeroizing(token),
            is_revoked: false,
        });
        state.members.push(MemoryMember {
            id: member.id,
            name: member.name,
            is_admin: member.is_admin,
            is_machine: false,
            public_key: None,
            is_revoked: false,
        });
    }

    /// Makes `member_id` a member of `group`, creating the group if needed.
    pub fn insert_group_membership(&mut self, member_id: i64, group: impl Into<String>) {
        let group = group.into();
        let mut state = self.setup_state();
        // Keep generated member IDs from colliding with this one.
        state.last_id = state.last_id.max(member_id);
        if !state.group_ids.contains_key(&group) {
            let group_id = state.next_id();
            state.group_ids.insert(group.clone(), group_id);
        }
        state
            .groups_by_member
            .entry(member_id)
            .or_default()
            .insert(group);
    }

    /// Attaches `rule` to the repository with canonical key `repo_key`,
    /// registering the repository if needed.
    pub fn insert_branch_rule(&mut self, repo_key: impl Into<String>, rule: BranchRule) {
        let repo_key = repo_key.into();
        let mut state = self.setup_state();
        if !state.repository_ids.contains_key(&repo_key) {
            let repository_id = state.next_id();
            state.repository_ids.insert(repo_key.clone(), repository_id);
        }
        state
            .rules_by_repository
            .entry(repo_key)
            .or_default()
            .push(rule);
    }

    /// Attaches path withholding `rule` to the repository with canonical key
    /// `repo_key`, registering the repository if needed.
    pub fn insert_path_rule(&mut self, repo_key: impl Into<String>, rule: WithholdRule) {
        let repo_key = repo_key.into();
        let mut state = self.setup_state();
        if !state.repository_ids.contains_key(&repo_key) {
            let repository_id = state.next_id();
            state.repository_ids.insert(repo_key.clone(), repository_id);
        }
        state
            .path_rules_by_repository
            .entry(repo_key)
            .or_default()
            .push(rule);
    }

    /// Returns a copy of every audit entry recorded so far (by this store or
    /// any clone of it), oldest first. Reading only copies the log, so a
    /// poisoned lock still returns what was recorded.
    pub fn audit_entries(&self) -> Vec<AuditLogEntry> {
        self.setup_state().audit_log.clone()
    }
}

impl PolicyStore for MemoryPolicyStore {
    fn authenticate_token_hash<'a>(
        &'a self,
        token_hash: &'a [u8; 32],
    ) -> PolicyStoreFuture<'a, Option<AuthenticatedMember>> {
        ready(self.with_state(|state| {
            // Compare against every token, even after a match, so the time
            // taken does not reveal which (or whether an early) entry matched.
            let mut matched_member_id = None;
            for token in &state.tokens {
                let is_match = bool::from(token.token_hash.as_slice().ct_eq(token_hash.as_slice()));
                if is_match && !token.is_revoked && matched_member_id.is_none() {
                    matched_member_id = Some(token.member_id);
                }
            }
            let member = matched_member_id.and_then(|member_id| {
                state
                    .members
                    .iter()
                    .find(|member| member.id == member_id && !member.is_revoked)
            });
            Ok(member.map(|member| AuthenticatedMember {
                id: member.id,
                name: member.name.clone(),
                is_admin: member.is_admin,
            }))
        }))
    }

    fn load_member_repo_policy<'a>(
        &'a self,
        member_id: i64,
        repo_key: &'a str,
    ) -> PolicyStoreFuture<'a, MemberRepoPolicy> {
        ready(self.with_state(|state| {
            let rules = match state.rules_by_repository.get(repo_key) {
                Some(rules) => rules.clone(),
                None => Vec::new(),
            };
            let path_rules: Vec<(String, BTreeSet<String>)> =
                match state.path_rules_by_repository.get(repo_key) {
                    Some(rules) => rules
                        .iter()
                        .map(|rule| (rule.pattern.clone(), rule.allowed_groups.clone()))
                        .collect(),
                    None => Vec::new(),
                };
            let branch_policy = match compile_branch_policy(repo_key, rules) {
                Ok(branch_policy) => branch_policy,
                Err(error) => return Err(error),
            };
            let withhold_policy = match compile_withhold_policy(path_rules) {
                Ok(withhold_policy) => withhold_policy,
                Err(error) => return Err(error),
            };
            Ok(MemberRepoPolicy {
                member_groups: state.member_groups(member_id),
                branch_policy,
                withhold_policy,
            })
        }))
    }

    fn record_audit_event<'a>(&'a self, entry: AuditLogEntry) -> PolicyStoreFuture<'a, ()> {
        ready(self.with_state(|state| {
            state.audit_log.push(entry);
            Ok(())
        }))
    }

    fn list_member_groups<'a>(&'a self, member_id: i64) -> PolicyStoreFuture<'a, BTreeSet<String>> {
        ready(self.with_state(|state| Ok(state.member_groups(member_id))))
    }

    fn register_repository<'a>(
        &'a self,
        actor_member_id: Option<i64>,
        repo_path: &'a str,
    ) -> PolicyStoreFuture<'a, RegisterRepositoryResult> {
        if let Err(error) = validate_repository_path(repo_path) {
            return ready(Err(error));
        }
        ready(self.with_state(|state| {
            if let Some(id) = state.repository_ids.get(repo_path) {
                return Ok(RegisterRepositoryResult {
                    repository: RepositoryRecord {
                        id: *id,
                        path: repo_path.to_owned(),
                    },
                    created: false,
                });
            }
            let id = state.next_id();
            state.repository_ids.insert(repo_path.to_owned(), id);
            state
                .audit_log
                .push(register_repository_audit(actor_member_id, repo_path));
            Ok(RegisterRepositoryResult {
                repository: RepositoryRecord {
                    id,
                    path: repo_path.to_owned(),
                },
                created: true,
            })
        }))
    }

    fn list_repositories<'a>(&'a self) -> PolicyStoreFuture<'a, Vec<RepositoryRecord>> {
        ready(self.with_state(|state| {
            Ok(state
                .repository_ids
                .iter()
                .map(|(path, id)| RepositoryRecord {
                    id: *id,
                    path: path.clone(),
                })
                .collect())
        }))
    }

    fn create_group<'a>(
        &'a self,
        actor_member_id: Option<i64>,
        name: &'a str,
    ) -> PolicyStoreFuture<'a, GroupRecord> {
        if let Err(error) = validate_group_name(name) {
            return ready(Err(error));
        }
        ready(self.with_state(|state| {
            if state.group_ids.contains_key(name) {
                return Err(group_exists_error());
            }
            let id = state.next_id();
            state.group_ids.insert(name.to_owned(), id);
            state
                .audit_log
                .push(create_group_audit(actor_member_id, name));
            Ok(GroupRecord {
                id,
                name: name.to_owned(),
            })
        }))
    }

    fn list_groups<'a>(&'a self) -> PolicyStoreFuture<'a, Vec<GroupWithMembers>> {
        ready(self.with_state(|state| {
            let groups = state
                .group_ids
                .iter()
                .map(|(name, id)| {
                    let mut members: Vec<String> = state
                        .members
                        .iter()
                        .filter(|member| {
                            !member.is_revoked
                                && state
                                    .groups_by_member
                                    .get(&member.id)
                                    .is_some_and(|groups| groups.contains(name))
                        })
                        .map(|member| member.name.clone())
                        .collect();
                    members.sort();
                    GroupWithMembers {
                        id: *id,
                        name: name.clone(),
                        members,
                    }
                })
                .collect();
            Ok(groups)
        }))
    }

    fn add_group_member<'a>(
        &'a self,
        actor_member_id: Option<i64>,
        group_name: &'a str,
        member_name: &'a str,
    ) -> PolicyStoreFuture<'a, GroupMembershipChange> {
        if let Err(error) = validate_group_name(group_name) {
            return ready(Err(error));
        }
        if let Err(error) = validate_member_name(member_name) {
            return ready(Err(error));
        }
        ready(self.with_state(|state| {
            if !state.group_ids.contains_key(group_name) {
                return Err(group_not_found_error());
            }
            let Some(member_id) = state
                .active_member_by_name(member_name)
                .map(|member| member.id)
            else {
                return Err(member_not_found_error());
            };
            let changed = state
                .groups_by_member
                .entry(member_id)
                .or_default()
                .insert(group_name.to_owned());
            if changed {
                state.audit_log.push(group_membership_audit(
                    actor_member_id,
                    "group.member_add",
                    group_name,
                    member_name,
                ));
            }
            Ok(GroupMembershipChange {
                group: group_name.to_owned(),
                member: member_name.to_owned(),
                changed,
            })
        }))
    }

    fn remove_group_member<'a>(
        &'a self,
        actor_member_id: Option<i64>,
        group_name: &'a str,
        member_name: &'a str,
    ) -> PolicyStoreFuture<'a, GroupMembershipChange> {
        if let Err(error) = validate_group_name(group_name) {
            return ready(Err(error));
        }
        if let Err(error) = validate_member_name(member_name) {
            return ready(Err(error));
        }
        ready(self.with_state(|state| {
            if !state.group_ids.contains_key(group_name) {
                return Err(group_not_found_error());
            }
            let Some(member_id) = state.member_by_name(member_name).map(|member| member.id) else {
                return Err(member_not_found_error());
            };
            let changed = match state.groups_by_member.get_mut(&member_id) {
                Some(groups) => groups.remove(group_name),
                None => false,
            };
            if changed {
                state.audit_log.push(group_membership_audit(
                    actor_member_id,
                    "group.member_remove",
                    group_name,
                    member_name,
                ));
            }
            Ok(GroupMembershipChange {
                group: group_name.to_owned(),
                member: member_name.to_owned(),
                changed,
            })
        }))
    }

    fn create_member<'a>(
        &'a self,
        actor_member_id: Option<i64>,
        request: CreateMemberRequest,
    ) -> PolicyStoreFuture<'a, CreatedMember> {
        if let Err(error) = validate_create_member_request(&request) {
            return ready(Err(error));
        }
        ready(self.with_state(|state| {
            let created = match state.create_member(&request) {
                Ok(created) => created,
                Err(error) => return Err(error),
            };
            state
                .audit_log
                .push(create_member_audit(actor_member_id, &request));
            Ok(created)
        }))
    }

    fn issue_member_token<'a>(
        &'a self,
        actor_member_id: Option<i64>,
        member_name: &'a str,
        label: &'a str,
    ) -> PolicyStoreFuture<'a, IssuedToken> {
        if let Err(error) = validate_member_name(member_name) {
            return ready(Err(error));
        }
        if let Err(error) = validate_token_label(label) {
            return ready(Err(error));
        }
        ready(self.with_state(|state| {
            let Some(member_id) = state
                .active_member_by_name(member_name)
                .map(|member| member.id)
            else {
                return Err(member_not_found_error());
            };
            let token = match state.issue_token(member_id) {
                Ok(token) => token,
                Err(error) => return Err(error),
            };
            state
                .audit_log
                .push(issue_token_audit(actor_member_id, member_name, label));
            Ok(IssuedToken {
                member: member_name.to_owned(),
                label: label.to_owned(),
                token,
            })
        }))
    }

    fn revoke_member<'a>(
        &'a self,
        actor_member_id: Option<i64>,
        member_name: &'a str,
    ) -> PolicyStoreFuture<'a, RevokeMemberResult> {
        if let Err(error) = validate_member_name(member_name) {
            return ready(Err(error));
        }
        ready(self.with_state(|state| {
            let Some(member) = state.member_by_name(member_name).cloned() else {
                return Err(member_not_found_error());
            };
            if member.is_revoked {
                return Ok(RevokeMemberResult {
                    name: member_name.to_owned(),
                    revoked: false,
                });
            }
            let active_admin_count = state
                .members
                .iter()
                .filter(|candidate| candidate.is_admin && !candidate.is_revoked)
                .count();
            if member.is_admin && active_admin_count <= 1 {
                return Err(last_admin_error());
            }
            for candidate in &mut state.members {
                if candidate.id == member.id {
                    candidate.is_revoked = true;
                }
            }
            let mut revoked_token_count: u64 = 0;
            for token in &mut state.tokens {
                if token.member_id == member.id && !token.is_revoked {
                    token.is_revoked = true;
                    revoked_token_count += 1;
                }
            }
            state.audit_log.push(revoke_member_audit(
                actor_member_id,
                member_name,
                revoked_token_count,
            ));
            Ok(RevokeMemberResult {
                name: member_name.to_owned(),
                revoked: true,
            })
        }))
    }

    fn list_members<'a>(
        &'a self,
        include_revoked: bool,
    ) -> PolicyStoreFuture<'a, Vec<MemberRecord>> {
        ready(self.with_state(|state| {
            let mut members: Vec<MemberRecord> = state
                .members
                .iter()
                .filter(|member| include_revoked || !member.is_revoked)
                .map(|member| state.member_record(member))
                .collect();
            members.sort_by(|left, right| left.name.cmp(&right.name));
            Ok(members)
        }))
    }

    fn set_branch_rule<'a>(
        &'a self,
        actor_member_id: Option<i64>,
        repository: &'a str,
        pattern: &'a str,
        groups: BTreeSet<String>,
    ) -> PolicyStoreFuture<'a, BranchRuleRecord> {
        if let Err(error) = validate_repository_path(repository) {
            return ready(Err(error));
        }
        let rule = match validate_branch_rule(pattern, &groups) {
            Ok(rule) => rule,
            Err(error) => return ready(Err(error)),
        };
        ready(self.with_state(|state| {
            if let Err(error) = state.require_repository(repository) {
                return Err(error);
            }
            if let Err(error) = state.require_groups(&groups) {
                return Err(error);
            }
            let rules = state
                .rules_by_repository
                .entry(repository.to_owned())
                .or_default();
            rules.retain(|existing| existing.pattern != pattern);
            rules.push(rule);
            let record = BranchRuleRecord {
                repository: repository.to_owned(),
                pattern: pattern.to_owned(),
                groups: groups.into_iter().collect(),
            };
            state
                .audit_log
                .push(set_branch_rule_audit(actor_member_id, &record));
            Ok(record)
        }))
    }

    fn list_branch_rules<'a>(
        &'a self,
        repository: &'a str,
    ) -> PolicyStoreFuture<'a, Vec<BranchRuleRecord>> {
        if let Err(error) = validate_repository_path(repository) {
            return ready(Err(error));
        }
        ready(self.with_state(|state| {
            if let Err(error) = state.require_repository(repository) {
                return Err(error);
            }
            let mut rules: Vec<BranchRuleRecord> = match state.rules_by_repository.get(repository) {
                Some(rules) => rules
                    .iter()
                    .map(|rule| BranchRuleRecord {
                        repository: repository.to_owned(),
                        pattern: rule.pattern.clone(),
                        groups: rule.allowed_groups.iter().cloned().collect(),
                    })
                    .collect(),
                None => Vec::new(),
            };
            rules.sort_by(|left, right| left.pattern.cmp(&right.pattern));
            Ok(rules)
        }))
    }

    fn remove_branch_rule<'a>(
        &'a self,
        actor_member_id: Option<i64>,
        repository: &'a str,
        pattern: &'a str,
    ) -> PolicyStoreFuture<'a, bool> {
        if let Err(error) = validate_repository_path(repository) {
            return ready(Err(error));
        }
        ready(self.with_state(|state| {
            if let Err(error) = state.require_repository(repository) {
                return Err(error);
            }
            let removed = match state.rules_by_repository.get_mut(repository) {
                Some(rules) => {
                    let count_before = rules.len();
                    rules.retain(|rule| rule.pattern != pattern);
                    rules.len() != count_before
                }
                None => false,
            };
            if !removed {
                return Err(branch_rule_not_found_error());
            }
            state.audit_log.push(remove_branch_rule_audit(
                actor_member_id,
                repository,
                pattern,
            ));
            Ok(true)
        }))
    }

    fn set_path_rule<'a>(
        &'a self,
        actor_member_id: Option<i64>,
        repository: &'a str,
        pattern: &'a str,
        groups: BTreeSet<String>,
    ) -> PolicyStoreFuture<'a, PathRuleRecord> {
        if let Err(error) = validate_repository_path(repository) {
            return ready(Err(error));
        }
        let rule = match validate_path_rule(pattern, &groups) {
            Ok(rule) => rule,
            Err(error) => return ready(Err(error)),
        };
        ready(self.with_state(|state| {
            if let Err(error) = state.require_repository(repository) {
                return Err(error);
            }
            if let Err(error) = state.require_groups(&groups) {
                return Err(error);
            }
            let rules = state
                .path_rules_by_repository
                .entry(repository.to_owned())
                .or_default();
            let exists = rules.iter().any(|existing| existing.pattern == pattern);
            if !exists && rules.len() >= MAX_PATH_RULES {
                return Err(too_many_path_rules_error());
            }
            rules.retain(|existing| existing.pattern != pattern);
            rules.push(rule);
            let record = PathRuleRecord {
                repository: repository.to_owned(),
                pattern: pattern.to_owned(),
                groups: groups.into_iter().collect(),
            };
            state
                .audit_log
                .push(set_path_rule_audit(actor_member_id, &record));
            Ok(record)
        }))
    }

    fn list_path_rules<'a>(
        &'a self,
        repository: &'a str,
    ) -> PolicyStoreFuture<'a, Vec<PathRuleRecord>> {
        if let Err(error) = validate_repository_path(repository) {
            return ready(Err(error));
        }
        ready(self.with_state(|state| {
            if let Err(error) = state.require_repository(repository) {
                return Err(error);
            }
            let mut rules: Vec<PathRuleRecord> =
                match state.path_rules_by_repository.get(repository) {
                    Some(rules) => rules
                        .iter()
                        .map(|rule| PathRuleRecord {
                            repository: repository.to_owned(),
                            pattern: rule.pattern.clone(),
                            groups: rule.allowed_groups.iter().cloned().collect(),
                        })
                        .collect(),
                    None => Vec::new(),
                };
            rules.sort_by(|left, right| left.pattern.cmp(&right.pattern));
            Ok(rules)
        }))
    }

    fn remove_path_rule<'a>(
        &'a self,
        actor_member_id: Option<i64>,
        repository: &'a str,
        pattern: &'a str,
    ) -> PolicyStoreFuture<'a, bool> {
        if let Err(error) = validate_repository_path(repository) {
            return ready(Err(error));
        }
        ready(self.with_state(|state| {
            if let Err(error) = state.require_repository(repository) {
                return Err(error);
            }
            let removed = match state.path_rules_by_repository.get_mut(repository) {
                Some(rules) => {
                    let count_before = rules.len();
                    rules.retain(|rule| rule.pattern != pattern);
                    rules.len() != count_before
                }
                None => false,
            };
            if !removed {
                return Err(path_rule_not_found_error());
            }
            state
                .audit_log
                .push(remove_path_rule_audit(actor_member_id, repository, pattern));
            Ok(true)
        }))
    }

    fn bootstrap_admin<'a>(
        &'a self,
        name: &'a str,
        token_label: &'a str,
    ) -> PolicyStoreFuture<'a, CreatedMember> {
        let request = bootstrap_admin_request(name, token_label);
        if let Err(error) = validate_create_member_request(&request) {
            return ready(Err(error));
        }
        ready(self.with_state(|state| {
            if state
                .members
                .iter()
                .any(|member| member.is_admin && !member.is_revoked)
            {
                return Err(admin_exists_error());
            }
            let created = match state.create_member(&request) {
                Ok(created) => created,
                Err(error) => return Err(error),
            };
            state
                .audit_log
                .push(bootstrap_admin_audit(name, token_label));
            Ok(created)
        }))
    }

    fn get_member_public_key<'a>(
        &'a self,
        member_id: i64,
    ) -> PolicyStoreFuture<'a, Option<String>> {
        ready(self.with_state(|state| {
            Ok(state
                .members
                .iter()
                .find(|member| member.id == member_id && !member.is_revoked)
                .and_then(|member| member.public_key.clone()))
        }))
    }

    fn set_member_public_key<'a>(
        &'a self,
        actor_member_id: Option<i64>,
        member_name: &'a str,
        public_key: &'a str,
    ) -> PolicyStoreFuture<'a, MemberPublicKeyRecord> {
        if let Err(error) = validate_member_name(member_name) {
            return ready(Err(error));
        }
        if let Err(error) = validate_age_public_key(public_key) {
            return ready(Err(error));
        }
        ready(self.with_state(|state| {
            let Some(member) = state
                .members
                .iter_mut()
                .find(|member| member.name == member_name && !member.is_revoked)
            else {
                return Err(member_not_found_error());
            };
            member.public_key = Some(public_key.to_owned());
            state.audit_log.push(set_member_public_key_audit(
                actor_member_id,
                member_name,
                public_key,
            ));
            Ok(MemberPublicKeyRecord {
                name: member_name.to_owned(),
                public_key: public_key.to_owned(),
            })
        }))
    }

    fn set_secret_scope<'a>(
        &'a self,
        actor_member_id: Option<i64>,
        repository: &'a str,
        scope: &'a str,
        groups: BTreeSet<String>,
    ) -> PolicyStoreFuture<'a, SecretScopeRecord> {
        if let Err(error) = validate_repository_path(repository) {
            return ready(Err(error));
        }
        if let Err(error) = validate_secret_scope(scope, &groups) {
            return ready(Err(error));
        }
        ready(self.with_state(|state| {
            if let Err(error) = state.require_repository(repository) {
                return Err(error);
            }
            if let Err(error) = state.require_groups(&groups) {
                return Err(error);
            }
            state
                .secret_scopes_by_repository
                .entry(repository.to_owned())
                .or_default()
                .insert(scope.to_owned(), groups.clone());
            let record = SecretScopeRecord {
                repository: repository.to_owned(),
                scope: scope.to_owned(),
                groups: groups.into_iter().collect(),
            };
            state
                .audit_log
                .push(set_secret_scope_audit(actor_member_id, &record));
            Ok(record)
        }))
    }

    fn list_secret_scopes<'a>(
        &'a self,
        repository: &'a str,
    ) -> PolicyStoreFuture<'a, Vec<SecretScopeRecord>> {
        if let Err(error) = validate_repository_path(repository) {
            return ready(Err(error));
        }
        ready(self.with_state(|state| {
            if let Err(error) = state.require_repository(repository) {
                return Err(error);
            }
            let scopes = match state.secret_scopes_by_repository.get(repository) {
                Some(scopes) => scopes
                    .iter()
                    .map(|(scope, groups)| SecretScopeRecord {
                        repository: repository.to_owned(),
                        scope: scope.clone(),
                        groups: groups.iter().cloned().collect(),
                    })
                    .collect(),
                None => Vec::new(),
            };
            Ok(scopes)
        }))
    }

    fn remove_secret_scope<'a>(
        &'a self,
        actor_member_id: Option<i64>,
        repository: &'a str,
        scope: &'a str,
    ) -> PolicyStoreFuture<'a, bool> {
        if let Err(error) = validate_repository_path(repository) {
            return ready(Err(error));
        }
        if let Err(error) = validate_scope_name(scope) {
            return ready(Err(error));
        }
        ready(self.with_state(|state| {
            if let Err(error) = state.require_repository(repository) {
                return Err(error);
            }
            let removed = match state.secret_scopes_by_repository.get_mut(repository) {
                Some(scopes) => scopes.remove(scope).is_some(),
                None => false,
            };
            if !removed {
                return Err(secret_scope_not_found_error());
            }
            state.audit_log.push(remove_secret_scope_audit(
                actor_member_id,
                repository,
                scope,
            ));
            Ok(true)
        }))
    }

    fn resolve_secret_scope_recipients<'a>(
        &'a self,
        repository: &'a str,
        scope: &'a str,
    ) -> PolicyStoreFuture<'a, ScopeRecipientsRecord> {
        if let Err(error) = validate_repository_path(repository) {
            return ready(Err(error));
        }
        if let Err(error) = validate_scope_name(scope) {
            return ready(Err(error));
        }
        ready(self.with_state(|state| {
            if let Err(error) = state.require_repository(repository) {
                return Err(error);
            }
            let Some(scope_groups) = state
                .secret_scopes_by_repository
                .get(repository)
                .and_then(|scopes| scopes.get(scope))
            else {
                return Err(secret_scope_not_found_error());
            };
            let groups: Vec<String> = scope_groups.iter().cloned().collect();
            let mut matching_members: Vec<&MemoryMember> = state
                .members
                .iter()
                .filter(|member| {
                    !member.is_revoked
                        && state
                            .groups_by_member
                            .get(&member.id)
                            .is_some_and(|member_groups| !member_groups.is_disjoint(scope_groups))
                })
                .collect();
            matching_members.sort_by(|left, right| left.name.cmp(&right.name));
            let (recipients, members_without_key) = partition_recipients(
                matching_members
                    .into_iter()
                    .map(|member| (member.name.clone(), member.public_key.clone())),
            );
            Ok(ScopeRecipientsRecord {
                repository: repository.to_owned(),
                scope: scope.to_owned(),
                groups,
                recipients,
                members_without_key,
            })
        }))
    }

    fn resolve_group_recipients<'a>(
        &'a self,
        group: &'a str,
    ) -> PolicyStoreFuture<'a, GroupRecipientsRecord> {
        if let Err(error) = validate_group_name(group) {
            return ready(Err(error));
        }
        ready(self.with_state(|state| {
            if !state.group_ids.contains_key(group) {
                return Err(group_not_found_error());
            }
            let mut matching_members: Vec<&MemoryMember> = state
                .members
                .iter()
                .filter(|member| {
                    !member.is_revoked
                        && state
                            .groups_by_member
                            .get(&member.id)
                            .is_some_and(|member_groups| member_groups.contains(group))
                })
                .collect();
            matching_members.sort_by(|left, right| left.name.cmp(&right.name));
            let (recipients, members_without_key) = partition_recipients(
                matching_members
                    .into_iter()
                    .map(|member| (member.name.clone(), member.public_key.clone())),
            );
            Ok(GroupRecipientsRecord {
                group: group.to_owned(),
                recipients,
                members_without_key,
            })
        }))
    }
}

/// Splits member `(name, public_key)` pairs (already sorted by name) into
/// keyed recipients and members without a key.
fn partition_recipients(
    members: impl IntoIterator<Item = (String, Option<String>)>,
) -> (Vec<ScopeRecipient>, Vec<String>) {
    let mut recipients = Vec::new();
    let mut members_without_key = Vec::new();
    for (member_name, public_key) in members {
        match public_key {
            Some(public_key) => recipients.push(ScopeRecipient {
                member: member_name,
                public_key,
            }),
            None => members_without_key.push(member_name),
        }
    }
    (recipients, members_without_key)
}

/// The request [`PolicyStore::bootstrap_admin`] turns into a member.
fn bootstrap_admin_request(name: &str, token_label: &str) -> CreateMemberRequest {
    CreateMemberRequest {
        name: name.to_owned(),
        is_admin: true,
        is_machine: false,
        public_key: None,
        groups: BTreeSet::new(),
        token_label: token_label.to_owned(),
    }
}

fn member_not_found_error() -> PolicyStoreError {
    PolicyStoreError::NotFound("member not found".to_owned())
}

fn group_not_found_error() -> PolicyStoreError {
    PolicyStoreError::NotFound("group not found".to_owned())
}

fn missing_groups_error(missing: &[&str]) -> PolicyStoreError {
    // Group names are validated, so echoing them cannot inject anything.
    PolicyStoreError::NotFound(format!("group not found: {}", missing.join(", ")))
}

fn repository_not_registered_error() -> PolicyStoreError {
    PolicyStoreError::NotFound("repository is not registered".to_owned())
}

fn branch_rule_not_found_error() -> PolicyStoreError {
    PolicyStoreError::NotFound("branch rule not found".to_owned())
}

fn path_rule_not_found_error() -> PolicyStoreError {
    PolicyStoreError::NotFound("path rule not found".to_owned())
}

fn too_many_path_rules_error() -> PolicyStoreError {
    PolicyStoreError::InvalidInput(format!(
        "too many path rules for repository (maximum is {MAX_PATH_RULES})"
    ))
}

fn secret_scope_not_found_error() -> PolicyStoreError {
    PolicyStoreError::NotFound("secret scope not found".to_owned())
}

fn member_exists_error() -> PolicyStoreError {
    PolicyStoreError::Conflict("member already exists".to_owned())
}

fn group_exists_error() -> PolicyStoreError {
    PolicyStoreError::Conflict("group already exists".to_owned())
}

fn admin_exists_error() -> PolicyStoreError {
    PolicyStoreError::Conflict("an active admin already exists".to_owned())
}

fn last_admin_error() -> PolicyStoreError {
    PolicyStoreError::Conflict("cannot revoke the last active admin".to_owned())
}

fn register_repository_audit(actor_member_id: Option<i64>, repo_path: &str) -> AuditLogEntry {
    AuditLogEntry::new(
        actor_member_id,
        "repository.register",
        "repository",
        repo_path.to_owned(),
        serde_json::json!({}),
    )
}

fn create_group_audit(actor_member_id: Option<i64>, name: &str) -> AuditLogEntry {
    AuditLogEntry::new(
        actor_member_id,
        "group.create",
        "group",
        name.to_owned(),
        serde_json::json!({}),
    )
}

fn group_membership_audit(
    actor_member_id: Option<i64>,
    action: &str,
    group_name: &str,
    member_name: &str,
) -> AuditLogEntry {
    AuditLogEntry::new(
        actor_member_id,
        action,
        "group_membership",
        format!("{group_name}:{member_name}"),
        serde_json::json!({ "group": group_name, "member": member_name }),
    )
}

fn create_member_audit(
    actor_member_id: Option<i64>,
    request: &CreateMemberRequest,
) -> AuditLogEntry {
    AuditLogEntry::new(
        actor_member_id,
        "member.grant",
        "member",
        request.name.clone(),
        serde_json::json!({
            "is_admin": request.is_admin,
            "is_machine": request.is_machine,
            "has_public_key": request.public_key.is_some(),
            "groups": request.groups,
            "token_label": request.token_label,
        }),
    )
}

fn set_member_public_key_audit(
    actor_member_id: Option<i64>,
    member_name: &str,
    public_key: &str,
) -> AuditLogEntry {
    AuditLogEntry::new(
        actor_member_id,
        "member.public_key_set",
        "member",
        member_name.to_owned(),
        serde_json::json!({ "public_key": public_key }),
    )
}

fn issue_token_audit(
    actor_member_id: Option<i64>,
    member_name: &str,
    label: &str,
) -> AuditLogEntry {
    AuditLogEntry::new(
        actor_member_id,
        "member.token_issue",
        "member",
        member_name.to_owned(),
        serde_json::json!({ "token_label": label }),
    )
}

fn revoke_member_audit(
    actor_member_id: Option<i64>,
    member_name: &str,
    revoked_token_count: u64,
) -> AuditLogEntry {
    AuditLogEntry::new(
        actor_member_id,
        "member.revoke",
        "member",
        member_name.to_owned(),
        serde_json::json!({ "revoked_token_count": revoked_token_count }),
    )
}

fn set_branch_rule_audit(actor_member_id: Option<i64>, record: &BranchRuleRecord) -> AuditLogEntry {
    AuditLogEntry::new(
        actor_member_id,
        "branch_rule.set",
        "branch_rule",
        format!("{}:{}", record.repository, record.pattern),
        serde_json::json!({
            "repository": record.repository,
            "pattern": record.pattern,
            "groups": record.groups,
        }),
    )
}

fn remove_branch_rule_audit(
    actor_member_id: Option<i64>,
    repository: &str,
    pattern: &str,
) -> AuditLogEntry {
    AuditLogEntry::new(
        actor_member_id,
        "branch_rule.remove",
        "branch_rule",
        format!("{repository}:{pattern}"),
        serde_json::json!({ "repository": repository, "pattern": pattern }),
    )
}

fn set_path_rule_audit(actor_member_id: Option<i64>, record: &PathRuleRecord) -> AuditLogEntry {
    AuditLogEntry::new(
        actor_member_id,
        "path_rule.set",
        "path_rule",
        format!("{}:{}", record.repository, record.pattern),
        serde_json::json!({
            "repository": record.repository,
            "pattern": record.pattern,
            "groups": record.groups,
        }),
    )
}

fn remove_path_rule_audit(
    actor_member_id: Option<i64>,
    repository: &str,
    pattern: &str,
) -> AuditLogEntry {
    AuditLogEntry::new(
        actor_member_id,
        "path_rule.remove",
        "path_rule",
        format!("{repository}:{pattern}"),
        serde_json::json!({ "repository": repository, "pattern": pattern }),
    )
}

fn set_secret_scope_audit(
    actor_member_id: Option<i64>,
    record: &SecretScopeRecord,
) -> AuditLogEntry {
    AuditLogEntry::new(
        actor_member_id,
        "secret_scope.set",
        "secret_scope",
        format!("{}:{}", record.repository, record.scope),
        serde_json::json!({
            "repository": record.repository,
            "scope": record.scope,
            "groups": record.groups,
        }),
    )
}

fn remove_secret_scope_audit(
    actor_member_id: Option<i64>,
    repository: &str,
    scope: &str,
) -> AuditLogEntry {
    AuditLogEntry::new(
        actor_member_id,
        "secret_scope.remove",
        "secret_scope",
        format!("{repository}:{scope}"),
        serde_json::json!({ "repository": repository, "scope": scope }),
    )
}

fn bootstrap_admin_audit(name: &str, token_label: &str) -> AuditLogEntry {
    // Bootstrapping runs from the command line, not as any member.
    AuditLogEntry::new(
        None,
        "member.bootstrap_admin",
        "member",
        name.to_owned(),
        serde_json::json!({ "token_label": token_label }),
    )
}

/// A [`PolicyStore`] backed by PostgreSQL (schema in `migrations/`).
#[derive(Clone)]
pub struct PgPolicyStore {
    pool: PgPool,
}

impl fmt::Debug for PgPolicyStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The pool's connect options hold the database password.
        f.debug_struct("PgPolicyStore").finish_non_exhaustive()
    }
}

impl PgPolicyStore {
    /// Connects a pool to the PostgreSQL server at `database_url`
    /// (e.g. `postgres://user:password@host/db`).
    ///
    /// Fails if the URL cannot be parsed or the server cannot be reached.
    /// Errors never repeat the URL, so the password cannot leak into logs.
    pub async fn connect(database_url: &str) -> Result<Self, PolicyStoreError> {
        // sqlx's parse errors name the offending component, never the URL.
        let connect_options = match PgConnectOptions::from_str(database_url) {
            Ok(connect_options) => connect_options,
            Err(error) => return Err(PolicyStoreError::Database(error)),
        };
        match PgPoolOptions::new().connect_with(connect_options).await {
            Ok(pool) => Ok(Self::from_pool(pool)),
            Err(error) => Err(PolicyStoreError::Database(error)),
        }
    }

    /// Wraps an existing pool.
    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Applies any pending migrations embedded from `migrations/`.
    pub async fn migrate(&self) -> Result<(), PolicyStoreError> {
        match sqlx::migrate!("./migrations").run(&self.pool).await {
            Ok(()) => Ok(()),
            Err(error) => Err(PolicyStoreError::Database(sqlx::Error::from(error))),
        }
    }

    async fn begin(&self) -> Result<Transaction<'static, Postgres>, PolicyStoreError> {
        match self.pool.begin().await {
            Ok(transaction) => Ok(transaction),
            Err(error) => Err(PolicyStoreError::Database(error)),
        }
    }
}

/// Inserts one `audit_log` row.
const INSERT_AUDIT_SQL: &str = "INSERT INTO audit_log \
     (actor_member_id, action, target_type, target_name, details) \
     VALUES ($1, $2, $3, $4, $5)";

/// Appends `entry` to the audit log inside the caller's transaction.
async fn insert_audit_entry(
    connection: &mut PgConnection,
    entry: AuditLogEntry,
) -> Result<(), PolicyStoreError> {
    let result = sqlx::query(INSERT_AUDIT_SQL)
        .bind(entry.actor_member_id)
        .bind(entry.action)
        .bind(entry.target_type)
        .bind(entry.target_name)
        .bind(sqlx::types::Json(entry.details))
        .execute(connection)
        .await;
    match result {
        Ok(_) => Ok(()),
        Err(error) => Err(PolicyStoreError::Database(error)),
    }
}

async fn commit(transaction: Transaction<'static, Postgres>) -> Result<(), PolicyStoreError> {
    match transaction.commit().await {
        Ok(()) => Ok(()),
        Err(error) => Err(PolicyStoreError::Database(error)),
    }
}

/// Returns the IDs of `groups`, or [`PolicyStoreError::NotFound`] naming the
/// ones that do not exist. Locks the rows `FOR SHARE` so they cannot vanish
/// before the caller's transaction commits.
async fn find_group_ids(
    connection: &mut PgConnection,
    groups: &BTreeSet<String>,
) -> Result<Vec<i64>, PolicyStoreError> {
    let names: Vec<String> = groups.iter().cloned().collect();
    let rows = sqlx::query_as::<_, (i64, String)>(
        "SELECT id, name FROM groups WHERE name = ANY($1) FOR SHARE",
    )
    .bind(names)
    .fetch_all(connection)
    .await;
    let rows = match rows {
        Ok(rows) => rows,
        Err(error) => return Err(PolicyStoreError::Database(error)),
    };
    let found: BTreeSet<&str> = rows.iter().map(|(_, name)| name.as_str()).collect();
    let missing: Vec<&str> = groups
        .iter()
        .map(String::as_str)
        .filter(|group| !found.contains(group))
        .collect();
    if !missing.is_empty() {
        return Err(missing_groups_error(&missing));
    }
    Ok(rows.into_iter().map(|(id, _)| id).collect())
}

/// Looks up the ID of the group `name`, locked `FOR SHARE`.
async fn find_group_id(connection: &mut PgConnection, name: &str) -> Result<i64, PolicyStoreError> {
    let row = sqlx::query_scalar::<_, i64>("SELECT id FROM groups WHERE name = $1 FOR SHARE")
        .bind(name)
        .fetch_optional(connection)
        .await;
    match row {
        Ok(Some(id)) => Ok(id),
        Ok(None) => Err(group_not_found_error()),
        Err(error) => Err(PolicyStoreError::Database(error)),
    }
}

/// Looks up the ID of the member `name` (only an active one if
/// `active_only`), locked `FOR SHARE` so a concurrent revocation waits.
async fn find_member_id(
    connection: &mut PgConnection,
    name: &str,
    active_only: bool,
) -> Result<i64, PolicyStoreError> {
    let row = sqlx::query_scalar::<_, i64>(
        "SELECT id FROM members WHERE name = $1 AND (NOT $2 OR revoked_at IS NULL) FOR SHARE",
    )
    .bind(name)
    .bind(active_only)
    .fetch_optional(connection)
    .await;
    match row {
        Ok(Some(id)) => Ok(id),
        Ok(None) => Err(member_not_found_error()),
        Err(error) => Err(PolicyStoreError::Database(error)),
    }
}

/// Looks up the ID of the registered repository `path`.
async fn find_repository_id(
    connection: &mut PgConnection,
    path: &str,
) -> Result<i64, PolicyStoreError> {
    let row = sqlx::query_scalar::<_, i64>("SELECT id FROM repositories WHERE path = $1 FOR SHARE")
        .bind(path)
        .fetch_optional(connection)
        .await;
    match row {
        Ok(Some(id)) => Ok(id),
        Ok(None) => Err(repository_not_registered_error()),
        Err(error) => Err(PolicyStoreError::Database(error)),
    }
}

/// Generates a token for `member_id` and stores its digest.
async fn insert_member_token(
    connection: &mut PgConnection,
    member_id: i64,
    label: &str,
) -> Result<SecretString, PolicyStoreError> {
    let generated = match generate_api_token() {
        Ok(generated) => generated,
        Err(error) => return Err(error),
    };
    let result =
        sqlx::query("INSERT INTO member_tokens (member_id, token_hash, label) VALUES ($1, $2, $3)")
            .bind(member_id)
            .bind(generated.hash.as_slice())
            .bind(label)
            .execute(connection)
            .await;
    match result {
        Ok(_) => Ok(generated.token),
        Err(error) => Err(PolicyStoreError::Database(error)),
    }
}

/// Creates the member described by `request` (already validated), adds them
/// to its groups and issues their first token, inside the caller's
/// transaction.
async fn insert_member_with_token(
    connection: &mut PgConnection,
    request: &CreateMemberRequest,
) -> Result<CreatedMember, PolicyStoreError> {
    // `ON CONFLICT DO NOTHING` turns a concurrent duplicate into a clean
    // conflict instead of a unique-violation error.
    let inserted = sqlx::query_scalar::<_, i64>(
        "INSERT INTO members (name, is_admin, is_machine, public_key) VALUES ($1, $2, $3, $4) \
         ON CONFLICT (name) DO NOTHING RETURNING id",
    )
    .bind(&request.name)
    .bind(request.is_admin)
    .bind(request.is_machine)
    .bind(request.public_key.as_deref())
    .fetch_optional(&mut *connection)
    .await;
    let member_id = match inserted {
        Ok(Some(member_id)) => member_id,
        Ok(None) => return Err(member_exists_error()),
        Err(error) => return Err(PolicyStoreError::Database(error)),
    };
    let group_ids = match find_group_ids(&mut *connection, &request.groups).await {
        Ok(group_ids) => group_ids,
        Err(error) => return Err(error),
    };
    if let Err(error) = sqlx::query(
        "INSERT INTO group_memberships (group_id, member_id) SELECT UNNEST($1::BIGINT[]), $2",
    )
    .bind(group_ids)
    .bind(member_id)
    .execute(&mut *connection)
    .await
    {
        return Err(PolicyStoreError::Database(error));
    }
    let token = match insert_member_token(&mut *connection, member_id, &request.token_label).await {
        Ok(token) => token,
        Err(error) => return Err(error),
    };
    Ok(CreatedMember {
        member: MemberRecord {
            id: member_id,
            name: request.name.clone(),
            is_admin: request.is_admin,
            is_machine: request.is_machine,
            public_key: request.public_key.clone(),
            groups: request.groups.iter().cloned().collect(),
            revoked: false,
        },
        token,
    })
}

impl PolicyStore for PgPolicyStore {
    fn authenticate_token_hash<'a>(
        &'a self,
        token_hash: &'a [u8; 32],
    ) -> PolicyStoreFuture<'a, Option<AuthenticatedMember>> {
        Box::pin(async move {
            // The index on the unique `token_hash` column does the lookup; the
            // hash of a high-entropy token reveals nothing usable by timing.
            let row = sqlx::query_as::<_, (i64, String, bool)>(
                "SELECT m.id, m.name, m.is_admin \
                 FROM member_tokens mt \
                 JOIN members m ON m.id = mt.member_id \
                 WHERE mt.token_hash = $1 \
                   AND mt.revoked_at IS NULL \
                   AND m.revoked_at IS NULL",
            )
            .bind(token_hash.as_slice())
            .fetch_optional(&self.pool)
            .await;
            match row {
                Ok(Some((id, name, is_admin))) => {
                    Ok(Some(AuthenticatedMember { id, name, is_admin }))
                }
                Ok(None) => Ok(None),
                Err(error) => Err(PolicyStoreError::Database(error)),
            }
        })
    }

    fn load_member_repo_policy<'a>(
        &'a self,
        member_id: i64,
        repo_key: &'a str,
    ) -> PolicyStoreFuture<'a, MemberRepoPolicy> {
        Box::pin(async move {
            // Both queries read one consistent snapshot, so a concurrent
            // change to memberships and rules is seen entirely or not at all.
            // Dropping the transaction on an early return rolls it back.
            let mut transaction = match self.begin().await {
                Ok(transaction) => transaction,
                Err(error) => return Err(error),
            };
            if let Err(error) =
                sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
                    .execute(&mut *transaction)
                    .await
            {
                return Err(PolicyStoreError::Database(error));
            }

            let group_rows = sqlx::query_as::<_, (String,)>(
                "SELECT g.name \
                 FROM group_memberships gm \
                 JOIN groups g ON g.id = gm.group_id \
                 WHERE gm.member_id = $1",
            )
            .bind(member_id)
            .fetch_all(&mut *transaction)
            .await;
            let member_groups = match group_rows {
                Ok(rows) => rows.into_iter().map(|(name,)| name).collect(),
                Err(error) => return Err(PolicyStoreError::Database(error)),
            };

            // LEFT JOINs keep a rule that grants no group: it must still come
            // back (with no allowed groups) so it hides its refs from everyone
            // instead of silently disappearing.
            let rule_rows = sqlx::query_as::<_, (String, Option<String>)>(
                "SELECT br.ref_glob, g.name \
                 FROM repositories r \
                 JOIN branch_rules br ON br.repository_id = r.id \
                 LEFT JOIN branch_rule_groups brg ON brg.branch_rule_id = br.id \
                 LEFT JOIN groups g ON g.id = brg.group_id \
                 WHERE r.path = $1",
            )
            .bind(repo_key)
            .fetch_all(&mut *transaction)
            .await;
            let rule_rows = match rule_rows {
                Ok(rows) => rows,
                Err(error) => return Err(PolicyStoreError::Database(error)),
            };

            let path_rule_rows = sqlx::query_as::<_, (String, Option<String>)>(
                "SELECT pr.path_glob, g.name \
                 FROM repositories r \
                 JOIN path_rules pr ON pr.repository_id = r.id \
                 LEFT JOIN path_rule_groups prg ON prg.path_rule_id = pr.id \
                 LEFT JOIN groups g ON g.id = prg.group_id \
                 WHERE r.path = $1",
            )
            .bind(repo_key)
            .fetch_all(&mut *transaction)
            .await;
            let path_rule_rows = match path_rule_rows {
                Ok(rows) => rows,
                Err(error) => return Err(PolicyStoreError::Database(error)),
            };

            if let Err(error) = commit(transaction).await {
                return Err(error);
            }

            let mut groups_by_pattern: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
            for (pattern, group) in rule_rows {
                let allowed_groups = groups_by_pattern.entry(pattern).or_default();
                if let Some(group) = group {
                    allowed_groups.insert(group);
                }
            }
            // `BranchPolicy::compile` re-validates every pattern.
            let rules = groups_by_pattern
                .into_iter()
                .map(|(pattern, allowed_groups)| BranchRule {
                    pattern,
                    allowed_groups,
                });
            let branch_policy = match compile_branch_policy(repo_key, rules) {
                Ok(branch_policy) => branch_policy,
                Err(error) => return Err(error),
            };

            let mut path_groups_by_pattern: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
            for (pattern, group) in path_rule_rows {
                let allowed_groups = path_groups_by_pattern.entry(pattern).or_default();
                if let Some(group) = group {
                    allowed_groups.insert(group);
                }
            }
            let withhold_policy = match compile_withhold_policy(path_groups_by_pattern) {
                Ok(withhold_policy) => withhold_policy,
                Err(error) => return Err(error),
            };

            Ok(MemberRepoPolicy {
                member_groups,
                branch_policy,
                withhold_policy,
            })
        })
    }

    fn record_audit_event<'a>(&'a self, entry: AuditLogEntry) -> PolicyStoreFuture<'a, ()> {
        Box::pin(async move {
            let mut connection = match self.pool.acquire().await {
                Ok(connection) => connection,
                Err(error) => return Err(PolicyStoreError::Database(error)),
            };
            insert_audit_entry(&mut connection, entry).await
        })
    }

    fn list_member_groups<'a>(&'a self, member_id: i64) -> PolicyStoreFuture<'a, BTreeSet<String>> {
        Box::pin(async move {
            let rows = sqlx::query_scalar::<_, String>(
                "SELECT g.name FROM group_memberships gm \
                 JOIN groups g ON g.id = gm.group_id \
                 WHERE gm.member_id = $1",
            )
            .bind(member_id)
            .fetch_all(&self.pool)
            .await;
            match rows {
                Ok(rows) => Ok(rows.into_iter().collect()),
                Err(error) => Err(PolicyStoreError::Database(error)),
            }
        })
    }

    fn register_repository<'a>(
        &'a self,
        actor_member_id: Option<i64>,
        repo_path: &'a str,
    ) -> PolicyStoreFuture<'a, RegisterRepositoryResult> {
        Box::pin(async move {
            if let Err(error) = validate_repository_path(repo_path) {
                return Err(error);
            }
            let mut transaction = match self.begin().await {
                Ok(transaction) => transaction,
                Err(error) => return Err(error),
            };
            let inserted = sqlx::query_scalar::<_, i64>(
                "INSERT INTO repositories (path) VALUES ($1) \
                 ON CONFLICT (path) DO NOTHING RETURNING id",
            )
            .bind(repo_path)
            .fetch_optional(&mut *transaction)
            .await;
            let (id, created) = match inserted {
                Ok(Some(id)) => (id, true),
                Ok(None) => match find_repository_id(&mut transaction, repo_path).await {
                    Ok(id) => (id, false),
                    Err(error) => return Err(error),
                },
                Err(error) => return Err(PolicyStoreError::Database(error)),
            };
            if created
                && let Err(error) = insert_audit_entry(
                    &mut transaction,
                    register_repository_audit(actor_member_id, repo_path),
                )
                .await
            {
                return Err(error);
            }
            if let Err(error) = commit(transaction).await {
                return Err(error);
            }
            Ok(RegisterRepositoryResult {
                repository: RepositoryRecord {
                    id,
                    path: repo_path.to_owned(),
                },
                created,
            })
        })
    }

    fn list_repositories<'a>(&'a self) -> PolicyStoreFuture<'a, Vec<RepositoryRecord>> {
        Box::pin(async move {
            // `COLLATE "C"` sorts by bytes, matching `MemoryPolicyStore`.
            let rows = sqlx::query_as::<_, (i64, String)>(
                "SELECT id, path FROM repositories ORDER BY path COLLATE \"C\"",
            )
            .fetch_all(&self.pool)
            .await;
            match rows {
                Ok(rows) => Ok(rows
                    .into_iter()
                    .map(|(id, path)| RepositoryRecord { id, path })
                    .collect()),
                Err(error) => Err(PolicyStoreError::Database(error)),
            }
        })
    }

    fn create_group<'a>(
        &'a self,
        actor_member_id: Option<i64>,
        name: &'a str,
    ) -> PolicyStoreFuture<'a, GroupRecord> {
        Box::pin(async move {
            if let Err(error) = validate_group_name(name) {
                return Err(error);
            }
            let mut transaction = match self.begin().await {
                Ok(transaction) => transaction,
                Err(error) => return Err(error),
            };
            let inserted = sqlx::query_scalar::<_, i64>(
                "INSERT INTO groups (name) VALUES ($1) ON CONFLICT (name) DO NOTHING RETURNING id",
            )
            .bind(name)
            .fetch_optional(&mut *transaction)
            .await;
            let id = match inserted {
                Ok(Some(id)) => id,
                Ok(None) => return Err(group_exists_error()),
                Err(error) => return Err(PolicyStoreError::Database(error)),
            };
            if let Err(error) =
                insert_audit_entry(&mut transaction, create_group_audit(actor_member_id, name))
                    .await
            {
                return Err(error);
            }
            if let Err(error) = commit(transaction).await {
                return Err(error);
            }
            Ok(GroupRecord {
                id,
                name: name.to_owned(),
            })
        })
    }

    fn list_groups<'a>(&'a self) -> PolicyStoreFuture<'a, Vec<GroupWithMembers>> {
        Box::pin(async move {
            let rows = sqlx::query_as::<_, (i64, String, Option<String>)>(
                "SELECT g.id, g.name, m.name \
                 FROM groups g \
                 LEFT JOIN group_memberships gm ON gm.group_id = g.id \
                 LEFT JOIN members m ON m.id = gm.member_id AND m.revoked_at IS NULL \
                 ORDER BY g.name COLLATE \"C\", m.name COLLATE \"C\"",
            )
            .fetch_all(&self.pool)
            .await;
            let rows = match rows {
                Ok(rows) => rows,
                Err(error) => return Err(PolicyStoreError::Database(error)),
            };
            let mut groups: Vec<GroupWithMembers> = Vec::new();
            for (id, name, member) in rows {
                let is_same_group = groups.last().is_some_and(|group| group.id == id);
                if !is_same_group {
                    groups.push(GroupWithMembers {
                        id,
                        name,
                        members: Vec::new(),
                    });
                }
                if let (Some(member), Some(group)) = (member, groups.last_mut()) {
                    group.members.push(member);
                }
            }
            Ok(groups)
        })
    }

    fn add_group_member<'a>(
        &'a self,
        actor_member_id: Option<i64>,
        group_name: &'a str,
        member_name: &'a str,
    ) -> PolicyStoreFuture<'a, GroupMembershipChange> {
        Box::pin(async move {
            if let Err(error) = validate_group_name(group_name) {
                return Err(error);
            }
            if let Err(error) = validate_member_name(member_name) {
                return Err(error);
            }
            let mut transaction = match self.begin().await {
                Ok(transaction) => transaction,
                Err(error) => return Err(error),
            };
            let group_id = match find_group_id(&mut transaction, group_name).await {
                Ok(group_id) => group_id,
                Err(error) => return Err(error),
            };
            let member_id = match find_member_id(&mut transaction, member_name, true).await {
                Ok(member_id) => member_id,
                Err(error) => return Err(error),
            };
            let inserted = sqlx::query(
                "INSERT INTO group_memberships (group_id, member_id) VALUES ($1, $2) \
                 ON CONFLICT DO NOTHING",
            )
            .bind(group_id)
            .bind(member_id)
            .execute(&mut *transaction)
            .await;
            let changed = match inserted {
                Ok(result) => result.rows_affected() == 1,
                Err(error) => return Err(PolicyStoreError::Database(error)),
            };
            if changed
                && let Err(error) = insert_audit_entry(
                    &mut transaction,
                    group_membership_audit(
                        actor_member_id,
                        "group.member_add",
                        group_name,
                        member_name,
                    ),
                )
                .await
            {
                return Err(error);
            }
            if let Err(error) = commit(transaction).await {
                return Err(error);
            }
            Ok(GroupMembershipChange {
                group: group_name.to_owned(),
                member: member_name.to_owned(),
                changed,
            })
        })
    }

    fn remove_group_member<'a>(
        &'a self,
        actor_member_id: Option<i64>,
        group_name: &'a str,
        member_name: &'a str,
    ) -> PolicyStoreFuture<'a, GroupMembershipChange> {
        Box::pin(async move {
            if let Err(error) = validate_group_name(group_name) {
                return Err(error);
            }
            if let Err(error) = validate_member_name(member_name) {
                return Err(error);
            }
            let mut transaction = match self.begin().await {
                Ok(transaction) => transaction,
                Err(error) => return Err(error),
            };
            let group_id = match find_group_id(&mut transaction, group_name).await {
                Ok(group_id) => group_id,
                Err(error) => return Err(error),
            };
            let member_id = match find_member_id(&mut transaction, member_name, false).await {
                Ok(member_id) => member_id,
                Err(error) => return Err(error),
            };
            let deleted =
                sqlx::query("DELETE FROM group_memberships WHERE group_id = $1 AND member_id = $2")
                    .bind(group_id)
                    .bind(member_id)
                    .execute(&mut *transaction)
                    .await;
            let changed = match deleted {
                Ok(result) => result.rows_affected() == 1,
                Err(error) => return Err(PolicyStoreError::Database(error)),
            };
            if changed
                && let Err(error) = insert_audit_entry(
                    &mut transaction,
                    group_membership_audit(
                        actor_member_id,
                        "group.member_remove",
                        group_name,
                        member_name,
                    ),
                )
                .await
            {
                return Err(error);
            }
            if let Err(error) = commit(transaction).await {
                return Err(error);
            }
            Ok(GroupMembershipChange {
                group: group_name.to_owned(),
                member: member_name.to_owned(),
                changed,
            })
        })
    }

    fn create_member<'a>(
        &'a self,
        actor_member_id: Option<i64>,
        request: CreateMemberRequest,
    ) -> PolicyStoreFuture<'a, CreatedMember> {
        Box::pin(async move {
            if let Err(error) = validate_create_member_request(&request) {
                return Err(error);
            }
            let mut transaction = match self.begin().await {
                Ok(transaction) => transaction,
                Err(error) => return Err(error),
            };
            let created = match insert_member_with_token(&mut transaction, &request).await {
                Ok(created) => created,
                Err(error) => return Err(error),
            };
            if let Err(error) = insert_audit_entry(
                &mut transaction,
                create_member_audit(actor_member_id, &request),
            )
            .await
            {
                return Err(error);
            }
            if let Err(error) = commit(transaction).await {
                return Err(error);
            }
            Ok(created)
        })
    }

    fn issue_member_token<'a>(
        &'a self,
        actor_member_id: Option<i64>,
        member_name: &'a str,
        label: &'a str,
    ) -> PolicyStoreFuture<'a, IssuedToken> {
        Box::pin(async move {
            if let Err(error) = validate_member_name(member_name) {
                return Err(error);
            }
            if let Err(error) = validate_token_label(label) {
                return Err(error);
            }
            let mut transaction = match self.begin().await {
                Ok(transaction) => transaction,
                Err(error) => return Err(error),
            };
            let member_id = match find_member_id(&mut transaction, member_name, true).await {
                Ok(member_id) => member_id,
                Err(error) => return Err(error),
            };
            let token = match insert_member_token(&mut transaction, member_id, label).await {
                Ok(token) => token,
                Err(error) => return Err(error),
            };
            if let Err(error) = insert_audit_entry(
                &mut transaction,
                issue_token_audit(actor_member_id, member_name, label),
            )
            .await
            {
                return Err(error);
            }
            if let Err(error) = commit(transaction).await {
                return Err(error);
            }
            Ok(IssuedToken {
                member: member_name.to_owned(),
                label: label.to_owned(),
                token,
            })
        })
    }

    fn revoke_member<'a>(
        &'a self,
        actor_member_id: Option<i64>,
        member_name: &'a str,
    ) -> PolicyStoreFuture<'a, RevokeMemberResult> {
        Box::pin(async move {
            if let Err(error) = validate_member_name(member_name) {
                return Err(error);
            }
            let mut transaction = match self.begin().await {
                Ok(transaction) => transaction,
                Err(error) => return Err(error),
            };
            // Lock every active admin first, always in ID order, so two
            // concurrent revocations serialize here (instead of deadlocking)
            // and the second sees the first's result: the last active admin
            // can never be revoked by a race.
            let active_admin_ids = sqlx::query_scalar::<_, i64>(
                "SELECT id FROM members WHERE is_admin AND revoked_at IS NULL \
                 ORDER BY id FOR UPDATE",
            )
            .fetch_all(&mut *transaction)
            .await;
            let active_admin_ids = match active_admin_ids {
                Ok(ids) => ids,
                Err(error) => return Err(PolicyStoreError::Database(error)),
            };
            let target = sqlx::query_as::<_, (i64, bool, bool)>(
                "SELECT id, is_admin, revoked_at IS NOT NULL FROM members \
                 WHERE name = $1 FOR UPDATE",
            )
            .bind(member_name)
            .fetch_optional(&mut *transaction)
            .await;
            let (member_id, is_admin, is_revoked) = match target {
                Ok(Some(target)) => target,
                Ok(None) => return Err(member_not_found_error()),
                Err(error) => return Err(PolicyStoreError::Database(error)),
            };
            if is_revoked {
                return Ok(RevokeMemberResult {
                    name: member_name.to_owned(),
                    revoked: false,
                });
            }
            if is_admin && active_admin_ids.len() <= 1 {
                return Err(last_admin_error());
            }
            if let Err(error) = sqlx::query("UPDATE members SET revoked_at = NOW() WHERE id = $1")
                .bind(member_id)
                .execute(&mut *transaction)
                .await
            {
                return Err(PolicyStoreError::Database(error));
            }
            let revoked_tokens = sqlx::query(
                "UPDATE member_tokens SET revoked_at = NOW() \
                 WHERE member_id = $1 AND revoked_at IS NULL",
            )
            .bind(member_id)
            .execute(&mut *transaction)
            .await;
            let revoked_token_count = match revoked_tokens {
                Ok(result) => result.rows_affected(),
                Err(error) => return Err(PolicyStoreError::Database(error)),
            };
            if let Err(error) = insert_audit_entry(
                &mut transaction,
                revoke_member_audit(actor_member_id, member_name, revoked_token_count),
            )
            .await
            {
                return Err(error);
            }
            if let Err(error) = commit(transaction).await {
                return Err(error);
            }
            Ok(RevokeMemberResult {
                name: member_name.to_owned(),
                revoked: true,
            })
        })
    }

    fn list_members<'a>(
        &'a self,
        include_revoked: bool,
    ) -> PolicyStoreFuture<'a, Vec<MemberRecord>> {
        Box::pin(async move {
            let rows = sqlx::query_as::<
                _,
                (
                    i64,
                    String,
                    bool,
                    bool,
                    Option<String>,
                    bool,
                    Option<String>,
                ),
            >(
                "SELECT m.id, m.name, m.is_admin, m.is_machine, m.public_key, \
                        m.revoked_at IS NOT NULL, g.name \
                 FROM members m \
                 LEFT JOIN group_memberships gm ON gm.member_id = m.id \
                 LEFT JOIN groups g ON g.id = gm.group_id \
                 WHERE $1 OR m.revoked_at IS NULL \
                 ORDER BY m.name COLLATE \"C\", g.name COLLATE \"C\"",
            )
            .bind(include_revoked)
            .fetch_all(&self.pool)
            .await;
            let rows = match rows {
                Ok(rows) => rows,
                Err(error) => return Err(PolicyStoreError::Database(error)),
            };
            let mut members: Vec<MemberRecord> = Vec::new();
            for (id, name, is_admin, is_machine, public_key, revoked, group) in rows {
                let is_same_member = members.last().is_some_and(|member| member.id == id);
                if !is_same_member {
                    members.push(MemberRecord {
                        id,
                        name,
                        is_admin,
                        is_machine,
                        public_key,
                        groups: Vec::new(),
                        revoked,
                    });
                }
                if let (Some(group), Some(member)) = (group, members.last_mut()) {
                    member.groups.push(group);
                }
            }
            Ok(members)
        })
    }

    fn set_branch_rule<'a>(
        &'a self,
        actor_member_id: Option<i64>,
        repository: &'a str,
        pattern: &'a str,
        groups: BTreeSet<String>,
    ) -> PolicyStoreFuture<'a, BranchRuleRecord> {
        Box::pin(async move {
            if let Err(error) = validate_repository_path(repository) {
                return Err(error);
            }
            if let Err(error) = validate_branch_rule(pattern, &groups) {
                return Err(error);
            }
            let mut transaction = match self.begin().await {
                Ok(transaction) => transaction,
                Err(error) => return Err(error),
            };
            let repository_id = match find_repository_id(&mut transaction, repository).await {
                Ok(repository_id) => repository_id,
                Err(error) => return Err(error),
            };
            let group_ids = match find_group_ids(&mut transaction, &groups).await {
                Ok(group_ids) => group_ids,
                Err(error) => return Err(error),
            };
            // The no-op update makes `RETURNING` yield the existing row's ID.
            let rule_id = sqlx::query_scalar::<_, i64>(
                "INSERT INTO branch_rules (repository_id, ref_glob) VALUES ($1, $2) \
                 ON CONFLICT (repository_id, ref_glob) DO UPDATE SET ref_glob = EXCLUDED.ref_glob \
                 RETURNING id",
            )
            .bind(repository_id)
            .bind(pattern)
            .fetch_one(&mut *transaction)
            .await;
            let rule_id = match rule_id {
                Ok(rule_id) => rule_id,
                Err(error) => return Err(PolicyStoreError::Database(error)),
            };
            if let Err(error) =
                sqlx::query("DELETE FROM branch_rule_groups WHERE branch_rule_id = $1")
                    .bind(rule_id)
                    .execute(&mut *transaction)
                    .await
            {
                return Err(PolicyStoreError::Database(error));
            }
            if let Err(error) = sqlx::query(
                "INSERT INTO branch_rule_groups (branch_rule_id, group_id) \
                 SELECT $1, UNNEST($2::BIGINT[])",
            )
            .bind(rule_id)
            .bind(group_ids)
            .execute(&mut *transaction)
            .await
            {
                return Err(PolicyStoreError::Database(error));
            }
            let record = BranchRuleRecord {
                repository: repository.to_owned(),
                pattern: pattern.to_owned(),
                groups: groups.into_iter().collect(),
            };
            if let Err(error) = insert_audit_entry(
                &mut transaction,
                set_branch_rule_audit(actor_member_id, &record),
            )
            .await
            {
                return Err(error);
            }
            if let Err(error) = commit(transaction).await {
                return Err(error);
            }
            Ok(record)
        })
    }

    fn list_branch_rules<'a>(
        &'a self,
        repository: &'a str,
    ) -> PolicyStoreFuture<'a, Vec<BranchRuleRecord>> {
        Box::pin(async move {
            if let Err(error) = validate_repository_path(repository) {
                return Err(error);
            }
            // One query: no rows means the repository is not registered; a
            // row with no rule means it has no rules.
            let rows = sqlx::query_as::<_, (Option<String>, Option<String>)>(
                "SELECT br.ref_glob, g.name \
                 FROM repositories r \
                 LEFT JOIN branch_rules br ON br.repository_id = r.id \
                 LEFT JOIN branch_rule_groups brg ON brg.branch_rule_id = br.id \
                 LEFT JOIN groups g ON g.id = brg.group_id \
                 WHERE r.path = $1 \
                 ORDER BY br.ref_glob COLLATE \"C\", g.name COLLATE \"C\"",
            )
            .bind(repository)
            .fetch_all(&self.pool)
            .await;
            let rows = match rows {
                Ok(rows) => rows,
                Err(error) => return Err(PolicyStoreError::Database(error)),
            };
            if rows.is_empty() {
                return Err(repository_not_registered_error());
            }
            let mut rules: Vec<BranchRuleRecord> = Vec::new();
            for (pattern, group) in rows {
                let Some(pattern) = pattern else {
                    continue;
                };
                let is_same_rule = rules.last().is_some_and(|rule| rule.pattern == pattern);
                if !is_same_rule {
                    rules.push(BranchRuleRecord {
                        repository: repository.to_owned(),
                        pattern,
                        groups: Vec::new(),
                    });
                }
                if let (Some(group), Some(rule)) = (group, rules.last_mut()) {
                    rule.groups.push(group);
                }
            }
            Ok(rules)
        })
    }

    fn remove_branch_rule<'a>(
        &'a self,
        actor_member_id: Option<i64>,
        repository: &'a str,
        pattern: &'a str,
    ) -> PolicyStoreFuture<'a, bool> {
        Box::pin(async move {
            if let Err(error) = validate_repository_path(repository) {
                return Err(error);
            }
            let mut transaction = match self.begin().await {
                Ok(transaction) => transaction,
                Err(error) => return Err(error),
            };
            let repository_id = match find_repository_id(&mut transaction, repository).await {
                Ok(repository_id) => repository_id,
                Err(error) => return Err(error),
            };
            let deleted =
                sqlx::query("DELETE FROM branch_rules WHERE repository_id = $1 AND ref_glob = $2")
                    .bind(repository_id)
                    .bind(pattern)
                    .execute(&mut *transaction)
                    .await;
            match deleted {
                Ok(result) if result.rows_affected() == 1 => {}
                Ok(_) => return Err(branch_rule_not_found_error()),
                Err(error) => return Err(PolicyStoreError::Database(error)),
            }
            if let Err(error) = insert_audit_entry(
                &mut transaction,
                remove_branch_rule_audit(actor_member_id, repository, pattern),
            )
            .await
            {
                return Err(error);
            }
            if let Err(error) = commit(transaction).await {
                return Err(error);
            }
            Ok(true)
        })
    }

    fn set_path_rule<'a>(
        &'a self,
        actor_member_id: Option<i64>,
        repository: &'a str,
        pattern: &'a str,
        groups: BTreeSet<String>,
    ) -> PolicyStoreFuture<'a, PathRuleRecord> {
        Box::pin(async move {
            if let Err(error) = validate_repository_path(repository) {
                return Err(error);
            }
            if let Err(error) = validate_path_rule(pattern, &groups) {
                return Err(error);
            }
            let mut transaction = match self.begin().await {
                Ok(transaction) => transaction,
                Err(error) => return Err(error),
            };
            // Lock the repository row `FOR UPDATE` so concurrent inserts into
            // `path_rules` serialize their `MAX_PATH_RULES` check.
            let repository_id = sqlx::query_scalar::<_, i64>(
                "SELECT id FROM repositories WHERE path = $1 FOR UPDATE",
            )
            .bind(repository)
            .fetch_optional(&mut *transaction)
            .await;
            let repository_id = match repository_id {
                Ok(Some(repository_id)) => repository_id,
                Ok(None) => return Err(repository_not_registered_error()),
                Err(error) => return Err(PolicyStoreError::Database(error)),
            };
            let group_ids = match find_group_ids(&mut transaction, &groups).await {
                Ok(group_ids) => group_ids,
                Err(error) => return Err(error),
            };
            let existing_rule_id = sqlx::query_scalar::<_, i64>(
                "SELECT id FROM path_rules WHERE repository_id = $1 AND path_glob = $2",
            )
            .bind(repository_id)
            .bind(pattern)
            .fetch_optional(&mut *transaction)
            .await;
            let existing_rule_id = match existing_rule_id {
                Ok(id) => id,
                Err(error) => return Err(PolicyStoreError::Database(error)),
            };
            if existing_rule_id.is_none() {
                let rule_count = sqlx::query_scalar::<_, i64>(
                    "SELECT COUNT(*) FROM path_rules WHERE repository_id = $1",
                )
                .bind(repository_id)
                .fetch_one(&mut *transaction)
                .await;
                let rule_count = match rule_count {
                    Ok(count) => count,
                    Err(error) => return Err(PolicyStoreError::Database(error)),
                };
                let count = match usize::try_from(rule_count) {
                    Ok(count) => count,
                    Err(_) => return Err(too_many_path_rules_error()),
                };
                if count >= MAX_PATH_RULES {
                    return Err(too_many_path_rules_error());
                }
            }
            // The no-op update makes `RETURNING` yield the existing row's ID.
            let rule_id = sqlx::query_scalar::<_, i64>(
                "INSERT INTO path_rules (repository_id, path_glob) VALUES ($1, $2) \
                 ON CONFLICT (repository_id, path_glob) DO UPDATE SET path_glob = EXCLUDED.path_glob \
                 RETURNING id",
            )
            .bind(repository_id)
            .bind(pattern)
            .fetch_one(&mut *transaction)
            .await;
            let rule_id = match rule_id {
                Ok(rule_id) => rule_id,
                Err(error) => return Err(PolicyStoreError::Database(error)),
            };
            if let Err(error) = sqlx::query("DELETE FROM path_rule_groups WHERE path_rule_id = $1")
                .bind(rule_id)
                .execute(&mut *transaction)
                .await
            {
                return Err(PolicyStoreError::Database(error));
            }
            if let Err(error) = sqlx::query(
                "INSERT INTO path_rule_groups (path_rule_id, group_id) \
                 SELECT $1, UNNEST($2::BIGINT[])",
            )
            .bind(rule_id)
            .bind(group_ids)
            .execute(&mut *transaction)
            .await
            {
                return Err(PolicyStoreError::Database(error));
            }
            let record = PathRuleRecord {
                repository: repository.to_owned(),
                pattern: pattern.to_owned(),
                groups: groups.into_iter().collect(),
            };
            if let Err(error) = insert_audit_entry(
                &mut transaction,
                set_path_rule_audit(actor_member_id, &record),
            )
            .await
            {
                return Err(error);
            }
            if let Err(error) = commit(transaction).await {
                return Err(error);
            }
            Ok(record)
        })
    }

    fn list_path_rules<'a>(
        &'a self,
        repository: &'a str,
    ) -> PolicyStoreFuture<'a, Vec<PathRuleRecord>> {
        Box::pin(async move {
            if let Err(error) = validate_repository_path(repository) {
                return Err(error);
            }
            let rows = sqlx::query_as::<_, (Option<String>, Option<String>)>(
                "SELECT pr.path_glob, g.name \
                 FROM repositories r \
                 LEFT JOIN path_rules pr ON pr.repository_id = r.id \
                 LEFT JOIN path_rule_groups prg ON prg.path_rule_id = pr.id \
                 LEFT JOIN groups g ON g.id = prg.group_id \
                 WHERE r.path = $1 \
                 ORDER BY pr.path_glob COLLATE \"C\", g.name COLLATE \"C\"",
            )
            .bind(repository)
            .fetch_all(&self.pool)
            .await;
            let rows = match rows {
                Ok(rows) => rows,
                Err(error) => return Err(PolicyStoreError::Database(error)),
            };
            if rows.is_empty() {
                return Err(repository_not_registered_error());
            }
            let mut rules: Vec<PathRuleRecord> = Vec::new();
            for (pattern, group) in rows {
                let Some(pattern) = pattern else {
                    continue;
                };
                let is_same_rule = rules.last().is_some_and(|rule| rule.pattern == pattern);
                if !is_same_rule {
                    rules.push(PathRuleRecord {
                        repository: repository.to_owned(),
                        pattern,
                        groups: Vec::new(),
                    });
                }
                if let (Some(group), Some(rule)) = (group, rules.last_mut()) {
                    rule.groups.push(group);
                }
            }
            Ok(rules)
        })
    }

    fn remove_path_rule<'a>(
        &'a self,
        actor_member_id: Option<i64>,
        repository: &'a str,
        pattern: &'a str,
    ) -> PolicyStoreFuture<'a, bool> {
        Box::pin(async move {
            if let Err(error) = validate_repository_path(repository) {
                return Err(error);
            }
            let mut transaction = match self.begin().await {
                Ok(transaction) => transaction,
                Err(error) => return Err(error),
            };
            let repository_id = match find_repository_id(&mut transaction, repository).await {
                Ok(repository_id) => repository_id,
                Err(error) => return Err(error),
            };
            let deleted =
                sqlx::query("DELETE FROM path_rules WHERE repository_id = $1 AND path_glob = $2")
                    .bind(repository_id)
                    .bind(pattern)
                    .execute(&mut *transaction)
                    .await;
            match deleted {
                Ok(result) if result.rows_affected() == 1 => {}
                Ok(_) => return Err(path_rule_not_found_error()),
                Err(error) => return Err(PolicyStoreError::Database(error)),
            }
            if let Err(error) = insert_audit_entry(
                &mut transaction,
                remove_path_rule_audit(actor_member_id, repository, pattern),
            )
            .await
            {
                return Err(error);
            }
            if let Err(error) = commit(transaction).await {
                return Err(error);
            }
            Ok(true)
        })
    }

    fn bootstrap_admin<'a>(
        &'a self,
        name: &'a str,
        token_label: &'a str,
    ) -> PolicyStoreFuture<'a, CreatedMember> {
        Box::pin(async move {
            let request = bootstrap_admin_request(name, token_label);
            if let Err(error) = validate_create_member_request(&request) {
                return Err(error);
            }
            let mut transaction = match self.begin().await {
                Ok(transaction) => transaction,
                Err(error) => return Err(error),
            };
            // Held until commit or rollback: a concurrent bootstrap waits
            // here, then sees this one's admin and fails.
            if let Err(error) = sqlx::query("SELECT pg_advisory_xact_lock($1)")
                .bind(BOOTSTRAP_ADMIN_LOCK_KEY)
                .execute(&mut *transaction)
                .await
            {
                return Err(PolicyStoreError::Database(error));
            }
            let admin_exists = sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS (SELECT 1 FROM members WHERE is_admin AND revoked_at IS NULL)",
            )
            .fetch_one(&mut *transaction)
            .await;
            match admin_exists {
                Ok(false) => {}
                Ok(true) => return Err(admin_exists_error()),
                Err(error) => return Err(PolicyStoreError::Database(error)),
            }
            let created = match insert_member_with_token(&mut transaction, &request).await {
                Ok(created) => created,
                Err(error) => return Err(error),
            };
            if let Err(error) =
                insert_audit_entry(&mut transaction, bootstrap_admin_audit(name, token_label)).await
            {
                return Err(error);
            }
            if let Err(error) = commit(transaction).await {
                return Err(error);
            }
            Ok(created)
        })
    }

    fn get_member_public_key<'a>(
        &'a self,
        member_id: i64,
    ) -> PolicyStoreFuture<'a, Option<String>> {
        Box::pin(async move {
            let row = sqlx::query_scalar::<_, Option<String>>(
                "SELECT public_key FROM members WHERE id = $1 AND revoked_at IS NULL",
            )
            .bind(member_id)
            .fetch_optional(&self.pool)
            .await;
            match row {
                Ok(Some(public_key)) => Ok(public_key),
                Ok(None) => Ok(None),
                Err(error) => Err(PolicyStoreError::Database(error)),
            }
        })
    }

    fn set_member_public_key<'a>(
        &'a self,
        actor_member_id: Option<i64>,
        member_name: &'a str,
        public_key: &'a str,
    ) -> PolicyStoreFuture<'a, MemberPublicKeyRecord> {
        Box::pin(async move {
            if let Err(error) = validate_member_name(member_name) {
                return Err(error);
            }
            if let Err(error) = validate_age_public_key(public_key) {
                return Err(error);
            }
            let mut transaction = match self.begin().await {
                Ok(transaction) => transaction,
                Err(error) => return Err(error),
            };
            let updated = sqlx::query_scalar::<_, i64>(
                "UPDATE members SET public_key = $1 \
                 WHERE name = $2 AND revoked_at IS NULL \
                 RETURNING id",
            )
            .bind(public_key)
            .bind(member_name)
            .fetch_optional(&mut *transaction)
            .await;
            match updated {
                Ok(Some(_)) => {}
                Ok(None) => return Err(member_not_found_error()),
                Err(error) => return Err(PolicyStoreError::Database(error)),
            }
            if let Err(error) = insert_audit_entry(
                &mut transaction,
                set_member_public_key_audit(actor_member_id, member_name, public_key),
            )
            .await
            {
                return Err(error);
            }
            if let Err(error) = commit(transaction).await {
                return Err(error);
            }
            Ok(MemberPublicKeyRecord {
                name: member_name.to_owned(),
                public_key: public_key.to_owned(),
            })
        })
    }

    fn set_secret_scope<'a>(
        &'a self,
        actor_member_id: Option<i64>,
        repository: &'a str,
        scope: &'a str,
        groups: BTreeSet<String>,
    ) -> PolicyStoreFuture<'a, SecretScopeRecord> {
        Box::pin(async move {
            if let Err(error) = validate_repository_path(repository) {
                return Err(error);
            }
            if let Err(error) = validate_secret_scope(scope, &groups) {
                return Err(error);
            }
            let mut transaction = match self.begin().await {
                Ok(transaction) => transaction,
                Err(error) => return Err(error),
            };
            let repository_id = match find_repository_id(&mut transaction, repository).await {
                Ok(repository_id) => repository_id,
                Err(error) => return Err(error),
            };
            let group_ids = match find_group_ids(&mut transaction, &groups).await {
                Ok(group_ids) => group_ids,
                Err(error) => return Err(error),
            };
            // The no-op update makes `RETURNING` yield the existing row's ID.
            let scope_id = sqlx::query_scalar::<_, i64>(
                "INSERT INTO secret_scopes (repository_id, scope_name) VALUES ($1, $2) \
                 ON CONFLICT (repository_id, scope_name) DO UPDATE SET scope_name = EXCLUDED.scope_name \
                 RETURNING id",
            )
            .bind(repository_id)
            .bind(scope)
            .fetch_one(&mut *transaction)
            .await;
            let scope_id = match scope_id {
                Ok(scope_id) => scope_id,
                Err(error) => return Err(PolicyStoreError::Database(error)),
            };
            if let Err(error) =
                sqlx::query("DELETE FROM secret_scope_groups WHERE secret_scope_id = $1")
                    .bind(scope_id)
                    .execute(&mut *transaction)
                    .await
            {
                return Err(PolicyStoreError::Database(error));
            }
            if let Err(error) = sqlx::query(
                "INSERT INTO secret_scope_groups (secret_scope_id, group_id) \
                 SELECT $1, UNNEST($2::BIGINT[])",
            )
            .bind(scope_id)
            .bind(group_ids)
            .execute(&mut *transaction)
            .await
            {
                return Err(PolicyStoreError::Database(error));
            }
            let record = SecretScopeRecord {
                repository: repository.to_owned(),
                scope: scope.to_owned(),
                groups: groups.into_iter().collect(),
            };
            if let Err(error) = insert_audit_entry(
                &mut transaction,
                set_secret_scope_audit(actor_member_id, &record),
            )
            .await
            {
                return Err(error);
            }
            if let Err(error) = commit(transaction).await {
                return Err(error);
            }
            Ok(record)
        })
    }

    fn list_secret_scopes<'a>(
        &'a self,
        repository: &'a str,
    ) -> PolicyStoreFuture<'a, Vec<SecretScopeRecord>> {
        Box::pin(async move {
            if let Err(error) = validate_repository_path(repository) {
                return Err(error);
            }
            let rows = sqlx::query_as::<_, (Option<String>, Option<String>)>(
                "SELECT ss.scope_name, g.name \
                 FROM repositories r \
                 LEFT JOIN secret_scopes ss ON ss.repository_id = r.id \
                 LEFT JOIN secret_scope_groups ssg ON ssg.secret_scope_id = ss.id \
                 LEFT JOIN groups g ON g.id = ssg.group_id \
                 WHERE r.path = $1 \
                 ORDER BY ss.scope_name COLLATE \"C\", g.name COLLATE \"C\"",
            )
            .bind(repository)
            .fetch_all(&self.pool)
            .await;
            let rows = match rows {
                Ok(rows) => rows,
                Err(error) => return Err(PolicyStoreError::Database(error)),
            };
            if rows.is_empty() {
                return Err(repository_not_registered_error());
            }
            let mut scopes: Vec<SecretScopeRecord> = Vec::new();
            for (scope, group) in rows {
                let Some(scope) = scope else {
                    continue;
                };
                let is_same_scope = scopes.last().is_some_and(|record| record.scope == scope);
                if !is_same_scope {
                    scopes.push(SecretScopeRecord {
                        repository: repository.to_owned(),
                        scope,
                        groups: Vec::new(),
                    });
                }
                if let (Some(group), Some(record)) = (group, scopes.last_mut()) {
                    record.groups.push(group);
                }
            }
            Ok(scopes)
        })
    }

    fn remove_secret_scope<'a>(
        &'a self,
        actor_member_id: Option<i64>,
        repository: &'a str,
        scope: &'a str,
    ) -> PolicyStoreFuture<'a, bool> {
        Box::pin(async move {
            if let Err(error) = validate_repository_path(repository) {
                return Err(error);
            }
            if let Err(error) = validate_scope_name(scope) {
                return Err(error);
            }
            let mut transaction = match self.begin().await {
                Ok(transaction) => transaction,
                Err(error) => return Err(error),
            };
            let repository_id = match find_repository_id(&mut transaction, repository).await {
                Ok(repository_id) => repository_id,
                Err(error) => return Err(error),
            };
            let deleted = sqlx::query(
                "DELETE FROM secret_scopes WHERE repository_id = $1 AND scope_name = $2",
            )
            .bind(repository_id)
            .bind(scope)
            .execute(&mut *transaction)
            .await;
            match deleted {
                Ok(result) if result.rows_affected() == 1 => {}
                Ok(_) => return Err(secret_scope_not_found_error()),
                Err(error) => return Err(PolicyStoreError::Database(error)),
            }
            if let Err(error) = insert_audit_entry(
                &mut transaction,
                remove_secret_scope_audit(actor_member_id, repository, scope),
            )
            .await
            {
                return Err(error);
            }
            if let Err(error) = commit(transaction).await {
                return Err(error);
            }
            Ok(true)
        })
    }

    fn resolve_secret_scope_recipients<'a>(
        &'a self,
        repository: &'a str,
        scope: &'a str,
    ) -> PolicyStoreFuture<'a, ScopeRecipientsRecord> {
        Box::pin(async move {
            if let Err(error) = validate_repository_path(repository) {
                return Err(error);
            }
            if let Err(error) = validate_scope_name(scope) {
                return Err(error);
            }
            let mut transaction = match self.begin().await {
                Ok(transaction) => transaction,
                Err(error) => return Err(error),
            };
            if let Err(error) =
                sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
                    .execute(&mut *transaction)
                    .await
            {
                return Err(PolicyStoreError::Database(error));
            }

            let scope_row = sqlx::query_scalar::<_, Option<i64>>(
                "SELECT ss.id \
                 FROM repositories r \
                 LEFT JOIN secret_scopes ss ON ss.repository_id = r.id AND ss.scope_name = $2 \
                 WHERE r.path = $1",
            )
            .bind(repository)
            .bind(scope)
            .fetch_optional(&mut *transaction)
            .await;
            let scope_id = match scope_row {
                Ok(Some(Some(scope_id))) => scope_id,
                Ok(Some(None)) => return Err(secret_scope_not_found_error()),
                Ok(None) => return Err(repository_not_registered_error()),
                Err(error) => return Err(PolicyStoreError::Database(error)),
            };

            let groups = sqlx::query_scalar::<_, String>(
                "SELECT g.name \
                 FROM secret_scope_groups ssg \
                 JOIN groups g ON g.id = ssg.group_id \
                 WHERE ssg.secret_scope_id = $1 \
                 ORDER BY g.name COLLATE \"C\"",
            )
            .bind(scope_id)
            .fetch_all(&mut *transaction)
            .await;
            let groups = match groups {
                Ok(groups) => groups,
                Err(error) => return Err(PolicyStoreError::Database(error)),
            };

            let member_rows = sqlx::query_as::<_, (String, Option<String>)>(
                "SELECT m.name, m.public_key \
                 FROM secret_scope_groups ssg \
                 JOIN group_memberships gm ON gm.group_id = ssg.group_id \
                 JOIN members m ON m.id = gm.member_id \
                 WHERE ssg.secret_scope_id = $1 \
                   AND m.revoked_at IS NULL \
                 GROUP BY m.id, m.name, m.public_key \
                 ORDER BY m.name COLLATE \"C\"",
            )
            .bind(scope_id)
            .fetch_all(&mut *transaction)
            .await;
            let member_rows = match member_rows {
                Ok(rows) => rows,
                Err(error) => return Err(PolicyStoreError::Database(error)),
            };

            if let Err(error) = commit(transaction).await {
                return Err(error);
            }

            let (recipients, members_without_key) = partition_recipients(member_rows);
            Ok(ScopeRecipientsRecord {
                repository: repository.to_owned(),
                scope: scope.to_owned(),
                groups,
                recipients,
                members_without_key,
            })
        })
    }

    fn resolve_group_recipients<'a>(
        &'a self,
        group: &'a str,
    ) -> PolicyStoreFuture<'a, GroupRecipientsRecord> {
        Box::pin(async move {
            if let Err(error) = validate_group_name(group) {
                return Err(error);
            }
            let mut transaction = match self.begin().await {
                Ok(transaction) => transaction,
                Err(error) => return Err(error),
            };
            if let Err(error) =
                sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
                    .execute(&mut *transaction)
                    .await
            {
                return Err(PolicyStoreError::Database(error));
            }

            let group_id = sqlx::query_scalar::<_, i64>("SELECT id FROM groups WHERE name = $1")
                .bind(group)
                .fetch_optional(&mut *transaction)
                .await;
            let group_id = match group_id {
                Ok(Some(group_id)) => group_id,
                Ok(None) => return Err(group_not_found_error()),
                Err(error) => return Err(PolicyStoreError::Database(error)),
            };

            let member_rows = sqlx::query_as::<_, (String, Option<String>)>(
                "SELECT m.name, m.public_key \
                 FROM group_memberships gm \
                 JOIN members m ON m.id = gm.member_id \
                 WHERE gm.group_id = $1 \
                   AND m.revoked_at IS NULL \
                 ORDER BY m.name COLLATE \"C\"",
            )
            .bind(group_id)
            .fetch_all(&mut *transaction)
            .await;
            let member_rows = match member_rows {
                Ok(rows) => rows,
                Err(error) => return Err(PolicyStoreError::Database(error)),
            };

            if let Err(error) = commit(transaction).await {
                return Err(error);
            }

            let (recipients, members_without_key) = partition_recipients(member_rows);
            Ok(GroupRecipientsRecord {
                group: group.to_owned(),
                recipients,
                members_without_key,
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret;

    use super::{
        AGE_HRP_EXPANDED, API_TOKEN_PREFIX, AuditLogEntry, BECH32_CHARSET, MAX_PATH_RULES,
        MemoryPolicyStore, PolicyStore, PolicyStoreError, WithholdRule, bech32_decode_char,
        bech32_polymod, generate_api_token, validate_age_public_key, validate_branch_rule,
        validate_group_name, validate_member_name, validate_path_rule, validate_repository_path,
        validate_scope_name, validate_token_label,
    };
    use crate::auth::sha256_zeroizing;

    fn make_entry(action: &str, actor_member_id: Option<i64>) -> AuditLogEntry {
        AuditLogEntry {
            actor_member_id,
            action: action.to_owned(),
            target_type: "repository_ref".to_owned(),
            target_name: "team/app.git:refs/heads/main".to_owned(),
            details: serde_json::json!({ "reason": "test" }),
        }
    }

    fn is_invalid_input<T>(result: Result<T, PolicyStoreError>) -> bool {
        matches!(result, Err(PolicyStoreError::InvalidInput(_)))
    }

    #[tokio::test]
    async fn memory_store_audit_log_is_shared_across_clones() {
        let store = MemoryPolicyStore::new();
        let handle = store.clone();
        let first = make_entry("branch.merge_leak_override", Some(7));
        let second = make_entry("branch.other", None);

        if let Err(error) = store.record_audit_event(first.clone()).await {
            panic!("recording the first entry failed: {error}");
        }
        if let Err(error) = handle.record_audit_event(second.clone()).await {
            panic!("recording the second entry failed: {error}");
        }

        assert_eq!(store.audit_entries(), vec![first.clone(), second.clone()]);
        assert_eq!(handle.audit_entries(), vec![first, second]);
        assert!(format!("{store:?}").contains("audit_entry_count: 2"));
    }

    #[test]
    fn names_follow_the_documented_rules() {
        for valid in ["a", "Z9", "alice", "ci-bot_2.prod", &"a".repeat(64)] {
            assert!(validate_member_name(valid).is_ok(), "{valid:?}");
            assert!(validate_group_name(valid).is_ok(), "{valid:?}");
        }
        for invalid in [
            "",
            "-alice",
            ".alice",
            "_alice",
            "al ice",
            "al/ice",
            "al:ice",
            "élise",
            &"a".repeat(65),
        ] {
            assert!(
                is_invalid_input(validate_member_name(invalid)),
                "{invalid:?}"
            );
            assert!(
                is_invalid_input(validate_group_name(invalid)),
                "{invalid:?}"
            );
        }
    }

    #[test]
    fn token_labels_are_short_printable_ascii() {
        for valid in ["", "laptop", "CI token #2 (prod)", &"x".repeat(128)] {
            assert!(validate_token_label(valid).is_ok(), "{valid:?}");
        }
        for invalid in ["tab\there", "new\nline", "\u{7f}", "café", &"x".repeat(129)] {
            assert!(
                is_invalid_input(validate_token_label(invalid)),
                "{invalid:?}"
            );
        }
    }

    #[test]
    fn repository_paths_are_validated_and_api_is_reserved() {
        for valid in ["app.git", "team/app.git", "apis.git", "team/api/app.git"] {
            assert!(validate_repository_path(valid).is_ok(), "{valid:?}");
        }
        let too_long = format!("{}.git", "a".repeat(253));
        for invalid in [
            "",
            "api",
            "api/app.git",
            "../app.git",
            "team//app.git",
            ".hidden.git",
            "/app.git",
            "app.git/",
            "team/%2e%2e/app.git",
            too_long.as_str(),
        ] {
            assert!(
                is_invalid_input(validate_repository_path(invalid)),
                "{invalid:?}"
            );
        }
    }

    #[test]
    fn branch_rules_need_a_valid_glob_and_groups() {
        let groups = ["core".to_owned()].into_iter().collect();
        assert!(validate_branch_rule("refs/heads/private/*", &groups).is_ok());
        assert!(is_invalid_input(validate_branch_rule(
            "heads/private/*",
            &groups
        )));
        assert!(is_invalid_input(validate_branch_rule(
            "refs/heads/[oops",
            &groups
        )));
        assert!(is_invalid_input(validate_branch_rule(
            "refs/heads/private/*",
            &Default::default()
        )));
        let bad_groups = ["not a group".to_owned()].into_iter().collect();
        assert!(is_invalid_input(validate_branch_rule(
            "refs/heads/private/*",
            &bad_groups
        )));
    }

    #[test]
    fn generated_tokens_are_prefixed_hex_and_unique() {
        let first = match generate_api_token() {
            Ok(token) => token,
            Err(error) => panic!("token generation failed: {error}"),
        };
        let second = match generate_api_token() {
            Ok(token) => token,
            Err(error) => panic!("token generation failed: {error}"),
        };
        let first_token = first.token.expose_secret();
        assert_eq!(first_token.len(), 70);
        let Some(hex_digits) = first_token.strip_prefix(API_TOKEN_PREFIX) else {
            panic!("token lacks the {API_TOKEN_PREFIX} prefix");
        };
        assert!(
            hex_digits
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        );
        assert_ne!(first_token, second.token.expose_secret());
        assert_eq!(*first.hash, *sha256_zeroizing(first_token.as_bytes()));
    }

    #[test]
    fn scope_names_follow_identifier_rules() {
        for valid in ["dev", "staging", "prod", "us-east_1.prod", &"s".repeat(64)] {
            assert!(validate_scope_name(valid).is_ok(), "{valid:?}");
        }
        for invalid in [
            "",
            "-dev",
            ".dev",
            "_dev",
            "dev prod",
            "dev/prod",
            "dev:prod",
            "dév",
            &"s".repeat(65),
        ] {
            assert!(
                is_invalid_input(validate_scope_name(invalid)),
                "{invalid:?}"
            );
        }
    }

    fn encode_age_key_from_data(data: &str) -> String {
        assert_eq!(data.len(), 52);
        let mut values = Vec::with_capacity(58);
        for byte in data.bytes() {
            let Some(val) = bech32_decode_char(byte) else {
                panic!("non-bech32 test char: {byte}");
            };
            values.push(val);
        }
        values.extend([0u8; 6]);
        let polymod =
            bech32_polymod(AGE_HRP_EXPANDED.into_iter().chain(values.iter().copied())) ^ 1;
        let mut out = String::from("age1");
        out.push_str(data);
        for i in 0..6 {
            let idx = ((polymod >> (5 * (5 - i))) & 31) as usize;
            out.push(char::from(BECH32_CHARSET[idx]));
        }
        out
    }

    #[test]
    fn age_public_keys_are_validated_strictly() {
        let valid_spec_vector = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p";
        assert!(validate_age_public_key(valid_spec_vector).is_ok());

        // Degenerate all-zero 32-byte key must be rejected even with a valid checksum.
        let all_zero_key = encode_age_key_from_data(&"q".repeat(52));
        assert!(is_invalid_input(validate_age_public_key(&all_zero_key)));

        // Corrupted checksum (flip last character).
        let mut bad_checksum = valid_spec_vector.to_owned();
        bad_checksum.pop();
        bad_checksum.push('q');
        assert!(is_invalid_input(validate_age_public_key(&bad_checksum)));

        // Non-zero padding bits in 52nd data character even with a valid checksum.
        let non_zero_padding_data = format!("{}p", &valid_spec_vector[4..55]);
        let non_zero_padding_key = encode_age_key_from_data(&non_zero_padding_data);
        assert!(is_invalid_input(validate_age_public_key(
            &non_zero_padding_key
        )));

        // Wrong HRP, wrong length, uppercase, whitespace, non-bech32 characters.
        let uppercase = valid_spec_vector.to_ascii_uppercase();
        let with_leading_ws = format!(" {valid_spec_vector}");
        let with_trailing_ws = format!("{valid_spec_vector}\n");
        let too_long = format!("{valid_spec_vector}q");
        let too_short = &valid_spec_vector[..61];
        for invalid in [
            "",
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA",
            "bob1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p",
            too_short,
            too_long.as_str(),
            uppercase.as_str(),
            with_leading_ws.as_str(),
            with_trailing_ws.as_str(),
            "age1bl3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p",
        ] {
            assert!(
                is_invalid_input(validate_age_public_key(invalid)),
                "{invalid:?}"
            );
        }
    }

    #[test]
    fn path_rules_need_a_valid_glob_and_groups() {
        let groups = ["core".to_owned()].into_iter().collect();
        assert!(validate_path_rule("config/billing/**", &groups).is_ok());
        assert!(validate_path_rule("*.secret", &groups).is_ok());
        assert!(is_invalid_input(validate_path_rule("/abs/path", &groups)));
        assert!(is_invalid_input(validate_path_rule(".scrim/**", &groups)));
        assert!(is_invalid_input(validate_path_rule(
            "config/[oops",
            &groups
        )));
        assert!(is_invalid_input(validate_path_rule(
            "config/**",
            &Default::default()
        )));
        let bad_groups = ["not a group".to_owned()].into_iter().collect();
        assert!(is_invalid_input(validate_path_rule(
            "config/**",
            &bad_groups
        )));
    }

    #[tokio::test]
    async fn memory_store_enforces_max_path_rules_and_allows_updates() {
        let store = MemoryPolicyStore::new();
        if let Err(error) = store.create_group(None, "core").await {
            panic!("create_group failed: {error}");
        }
        if let Err(error) = store.create_group(None, "security").await {
            panic!("create_group failed: {error}");
        }
        if let Err(error) = store.register_repository(None, "app.git").await {
            panic!("register_repository failed: {error}");
        }

        let core: std::collections::BTreeSet<String> = ["core".to_owned()].into_iter().collect();
        let security: std::collections::BTreeSet<String> =
            ["security".to_owned()].into_iter().collect();
        for i in 0..MAX_PATH_RULES {
            if let Err(error) = store
                .set_path_rule(None, "app.git", &format!("dir/file-{i}.txt"), core.clone())
                .await
            {
                panic!("set_path_rule {i} failed: {error}");
            }
        }

        // Inserting one more distinct pattern fails with InvalidInput.
        assert!(is_invalid_input(
            store
                .set_path_rule(None, "app.git", "dir/overflow.txt", core.clone())
                .await
        ));

        // Updating an existing pattern at MAX_PATH_RULES succeeds.
        match store
            .set_path_rule(None, "app.git", "dir/file-0.txt", security)
            .await
        {
            Ok(record) => assert_eq!(record.groups, vec!["security".to_owned()]),
            Err(error) => panic!("updating existing rule at limit failed: {error}"),
        }
    }

    #[tokio::test]
    async fn memory_store_corrupt_path_rule_fails_closed() {
        let mut store = MemoryPolicyStore::new();
        store.insert_path_rule(
            "app.git",
            WithholdRule {
                pattern: ".scrim/**".to_owned(),
                allowed_groups: ["core".to_owned()].into_iter().collect(),
            },
        );
        match store.load_member_repo_policy(1, "app.git").await {
            Err(PolicyStoreError::InvalidPathRule { path_glob, .. }) => {
                assert_eq!(path_glob, ".scrim/**");
            }
            Err(error) => panic!("expected InvalidPathRule, got: {error}"),
            Ok(_) => panic!("corrupt path rule must fail closed"),
        }
    }
}
