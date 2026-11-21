//! Where members, their tokens, group memberships and branch rules come from.
//!
//! The server only ever sees a [`PolicyStore`]: authentication hands it the
//! SHA-256 hash of the presented token, and every Git request asks it for the
//! member's groups and the repository's [`BranchPolicy`]. Three stores exist:
//! [`StaticPolicyStore`] keeps the single shared token of Milestone M0,
//! [`MemoryPolicyStore`] holds everything in memory (for tests and embedding),
//! and [`PgPolicyStore`] reads PostgreSQL.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    future::Future,
    pin::Pin,
    str::FromStr,
};

use scrim_policy::{BranchPolicy, BranchRule, PolicyError};
use sqlx::{
    PgPool,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::auth::{TokenAuth, sha256_zeroizing};

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
    /// Any other internal failure, described by the message.
    Internal(String),
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
            Self::Internal(message) => write!(f, "policy store error: {message}"),
        }
    }
}

impl std::error::Error for PolicyStoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Database(error) => Some(error),
            Self::InvalidBranchRule { source, .. } => Some(source),
            Self::Internal(_) => None,
        }
    }
}

/// The boxed future every [`PolicyStore`] method returns, which keeps the
/// trait object-safe without an `async-trait` dependency.
pub type PolicyStoreFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, PolicyStoreError>> + Send + 'a>>;

/// Source of members and repository policy, shared by all requests.
pub trait PolicyStore: Send + Sync + 'static {
    /// Returns the active member owning the token whose SHA-256 hash is
    /// `token_hash`, or `None` when no active token matches (including
    /// revoked tokens and revoked members).
    fn authenticate_token_hash<'a>(
        &'a self,
        token_hash: &'a [u8; 32],
    ) -> PolicyStoreFuture<'a, Option<AuthenticatedMember>>;

    /// Loads `member_id`'s groups and the branch rules of the repository whose
    /// canonical key is `repo_key`. A repository without rules yields an empty
    /// policy, so every ref stays visible.
    ///
    /// Fails with [`PolicyStoreError::InvalidBranchRule`] if any stored rule
    /// is invalid.
    fn load_member_repo_policy<'a>(
        &'a self,
        member_id: i64,
        repo_key: &'a str,
    ) -> PolicyStoreFuture<'a, MemberRepoPolicy>;
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
                }),
                Err(error) => Err(error),
            }
        })
    }
}

/// One member of a [`MemoryPolicyStore`] and the hash of their token.
#[derive(Clone)]
struct MemoryMember {
    member: AuthenticatedMember,
    token_hash: Zeroizing<[u8; 32]>,
}

/// A [`PolicyStore`] held entirely in memory, populated before it is shared.
#[derive(Clone, Default)]
pub struct MemoryPolicyStore {
    members: Vec<MemoryMember>,
    groups_by_member: BTreeMap<i64, BTreeSet<String>>,
    rules_by_repository: BTreeMap<String, Vec<BranchRule>>,
}

impl fmt::Debug for MemoryPolicyStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Token hashes stay out of debug output.
        f.debug_struct("MemoryPolicyStore")
            .field("member_count", &self.members.len())
            .field("groups_by_member", &self.groups_by_member)
            .field("rules_by_repository", &self.rules_by_repository)
            .finish()
    }
}

impl MemoryPolicyStore {
    /// Creates an empty store: no members, groups or rules.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds `member`, authenticated by `token` (only its SHA-256 hash is
    /// kept). The caller keeps IDs and tokens unique.
    pub fn insert_member(&mut self, member: AuthenticatedMember, token: &[u8]) {
        self.members.push(MemoryMember {
            member,
            token_hash: sha256_zeroizing(token),
        });
    }

    /// Makes `member_id` a member of `group`.
    pub fn insert_group_membership(&mut self, member_id: i64, group: impl Into<String>) {
        self.groups_by_member
            .entry(member_id)
            .or_default()
            .insert(group.into());
    }

    /// Attaches `rule` to the repository with canonical key `repo_key`.
    pub fn insert_branch_rule(&mut self, repo_key: impl Into<String>, rule: BranchRule) {
        self.rules_by_repository
            .entry(repo_key.into())
            .or_default()
            .push(rule);
    }
}

impl PolicyStore for MemoryPolicyStore {
    fn authenticate_token_hash<'a>(
        &'a self,
        token_hash: &'a [u8; 32],
    ) -> PolicyStoreFuture<'a, Option<AuthenticatedMember>> {
        // Compare against every member, even after a match, so the time taken
        // does not reveal which (or whether an early) entry matched.
        let mut matched_member = None;
        for entry in &self.members {
            let is_match = bool::from(entry.token_hash.as_slice().ct_eq(token_hash.as_slice()));
            if is_match && matched_member.is_none() {
                matched_member = Some(entry.member.clone());
            }
        }
        Box::pin(async move { Ok(matched_member) })
    }

    fn load_member_repo_policy<'a>(
        &'a self,
        member_id: i64,
        repo_key: &'a str,
    ) -> PolicyStoreFuture<'a, MemberRepoPolicy> {
        Box::pin(async move {
            let member_groups = match self.groups_by_member.get(&member_id) {
                Some(groups) => groups.clone(),
                None => BTreeSet::new(),
            };
            let rules = match self.rules_by_repository.get(repo_key) {
                Some(rules) => rules.clone(),
                None => Vec::new(),
            };
            match compile_branch_policy(repo_key, rules) {
                Ok(branch_policy) => Ok(MemberRepoPolicy {
                    member_groups,
                    branch_policy,
                }),
                Err(error) => Err(error),
            }
        })
    }
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
            let mut transaction = match self.pool.begin().await {
                Ok(transaction) => transaction,
                Err(error) => return Err(PolicyStoreError::Database(error)),
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
            if let Err(error) = transaction.commit().await {
                return Err(PolicyStoreError::Database(error));
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
            match compile_branch_policy(repo_key, rules) {
                Ok(branch_policy) => Ok(MemberRepoPolicy {
                    member_groups,
                    branch_policy,
                }),
                Err(error) => Err(error),
            }
        })
    }
}
