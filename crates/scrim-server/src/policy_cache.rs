//! Read-through cache for per-request member repository policy.
//!
//! Every Git request loads the member's groups and the repository's branch and
//! path rules (see [`PolicyStore::load_member_repo_policy`]).
//! [`CachedPolicyStore`] keeps those answers in a [`PolicyCacheBackend`]
//! (Redis in production, see [`RedisPolicyCache`]) so busy servers do not hit
//! PostgreSQL for each fetch.
//!
//! Invalidation is epoch based: every cache key embeds the current value of
//! [`POLICY_CACHE_EPOCH_KEY`], and every successful mutation increments it, so
//! all earlier entries become unreachable at once, across every server sharing
//! the cache. A miss writes its entry under the epoch observed *before* the
//! store was read, so a mutation racing the read orphans the (possibly stale)
//! entry instead of letting it shadow the new state.
//!
//! The cache never weakens authentication: token and SSH-key lookups always go
//! straight to the store, so revocations apply immediately. Any cache failure
//! falls back to the store, and store failures are returned unchanged, so the
//! server still fails closed.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use fred::prelude::{
    Builder, ClientLike, Config, Expiration, KeysInterface, ReconnectPolicy, ServerConfig,
};
use futures_util::future::BoxFuture;
use scrim_policy::{BranchPolicy, BranchRule, WithholdPolicy, WithholdRule};
use serde::{Deserialize, Serialize};

use crate::{
    auth::sha256_zeroizing,
    policy_store::{
        AuditLogEntry, AuditLogPage, AuditLogQuery, AuthenticatedMember, BranchRuleRecord,
        CreateMemberRequest, CreatedMember, GroupMembershipChange, GroupRecipientsRecord,
        GroupRecord, GroupWithMembers, IssuedToken, MemberPublicKeyRecord, MemberRecord,
        MemberRepoPolicy, MemberSshKeyRecord, MemberTokenRecord, PathRuleRecord, PolicyStore,
        PolicyStoreError, PolicyStoreFuture, RegisterRepositoryResult, RepositoryRecord,
        RevokeMemberResult, ScopeRecipientsRecord, SecretScopeRecord,
    },
    pre_receive::encode_hex,
};

/// Redis key holding the policy cache epoch (a decimal counter).
pub const POLICY_CACHE_EPOCH_KEY: &str = "scrim:policy:v1:epoch";

/// How long a cached member repository policy lives unless invalidated.
pub const DEFAULT_POLICY_CACHE_TTL_SECONDS: u64 = 60;

/// Largest cached entry that is decoded; anything bigger is treated as corrupt.
const MAX_CACHED_POLICY_BYTES: usize = 4 * 1024 * 1024;

/// How long connecting to Redis may take before the attempt fails.
const REDIS_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// How long one Redis command may take before the cache is bypassed.
const REDIS_COMMAND_TIMEOUT: Duration = Duration::from_secs(2);

/// Storage behind [`CachedPolicyStore`].
///
/// Errors are plain messages that must never contain credentials; the cache
/// logs them and falls back to the policy store.
pub trait PolicyCacheBackend: Send + Sync + 'static {
    /// Returns the current epoch, `0` if none was ever set.
    fn get_epoch(&self) -> BoxFuture<'_, Result<u64, String>>;

    /// Atomically increments the epoch and returns the new value.
    fn bump_epoch(&self) -> BoxFuture<'_, Result<u64, String>>;

    /// Returns the bytes stored under `key`, or `None` if absent or expired.
    fn get_bytes(&self, key: &str) -> BoxFuture<'_, Result<Option<Vec<u8>>, String>>;

    /// Stores `value` under `key` for `ttl_seconds` seconds.
    fn set_bytes(
        &self,
        key: &str,
        value: Vec<u8>,
        ttl_seconds: u64,
    ) -> BoxFuture<'_, Result<(), String>>;
}

/// A [`PolicyCacheBackend`] backed by a Redis (or Valkey) server.
pub struct RedisPolicyCache {
    client: fred::clients::Client,
}

impl fmt::Debug for RedisPolicyCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The connection URL (and any password in it) stays out of debug output.
        f.debug_struct("RedisPolicyCache").finish_non_exhaustive()
    }
}

impl RedisPolicyCache {
    /// Connects to the centralized Redis server at `redis_url` (`redis://` or,
    /// for TLS, `rediss://`), reconnecting in the background if the
    /// connection drops later.
    ///
    /// # Errors
    ///
    /// Fails if the URL is not a `redis://` or `rediss://` URL or the first
    /// connection attempt fails. Error messages never contain the URL.
    pub async fn connect(redis_url: &str) -> Result<Self, String> {
        if !(redis_url.starts_with("redis://") || redis_url.starts_with("rediss://")) {
            return Err("the Redis URL must start with redis:// or rediss://".to_owned());
        }
        // The parser's error could echo parts of the URL, so it is not shown.
        let config = match Config::from_url(redis_url) {
            Ok(config) => config,
            Err(_) => return Err("the Redis URL is invalid".to_owned()),
        };
        if !matches!(config.server, ServerConfig::Centralized { .. }) {
            return Err("only a single (centralized) Redis server is supported".to_owned());
        }
        let mut builder = Builder::from_config(config);
        builder
            .with_connection_config(|connection| {
                connection.connection_timeout = REDIS_CONNECT_TIMEOUT;
                connection.internal_command_timeout = REDIS_COMMAND_TIMEOUT;
                // A failed command falls back to the store instead of retrying.
                connection.max_command_attempts = 1;
            })
            .with_performance_config(|performance| {
                performance.default_command_timeout = REDIS_COMMAND_TIMEOUT;
            })
            // Reconnect forever, backing off from 100 ms to 5 s.
            .set_policy(ReconnectPolicy::new_exponential(0, 100, 5_000, 2));
        let client = match builder.build() {
            Ok(client) => client,
            Err(error) => return Err(format!("cannot configure the Redis client: {error}")),
        };
        // The background connection task keeps running after its handle is
        // dropped, reconnecting as needed.
        if let Err(error) = client.init().await {
            return Err(format!("cannot connect to Redis: {}", error.details()));
        }
        Ok(Self { client })
    }

    /// Fails fast while disconnected, so requests do not wait for command
    /// timeouts during an outage.
    fn require_connected(&self) -> Result<(), String> {
        if self.client.is_connected() {
            Ok(())
        } else {
            Err("Redis is not connected".to_owned())
        }
    }
}

/// Formats a Redis command error without anything but its kind and details.
fn redis_error(command: &str, error: &fred::error::Error) -> String {
    format!(
        "Redis {command} failed: {:?}: {}",
        error.kind(),
        error.details()
    )
}

impl PolicyCacheBackend for RedisPolicyCache {
    fn get_epoch(&self) -> BoxFuture<'_, Result<u64, String>> {
        Box::pin(async move {
            if let Err(error) = self.require_connected() {
                return Err(error);
            }
            match self
                .client
                .get::<Option<u64>, _>(POLICY_CACHE_EPOCH_KEY)
                .await
            {
                Ok(Some(epoch)) => Ok(epoch),
                Ok(None) => Ok(0),
                Err(error) => Err(redis_error("GET", &error)),
            }
        })
    }

    fn bump_epoch(&self) -> BoxFuture<'_, Result<u64, String>> {
        Box::pin(async move {
            if let Err(error) = self.require_connected() {
                return Err(error);
            }
            match self.client.incr::<u64, _>(POLICY_CACHE_EPOCH_KEY).await {
                Ok(epoch) => Ok(epoch),
                Err(error) => Err(redis_error("INCR", &error)),
            }
        })
    }

    fn get_bytes(&self, key: &str) -> BoxFuture<'_, Result<Option<Vec<u8>>, String>> {
        let key = key.to_owned();
        Box::pin(async move {
            if let Err(error) = self.require_connected() {
                return Err(error);
            }
            match self.client.get::<Option<Vec<u8>>, _>(key).await {
                Ok(value) => Ok(value),
                Err(error) => Err(redis_error("GET", &error)),
            }
        })
    }

    fn set_bytes(
        &self,
        key: &str,
        value: Vec<u8>,
        ttl_seconds: u64,
    ) -> BoxFuture<'_, Result<(), String>> {
        let key = key.to_owned();
        Box::pin(async move {
            if let Err(error) = self.require_connected() {
                return Err(error);
            }
            // Clamped into `1..=i64::MAX`, so the cast is lossless.
            let ttl_seconds = ttl_seconds.clamp(1, i64::MAX as u64) as i64;
            match self
                .client
                .set::<(), _, _>(key, value, Some(Expiration::EX(ttl_seconds)), None, false)
                .await
            {
                Ok(()) => Ok(()),
                Err(error) => Err(redis_error("SET", &error)),
            }
        })
    }
}

/// A [`PolicyCacheBackend`] held in memory, for tests and embedders.
///
/// [`MemoryPolicyCache::set_failing`] makes every operation fail, to exercise
/// the fallback paths of [`CachedPolicyStore`].
#[derive(Debug, Default)]
pub struct MemoryPolicyCache {
    state: Mutex<MemoryCacheState>,
}

#[derive(Debug, Default)]
struct MemoryCacheState {
    epoch: u64,
    /// Value and expiry instant of each key.
    entries: BTreeMap<String, (Vec<u8>, Instant)>,
    is_failing: bool,
}

impl MemoryPolicyCache {
    /// Creates an empty cache at epoch `0`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Makes every later operation fail (`true`) or succeed again (`false`).
    pub fn set_failing(&self, is_failing: bool) {
        match self.state.lock() {
            Ok(mut state) => state.is_failing = is_failing,
            Err(poisoned) => poisoned.into_inner().is_failing = is_failing,
        }
    }

    /// Runs `operation` on the locked state unless failures are simulated.
    fn with_state<T>(
        &self,
        operation: impl FnOnce(&mut MemoryCacheState) -> T,
    ) -> Result<T, String> {
        match self.state.lock() {
            Ok(mut state) => {
                if state.is_failing {
                    Err("simulated policy cache failure".to_owned())
                } else {
                    Ok(operation(&mut state))
                }
            }
            Err(_) => Err("memory policy cache mutex is poisoned".to_owned()),
        }
    }
}

impl PolicyCacheBackend for MemoryPolicyCache {
    fn get_epoch(&self) -> BoxFuture<'_, Result<u64, String>> {
        Box::pin(std::future::ready(self.with_state(|state| state.epoch)))
    }

    fn bump_epoch(&self) -> BoxFuture<'_, Result<u64, String>> {
        Box::pin(std::future::ready(self.with_state(|state| {
            state.epoch = state.epoch.saturating_add(1);
            state.epoch
        })))
    }

    fn get_bytes(&self, key: &str) -> BoxFuture<'_, Result<Option<Vec<u8>>, String>> {
        let result = self.with_state(|state| match state.entries.get(key) {
            Some((value, expires_at)) if *expires_at > Instant::now() => Some(value.clone()),
            Some(_) => {
                state.entries.remove(key);
                None
            }
            None => None,
        });
        Box::pin(std::future::ready(result))
    }

    fn set_bytes(
        &self,
        key: &str,
        value: Vec<u8>,
        ttl_seconds: u64,
    ) -> BoxFuture<'_, Result<(), String>> {
        let result = self.with_state(|state| {
            let expires_at = Instant::now() + Duration::from_secs(ttl_seconds.max(1));
            state.entries.insert(key.to_owned(), (value, expires_at));
        });
        Box::pin(std::future::ready(result))
    }
}

/// Returns the cache key of `member_id`'s policy for `repo_key` at `epoch`.
///
/// The repository key is hashed so the cache key has a fixed shape whatever
/// characters the repository path contains.
pub fn policy_cache_key(epoch: u64, member_id: i64, repo_key: &str) -> String {
    let repo_hash = encode_hex(sha256_zeroizing(repo_key.as_bytes()).as_slice());
    format!(
        "scrim:policy:v1:e{epoch}:m{member_id}:r{}",
        repo_hash.as_str()
    )
}

/// The serialized form of a [`MemberRepoPolicy`].
#[derive(Serialize, Deserialize)]
struct CachedMemberPolicy {
    member_groups: BTreeSet<String>,
    branch_rules: Vec<CachedRule>,
    withhold_rules: Vec<CachedRule>,
}

/// One branch or path rule: a glob and the groups it allows.
#[derive(Serialize, Deserialize)]
struct CachedRule {
    pattern: String,
    allowed_groups: BTreeSet<String>,
}

/// Serializes `policy` from its source rules.
fn encode_cached_policy(policy: &MemberRepoPolicy) -> Result<Vec<u8>, String> {
    let cached = CachedMemberPolicy {
        member_groups: policy.member_groups.clone(),
        branch_rules: policy
            .branch_policy
            .rules()
            .iter()
            .map(|rule| CachedRule {
                pattern: rule.pattern.clone(),
                allowed_groups: rule.allowed_groups.clone(),
            })
            .collect(),
        withhold_rules: policy
            .withhold_policy
            .rules()
            .iter()
            .map(|rule| CachedRule {
                pattern: rule.pattern.clone(),
                allowed_groups: rule.allowed_groups.clone(),
            })
            .collect(),
    };
    match serde_json::to_vec(&cached) {
        Ok(bytes) => Ok(bytes),
        Err(error) => Err(format!("cannot serialize policy: {error}")),
    }
}

/// Deserializes and recompiles a cached policy; every rule is validated again,
/// so a corrupted or tampered entry is rejected rather than trusted.
fn decode_cached_policy(bytes: &[u8]) -> Result<MemberRepoPolicy, String> {
    if bytes.len() > MAX_CACHED_POLICY_BYTES {
        return Err("cached policy is too large".to_owned());
    }
    let cached: CachedMemberPolicy = match serde_json::from_slice(bytes) {
        Ok(cached) => cached,
        Err(error) => return Err(format!("cannot parse cached policy: {error}")),
    };
    let branch_policy =
        match BranchPolicy::compile(cached.branch_rules.into_iter().map(|rule| BranchRule {
            pattern: rule.pattern,
            allowed_groups: rule.allowed_groups,
        })) {
            Ok(branch_policy) => branch_policy,
            Err(error) => return Err(format!("cached branch rule is invalid: {error}")),
        };
    let withhold_policy =
        match WithholdPolicy::compile(cached.withhold_rules.into_iter().map(|rule| WithholdRule {
            pattern: rule.pattern,
            allowed_groups: rule.allowed_groups,
        })) {
            Ok(withhold_policy) => withhold_policy,
            Err(error) => return Err(format!("cached path rule is invalid: {error}")),
        };
    Ok(MemberRepoPolicy {
        member_groups: cached.member_groups,
        branch_policy,
        withhold_policy,
    })
}

/// A [`PolicyStore`] that caches [`PolicyStore::load_member_repo_policy`] in
/// a [`PolicyCacheBackend`] and delegates everything else to `inner`.
///
/// Authentication is never cached. Each successful mutation bumps the cache
/// epoch; if that bump fails the committed change still stands and cached
/// policies may stay stale for at most the TTL (a warning is logged).
pub struct CachedPolicyStore {
    inner: Arc<dyn PolicyStore>,
    cache: Arc<dyn PolicyCacheBackend>,
    ttl_seconds: u64,
}

impl CachedPolicyStore {
    /// Caches `inner`'s member repository policies in `cache` for
    /// [`DEFAULT_POLICY_CACHE_TTL_SECONDS`].
    pub fn new(inner: Arc<dyn PolicyStore>, cache: Arc<dyn PolicyCacheBackend>) -> Self {
        Self {
            inner,
            cache,
            ttl_seconds: DEFAULT_POLICY_CACHE_TTL_SECONDS,
        }
    }

    /// Sets how long entries live (at least one second).
    pub fn with_ttl_seconds(mut self, ttl_seconds: u64) -> Self {
        self.ttl_seconds = ttl_seconds.max(1);
        self
    }

    /// Bumps the epoch after a successful mutation, returning `result` as is.
    async fn invalidate_after<T>(
        &self,
        result: Result<T, PolicyStoreError>,
    ) -> Result<T, PolicyStoreError> {
        if result.is_ok()
            && let Err(error) = self.cache.bump_epoch().await
        {
            tracing::warn!(
                %error,
                "cannot invalidate the policy cache; cached policies may stay stale until they expire"
            );
        }
        result
    }
}

impl PolicyStore for CachedPolicyStore {
    fn authenticate_token_hash<'a>(
        &'a self,
        token_hash: &'a [u8; 32],
    ) -> PolicyStoreFuture<'a, Option<AuthenticatedMember>> {
        // Never cached: token and member revocations must apply at once.
        self.inner.authenticate_token_hash(token_hash)
    }

    fn load_member_repo_policy<'a>(
        &'a self,
        member_id: i64,
        repo_key: &'a str,
    ) -> PolicyStoreFuture<'a, MemberRepoPolicy> {
        Box::pin(async move {
            let epoch = match self.cache.get_epoch().await {
                Ok(epoch) => epoch,
                Err(error) => {
                    tracing::warn!(%error, "policy cache unavailable; reading the policy store");
                    return self
                        .inner
                        .load_member_repo_policy(member_id, repo_key)
                        .await;
                }
            };
            let key = policy_cache_key(epoch, member_id, repo_key);
            match self.cache.get_bytes(&key).await {
                Ok(Some(bytes)) => match decode_cached_policy(&bytes) {
                    Ok(policy) => return Ok(policy),
                    Err(error) => tracing::warn!(%error, "ignoring an invalid policy cache entry"),
                },
                Ok(None) => {}
                Err(error) => tracing::warn!(%error, "cannot read the policy cache"),
            }

            let policy = match self
                .inner
                .load_member_repo_policy(member_id, repo_key)
                .await
            {
                Ok(policy) => policy,
                Err(error) => return Err(error),
            };
            // Stored under the epoch read before the store was queried, so a
            // concurrent mutation's bump orphans this entry.
            match encode_cached_policy(&policy) {
                Ok(bytes) => {
                    if let Err(error) = self.cache.set_bytes(&key, bytes, self.ttl_seconds).await {
                        tracing::warn!(%error, "cannot write the policy cache");
                    }
                }
                Err(error) => tracing::warn!(%error, "cannot cache the policy"),
            }
            Ok(policy)
        })
    }

    fn record_audit_event<'a>(&'a self, entry: AuditLogEntry) -> PolicyStoreFuture<'a, ()> {
        self.inner.record_audit_event(entry)
    }

    fn list_member_groups<'a>(&'a self, member_id: i64) -> PolicyStoreFuture<'a, BTreeSet<String>> {
        self.inner.list_member_groups(member_id)
    }

    fn register_repository<'a>(
        &'a self,
        actor_member_id: Option<i64>,
        repo_path: &'a str,
    ) -> PolicyStoreFuture<'a, RegisterRepositoryResult> {
        Box::pin(async move {
            let result = self
                .inner
                .register_repository(actor_member_id, repo_path)
                .await;
            self.invalidate_after(result).await
        })
    }

    fn list_repositories<'a>(&'a self) -> PolicyStoreFuture<'a, Vec<RepositoryRecord>> {
        self.inner.list_repositories()
    }

    fn create_group<'a>(
        &'a self,
        actor_member_id: Option<i64>,
        name: &'a str,
    ) -> PolicyStoreFuture<'a, GroupRecord> {
        Box::pin(async move {
            let result = self.inner.create_group(actor_member_id, name).await;
            self.invalidate_after(result).await
        })
    }

    fn list_groups<'a>(&'a self) -> PolicyStoreFuture<'a, Vec<GroupWithMembers>> {
        self.inner.list_groups()
    }

    fn delete_group<'a>(
        &'a self,
        actor_member_id: Option<i64>,
        group_name: &'a str,
    ) -> PolicyStoreFuture<'a, ()> {
        Box::pin(async move {
            let result = self.inner.delete_group(actor_member_id, group_name).await;
            self.invalidate_after(result).await
        })
    }

    fn add_group_member<'a>(
        &'a self,
        actor_member_id: Option<i64>,
        group_name: &'a str,
        member_name: &'a str,
    ) -> PolicyStoreFuture<'a, GroupMembershipChange> {
        Box::pin(async move {
            let result = self
                .inner
                .add_group_member(actor_member_id, group_name, member_name)
                .await;
            self.invalidate_after(result).await
        })
    }

    fn remove_group_member<'a>(
        &'a self,
        actor_member_id: Option<i64>,
        group_name: &'a str,
        member_name: &'a str,
    ) -> PolicyStoreFuture<'a, GroupMembershipChange> {
        Box::pin(async move {
            let result = self
                .inner
                .remove_group_member(actor_member_id, group_name, member_name)
                .await;
            self.invalidate_after(result).await
        })
    }

    fn create_member<'a>(
        &'a self,
        actor_member_id: Option<i64>,
        request: CreateMemberRequest,
    ) -> PolicyStoreFuture<'a, CreatedMember> {
        Box::pin(async move {
            let result = self.inner.create_member(actor_member_id, request).await;
            self.invalidate_after(result).await
        })
    }

    fn issue_member_token<'a>(
        &'a self,
        actor_member_id: Option<i64>,
        member_name: &'a str,
        label: &'a str,
    ) -> PolicyStoreFuture<'a, IssuedToken> {
        Box::pin(async move {
            let result = self
                .inner
                .issue_member_token(actor_member_id, member_name, label)
                .await;
            self.invalidate_after(result).await
        })
    }

    fn list_member_tokens<'a>(
        &'a self,
        member_name: &'a str,
        include_revoked: bool,
    ) -> PolicyStoreFuture<'a, Vec<MemberTokenRecord>> {
        self.inner.list_member_tokens(member_name, include_revoked)
    }

    fn revoke_member_token<'a>(
        &'a self,
        actor_member_id: Option<i64>,
        member_name: &'a str,
        token_id: i64,
    ) -> PolicyStoreFuture<'a, ()> {
        Box::pin(async move {
            let result = self
                .inner
                .revoke_member_token(actor_member_id, member_name, token_id)
                .await;
            self.invalidate_after(result).await
        })
    }

    fn revoke_member<'a>(
        &'a self,
        actor_member_id: Option<i64>,
        member_name: &'a str,
    ) -> PolicyStoreFuture<'a, RevokeMemberResult> {
        Box::pin(async move {
            let result = self.inner.revoke_member(actor_member_id, member_name).await;
            self.invalidate_after(result).await
        })
    }

    fn list_members<'a>(
        &'a self,
        include_revoked: bool,
    ) -> PolicyStoreFuture<'a, Vec<MemberRecord>> {
        self.inner.list_members(include_revoked)
    }

    fn set_branch_rule<'a>(
        &'a self,
        actor_member_id: Option<i64>,
        repository: &'a str,
        pattern: &'a str,
        groups: BTreeSet<String>,
    ) -> PolicyStoreFuture<'a, BranchRuleRecord> {
        Box::pin(async move {
            let result = self
                .inner
                .set_branch_rule(actor_member_id, repository, pattern, groups)
                .await;
            self.invalidate_after(result).await
        })
    }

    fn list_branch_rules<'a>(
        &'a self,
        repository: &'a str,
    ) -> PolicyStoreFuture<'a, Vec<BranchRuleRecord>> {
        self.inner.list_branch_rules(repository)
    }

    fn remove_branch_rule<'a>(
        &'a self,
        actor_member_id: Option<i64>,
        repository: &'a str,
        pattern: &'a str,
    ) -> PolicyStoreFuture<'a, bool> {
        Box::pin(async move {
            let result = self
                .inner
                .remove_branch_rule(actor_member_id, repository, pattern)
                .await;
            self.invalidate_after(result).await
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
            let result = self
                .inner
                .set_path_rule(actor_member_id, repository, pattern, groups)
                .await;
            self.invalidate_after(result).await
        })
    }

    fn list_path_rules<'a>(
        &'a self,
        repository: &'a str,
    ) -> PolicyStoreFuture<'a, Vec<PathRuleRecord>> {
        self.inner.list_path_rules(repository)
    }

    fn remove_path_rule<'a>(
        &'a self,
        actor_member_id: Option<i64>,
        repository: &'a str,
        pattern: &'a str,
    ) -> PolicyStoreFuture<'a, bool> {
        Box::pin(async move {
            let result = self
                .inner
                .remove_path_rule(actor_member_id, repository, pattern)
                .await;
            self.invalidate_after(result).await
        })
    }

    fn bootstrap_admin<'a>(
        &'a self,
        name: &'a str,
        token_label: &'a str,
    ) -> PolicyStoreFuture<'a, CreatedMember> {
        Box::pin(async move {
            let result = self.inner.bootstrap_admin(name, token_label).await;
            self.invalidate_after(result).await
        })
    }

    fn get_member_public_key<'a>(
        &'a self,
        member_id: i64,
    ) -> PolicyStoreFuture<'a, Option<String>> {
        self.inner.get_member_public_key(member_id)
    }

    fn set_member_public_key<'a>(
        &'a self,
        actor_member_id: Option<i64>,
        member_name: &'a str,
        public_key: &'a str,
    ) -> PolicyStoreFuture<'a, MemberPublicKeyRecord> {
        Box::pin(async move {
            let result = self
                .inner
                .set_member_public_key(actor_member_id, member_name, public_key)
                .await;
            self.invalidate_after(result).await
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
            let result = self
                .inner
                .set_secret_scope(actor_member_id, repository, scope, groups)
                .await;
            self.invalidate_after(result).await
        })
    }

    fn list_secret_scopes<'a>(
        &'a self,
        repository: &'a str,
    ) -> PolicyStoreFuture<'a, Vec<SecretScopeRecord>> {
        self.inner.list_secret_scopes(repository)
    }

    fn remove_secret_scope<'a>(
        &'a self,
        actor_member_id: Option<i64>,
        repository: &'a str,
        scope: &'a str,
    ) -> PolicyStoreFuture<'a, bool> {
        Box::pin(async move {
            let result = self
                .inner
                .remove_secret_scope(actor_member_id, repository, scope)
                .await;
            self.invalidate_after(result).await
        })
    }

    fn resolve_secret_scope_recipients<'a>(
        &'a self,
        repository: &'a str,
        scope: &'a str,
    ) -> PolicyStoreFuture<'a, ScopeRecipientsRecord> {
        self.inner
            .resolve_secret_scope_recipients(repository, scope)
    }

    fn resolve_group_recipients<'a>(
        &'a self,
        group: &'a str,
    ) -> PolicyStoreFuture<'a, GroupRecipientsRecord> {
        self.inner.resolve_group_recipients(group)
    }

    fn list_audit_log<'a>(&'a self, query: AuditLogQuery) -> PolicyStoreFuture<'a, AuditLogPage> {
        self.inner.list_audit_log(query)
    }

    fn authenticate_ssh_key<'a>(
        &'a self,
        fingerprint: &'a str,
    ) -> PolicyStoreFuture<'a, Option<AuthenticatedMember>> {
        // Never cached: SSH key and member revocations must apply at once.
        self.inner.authenticate_ssh_key(fingerprint)
    }

    fn add_member_ssh_key<'a>(
        &'a self,
        actor_member_id: Option<i64>,
        member_name: &'a str,
        public_key: &'a str,
        label: &'a str,
    ) -> PolicyStoreFuture<'a, MemberSshKeyRecord> {
        Box::pin(async move {
            let result = self
                .inner
                .add_member_ssh_key(actor_member_id, member_name, public_key, label)
                .await;
            self.invalidate_after(result).await
        })
    }

    fn list_member_ssh_keys<'a>(
        &'a self,
        member_name: &'a str,
    ) -> PolicyStoreFuture<'a, Vec<MemberSshKeyRecord>> {
        self.inner.list_member_ssh_keys(member_name)
    }

    fn revoke_member_ssh_key<'a>(
        &'a self,
        actor_member_id: Option<i64>,
        member_name: &'a str,
        key_id: i64,
    ) -> PolicyStoreFuture<'a, bool> {
        Box::pin(async move {
            let result = self
                .inner
                .revoke_member_ssh_key(actor_member_id, member_name, key_id)
                .await;
            self.invalidate_after(result).await
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{
        future::Future,
        sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    };

    use super::*;
    use crate::policy_store::MemoryPolicyStore;

    const REPO: &str = "team/app.git";
    const ALICE_ID: i64 = 1;
    const ALICE_TOKEN: &[u8] = b"alice-token";
    const AGE_PUBLIC_KEY: &str = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p";
    const ED25519_KEY: &str = "ssh-ed25519 \
        AAAAC3NzaC1lZDI1NTE5AAAAIH2ACokL5rFZeMA6cnIFOE6yBk13muMZSo6BO+J/4jM+";

    fn groups(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|name| (*name).to_owned()).collect()
    }

    /// A store with member `alice` (group `dev`) and one branch and one path
    /// rule on [`REPO`].
    fn seeded_memory_store() -> MemoryPolicyStore {
        let mut store = MemoryPolicyStore::new();
        store.insert_member(
            AuthenticatedMember {
                id: ALICE_ID,
                name: "alice".to_owned(),
                is_admin: false,
            },
            ALICE_TOKEN,
        );
        store.insert_group_membership(ALICE_ID, "dev");
        match BranchRule::new("refs/heads/private/*", ["dev".to_owned()]) {
            Ok(rule) => store.insert_branch_rule(REPO, rule),
            Err(error) => panic!("branch rule should be valid: {error}"),
        }
        match WithholdRule::new("secret/**", groups(&["dev"])) {
            Ok(rule) => store.insert_path_rule(REPO, rule),
            Err(error) => panic!("path rule should be valid: {error}"),
        }
        store
    }

    /// Wraps a [`MemoryPolicyStore`], counting reads and optionally failing
    /// or simulating a concurrent mutation during a policy load.
    struct CountingStore {
        inner: MemoryPolicyStore,
        policy_loads: AtomicUsize,
        token_authentications: AtomicUsize,
        ssh_authentications: AtomicUsize,
        is_failing: AtomicBool,
        /// When set, the next policy load adds `alice` to the group and bumps
        /// the cache's epoch after reading, as another server's mutation would.
        concurrent_mutation: Mutex<Option<(Arc<MemoryPolicyCache>, String)>>,
    }

    impl CountingStore {
        fn new(inner: MemoryPolicyStore) -> Self {
            Self {
                inner,
                policy_loads: AtomicUsize::new(0),
                token_authentications: AtomicUsize::new(0),
                ssh_authentications: AtomicUsize::new(0),
                is_failing: AtomicBool::new(false),
                concurrent_mutation: Mutex::new(None),
            }
        }

        fn policy_loads(&self) -> usize {
            self.policy_loads.load(Ordering::SeqCst)
        }

        fn take_concurrent_mutation(&self) -> Option<(Arc<MemoryPolicyCache>, String)> {
            match self.concurrent_mutation.lock() {
                Ok(mut slot) => slot.take(),
                Err(_) => panic!("concurrent mutation mutex is poisoned"),
            }
        }
    }

    impl PolicyStore for CountingStore {
        fn authenticate_token_hash<'a>(
            &'a self,
            token_hash: &'a [u8; 32],
        ) -> PolicyStoreFuture<'a, Option<AuthenticatedMember>> {
            self.token_authentications.fetch_add(1, Ordering::SeqCst);
            self.inner.authenticate_token_hash(token_hash)
        }

        fn load_member_repo_policy<'a>(
            &'a self,
            member_id: i64,
            repo_key: &'a str,
        ) -> PolicyStoreFuture<'a, MemberRepoPolicy> {
            Box::pin(async move {
                self.policy_loads.fetch_add(1, Ordering::SeqCst);
                if self.is_failing.load(Ordering::SeqCst) {
                    return Err(PolicyStoreError::Internal("store is down".to_owned()));
                }
                let result = self
                    .inner
                    .load_member_repo_policy(member_id, repo_key)
                    .await;
                if let Some((cache, group)) = self.take_concurrent_mutation() {
                    let mut writer = self.inner.clone();
                    writer.insert_group_membership(member_id, group);
                    if let Err(error) = cache.bump_epoch().await {
                        panic!("bump should succeed: {error}");
                    }
                }
                result
            })
        }

        fn record_audit_event<'a>(&'a self, entry: AuditLogEntry) -> PolicyStoreFuture<'a, ()> {
            self.inner.record_audit_event(entry)
        }

        fn authenticate_ssh_key<'a>(
            &'a self,
            fingerprint: &'a str,
        ) -> PolicyStoreFuture<'a, Option<AuthenticatedMember>> {
            self.ssh_authentications.fetch_add(1, Ordering::SeqCst);
            self.inner.authenticate_ssh_key(fingerprint)
        }
    }

    async fn load(store: &dyn PolicyStore) -> MemberRepoPolicy {
        match store.load_member_repo_policy(ALICE_ID, REPO).await {
            Ok(policy) => policy,
            Err(error) => panic!("policy should load: {error}"),
        }
    }

    async fn epoch(cache: &MemoryPolicyCache) -> u64 {
        match cache.get_epoch().await {
            Ok(epoch) => epoch,
            Err(error) => panic!("epoch should be readable: {error}"),
        }
    }

    async fn cached_bytes(cache: &MemoryPolicyCache, epoch: u64) -> Option<Vec<u8>> {
        match cache
            .get_bytes(&policy_cache_key(epoch, ALICE_ID, REPO))
            .await
        {
            Ok(bytes) => bytes,
            Err(error) => panic!("cache should be readable: {error}"),
        }
    }

    fn assert_same_policy(actual: &MemberRepoPolicy, expected: &MemberRepoPolicy) {
        assert_eq!(actual.member_groups, expected.member_groups);
        assert_eq!(actual.branch_policy.rules(), expected.branch_policy.rules());
        assert_eq!(
            actual.withhold_policy.rules(),
            expected.withhold_policy.rules()
        );
    }

    #[tokio::test]
    async fn cache_hit_avoids_the_inner_store() {
        let counting = Arc::new(CountingStore::new(seeded_memory_store()));
        let cache = Arc::new(MemoryPolicyCache::new());
        let cached = CachedPolicyStore::new(counting.clone(), cache.clone());

        let first = load(&cached).await;
        let second = load(&cached).await;
        assert_eq!(counting.policy_loads(), 1);
        assert_same_policy(&second, &first);
        assert_eq!(second.member_groups, groups(&["dev"]));
        assert!(
            !second
                .branch_policy
                .is_ref_visible("refs/heads/private/x", &groups(&["ops"]))
        );
        assert!(
            second
                .branch_policy
                .is_ref_visible("refs/heads/private/x", &groups(&["dev"]))
        );
        assert!(second.withhold_policy.has_withheld_rules(&groups(&["ops"])));
        assert!(cached_bytes(&cache, 0).await.is_some());
    }

    /// Primes the cache, changes the store behind the cache's back, checks the
    /// stale answer is still served, then runs `mutation` through the cache
    /// and checks it bumped the epoch and the next load sees the change.
    async fn assert_mutation_invalidates<T>(
        cached: &CachedPolicyStore,
        cache: &MemoryPolicyCache,
        backdoor: &mut MemoryPolicyStore,
        step: &str,
        mutation: impl Future<Output = Result<T, PolicyStoreError>>,
    ) -> T {
        let marker = format!("marker-{step}");
        let _ = load(cached).await;
        backdoor.insert_group_membership(ALICE_ID, marker.clone());
        let stale = load(cached).await;
        assert!(
            !stale.member_groups.contains(&marker),
            "{step}: expected a cache hit before the mutation"
        );

        let epoch_before = epoch(cache).await;
        let value = match mutation.await {
            Ok(value) => value,
            Err(error) => panic!("{step}: mutation should succeed: {error}"),
        };
        assert_eq!(epoch(cache).await, epoch_before + 1, "{step}: epoch bump");
        let fresh = load(cached).await;
        assert!(
            fresh.member_groups.contains(&marker),
            "{step}: expected the cached policy to be invalidated"
        );
        value
    }

    #[tokio::test]
    async fn every_mutation_bumps_the_epoch_and_invalidates_policies() {
        let memory = seeded_memory_store();
        let mut backdoor = memory.clone();
        let cache = Arc::new(MemoryPolicyCache::new());
        let cached = CachedPolicyStore::new(Arc::new(memory), cache.clone());
        let c = &cached;
        let k = cache.as_ref();
        let b = &mut backdoor;

        assert_mutation_invalidates(c, k, b, "bootstrap", c.bootstrap_admin("root", "boot")).await;
        assert_mutation_invalidates(
            c,
            k,
            b,
            "register",
            c.register_repository(None, "team/other.git"),
        )
        .await;
        assert_mutation_invalidates(c, k, b, "group", c.create_group(None, "ops")).await;
        let request = CreateMemberRequest {
            name: "bob".to_owned(),
            is_admin: false,
            is_machine: false,
            public_key: None,
            groups: groups(&["ops"]),
            token_label: "laptop".to_owned(),
        };
        assert_mutation_invalidates(c, k, b, "member", c.create_member(None, request)).await;
        assert_mutation_invalidates(c, k, b, "add", c.add_group_member(None, "ops", "alice")).await;
        assert_mutation_invalidates(
            c,
            k,
            b,
            "remove",
            c.remove_group_member(None, "ops", "alice"),
        )
        .await;
        assert_mutation_invalidates(c, k, b, "token", c.issue_member_token(None, "bob", "ci"))
            .await;
        let bob_tokens = match c.list_member_tokens("bob", false).await {
            Ok(tokens) => tokens,
            Err(error) => panic!("list_member_tokens should succeed: {error}"),
        };
        let bob_token_id = match bob_tokens.last() {
            Some(token) => token.id,
            None => panic!("expected issued token for bob"),
        };
        assert_mutation_invalidates(
            c,
            k,
            b,
            "token-revoke",
            c.revoke_member_token(None, "bob", bob_token_id),
        )
        .await;
        assert_mutation_invalidates(
            c,
            k,
            b,
            "age-key",
            c.set_member_public_key(None, "bob", AGE_PUBLIC_KEY),
        )
        .await;
        let ssh_key = assert_mutation_invalidates(
            c,
            k,
            b,
            "ssh-add",
            c.add_member_ssh_key(None, "bob", ED25519_KEY, "laptop"),
        )
        .await;
        assert_mutation_invalidates(
            c,
            k,
            b,
            "ssh-revoke",
            c.revoke_member_ssh_key(None, "bob", ssh_key.id),
        )
        .await;
        assert_mutation_invalidates(
            c,
            k,
            b,
            "branch-set",
            c.set_branch_rule(None, REPO, "refs/heads/ops/*", groups(&["ops"])),
        )
        .await;
        assert_mutation_invalidates(
            c,
            k,
            b,
            "branch-remove",
            c.remove_branch_rule(None, REPO, "refs/heads/ops/*"),
        )
        .await;
        assert_mutation_invalidates(
            c,
            k,
            b,
            "path-set",
            c.set_path_rule(None, REPO, "ops/**", groups(&["ops"])),
        )
        .await;
        assert_mutation_invalidates(
            c,
            k,
            b,
            "path-remove",
            c.remove_path_rule(None, REPO, "ops/**"),
        )
        .await;
        assert_mutation_invalidates(
            c,
            k,
            b,
            "scope-set",
            c.set_secret_scope(None, REPO, "prod", groups(&["ops"])),
        )
        .await;
        assert_mutation_invalidates(
            c,
            k,
            b,
            "scope-remove",
            c.remove_secret_scope(None, REPO, "prod"),
        )
        .await;
        assert_mutation_invalidates(c, k, b, "revoke", c.revoke_member(None, "bob")).await;
        assert_mutation_invalidates(c, k, b, "group-temp", c.create_group(None, "temp-del")).await;
        assert_mutation_invalidates(c, k, b, "group-delete", c.delete_group(None, "temp-del"))
            .await;
        assert_eq!(epoch(k).await, 20);

        // A failed mutation commits nothing and leaves the epoch alone.
        assert!(c.create_group(None, "ops").await.is_err());
        assert_eq!(epoch(k).await, 20);
    }

    #[tokio::test]
    async fn concurrent_mutation_during_a_miss_cannot_install_stale_policy() {
        let counting = Arc::new(CountingStore::new(seeded_memory_store()));
        let cache = Arc::new(MemoryPolicyCache::new());
        let cached = CachedPolicyStore::new(counting.clone(), cache.clone());
        match counting.concurrent_mutation.lock() {
            Ok(mut slot) => *slot = Some((cache.clone(), "late".to_owned())),
            Err(_) => panic!("concurrent mutation mutex is poisoned"),
        }

        let raced = load(&cached).await;
        assert!(!raced.member_groups.contains("late"));
        // The stale answer was written under the old epoch only.
        assert_eq!(epoch(&cache).await, 1);
        assert!(cached_bytes(&cache, 0).await.is_some());
        assert!(cached_bytes(&cache, 1).await.is_none());

        let fresh = load(&cached).await;
        assert!(fresh.member_groups.contains("late"));
        assert_eq!(counting.policy_loads(), 2);
        assert!(cached_bytes(&cache, 1).await.is_some());
    }

    #[tokio::test]
    async fn corrupt_cache_entries_fall_back_to_the_store() {
        let counting = Arc::new(CountingStore::new(seeded_memory_store()));
        let cache = Arc::new(MemoryPolicyCache::new());
        let cached = CachedPolicyStore::new(counting.clone(), cache.clone());
        let expected = load(&cached).await;
        let key = policy_cache_key(0, ALICE_ID, REPO);

        let invalid_rule = br#"{"member_groups":["dev","admin"],"branch_rules":[{"pattern":"refs/heads/[","allowed_groups":["dev"]}],"withhold_rules":[]}"#;
        let oversized = vec![b' '; MAX_CACHED_POLICY_BYTES + 1];
        for (round, corrupt) in [b"not json".to_vec(), invalid_rule.to_vec(), oversized]
            .into_iter()
            .enumerate()
        {
            if let Err(error) = cache.set_bytes(&key, corrupt, 60).await {
                panic!("cache write should succeed: {error}");
            }
            let recovered = load(&cached).await;
            assert_same_policy(&recovered, &expected);
            assert_eq!(counting.policy_loads(), round + 2);
        }
        // The fallback rewrote a valid entry, which now hits.
        let _ = load(&cached).await;
        assert_eq!(counting.policy_loads(), 4);
    }

    #[tokio::test]
    async fn cache_outage_falls_back_while_store_errors_fail_closed() {
        let counting = Arc::new(CountingStore::new(seeded_memory_store()));
        let cache = Arc::new(MemoryPolicyCache::new());
        let cached = CachedPolicyStore::new(counting.clone(), cache.clone());

        cache.set_failing(true);
        let _ = load(&cached).await;
        let _ = load(&cached).await;
        assert_eq!(counting.policy_loads(), 2);

        // Store failures are returned whether or not the cache works, and
        // nothing is cached for them.
        counting.is_failing.store(true, Ordering::SeqCst);
        assert!(
            cached
                .load_member_repo_policy(ALICE_ID, REPO)
                .await
                .is_err()
        );
        cache.set_failing(false);
        assert!(
            cached
                .load_member_repo_policy(ALICE_ID, REPO)
                .await
                .is_err()
        );
        assert!(cached_bytes(&cache, 0).await.is_none());

        // A mutation still commits when the epoch cannot be bumped.
        let memory = seeded_memory_store();
        let observer = memory.clone();
        let cached_memory = CachedPolicyStore::new(Arc::new(memory), cache.clone());
        cache.set_failing(true);
        assert!(cached_memory.create_group(None, "ops").await.is_ok());
        match observer.list_groups().await {
            Ok(listed) => assert!(listed.iter().any(|group| group.name == "ops")),
            Err(error) => panic!("groups should list: {error}"),
        }
    }

    #[tokio::test]
    async fn authentication_always_bypasses_the_cache() {
        let memory = seeded_memory_store();
        let backdoor = memory.clone();
        let counting = Arc::new(CountingStore::new(memory));
        let cache = Arc::new(MemoryPolicyCache::new());
        let cached = CachedPolicyStore::new(counting.clone(), cache.clone());
        let token_hash = sha256_zeroizing(ALICE_TOKEN);
        let ssh_key = match backdoor
            .add_member_ssh_key(None, "alice", ED25519_KEY, "laptop")
            .await
        {
            Ok(record) => record,
            Err(error) => panic!("SSH key should register: {error}"),
        };

        match cached.authenticate_token_hash(&token_hash).await {
            Ok(Some(member)) => assert_eq!(member.id, ALICE_ID),
            other => panic!("alice's token should authenticate: {other:?}"),
        }
        match cached.authenticate_ssh_key(&ssh_key.fingerprint).await {
            Ok(Some(member)) => assert_eq!(member.id, ALICE_ID),
            other => panic!("alice's SSH key should authenticate: {other:?}"),
        }

        // Revoking straight in the store (no epoch bump) applies at once.
        match backdoor
            .revoke_member_ssh_key(None, "alice", ssh_key.id)
            .await
        {
            Ok(revoked) => assert!(revoked),
            Err(error) => panic!("SSH key should revoke: {error}"),
        }
        match cached.authenticate_ssh_key(&ssh_key.fingerprint).await {
            Ok(None) => {}
            other => panic!("a revoked SSH key must not authenticate: {other:?}"),
        }
        match backdoor.revoke_member(None, "alice").await {
            Ok(result) => assert!(result.revoked),
            Err(error) => panic!("alice should revoke: {error}"),
        }
        match cached.authenticate_token_hash(&token_hash).await {
            Ok(None) => {}
            other => panic!("a revoked member's token must not authenticate: {other:?}"),
        }

        assert_eq!(counting.token_authentications.load(Ordering::SeqCst), 2);
        assert_eq!(counting.ssh_authentications.load(Ordering::SeqCst), 2);
        assert_eq!(epoch(&cache).await, 0);
    }

    /// Runs against a real server: `REDIS_URL=redis://127.0.0.1:6379 cargo
    /// test -p scrim-server live_redis -- --ignored`.
    #[tokio::test]
    #[ignore = "needs a Redis server in REDIS_URL"]
    async fn live_redis_round_trip() {
        let redis_url = match std::env::var("REDIS_URL") {
            Ok(redis_url) => zeroize::Zeroizing::new(redis_url),
            Err(_) => panic!("set REDIS_URL to run this test"),
        };
        let redis = match RedisPolicyCache::connect(&redis_url).await {
            Ok(redis) => Arc::new(redis),
            Err(error) => panic!("Redis should connect: {error}"),
        };
        let before = match redis.get_epoch().await {
            Ok(epoch) => epoch,
            Err(error) => panic!("GET should work: {error}"),
        };
        match redis.bump_epoch().await {
            Ok(after) => assert_eq!(after, before + 1),
            Err(error) => panic!("INCR should work: {error}"),
        }

        let counting = Arc::new(CountingStore::new(seeded_memory_store()));
        let cached = CachedPolicyStore::new(counting.clone(), redis.clone()).with_ttl_seconds(30);
        let first = load(&cached).await;
        let second = load(&cached).await;
        assert_same_policy(&second, &first);
        assert_eq!(counting.policy_loads(), 1);
        match redis.bump_epoch().await {
            Ok(_) => {}
            Err(error) => panic!("INCR should work: {error}"),
        }
        let _ = load(&cached).await;
        assert_eq!(counting.policy_loads(), 2);
    }
}
