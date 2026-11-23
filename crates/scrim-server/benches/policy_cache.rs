//! Criterion benchmarks for the per-request policy cache: cache key
//! formatting/hashing, [`MemoryPolicyCache`] hits, cold misses, and
//! epoch-based invalidation, plus an opt-in [`RedisPolicyCache`] group.
//!
//! # Real Redis (opt-in)
//!
//! Set `REDIS_URL` to a `redis://` or `rediss://` URL (for example
//! `REDIS_URL=redis://127.0.0.1:6379`) to also run the `policy_cache_redis`
//! group against a live Redis server. The benchmarks never flush the server;
//! miss benchmarks use unique member IDs with a short TTL, and invalidation
//! increments the shared policy cache epoch key.

// The `?` operator and the unwrap/expect family are deliberately forbidden in
// this codebase; clippy's suggestion to use `?` is allowed away accordingly.
#![allow(clippy::question_mark)]

use std::collections::BTreeSet;
use std::hint::black_box;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use scrim_policy::{BranchRule, WithholdRule};
use scrim_server::{
    AuthenticatedMember, CachedPolicyStore, MemoryPolicyCache, MemoryPolicyStore, PolicyStore,
    RedisPolicyCache, policy_cache_key,
};

const MEMBER_ID: i64 = 1;
const REPO_KEY: &str = "platform/core-services.git";
const CACHE_TTL_SECONDS: u64 = 3_600;
const MISS_TTL_SECONDS: u64 = 30;
const REDIS_URL_ENV: &str = "REDIS_URL";

/// Unwraps a setup or benchmark result, panicking with `context` on failure.
fn must<T, E: std::fmt::Display>(result: Result<T, E>, context: &str) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("{context}: {error}"),
    }
}

fn groups(names: &[&str]) -> BTreeSet<String> {
    names.iter().map(|name| (*name).to_owned()).collect()
}

/// Builds a current-thread Tokio runtime for driving in-memory cache futures.
fn build_current_thread_runtime() -> tokio::runtime::Runtime {
    must(
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build(),
        "build current-thread tokio runtime",
    )
}

/// Builds a multi-thread Tokio runtime so Redis background I/O continues
/// running between Criterion iterations.
fn build_multi_thread_runtime() -> tokio::runtime::Runtime {
    must(
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build(),
        "build multi-thread tokio runtime",
    )
}

/// Seeds a [`MemoryPolicyStore`] with member `alice`, groups, realistic branch
/// rules, and realistic path withholding rules for [`REPO_KEY`].
fn seeded_policy_store(runtime: &tokio::runtime::Runtime) -> MemoryPolicyStore {
    let mut store = MemoryPolicyStore::new();
    store.insert_member(
        AuthenticatedMember {
            id: MEMBER_ID,
            name: "alice".to_owned(),
            is_admin: false,
        },
        b"bench-token-alice",
    );
    store.insert_group_membership(MEMBER_ID, "engineering");
    store.insert_group_membership(MEMBER_ID, "backend");

    for group_name in ["billing", "security", "ops", "release"] {
        must(
            runtime.block_on(store.create_group(None, group_name)),
            "create group",
        );
    }

    let branch_rules = [
        ("refs/heads/private/*", &["engineering", "security"][..]),
        ("refs/heads/release-*", &["release", "ops"][..]),
        ("refs/heads/feature/*/security", &["security"][..]),
        ("refs/tags/internal-*", &["engineering", "ops"][..]),
    ];
    for (pattern, allowed) in branch_rules {
        let rule = must(
            BranchRule::new(pattern, groups(allowed)),
            "valid branch rule",
        );
        store.insert_branch_rule(REPO_KEY, rule);
    }

    let path_rules = [
        ("secrets/**", &["security"][..]),
        ("config/billing/**", &["billing"][..]),
        ("infra/prod/*.toml", &["ops", "security"][..]),
        ("services/payments/**", &["backend", "billing"][..]),
    ];
    for (pattern, allowed) in path_rules {
        let rule = must(
            WithholdRule::new(pattern, groups(allowed)),
            "valid withhold rule",
        );
        store.insert_path_rule(REPO_KEY, rule);
    }

    store
}

fn policy_cache_memory(criterion: &mut Criterion) {
    let runtime = build_current_thread_runtime();
    let store = Arc::new(seeded_policy_store(&runtime));

    let warm_cache = Arc::new(MemoryPolicyCache::new());
    let warm_store = CachedPolicyStore::new(Arc::clone(&store) as Arc<dyn PolicyStore>, warm_cache)
        .with_ttl_seconds(CACHE_TTL_SECONDS);
    must(
        runtime.block_on(warm_store.load_member_repo_policy(MEMBER_ID, REPO_KEY)),
        "warm memory policy cache",
    );

    let mut group = criterion.benchmark_group("policy_cache_memory");

    group.bench_function("policy_cache_key", |bencher| {
        bencher.iter(|| {
            black_box(policy_cache_key(
                black_box(42),
                black_box(MEMBER_ID),
                black_box(REPO_KEY),
            ))
        });
    });

    group.bench_function("memory_store_baseline", |bencher| {
        bencher.iter(|| {
            black_box(must(
                runtime.block_on(store.load_member_repo_policy(MEMBER_ID, REPO_KEY)),
                "memory store baseline",
            ))
        });
    });

    group.bench_function("memory_cache_hit", |bencher| {
        bencher.iter(|| {
            black_box(must(
                runtime.block_on(warm_store.load_member_repo_policy(MEMBER_ID, REPO_KEY)),
                "memory cache hit",
            ))
        });
    });

    group.bench_function("memory_cache_miss_and_populate", |bencher| {
        bencher.iter_batched(
            || {
                let cache = Arc::new(MemoryPolicyCache::new());
                CachedPolicyStore::new(Arc::clone(&store) as Arc<dyn PolicyStore>, cache)
                    .with_ttl_seconds(CACHE_TTL_SECONDS)
            },
            |cached| {
                black_box(must(
                    runtime.block_on(cached.load_member_repo_policy(MEMBER_ID, REPO_KEY)),
                    "memory cache miss and populate",
                ))
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("memory_cache_invalidation_and_reload", |bencher| {
        let updated_groups = groups(&["engineering", "ops"]);
        bencher.iter_batched(
            || {
                let local_store = Arc::new(seeded_policy_store(&runtime));
                let cache = Arc::new(MemoryPolicyCache::new());
                let cached =
                    CachedPolicyStore::new(local_store, cache).with_ttl_seconds(CACHE_TTL_SECONDS);
                must(
                    runtime.block_on(cached.load_member_repo_policy(MEMBER_ID, REPO_KEY)),
                    "prime memory cache before invalidation",
                );
                cached
            },
            |cached| {
                black_box(must(
                    runtime.block_on(async {
                        match cached
                            .set_branch_rule(
                                None,
                                REPO_KEY,
                                "refs/heads/release-*",
                                updated_groups.clone(),
                            )
                            .await
                        {
                            Ok(_) => cached.load_member_repo_policy(MEMBER_ID, REPO_KEY).await,
                            Err(error) => Err(error),
                        }
                    }),
                    "memory cache invalidation and reload",
                ))
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

/// Benchmarks [`RedisPolicyCache`] against `REDIS_URL` if set; skips cleanly
/// when unset.
fn policy_cache_redis(criterion: &mut Criterion) {
    let redis_url = match std::env::var(REDIS_URL_ENV) {
        Ok(url) if !url.is_empty() => url,
        _ => return,
    };

    let runtime = build_multi_thread_runtime();
    let store = Arc::new(seeded_policy_store(&runtime));
    let redis = Arc::new(must(
        runtime.block_on(RedisPolicyCache::connect(&redis_url)),
        "connect RedisPolicyCache",
    ));

    let cached = CachedPolicyStore::new(
        Arc::clone(&store) as Arc<dyn PolicyStore>,
        Arc::clone(&redis) as Arc<dyn scrim_server::PolicyCacheBackend>,
    )
    .with_ttl_seconds(CACHE_TTL_SECONDS);

    // Warm the hit key for the current epoch before measuring cache hits.
    must(
        runtime.block_on(cached.load_member_repo_policy(MEMBER_ID, REPO_KEY)),
        "warm redis policy cache",
    );

    let mut group = criterion.benchmark_group("policy_cache_redis");

    group.bench_function("memory_store_baseline", |bencher| {
        bencher.iter(|| {
            black_box(must(
                runtime.block_on(store.load_member_repo_policy(MEMBER_ID, REPO_KEY)),
                "memory store baseline",
            ))
        });
    });

    group.bench_function("redis_cache_hit", |bencher| {
        bencher.iter(|| {
            black_box(must(
                runtime.block_on(cached.load_member_repo_policy(MEMBER_ID, REPO_KEY)),
                "redis cache hit",
            ))
        });
    });

    // Derive a unique starting member ID so miss benchmarks never collide with
    // existing keys or each other without flushing the Redis instance.
    let now_nanos = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_nanos(),
        Err(_) => 1_000_000,
    };
    let mut miss_member_id = ((now_nanos % 1_000_000_000_000) as i64).saturating_add(1_000);
    let cached_miss = CachedPolicyStore::new(
        Arc::clone(&store) as Arc<dyn PolicyStore>,
        Arc::clone(&redis) as Arc<dyn scrim_server::PolicyCacheBackend>,
    )
    .with_ttl_seconds(MISS_TTL_SECONDS);

    group.bench_function("redis_cache_miss_and_populate", |bencher| {
        bencher.iter(|| {
            miss_member_id = miss_member_id.saturating_add(1);
            black_box(must(
                runtime.block_on(cached_miss.load_member_repo_policy(miss_member_id, REPO_KEY)),
                "redis cache miss and populate",
            ))
        });
    });

    let updated_groups = groups(&["engineering", "ops"]);
    group.bench_function("redis_epoch_invalidation", |bencher| {
        bencher.iter(|| {
            black_box(must(
                runtime.block_on(async {
                    match cached
                        .set_branch_rule(
                            None,
                            REPO_KEY,
                            "refs/heads/release-*",
                            updated_groups.clone(),
                        )
                        .await
                    {
                        Ok(_) => cached.load_member_repo_policy(MEMBER_ID, REPO_KEY).await,
                        Err(error) => Err(error),
                    }
                }),
                "redis epoch invalidation",
            ))
        });
    });

    group.finish();
}

criterion_group!(benches, policy_cache_memory, policy_cache_redis);
criterion_main!(benches);
