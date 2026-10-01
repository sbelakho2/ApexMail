//! Redis-path rate-limiter tests (audit SM12 F16a).
//!
//! The HTTP route harnesses deliberately point Redis at an unreachable port
//! so every sales/api route test exercises the rate limiter's IN-MEMORY
//! FALLBACK — the Redis path production actually uses was never driven from
//! this crate. This suite drives BOTH paths of the real
//! `apexmail_rate_limiter::RedisLimiter`:
//!
//! - `fallback_*` tests run UNCONDITIONALLY against `RedisLimiter::
//!   fallback_only` — the tenant-scoped in-memory fallback (the audit-F5
//!   fix boundary: a Redis outage must not collapse per-tenant isolation).
//! - `redis_*` tests run against a REAL Redis when `TEST_REDIS_URL` is set
//!   (the same workspace convention `schema_contract_tests.rs` uses for
//!   `TEST_DATABASE_URL`), and follow the workspace soft-skip contract when
//!   it is unset: a missing variable prints an explicit skip line in dev
//!   and is a HARD PANIC under the release test mode
//!   (`migrator::test_support::assert_soft_skip_allowed`), never a silent
//!   green.

use std::sync::Arc;

use apexmail_rate_limiter::{RateLimitConfig, RedisLimiter};

fn test_config() -> RateLimitConfig {
    RateLimitConfig::new(10).with_burst(3)
}

/// Unique per-run key prefix so parallel suite re-runs against the same
/// Redis never collide.
fn unique_prefix(test_name: &str) -> String {
    format!(
        "itest:rl:{test_name}:{}:",
        uuid::Uuid::new_v4().simple()
    )
}

/// Resolve TEST_REDIS_URL per the workspace soft-skip contract: `None`
/// means "print an explicit skip line and return" in dev (and never runs,
/// because `assert_soft_skip_allowed` panics first under the release test
/// mode).
async fn test_redis_url(test_name: &str) -> Option<String> {
    migrator::test_support::assert_soft_skip_allowed("TEST_REDIS_URL");
    match std::env::var("TEST_REDIS_URL") {
        Ok(value) if !value.trim().is_empty() => Some(value),
        _ => {
            eprintln!("skipping {test_name}: set TEST_REDIS_URL to run the Redis-path test");
            None
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Fallback-path tests (hermetic — no Redis required)
// ═══════════════════════════════════════════════════════════════════════════

/// THE F5 BOUNDARY: when Redis is unreachable, the fallback must stay
/// per-tenant. One noisy tenant draining its own bucket must leave every
/// other tenant's (and the unscoped default's) budget untouched. The
/// pre-fix single un-keyed `GovernorLimiter` collapsed all callers into
/// one pod-wide bucket and denied tenant-b here.
#[tokio::test]
async fn fallback_tenant_scope_boundary_noisy_tenant_cannot_exhaust_others() {
    let config = RateLimitConfig::new(2).with_burst(2);
    // shares=1 → each tenant's fallback bucket is exactly the burst.
    let limiter = RedisLimiter::fallback_only(&config).with_fallback_shares(1);

    // Tenant A exhausts its whole bucket.
    assert!(
        limiter
            .check_n_for_tenant(Some("tenant-noisy"), 2)
            .await
            .is_allowed(),
        "tenant-noisy may consume its own full burst"
    );
    assert!(
        limiter
            .check_n_for_tenant(Some("tenant-noisy"), 1)
            .await
            .is_denied(),
        "tenant-noisy must be denied once ITS OWN bucket is drained"
    );

    // Tenant B is unaffected — the shared-bucket regression denies this.
    assert!(
        limiter
            .check_n_for_tenant(Some("tenant-b"), 2)
            .await
            .is_allowed(),
        "tenant-b must keep its own isolated fallback budget"
    );
    // The unscoped default bucket is independent of both tenants.
    assert!(
        limiter.check_n_for_tenant(None, 2).await.is_allowed(),
        "the default bucket must not share state with named tenants"
    );
}

/// The pod-share division applies PER TENANT (not just globally): with
/// shares=4 and burst 16, each tenant may admit ~4, not the full 16.
#[tokio::test]
async fn fallback_share_division_bounds_each_tenant_budget() {
    let config = RateLimitConfig::new(100).with_burst(16);
    let limiter = RedisLimiter::fallback_only(&config).with_fallback_shares(4);
    assert_eq!(limiter.fallback_shares(), 4, "configured shares must hold");

    let mut allowed = 0;
    for _ in 0..16 {
        if limiter
            .check_n_for_tenant(Some("tenant-divided"), 1)
            .await
            .is_allowed()
        {
            allowed += 1;
        }
    }
    assert!(
        (4..=5).contains(&allowed),
        "divided fallback must admit ~ceil(16/4)=4 per tenant, got {allowed}"
    );
}

/// RS-054/K2: `peek` when Redis is absent must FAIL OPEN (allow) without
/// consuming fallback budget — a monitoring read must never over-throttle.
#[tokio::test]
async fn fallback_peek_fails_open_and_does_not_consume_budget() {
    let config = RateLimitConfig::new(10).with_burst(2);
    let limiter = RedisLimiter::fallback_only(&config).with_fallback_shares(1);

    assert!(limiter.check().await.is_allowed(), "first token is spendable");
    for _ in 0..10 {
        let peeked = limiter.peek().await;
        assert!(
            peeked.is_allowed(),
            "fallback peek fails open (allow) when Redis is unavailable"
        );
    }
    assert!(
        limiter.check().await.is_allowed(),
        "peeks must not have consumed the last token"
    );
    assert!(limiter.check().await.is_denied(), "burst=2 still holds");
    assert!(
        limiter.is_in_fallback(),
        "a limiter built fallback_only must report fallback mode"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Redis-path tests (TEST_REDIS_URL required)
// ═══════════════════════════════════════════════════════════════════════════

/// Connects to the configured test Redis. `test_redis_url` already applied
/// the soft-skip contract (unset → explicit skip line + `None`); a URL that
/// IS set but unreachable is infrastructure breakage — PANIC with a clear
/// message (never a soft skip), matching how the DB-backed suites treat a
/// configured-but-broken TEST_DATABASE_URL.
async fn connected_limiter(test_name: &str, prefix: &str, url: &str, config: &RateLimitConfig) -> RedisLimiter {
    match RedisLimiter::connect(config, url).await {
        Some(limiter) => limiter.with_prefix(prefix),
        None => panic!(
            "{test_name}: TEST_REDIS_URL is configured but Redis at it is unreachable — \
             start the test Redis or fix the URL (connect returned None)"
        ),
    }
}

/// The production path: the token bucket admits the burst, denies beyond
/// it, reports the ACTUAL remaining tokens, and `reset` clears state.
#[tokio::test]
async fn redis_path_enforces_token_bucket_burst_and_reset() {
    let Some(url) = test_redis_url("redis_path_enforces_token_bucket_burst_and_reset").await
    else {
        return;
    };
    let prefix = unique_prefix("token_bucket");
    let config = test_config(); // burst 3
    let limiter = connected_limiter(
        "redis_path_enforces_token_bucket_burst_and_reset",
        &prefix,
        &url,
        &config,
    )
    .await;
    limiter.reset().await.expect("clean slate");

    for i in 0..3 {
        let decision = limiter.check().await;
        assert!(
            decision.is_allowed(),
            "burst check {} of 3 must be allowed on the Redis path",
            i + 1
        );
    }
    let fourth = limiter.check().await;
    assert!(
        fourth.is_denied(),
        "the 4th check must be denied — the Redis bucket is exhausted"
    );
    // Peek is a read-only reflection of the shared state (fix K2).
    assert!(
        limiter.peek().await.is_denied(),
        "peek must reflect the exhausted bucket without refilling it"
    );

    limiter.reset().await.expect("reset");
    assert!(
        limiter.check().await.is_allowed(),
        "after reset the bucket must admit again"
    );
    limiter.reset().await.expect("final cleanup");
}

/// Tenant scoping on the REAL Redis path: different tenants own different
/// keys, so one tenant's exhaustion never bleeds into another's budget.
#[tokio::test]
async fn redis_path_tenant_keys_are_independent() {
    let Some(url) = test_redis_url("redis_path_tenant_keys_are_independent").await else {
        return;
    };
    let prefix = unique_prefix("tenant_keys");
    let config = test_config();
    let limiter = connected_limiter(
        "redis_path_tenant_keys_are_independent",
        &prefix,
        &url,
        &config,
    )
    .await;
    limiter.reset_for_tenant(Some("tenant-a")).await.expect("clean a");
    limiter.reset_for_tenant(Some("tenant-b")).await.expect("clean b");

    assert!(
        limiter
            .check_n_for_tenant(Some("tenant-a"), 3)
            .await
            .is_allowed(),
        "tenant-a consumes its full burst"
    );
    assert!(
        limiter
            .check_n_for_tenant(Some("tenant-a"), 1)
            .await
            .is_denied(),
        "tenant-a is denied at its own limit"
    );
    assert!(
        limiter
            .check_n_for_tenant(Some("tenant-b"), 3)
            .await
            .is_allowed(),
        "tenant-b must keep an independent Redis bucket"
    );

    limiter.reset_for_tenant(Some("tenant-a")).await.expect("cleanup a");
    limiter.reset_for_tenant(Some("tenant-b")).await.expect("cleanup b");
}

/// Shared-state semantics: a NEW limiter instance (pod restart, another
/// replica) must observe the SAME Redis bucket — state lives in Redis, not
/// in the process.
#[tokio::test]
async fn redis_path_state_survives_new_limiter_instances() {
    let Some(url) = test_redis_url("redis_path_state_survives_new_limiter_instances").await
    else {
        return;
    };
    let prefix = unique_prefix("restart");
    let config = test_config();

    let first = connected_limiter(
        "redis_path_state_survives_new_limiter_instances",
        &prefix,
        &url,
        &config,
    )
    .await;
    first.reset().await.expect("clean slate");
    for _ in 0..3 {
        assert!(first.check().await.is_allowed());
    }
    drop(first);

    // "Restarted pod": a fresh instance over the same key prefix.
    let second = connected_limiter(
        "redis_path_state_survives_new_limiter_instances",
        &prefix,
        &url,
        &config,
    )
    .await;
    let decision = second.check().await;
    assert!(
        decision.is_denied(),
        "the new instance must observe the exhausted shared bucket, got {decision:?}"
    );
    second.reset().await.expect("cleanup");
}

/// Fix #3 boundary: concurrent checks clone the multiplexed
/// ConnectionManager and rely on the Lua script for atomicity — 20 racing
/// tenant checks must all be admitted (burst per fresh tenant) without
/// serializing on any connection-level lock.
#[tokio::test]
async fn redis_path_concurrent_checks_share_the_multiplexed_connection() {
    let Some(url) =
        test_redis_url("redis_path_concurrent_checks_share_the_multiplexed_connection").await
    else {
        return;
    };
    let prefix = unique_prefix("concurrent");
    let config = test_config();
    let limiter = Arc::new(
        connected_limiter(
            "redis_path_concurrent_checks_share_the_multiplexed_connection",
            &prefix,
            &url,
            &config,
        )
        .await,
    );

    let handles: Vec<_> = (0..20u32)
        .map(|t| {
            let l = Arc::clone(&limiter);
            tokio::spawn(async move {
                l.check_n_for_tenant(Some(&format!("tenant-{t}")), 1)
                    .await
                    .is_allowed()
            })
        })
        .collect();
    let mut allowed = 0;
    for h in handles {
        assert!(h.await.expect("check task must not panic"), "fresh tenant check");
        allowed += 1;
    }
    assert_eq!(allowed, 20, "all concurrent distinct-tenant checks pass");
    limiter.reset().await.expect("cleanup");
}
