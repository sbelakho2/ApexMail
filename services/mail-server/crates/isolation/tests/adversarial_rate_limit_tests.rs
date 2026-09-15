//! Adversarial rate-limit tests: exact N/N+1 boundaries, atomic resource
//! limits, quota metrics, and fail-closed behaviour when Redis is down.
//!
//! Redis is skipped only when `TEST_REDIS_URL` is unset; a configured but
//! unreachable Redis must yield errors (never an allow).

use isolation::config::QuotaConfig;
use isolation::rate_limit::{workspace_api_rate_limit_key_parts, RateLimitService};
use isolation::types::{RateLimitConfig, TokenBucketConfig};
use uuid::Uuid;

fn redis_pool() -> Option<deadpool_redis::Pool> {
    let url = std::env::var("TEST_REDIS_URL").ok()?;
    if url.trim().is_empty() {
        return None;
    }
    let cfg = deadpool_redis::Config::from_url(url);
    Some(
        cfg.create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .expect("redis pool config"),
    )
}

fn unreachable_pool() -> deadpool_redis::Pool {
    let cfg = deadpool_redis::Config::from_url("redis://127.0.0.1:1");
    cfg.create_pool(Some(deadpool_redis::Runtime::Tokio1))
        .expect("pool config")
}

fn test_config(max_requests: i64) -> RateLimitConfig {
    RateLimitConfig {
        window_ms: 60_000,
        max_requests,
        burst_limit: None,
        key_prefix: Some("advtest".to_string()),
    }
}

fn quota() -> QuotaConfig {
    QuotaConfig {
        api_requests_per_minute: 3,
        emails_per_month: 2,
        webhooks_per_month: 2,
        contacts_limit: 2,
        templates_limit: 2,
        domains_limit: 2,
        storage_bytes: 100,
    }
}

#[tokio::test]
async fn sliding_window_boundary_is_exactly_n_then_refused() {
    let Some(pool) = redis_pool() else {
        eprintln!("skipping: TEST_REDIS_URL is not configured");
        return;
    };
    let service = RateLimitService::new(pool);
    let key = format!("adv-boundary-{}", Uuid::new_v4().simple());
    let config = test_config(3);

    // Requests 1..=N are allowed with a shrinking remainder.
    for expected_remaining in (0..3).rev() {
        let result = service
            .check_rate_limit(&key, &config)
            .await
            .expect("allowed request");
        assert!(result.allowed, "{result:?}");
        assert_eq!(result.remaining, expected_remaining);
        assert_eq!(result.limit, 3);
        assert!(result.retry_after.is_none());
    }
    // Request N+1 is refused with a retry hint.
    let refused = service
        .check_rate_limit(&key, &config)
        .await
        .expect("refused request");
    assert!(!refused.allowed, "{refused:?}");
    assert_eq!(refused.remaining, 0);
    assert!(refused.retry_after.is_some());
    // The status endpoint reports the same truth as enforcement.
    let status = service
        .get_rate_limit_status(&key, &config)
        .await
        .expect("status");
    assert!(!status.allowed);
    assert_eq!(status.remaining, 0);
    // Reset clears the window and the next request is allowed again.
    service
        .reset_rate_limit(&key, config.key_prefix.as_deref())
        .await
        .expect("reset");
    assert!(
        service
            .check_rate_limit(&key, &config)
            .await
            .expect("after reset")
            .allowed
    );
}

#[tokio::test]
async fn token_bucket_refuses_after_capacity_and_never_refills_a_zero_rate() {
    let Some(pool) = redis_pool() else {
        eprintln!("skipping: TEST_REDIS_URL is not configured");
        return;
    };
    let service = RateLimitService::new(pool);
    let key = format!("adv-bucket-{}", Uuid::new_v4().simple());
    let config = TokenBucketConfig {
        capacity: 2,
        refill_rate: 0.0,
        refill_interval_ms: 60_000,
    };

    assert!(
        service
            .check_token_bucket(&key, &config, 1)
            .await
            .expect("token 1")
            .allowed
    );
    assert!(
        service
            .check_token_bucket(&key, &config, 1)
            .await
            .expect("token 2")
            .allowed
    );
    let refused = service
        .check_token_bucket(&key, &config, 1)
        .await
        .expect("token 3");
    assert!(!refused.allowed, "{refused:?}");
    assert!(refused.retry_after.is_some());
    // A zero-token request is a no-op (never consumes).
    assert!(
        service
            .check_token_bucket(&key, &config, 0)
            .await
            .expect("zero tokens")
            .allowed
    );
}

#[tokio::test]
async fn workspace_quota_boundaries_are_atomic_and_metric_scoped() {
    let Some(pool) = redis_pool() else {
        eprintln!("skipping: TEST_REDIS_URL is not configured");
        return;
    };
    let raw = pool.clone();
    let service = RateLimitService::new(pool);
    let workspace = format!("adv-ws-{}", Uuid::new_v4().simple());
    let quota = quota();

    // api_requests_per_minute: exactly 3 then refused.
    for _ in 0..3 {
        assert!(
            service
                .check_workspace_quota(&workspace, "api_requests_per_minute", &quota, 1)
                .await
                .expect("api quota")
                .allowed
        );
    }
    let api_key = workspace_api_rate_limit_key_parts(&workspace).0;
    let refused = service
        .check_workspace_quota(&workspace, "api_requests_per_minute", &quota, 1)
        .await
        .expect("api quota refused");
    assert!(!refused.allowed);
    assert!(api_key.contains(&workspace), "key must be workspace-scoped");

    // emails_per_month is a separate counter: still allowed.
    assert!(
        service
            .check_workspace_quota(&workspace, "emails_per_month", &quota, 1)
            .await
            .expect("email quota")
            .allowed
    );
    assert!(
        service
            .check_workspace_quota(&workspace, "emails_per_month", &quota, 1)
            .await
            .expect("email quota 2")
            .allowed
    );
    assert!(
        !service
            .check_workspace_quota(&workspace, "emails_per_month", &quota, 1)
            .await
            .expect("email quota 3")
            .allowed
    );

    // Resource metrics are atomic increment-under-limit: 2 contacts, the
    // third is refused, and a refused increment must not move the counter.
    for _ in 0..2 {
        assert!(
            service
                .check_workspace_quota(&workspace, "contacts", &quota, 1)
                .await
                .expect("contact quota")
                .allowed
        );
    }
    assert!(
        !service
            .check_workspace_quota(&workspace, "contacts", &quota, 1)
            .await
            .expect("contact quota refused")
            .allowed
    );
    let mut conn = raw.get().await.expect("raw redis");
    let current: Option<i64> = redis::cmd("GET")
        .arg(format!("workspace:{workspace}:resource:contacts"))
        .query_async(&mut conn)
        .await
        .expect("read counter");
    assert_eq!(
        current,
        Some(2),
        "a refused increment must not consume headroom"
    );

    // An unknown metric is an error, not a silent allow.
    assert!(service
        .check_workspace_quota(&workspace, "unicorn_requests", &quota, 1)
        .await
        .is_err());
}

#[tokio::test]
async fn resource_counters_never_go_negative() {
    let Some(pool) = redis_pool() else {
        eprintln!("skipping: TEST_REDIS_URL is not configured");
        return;
    };
    let raw = pool.clone();
    let service = RateLimitService::new(pool);
    let workspace = format!("adv-count-{}", Uuid::new_v4().simple());

    assert_eq!(
        service
            .increment_resource_count(&workspace, "templates", 3)
            .await
            .expect("incr"),
        3
    );
    assert_eq!(
        service
            .decrement_resource_count(&workspace, "templates", 10)
            .await
            .expect("decr"),
        0,
        "decrement saturates at zero"
    );
    service
        .set_resource_count(&workspace, "domains", 7)
        .await
        .expect("set");
    let mut conn = raw.get().await.expect("raw redis");
    let domains: Option<i64> = redis::cmd("GET")
        .arg(format!("workspace:{workspace}:resource:domains"))
        .query_async(&mut conn)
        .await
        .expect("read domains");
    assert_eq!(domains, Some(7));
}

#[tokio::test]
async fn unreachable_redis_fails_closed_for_every_operation() {
    let service = RateLimitService::new(unreachable_pool());
    let config = test_config(10);
    let bucket = TokenBucketConfig {
        capacity: 1,
        refill_rate: 1.0,
        refill_interval_ms: 1000,
    };
    let quota = quota();

    // Every enforcement path returns an error — the caller must treat that
    // as a denial, never as an allow.
    assert!(service.check_rate_limit("k", &config).await.is_err());
    assert!(service.check_token_bucket("k", &bucket, 1).await.is_err());
    assert!(service
        .check_workspace_quota("ws", "api_requests_per_minute", &quota, 1)
        .await
        .is_err());
    assert!(service
        .check_workspace_quota("ws", "contacts", &quota, 1)
        .await
        .is_err());
    assert!(service.get_rate_limit_status("k", &config).await.is_err());
    assert!(service
        .reset_rate_limit("k", Some("advtest"))
        .await
        .is_err());
    assert!(service
        .increment_resource_count("ws", "contacts", 1)
        .await
        .is_err());
    assert!(service
        .decrement_resource_count("ws", "contacts", 1)
        .await
        .is_err());
    assert!(service
        .set_resource_count("ws", "contacts", 1)
        .await
        .is_err());
}
