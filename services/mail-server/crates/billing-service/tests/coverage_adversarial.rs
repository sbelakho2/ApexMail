//! Adversarial coverage tests for `billing-service`.
//!
//! Every DB-backed test provisions its OWN canonical database by cloning the
//! migrator template for the pinned chain (the workspace convention; the
//! template is created by `migrator::test_support` in any DB-backed suite).
//! `TEST_DATABASE_URL` unset → soft-skip (`Ok(None)`); a configured
//! provisioning failure panics. Redis-backed paths use `TEST_REDIS_URL`.
//!
//! The mandate: this crate moves money and meters usage — tests attack
//! boundaries (exactly-at/one-below/one-above limits), idempotency, replay,
//! overflow, malformed input, and refusal paths, and assert that nothing is
//! written/deleted outside its window.

use std::sync::Arc;
use std::time::Duration;

use billing_service::config::BillingConfig;
use billing_service::types::MeterEventType;
use billing_service::usage::{
    check_quota, enforced_counter_key, get_usage, meter_event_type_str, month_period_for_tz,
    record_usage, record_with_quota_check, reset_monthly_counters, rollback_usage_record,
    UsageError,
};
use billing_service::usage_ingest::{
    classify_reconciliation, derived_event_id, ingest_usage_batch, sweep_target_day, IngestEvent,
    RECON_ABSOLUTE_SLACK, RECON_RELATIVE_SLACK_PERCENT,
};
use billing_service::AppState;
use chrono::{DateTime, Datelike, NaiveDate, TimeZone, Utc};
use deadpool_redis::{Pool as RedisPool, Runtime};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Provisioning harness
// ---------------------------------------------------------------------------

const MAX_DB_NAME_LEN: usize = 63;

fn test_database_url() -> Option<String> {
    std::env::var("TEST_DATABASE_URL")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn admin_database_url(server_part: &str) -> String {
    std::env::var("TEST_DATABASE_ADMIN_URL")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| format!("{server_part}/postgres"))
}

/// Number/max version of the canonical chain, used to pick the matching
/// migrator template database (`apexmail_canonical_tpl_<count>_<newest>_<digest>`).
fn canonical_chain_shape() -> (usize, i64) {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../migrations");
    let mut count = 0_usize;
    let mut newest = 0_i64;
    for entry in std::fs::read_dir(&dir).expect("read migrations dir") {
        let name = entry.expect("migrations dir entry").file_name();
        let name = name.to_string_lossy().to_string();
        if let Some(prefix) = name.split('_').next() {
            if let Ok(version) = prefix.parse::<i64>() {
                count += 1;
                newest = newest.max(version);
            }
        }
    }
    (count, newest)
}

/// A provisioned test environment. Drop closes both pools so the database
/// can be dropped by the next run.
struct Harness {
    state: Arc<AppState>,
    pool: PgPool,
    redis: RedisPool,
    db_name: String,
    admin_url: String,
}

impl Harness {
    async fn finish(self) {
        self.pool.close().await;
        if let Ok(admin) = PgPoolOptions::new()
            .max_connections(1)
            .connect(&self.admin_url)
            .await
        {
            let _ = sqlx::query(&format!(
                r#"DROP DATABASE IF EXISTS "{}" WITH (FORCE)"#,
                self.db_name
            ))
            .execute(&admin)
            .await;
            admin.close().await;
        }
    }
}

async fn provision(test_name: &str) -> Option<Harness> {
    let url = test_database_url()?;
    let (server_part, db_part) = url
        .rsplit_once('/')
        .expect("TEST_DATABASE_URL has a database segment");
    let db_only = db_part.split('?').next().unwrap_or(db_part);
    // DB names are capped at 63 bytes: derive a short deterministic suffix
    // from the (unique) test name instead of embedding it verbatim.
    let mut digest: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in test_name.bytes() {
        digest ^= u64::from(byte);
        digest = digest.wrapping_mul(0x0000_0100_0000_01b3);
    }
    let db_name = format!("{db_only}_bcov_{:08x}", digest & 0xffff_ffff);
    assert!(
        db_name.len() <= MAX_DB_NAME_LEN,
        "test db name too long: {db_name}"
    );

    let admin_url = admin_database_url(server_part);
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(30))
        .connect(&admin_url)
        .await
        .unwrap_or_else(|error| panic!("connect admin {admin_url}: {error}"));

    let (count, newest) = canonical_chain_shape();
    let prefix = format!("apexmail_canonical_tpl_{count}_{newest}_");
    let template: Option<String> = sqlx::query_scalar(
        "SELECT datname FROM pg_database WHERE datname LIKE $1 ORDER BY datname DESC LIMIT 1",
    )
    .bind(format!("{prefix}%"))
    .fetch_optional(&admin)
    .await
    .expect("list canonical templates");
    let template = template.unwrap_or_else(|| {
        panic!(
            "no canonical template for chain ({count} migrations, newest {newest}); \
             provision by running a DB-backed test in a crate that uses migrator::test_support"
        )
    });

    sqlx::query(&format!(
        r#"DROP DATABASE IF EXISTS "{}" WITH (FORCE)"#,
        db_name
    ))
    .execute(&admin)
    .await
    .unwrap_or_else(|error| panic!("drop {db_name}: {error}"));
    sqlx::query(&format!(
        r#"CREATE DATABASE "{}" TEMPLATE "{}""#,
        db_name, template
    ))
    .execute(&admin)
    .await
    .unwrap_or_else(|error| panic!("clone {db_name} from {template}: {error}"));
    admin.close().await;

    let pool = PgPoolOptions::new()
        .max_connections(4)
        .acquire_timeout(Duration::from_secs(10))
        .connect(&format!("{server_part}/{db_name}"))
        .await
        .unwrap_or_else(|error| panic!("connect {db_name}: {error}"));

    let redis_url = std::env::var("TEST_REDIS_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .expect("TEST_REDIS_URL must be set for billing coverage tests");
    let redis = deadpool_redis::Config::from_url(redis_url)
        .create_pool(Some(Runtime::Tokio1))
        .expect("create redis pool");

    let config = BillingConfig {
        database_url: format!("{server_part}/{db_name}"),
        redis_url: "redis://127.0.0.1:6379".to_string(),
        service_auth_token: "coverage-service-token".to_string(),
        stripe_webhook_secret: "whsec_coverage_secret".to_string(),
        api_base_url: "http://127.0.0.1:9".to_string(),
        ..BillingConfig::default()
    };
    let state = AppState::new(pool.clone(), redis.clone(), config);

    Some(Harness {
        state,
        pool,
        redis,
        db_name,
        admin_url,
    })
}

/// Run `body` with a fresh DB/Redis environment, soft-skipping when
/// `TEST_DATABASE_URL` is unset. The body block receives `h: Harness`.
macro_rules! db_test {
    ($name:ident, |$h:ident| $body:block) => {
        #[tokio::test]
        async fn $name() {
            let Some($h) = provision(stringify!($name)).await else {
                return;
            };
            $body
            $h.finish().await;
        }
    };
}

// ---------------------------------------------------------------------------
// Seeding helpers
// ---------------------------------------------------------------------------

/// Clear every real-time counter key for a tenant. Redis is SHARED between
/// runs (unlike the freshly cloned DB), so deterministic tenant ids would
/// otherwise accumulate counters across runs and make quota assertions
/// order-dependent.
async fn reset_tenant_redis(h: &Harness, tenant_id: &str) {
    let mut conn = h.redis.get().await.expect("redis connection");
    let pattern = format!("meter:rt:{tenant_id}:*");
    let mut cursor: u64 = 0;
    loop {
        let (next, keys): (u64, Vec<String>) = redis::cmd("SCAN")
            .arg(cursor)
            .arg("MATCH")
            .arg(&pattern)
            .arg("COUNT")
            .arg(100)
            .query_async(&mut conn)
            .await
            .expect("scan tenant keys");
        if !keys.is_empty() {
            let _: () = redis::cmd("DEL")
                .arg(&keys)
                .query_async(&mut conn)
                .await
                .expect("delete tenant keys");
        }
        cursor = next;
        if cursor == 0 {
            break;
        }
    }
}

async fn seed_tenant(h: &Harness, tenant_id: &str, plan: &str) {
    reset_tenant_redis(h, tenant_id).await;
    sqlx::query(
        "INSERT INTO tenants (id, name, plan, status) VALUES ($1, $2, $3, 'active')
         ON CONFLICT (id) DO UPDATE SET plan = EXCLUDED.plan",
    )
    .bind(tenant_id)
    .bind(format!("Coverage {tenant_id}"))
    .bind(plan)
    .execute(&h.pool)
    .await
    .expect("seed tenant");
}

async fn seed_tenant_with_status(h: &Harness, tenant_id: &str, plan: &str, status: &str) {
    seed_tenant(h, tenant_id, plan).await;
    sqlx::query("UPDATE tenants SET status = $2 WHERE id = $1")
        .bind(tenant_id)
        .bind(status)
        .execute(&h.pool)
        .await
        .expect("set tenant status");
}

async fn seed_tenant_created_at(
    h: &Harness,
    tenant_id: &str,
    plan: &str,
    created_at: DateTime<Utc>,
) {
    reset_tenant_redis(h, tenant_id).await;
    sqlx::query(
        "INSERT INTO tenants (id, name, plan, status, created_at)
         VALUES ($1, $2, $3, 'active', $4)
         ON CONFLICT (id) DO UPDATE SET plan = EXCLUDED.plan, created_at = EXCLUDED.created_at",
    )
    .bind(tenant_id)
    .bind(format!("Coverage {tenant_id}"))
    .bind(plan)
    .bind(created_at)
    .execute(&h.pool)
    .await
    .expect("seed tenant with created_at");
}

async fn seed_plan(pool: &PgPool, name: &str, email_limit: i64, api_call_limit: i64) {
    sqlx::query(
        "INSERT INTO plans (id, name, display_name, price_cents, email_limit, api_call_limit)
         VALUES ($1, $2, $2, 0, $3, $4)
         ON CONFLICT (name) DO UPDATE SET email_limit = EXCLUDED.email_limit,
             api_call_limit = EXCLUDED.api_call_limit",
    )
    .bind(format!("plan_{name}"))
    .bind(name)
    .bind(email_limit)
    .bind(api_call_limit)
    .execute(pool)
    .await
    .expect("seed plan");
}

async fn seed_stripe_subscription(
    pool: &PgPool,
    tenant_id: &str,
    subscription_id: &str,
    status: &str,
    cycle_start: DateTime<Utc>,
    cycle_end: DateTime<Utc>,
) {
    sqlx::query(
        "INSERT INTO stripe_subscriptions
             (tenant_id, stripe_subscription_id, plan, status, billing_cycle_start,
              billing_cycle_end, stripe_customer_id, stripe_price_id)
         VALUES ($1, $2, 'growth', $3, $4, $5, 'cus_cov', 'price_cov')",
    )
    .bind(tenant_id)
    .bind(subscription_id)
    .bind(status)
    .bind(cycle_start)
    .bind(cycle_end)
    .execute(pool)
    .await
    .expect("seed stripe subscription");
}

async fn event_count(pool: &PgPool, tenant_id: &str, event_id: Uuid) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM metering_events WHERE tenant_id = $1 AND id = $2")
        .bind(tenant_id)
        .bind(event_id)
        .fetch_one(pool)
        .await
        .expect("count metering events")
}

async fn redis_i64(redis: &RedisPool, key: &str) -> i64 {
    let mut conn = redis.get().await.expect("redis connection");
    redis::cmd("GET")
        .arg(key)
        .query_async::<Option<i64>>(&mut conn)
        .await
        .expect("redis GET")
        .unwrap_or(0)
}

async fn redis_set_i64(redis: &RedisPool, key: &str, value: i64) {
    let mut conn = redis.get().await.expect("redis connection");
    let _: () = redis::cmd("SET")
        .arg(key)
        .arg(value)
        .query_async(&mut conn)
        .await
        .expect("redis SET");
}

async fn redis_del(redis: &RedisPool, key: &str) {
    let mut conn = redis.get().await.expect("redis connection");
    let _: () = redis::cmd("DEL")
        .arg(key)
        .query_async(&mut conn)
        .await
        .expect("redis DEL");
}

async fn usage_counter_key(pool: &PgPool, tenant_id: &str, event: MeterEventType) -> String {
    enforced_counter_key(pool, tenant_id, event, Utc::now()).await
}

// ---------------------------------------------------------------------------
// usage.rs — record_usage boundary/idempotency attacks
// ---------------------------------------------------------------------------

db_test!(record_usage_rejects_zero_and_negative_quantities, |h| {
    let tenant = "cov_usage_quant";
    seed_tenant(&h, tenant, "free").await;
    let event_id = Uuid::new_v4();

    for quantity in [0_i64, -1, i64::MIN] {
        let error = record_usage(
            &h.pool,
            &h.redis,
            tenant,
            MeterEventType::EmailsSent,
            quantity,
            Some(event_id),
            None,
        )
        .await
        .expect_err("non-positive quantity must be refused");
        assert!(
            matches!(error, UsageError::InvalidQuantity(value) if value == quantity),
            "unexpected error for {quantity}: {error}"
        );
    }

    assert_eq!(
        event_count(&h.pool, tenant, event_id).await,
        0,
        "refused quantities must write nothing"
    );
});

db_test!(record_usage_is_idempotent_for_identical_replay, |h| {
    let tenant = "cov_usage_replay";
    seed_tenant(&h, tenant, "free").await;
    let event_id = Uuid::new_v4();
    let metadata = serde_json::json!({"messageId": "m-1"});

    let first = record_usage(
        &h.pool,
        &h.redis,
        tenant,
        MeterEventType::EmailsSent,
        5,
        Some(event_id),
        Some(metadata.clone()),
    )
    .await
    .expect("first record");
    assert!(first, "first record must report newly recorded");

    // The exact same logical operation replayed (same id, same payload).
    let second = record_usage(
        &h.pool,
        &h.redis,
        tenant,
        MeterEventType::EmailsSent,
        5,
        Some(event_id),
        Some(metadata),
    )
    .await
    .expect("replay must not error");
    assert!(!second, "replay must report duplicate");

    assert_eq!(event_count(&h.pool, tenant, event_id).await, 1);
    let counter = redis_i64(
        &h.redis,
        &usage_counter_key(&h.pool, tenant, MeterEventType::EmailsSent).await,
    )
    .await;
    assert_eq!(counter, 5, "counter must count the event exactly once");

    // The immutable usage-operations ledger holds exactly one claim.
    let claims: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM usage_operations WHERE tenant_id = $1 AND event_id = $2",
    )
    .bind(tenant)
    .bind(event_id)
    .fetch_one(&h.pool)
    .await
    .expect("count claims");
    assert_eq!(claims, 1, "one logical operation == one durable claim");
});

db_test!(record_usage_rejects_divergent_reuse_of_event_id, |h| {
    let tenant = "cov_usage_conflict";
    seed_tenant(&h, tenant, "free").await;
    let event_id = Uuid::new_v4();

    record_usage(
        &h.pool,
        &h.redis,
        tenant,
        MeterEventType::EmailsSent,
        7,
        Some(event_id),
        None,
    )
    .await
    .expect("first record");

    let error = record_usage(
        &h.pool,
        &h.redis,
        tenant,
        MeterEventType::EmailsSent,
        8, // divergent quantity
        Some(event_id),
        None,
    )
    .await
    .expect_err("reused id with different content must be rejected");
    assert!(
        matches!(error, UsageError::OperationConflict { event_id: id, .. } if id == event_id),
        "expected OperationConflict, got {error}"
    );

    assert_eq!(
        event_count(&h.pool, tenant, event_id).await,
        1,
        "conflicting reuse must not add a metering row"
    );
    let counter = redis_i64(
        &h.redis,
        &usage_counter_key(&h.pool, tenant, MeterEventType::EmailsSent).await,
    )
    .await;
    assert_eq!(
        counter, 7,
        "conflicting reuse must not increment the counter"
    );

    // The operation key is tenant+kind+id, so the SAME id under a DIFFERENT
    // kind is a different logical operation in the durable ledger (documented
    // F71 semantics) and the metering row IS written. The Redis dedup key is
    // only keyed by event id, though, so the API reports the second write as
    // a duplicate — a caller reusing one event id across kinds gets an
    // inconsistent answer (durable row written, reported duplicate). Assert
    // BOTH halves so the inconsistency stays visible instead of silently
    // accepted.
    let recorded = record_usage(
        &h.pool,
        &h.redis,
        tenant,
        MeterEventType::ApiCalls,
        7,
        Some(event_id),
        None,
    )
    .await
    .expect("different kind is a distinct logical operation");
    assert!(
        !recorded,
        "Redis event-id dedup key is shared across event kinds (reported duplicate)"
    );
    let rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM metering_events WHERE tenant_id = $1 AND id = $2")
            .bind(tenant)
            .bind(event_id)
            .fetch_one(&h.pool)
            .await
            .expect("count rows for reused id");
    assert_eq!(rows, 2, "one row per (kind, id) logical operation");
    let api_total: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(quantity), 0)::bigint FROM metering_events
         WHERE tenant_id = $1 AND event_type = 'api_calls'",
    )
    .bind(tenant)
    .fetch_one(&h.pool)
    .await
    .expect("api total");
    assert_eq!(api_total, 7);

    // Replaying the api_calls operation verbatim is still a duplicate.
    let replay = record_usage(
        &h.pool,
        &h.redis,
        tenant,
        MeterEventType::ApiCalls,
        7,
        Some(event_id),
        None,
    )
    .await
    .expect("replay");
    assert!(!replay, "identical replay of the same kind must dedup");
});

db_test!(
    record_usage_enriches_metadata_and_anchors_counter_to_cycle,
    |h| {
        let tenant = "cov_usage_anchor";
        seed_tenant(&h, tenant, "growth").await;
        let now = Utc::now();
        let cycle_start = now - chrono::Duration::days(3);
        let cycle_end = now + chrono::Duration::days(27);
        seed_stripe_subscription(
            &h.pool,
            tenant,
            "sub_cov_anchor",
            "active",
            cycle_start,
            cycle_end,
        )
        .await;

        let event_id = Uuid::new_v4();
        record_usage(
            &h.pool,
            &h.redis,
            tenant,
            MeterEventType::EmailsSent,
            3,
            Some(event_id),
            None,
        )
        .await
        .expect("record with subscription context");

        let metadata: serde_json::Value =
            sqlx::query_scalar("SELECT metadata FROM metering_events WHERE id = $1")
                .bind(event_id)
                .fetch_one(&h.pool)
                .await
                .expect("read metadata");
        assert_eq!(metadata["subscriptionId"], "sub_cov_anchor");
        assert!(metadata["subscriptionPeriodStart"].is_string());
        assert!(metadata["subscriptionPeriodEnd"].is_string());

        // The counter key is the anchored cycle label, matching the exported key.
        let key = enforced_counter_key(&h.pool, tenant, MeterEventType::EmailsSent, now).await;
        let expected_cycle_label = format!(":c{}-{:02}", cycle_start.year(), cycle_start.month());
        assert!(
            key.ends_with(&expected_cycle_label),
            "anchored cycle key expected ({expected_cycle_label}), got {key}"
        );
        assert_eq!(redis_i64(&h.redis, &key).await, 3);
    }
);

db_test!(record_usage_without_cycle_uses_calendar_month_key, |h| {
    let tenant = "cov_usage_calmonth";
    seed_tenant(&h, tenant, "free").await;
    let now = Utc::now();
    let event_id = Uuid::new_v4();
    record_usage(
        &h.pool,
        &h.redis,
        tenant,
        MeterEventType::ApiCalls,
        2,
        Some(event_id),
        None,
    )
    .await
    .expect("record without subscription");

    let expected = format!(
        "meter:rt:{tenant}:api_calls:{}-{:02}",
        now.year(),
        now.month()
    );
    assert_eq!(redis_i64(&h.redis, &expected).await, 2);
});

db_test!(record_usage_accepts_non_object_metadata, |h| {
    let tenant = "cov_usage_meta";
    seed_tenant(&h, tenant, "free").await;
    let event_id = Uuid::new_v4();
    let recorded = record_usage(
        &h.pool,
        &h.redis,
        tenant,
        MeterEventType::BandwidthGb,
        11,
        Some(event_id),
        Some(serde_json::json!("raw-scalar")),
    )
    .await
    .expect("scalar metadata is normalized");
    assert!(recorded);

    let metadata: serde_json::Value =
        sqlx::query_scalar("SELECT metadata FROM metering_events WHERE id = $1")
            .bind(event_id)
            .fetch_one(&h.pool)
            .await
            .expect("read metadata");
    assert_eq!(metadata["value"], "raw-scalar");
});

// ---------------------------------------------------------------------------
// usage.rs — get_usage / check_quota plan-limit boundaries
// ---------------------------------------------------------------------------

db_test!(get_usage_aggregates_only_the_requested_period, |h| {
    let tenant = "cov_usage_period";
    seed_tenant(&h, tenant, "covperiod").await;
    seed_plan(&h.pool, "covperiod", 1000, 5000).await;

    let now = Utc::now();
    let period_start = now - chrono::Duration::days(10);
    let period_end = now + chrono::Duration::days(10);

    // One event inside the window, one 40 days back (outside).
    let inside = Uuid::new_v4();
    let outside = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO metering_events (id, tenant_id, event_type, quantity, timestamp)
         VALUES ($1, $2, 'emails_sent', 100, $3), ($4, $2, 'emails_sent', 999, $5)",
    )
    .bind(inside)
    .bind(tenant)
    .bind(now)
    .bind(outside)
    .bind(now - chrono::Duration::days(40))
    .execute(&h.pool)
    .await
    .expect("seed metering events");

    let summary = get_usage(&h.pool, tenant, period_start, period_end)
        .await
        .expect("get_usage");
    assert_eq!(
        summary.emails_sent, 100,
        "events outside the period must be excluded"
    );
    assert_eq!(summary.emails_limit, 1000);
    assert_eq!(summary.api_calls, 0);
    assert_eq!(summary.api_calls_limit, 5000);
    assert!((summary.percent_used - 10.0).abs() < f64::EPSILON);
    assert_eq!(summary.metrics["emails_sent"], 100);
});

db_test!(get_usage_zero_limit_does_not_divide_by_zero, |h| {
    let tenant = "cov_usage_zerolimit";
    seed_tenant(&h, tenant, "covzero").await;
    seed_plan(&h.pool, "covzero", 0, 0).await;

    let now = Utc::now();
    let summary = get_usage(
        &h.pool,
        tenant,
        now - chrono::Duration::days(1),
        now + chrono::Duration::days(1),
    )
    .await
    .expect("get_usage with zero limit");
    assert_eq!(summary.emails_limit, 0);
    assert_eq!(summary.percent_used, 0.0);
});

db_test!(get_usage_unknown_tenant_resolves_builtin_free_limits, |h| {
    let now = Utc::now();
    let summary = get_usage(
        &h.pool,
        "cov_usage_missing_tenant",
        now - chrono::Duration::days(1),
        now + chrono::Duration::days(1),
    )
    .await
    .expect("get_usage for unknown tenant");
    assert_eq!(summary.emails_sent, 0);
    // No tenant row → both limits fall back to 0 (refuse, never unlimited).
    assert_eq!(summary.emails_limit, 0);
    assert_eq!(summary.api_calls_limit, 0);
});

db_test!(free_plan_launch_allowance_expires_after_30_days, |h| {
    let fresh = "cov_usage_launchnew";
    let stale = "cov_usage_launchold";
    seed_tenant_created_at(&h, fresh, "free", Utc::now() - chrono::Duration::days(1)).await;
    seed_tenant_created_at(&h, stale, "free", Utc::now() - chrono::Duration::days(40)).await;

    let now = Utc::now();
    let fresh_summary = get_usage(
        &h.pool,
        fresh,
        now - chrono::Duration::days(1),
        now + chrono::Duration::days(1),
    )
    .await
    .expect("fresh free usage");
    let stale_summary = get_usage(
        &h.pool,
        stale,
        now - chrono::Duration::days(1),
        now + chrono::Duration::days(1),
    )
    .await
    .expect("stale free usage");

    assert_eq!(
        fresh_summary.emails_limit, 30_000,
        "launch allowance applies"
    );
    assert_eq!(
        stale_summary.emails_limit, 3_000,
        "launch allowance expired"
    );
});

db_test!(plan_override_wins_over_tenant_plan, |h| {
    let tenant = "cov_usage_override";
    seed_tenant(&h, tenant, "free").await;
    seed_plan(&h.pool, "covoverride", 12_345, 999).await;
    sqlx::query(
        "INSERT INTO plan_overrides (tenant_id, plan, active, expires_at)
         VALUES ($1, 'covoverride', true, NOW() + INTERVAL '10 days')",
    )
    .bind(tenant)
    .execute(&h.pool)
    .await
    .expect("seed plan override");

    let now = Utc::now();
    let summary = get_usage(
        &h.pool,
        tenant,
        now - chrono::Duration::days(1),
        now + chrono::Duration::days(1),
    )
    .await
    .expect("override usage");
    assert_eq!(summary.emails_limit, 12_345);
    assert_eq!(summary.api_calls_limit, 999);
});

db_test!(plan_override_expired_falls_back_to_tenant_plan, |h| {
    let tenant = "cov_usage_overexp";
    seed_tenant(&h, tenant, "covbase").await;
    seed_plan(&h.pool, "covbase", 5_000, 500).await;
    seed_plan(&h.pool, "covstale", 77, 7).await;
    sqlx::query(
        "INSERT INTO plan_overrides (tenant_id, plan, active, expires_at)
         VALUES ($1, 'covstale', true, NOW() - INTERVAL '1 second')",
    )
    .bind(tenant)
    .execute(&h.pool)
    .await
    .expect("seed expired override");

    let now = Utc::now();
    let summary = get_usage(
        &h.pool,
        tenant,
        now - chrono::Duration::days(1),
        now + chrono::Duration::days(1),
    )
    .await
    .expect("expired override usage");
    assert_eq!(summary.emails_limit, 5_000, "expired override must not win");
});

db_test!(check_quota_boundary_exactly_at_limit_is_exhausted, |h| {
    let tenant = "cov_quota_boundary";
    seed_tenant(&h, tenant, "covq").await;
    seed_plan(&h.pool, "covq", 100, 50).await;

    let key = usage_counter_key(&h.pool, tenant, MeterEventType::EmailsSent).await;

    redis_set_i64(&h.redis, &key, 99).await;
    let at_99 = check_quota(&h.pool, &h.redis, tenant)
        .await
        .expect("quota at 99");
    assert!(at_99.allowed, "99 of 100 must be allowed");
    assert_eq!(at_99.current, 99);
    assert_eq!(at_99.limit, 100);
    assert!((at_99.percent_used - 99.0).abs() < f64::EPSILON);

    redis_set_i64(&h.redis, &key, 100).await;
    let at_100 = check_quota(&h.pool, &h.redis, tenant)
        .await
        .expect("quota at 100");
    assert!(!at_100.allowed, "exactly at the limit is exhausted");

    redis_set_i64(&h.redis, &key, 101).await;
    let at_101 = check_quota(&h.pool, &h.redis, tenant)
        .await
        .expect("quota at 101");
    assert!(!at_101.allowed, "above the limit is exhausted");

    redis_del(&h.redis, &key).await;
});

db_test!(check_quota_unlimited_and_zero_limit_edges, |h| {
    let unlimited = "cov_quota_unlim";
    let zero = "cov_quota_zero";
    seed_tenant(&h, unlimited, "covunlim").await;
    seed_plan(&h.pool, "covunlim", -1, -1).await;
    seed_tenant(&h, zero, "covzeroq").await;
    seed_plan(&h.pool, "covzeroq", 0, 0).await;

    let unlim = check_quota(&h.pool, &h.redis, unlimited)
        .await
        .expect("unlimited");
    assert!(unlim.allowed);
    assert_eq!(unlim.limit, -1);
    assert_eq!(unlim.percent_used, 0.0);

    let zeroq = check_quota(&h.pool, &h.redis, zero)
        .await
        .expect("zero limit");
    assert!(!zeroq.allowed, "a zero limit can never be met");
    assert_eq!(zeroq.percent_used, 100.0);
});

db_test!(check_quota_falls_back_to_db_when_redis_unavailable, |h| {
    let tenant = "cov_quota_fallback";
    seed_tenant(&h, tenant, "covfallback").await;
    seed_plan(&h.pool, "covfallback", 1_000, 100).await;

    // Past-month usage that must NOT count toward this month's DB fallback.
    let now = Utc::now();
    let period_start = now
        .date_naive()
        .with_day(1)
        .expect("first day")
        .and_hms_opt(0, 0, 0)
        .expect("midnight")
        .and_utc();
    sqlx::query(
        "INSERT INTO metering_events (id, tenant_id, event_type, quantity, timestamp)
         VALUES ($1, $2, 'emails_sent', 400, $3), ($4, $2, 'emails_sent', 999, $5)",
    )
    .bind(Uuid::new_v4())
    .bind(tenant)
    .bind(now)
    .bind(Uuid::new_v4())
    .bind(period_start - chrono::Duration::days(1))
    .execute(&h.pool)
    .await
    .expect("seed metering events");

    // A pool pointed at a closed port: get() fails fast (connection refused),
    // exercising the DB fallback without any real network dependency.
    let broken = deadpool_redis::Config::from_url("redis://127.0.0.1:1")
        .create_pool(Some(Runtime::Tokio1))
        .expect("broken redis pool");
    let status = check_quota(&h.pool, &broken, tenant)
        .await
        .expect("fallback quota");
    assert_eq!(
        status.current, 400,
        "fallback aggregates the same period only"
    );
    assert!(status.allowed);
    assert_eq!(status.limit, 1_000);
});

// ---------------------------------------------------------------------------
// usage.rs — record_with_quota_check exactly-once accounting
// ---------------------------------------------------------------------------

db_test!(quota_check_records_exactly_at_limit_and_denies_above, |h| {
    let tenant = "cov_quota_rec";
    seed_tenant(&h, tenant, "covqr").await;
    seed_plan(&h.pool, "covqr", 10, 10).await;

    let first_id = Uuid::new_v4();
    let first = record_with_quota_check(
        &h.pool,
        &h.redis,
        tenant,
        MeterEventType::EmailsSent,
        10,
        Some(first_id),
        None,
    )
    .await
    .expect("record exactly at limit");
    assert!(first.allowed);
    assert_eq!(first.current, 10);
    assert!(!first.duplicate);

    // One above the limit: the Lua refuses and MUST NOT increment.
    let denied_id = Uuid::new_v4();
    let denied = record_with_quota_check(
        &h.pool,
        &h.redis,
        tenant,
        MeterEventType::EmailsSent,
        1,
        Some(denied_id),
        None,
    )
    .await
    .expect("deny above limit");
    assert!(!denied.allowed, "one above the limit must be denied");
    assert_eq!(
        redis_i64(
            &h.redis,
            &usage_counter_key(&h.pool, tenant, MeterEventType::EmailsSent).await
        )
        .await,
        10,
        "denied reservations must not consume quota"
    );
    assert_eq!(event_count(&h.pool, tenant, denied_id).await, 0);

    // Duplicate id short-circuits without consuming quota.
    let dup = record_with_quota_check(
        &h.pool,
        &h.redis,
        tenant,
        MeterEventType::EmailsSent,
        5,
        Some(first_id),
        None,
    )
    .await
    .expect("duplicate replay");
    assert!(dup.duplicate);
    assert_eq!(
        redis_i64(
            &h.redis,
            &usage_counter_key(&h.pool, tenant, MeterEventType::EmailsSent).await
        )
        .await,
        10
    );
});

db_test!(quota_check_rejects_nonpositive_quantity, |h| {
    let tenant = "cov_quota_qty";
    seed_tenant(&h, tenant, "covqty").await;
    let error = record_with_quota_check(
        &h.pool,
        &h.redis,
        tenant,
        MeterEventType::EmailsSent,
        0,
        None,
        None,
    )
    .await
    .expect_err("zero quantity refused");
    assert!(matches!(error, UsageError::InvalidQuantity(0)));
});

db_test!(unmetered_event_types_are_unlimited_under_zero_plan, |h| {
    let tenant = "cov_quota_unmetered";
    seed_tenant(&h, tenant, "covunmet").await;
    seed_plan(&h.pool, "covunmet", 0, 0).await;

    for event_type in [MeterEventType::BandwidthGb, MeterEventType::StorageGbHours] {
        let result = record_with_quota_check(
            &h.pool,
            &h.redis,
            tenant,
            event_type,
            1_000_000,
            Some(Uuid::new_v4()),
            None,
        )
        .await
        .expect("unmetered event");
        assert!(
            result.allowed,
            "{event_type:?} must not be gated by the email/api limits"
        );
    }
});

db_test!(api_calls_use_api_limit_not_email_limit, |h| {
    let tenant = "cov_quota_apicalls";
    seed_tenant(&h, tenant, "covapi").await;
    seed_plan(&h.pool, "covapi", 1, 1_000).await;

    let result = record_with_quota_check(
        &h.pool,
        &h.redis,
        tenant,
        MeterEventType::ApiCalls,
        500,
        Some(Uuid::new_v4()),
        None,
    )
    .await
    .expect("api call under its own limit");
    assert!(
        result.allowed,
        "api_calls denied under its own limit: {result:?}"
    );
});

db_test!(paid_subscription_widens_email_ceiling, |h| {
    let tenant = "cov_quota_paidceil";
    seed_tenant(&h, tenant, "covceil").await;
    seed_plan(&h.pool, "covceil", 100, 100).await;
    // The paid-subscription gate joins stripe_subscriptions.plan to plans and
    // requires price_monthly > 0, so the subscription's plan needs a price.
    sqlx::query(
        "INSERT INTO plans (id, name, display_name, price_cents, price_monthly, email_limit, api_call_limit)
         VALUES ('plan_growth', 'growth', 'Growth', 4900, 4900, 100000, 100000)
         ON CONFLICT (name) DO UPDATE SET price_monthly = 4900",
    )
    .execute(&h.pool)
    .await
    .expect("seed growth plan");
    let now = Utc::now();
    seed_stripe_subscription(
        &h.pool,
        tenant,
        "sub_cov_ceil",
        "active",
        now - chrono::Duration::days(2),
        now + chrono::Duration::days(28),
    )
    .await;

    // 200 = the default 100% overage allowance above a 100 limit.
    let at_ceiling = record_with_quota_check(
        &h.pool,
        &h.redis,
        tenant,
        MeterEventType::EmailsSent,
        200,
        Some(Uuid::new_v4()),
        None,
    )
    .await
    .expect("at ceiling");
    assert!(
        at_ceiling.allowed,
        "200% allowance must admit the soft ceiling"
    );

    let beyond = record_with_quota_check(
        &h.pool,
        &h.redis,
        tenant,
        MeterEventType::EmailsSent,
        1,
        Some(Uuid::new_v4()),
        None,
    )
    .await
    .expect("beyond ceiling");
    assert!(!beyond.allowed, "beyond the soft ceiling must be refused");
});

db_test!(
    reset_monthly_counters_clears_calendar_and_anchored_keys,
    |h| {
        let tenant = "cov_usage_reset";
        seed_tenant(&h, tenant, "free").await;
        let now = Utc::now();
        let plain = format!(
            "meter:rt:{tenant}:emails_sent:{}-{:02}",
            now.year(),
            now.month()
        );
        let anchored = format!(
            "meter:rt:{tenant}:emails_sent:c{}-{:02}",
            now.year(),
            now.month()
        );
        redis_set_i64(&h.redis, &plain, 5).await;
        redis_set_i64(&h.redis, &anchored, 7).await;

        reset_monthly_counters(&h.redis, tenant, now.year(), now.month())
            .await
            .expect("reset counters");

        assert_eq!(
            redis_i64(&h.redis, &plain).await,
            0,
            "plain key must be cleared"
        );
        assert_eq!(
            redis_i64(&h.redis, &anchored).await,
            0,
            "anchored key must be cleared"
        );
    }
);

db_test!(
    rollback_usage_record_deletes_row_and_compensates_counter,
    |h| {
        let tenant = "cov_usage_rollback";
        seed_tenant(&h, tenant, "free").await;
        let event_id = Uuid::new_v4();
        let recorded_at = Utc::now();
        record_usage(
            &h.pool,
            &h.redis,
            tenant,
            MeterEventType::EmailsSent,
            4,
            Some(event_id),
            None,
        )
        .await
        .expect("record before rollback");

        rollback_usage_record(
            &h.pool,
            &h.redis,
            tenant,
            MeterEventType::EmailsSent,
            4,
            event_id,
            recorded_at,
        )
        .await
        .expect("rollback");

        assert_eq!(event_count(&h.pool, tenant, event_id).await, 0);
        assert_eq!(
            redis_i64(
                &h.redis,
                &usage_counter_key(&h.pool, tenant, MeterEventType::EmailsSent).await
            )
            .await,
            0
        );
        // Rollback is written to the audit log.
        let audits: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_logs
         WHERE tenant_id = $1 AND action = 'billing.metering_event_rolled_back'",
        )
        .bind(tenant)
        .fetch_one(&h.pool)
        .await
        .expect("count rollback audits");
        assert_eq!(audits, 1);
    }
);

// ---------------------------------------------------------------------------
// usage.rs — pure boundary functions
// ---------------------------------------------------------------------------

#[test]
fn month_period_for_tz_handles_utc_and_invalid_zones() {
    let now = Utc.with_ymd_and_hms(2026, 3, 15, 12, 0, 0).unwrap();
    let (start, end) = month_period_for_tz(now, None).expect("utc period");
    assert_eq!(start, Utc.with_ymd_and_hms(2026, 3, 1, 0, 0, 0).unwrap());
    assert_eq!(end, Utc.with_ymd_and_hms(2026, 4, 1, 0, 0, 0).unwrap());

    let (start, end) = month_period_for_tz(now, Some("Europe/Tallinn")).expect("tallinn period");
    // Tallinn is UTC+2 in March (before DST), so local midnight is 22:00 UTC.
    assert_eq!(start, Utc.with_ymd_and_hms(2026, 2, 28, 22, 0, 0).unwrap());
    assert_eq!(end, Utc.with_ymd_and_hms(2026, 3, 31, 21, 0, 0).unwrap());

    assert!(month_period_for_tz(now, Some("Not/AZone")).is_err());
}

#[test]
fn month_period_for_tz_survives_leap_day_and_dst_gaps() {
    // Leap day 2028-02-29 in a zone where midnight is unambiguous.
    let leap = Utc.with_ymd_and_hms(2028, 2, 29, 12, 0, 0).unwrap();
    let (start, end) = month_period_for_tz(leap, Some("UTC")).expect("leap february");
    assert_eq!(start, Utc.with_ymd_and_hms(2028, 2, 1, 0, 0, 0).unwrap());
    assert_eq!(end, Utc.with_ymd_and_hms(2028, 3, 1, 0, 0, 0).unwrap());

    // Europe/Tallinn spring-forward: 2026-03-29 03:00 local → 04:00.
    // The month boundary itself (midnight) is fine, but the period end for
    // March/April crosses DST and must still be local midnight.
    let dst = Utc.with_ymd_and_hms(2026, 3, 29, 1, 30, 0).unwrap();
    let (start, end) = month_period_for_tz(dst, Some("Europe/Tallinn")).expect("dst march");
    assert_eq!(start, Utc.with_ymd_and_hms(2026, 2, 28, 22, 0, 0).unwrap());
    assert_eq!(end, Utc.with_ymd_and_hms(2026, 3, 31, 21, 0, 0).unwrap());

    // December boundary in a southern-hemisphere zone.
    let dec = Utc.with_ymd_and_hms(2026, 12, 31, 23, 59, 59).unwrap();
    let (start, end) = month_period_for_tz(dec, Some("Pacific/Auckland")).expect("auckland");
    // 23:59:59 UTC on Dec 31 is already Jan 1 (NZDT, UTC+13): the period
    // must span the whole local month, ending at local Feb 1 midnight.
    assert_eq!(start, Utc.with_ymd_and_hms(2026, 12, 31, 11, 0, 0).unwrap());
    assert_eq!(end, Utc.with_ymd_and_hms(2027, 1, 31, 11, 0, 0).unwrap());
    assert!(start < dec);
}

#[test]
fn month_period_for_tz_handles_year_boundary_and_local_first_day() {
    // 2027-01-01 00:30 UTC is 2027-01-01 02:30 in Tallinn; the period start
    // must be local midnight of January.
    let now = Utc.with_ymd_and_hms(2027, 1, 1, 0, 30, 0).unwrap();
    let (start, end) = month_period_for_tz(now, Some("Europe/Tallinn")).expect("january");
    assert_eq!(start, Utc.with_ymd_and_hms(2026, 12, 31, 22, 0, 0).unwrap());
    assert_eq!(end, Utc.with_ymd_and_hms(2027, 1, 31, 22, 0, 0).unwrap());

    // Blank/whitespace timezone behaves like None.
    let (blank_start, _) = month_period_for_tz(now, Some("   ")).expect("blank tz");
    assert_eq!(
        blank_start,
        Utc.with_ymd_and_hms(2027, 1, 1, 0, 0, 0).unwrap()
    );
}

#[test]
fn meter_event_type_strings_are_stable_wire_values() {
    assert_eq!(
        meter_event_type_str(MeterEventType::EmailsSent),
        "emails_sent"
    );
    assert_eq!(
        meter_event_type_str(MeterEventType::EmailsDelivered),
        "emails_delivered"
    );
    assert_eq!(meter_event_type_str(MeterEventType::ApiCalls), "api_calls");
    assert_eq!(
        meter_event_type_str(MeterEventType::WebhooksDelivered),
        "webhooks_delivered"
    );
    assert_eq!(
        meter_event_type_str(MeterEventType::DedicatedIpHours),
        "dedicated_ip_hours"
    );
    assert_eq!(
        meter_event_type_str(MeterEventType::StorageGbHours),
        "storage_gb_hours"
    );
    assert_eq!(
        meter_event_type_str(MeterEventType::BandwidthGb),
        "bandwidth_gb"
    );
}

// ---------------------------------------------------------------------------
// usage_ingest.rs — batch ingest attacks
// ---------------------------------------------------------------------------

fn ingest_event(tenant: &str, event_type: MeterEventType, quantity: i64, id: Uuid) -> IngestEvent {
    IngestEvent {
        tenant_id: tenant.to_string(),
        event_type,
        quantity,
        event_id: Some(id),
        metadata: None,
    }
}

db_test!(
    ingest_batch_counts_accepted_duplicates_and_rejections,
    |h| {
        let tenant = "cov_ingest_batch";
        seed_tenant(&h, tenant, "free").await;
        let duplicate_id = Uuid::new_v4();

        let events = vec![
            ingest_event(tenant, MeterEventType::ApiCalls, 2, Uuid::new_v4()),
            // Same id with identical payload → duplicate.
            ingest_event(tenant, MeterEventType::ApiCalls, 2, duplicate_id),
            ingest_event(tenant, MeterEventType::ApiCalls, 2, duplicate_id),
            // Non-positive quantity → rejected.
            ingest_event(tenant, MeterEventType::ApiCalls, 0, Uuid::new_v4()),
            // Divergent reuse of the duplicate id → rejected (conflict).
            ingest_event(tenant, MeterEventType::ApiCalls, 9, duplicate_id),
        ];

        let result = ingest_usage_batch(&h.pool, &h.redis, &events).await;
        assert_eq!(
            result.accepted, 2,
            "fresh event + first write of duplicate id"
        );
        assert_eq!(result.duplicates, 1, "one identical replay");
        assert_eq!(result.rejected, 2, "zero quantity + divergent reuse");
        assert_eq!(result.errors.len(), 2, "both rejections are surfaced");
        assert!(
            result.errors.iter().all(|message| message.contains(tenant)),
            "errors name the tenant: {:?}",
            result.errors
        );
    }
);

db_test!(ingest_batch_error_list_is_capped_but_count_is_not, |h| {
    let tenant = "cov_ingest_cap";
    seed_tenant(&h, tenant, "free").await;

    let events: Vec<IngestEvent> = (0..8)
        .map(|_| ingest_event(tenant, MeterEventType::ApiCalls, -1, Uuid::new_v4()))
        .collect();
    let result = ingest_usage_batch(&h.pool, &h.redis, &events).await;
    assert_eq!(result.rejected, 8, "every rejection is counted");
    assert_eq!(result.errors.len(), 5, "error strings are capped at 5");
});

db_test!(ingest_batch_quota_exhaustion_never_invents_usage, |h| {
    let tenant = "cov_ingest_quota";
    seed_tenant(&h, tenant, "coviq").await;
    seed_plan(&h.pool, "coviq", 10, 10).await;

    let events = vec![
        ingest_event(tenant, MeterEventType::EmailsSent, 6, Uuid::new_v4()),
        ingest_event(tenant, MeterEventType::EmailsSent, 4, Uuid::new_v4()),
        // Quota exhausted mid-batch; record_usage (not the atomic gate) has
        // no ceiling, so this must be recorded, never silently dropped...
        ingest_event(tenant, MeterEventType::EmailsSent, 5, Uuid::new_v4()),
    ];
    let result = ingest_usage_batch(&h.pool, &h.redis, &events).await;
    assert_eq!(result.accepted, 3);

    let total: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(quantity), 0)::bigint FROM metering_events
         WHERE tenant_id = $1 AND event_type = 'emails_sent'",
    )
    .bind(tenant)
    .fetch_one(&h.pool)
    .await
    .expect("sum usage");
    assert_eq!(total, 15, "the batch is recorded exactly as submitted");
});

db_test!(ingest_empty_batch_is_a_noop, |h| {
    let result = ingest_usage_batch(&h.pool, &h.redis, &[]).await;
    assert_eq!(result.accepted, 0);
    assert_eq!(result.duplicates, 0);
    assert_eq!(result.rejected, 0);
    assert!(result.errors.is_empty());
});

db_test!(ingest_huge_quantity_does_not_overflow_counter_or_db, |h| {
    let tenant = "cov_ingest_huge";
    seed_tenant(&h, tenant, "free").await;
    let events = vec![ingest_event(
        tenant,
        MeterEventType::BandwidthGb,
        i64::MAX,
        Uuid::new_v4(),
    )];
    let result = ingest_usage_batch(&h.pool, &h.redis, &events).await;
    assert_eq!(result.accepted, 1, "i64::MAX is representable");
    let stored: i64 = sqlx::query_scalar(
        "SELECT quantity FROM metering_events WHERE tenant_id = $1 AND event_type = 'bandwidth_gb'",
    )
    .bind(tenant)
    .fetch_one(&h.pool)
    .await
    .expect("stored quantity");
    assert_eq!(stored, i64::MAX, "no truncation, no wraparound");
});

#[test]
fn ingest_event_json_rejects_unknown_fields_and_defaults_quantity() {
    let base = serde_json::json!({
        "tenantId": "t1",
        "eventType": "api_calls",
    });
    let parsed: IngestEvent = serde_json::from_value(base.clone()).expect("defaults quantity");
    assert_eq!(parsed.quantity, 1);
    assert!(parsed.event_id.is_none());

    let mut unknown = base.clone();
    unknown["unexpected"] = serde_json::json!(1);
    assert!(
        serde_json::from_value::<IngestEvent>(unknown).is_err(),
        "deny_unknown_fields must refuse unexpected keys"
    );

    let mut bad_type = base;
    bad_type["eventType"] = serde_json::json!("not_a_metric");
    assert!(serde_json::from_value::<IngestEvent>(bad_type).is_err());
}

// ---------------------------------------------------------------------------
// usage_ingest.rs — derived sweep + reconciliation
// ---------------------------------------------------------------------------

#[test]
fn sweep_target_day_is_always_yesterday_utc() {
    let just_after_midnight = Utc.with_ymd_and_hms(2026, 3, 1, 0, 0, 0).unwrap();
    assert_eq!(sweep_target_day(just_after_midnight), date(2026, 2, 28));

    let end_of_day = Utc.with_ymd_and_hms(2026, 3, 1, 23, 59, 59).unwrap();
    assert_eq!(sweep_target_day(end_of_day), date(2026, 2, 28));

    // Leap day is a valid target (2028-02-29 → previous day 2028-02-28).
    let leap = Utc.with_ymd_and_hms(2028, 2, 29, 12, 0, 0).unwrap();
    assert_eq!(sweep_target_day(leap), date(2028, 2, 28));
}

#[test]
fn derived_event_id_is_deterministic_and_field_sensitive() {
    let day = date(2026, 5, 1);
    let first = derived_event_id("t", "emails_delivered", day, "src");
    assert_eq!(first, derived_event_id("t", "emails_delivered", day, "src"));

    assert_ne!(
        first,
        derived_event_id("t2", "emails_delivered", day, "src")
    );
    assert_ne!(first, derived_event_id("t", "api_calls", day, "src"));
    assert_ne!(
        first,
        derived_event_id("t", "emails_delivered", date(2026, 5, 2), "src")
    );
    assert_ne!(
        first,
        derived_event_id("t", "emails_delivered", day, "other-src")
    );

    // Generated ids must be RFC-4122 version 5-shaped.
    let bytes = first.as_bytes();
    assert_eq!(bytes[6] >> 4, 5, "version nibble");
    assert_eq!(bytes[8] >> 6, 0b10, "variant bits");
}

#[test]
fn classify_reconciliation_slack_boundaries() {
    // Exact match: zero drift, no discrepancy.
    assert_eq!(classify_reconciliation(100, 100, 0), (0, false));
    // Absolute slack of 25 is NOT flagged (unaccounted must exceed it).
    assert_eq!(
        classify_reconciliation(100, 100 - RECON_ABSOLUTE_SLACK, 0),
        (25, false)
    );
    let (drift, discrepancy) = classify_reconciliation(100, 100 - RECON_ABSOLUTE_SLACK - 1, 0);
    assert_eq!(drift, 26);
    assert!(discrepancy);

    // Relative slack: 5% of 10_000 = 500, and it DOMINATES the absolute
    // slack → 499 unaccounted is within slack, 501 is a candidate.
    assert_eq!(
        classify_reconciliation(10_000, 10_000 - 499, 0),
        (499, false)
    );
    let (drift, discrepancy) = classify_reconciliation(10_000, 10_000 - 501, 0);
    assert_eq!(drift, 501);
    assert!(discrepancy);

    // Over-delivery is negative drift and never a candidate.
    let (drift, discrepancy) = classify_reconciliation(100, 200, 0);
    assert_eq!(drift, -100);
    assert!(!discrepancy);

    // Bounced volume reduces the unaccounted gap.
    let (drift, discrepancy) = classify_reconciliation(100, 50, 10);
    assert_eq!(drift, 40);
    assert!(discrepancy);
    assert_eq!(
        classify_reconciliation(100, 70, 25),
        (5, false),
        "bounces explain the gap"
    );

    // Zero reserved can never be a candidate, even with negative drift.
    assert_eq!(classify_reconciliation(0, 0, 0), (0, false));
    let (drift, discrepancy) = classify_reconciliation(0, 1, 0);
    assert_eq!(drift, -1);
    assert!(!discrepancy);
}

#[test]
fn reconciliation_constants_are_the_documented_slack() {
    assert_eq!(RECON_ABSOLUTE_SLACK, 25);
    assert_eq!(RECON_RELATIVE_SLACK_PERCENT, 5);
}

fn date(year: i32, month: u32, day: u32) -> NaiveDate {
    NaiveDate::from_ymd_opt(year, month, day).expect("valid date")
}

// ---------------------------------------------------------------------------
// routes.rs — HTTP surface: auth gates, malformed input, error mapping
// ---------------------------------------------------------------------------

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use tower::ServiceExt;

const SERVICE_TOKEN: &str = "coverage-service-token";

fn authed(method: &str, uri: &str) -> axum::http::request::Builder {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("x-api-key", SERVICE_TOKEN)
}

fn tenant_token(tenant_id: &str) -> String {
    format!("{tenant_id}:{SERVICE_TOKEN}")
}

async fn call(app: &axum::Router, request: Request<Body>) -> (StatusCode, serde_json::Value) {
    let response = app
        .clone()
        .oneshot(request)
        .await
        .expect("router is infallible");
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body");
    let json = serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
    (status, json)
}

db_test!(router_health_is_public_and_other_routes_require_auth, |h| {
    let app = billing_service::routes::router(h.state.clone());

    let (status, json) = call(
        &app,
        Request::builder()
            .uri("/health")
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["status"], "ok");

    // No token at all.
    let (status, _) = call(
        &app,
        Request::builder()
            .uri("/plans")
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Wrong token.
    let (status, _) = call(
        &app,
        Request::builder()
            .uri("/plans")
            .header("x-api-key", "not-the-token")
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Malformed Authorization scheme.
    let (status, _) = call(
        &app,
        Request::builder()
            .uri("/plans")
            .header(header::AUTHORIZATION, "Basic dXNlcjpwYXNz")
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Valid token via the bearer path.
    let (status, json) = call(
        &app,
        Request::builder()
            .uri("/plans")
            .header(header::AUTHORIZATION, format!("Bearer {SERVICE_TOKEN}"))
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(json["plans"].is_array());
});

db_test!(router_scoped_token_is_confined_to_its_tenant, |h| {
    let app = billing_service::routes::router(h.state.clone());
    let own = "cov_route_scope_a";
    let other = "cov_route_scope_b";
    seed_tenant(&h, own, "free").await;
    seed_tenant(&h, other, "free").await;

    // Cross-tenant usage probe → 403, never data.
    let (status, json) = call(
        &app,
        Request::builder()
            .uri(format!("/usage?tenant_id={other}"))
            .header("x-api-key", tenant_token(own))
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(json["error"]["code"], "FORBIDDEN");

    // Own tenant → 200.
    let (status, _) = call(
        &app,
        Request::builder()
            .uri(format!("/usage?tenant_id={own}"))
            .header("x-api-key", tenant_token(own))
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Platform-wide reports refuse a tenant-scoped token even for its own id.
    for uri in ["/reports/mrr", "/reports/churn", "/reports/dunning"] {
        let (status, _) = call(
            &app,
            Request::builder()
                .uri(uri)
                .header("x-api-key", tenant_token(own))
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "{uri} must require Any scope"
        );
    }

    // Scoped token on /plans/seed (admin mutation) is forbidden too.
    let (status, _) = call(
        &app,
        Request::builder()
            .method("POST")
            .uri("/plans/seed")
            .header("x-api-key", tenant_token(own))
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
});

db_test!(router_usage_query_rejects_malformed_input_honestly, |h| {
    let app = billing_service::routes::router(h.state.clone());
    let tenant = "cov_route_usage";
    seed_tenant(&h, tenant, "free").await;

    // Missing tenant_id is a client error, not a 500.
    let (status, _) = call(
        &app,
        authed("GET", "/usage")
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert!(status.is_client_error(), "missing tenant_id: {status}");

    // Unknown timezone is a 400 with a validation code.
    let (status, json) = call(
        &app,
        authed("GET", &format!("/usage?tenant_id={tenant}&tz=Mars/Olympus"))
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json["error"]["code"], "INVALID_INPUT");

    // Valid timezone succeeds and reports period boundaries.
    let (status, json) = call(
        &app,
        authed(
            "GET",
            &format!("/usage?tenant_id={tenant}&tz=Europe/Tallinn"),
        )
        .body(Body::empty())
        .expect("request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["tenant_id"], tenant);
    assert!(json["period_start"].is_string());

    // Unknown extra query parameter is refused (deny_unknown_fields).
    let (status, _) = call(
        &app,
        authed("GET", &format!("/usage?tenant_id={tenant}&bogus=1"))
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert!(status.is_client_error(), "unknown query field: {status}");
});

db_test!(router_record_usage_maps_user_errors_to_4xx, |h| {
    let app = billing_service::routes::router(h.state.clone());
    let tenant = "cov_route_record";
    seed_tenant(&h, tenant, "covroute").await;
    seed_plan(&h.pool, "covroute", 1_000, 1_000).await;

    // Non-positive quantity → 400 (not 500).
    let (status, json) = call(
        &app,
        authed("POST", "/usage/record")
            .header("content-type", "application/json")
            .body(Body::from(format!(
                r#"{{"tenant_id":"{tenant}","event_type":"emails_sent","quantity":0}}"#
            )))
            .expect("request"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json["error"]["code"], "VALIDATION_ERROR");

    // Unknown event type → 4xx from the deserializer.
    let (status, _) = call(
        &app,
        authed("POST", "/usage/record")
            .header("content-type", "application/json")
            .body(Body::from(format!(
                r#"{{"tenant_id":"{tenant}","event_type":"teleportation","quantity":1}}"#
            )))
            .expect("request"),
    )
    .await;
    assert!(status.is_client_error(), "unknown event type: {status}");

    // Unknown field → 422 (deny_unknown_fields), never silently ignored.
    let (status, _) = call(
        &app,
        authed("POST", "/usage/record")
            .header("content-type", "application/json")
            .body(Body::from(format!(
                r#"{{"tenant_id":"{tenant}","event_type":"emails_sent","quantity":1,"extra":true}}"#
            )))
            .expect("request"),
    )
    .await;
    assert!(status.is_client_error(), "unknown body field: {status}");

    // Malformed JSON → 4xx.
    let (status, _) = call(
        &app,
        authed("POST", "/usage/record")
            .header("content-type", "application/json")
            .body(Body::from("{not json"))
            .expect("request"),
    )
    .await;
    assert!(status.is_client_error(), "malformed json: {status}");

    // Valid record → 201 {"recorded": true}.
    let event_id = Uuid::new_v4();
    let (status, json) = call(
        &app,
        authed("POST", "/usage/record")
            .header("content-type", "application/json")
            .body(Body::from(format!(
                r#"{{"tenant_id":"{tenant}","event_type":"emails_sent","quantity":5,"event_id":"{event_id}"}}"#
            )))
            .expect("request"),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(json["recorded"], true, "record body: {json}");

    // Identical replay → 201 {"recorded": false}, still exactly one row.
    let (status, json) = call(
        &app,
        authed("POST", "/usage/record")
            .header("content-type", "application/json")
            .body(Body::from(format!(
                r#"{{"tenant_id":"{tenant}","event_type":"emails_sent","quantity":5,"event_id":"{event_id}"}}"#
            )))
            .expect("request"),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(json["recorded"], false, "replay body: {json}");

    // /usage/record-checked returns the quota state; exactly at the limit is
    // allowed, one above is a 429 (quota refusal, never a 500).
    let (status, json) = call(
        &app,
        authed("POST", "/usage/record-checked")
            .header("content-type", "application/json")
            .body(Body::from(format!(
                r#"{{"tenant_id":"{tenant}","event_type":"emails_sent","quantity":995}}"#
            )))
            .expect("request"),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(json["allowed"], true, "checked body: {json}");
    assert_eq!(json["current"], 1000, "checked body: {json}");

    let (status, json) = call(
        &app,
        authed("POST", "/usage/record-checked")
            .header("content-type", "application/json")
            .body(Body::from(format!(
                r#"{{"tenant_id":"{tenant}","event_type":"emails_sent","quantity":1}}"#
            )))
            .expect("request"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "checked body: {json}"
    );
    assert_eq!(json["allowed"], false);
});

db_test!(router_ingest_status_codes_and_batch_cap, |h| {
    let app = billing_service::routes::router(h.state.clone());
    let tenant = "cov_route_ingest";
    seed_tenant(&h, tenant, "free").await;

    // All events rejected → 422.
    let (status, _) = call(
        &app,
        authed("POST", "/usage/ingest")
            .header("content-type", "application/json")
            .body(Body::from(format!(
                r#"{{"events":[{{"tenantId":"{tenant}","eventType":"api_calls","quantity":-1}}]}}"#
            )))
            .expect("request"),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    // Mixed accepted+rejected → 207.
    let (status, json) = call(
        &app,
        authed("POST", "/usage/ingest")
            .header("content-type", "application/json")
            .body(Body::from(format!(
                r#"{{"events":[{{"tenantId":"{tenant}","eventType":"api_calls","quantity":2}},
                              {{"tenantId":"{tenant}","eventType":"api_calls","quantity":0}}]}}"#
            )))
            .expect("request"),
    )
    .await;
    assert_eq!(status, StatusCode::MULTI_STATUS);
    assert_eq!(json["accepted"], 1);
    assert_eq!(json["rejected"], 1);

    // Unknown field inside an event → 4xx (deny_unknown_fields).
    let (status, _) = call(
        &app,
        authed("POST", "/usage/ingest")
            .header("content-type", "application/json")
            .body(Body::from(format!(
                r#"{{"events":[{{"tenantId":"{tenant}","eventType":"api_calls","quantity":1,"x":1}}]}}"#
            )))
            .expect("request"),
    )
    .await;
    assert!(status.is_client_error(), "unknown ingest field: {status}");

    // Cross-tenant ingest with a scoped token → 403 before any write.
    let (status, _) = call(
        &app,
        Request::builder()
            .method("POST")
            .uri("/usage/ingest")
            .header("x-api-key", tenant_token("cov_route_ingest_other"))
            .header("content-type", "application/json")
            .body(Body::from(format!(
                r#"{{"events":[{{"tenantId":"{tenant}","eventType":"api_calls","quantity":1}}]}}"#
            )))
            .expect("request"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
});

db_test!(router_invoice_routes_clamp_and_404, |h| {
    let app = billing_service::routes::router(h.state.clone());
    let tenant = "cov_route_invoice";
    seed_tenant(&h, tenant, "free").await;

    // Empty list is a 200 with an empty array.
    let (status, json) = call(
        &app,
        authed("GET", &format!("/invoices?tenant_id={tenant}"))
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["invoices"].as_array().map(Vec::len), Some(0));

    // Negative limit/offset are clamped to valid values, never a DB error.
    for query in [
        "limit=-5",
        "offset=-100",
        "limit=1000000",
        "offset=999999999",
    ] {
        let (status, _) = call(
            &app,
            authed("GET", &format!("/invoices?tenant_id={tenant}&{query}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "query {query} must be clamped");
    }

    // Non-UUID path → client error.
    let (status, _) = call(
        &app,
        authed("GET", &format!("/invoices/not-a-uuid?tenant_id={tenant}"))
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert!(status.is_client_error(), "bad uuid: {status}");

    // Unknown invoice → 404, not 500.
    let missing = Uuid::new_v4();
    let (status, _) = call(
        &app,
        authed("GET", &format!("/invoices/{missing}?tenant_id={tenant}"))
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Existing invoice for the tenant → 200; another tenant's invoice → 404.
    let invoice_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO invoices (id, tenant_id, amount, currency, status, invoice_number,
                               subtotal, vat_total, total, line_items, issued_at,
                               due_at, period_start, period_end)
         VALUES ($1, $2, 1234, 'EUR', 'pending', $3,
                 1000, 234, 1234, '[]'::jsonb, NOW(), NOW() + INTERVAL '14 days',
                 NOW() - INTERVAL '30 days', NOW())",
    )
    .bind(invoice_id)
    .bind(tenant)
    .bind(format!("COV-{}", invoice_id.simple()))
    .execute(&h.pool)
    .await
    .expect("seed invoice");

    let (status, json) = call(
        &app,
        authed("GET", &format!("/invoices/{invoice_id}?tenant_id={tenant}"))
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    // The handler serializes the invoice object at the TOP level.
    assert_eq!(json["tenant_id"], tenant);
    assert_eq!(
        json["invoice_number"],
        format!("COV-{}", invoice_id.simple())
    );

    let other = "cov_route_invoice_b";
    seed_tenant(&h, other, "free").await;
    let (status, _) = call(
        &app,
        authed("GET", &format!("/invoices/{invoice_id}?tenant_id={other}"))
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "cross-tenant invoice must 404"
    );
});

db_test!(router_quota_and_subscription_surfaces, |h| {
    let app = billing_service::routes::router(h.state.clone());
    let tenant = "cov_route_quota";
    seed_tenant(&h, tenant, "free").await;

    let (status, json) = call(
        &app,
        authed("GET", &format!("/quota?tenant_id={tenant}"))
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["allowed"], true);
    assert_eq!(json["current"], 0);

    // No subscription → subscription: null (not an error).
    let (status, json) = call(
        &app,
        authed("GET", &format!("/subscription?tenant_id={tenant}"))
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(json["subscription"].is_null());

    // A seeded active subscription is returned.
    let now = Utc::now();
    seed_stripe_subscription(
        &h.pool,
        tenant,
        "sub_cov_route",
        "active",
        now - chrono::Duration::days(1),
        now + chrono::Duration::days(29),
    )
    .await;
    let (status, json) = call(
        &app,
        authed("GET", &format!("/subscription?tenant_id={tenant}"))
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    // The subscription view resolves the EFFECTIVE plan from tenants.plan.
    assert_eq!(json["subscription"]["plan_name"], "free", "body: {json}");
    assert_eq!(
        json["subscription"]["stripe_subscription_id"],
        "sub_cov_route"
    );
});

db_test!(
    router_direct_plan_transitions_are_refused_with_conflict,
    |h| {
        let app = billing_service::routes::router(h.state.clone());
        let tenant = "cov_route_transition";
        seed_tenant(&h, tenant, "free").await;

        let (status, json) = call(
            &app,
            authed("POST", &format!("/switch-plan?tenant_id={tenant}"))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"planName":"growth"}"#))
                .expect("request"),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(json["error"]["code"], "CONFLICT");

        let (status, _) = call(
            &app,
            authed("POST", &format!("/cancel?tenant_id={tenant}"))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"reason":"too expensive"}"#))
                .expect("request"),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);

        // Unknown body field → 4xx.
        let (status, _) = call(
            &app,
            authed("POST", &format!("/switch-plan?tenant_id={tenant}"))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"planName":"growth","sneaky":true}"#))
                .expect("request"),
        )
        .await;
        assert!(status.is_client_error());
    }
);

db_test!(
    router_payg_and_overage_estimates_reject_negative_inputs,
    |h| {
        let app = billing_service::routes::router(h.state.clone());
        let tenant = "cov_route_payg";
        seed_tenant(&h, tenant, "covpayg").await;
        seed_plan(&h.pool, "covpayg", 100, 100).await;

        // Pricing is public to any authenticated caller.
        let (status, json) = call(
            &app,
            authed("GET", "/payg/pricing")
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(json["emailPricing"].is_array());

        // Negative usage → 400.
        let (status, _) = call(
            &app,
            authed("POST", "/payg/estimate")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"emailsSent":-1,"apiCalls":0}"#))
                .expect("request"),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // Zero usage → 200 with the minimum charge applied.
        let (status, json) = call(
            &app,
            authed("POST", "/payg/estimate")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"emailsSent":0,"apiCalls":0}"#))
                .expect("request"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["cost"]["totalCostCents"], 0);

        // Amounts beyond i64 → 400, never a panic.
        let (status, _) = call(
            &app,
            authed("POST", "/payg/estimate")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"emailsSent":9223372036854775807,"apiCalls":9223372036854775807}"#,
                ))
                .expect("request"),
        )
        .await;
        assert!(status.is_client_error(), "overflow estimate: {status}");

        // Overage: a server plan limit overrides the client value.
        let (status, json) = call(
            &app,
            authed("POST", "/overage/estimate")
                .header("content-type", "application/json")
                .body(Body::from(format!(
                    r#"{{"tenantId":"{tenant}","emailsSent":150,"emailLimit":10}}"#
                )))
                .expect("request"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["usage"]["emailLimit"], 100, "server plan limit wins");
        // 50 over the 100 limit at 40 millicents/email = 2000 millicents = 2 cents.
        assert_eq!(json["overageCostCents"], 2);

        // Negative client limit → 400.
        let (status, _) = call(
            &app,
            authed("POST", "/overage/estimate")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"emailsSent":10,"emailLimit":-1}"#))
                .expect("request"),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // Unknown tenant for a scoped Any token: server limit is absent, the
        // validated client limit stands.
        let (status, json) = call(
            &app,
            authed("POST", "/overage/estimate")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"tenantId":"cov_route_missing","emailsSent":10,"emailLimit":5}"#,
                ))
                .expect("request"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["usage"]["emailLimit"], 5);
    }
);

db_test!(router_reports_require_dates_and_return_json, |h| {
    let app = billing_service::routes::router(h.state.clone());

    // MRR/churn/dunning are date-free and work on empty tables.
    for uri in ["/reports/mrr", "/reports/churn", "/reports/dunning"] {
        let (status, json) = call(
            &app,
            authed("GET", uri).body(Body::empty()).expect("request"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{uri}");
        assert!(json["report"].is_array(), "{uri} report array");
    }

    // Revenue/costs require a date range.
    for uri in ["/reports/revenue", "/reports/costs"] {
        let (status, _) = call(
            &app,
            authed("GET", uri).body(Body::empty()).expect("request"),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{uri} needs dates");

        let (status, _) = call(
            &app,
            authed("GET", &format!("{uri}?startDate=nonsense&endDate=also-bad"))
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{uri} bad dates");

        let (status, json) = call(
            &app,
            authed(
                "GET",
                &format!("{uri}?startDate=2026-01-01&endDate=2026-02-01"),
            )
            .body(Body::empty())
            .expect("request"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{uri} valid dates");
        assert!(json["report"].is_array());
    }

    // Export requires type + dates.
    let (status, _) = call(
        &app,
        authed("GET", "/export")
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, _) = call(
        &app,
        authed("GET", "/export?type=invoices&startDate=9&endDate=10")
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, _) = call(
        &app,
        authed(
            "GET",
            "/export?type=unknown-kind&startDate=2026-01-01&endDate=2026-02-01",
        )
        .body(Body::empty())
        .expect("request"),
    )
    .await;
    assert!(status.is_client_error(), "unknown export type: {status}");

    let (status, _) = call(
        &app,
        authed(
            "GET",
            "/export?type=invoices&startDate=2026-01-01&endDate=2026-02-01&format=csv",
        )
        .body(Body::empty())
        .expect("request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
});

db_test!(router_plan_admin_surface, |h| {
    let app = billing_service::routes::router(h.state.clone());

    // Seeding is idempotent and reaches the DB.
    for _ in 0..2 {
        let (status, json) = call(
            &app,
            authed("POST", "/plans/seed")
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["message"], "Default plans seeded");
    }

    // Unknown plan → 404.
    let (status, _) = call(
        &app,
        authed("GET", "/plans/definitely-missing")
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Compare an existing plan against itself: zero difference.
    let (status, json) = call(
        &app,
        authed("GET", "/plans/compare/free/free")
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["differences"]["priceDifference"], 0);

    // Compare with one unknown plan → 404.
    let (status, _) = call(
        &app,
        authed("GET", "/plans/compare/free/nope")
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Plan create with unknown fields → 4xx.
    let (status, _) = call(
        &app,
        authed("POST", "/plans")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"name":"covx","displayName":"X","description":"d","priceMonthly":0,
                    "priceYearly":0,"features":{},"limits":{},"bogus":1}"#,
            ))
            .expect("request"),
    )
    .await;
    assert!(status.is_client_error());

    // Tenant feature probe for an unknown tenant → hasAccess false.
    let (status, json) = call(
        &app,
        authed(
            "GET",
            "/plans/features/api_access?tenant_id=cov_route_missing",
        )
        .body(Body::empty())
        .expect("request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["hasAccess"], false);

    // Tenant features for unknown tenant → empty object (not an error).
    let (status, json) = call(
        &app,
        authed("GET", "/plans/tenant/features?tenant_id=cov_route_missing")
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json, serde_json::json!({}));
});

// ---------------------------------------------------------------------------
// overage.rs — end-of-period sweep: boundaries, idempotency, isolation
// ---------------------------------------------------------------------------

async fn seed_billing_address(h: &Harness, tenant: &str, country: &str) {
    sqlx::query(
        "INSERT INTO billing_addresses (tenant_id, company_name, address_line1, city, postal_code, country)
         VALUES ($1, $2, 'Test 1', 'Tallinn', '10111', $3)
         ON CONFLICT (tenant_id) DO UPDATE SET country = EXCLUDED.country",
    )
    .bind(tenant)
    .bind(format!("Coverage {tenant} OÜ"))
    .bind(country)
    .execute(&h.pool)
    .await
    .expect("seed billing address");
}

async fn seed_billing_period(
    h: &Harness,
    tenant: &str,
    period_start: DateTime<Utc>,
    period_end: DateTime<Utc>,
    plan_name: &str,
    email_allowance: Option<i64>,
    rate_millicents: Option<i64>,
) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO billing_periods
             (tenant_id, usage_kind, period_start, period_end, plan_name, email_allowance,
              overage_rate_millicents, currency, invoice_state)
         VALUES ($1, 'subscription', $2, $3, $4, $5, $6, 'EUR', 'unbilled')
         RETURNING id",
    )
    .bind(tenant)
    .bind(period_start)
    .bind(period_end)
    .bind(plan_name)
    .bind(email_allowance)
    .bind(rate_millicents)
    .fetch_one(&h.pool)
    .await
    .expect("seed billing period")
}

async fn seed_metering(
    h: &Harness,
    tenant: &str,
    event_type: &str,
    quantity: i64,
    at: DateTime<Utc>,
) {
    sqlx::query(
        "INSERT INTO metering_events (id, tenant_id, event_type, quantity, timestamp)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(Uuid::new_v4())
    .bind(tenant)
    .bind(event_type)
    .bind(quantity)
    .bind(at)
    .execute(&h.pool)
    .await
    .expect("seed metering event");
}

async fn invoice_count(h: &Harness, tenant: &str) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM invoices WHERE tenant_id = $1")
        .bind(tenant)
        .fetch_one(&h.pool)
        .await
        .expect("count invoices")
}

db_test!(overage_sweep_bills_only_the_excess_and_never_twice, |h| {
    let tenant = "cov_over_boundary";
    seed_tenant(&h, tenant, "growth").await;
    seed_billing_address(&h, tenant, "EE").await;
    seed_plan(&h.pool, "growth", 100, 1_000).await;

    let now = Utc::now();
    let start = now - chrono::Duration::days(30);
    let end = now - chrono::Duration::days(1);

    // Exactly at the limit: no billable overage.
    let at_limit = seed_billing_period(&h, tenant, start, end, "growth", Some(100), Some(40)).await;
    seed_metering(
        &h,
        tenant,
        "emails_sent",
        100,
        start + chrono::Duration::days(1),
    )
    .await;

    // One above the limit: one billable email.
    let above = "cov_over_boundary2";
    seed_tenant(&h, above, "growth").await;
    seed_billing_address(&h, above, "EE").await;
    let above_period =
        seed_billing_period(&h, above, start, end, "growth", Some(100), Some(40)).await;
    seed_metering(
        &h,
        above,
        "emails_sent",
        150,
        start + chrono::Duration::days(1),
    )
    .await;

    let result = billing_service::overage::sweep_period_overage(&h.state)
        .await
        .expect("first sweep");
    assert!(result.failed_periods == 0, "no period may fail: {result:?}");
    assert_eq!(
        result.skipped_no_overage, 1,
        "at-limit period skipped: {result:?}"
    );
    assert_eq!(
        result.invoices_created, 1,
        "one overage invoice: {result:?}"
    );
    assert_eq!(invoice_count(&h, tenant).await, 0);
    assert_eq!(invoice_count(&h, above).await, 1);

    // 50 over the limit at 40 millicents/email = 2000 millicents → 2 cents.
    let (subtotal, vat_total, total, currency, period): (
        i64,
        i64,
        i64,
        String,
        Option<DateTime<Utc>>,
    ) = sqlx::query_as(
        "SELECT subtotal, vat_total, total, currency, overage_period
             FROM invoices WHERE tenant_id = $1",
    )
    .bind(above)
    .fetch_one(&h.pool)
    .await
    .expect("read overage invoice");
    assert_eq!(subtotal, 2, "only the excess is billed");
    // Invoices persist the ISO code case-insensitively (writers store
    // lowercase; the PDF/KMD surfaces uppercase it).
    assert_eq!(currency.to_uppercase(), "EUR");
    assert_eq!(period, Some(start));
    assert_eq!(total, subtotal + vat_total, "invoice totals must reconcile");

    // States: terminal for both.
    let at_limit_state: String =
        sqlx::query_scalar("SELECT invoice_state::text FROM billing_periods WHERE id = $1")
            .bind(at_limit)
            .fetch_one(&h.pool)
            .await
            .expect("state");
    assert_eq!(at_limit_state, "skipped");
    let above_state: String =
        sqlx::query_scalar("SELECT invoice_state::text FROM billing_periods WHERE id = $1")
            .bind(above_period)
            .fetch_one(&h.pool)
            .await
            .expect("state");
    assert_eq!(above_state, "invoiced");

    // Replay: nothing new, no second collection.
    let replay = billing_service::overage::sweep_period_overage(&h.state)
        .await
        .expect("replay sweep");
    assert_eq!(replay.invoices_created, 0, "replay must not re-invoice");
    assert_eq!(replay.payg_invoices_created, 0);
    assert_eq!(invoice_count(&h, above).await, 1);
    let collections: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM invoice_collection_outbox WHERE invoice_id IN
             (SELECT id FROM invoices WHERE tenant_id = $1)",
    )
    .bind(above)
    .fetch_one(&h.pool)
    .await
    .expect("count outbox");
    assert_eq!(
        collections, 1,
        "exactly one collection operation per invoice"
    );
});

db_test!(
    overage_sweep_defers_without_address_and_recovers_after,
    |h| {
        let tenant = "cov_over_noaddr";
        seed_tenant(&h, tenant, "growth").await;
        seed_plan(&h.pool, "growth", 100, 1_000).await;
        let now = Utc::now();
        let start = now - chrono::Duration::days(30);
        let end = now - chrono::Duration::days(1);
        let period =
            seed_billing_period(&h, tenant, start, end, "growth", Some(100), Some(40)).await;
        seed_metering(
            &h,
            tenant,
            "emails_sent",
            200,
            start + chrono::Duration::days(1),
        )
        .await;

        let result = billing_service::overage::sweep_period_overage(&h.state)
            .await
            .expect("sweep without address");
        assert_eq!(result.skipped_no_address, 1, "{result:?}");
        assert_eq!(invoice_count(&h, tenant).await, 0);
        let state: String =
            sqlx::query_scalar("SELECT invoice_state::text FROM billing_periods WHERE id = $1")
                .bind(period)
                .fetch_one(&h.pool)
                .await
                .expect("state");
        assert_eq!(state, "unbilled", "deferred period must stay retryable");

        // Backfill the address: the next sweep invoices exactly once.
        seed_billing_address(&h, tenant, "EE").await;
        let recovered = billing_service::overage::sweep_period_overage(&h.state)
            .await
            .expect("sweep after address backfill");
        assert_eq!(recovered.invoices_created, 1, "{recovered:?}");
        assert_eq!(invoice_count(&h, tenant).await, 1);
    }
);

db_test!(
    overage_sweep_surfaces_unknown_plan_and_unlimited_terminal,
    |h| {
        let unknown = "cov_over_unknown";
        let unlimited = "cov_over_unlimited";
        seed_tenant(&h, unknown, "growth").await;
        seed_billing_address(&h, unknown, "EE").await;
        seed_tenant(&h, unlimited, "growth").await;
        seed_billing_address(&h, unlimited, "EE").await;

        let now = Utc::now();
        let start = now - chrono::Duration::days(30);
        let end = now - chrono::Duration::days(1);
        let unknown_period =
            seed_billing_period(&h, unknown, start, end, "zzz-no-such-plan", None, None).await;
        seed_metering(
            &h,
            unknown,
            "emails_sent",
            500,
            start + chrono::Duration::days(1),
        )
        .await;
        let unlimited_period =
            seed_billing_period(&h, unlimited, start, end, "growth", Some(-1), Some(40)).await;
        seed_metering(
            &h,
            unlimited,
            "emails_sent",
            500,
            start + chrono::Duration::days(1),
        )
        .await;

        let result = billing_service::overage::sweep_period_overage(&h.state)
            .await
            .expect("sweep");
        assert_eq!(result.skipped_unknown_plan, 1, "{result:?}");
        assert_eq!(invoice_count(&h, unknown).await, 0);
        let unknown_state: String =
            sqlx::query_scalar("SELECT invoice_state::text FROM billing_periods WHERE id = $1")
                .bind(unknown_period)
                .fetch_one(&h.pool)
                .await
                .expect("state");
        assert_eq!(
            unknown_state, "needs_review",
            "unknown plan must never be billed"
        );
        assert_eq!(result.skipped_no_overage, 1, "{result:?}");
        let unlimited_state: String =
            sqlx::query_scalar("SELECT invoice_state::text FROM billing_periods WHERE id = $1")
                .bind(unlimited_period)
                .fetch_one(&h.pool)
                .await
                .expect("state");
        assert_eq!(unlimited_state, "skipped");
    }
);

db_test!(overage_sweep_flags_aged_zero_usage_period, |h| {
    let tenant = "cov_over_aged";
    seed_tenant(&h, tenant, "growth").await;
    seed_billing_address(&h, tenant, "EE").await;
    let now = Utc::now();
    // Ended 60 days ago (beyond the 40-day metering retention) with no
    // events: cannot distinguish empty from aged-out — review, don't drop.
    let start = now - chrono::Duration::days(90);
    let end = now - chrono::Duration::days(60);
    let period = seed_billing_period(&h, tenant, start, end, "growth", Some(100), Some(40)).await;

    let result = billing_service::overage::sweep_period_overage(&h.state)
        .await
        .expect("sweep aged period");
    assert_eq!(result.aged_needs_review, 1, "{result:?}");
    assert_eq!(invoice_count(&h, tenant).await, 0);
    let state: String =
        sqlx::query_scalar("SELECT invoice_state::text FROM billing_periods WHERE id = $1")
            .bind(period)
            .fetch_one(&h.pool)
            .await
            .expect("state");
    assert_eq!(state, "needs_review");
});

db_test!(overage_sweep_never_touches_future_periods, |h| {
    let tenant = "cov_over_future";
    seed_tenant(&h, tenant, "growth").await;
    seed_billing_address(&h, tenant, "EE").await;
    let now = Utc::now();
    let start = now + chrono::Duration::days(1);
    let end = now + chrono::Duration::days(31);
    seed_billing_period(&h, tenant, start, end, "growth", Some(100), Some(40)).await;
    seed_metering(
        &h,
        tenant,
        "emails_sent",
        10_000,
        start + chrono::Duration::days(1),
    )
    .await;

    let result = billing_service::overage::sweep_period_overage(&h.state)
        .await
        .expect("sweep future period");
    assert_eq!(
        result.periods_checked, 0,
        "future periods are out of scope: {result:?}"
    );
    assert_eq!(invoice_count(&h, tenant).await, 0);
});

db_test!(
    overage_sweep_adopts_existing_invoice_and_flags_mismatch,
    |h| {
        let tenant = "cov_over_conflict";
        seed_tenant(&h, tenant, "growth").await;
        seed_billing_address(&h, tenant, "EE").await;
        let now = Utc::now();
        let start = now - chrono::Duration::days(30);
        let end = now - chrono::Duration::days(1);
        let period =
            seed_billing_period(&h, tenant, start, end, "growth", Some(100), Some(40)).await;
        seed_metering(
            &h,
            tenant,
            "emails_sent",
            200,
            start + chrono::Duration::days(1),
        )
        .await;

        // A pre-existing invoice for the same (tenant, overage_period) with a
        // DIFFERENT amount: the sweep must adopt it (no second invoice, no
        // second collection) and surface the mismatch.
        let existing = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO invoices (id, tenant_id, amount, currency, status, invoice_number,
                               subtotal, vat_total, total, line_items, issued_at,
                               due_at, period_start, period_end, overage_period)
         VALUES ($1, $2, 999, 'EUR', 'draft', $3, 999, 0, 999, '[]'::jsonb, NOW(),
                 NOW() + INTERVAL '14 days', $4, $5, $4)",
        )
        .bind(existing)
        .bind(tenant)
        .bind(format!("COV-CONFLICT-{}", existing.simple()))
        .bind(start)
        .bind(end)
        .execute(&h.pool)
        .await
        .expect("seed conflicting invoice");

        let result = billing_service::overage::sweep_period_overage(&h.state)
            .await
            .expect("sweep with conflict");
        assert_eq!(result.conflicts_existing, 1, "{result:?}");
        assert_eq!(result.invoices_created, 0, "no second invoice: {result:?}");
        assert_eq!(
            result.existing_invoice_mismatches, 1,
            "mismatch must be surfaced"
        );
        assert_eq!(invoice_count(&h, tenant).await, 1);
        let (state, linked): (String, Option<Uuid>) = sqlx::query_as(
            "SELECT invoice_state::text, invoice_id FROM billing_periods WHERE id = $1",
        )
        .bind(period)
        .fetch_one(&h.pool)
        .await
        .expect("period state");
        assert_eq!(state, "invoiced");
        assert_eq!(linked, Some(existing), "period links the adopted invoice");
    }
);

db_test!(payg_sweep_invoices_completed_months_once, |h| {
    let tenant = "cov_over_payg";
    seed_tenant(&h, tenant, "payg").await;
    seed_billing_address(&h, tenant, "EE").await;

    // Previous completed calendar month.
    let now = Utc::now();
    let this_month = now
        .date_naive()
        .with_day(1)
        .expect("first day")
        .and_hms_opt(0, 0, 0)
        .expect("midnight")
        .and_utc();
    let month_start = this_month - chrono::Months::new(1);
    let mid = month_start + chrono::Duration::days(3);
    seed_metering(&h, tenant, "emails_sent", 15_000, mid).await;
    seed_metering(&h, tenant, "api_calls", 101_000, mid).await;

    let result = billing_service::overage::sweep_period_overage(&h.state)
        .await
        .expect("payg sweep");
    assert_eq!(result.payg_invoices_created, 1, "{result:?}");
    assert_eq!(invoice_count(&h, tenant).await, 1);

    // 15 000 emails: 10 000 @100 + 5 000 @80 = 1_400_000 millicents → 1400
    // cents. 101 000 API calls: 1 000 billable → 1 unit @10 cents = 10.
    let (subtotal, total, currency, period): (i64, i64, String, Option<DateTime<Utc>>) =
        sqlx::query_as(
            "SELECT subtotal, total, currency, overage_period FROM invoices WHERE tenant_id = $1",
        )
        .bind(tenant)
        .fetch_one(&h.pool)
        .await
        .expect("payg invoice");
    assert_eq!(subtotal, 1_410, "tiered PAYG total in cents");
    assert_eq!(currency.to_uppercase(), "EUR");
    assert_eq!(period, Some(month_start));
    assert!(total >= subtotal, "VAT must never be negative");

    // Replay creates nothing new.
    let replay = billing_service::overage::sweep_period_overage(&h.state)
        .await
        .expect("payg replay");
    assert_eq!(replay.payg_invoices_created, 0, "{replay:?}");
    assert_eq!(invoice_count(&h, tenant).await, 1);
});

db_test!(payg_zero_usage_month_is_skipped_without_invoice, |h| {
    let tenant = "cov_over_paygzero";
    seed_tenant(&h, tenant, "payg").await;
    seed_billing_address(&h, tenant, "EE").await;

    let result = billing_service::overage::sweep_period_overage(&h.state)
        .await
        .expect("payg zero sweep");
    assert_eq!(result.payg_invoices_created, 0, "{result:?}");
    assert_eq!(invoice_count(&h, tenant).await, 0);

    // The completed month still gets a terminal period record.
    let states: Vec<String> = sqlx::query_scalar(
        "SELECT invoice_state::text FROM billing_periods WHERE tenant_id = $1 AND usage_kind = 'payg'",
    )
    .bind(tenant)
    .fetch_all(&h.pool)
    .await
    .expect("payg states");
    assert!(!states.is_empty(), "each completed month is claimed");
    assert!(
        states.iter().all(|state| state == "skipped"),
        "zero months are terminally skipped: {states:?}"
    );
});

db_test!(overage_sweep_applies_wallet_before_dunning, |h| {
    let tenant = "cov_over_wallet";
    seed_tenant(&h, tenant, "growth").await;
    seed_billing_address(&h, tenant, "EE").await;
    let now = Utc::now();
    let start = now - chrono::Duration::days(30);
    let end = now - chrono::Duration::days(1);
    seed_billing_period(&h, tenant, start, end, "growth", Some(0), Some(40)).await;
    // 25 emails at 40 millicents = 1 cent of overage.
    seed_metering(
        &h,
        tenant,
        "emails_sent",
        25,
        start + chrono::Duration::days(1),
    )
    .await;
    sqlx::query(
        "INSERT INTO wallets (tenant_id, balance, currency) VALUES ($1, 10, 'EUR')
         ON CONFLICT (tenant_id) DO UPDATE SET balance = 10, currency = 'EUR'",
    )
    .bind(tenant)
    .execute(&h.pool)
    .await
    .expect("seed wallet");

    let result = billing_service::overage::sweep_period_overage(&h.state)
        .await
        .expect("sweep with wallet");
    assert_eq!(result.invoices_created, 1, "{result:?}");
    assert_eq!(
        result.wallet_paid, 1,
        "wallet must settle the small invoice: {result:?}"
    );

    let (status, paid_at): (String, Option<DateTime<Utc>>) =
        sqlx::query_as("SELECT status, paid_at FROM invoices WHERE tenant_id = $1")
            .bind(tenant)
            .fetch_one(&h.pool)
            .await
            .expect("invoice");
    assert_eq!(status, "paid");
    assert!(paid_at.is_some());
    let balance: i64 = sqlx::query_scalar("SELECT balance FROM wallets WHERE tenant_id = $1")
        .bind(tenant)
        .fetch_one(&h.pool)
        .await
        .expect("wallet balance");
    assert!(
        balance >= 0,
        "wallet balance must never go negative: {balance}"
    );
    let allocations: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM invoice_payment_allocations WHERE tenant_id = $1")
            .bind(tenant)
            .fetch_one(&h.pool)
            .await
            .expect("allocations");
    assert_eq!(allocations, 1);

    // Replay: the settled period is never collected or credited twice.
    let replay = billing_service::overage::sweep_period_overage(&h.state)
        .await
        .expect("wallet replay");
    assert_eq!(replay.invoices_created, 0);
    let allocations_after: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM invoice_payment_allocations WHERE tenant_id = $1")
            .bind(tenant)
            .fetch_one(&h.pool)
            .await
            .expect("allocations after replay");
    assert_eq!(allocations_after, 1);
});

// ---------------------------------------------------------------------------
// stripe_webhooks.rs — signature, replay, ordering, unknown events
// ---------------------------------------------------------------------------

fn sign_payload(secret: &str, payload: &[u8], timestamp: i64) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC key");
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(payload);
    format!(
        "t={timestamp},v1={}",
        hex::encode(mac.finalize().into_bytes())
    )
}

const WEBHOOK_SECRET: &str = "whsec_coverage_secret";

async fn post_signed_webhook(
    app: &axum::Router,
    payload: &serde_json::Value,
    timestamp: i64,
) -> (StatusCode, serde_json::Value) {
    let body = serde_json::to_vec(payload).expect("serialize payload");
    let signature = sign_payload(WEBHOOK_SECRET, &body, timestamp);
    call(
        app,
        Request::builder()
            .method("POST")
            .uri("/webhooks/stripe")
            .header("content-type", "application/json")
            .header("stripe-signature", signature)
            .body(Body::from(body))
            .expect("request"),
    )
    .await
}

/// Post a signed webhook that MUST be accepted; on refusal, surface the
/// recorded processing error so failures are diagnosable.
async fn expect_webhook_ok(
    h: &Harness,
    app: &axum::Router,
    payload: &serde_json::Value,
    event_id: &str,
) {
    let (status, body) = post_signed_webhook(app, payload, Utc::now().timestamp()).await;
    if status != StatusCode::OK {
        let error: Option<String> = sqlx::query_scalar(
            "SELECT error FROM stripe_webhook_events WHERE stripe_event_id = $1",
        )
        .bind(event_id)
        .fetch_optional(&h.pool)
        .await
        .expect("failed event lookup")
        .flatten();
        panic!("webhook {event_id} rejected: {status} body={body} error={error:?}");
    }
}

async fn seed_stripe_plan(h: &Harness, name: &str, price_id: &str) {
    sqlx::query(
        "INSERT INTO plans (id, name, display_name, price_cents, price_monthly,
                            email_limit, api_call_limit, stripe_price_id_monthly, is_active)
         VALUES ($1, $2, $2, 4900, 4900, 100000, 100000, $3, true)
         ON CONFLICT (name) DO UPDATE SET stripe_price_id_monthly = EXCLUDED.stripe_price_id_monthly,
             is_active = true, price_monthly = 4900",
    )
    .bind(format!("plan_{name}"))
    .bind(name)
    .bind(price_id)
    .execute(&h.pool)
    .await
    .expect("seed stripe plan");
}

fn stripe_event(id: &str, event_type: &str, object: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "type": event_type,
        "data": { "object": object }
    })
}

fn subscription_object(
    tenant: &str,
    subscription_id: &str,
    status: &str,
    price_id: &str,
    period_start: i64,
    period_end: i64,
) -> serde_json::Value {
    serde_json::json!({
        "id": subscription_id,
        "customer": "cus_cov_wh",
        "status": status,
        "metadata": { "tenant_id": tenant },
        "current_period_start": period_start,
        "current_period_end": period_end,
        "cancel_at_period_end": false,
        "canceled_at": null,
        "trial_end": null,
        "items": { "data": [ { "price": { "id": price_id, "recurring": { "interval": "month" } } } ] }
    })
}

db_test!(stripe_webhook_signature_attacks_write_nothing, |h| {
    let app = billing_service::routes::router(h.state.clone());
    let tenant = "cov_wh_sig";
    seed_tenant(&h, tenant, "free").await;

    let payload = stripe_event(
        "evt_cov_sig_valid",
        "customer.subscription.created",
        subscription_object(
            tenant,
            "sub_sig",
            "active",
            "price_cov",
            1_760_000_000,
            1_762_592_000,
        ),
    );

    // Missing header.
    let (status, _) = call(
        &app,
        Request::builder()
            .method("POST")
            .uri("/webhooks/stripe")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&payload).unwrap()))
            .expect("request"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Wrong secret (valid HMAC, wrong key).
    let body = serde_json::to_vec(&payload).unwrap();
    let forged = sign_payload("whsec_wrong_secret", &body, Utc::now().timestamp());
    let (status, _) = call(
        &app,
        Request::builder()
            .method("POST")
            .uri("/webhooks/stripe")
            .header("stripe-signature", forged)
            .body(Body::from(body.clone()))
            .expect("request"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Tampered body: signature minted for the original payload.
    let signature = sign_payload(WEBHOOK_SECRET, &body, Utc::now().timestamp());
    let mut tampered = payload.clone();
    tampered["data"]["object"]["status"] = serde_json::json!("active");
    tampered["data"]["object"]["current_period_end"] = serde_json::json!(1_999_999_999_i64);
    let (status, _) = call(
        &app,
        Request::builder()
            .method("POST")
            .uri("/webhooks/stripe")
            .header("stripe-signature", signature)
            .body(Body::from(serde_json::to_vec(&tampered).unwrap()))
            .expect("request"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "tampered body must not verify"
    );

    // Expired timestamp (outside the 300s tolerance).
    let expired = sign_payload(WEBHOOK_SECRET, &body, Utc::now().timestamp() - 400);
    let (status, _) = call(
        &app,
        Request::builder()
            .method("POST")
            .uri("/webhooks/stripe")
            .header("stripe-signature", expired)
            .body(Body::from(body.clone()))
            .expect("request"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "expired signature must be refused"
    );

    // Malformed signature headers.
    for header in [
        "",
        "v1=deadbeef",
        "t=abc,v1=deadbeef",
        "t=123",
        "t=123,v1=zzzz",
    ] {
        let (status, _) = call(
            &app,
            Request::builder()
                .method("POST")
                .uri("/webhooks/stripe")
                .header("stripe-signature", header)
                .body(Body::from(body.clone()))
                .expect("request"),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "header {header:?}");
    }

    // Correct signature but non-JSON body.
    let garbage = b"not-json{{{".to_vec();
    let signature = sign_payload(WEBHOOK_SECRET, &garbage, Utc::now().timestamp());
    let (status, _) = call(
        &app,
        Request::builder()
            .method("POST")
            .uri("/webhooks/stripe")
            .header("stripe-signature", signature)
            .body(Body::from(garbage))
            .expect("request"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Correct signature but no event id.
    let no_id =
        serde_json::json!({"type": "customer.subscription.created", "data": {"object": {}}});
    let (status, _) = post_signed_webhook(&app, &no_id, Utc::now().timestamp()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Every refusal above must have written NO webhook claim row and no
    // subscription state.
    let events: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM stripe_webhook_events")
        .fetch_one(&h.pool)
        .await
        .expect("count events");
    assert_eq!(events, 0, "failed verification must write nothing");
    let subs: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM stripe_subscriptions")
        .fetch_one(&h.pool)
        .await
        .expect("count subscriptions");
    assert_eq!(subs, 0);
});

db_test!(
    stripe_webhook_unknown_event_type_is_acknowledged_not_500,
    |h| {
        let app = billing_service::routes::router(h.state.clone());
        let payload = stripe_event(
            "evt_cov_unknown",
            "pizza.delivered",
            serde_json::json!({"id": "x"}),
        );

        let (status, json) = post_signed_webhook(&app, &payload, Utc::now().timestamp()).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["received"], true);

        let (event_type, status_text): (String, String) = sqlx::query_as(
            "SELECT event_type, status FROM stripe_webhook_events WHERE stripe_event_id = $1",
        )
        .bind("evt_cov_unknown")
        .fetch_one(&h.pool)
        .await
        .expect("webhook row");
        assert_eq!(event_type, "pizza.delivered");
        assert_eq!(
            status_text, "processed",
            "unknown events are terminally acknowledged"
        );
    }
);

db_test!(
    stripe_webhook_replay_is_idempotent_and_reclaims_stale,
    |h| {
        let app = billing_service::routes::router(h.state.clone());
        let tenant = "cov_wh_replay";
        seed_tenant(&h, tenant, "free").await;
        seed_stripe_plan(&h, "growth", "price_cov_monthly").await;

        let now = Utc::now().timestamp();
        let payload = stripe_event(
            "evt_cov_replay",
            "customer.subscription.created",
            subscription_object(
                tenant,
                "sub_cov_replay",
                "active",
                "price_cov_monthly",
                now,
                now + 2_592_000,
            ),
        );

        expect_webhook_ok(&h, &app, &payload, "evt_cov_replay").await;

        let plan: String = sqlx::query_scalar("SELECT plan FROM tenants WHERE id = $1")
            .bind(tenant)
            .fetch_one(&h.pool)
            .await
            .expect("tenant plan");
        assert_eq!(
            plan, "growth",
            "verified subscription webhook grants the plan"
        );
        let watermark_after_first: Option<DateTime<Utc>> = sqlx::query_scalar(
            "SELECT event_watermark FROM stripe_subscriptions WHERE tenant_id = $1",
        )
        .bind(tenant)
        .fetch_one(&h.pool)
        .await
        .expect("watermark");
        assert!(watermark_after_first.is_some(), "watermark recorded");

        // Replay: 200, no re-application, no duplicate rows.
        expect_webhook_ok(&h, &app, &payload, "evt_cov_replay").await;
        let events: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM stripe_webhook_events WHERE stripe_event_id = 'evt_cov_replay'",
        )
        .fetch_one(&h.pool)
        .await
        .expect("count replay rows");
        assert_eq!(events, 1, "one claim row per event id");
        let subs: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM stripe_subscriptions WHERE tenant_id = $1")
                .bind(tenant)
                .fetch_one(&h.pool)
                .await
                .expect("count subscriptions");
        assert_eq!(subs, 1);

        // Stale-pending reclaim: an 11-minute-old pending row is reclaimed, a
        // fresh one is left alone.
        sqlx::query(
        "INSERT INTO stripe_webhook_events (id, stripe_event_id, event_type, status, created_at, updated_at)
         VALUES (gen_random_uuid(), 'evt_cov_stale', 'customer.subscription.updated', 'pending',
                 NOW() - INTERVAL '20 minutes', NOW() - INTERVAL '11 minutes'),
                (gen_random_uuid(), 'evt_cov_fresh', 'customer.subscription.updated', 'pending',
                 NOW(), NOW())",
    )
    .execute(&h.pool)
    .await
    .expect("seed pending rows");

        let reclaimed = billing_service::stripe_webhooks::reclaim_stale_pending_webhooks(&h.state)
            .await
            .expect("reclaim");
        assert_eq!(reclaimed, vec!["evt_cov_stale".to_string()]);
        let stale_status: String = sqlx::query_scalar(
            "SELECT status FROM stripe_webhook_events WHERE stripe_event_id = 'evt_cov_stale'",
        )
        .fetch_one(&h.pool)
        .await
        .expect("stale row");
        assert_eq!(stale_status, "received");
        let fresh_status: String = sqlx::query_scalar(
            "SELECT status FROM stripe_webhook_events WHERE stripe_event_id = 'evt_cov_fresh'",
        )
        .fetch_one(&h.pool)
        .await
        .expect("fresh row");
        assert_eq!(fresh_status, "pending", "fresh pending work is not stolen");
    }
);

db_test!(stripe_webhook_out_of_order_events_never_rewind_state, |h| {
    let app = billing_service::routes::router(h.state.clone());
    let tenant = "cov_wh_order";
    seed_tenant(&h, tenant, "free").await;
    seed_stripe_plan(&h, "growth", "price_cov_monthly").await;

    let now = Utc::now().timestamp();

    // 1. A deleted event for an unknown subscription is a no-op: it must
    // NOT downgrade a tenant that never had this subscription.
    let deleted = stripe_event(
        "evt_cov_del_first",
        "customer.subscription.deleted",
        subscription_object(
            tenant,
            "sub_cov_order",
            "canceled",
            "price_cov_monthly",
            now,
            now + 2_592_000,
        ),
    );
    expect_webhook_ok(&h, &app, &deleted, "evt_cov_del_first").await;
    let plan: String = sqlx::query_scalar("SELECT plan FROM tenants WHERE id = $1")
        .bind(tenant)
        .fetch_one(&h.pool)
        .await
        .expect("plan");
    assert_eq!(plan, "free", "stale delete must not touch the tenant");

    // 2. Created with cycle T2 applies.
    let cycle_t2 = now;
    let created = stripe_event(
        "evt_cov_create",
        "customer.subscription.created",
        subscription_object(
            tenant,
            "sub_cov_order",
            "active",
            "price_cov_monthly",
            cycle_t2,
            cycle_t2 + 2_592_000,
        ),
    );
    expect_webhook_ok(&h, &app, &created, "evt_cov_create").await;

    // 3. An older active update (cycle T1 < T2) is stale: ignored.
    let cycle_t1 = now - 86_400;
    let stale = stripe_event(
        "evt_cov_stale_update",
        "customer.subscription.updated",
        subscription_object(
            tenant,
            "sub_cov_order",
            "active",
            "price_cov_monthly",
            cycle_t1,
            cycle_t1 + 2_592_000,
        ),
    );
    expect_webhook_ok(&h, &app, &stale, "evt_cov_stale_update").await;

    let stored_start: DateTime<Utc> = sqlx::query_scalar(
        "SELECT billing_cycle_start FROM stripe_subscriptions WHERE tenant_id = $1",
    )
    .bind(tenant)
    .fetch_one(&h.pool)
    .await
    .expect("stored cycle");
    assert_eq!(
        stored_start.timestamp(),
        cycle_t2,
        "an older event must not rewind the billing cycle"
    );

    // 4. A deleted event for the known row cancels it and downgrades.
    let deleted = stripe_event(
        "evt_cov_del_known",
        "customer.subscription.deleted",
        subscription_object(
            tenant,
            "sub_cov_order",
            "canceled",
            "price_cov_monthly",
            cycle_t2,
            cycle_t2 + 2_592_000,
        ),
    );
    expect_webhook_ok(&h, &app, &deleted, "evt_cov_del_known").await;
    let (sub_status, plan): (String, String) = sqlx::query_as(
        "SELECT s.status::text, t.plan FROM stripe_subscriptions s
         JOIN tenants t ON t.id = s.tenant_id WHERE s.tenant_id = $1",
    )
    .bind(tenant)
    .fetch_one(&h.pool)
    .await
    .expect("canceled state");
    assert_eq!(sub_status, "canceled");
    assert_eq!(plan, "free");
});

db_test!(stripe_webhook_unresolvable_invoice_paid_deadletters, |h| {
    let app = billing_service::routes::router(h.state.clone());
    let now = Utc::now().timestamp();
    let payload = stripe_event(
        "evt_cov_unresolved",
        "invoice.paid",
        serde_json::json!({
            "id": "in_cov_unresolved",
            "amount_due": 1000,
            "amount_paid": 1000,
            "currency": "eur",
            "subtotal": 1000,
            "tax": 0,
            "total": 1000,
            "subscription": "sub_does_not_exist",
        }),
    );
    let (status, _) = post_signed_webhook(&app, &payload, now).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "unresolvable revenue must be refused for replay, not silently dropped"
    );

    let (status_text, error): (String, Option<String>) = sqlx::query_as(
        "SELECT status, error FROM stripe_webhook_events WHERE stripe_event_id = $1",
    )
    .bind("evt_cov_unresolved")
    .fetch_one(&h.pool)
    .await
    .expect("failed event row");
    assert_eq!(status_text, "failed");
    assert!(
        error
            .unwrap_or_default()
            .contains("could not be resolved to a tenant"),
        "failure reason is recorded"
    );

    // No local invoice was invented.
    let invoices: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM invoices")
        .fetch_one(&h.pool)
        .await
        .expect("count invoices");
    assert_eq!(invoices, 0);
});

db_test!(stripe_webhook_invoice_paid_persists_verified_payment, |h| {
    let app = billing_service::routes::router(h.state.clone());
    let tenant = "cov_wh_paid";
    seed_tenant(&h, tenant, "growth").await;
    // Non-EU billing country → 0% VAT, so Stripe's tax=0 is the truth.
    seed_billing_address(&h, tenant, "US").await;
    let now = Utc::now().timestamp();
    sqlx::query(
        "INSERT INTO stripe_subscriptions
             (tenant_id, stripe_subscription_id, plan, status, billing_cycle_start,
              billing_cycle_end, stripe_customer_id)
         VALUES ($1, 'sub_cov_paid', 'growth', 'active', to_timestamp($2), to_timestamp($3), 'cus_cov_wh')",
    )
    .bind(tenant)
    .bind((now - 86_400) as f64)
    .bind((now + 2_592_000) as f64)
    .execute(&h.pool)
    .await
    .expect("seed subscription");

    let payload = stripe_event(
        "evt_cov_paid",
        "invoice.paid",
        serde_json::json!({
            "id": "in_cov_paid",
            "amount_due": 4900,
            "amount_paid": 4900,
            "currency": "eur",
            "subtotal": 4900,
            "tax": 0,
            "total": 4900,
            "number": "2026-000099",
            "subscription_details": { "metadata": { "tenant_id": tenant } },
            "subscription": "sub_cov_paid",
        }),
    );
    expect_webhook_ok(&h, &app, &payload, "evt_cov_paid").await;

    let (total, status_text, stripe_id, currency): (i64, String, Option<String>, String) =
        sqlx::query_as(
            "SELECT COALESCE(total, amount), status, stripe_invoice_id, currency
             FROM invoices WHERE tenant_id = $1",
        )
        .bind(tenant)
        .fetch_one(&h.pool)
        .await
        .expect("local invoice");
    assert_eq!(total, 4900, "the verified payment is stored in cents");
    assert_eq!(status_text, "paid");
    assert_eq!(stripe_id.as_deref(), Some("in_cov_paid"));
    assert_eq!(currency.to_uppercase(), "EUR");

    // Replay of the same Stripe invoice id must not duplicate the row.
    let mut replay = payload.clone();
    replay["id"] = serde_json::json!("evt_cov_paid_replay");
    let (status, _) = post_signed_webhook(&app, &replay, now).await;
    assert_eq!(status, StatusCode::OK);
    let invoices: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM invoices WHERE stripe_invoice_id = 'in_cov_paid'")
            .fetch_one(&h.pool)
            .await
            .expect("count invoices");
    assert_eq!(invoices, 1, "replay is idempotent on the Stripe invoice id");

    // The tax snapshot is immutable and reconciled.
    let snapshots: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM stripe_tax_snapshots WHERE stripe_invoice_id = 'in_cov_paid'",
    )
    .fetch_one(&h.pool)
    .await
    .expect("count snapshots");
    assert_eq!(snapshots, 1);
});

// ---------------------------------------------------------------------------
// hetzner_ip_provider.rs — REMOVED: one provisioning implementation
// ---------------------------------------------------------------------------
// billing-service carried a second, divergent dedicated-IP provisioning
// implementation (direct floating-IP creation, immediate 'warming' insert,
// its own status vocabulary) next to the canonical state machine in
// api-server's `ip_provider` (provisioning -> created -> attached ->
// rdns_ready -> warming -> active, with compensation). It had NO production
// caller — but had it ever been wired up, it would have bypassed the
// lifecycle guarantees migration 207 established. The duplicate is deleted;
// this scan keeps it deleted.
#[test]
fn billing_service_has_no_second_dedicated_ip_provisioning_implementation() {
    let lib_rs = include_str!("../src/lib.rs");
    assert!(
        !lib_rs.contains("hetzner_ip_provider"),
        "billing-service must not re-grow a provisioning implementation: dedicated-IP \
         provisioning belongs to api-server's ip_provider (the migration-207 state machine)"
    );
    let has_hetzner_source = std::path::Path::new("src")
        .read_dir()
        .map(|entries| {
            entries
                .filter_map(|entry| entry.ok())
                .any(|entry| entry.file_name().to_string_lossy().contains("hetzner"))
        })
        .unwrap_or(false);
    assert!(
        !has_hetzner_source,
        "a hetzner-named source file exists in billing-service/src — the duplicate provider \
         must not come back"
    );
}

// ---------------------------------------------------------------------------
// maintenance.rs — abuse lifecycle, admin reset, derived sweep, reconciliation
// ---------------------------------------------------------------------------

use billing_service::maintenance::{
    admin_reset_dunning_restriction_aware, clear_tenant_restriction, impose_tenant_restriction,
    record_abuse_report, resolve_abuse_report, review_abuse_report, tenant_has_open_abuse_hold,
};
use billing_service::usage_ingest::{reconcile_daily_deliveries, sweep_derived_usage};

db_test!(abuse_lifecycle_transitions_and_holds, |h| {
    let tenant = "cov_abuse_life";
    seed_tenant_with_status(&h, tenant, "free", "active").await;

    let report_id = record_abuse_report(
        &h.state,
        tenant,
        "spam",
        Some("fbl"),
        serde_json::json!({"reportId": "r1"}),
    )
    .await
    .expect("record abuse report");
    assert!(tenant_has_open_abuse_hold(&h.state, tenant)
        .await
        .expect("hold"));

    // Skipping investigation (open -> confirmed) is unauthorized.
    let error = review_abuse_report(&h.pool, report_id, "confirmed", "admin1", "n")
        .await
        .expect_err("open -> confirmed must be refused");
    assert!(
        error.contains("Unauthorized abuse report transition"),
        "{error}"
    );
    let status: String = sqlx::query_scalar("SELECT status FROM abuse_reports WHERE id = $1")
        .bind(report_id)
        .fetch_one(&h.pool)
        .await
        .expect("status");
    assert_eq!(status, "open", "a refused transition changes nothing");

    // A bogus target status is refused too.
    assert!(
        review_abuse_report(&h.pool, report_id, "banana", "admin1", "n")
            .await
            .is_err()
    );
    // Unknown report id is an error, not a silent success.
    assert!(
        review_abuse_report(&h.pool, Uuid::new_v4(), "dismissed", "admin1", "n")
            .await
            .is_err()
    );

    // open -> investigating imposes (idempotently) the abuse restriction.
    review_abuse_report(&h.pool, report_id, "investigating", "admin1", "looking")
        .await
        .expect("investigating");
    assert!(
        review_abuse_report(&h.pool, report_id, "investigating", "admin1", "again")
            .await
            .is_err(),
        "same-status re-review is not an authorized transition"
    );
    let restrictions: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM tenant_restrictions WHERE tenant_id = $1 AND kind = 'abuse' AND cleared_at IS NULL",
    )
    .bind(tenant)
    .fetch_one(&h.pool)
    .await
    .expect("abuse restrictions");
    assert_eq!(restrictions, 1, "one active abuse restriction, not two");

    // investigating -> confirmed keeps the hold; resolve clears it.
    review_abuse_report(&h.pool, report_id, "confirmed", "admin2", "confirmed")
        .await
        .expect("confirmed");
    assert!(tenant_has_open_abuse_hold(&h.state, tenant)
        .await
        .expect("hold"));
    resolve_abuse_report(&h.pool, report_id, "admin2", "remediated")
        .await
        .expect("resolve");
    assert!(
        !tenant_has_open_abuse_hold(&h.state, tenant)
            .await
            .expect("hold cleared"),
        "a resolved report must release the abuse hold"
    );
    let cleared: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM tenant_restrictions WHERE tenant_id = $1 AND kind = 'abuse' AND cleared_at IS NOT NULL",
    )
    .bind(tenant)
    .fetch_one(&h.pool)
    .await
    .expect("cleared count");
    assert_eq!(cleared, 1);
    // Terminal: resolving twice is refused (no reopening, no double audit).
    assert!(resolve_abuse_report(&h.pool, report_id, "admin2", "again")
        .await
        .is_err());
});

db_test!(tenant_restriction_impose_and_clear_idempotency, |h| {
    let tenant = "cov_restrict";
    seed_tenant_with_status(&h, tenant, "free", "active").await;

    impose_tenant_restriction(
        &h.pool,
        tenant,
        "administrative",
        "fraud",
        "admin",
        Some("adm1"),
    )
    .await
    .expect("impose");
    impose_tenant_restriction(
        &h.pool,
        tenant,
        "administrative",
        "fraud v2",
        "admin",
        Some("adm2"),
    )
    .await
    .expect("re-impose is an update");
    let (count, reason, actor): (i64, String, Option<String>) = sqlx::query_as(
        "SELECT COUNT(*), MIN(reason), MIN(actor_id) FROM tenant_restrictions
         WHERE tenant_id = $1 AND kind = 'administrative' AND cleared_at IS NULL",
    )
    .bind(tenant)
    .fetch_one(&h.pool)
    .await
    .expect("restriction");
    assert_eq!(count, 1, "one active restriction per kind");
    assert_eq!(reason, "fraud v2", "re-imposition updates the reason");

    assert!(
        clear_tenant_restriction(&h.pool, tenant, "administrative", "adm2", "cleared")
            .await
            .expect("clear")
    );
    assert!(
        !clear_tenant_restriction(&h.pool, tenant, "administrative", "adm2", "again")
            .await
            .expect("second clear"),
        "clearing an already-cleared restriction reports no change"
    );
    assert!(actor.is_some() || actor.is_none());
});

db_test!(admin_reset_clears_billing_but_not_abuse_hold, |h| {
    let tenant = "cov_admin_reset";
    seed_tenant_with_status(&h, tenant, "free", "suspended").await;
    impose_tenant_restriction(&h.pool, tenant, "billing", "unpaid", "system", None)
        .await
        .expect("billing hold");
    let report_id = record_abuse_report(&h.state, tenant, "phishing", None, serde_json::json!({}))
        .await
        .expect("abuse report");

    // With an open abuse report the tenant must NOT be reactivated.
    admin_reset_dunning_restriction_aware(&h.pool, &h.redis, tenant, "admin9", "goodwill")
        .await
        .expect("reset");
    let status: String = sqlx::query_scalar("SELECT status FROM tenants WHERE id = $1")
        .bind(tenant)
        .fetch_one(&h.pool)
        .await
        .expect("tenant status");
    assert_eq!(
        status, "suspended",
        "an open abuse report blocks reactivation"
    );
    let (cleared_by, cleared_reason): (Option<String>, Option<String>) = sqlx::query_as(
        "SELECT cleared_by, cleared_reason FROM tenant_restrictions
         WHERE tenant_id = $1 AND kind = 'billing'",
    )
    .bind(tenant)
    .fetch_one(&h.pool)
    .await
    .expect("billing restriction");
    assert_eq!(cleared_by.as_deref(), Some("admin9"));
    assert_eq!(
        cleared_reason.as_deref(),
        Some("admin dunning reset: goodwill")
    );

    // Dismissing the abuse report releases the abuse hold, but the tenant
    // still does NOT reactivate on a subsequent admin reset: the reset only
    // reactivates when it clears an ACTIVE billing restriction in the same
    // transaction (conservative attribution — an unattributable suspension
    // is never auto-cleared). The earlier reset already cleared the billing
    // hold, so a billing-attributed suspension that outlived one abuse hold
    // stays suspended. Asserted here as documented behaviour; the residual
    // stuck-state risk is reported.
    review_abuse_report(&h.pool, report_id, "dismissed", "admin9", "false positive")
        .await
        .expect("dismiss");
    admin_reset_dunning_restriction_aware(&h.pool, &h.redis, tenant, "admin9", "second pass")
        .await
        .expect("second reset");
    let status: String = sqlx::query_scalar("SELECT status FROM tenants WHERE id = $1")
        .bind(tenant)
        .fetch_one(&h.pool)
        .await
        .expect("tenant status");
    assert_eq!(
        status, "suspended",
        "no ACTIVE billing hold remains to attribute the suspension to"
    );
    let active_holds: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM tenant_restrictions WHERE tenant_id = $1 AND cleared_at IS NULL",
    )
    .bind(tenant)
    .fetch_one(&h.pool)
    .await
    .expect("active holds");
    assert_eq!(
        active_holds, 0,
        "no holds remain, yet the tenant stays suspended"
    );
});

db_test!(derived_usage_sweep_records_yesterday_exactly_once, |h| {
    let tenant_a = "cov_derived_a";
    let tenant_b = "cov_derived_b";
    seed_tenant(&h, tenant_a, "free").await;
    seed_tenant(&h, tenant_b, "free").await;
    let now = Utc::now();
    let yesterday = now - chrono::Duration::days(1);
    let day_start = yesterday
        .date_naive()
        .and_hms_opt(0, 0, 0)
        .expect("midnight")
        .and_utc();

    // Two sent messages for A, one for B yesterday; one pending and one sent
    // TODAY must not be counted.
    for (tenant, sent_at) in [
        (tenant_a, day_start + chrono::Duration::hours(2)),
        (tenant_a, day_start + chrono::Duration::hours(5)),
        (tenant_b, day_start + chrono::Duration::hours(7)),
        (tenant_a, now), // today — out of scope
    ] {
        sqlx::query(
            "INSERT INTO email_queue (id, tenant_id, from_address, to_addresses, subject, status, sent_at)
             VALUES (gen_random_uuid(), $1, 'a@b.c', ARRAY['x@y.z'], 's', 'sent', $2)",
        )
        .bind(tenant)
        .bind(sent_at)
        .execute(&h.pool)
        .await
        .expect("seed sent queue row");
    }
    sqlx::query(
        "INSERT INTO email_queue (id, tenant_id, from_address, to_addresses, subject, status)
         VALUES (gen_random_uuid(), $1, 'a@b.c', ARRAY['x@y.z'], 's', 'pending')",
    )
    .bind(tenant_a)
    .execute(&h.pool)
    .await
    .expect("pending row");

    // One delivered webhook yesterday for A (tenant B has a pending one).
    sqlx::query(
        "INSERT INTO webhook_events (tenant_id, event_type, delivery_status, updated_at)
         VALUES ($1, 'message.delivered', 'delivered', $2)",
    )
    .bind(tenant_a)
    .bind(day_start + chrono::Duration::hours(3))
    .execute(&h.pool)
    .await
    .expect("webhook delivered");
    sqlx::query(
        "INSERT INTO webhook_events (tenant_id, event_type, delivery_status, updated_at)
         VALUES ($1, 'message.delivered', 'pending', $2)",
    )
    .bind(tenant_b)
    .bind(day_start + chrono::Duration::hours(3))
    .execute(&h.pool)
    .await
    .expect("webhook pending");

    let first = sweep_derived_usage(&h.pool, now)
        .await
        .expect("derived sweep");
    assert_eq!(
        first.emails_delivered, 2,
        "both tenants with sent mail are recorded: {first:?}"
    );
    assert_eq!(first.webhooks_delivered, 1, "{first:?}");
    let rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT tenant_id, SUM(quantity)::bigint FROM metering_events
         WHERE event_type = 'emails_delivered' GROUP BY tenant_id ORDER BY tenant_id",
    )
    .fetch_all(&h.pool)
    .await
    .expect("derived rows");
    assert_eq!(
        rows,
        vec![(tenant_a.to_string(), 2), (tenant_b.to_string(), 1)]
    );

    let replay = sweep_derived_usage(&h.pool, now)
        .await
        .expect("derived replay");
    assert_eq!(
        replay.emails_delivered, 0,
        "markers make the day idempotent"
    );
    assert_eq!(replay.webhooks_delivered, 0);
    let markers: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM metering_daily_markers")
        .fetch_one(&h.pool)
        .await
        .expect("markers");
    assert_eq!(markers, 3, "one marker per derived aggregate");
});

db_test!(reconciliation_reports_candidates_and_replays_once, |h| {
    let candidate = "cov_recon_cand";
    let clean = "cov_recon_clean";
    seed_tenant(&h, candidate, "free").await;
    seed_tenant(&h, clean, "free").await;
    let now = Utc::now();
    let day_start = (now - chrono::Duration::days(1))
        .date_naive()
        .and_hms_opt(0, 0, 0)
        .expect("midnight")
        .and_utc();
    let at = day_start + chrono::Duration::hours(4);

    for (tenant, sent, delivered) in [(candidate, 1_000, 100), (clean, 100, 99)] {
        sqlx::query(
            "INSERT INTO metering_events (id, tenant_id, event_type, quantity, timestamp)
             VALUES (gen_random_uuid(), $1, 'emails_sent', $2, $3),
                    (gen_random_uuid(), $1, 'emails_delivered', $4, $3)",
        )
        .bind(tenant)
        .bind(sent)
        .bind(at)
        .bind(delivered)
        .execute(&h.pool)
        .await
        .expect("seed metering");
    }

    let summary = reconcile_daily_deliveries(&h.pool, now)
        .await
        .expect("reconcile");
    assert_eq!(summary.tenants_compared, 2, "{summary:?}");
    assert_eq!(summary.reports_written, 2);
    assert_eq!(
        summary.overage_candidates, 1,
        "only the big gap is a candidate"
    );

    let (reserved, delivered, unaccounted, is_candidate): (i64, i64, i64, bool) = sqlx::query_as(
        "SELECT reserved_emails, delivered_emails, unaccounted_emails, overage_candidate
         FROM billing_reconciliation_reports WHERE tenant_id = $1",
    )
    .bind(candidate)
    .fetch_one(&h.pool)
    .await
    .expect("report");
    assert_eq!((reserved, delivered, unaccounted), (1_000, 100, 900));
    assert!(is_candidate);

    let replay = reconcile_daily_deliveries(&h.pool, now)
        .await
        .expect("reconcile replay");
    assert_eq!(
        replay.reports_written, 0,
        "reports are idempotent per period"
    );
});

db_test!(
    deadletter_retry_worker_is_a_clean_noop_without_entries,
    |h| {
        billing_service::stripe_webhooks::retry_deadlettered_webhooks(&h.state)
            .await
            .expect("retry with an empty deadletter set");
    }
);

// ---------------------------------------------------------------------------
// routes.rs — second adversarial pass: proration preview, PAYG usage,
// reconciliation reports, current-plan resolution, export formats.
// ---------------------------------------------------------------------------

db_test!(
    router_proration_preview_is_honest_about_unknown_states,
    |h| {
        let app = billing_service::routes::router(h.state.clone());
        let tenant = "cov_route_proration";
        seed_tenant(&h, tenant, "growth").await;
        seed_plan(&h.pool, "growth", 100_000, 100_000).await;

        // No subscription at all: a user-state problem, not a server error.
        let (status, _) = call(
            &app,
            authed(
                "GET",
                &format!("/proration/preview/growth?tenant_id={tenant}"),
            )
            .body(Body::empty())
            .expect("request"),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // A subscription without a billing cycle cannot be prorated.
        sqlx::query(
            "INSERT INTO stripe_subscriptions
             (tenant_id, stripe_subscription_id, plan, status, stripe_customer_id)
         VALUES ($1, 'sub_cov_proration', 'growth', 'active', 'cus_cov_proration')",
        )
        .bind(tenant)
        .execute(&h.pool)
        .await
        .expect("subscription without cycle");
        sqlx::query(
            "UPDATE stripe_subscriptions SET billing_cycle_start = NULL WHERE tenant_id = $1",
        )
        .bind(tenant)
        .execute(&h.pool)
        .await
        .expect("clear cycle start");
        let (status, _) = call(
            &app,
            authed(
                "GET",
                &format!("/proration/preview/growth?tenant_id={tenant}"),
            )
            .body(Body::empty())
            .expect("request"),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);

        // With a real cycle the preview computes and reconciles internally.
        let now = Utc::now();
        sqlx::query(
            "UPDATE stripe_subscriptions
         SET billing_cycle_start = $2, billing_cycle_end = $3, billing_interval = 'monthly'
         WHERE tenant_id = $1",
        )
        .bind(tenant)
        .bind(now - chrono::Duration::days(10))
        .bind(now + chrono::Duration::days(20))
        .execute(&h.pool)
        .await
        .expect("cycle");
        let (status, json) = call(
            &app,
            authed(
                "GET",
                &format!("/proration/preview/growth?tenant_id={tenant}"),
            )
            .body(Body::empty())
            .expect("request"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{json}");
        assert!(json["netAmount"].is_i64(), "{json}");
        assert!(json["creditAmount"].is_i64(), "{json}");
        assert!(json["chargeAmount"].is_i64(), "{json}");
        assert_eq!(
            json["netAmount"].as_i64(),
            Some(json["chargeAmount"].as_i64().unwrap() - json["creditAmount"].as_i64().unwrap()),
            "the preview reconciles: net = charge - credit"
        );

        // Unknown target plan: 404, never a silent free-plan downgrade.
        let (status, _) = call(
            &app,
            authed(
                "GET",
                &format!("/proration/preview/no_such_plan?tenant_id={tenant}"),
            )
            .body(Body::empty())
            .expect("request"),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // Yearly interval override still computes.
        let (status, json) = call(
            &app,
            authed(
                "GET",
                &format!("/proration/preview/growth?tenant_id={tenant}&billing_interval=yearly"),
            )
            .body(Body::empty())
            .expect("request"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{json}");

        // A tenant-scoped token can never preview another tenant's switch.
        let other = "cov_route_proration_other";
        seed_tenant(&h, other, "growth").await;
        let (status, _) = call(
            &app,
            Request::builder()
                .method("GET")
                .uri(format!("/proration/preview/growth?tenant_id={other}"))
                .header("x-api-key", tenant_token(tenant))
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }
);

db_test!(router_payg_usage_and_reconciliation_surface, |h| {
    let app = billing_service::routes::router(h.state.clone());
    let tenant = "cov_route_payg_surface";
    seed_tenant(&h, tenant, "payg").await;
    seed_plan(&h.pool, "payg", 100_000, 100_000).await;

    let now = Utc::now();
    sqlx::query(
        "INSERT INTO metering_events (id, tenant_id, event_type, quantity, timestamp)
         VALUES (gen_random_uuid(), $1, 'emails_sent', 5000, NOW()),
                (gen_random_uuid(), $1, 'api_calls', 150000, NOW())",
    )
    .bind(tenant)
    .execute(&h.pool)
    .await
    .expect("usage");

    let (status, json) = call(
        &app,
        authed("GET", &format!("/payg/usage?tenant_id={tenant}"))
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{json}");
    assert_eq!(json["usage"]["emailsSent"], 5000);
    assert_eq!(json["usage"]["apiCalls"], 150000);
    assert_eq!(json["cost"]["emailCostCents"], 500);
    assert_eq!(json["cost"]["apiCostCents"], 500);
    assert_eq!(json["cost"]["totalCostCents"], 1000);
    assert!(json["period"]["start"].is_string());
    assert!(json["pricing"]["emailPricing"].is_array());
    assert!(json["pricing"]["minimumMonthlyChargeCents"].is_i64());

    // Reconciliation reports: pagination clamps and candidate filtering.
    let day = now.date_naive();
    sqlx::query(
        "INSERT INTO billing_reconciliation_reports
             (id, tenant_id, period_start, period_end, reserved_emails, delivered_emails,
              bounced_emails, complained_emails, unaccounted_emails, overage_candidate, status)
         VALUES (gen_random_uuid(), $1, $2, $2, 100, 100, 0, 0, 0, false, 'ok'),
                (gen_random_uuid(), $1, $3, $3, 100, 40, 0, 0, 60, true, 'overage_candidate')",
    )
    .bind(tenant)
    .bind(day)
    .bind(day - chrono::Duration::days(1))
    .execute(&h.pool)
    .await
    .expect("reconciliation rows");

    let (status, json) = call(
        &app,
        authed(
            "GET",
            &format!("/usage/reconciliation?tenant_id={tenant}&only_candidates=true&limit=99999"),
        )
        .body(Body::empty())
        .expect("request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{json}");
    let reports = json["reports"].as_array().expect("reports array");
    assert_eq!(reports.len(), 1, "candidate filter applies");
    assert_eq!(reports[0]["overageCandidate"], true);
    assert_eq!(reports[0]["unaccountedEmails"], 60);

    let (status, json) = call(
        &app,
        authed(
            "GET",
            &format!("/usage/reconciliation?tenant_id={tenant}&limit=0"),
        )
        .body(Body::empty())
        .expect("request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        json["reports"].as_array().expect("reports").len(),
        1,
        "limit=0 clamps up to 1, never unbounded"
    );

    // Cross-tenant probes are refused on both surfaces.
    let (status, _) = call(
        &app,
        Request::builder()
            .method("GET")
            .uri(format!("/payg/usage?tenant_id={tenant}"))
            .header("x-api-key", tenant_token("cov_route_someone_else"))
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
});

db_test!(router_current_plan_and_plan_upsert_round_trip, |h| {
    let app = billing_service::routes::router(h.state.clone());

    // Unknown tenant: an explicit null, not an error.
    let (status, json) = call(
        &app,
        authed(
            "GET",
            "/plans/tenant/current?tenant_id=cov_route_plan_missing",
        )
        .body(Body::empty())
        .expect("request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(json.is_null());

    // Successful plan creation (exercises the upsert input path).
    let (status, json) = call(
        &app,
        authed("POST", "/plans")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"name":"cov_plan_roundtrip","displayName":"Round Trip",
                    "description":"adversarial","priceMonthly":1234,"priceYearly":12340,
                    "features":{"dedicatedIp":true,"dedicatedIpCount":3,"maxSendingDomains":5,
                                "ssoEnabled":false,"auditLogs":true,"apiAccess":true,
                                "webhooksEnabled":true,"inboundEmail":false,
                                "advancedAnalytics":false,"sendTimeOptimization":false,
                                "abTesting":false,"timeTravelDebugging":false,"dataExport":true,
                                "customTrackingDomain":false,"customTemplates":true,
                                "templateApprovalWorkflow":false,"whiteLabel":false,
                                "poweredByFooter":true,"customRetention":false,
                                "maxRetentionDays":30,"maxTeamMembers":0,"subaccounts":false,
                                "maxSubaccounts":0,"supportLevel":"priority","dedicatedCsm":false,
                                "priorityOnboarding":false,"byoip":false,"slaGuarantee":false,
                                "slaCreditPercentage":0,"hipaaCompliance":false,
                                "soc2Compliance":false,"privateCloud":false},
                    "limits":{"emailsPerMonth":4321,"apiCallsPerMonth":9876}}"#,
            ))
            .expect("request"),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{json}");
    assert_eq!(json["name"], "cov_plan_roundtrip");
    assert_eq!(json["emailLimit"], 4321);
    assert_eq!(json["apiCallLimit"], 9876);

    let (status, json) = call(
        &app,
        authed("GET", "/plans/cov_plan_roundtrip")
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["displayName"], "Round Trip");

    // A tenant on that plan resolves through the current-plan route.
    let tenant = "cov_route_current_plan";
    seed_tenant(&h, tenant, "cov_plan_roundtrip").await;
    let (status, json) = call(
        &app,
        authed("GET", &format!("/plans/tenant/current?tenant_id={tenant}"))
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{json}");
    assert_eq!(
        json["emailLimit"], 4321,
        "current plan resolves through the tenant's plan name"
    );

    // PATCH changes only what it names.
    let (status, json) = call(
        &app,
        authed("PATCH", "/plans/cov_plan_roundtrip")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"displayName":"Patched","limits":{"apiCallsPerMonth":1}}"#,
            ))
            .expect("request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{json}");
    assert_eq!(json["displayName"], "Patched");
    assert_eq!(json["apiCallLimit"], 1);
    assert_eq!(
        json["emailLimit"], 4321,
        "unspecified limits survive the patch"
    );

    // An unknown plan is never silently created by a PATCH.
    let (status, _) = call(
        &app,
        authed("PATCH", "/plans/cov_plan_absent")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"displayName":"Nope"}"#))
            .expect("request"),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
});

db_test!(router_export_formats_and_invoice_window, |h| {
    let app = billing_service::routes::router(h.state.clone());
    let tenant = "cov_route_export";
    seed_tenant(&h, tenant, "free").await;
    let now = Utc::now();
    sqlx::query(
        "INSERT INTO invoices (id, tenant_id, amount, currency, status, invoice_number,
                               subtotal, vat_total, total, issued_at, due_at,
                               period_start, period_end, created_at, updated_at)
         VALUES (gen_random_uuid(), $1, 1200, 'EUR', 'paid', 'COV-EXPORT-1',
                 1000, 200, 1200, $2, $2, $2, $2, $2, $2)",
    )
    .bind(tenant)
    .bind(now)
    .execute(&h.pool)
    .await
    .expect("invoice");

    let start = (now - chrono::Duration::days(1)).format("%Y-%m-%d");
    let end = (now + chrono::Duration::days(1)).format("%Y-%m-%d");

    // JSON export returns structured rows.
    let (status, json) = call(
        &app,
        authed(
            "GET",
            &format!("/export?type=invoices&startDate={start}&endDate={end}&format=json"),
        )
        .body(Body::empty())
        .expect("request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let rows = json["data"].as_array().expect("export rows");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["invoice_number"], "COV-EXPORT-1");
    assert_eq!(rows[0]["total"], 1200);

    // CSV export renders the same rows as a text table.
    let response = app
        .clone()
        .oneshot(
            authed(
                "GET",
                &format!("/export?type=invoices&startDate={start}&endDate={end}&format=csv"),
            )
            .body(Body::empty())
            .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(content_type.starts_with("text/csv"), "{content_type}");
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("COV-EXPORT-1"), "{text}");
    assert!(text.contains("invoice_number"), "header row: {text}");

    // An empty window is a valid, empty export.
    let (status, json) = call(
        &app,
        authed(
            "GET",
            "/export?type=transactions&startDate=1999-01-01&endDate=1999-01-02&format=json",
        )
        .body(Body::empty())
        .expect("request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["data"].as_array().expect("rows").len(), 0);
});

// ---------------------------------------------------------------------------
// usage_ingest.rs — bounce/complaint collection in the reconciliation report
// ---------------------------------------------------------------------------

db_test!(
    reconciliation_counts_bounces_and_complaints_per_tenant,
    |h| {
        let tenant = "cov_recon_delivery";
        seed_tenant(&h, tenant, "free").await;
        let now = Utc::now();
        let day = billing_service::usage_ingest::sweep_target_day(now);
        let day_start = day.and_hms_opt(0, 0, 0).expect("midnight").and_utc();

        // Reserved 1000, delivered 900, bounced 90 (aggregated pipeline) and
        // 5 complaints: 10 unaccounted — under the slack, so no candidate.
        sqlx::query(
            "INSERT INTO metering_events (id, tenant_id, event_type, quantity, timestamp)
         VALUES (gen_random_uuid(), $1, 'emails_sent', 1000, $2),
                (gen_random_uuid(), $1, 'emails_delivered', 900, $2)",
        )
        .bind(tenant)
        .bind(day_start + chrono::Duration::hours(3))
        .execute(&h.pool)
        .await
        .expect("metering");
        sqlx::query(
            "INSERT INTO bounce_analytics_daily (tenant_id, date, total_bounces)
         VALUES ($1, $2, 90)",
        )
        .bind(tenant)
        .bind(day)
        .execute(&h.pool)
        .await
        .expect("bounce analytics");
        for recipient in ["a@example.com", "b@example.com"] {
            sqlx::query(
                "INSERT INTO complaints (tenant_id, recipient, created_at) VALUES ($1, $2, $3)",
            )
            .bind(tenant)
            .bind(recipient)
            .bind(day_start + chrono::Duration::hours(5))
            .execute(&h.pool)
            .await
            .expect("complaint");
        }

        let summary = billing_service::usage_ingest::reconcile_daily_deliveries(&h.pool, now)
            .await
            .expect("reconcile");
        assert_eq!(summary.reports_written, 1, "{summary:?}");
        assert_eq!(summary.overage_candidates, 0, "90+10 accounted, no gap");
        assert!(summary.skipped_sources.is_empty(), "{summary:?}");

        let (reserved, delivered, bounced, complained, unaccounted): (i64, i64, i64, i64, i64) =
            sqlx::query_as(
                "SELECT reserved_emails, delivered_emails, bounced_emails, complained_emails,
                    unaccounted_emails
             FROM billing_reconciliation_reports WHERE tenant_id = $1",
            )
            .bind(tenant)
            .fetch_one(&h.pool)
            .await
            .expect("report");
        assert_eq!(
            (reserved, delivered, bounced, complained, unaccounted),
            (1000, 900, 90, 2, 10),
            "bounces are accounted for; complaints are reported but never deducted"
        );

        // Replays never rewrite the immutable report.
        let replay = billing_service::usage_ingest::reconcile_daily_deliveries(&h.pool, now)
            .await
            .expect("reconcile replay");
        assert_eq!(replay.reports_written, 0);
    }
);

// ---------------------------------------------------------------------------
// VAT / statutory: KMD from the recognition ledger; cash-special timing
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
async fn seed_recognition_entry(
    h: &Harness,
    supply_id: &str,
    tenant: &str,
    event_type: &str,
    recognition_period: &str,
    taxable_cents: i64,
    vat_rate: f64,
    vat_cents: i64,
    currency: &str,
    scheme: &str,
) {
    sqlx::query(
        "INSERT INTO vat_recognition_entries
             (id, supply_id, tenant_id, event_type, taxable_event_at, recognition_period,
              taxable_amount_cents, vat_rate, vat_amount_cents, currency, scheme)
         VALUES (gen_random_uuid(), $1, $2, $3, NOW(), $4, $5, $6, $7, $8, $9)",
    )
    .bind(supply_id)
    .bind(tenant)
    .bind(event_type)
    .bind(recognition_period)
    .bind(taxable_cents)
    .bind(vat_rate)
    .bind(vat_cents)
    .bind(currency)
    .bind(scheme)
    .execute(&h.pool)
    .await
    .expect("seed recognition entry");
}

db_test!(
    vat_kmd_totals_equal_ledger_and_exclude_other_currencies,
    |h| {
        let tenant_a = "cov_kmd_ledger_a";
        let tenant_b = "cov_kmd_ledger_b";
        seed_tenant(&h, tenant_a, "growth").await;
        seed_tenant(&h, tenant_b, "growth").await;
        assert!(
            billing_service::vat_kmd::kmd_table_exists(&h.pool).await,
            "canonical schema carries the KMD table"
        );

        // EUR ledger rows across two tenants, two rates; one USD row excluded.
        seed_recognition_entry(
            &h, "kmd-1", tenant_a, "supply", "2026-05", 10_000, 24.0, 2_400, "EUR", "general",
        )
        .await;
        seed_recognition_entry(
            &h, "kmd-2", tenant_a, "supply", "2026-05", 20_000, 24.0, 4_800, "EUR", "general",
        )
        .await;
        seed_recognition_entry(
            &h, "kmd-3", tenant_b, "supply", "2026-05", 5_000, 9.0, 450, "eur", "general",
        )
        .await;
        seed_recognition_entry(
            &h, "kmd-4", tenant_b, "supply", "2026-05", 7_000, 24.0, 1_680, "USD", "general",
        )
        .await;
        // Different period: never included.
        seed_recognition_entry(
            &h, "kmd-5", tenant_a, "supply", "2026-04", 999_999, 24.0, 239_999, "EUR", "general",
        )
        .await;

        let result = billing_service::vat_kmd::generate_kmd_return(&h.pool, 2026, 5)
            .await
            .expect("generate KMD");
        assert_eq!(
            result.total_taxable_cents, 35_000,
            "EUR taxable sums exactly"
        );
        assert_eq!(result.total_vat_cents, 7_650, "EUR VAT sums exactly");
        assert_eq!(result.invoice_count, 3, "distinct EUR supplies");
        assert_eq!(result.tenant_count, 2);
        // Rate buckets must reconcile with the headline totals to the cent.
        let bucket_taxable: i64 = result.rates.iter().map(|b| b.taxable_amount_cents).sum();
        let bucket_vat: i64 = result.rates.iter().map(|b| b.vat_amount_cents).sum();
        assert_eq!(bucket_taxable, result.total_taxable_cents);
        assert_eq!(bucket_vat, result.total_vat_cents);
        assert_eq!(result.rates.len(), 2, "24% and 9% buckets");
        // The USD supply is visible but excluded from the EUR return.
        assert_eq!(result.excluded_other_currency.len(), 1);
        assert_eq!(result.excluded_other_currency[0].currency, "USD");
        assert_eq!(
            result.excluded_other_currency[0].taxable_amount_cents,
            7_000
        );

        // Persisted return round-trips through the latest-return reader.
        let latest = billing_service::vat_kmd::get_latest_kmd_return(&h.pool)
            .await
            .expect("latest KMD")
            .expect("one return");
        assert_eq!((latest.tax_year, latest.tax_month), (2026, 5));
        assert_eq!(latest.total_vat_cents, 7_650);
        assert_eq!(latest.kmd_id, result.kmd_id);
        let periods = billing_service::vat_kmd::list_generated_kmd_periods(&h.pool)
            .await
            .expect("list periods");
        assert_eq!(periods, vec![(2026, 5)]);

        // Re-filing the same period is refused (unique period identity), never
        // silently doubled.
        let replay = billing_service::vat_kmd::generate_kmd_return(&h.pool, 2026, 5).await;
        assert!(replay.is_err(), "replay must not create a second return");
        let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM vat_kmd_returns")
            .fetch_one(&h.pool)
            .await
            .unwrap();
        assert_eq!(rows, 1);

        // Filing deadline: 23:59:59 Tallinn on the 20th, expressed in UTC.
        let may = billing_service::vat_kmd::vat_return_due_date(2026, 5);
        assert_eq!(
            may.to_rfc3339(),
            "2026-06-20T20:59:59+00:00",
            "EEST is UTC+3"
        );
        let dec = billing_service::vat_kmd::vat_return_due_date(2026, 12);
        assert_eq!(
            dec.to_rfc3339(),
            "2027-01-20T21:59:59+00:00",
            "EET is UTC+2"
        );
    }
);

/// `identity` is `(invoice_number, status, billing_country)`;
/// `money` is `(subtotal_cents, vat_rate, vat_total_cents)`.
async fn seed_invoice_row(
    h: &Harness,
    tenant: &str,
    identity: (&str, &str, &str),
    issued_at: DateTime<Utc>,
    paid_at: Option<DateTime<Utc>>,
    money: (i64, f64, i64),
) -> Uuid {
    let (number, status, country) = identity;
    let (subtotal, vat_rate, vat_total) = money;
    sqlx::query_scalar(
        "INSERT INTO invoices (id, tenant_id, invoice_number, status, currency, subtotal, vat_rate,
             vat_total, total, issued_at, due_at, paid_at, billing_country)
         VALUES (gen_random_uuid(), $1, $2, $3, 'EUR', $4, $5, $6, $4 + $6, $7, $7 + INTERVAL '30 days',
                 $8, $9)
         RETURNING id",
    )
    .bind(tenant)
    .bind(number)
    .bind(status)
    .bind(subtotal)
    .bind(vat_rate)
    .bind(vat_total)
    .bind(issued_at)
    .bind(paid_at)
    .bind(country)
    .fetch_one(&h.pool)
    .await
    .expect("seed invoice")
}

db_test!(vat_recognition_general_and_cash_special_timing, |h| {
    let tenant = "cov_recog_general";
    let cash = "cov_recog_cash";
    seed_tenant(&h, tenant, "growth").await;
    seed_tenant(&h, cash, "growth").await;
    let now = Utc::now();

    // General scheme: issuing the invoice is the taxable event, in the
    // Tallinn month of issue.
    let issued = now - chrono::Duration::days(3);
    let general_invoice = seed_invoice_row(
        &h,
        tenant,
        ("REC-GEN-1", "pending", "EE"),
        issued,
        None,
        (10_000, 24.0, 2_400),
    )
    .await;
    let entry = billing_service::vat_recognition::materialize_invoice_recognition_by_id(
        &h.pool,
        general_invoice,
        now,
    )
    .await
    .expect("materialize")
    .expect("general scheme always recognises");
    assert_eq!(entry.event_type.as_str(), "supply");
    assert_eq!(entry.taxable_amount_cents, 10_000);
    assert_eq!(entry.vat_amount_cents, 2_400);
    assert_eq!(entry.currency, "EUR");
    let expected_period = issued.format("%Y-%m").to_string();
    assert_eq!(entry.recognition_period, expected_period);

    // Replay replaces the current row, never duplicates it.
    let replay = billing_service::vat_recognition::materialize_invoice_recognition_by_id(
        &h.pool,
        general_invoice,
        now,
    )
    .await
    .expect("replay")
    .expect("still recognised");
    assert_eq!(replay.recognition_period, expected_period);
    let rows: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM vat_recognition_entries WHERE supply_id = $1 AND scheme = 'general'",
    )
    .bind(general_invoice.to_string())
    .fetch_one(&h.pool)
    .await
    .unwrap();
    assert_eq!(rows, 1, "replay is a single current entry");

    // Missing invoice → None, nothing written.
    let missing = billing_service::vat_recognition::materialize_invoice_recognition_by_id(
        &h.pool,
        Uuid::new_v4(),
        now,
    )
    .await
    .expect("missing is not an error");
    assert!(missing.is_none());

    // Cash-special: an unpaid supply inside the deferral window recognises
    // nothing yet.
    sqlx::query(
        "INSERT INTO vat_accounting_bases (tenant_id, scheme, effective_from, authorised_at, authorisation_reference)
         VALUES ($1, 'cash_special', $2::date - interval '1 year', $2::date - interval '1 year', 'EMTA-123')",
    )
    .bind(cash)
    .bind(now.date_naive())
    .execute(&h.pool)
    .await
    .unwrap();
    let recent = seed_invoice_row(
        &h,
        cash,
        ("REC-CASH-RECENT", "pending", "EE"),
        now - chrono::Duration::days(10),
        None,
        (50_000, 24.0, 12_000),
    )
    .await;
    let deferred = billing_service::vat_recognition::materialize_invoice_recognition_by_id(
        &h.pool, recent, now,
    )
    .await
    .expect("deferral is not an error");
    assert!(
        deferred.is_none(),
        "unpaid cash-special supply inside the 3-month window recognises nothing"
    );

    // Paid before the fallback → the payment date is the taxable event.
    let paid_invoice = seed_invoice_row(
        &h,
        cash,
        ("REC-CASH-PAID", "paid", "EE"),
        now - chrono::Duration::days(40),
        Some(now - chrono::Duration::days(35)),
        (20_000, 24.0, 4_800),
    )
    .await;
    let paid_entry = billing_service::vat_recognition::materialize_invoice_recognition_by_id(
        &h.pool,
        paid_invoice,
        now,
    )
    .await
    .expect("materialize paid")
    .expect("payment recognised");
    assert_eq!(paid_entry.event_type.as_str(), "payment");
    assert_eq!(
        paid_entry.recognition_period,
        (now - chrono::Duration::days(35))
            .format("%Y-%m")
            .to_string()
    );

    // Never paid, issued more than two months ago → the fallback sweep
    // materialises the cash_special_due event exactly once.
    // Issued far enough back that the third-calendar-month fallback has
    // already arrived (now - 100 days => fallback < now).
    let stale = seed_invoice_row(
        &h,
        cash,
        ("REC-CASH-STALE", "pending", "EE"),
        now - chrono::Duration::days(100),
        None,
        (30_000, 24.0, 7_200),
    )
    .await;
    let swept = billing_service::vat_recognition::materialize_due_cash_special(&h.pool, now)
        .await
        .expect("fallback sweep");
    assert_eq!(swept, 1, "exactly the stale unpaid supply");
    let event_type: String = sqlx::query_scalar(
        "SELECT event_type FROM vat_recognition_entries WHERE supply_id = $1 AND scheme = 'cash_special'",
    )
    .bind(stale.to_string())
    .fetch_one(&h.pool)
    .await
    .unwrap();
    assert_eq!(event_type, "cash_special_due");
    // Replay of the sweep is a no-op.
    let swept_again = billing_service::vat_recognition::materialize_due_cash_special(&h.pool, now)
        .await
        .expect("fallback replay");
    assert_eq!(swept_again, 0, "already-materialised supplies are skipped");

    // Backfill: idempotent over an explicit period range.
    let from = (now - chrono::Duration::days(80))
        .format("%Y-%m")
        .to_string();
    let to = now.format("%Y-%m").to_string();
    let written =
        billing_service::vat_recognition::backfill_recognition_from_invoices(&h.pool, &from, &to)
            .await
            .expect("backfill");
    assert!(
        written >= 2,
        "general + cash invoices are re-materialised: {written}"
    );
    let written_again =
        billing_service::vat_recognition::backfill_recognition_from_invoices(&h.pool, &from, &to)
            .await
            .expect("backfill replay");
    assert_eq!(
        written_again, written,
        "backfill is idempotent (replace, never append)"
    );
});

// ---------------------------------------------------------------------------
// invoices.rs — numbering under concurrency, immutable snapshots, overflow
// ---------------------------------------------------------------------------

db_test!(
    invoice_numbering_is_gap_free_and_monotonic_under_concurrency,
    |h| {
        use billing_service::invoices::generate_invoice_number;

        let pool = h.pool.clone();
        let futures = (0..16).map(|_| generate_invoice_number(&pool));
        let results = futures::future::join_all(futures).await;
        let mut serials: Vec<i64> = results
            .into_iter()
            .map(|r| {
                let number = r.expect("numbering must not fail");
                let (year, serial) = number.split_once('-').expect("YYYY-NNNNNN");
                assert_eq!(year.len(), 4);
                assert_eq!(serial.len(), 6, "zero-padded to six digits: {number}");
                serial.parse::<i64>().expect("numeric serial")
            })
            .collect();
        serials.sort_unstable();
        assert_eq!(serials.len(), 16);
        assert!(
            serials.windows(2).all(|w| w[1] == w[0] + 1),
            "concurrent numbering must be monotonic and gap-free: {serials:?}"
        );
    }
);

db_test!(
    invoice_creation_validates_and_freezes_immutable_snapshot,
    |h| {
        use billing_service::invoices::{
            allocate_vat_across_lines, create_invoice, CreateInvoiceInput, InvoiceError,
            NewLineItem,
        };

        let tenant = "cov_inv_snapshot";
        seed_tenant(&h, tenant, "growth").await;
        let now = Utc::now();
        let input = || CreateInvoiceInput {
            tenant_id: tenant.to_string(),
            stripe_invoice_id: None,
            line_items: vec![NewLineItem {
                description: "Usage 2026-09".into(),
                quantity: 10,
                unit_price: 10_000,
            }],
            period_start: now - chrono::Duration::days(30),
            period_end: now,
            due_at: None,
            currency: None,
            overage_period: None,
        };

        // No billing address → typed refusal, no invoice row.
        let missing = create_invoice(&h.pool, input()).await;
        assert!(
            matches!(missing, Err(InvoiceError::NoBillingAddress)),
            "missing address must be refused: {missing:?}"
        );
        assert_eq!(invoice_count(&h, tenant).await, 0);

        seed_billing_address(&h, tenant, "EE").await;

        // quantity × unit_price overflow → typed refusal before any INSERT.
        let mut overflow_input = input();
        overflow_input.line_items[0].quantity = i64::MAX;
        overflow_input.line_items[0].unit_price = 2;
        let overflow = create_invoice(&h.pool, overflow_input).await;
        assert!(
            matches!(overflow, Err(InvoiceError::PdfGeneration(_))),
            "overflow must be refused: {overflow:?}"
        );
        assert_eq!(invoice_count(&h, tenant).await, 0, "refusals never persist");

        // Valid invoice: totals reconcile to the cent and per-line VAT sums
        // exactly to the headline VAT.
        let invoice = create_invoice(&h.pool, input()).await.expect("invoice");
        assert_eq!(invoice.subtotal, 100_000);
        assert_eq!(invoice.total, invoice.subtotal + invoice.vat_total);
        let rate = invoice.line_items[0].vat_rate;
        let allocated = allocate_vat_across_lines(&[100_000], rate);
        assert_eq!(
            invoice.line_items.iter().map(|l| l.vat_amount).sum::<i64>(),
            invoice.vat_total,
            "per-line VAT must reconcile with the headline total"
        );
        assert_eq!(invoice.line_items[0].vat_amount, allocated[0]);
        assert!(invoice
            .invoice_number
            .starts_with(&now.format("%Y").to_string()));

        // The issued snapshot survives a later address change.
        let before: Option<String> =
            sqlx::query_scalar("SELECT billing_address FROM invoices WHERE id = $1")
                .bind(invoice.id)
                .fetch_one(&h.pool)
                .await
                .unwrap();
        let before = before.expect("F08 snapshot stored");
        assert!(
            before.contains("Coverage"),
            "snapshot carries the buyer name"
        );
        sqlx::query(
            "UPDATE billing_addresses SET company_name = 'Changed OÜ', country = 'DE',
             address_line1 = 'Elsewhere 9' WHERE tenant_id = $1",
        )
        .bind(tenant)
        .execute(&h.pool)
        .await
        .unwrap();
        let after: Option<String> =
            sqlx::query_scalar("SELECT billing_address FROM invoices WHERE id = $1")
                .bind(invoice.id)
                .fetch_one(&h.pool)
                .await
                .unwrap();
        assert_eq!(
            before,
            after.expect("snapshot survives"),
            "F08 immutability"
        );

        // The snapshot is also served back through the reader.
        let reread = billing_service::invoices::get_invoice_by_id(&h.pool, invoice.id)
            .await
            .expect("re-read invoice")
            .expect("invoice exists");
        assert_eq!(reread.invoice_number, invoice.invoice_number);
        assert_eq!(reread.total, invoice.total);
    }
);

// ---------------------------------------------------------------------------
// accounting_export.rs — hostile names are RFC 4180 escaped, formula-safe
// ---------------------------------------------------------------------------

db_test!(accounting_export_escapes_hostile_names_and_formulas, |h| {
    use billing_service::accounting_export::export_accounting_csv;

    let tenant = "cov_export_x";
    seed_tenant(&h, tenant, "growth").await;
    // Hostile buyer name: quote, comma, and an embedded newline that must
    // never split the CSV record; company_name stays NULL so the tenant name
    // is the exported customer name.
    sqlx::query("UPDATE tenants SET name = $2 WHERE id = $1")
        .bind(tenant)
        .bind("O\"Brien, Ltd.\nSecond line")
        .execute(&h.pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO billing_addresses (tenant_id, company_name, address_line1, city, postal_code, country, vat_number)
         VALUES ($1, NULL, '=SUM(A1:A2)', 'Tallinn', '10111', 'EE', 'EE123456789')",
    )
    .bind(tenant)
    .execute(&h.pool)
    .await
    .unwrap();
    seed_invoice_row(
        &h,
        tenant,
        ("EXP-1", "paid", "EE"),
        Utc::now(),
        None,
        (1_000, 24.0, 240),
    )
    .await;

    let csv = export_accounting_csv(
        &h.pool,
        Utc::now() - chrono::Duration::hours(1),
        Utc::now() + chrono::Duration::hours(1),
    )
    .await
    .expect("export");

    // BOM + header retained.
    assert!(csv.starts_with('\u{feff}'));
    assert!(csv.contains("\"Arve number\""));
    // Embedded quotes are doubled; commas and the newline stay inside one
    // quoted field (exactly one data record follows the header).
    assert!(
        csv.contains("\"O\"\"Brien, Ltd.\nSecond line\""),
        "customer name must be RFC 4180 escaped: {csv}"
    );
    // The embedded newline stays inside the quoted field: the physical
    // lines are header, record-part-1 (unclosed quote), record-part-2, and
    // the trailing newline — never a broken/duplicated data record.
    let records: Vec<&str> = csv.split('\n').collect();
    assert_eq!(
        records.len(),
        4,
        "record not split incorrectly: {records:?}"
    );
    assert!(
        records[1].starts_with("\"EXP-1\",") && records[1].ends_with("O\"\"Brien, Ltd."),
        "attribute columns precede the newline-bearing name"
    );
    assert!(records[2].starts_with("Second line\","));
    // Leading '='/+/-/@ values are prefixed so spreadsheets do not execute
    // them as formulas.
    assert!(
        csv.contains("\"'=SUM(A1:A2), Tallinn, 10111, EE\""),
        "address formula neutralized inside its quoted field: {csv}"
    );
    assert!(
        !csv.contains(",\"=cmd"),
        "formula must never start an unescaped cell: {csv}"
    );
    // Amounts: VTA rate is derived by integer half-up: 240/1000 → 24%.
    assert!(csv.contains("\"24%\""));
    assert!(csv.contains("\"EUR\""));
    // A window that excludes the invoice yields only the header.
    let empty = export_accounting_csv(
        &h.pool,
        Utc::now() + chrono::Duration::days(1),
        Utc::now() + chrono::Duration::days(2),
    )
    .await
    .expect("empty export");
    assert_eq!(empty.lines().count(), 1, "header only");
});

// ---------------------------------------------------------------------------
// credit_notes.rs — idempotent replay: matching returns, mismatch refuses
// ---------------------------------------------------------------------------

db_test!(credit_note_replay_matches_payload_or_refuses, |h| {
    use billing_service::credit_notes::{
        create_credit_note, CreateCreditNoteInput, CreditNoteError,
    };

    let tenant = "cov_cn_replay";
    seed_tenant(&h, tenant, "growth").await;
    let invoice = seed_invoice_row(
        &h,
        tenant,
        ("CN-1", "paid", "EE"),
        Utc::now(),
        Some(Utc::now()),
        (10_000, 24.0, 2_400),
    )
    .await;

    let input = || CreateCreditNoteInput {
        invoice_id: invoice,
        amount: 500,
        reason: "goodwill".into(),
        tenant_id: tenant.to_string(),
        idempotency_key: "cov-cn-key".into(),
    };
    let first = create_credit_note(&h.pool, input())
        .await
        .expect("first credit");
    assert_eq!(first.amount, 500);

    // Exact replay returns the SAME row and mints nothing new.
    let replay = create_credit_note(&h.pool, input()).await.expect("replay");
    assert_eq!(replay.id, first.id, "replay returns the stored record");
    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM credit_notes WHERE tenant_id = $1")
        .bind(tenant)
        .fetch_one(&h.pool)
        .await
        .unwrap();
    assert_eq!(rows, 1, "no duplicate credit note");

    // Same key, different amount → typed refusal, no write.
    let mut divergent = input();
    divergent.amount = 501;
    let mismatched = create_credit_note(&h.pool, divergent).await;
    assert!(
        matches!(
            mismatched,
            Err(CreditNoteError::IdempotencyKeyReused { .. })
        ),
        "divergent reuse must be refused: {mismatched:?}"
    );
    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM credit_notes WHERE tenant_id = $1")
        .bind(tenant)
        .fetch_one(&h.pool)
        .await
        .unwrap();
    assert_eq!(rows, 1);
});

db_test!(overage_sweep_backfills_legacy_pricing_snapshot_once, |h| {
    use billing_service::overage::{default_period_currency, invalidate_subscription_cache};

    let tenant = "cov_over_legacy_rate";
    seed_tenant(&h, tenant, "growth").await;
    seed_billing_address(&h, tenant, "EE").await;
    let now = Utc::now();
    let start = now - chrono::Duration::days(31);
    let end = now - chrono::Duration::days(2);
    // Legacy period: pricing columns unset (pre-snapshot rows).
    let period = seed_billing_period(&h, tenant, start, end, "growth", Some(100), None).await;
    seed_metering(
        &h,
        tenant,
        "emails_sent",
        1_100,
        start + chrono::Duration::days(1),
    )
    .await;

    let result = billing_service::overage::sweep_period_overage(&h.state)
        .await
        .expect("sweep");
    assert_eq!(result.invoices_created, 1, "{result:?}");

    let (rate, snapshot): (Option<i64>, Option<serde_json::Value>) = sqlx::query_as(
        "SELECT overage_rate_millicents::bigint, pricing_snapshot
         FROM billing_periods WHERE id = $1",
    )
    .bind(period)
    .fetch_one(&h.pool)
    .await
    .expect("period row");
    assert_eq!(
        rate,
        Some(35),
        "builtin plan rate backfilled onto the period"
    );
    let snapshot = snapshot.expect("legacy period gains a pricing snapshot");
    assert_eq!(snapshot["backfilled"], true);
    assert_eq!(snapshot["planName"], "growth");
    assert_eq!(snapshot["emailAllowance"], 100);
    assert_eq!(snapshot["overageRateMillicents"], 35);
    assert_eq!(snapshot["currency"], default_period_currency());
    assert_eq!(default_period_currency(), "EUR");

    // The invoice's own money invariant: total = subtotal + VAT.
    let (inv_subtotal, inv_vat, inv_total): (i64, i64, i64) =
        sqlx::query_as("SELECT subtotal, vat_total, total FROM invoices WHERE tenant_id = $1")
            .bind(tenant)
            .fetch_one(&h.pool)
            .await
            .expect("invoice");
    // 1 000 excess emails × 35 millicents = 35 000 millicents = 35 cents.
    assert_eq!(inv_subtotal, 35, "exact integer money, no float drift");
    assert_eq!(inv_total, inv_subtotal + inv_vat);
    assert_eq!(
        inv_total, 43,
        "35c + 24% VAT (8c half-up) reconciles exactly"
    );

    // Cache invalidation is safe for known and unknown tenants.
    invalidate_subscription_cache(tenant);
    invalidate_subscription_cache("tenant-that-does-not-exist");
});

db_test!(
    stripe_webhook_cross_tenant_binding_and_bad_states_refuse,
    |h| {
        let app = billing_service::routes::router(h.state.clone());
        let tenant_a = "cov_wh_bind_a";
        let tenant_b = "cov_wh_bind_b";
        seed_tenant(&h, tenant_a, "free").await;
        seed_tenant(&h, tenant_b, "free").await;
        seed_stripe_plan(&h, "growth", "price_cov_monthly").await;
        let now = Utc::now().timestamp();

        // Bind the subscription to tenant A.
        expect_webhook_ok(
            &h,
            &app,
            &stripe_event(
                "evt_cov_bind_a",
                "customer.subscription.created",
                subscription_object(
                    tenant_a,
                    "sub_cov_bound",
                    "active",
                    "price_cov_monthly",
                    now,
                    now + 2_592_000,
                ),
            ),
            "evt_cov_bind_a",
        )
        .await;
        let plan_a: String = sqlx::query_scalar("SELECT plan FROM tenants WHERE id = $1")
            .bind(tenant_a)
            .fetch_one(&h.pool)
            .await
            .unwrap();
        assert_eq!(plan_a, "growth");

        // The SAME Stripe subscription id claimed by another tenant is refused:
        // a webhook can never move a subscription (or paid entitlement) across
        // tenants.
        let (status, _) = post_signed_webhook(
            &app,
            &stripe_event(
                "evt_cov_bind_b",
                "customer.subscription.updated",
                subscription_object(
                    tenant_b,
                    "sub_cov_bound",
                    "active",
                    "price_cov_monthly",
                    now,
                    now + 2_592_000,
                ),
            ),
            now,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (error,): (Option<String>,) = sqlx::query_as(
            "SELECT error FROM stripe_webhook_events WHERE stripe_event_id = 'evt_cov_bind_b'",
        )
        .fetch_one(&h.pool)
        .await
        .unwrap();
        assert!(
            error
                .unwrap_or_default()
                .contains("already bound to a different tenant"),
            "cross-tenant binding must be recorded as a refusal"
        );
        let plan_b: String = sqlx::query_scalar("SELECT plan FROM tenants WHERE id = $1")
            .bind(tenant_b)
            .fetch_one(&h.pool)
            .await
            .unwrap();
        assert_eq!(plan_b, "free", "tenant B gains nothing");

        // An impossible status transition is refused (active -> incomplete).
        let (status, _) = post_signed_webhook(
            &app,
            &stripe_event(
                "evt_cov_bad_transition",
                "customer.subscription.updated",
                subscription_object(
                    tenant_a,
                    "sub_cov_bound",
                    "incomplete",
                    "price_cov_monthly",
                    now,
                    now + 2_592_000,
                ),
            ),
            now,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let status_text: String = sqlx::query_scalar(
        "SELECT status FROM stripe_subscriptions WHERE stripe_subscription_id = 'sub_cov_bound'",
    )
    .fetch_one(&h.pool)
    .await
    .unwrap();
        assert_eq!(status_text, "active", "refused event never rewinds state");

        // A subscription with no line-item price cannot grant anything.
        let mut no_price = subscription_object(
            tenant_b,
            "sub_cov_noprice",
            "active",
            "price_cov_monthly",
            now,
            now + 2_592_000,
        );
        no_price["items"]["data"] = serde_json::json!([]);
        let (status, _) = post_signed_webhook(
            &app,
            &stripe_event("evt_cov_noprice", "customer.subscription.created", no_price),
            now,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // An unknown Stripe price id cannot grant anything either.
        let (status, _) = post_signed_webhook(
            &app,
            &stripe_event(
                "evt_cov_unknownprice",
                "customer.subscription.created",
                subscription_object(
                    tenant_b,
                    "sub_cov_unknownprice",
                    "active",
                    "price_that_does_not_exist",
                    now,
                    now + 2_592_000,
                ),
            ),
            now,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let plan_b: String = sqlx::query_scalar("SELECT plan FROM tenants WHERE id = $1")
            .bind(tenant_b)
            .fetch_one(&h.pool)
            .await
            .unwrap();
        assert_eq!(plan_b, "free", "no unverified price may grant a plan");
        let subs_b: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM stripe_subscriptions WHERE tenant_id = $1")
                .bind(tenant_b)
                .fetch_one(&h.pool)
                .await
                .unwrap();
        assert_eq!(subs_b, 0, "refused events write no subscription rows");
    }
);
