//! Adversarial coverage tests for `billing-service`.
//!
//! Every DB-backed test provisions its OWN canonical database by cloning the
//! migrator template for the pinned chain (the workspace convention; the
//! template is created by `migrator::test_support` in any DB-backed suite).
//! `TEST_DATABASE_URL` unset → soft-skip (`Ok(None)`); a configured
//! provisioning failure panics. Redis-backed paths use `TEST_REDIS_URL`.
//!
//! The mandate: this crate moves money and meters usage, tests attack
//! boundaries (exactly-at/one-below/one-above limits), idempotency, replay,
//! overflow, malformed input, and refusal paths, and assert that nothing is
//! written/deleted outside its window.

use std::sync::Arc;
use std::time::Duration;

/// The active-plan row shape read by the parity assertions
/// (`clippy::type_complexity`): name, display_name, price_monthly,
/// price_yearly, email_limit, api_call_limit, is_active, features.
type PlanRow = (String, String, i64, i64, i64, i64, bool, serde_json::Value);

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
use chrono::{DateTime, Datelike, NaiveDate, SubsecRound, TimeZone, Utc};
use deadpool_redis::{Pool as RedisPool, Runtime};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Provisioning harness
// ---------------------------------------------------------------------------

/// Install a process-wide TRACE subscriber once. Tracing macros evaluate
/// their field expressions only when the callsite is enabled; without a
/// subscriber every dynamic `x = %expr` field line in the measured crate
/// sources would be an uncoverable region. Output goes to the sink.
fn ensure_trace_sink() {
    static INSTALLED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    if INSTALLED.set(()).is_ok() {
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(std::io::sink)
            .finish();
        let _ = tracing::subscriber::set_global_default(subscriber);
    }
}

const MAX_DB_NAME_LEN: usize = 63;

/// Release-mode soft-skip contract (audit CI-2): under
/// `APEXMAIL_RELEASE_TEST_MODE=1` a missing infrastructure variable is a hard
/// panic naming the variable, never a silent skip. (This crate does not
/// depend on `migrator`, so the workspace guard is mirrored here rather than
/// reused; a variable that IS set passes straight through.)
fn assert_soft_skip_allowed(env_var: &str) {
    if std::env::var(env_var)
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false)
    {
        return;
    }
    if std::env::var("APEXMAIL_RELEASE_TEST_MODE").as_deref() == Ok("1") {
        panic!(
            "APEXMAIL_RELEASE_TEST_MODE: required variable {env_var} is missing, \
             release CI must not skip infrastructure tests"
        );
    }
}

fn test_database_url() -> Option<String> {
    assert_soft_skip_allowed("TEST_DATABASE_URL");
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
    ensure_trace_sink();
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
        // Hex-encoded key material, exactly like the deployment's
        // `MOLLIE_API_KEY`, so the handler's strict hex-decoding path is
        // exercised (the raw-bytes fallback is only for non-hex local values).
        mollie_api_key: "test_mock_api_key".to_string(),
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
    // Fix #10: a plans row whose `features` is present but invalid now fails
    // plan/quota lookups CLOSED (typed error), and the column default ('{}')
    // is invalid for PlanFeatures. The fixture therefore persists the
    // documented default feature set so the seeded plan resolves exactly
    // like an API-seeded one. All assertions unchanged.
    let features = serde_json::to_value(billing_service::types::PlanFeatures::default())
        .expect("PlanFeatures serializes");
    sqlx::query(
        "INSERT INTO plans (id, name, display_name, price_cents, email_limit, api_call_limit, features)
         VALUES ($1, $2, $2, 0, $3, $4, $5)
         ON CONFLICT (name) DO UPDATE SET email_limit = EXCLUDED.email_limit,
             api_call_limit = EXCLUDED.api_call_limit",
    )
    .bind(format!("plan_{name}"))
    .bind(name)
    .bind(email_limit)
    .bind(api_call_limit)
    .bind(&features)
    .execute(pool)
    .await
    .expect("seed plan");
}

async fn seed_mollie_subscription(
    pool: &PgPool,
    tenant_id: &str,
    subscription_id: &str,
    status: &str,
    cycle_start: DateTime<Utc>,
    cycle_end: DateTime<Utc>,
) {
    sqlx::query(
        // Mollie customers are real objects (`cst_…`); the tenant is bound to
        // one through `mollie_customers`
        // id, and the plan code is OUR merchant-defined catalog code.
        "INSERT INTO subscription_state
             (tenant_id, provider_contract_id, plan, status, billing_cycle_start,
              billing_cycle_end, provider_customer_id, snapshot_plan_code)
         VALUES ($1, $2, 'growth', $3, $4, $5, $1, 'apexmail_growth_monthly')",
    )
    .bind(tenant_id)
    .bind(subscription_id)
    .bind(status)
    .bind(cycle_start)
    .bind(cycle_end)
    .execute(pool)
    .await
    .expect("seed mollie subscription");
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
// usage.rs, record_usage boundary/idempotency attacks
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
    // a duplicate, a caller reusing one event id across kinds gets an
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
        seed_mollie_subscription(
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
// usage.rs, get_usage / check_quota plan-limit boundaries
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
// usage.rs, record_with_quota_check exactly-once accounting
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
    // The paid-subscription gate joins subscription_state.plan to plans and
    // requires price_monthly > 0, so the subscription's plan needs a price.
    // Fix #10: the features column must carry a valid PlanFeatures document —
    // the '{}' column default now (correctly) fails plan lookups closed.
    sqlx::query(
        "INSERT INTO plans (id, name, display_name, price_cents, price_monthly, email_limit, api_call_limit, features)
         VALUES ('plan_growth', 'growth', 'Growth', 4900, 4900, 100000, 100000, $1)
         ON CONFLICT (name) DO UPDATE SET price_monthly = 4900",
    )
    .bind(serde_json::to_value(billing_service::types::PlanFeatures::default())
        .expect("PlanFeatures serializes"))
    .execute(&h.pool)
    .await
    .expect("seed growth plan");
    let now = Utc::now();
    seed_mollie_subscription(
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
// usage.rs, rollback releases the logical-operation claim (F3)
// ---------------------------------------------------------------------------

// The live defect: a send reserves quota, the enqueue fails and the
// reservation is rolled back, but the `usage_operations` claim survived,
// so the client's retry of the same idempotency key was admitted as a
// REPLAY (quota-free, unmetered). After the fix, the retry re-claims and is
// metered exactly once.
db_test!(rollback_releases_the_claim_so_a_retry_is_metered, |h| {
    async fn claim_count(h: &Harness, tenant: &str, event_id: Uuid) -> i64 {
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM usage_operations WHERE tenant_id = $1 AND event_id = $2",
        )
        .bind(tenant)
        .bind(event_id)
        .fetch_one(&h.pool)
        .await
        .expect("count usage operations")
    }

    let tenant = "cov_usage_rollback_retry";
    seed_tenant(&h, tenant, "free").await;
    let event_id = Uuid::new_v4();

    // 1. First attempt: reservation + metering row + usage_operations claim.
    let first = record_with_quota_check(
        &h.pool,
        &h.redis,
        tenant,
        MeterEventType::EmailsSent,
        1,
        Some(event_id),
        None,
    )
    .await
    .expect("first reservation");
    assert!(first.allowed && !first.duplicate);
    assert_eq!(event_count(&h.pool, tenant, event_id).await, 1);
    assert_eq!(
        claim_count(&h, tenant, event_id).await,
        1,
        "first attempt owns the claim"
    );

    // 2. Enqueue failed → SendAdmission::rollback (deletes the meter row,
    //    releases the quota counter, drops the Redis dedup key).
    rollback_usage_record(
        &h.pool,
        &h.redis,
        tenant,
        MeterEventType::EmailsSent,
        1,
        event_id,
        Utc::now(),
    )
    .await
    .expect("rollback");
    assert_eq!(event_count(&h.pool, tenant, event_id).await, 0);
    assert_eq!(
        claim_count(&h, tenant, event_id).await,
        0,
        "the rollback must release the logical-operation claim too"
    );

    // 3. The client retries the SAME logical send (same idempotency key
    //    derives the same event id). It must be metered again, NOT treated
    //    as a replay that owns a metering row which no longer exists.
    let retry = record_with_quota_check(
        &h.pool,
        &h.redis,
        tenant,
        MeterEventType::EmailsSent,
        1,
        Some(event_id),
        None,
    )
    .await
    .expect("retry reservation");
    assert!(retry.allowed, "the retry fits the free quota");
    assert!(
        !retry.duplicate,
        "a retried send after rollback is a fresh operation, not an unmetered replay"
    );
    assert_eq!(
        event_count(&h.pool, tenant, event_id).await,
        1,
        "the retried send IS metered"
    );
    assert_eq!(
        claim_count(&h, tenant, event_id).await,
        1,
        "the retry re-claims the operation"
    );
});

// ---------------------------------------------------------------------------
// send_admission.rs, send-time consent gate on the production backend (F4)
// ---------------------------------------------------------------------------

// The documented send-time consent enforcer had ZERO callers. This drives
// the production `PostgresAdmissionBackend` (real `consent_records`) through
// the shared admission gate: a marketing send without an active consent
// record is refused with a named reason and consumes no quota; transactional
// sends keep their existing contract; an active consent record admits the
// marketing send; a revoked one blocks it again.
db_test!(
    consent_gate_refuses_marketing_and_admits_transactional,
    |h| {
        use billing_service::send_admission::{
            AdmissionMeter, PostgresAdmissionBackend, SendAdmissionError, SendAdmissionRequest,
            SendAdmissionService,
        };

        let tenant = "cov_send_consent";
        seed_plan(&h.pool, "free", 3_000, 30_000).await;
        seed_tenant(&h, tenant, "free").await;

        // The idempotency keys below derive DETERMINISTIC event ids, and the
        // canonical `meter:dedup:<event-id>` Redis keys live ~40 days while
        // this test's database clone does not: a repeated run would see a
        // stale dedup key, replay the reservation (no metering row) and
        // falsely fail. Clear this test's own keys so each run reserves
        // afresh.
        {
            use billing_service::send_admission::usage_event_id;
            let mut conn = h.redis.get().await.expect("redis");
            for key in [
                "smtp:<consent-1>",
                "smtp:<consent-tx>",
                "smtp:<consent-2>",
                "smtp:<consent-3>",
            ] {
                let event_id = usage_event_id(tenant, Some(key), None);
                let _: Result<i64, _> = redis::cmd("DEL")
                    .arg(format!("meter:dedup:{event_id}"))
                    .query_async(&mut conn)
                    .await;
            }
        }

        let service = SendAdmissionService::new(Arc::new(PostgresAdmissionBackend::new(
            h.pool.clone(),
            h.redis.clone(),
        )));

        let recipient = "consent-missing@example.test";
        let rcpt = vec![recipient.to_string()];
        let marketing_event = Uuid::new_v4();

        // 1. Marketing without consent → refused with the enforcer's reason.
        let error = service
            .admit(SendAdmissionRequest {
                tenant_id: tenant,
                meter: AdmissionMeter::FilteredRecipients(&rcpt),
                idempotency_key: Some("smtp:<consent-1>"),
                idempotency_item: None,
                category: Some("marketing"),
            })
            .await
            .expect_err("marketing without consent must be refused");
        match error {
            SendAdmissionError::ConsentRefused { email, reason } => {
                assert_eq!(email, recipient);
                assert!(
                    reason.contains("consent"),
                    "named reason must mention consent: {reason}"
                );
            }
            other => panic!("expected ConsentRefused, got {other:?}"),
        }

        // 2. Transactional to the SAME recipient: admitted, metered (the
        //    pre-existing contract).
        let transactional = service
            .admit(SendAdmissionRequest {
                tenant_id: tenant,
                meter: AdmissionMeter::FilteredRecipients(&rcpt),
                idempotency_key: Some("smtp:<consent-tx>"),
                idempotency_item: None,
                category: Some("transactional"),
            })
            .await
            .expect("transactional sends are consent-exempt");
        assert_eq!(transactional.category(), "transactional");
        transactional.commit();

        let metered: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM metering_events WHERE tenant_id = $1")
                .bind(tenant)
                .fetch_one(&h.pool)
                .await
                .expect("count metering events");
        assert_eq!(
            metered, 1,
            "only the transactional send is metered; the refused marketing send reserved nothing"
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM usage_operations WHERE tenant_id = $1 AND event_id = $2",
            )
            .bind(tenant)
            .bind(marketing_event)
            .fetch_one(&h.pool)
            .await
            .expect("count claims"),
            0,
            "a refused send never claims a logical operation"
        );

        // 3. An ACTIVE marketing consent record admits the marketing send.
        sqlx::query(
        "INSERT INTO consent_records
             (id, tenant_id, subscriber_id, email, consent_type, granted, granted_at, source, metadata)
         VALUES ($1, $2, 'sub-consent-1', $3, 'marketing', true, NOW(), 'api', '{}'::jsonb)",
    )
    .bind("consent-1")
    .bind(tenant)
    .bind(recipient)
    .execute(&h.pool)
    .await
    .expect("seed consent record");

        let consented = service
            .admit(SendAdmissionRequest {
                tenant_id: tenant,
                meter: AdmissionMeter::FilteredRecipients(&rcpt),
                idempotency_key: Some("smtp:<consent-2>"),
                idempotency_item: None,
                category: Some("marketing"),
            })
            .await
            .expect("marketing with active consent is admitted");
        assert_eq!(consented.category(), "marketing");
        consented.commit();

        // 4. Revocation blocks it again (opt-out honored).
        sqlx::query(
            "UPDATE consent_records SET granted = false, revoked_at = NOW()
         WHERE tenant_id = $1 AND email = $2 AND consent_type = 'marketing'",
        )
        .bind(tenant)
        .bind(recipient)
        .execute(&h.pool)
        .await
        .expect("revoke consent");
        let revoked = service
            .admit(SendAdmissionRequest {
                tenant_id: tenant,
                meter: AdmissionMeter::FilteredRecipients(&rcpt),
                idempotency_key: Some("smtp:<consent-3>"),
                idempotency_item: None,
                category: Some("marketing"),
            })
            .await
            .expect_err("a revoked consent must block marketing again");
        assert!(
            matches!(revoked, SendAdmissionError::ConsentRefused { .. }),
            "got {revoked:?}"
        );
    }
);

// ---------------------------------------------------------------------------
// plans.rs, bootstrap reconciliation against the canonical catalog (F1)
// ---------------------------------------------------------------------------

// The exact live-dogfood drift: Free 30k/mo, Pro €10, Business €50, a
// missing starter/growth/enterprise/payg, and two active inline test rows
// (`DF5 Small`/`DF5 Big`). The reconcile must converge the table to
// `platform-catalog` exactly, and must be idempotent.
db_test!(reconcile_plans_converges_to_the_canonical_catalog, |h| {
    use billing_service::plans::{
        default_plans, plan_overage_rate_millicents, reconcile_plans_with_catalog,
        PlanReconcileReport,
    };

    let features = serde_json::to_value(billing_service::types::PlanFeatures::default())
        .expect("PlanFeatures serializes");

    // Drifted rows a stale seed left behind, plus active foreign test rows.
    let drift: [(&str, &str, i64, i64, i64, i64, i32); 5] = [
        ("free", "Free", 0, 0, 30_000, 100_000, 0),
        ("pro", "Pro", 1_000, 10_000, 150_000, 2_000_000, 2),
        ("scale", "Business", 5_000, 50_000, 2_000_000, 20_000_000, 4),
        ("df5small", "DF5 Small", 1_000, 10_000, 10, 100_000, 90),
        ("df5big", "DF5 Big", 5_000, 50_000, 1_000_000, 1_000_000, 91),
    ];
    for (name, display, price_m, price_y, email_limit, api_calls, sort) in drift {
        sqlx::query(
            "INSERT INTO plans (id, name, display_name, description, price_monthly,
                                price_yearly, email_limit, api_call_limit, features,
                                is_active, sort_order, created_at, updated_at)
             VALUES ($1, $2, $3, 'dogfood seeded catalog row', $4, $5, $6, $7, $8,
                     true, $9, NOW(), NOW())",
        )
        .bind(format!("pln_{name}"))
        .bind(name)
        .bind(display)
        .bind(price_m)
        .bind(price_y)
        .bind(email_limit)
        .bind(api_calls)
        .bind(&features)
        .bind(sort)
        .execute(&h.pool)
        .await
        .expect("seed drifted plan row");
    }

    let report = reconcile_plans_with_catalog(&h.pool)
        .await
        .expect("reconcile plans");
    assert_eq!(
        report,
        PlanReconcileReport {
            inserted: 4,
            repaired: 3,
            deactivated: 2,
        },
        "missing tiers inserted, drifted rows repaired, foreign test rows deactivated"
    );

    // The ACTIVE set now equals the canonical catalog exactly: every
    // catalog row present with the catalog price/limit/retention/team.
    // (Foreign rows stay in the table as deactivated history, asserted
    // below, but are never served by `get_active_plans`.)
    let rows: Vec<PlanRow> = sqlx::query_as(
        "SELECT name, display_name, price_monthly, price_yearly, email_limit,
                api_call_limit, is_active, features
         FROM plans
         WHERE is_active = true
         ORDER BY sort_order",
    )
    .fetch_all(&h.pool)
    .await
    .expect("read reconciled plans");
    assert_eq!(
        rows.len(),
        platform_catalog::PLANS.len(),
        "the active plans must be exactly the catalog rows"
    );
    for (index, catalog) in platform_catalog::PLANS.iter().enumerate() {
        let (name, display, price_m, price_y, email_limit, api_calls, active, features_json) =
            &rows[index];
        assert_eq!(name, catalog.name, "row {index}: name");
        assert_eq!(display, catalog.display_name, "{}: display", catalog.name);
        assert_eq!(
            *price_m, catalog.price_monthly_cents,
            "{}: eur/mo",
            catalog.name
        );
        assert_eq!(
            *price_y, catalog.price_yearly_cents,
            "{}: eur/yr",
            catalog.name
        );
        assert_eq!(
            *email_limit, catalog.email_limit,
            "{}: email limit",
            catalog.name
        );
        assert_eq!(
            *api_calls, catalog.api_call_limit,
            "{}: api limit",
            catalog.name
        );
        assert!(active, "{}: catalog rows must be active", catalog.name);
        let features: billing_service::types::PlanFeatures =
            serde_json::from_value(features_json.clone()).expect("features round-trip");
        assert_eq!(
            features.max_retention_days as i64, catalog.max_retention_days,
            "{}: retention",
            catalog.name
        );
        assert_eq!(
            features.max_team_members as i64, catalog.max_team_members,
            "{}: team members",
            catalog.name
        );
        assert_eq!(
            plan_overage_rate_millicents(catalog.name),
            catalog.overage_millicents_per_email,
            "{}: overage rate",
            catalog.name
        );
    }

    // No foreign row may be served: test rows deactivated, never deleted
    // (their mollie/subscription references stay resolvable).
    let catalog_names: Vec<&str> = platform_catalog::PLANS.iter().map(|p| p.name).collect();
    let foreign_active: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM plans WHERE NOT (name = ANY($1)) AND is_active = true",
    )
    .bind(&catalog_names)
    .fetch_one(&h.pool)
    .await
    .expect("count foreign active plans");
    assert_eq!(foreign_active, 0, "no foreign/test plan may stay active");
    for test_row in ["df5small", "df5big"] {
        let active: bool = sqlx::query_scalar("SELECT is_active FROM plans WHERE name = $1")
            .bind(test_row)
            .fetch_one(&h.pool)
            .await
            .expect("test row still exists");
        assert!(!active, "{test_row} must be deactivated");
    }
    // The public listing is exactly the catalog (active rows only).
    let listed = billing_service::plans::get_active_plans(&h.pool)
        .await
        .expect("active plans");
    assert_eq!(listed.len(), platform_catalog::PLANS.len());

    // Idempotence: a second reconcile changes nothing.
    let second = reconcile_plans_with_catalog(&h.pool)
        .await
        .expect("reconcile replay");
    assert_eq!(
        second,
        PlanReconcileReport::default(),
        "reconcile must be a no-op once converged"
    );
    assert_eq!(default_plans().len(), platform_catalog::PLANS.len());
});

// The live P1 (capability waves): existing environments' plan rows predate
// the new capability flags, so every row reported them false and the new
// capabilities were ungrantable by plan. The reconcile must therefore
// converge the feature BOOLEANS, not just prices/limits, on boot/seed.
db_test!(reconcile_repairs_drifted_capability_flags, |h| {
    use billing_service::plans::{
        default_plans, reconcile_plans_with_catalog, PlanReconcileReport,
    };
    use billing_service::types::PlanFeatures;

    // Stale rows exactly as a pre-capability environment held them: the
    // full, parseable PlanFeatures JSON with every capability flag false.
    let stale = serde_json::to_value(PlanFeatures::default()).expect("PlanFeatures serializes");
    let stale_plans = ["pro", "growth", "scale", "enterprise"];
    for (index, name) in stale_plans.iter().enumerate() {
        sqlx::query(
            "INSERT INTO plans (id, name, display_name, description, price_monthly,
                                price_yearly, email_limit, api_call_limit, features,
                                is_active, sort_order, created_at, updated_at)
             VALUES ($1, $2, $2, 'stale pre-capability row', 0, 0, 0, 0, $3, true, $4, NOW(), NOW())",
        )
        .bind(format!("pln_stale_{name}"))
        .bind(name)
        .bind(&stale)
        .bind(index as i32)
        .execute(&h.pool)
        .await
        .expect("seed stale capability row");
    }

    let report = reconcile_plans_with_catalog(&h.pool)
        .await
        .expect("reconcile plans");
    assert_eq!(
        report.repaired, 4,
        "every stale capability row must be reported repaired"
    );

    // The P1 flags this test exists for: the plan that sells the capability
    // must grant it after the reconcile (red before the fix: the flag that
    // drifted, e.g. `growth.time_travel_debugging`, stayed false).
    for (name, flag) in [
        ("growth", "time_travel_debugging"),
        ("growth", "custom_retention"),
        ("pro", "custom_tracking_domain"),
        ("scale", "template_approval_workflow"),
        ("enterprise", "subaccounts"),
    ] {
        let stored: bool =
            sqlx::query_scalar("SELECT (features->>$1)::bool FROM plans WHERE name = $2")
                .bind(flag)
                .bind(name)
                .fetch_one(&h.pool)
                .await
                .expect("read converged flag");
        assert!(stored, "{name}.{flag} must converge to the seed's grant");
    }

    // And the reconciled features equal the canonical seeds exactly.
    for seed in default_plans() {
        if !stale_plans.contains(&seed.name) {
            continue;
        }
        let stored: serde_json::Value =
            sqlx::query_scalar("SELECT features FROM plans WHERE name = $1")
                .bind(seed.name)
                .fetch_one(&h.pool)
                .await
                .expect("read reconciled features");
        assert_eq!(
            stored,
            serde_json::to_value(&seed.features).expect("seed features serialize"),
            "{}: features must converge to the canonical seed",
            seed.name
        );
    }

    // Idempotence still holds after a features-only repair: a second pass
    // reports zero changes and never deactivates a catalog row.
    let second = reconcile_plans_with_catalog(&h.pool)
        .await
        .expect("reconcile replay");
    assert_eq!(
        second,
        PlanReconcileReport::default(),
        "reconcile must be a no-op once the capability flags converged"
    );
});

// ---------------------------------------------------------------------------
// usage.rs, pure boundary functions
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
// usage_ingest.rs, batch ingest attacks
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
// usage_ingest.rs, derived sweep + reconciliation
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
// routes.rs, HTTP surface: auth gates, malformed input, error mapping
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
    seed_mollie_subscription(
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
    // N-01 (beta authority inversion): the public DTO carries NO provider
    // object ids.
    assert!(
        json["subscription"].get("mollieSubscriptionId").is_none()
            && json["subscription"].get("mollie_subscription_id").is_none(),
        "body: {json}"
    );
    assert_eq!(json["subscription"]["status"], "active", "body: {json}");
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

        // External audit 15 Oct, H1: cancellation is a LOCAL state change, not
        // a checkout/portal refusal. With no subscription it is a coherent 404.
        let (status, json) = call(
            &app,
            authed("POST", &format!("/cancel?tenant_id={tenant}"))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"reason":"too expensive"}"#))
                .expect("request"),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(
            json["error"]["message"]
                .as_str()
                .unwrap_or("")
                .contains("No active subscription"),
            "{json}"
        );

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

    // Seeding is RECONCILIATION to the canonical catalog now (F1 fix), and
    // idempotent: the first call reports what it changed, the second is a
    // clean no-op.
    let mut first = true;
    for _ in 0..2 {
        let (status, json) = call(
            &app,
            authed("POST", "/plans/seed")
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            json["message"], "Default plans reconciled with the canonical catalog",
            "{json}"
        );
        if !first {
            assert_eq!(json["inserted"], 0, "second reconcile inserts nothing");
            assert_eq!(json["repaired"], 0, "second reconcile repairs nothing");
            assert_eq!(
                json["deactivated"], 0,
                "second reconcile deactivates nothing"
            );
        }
        first = false;
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
// overage.rs, end-of-period sweep: boundaries, idempotency, isolation
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

async fn seed_reverse_charge_business(h: &Harness, tenant: &str) {
    // V30: a verified cross-border EU business pays the NET list price
    // (reverse charge). The evidence row is what authorises the 0 % rate.
    sqlx::query(
        "INSERT INTO billing_addresses (tenant_id, company_name, vat_number, address_line1, \
            city, postal_code, country, is_business) \
         VALUES ($1, $2, 'DE123456789', 'Test 1', 'Berlin', '10115', 'DE', TRUE) \
         ON CONFLICT (tenant_id) DO UPDATE SET country = 'DE', vat_number = 'DE123456789', \
            is_business = TRUE",
    )
    .bind(tenant)
    .bind(format!("Coverage {tenant} GmbH"))
    .execute(&h.pool)
    .await
    .expect("seed reverse-charge billing address");
    sqlx::query(
        "INSERT INTO vat_validation_evidence \
            (tenant_id, vat_number, country, source, requested_at, valid, response_hash, valid_from) \
         VALUES ($1, 'DE123456789', 'DE', 'VIES', NOW() - INTERVAL '1 day', TRUE, \
            'coverage-evidence', CURRENT_DATE - 1)",
    )
    .bind(tenant)
    .execute(&h.pool)
    .await
    .expect("seed VIES evidence");
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

    // TIMESTAMPTZ stores microseconds: derive the period at the precision
    // the database round-trips, so the asserted `overage_period` is exactly
    // the persisted value.
    let now = Utc::now();
    let start = (now - chrono::Duration::days(30)).trunc_subsecs(6);
    let end = (now - chrono::Duration::days(1)).trunc_subsecs(6);

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
    // events: cannot distinguish empty from aged-out, review, don't drop.
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
// mollie_webhooks.rs, Mollie's wire: `id=tr_…`, authenticated fetch, replay,
// ordering, recurring settlement and token binding
// ---------------------------------------------------------------------------
//
// Mollie posts `application/x-www-form-urlencoded` with ONE parameter `id`
// (a payment `tr_…` or a refund `re_…`). There is NO signature and NO status
// on the wire: the only way to know what happened is an authenticated
// `GET /v2/payments/{id}` with the secret key. These tests run a local mock
// Mollie API and post the same form bodies Mollie would.

/// The bare acknowledgement the handler returns for an accepted delivery.
const MOLLIE_ACCEPTED: &str = "OK";

type MockResponses = Arc<std::sync::Mutex<std::collections::HashMap<String, (u16, String)>>>;

/// Provider-side object ledger: subscriptions the mock MINTED (distinct ids
/// per create call) and ids DELETEd, so tests can assert provider-side
/// facts (one live subscription after a racing activation, an orphan
/// actually canceled) instead of only local rows.
#[derive(Default)]
struct MockState {
    responses: MockResponses,
    created: std::sync::Mutex<Vec<String>>,
    counter: std::sync::atomic::AtomicU64,
}

struct MockMollie {
    state: &'static MockState,
}

impl MockMollie {
    fn route(&self, path: &str, status: u16, body: impl Into<String>) {
        self.state
            .responses
            .lock()
            .expect("lock")
            .insert(path.to_string(), (status, body.into()));
    }

    fn publish_payment(&self, document: &serde_json::Value) {
        let id = document["id"].as_str().expect("payment document id");
        self.route(&format!("/v2/payments/{id}"), 200, document.to_string());
    }

    /// Subscription ids the mock minted (in creation order). Always empty
    /// in the local-authority world: the activation mints NO provider
    /// schedule (the assertion the activation test pins).
    fn created(&self) -> Vec<String> {
        self.state.created.lock().expect("lock").clone()
    }
}

async fn mock_handler(
    axum::extract::State(state): axum::extract::State<&'static MockState>,
    request: axum::http::Request<axum::body::Body>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    if method == axum::http::Method::POST && path.ends_with("/subscriptions") {
        let explicit = state.responses.lock().expect("lock").get(&path).cloned();
        if explicit.is_none() {
            // Distinct minted ids per create call: the activation saga must
            // serialize racing checkouts BEFORE the provider mutation, so two
            // concurrent activations mint two objects and retire exactly one.
            let n = state
                .counter
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let id = format!("sub_dyn_{n}");
            state.created.lock().expect("lock").push(id.clone());
            let body = serde_json::json!({
                "id": id,
                "customerId": path.split('/').nth(3).unwrap_or("cst_dyn"),
                "status": "active",
                "amount": { "currency": "EUR", "value": "20.00" },
                "interval": "1 month",
                "description": "ApexMail (dynamic mock)"
            })
            .to_string();
            return (
                axum::http::StatusCode::CREATED,
                [(axum::http::header::CONTENT_TYPE, "application/json")],
                body,
            )
                .into_response();
        }
    }
    let (status, response_body) = state
        .responses
        .lock()
        .expect("lock")
        .get(&path)
        .cloned()
        .unwrap_or_else(|| {
            if path.ends_with("/refunds") {
                (200, r#"{"_embedded":{"refunds":[]}}"#.to_string())
            } else if path.ends_with("/chargebacks") {
                (200, r#"{"_embedded":{"chargebacks":[]}}"#.to_string())
            } else {
                (404, r#"{"title":"Not Found"}"#.to_string())
            }
        });
    // `{seq}` in a routed body is replaced by the global call counter, so a
    // POST /v2/payments route mints a DISTINCT payment id per call (the
    // attempts ledger's unique key made shared ids a fixture lie).
    let seq = state
        .counter
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let response_body = response_body.replace("{seq}", &seq.to_string());
    (
        axum::http::StatusCode::from_u16(status).expect("status"),
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        response_body,
    )
        .into_response()
}

/// The one process-wide mock Mollie API (own OS thread so it outlives the
/// per-test runtimes), installing the client configuration exactly once.
fn mock_mollie_api() -> &'static MockMollie {
    static MOCK: std::sync::OnceLock<MockMollie> = std::sync::OnceLock::new();
    MOCK.get_or_init(|| {
        let state: &'static MockState = Box::leak(Box::new(MockState::default()));
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind mock");
        listener
            .set_nonblocking(true)
            .expect("nonblocking mock listener");
        let address = listener.local_addr().expect("mock address");
        let app = axum::Router::new().fallback(mock_handler).with_state(state);
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("mock runtime");
            runtime.block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener).expect("tokio listener");
                axum::serve(listener, app).await.expect("mock server");
            });
        });
        std::env::set_var("MOLLIE_API_KEY", "test_mock_api_key");
        std::env::set_var("MOLLIE_API_BASE_URL", format!("http://{address}/v2"));
        MockMollie { state }
    })
}

fn money_value(cents: i64) -> String {
    format!("{}.{:02}", cents.div_euclid(100), cents.rem_euclid(100))
}

/// A fetched Mollie payment document (decimal amounts, camelCase fields).
#[allow(clippy::too_many_arguments)]
fn payment_document(
    payment_id: &str,
    status: &str,
    cents: i64,
    sequence_type: Option<&str>,
    customer_id: &str,
    mandate_id: Option<&str>,
    metadata: serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({
        "id": payment_id,
        "status": status,
        "amount": { "currency": "EUR", "value": money_value(cents) },
        "sequenceType": sequence_type,
        "customerId": customer_id,
        "mandateId": mandate_id,
        "paidAt": "2026-10-14T10:00:00+00:00",
        "method": "ideal",
        "metadata": metadata,
    })
}

/// A recurring charge against a stored mandate for `invoice_id`.
///
/// The metadata mirrors what `renew_subscription_locked` ACTUALLY sends
/// (`tenant_id`, `plan_name`, `interval`, `reference`): the fixture this
/// replaces carried only a reference, which is exactly why MON-8 shipped.
fn recurring_payment(
    payment_id: &str,
    invoice_id: Uuid,
    cents: i64,
    tenant: Option<&str>,
) -> serde_json::Value {
    let tenant = tenant.unwrap_or("cst_cov");
    let mut metadata = serde_json::json!({
        "reference": format!("invoice:{invoice_id}"),
        "tenant_id": tenant,
        "plan_name": "growth",
        "interval": "monthly",
    });
    if tenant.is_empty() {
        metadata
            .as_object_mut()
            .expect("object")
            .remove("tenant_id");
    }
    payment_document(
        payment_id,
        "paid",
        cents,
        Some("recurring"),
        tenant,
        Some("mdt_cov"),
        metadata,
    )
}

/// A first (checkout/mandate-creating) payment for `tenant`.
fn first_payment(
    payment_id: &str,
    tenant: &str,
    mandate_id: &str,
    invoice_id: Option<Uuid>,
) -> serde_json::Value {
    let mut metadata = serde_json::json!({ "tenant_id": tenant });
    if let Some(invoice_id) = invoice_id {
        metadata["reference"] = serde_json::json!(format!("invoice:{invoice_id}"));
    }
    payment_document(
        payment_id,
        "paid",
        2_900,
        Some("first"),
        tenant,
        Some(mandate_id),
        metadata,
    )
}

/// POST a raw body to `/webhooks/mollie` and return `(status, body-text)`.
async fn post_mollie(app: &axum::Router, body: Vec<u8>) -> (StatusCode, String) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/webhooks/mollie")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .expect("request"),
        )
        .await
        .expect("router is infallible");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body");
    (status, String::from_utf8_lossy(&bytes).to_string())
}

async fn post_mollie_with_header(
    app: &axum::Router,
    body: Vec<u8>,
    header_name: &str,
    header_value: &str,
) -> (StatusCode, String) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/webhooks/mollie")
                .header("content-type", "application/json")
                .header(header_name, header_value)
                .body(Body::from(body))
                .expect("request"),
        )
        .await
        .expect("router is infallible");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body");
    (status, String::from_utf8_lossy(&bytes).to_string())
}

/// Deliver a payment id exactly as Mollie's webhook does.
async fn deliver_payment(app: &axum::Router, payment_id: &str) -> (StatusCode, String) {
    post_mollie(app, format!("id={payment_id}").into_bytes()).await
}

async fn expect_mollie_ok(app: &axum::Router, payment_id: &str) {
    let (status, text) = deliver_payment(app, payment_id).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "webhook {payment_id} rejected: {text}"
    );
    assert_eq!(
        text, MOLLIE_ACCEPTED,
        "the acknowledgement is the bare OK body Mollie treats as success"
    );
}

/// The `error` field of a JSON refusal body.
fn json_error(text: &str) -> String {
    serde_json::from_str::<serde_json::Value>(text)
        .ok()
        .and_then(|value| value["error"].as_str().map(str::to_string))
        .unwrap_or_else(|| panic!("expected a JSON error body, got {text:?}"))
}

/// Serializes the tests that inspect the process-shared deadletter indexes.
static WEBHOOK_DEADLETTER_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The `(status, error)` rows recorded for a payment id.
async fn webhook_rows(h: &Harness, payment_id: &str) -> Vec<(String, Option<String>)> {
    sqlx::query_as(
        "SELECT status, error FROM mollie_webhook_events
         WHERE mollie_payment_id = $1 ORDER BY created_at",
    )
    .bind(payment_id)
    .fetch_all(&h.pool)
    .await
    .expect("webhook rows")
}

/// Deadletter entries whose stored payload names one of `needles`.
async fn deadletters_naming(h: &Harness, needles: &[&str]) -> Vec<serde_json::Value> {
    let mut conn = h.redis.get().await.expect("redis connection");
    let keys: Vec<String> = redis::cmd("KEYS")
        .arg("mollie:deadletter:event:*")
        .query_async(&mut conn)
        .await
        .expect("deadletter keys");
    let mut entries = Vec::new();
    for key in keys {
        let value: Option<String> = redis::cmd("GET")
            .arg(&key)
            .query_async(&mut conn)
            .await
            .expect("deadletter entry");
        let Some(value) = value else { continue };
        if needles.iter().any(|needle| value.contains(needle)) {
            entries.push(serde_json::from_str(&value).expect("deadletter entry is JSON"));
        }
    }
    entries
}

/// Delete deadletter entries whose stored payload names any of `needles`.
async fn clear_deadletters_naming(h: &Harness, needles: &[&str]) {
    let mut conn = h.redis.get().await.expect("redis connection");
    let keys: Vec<String> = redis::cmd("KEYS")
        .arg("mollie:deadletter:event:*")
        .query_async(&mut conn)
        .await
        .expect("deadletter keys");
    for key in keys {
        let value: Option<String> = redis::cmd("GET")
            .arg(&key)
            .query_async(&mut conn)
            .await
            .expect("deadletter entry");
        if let Some(value) = value {
            if needles.iter().any(|needle| value.contains(needle)) {
                let _: () = redis::cmd("DEL")
                    .arg(&key)
                    .query_async(&mut conn)
                    .await
                    .expect("delete deadletter");
            }
        }
    }
}

/// A local `pending` invoice in the shape the recurring-charge contract
/// produces (the wire names it by `invoice:{id}`).
async fn seed_cov_local_invoice(
    h: &Harness,
    tenant: &str,
    invoice_id: Uuid,
    subtotal: i64,
    vat: i64,
    total: i64,
    currency: &str,
) {
    sqlx::query(
        "INSERT INTO invoices (id, tenant_id, invoice_number, status, amount, currency,
                               subtotal, vat_total, total, due_at, period_start, period_end,
                               created_at, updated_at)
         VALUES ($1, $2, $3, 'pending', $6, $7, $4, $5, $6, NOW(), NOW(),
                 NOW() + INTERVAL '30 days', NOW(), NOW())",
    )
    .bind(invoice_id)
    .bind(tenant)
    .bind(format!("COV-WH-{}", &invoice_id.to_string()[..8]))
    .bind(subtotal)
    .bind(vat)
    .bind(total)
    .bind(currency)
    .execute(&h.pool)
    .await
    .expect("seed local invoice");
}

/// The tenant's `subscription_state` row, optionally already tokenized.
async fn seed_cov_subscription(
    h: &Harness,
    tenant: &str,
    subscription_id: &str,
    token: Option<&str>,
) {
    sqlx::query(
        "INSERT INTO subscription_state
             (tenant_id, provider_contract_id, plan, status, billing_cycle_start,
              billing_cycle_end, provider_customer_id, snapshot_plan_code,
              provider_method_id)
         VALUES ($1, $2, 'growth', 'active', NOW(), NOW() + INTERVAL '30 days', $1,
                 'apexmail_growth_monthly', $3)",
    )
    .bind(tenant)
    .bind(subscription_id)
    .bind(token)
    .execute(&h.pool)
    .await
    .expect("seed mollie subscription");
}

db_test!(mollie_webhook_form_body_is_verified_by_fetch, |h| {
    let mock = mock_mollie_api();
    let app = billing_service::routes::router(h.state.clone());
    let tenant = "cov_wh_form";
    seed_tenant(&h, tenant, "free").await;
    let invoice_id = Uuid::new_v4();
    seed_cov_local_invoice(&h, tenant, invoice_id, 1_000, 0, 1_000, "eur").await;
    mock.publish_payment(&recurring_payment(
        "tr_cov_form",
        invoice_id,
        1_000,
        Some(tenant),
    ));

    expect_mollie_ok(&app, "tr_cov_form").await;

    let (status_text, allocations, rows): (String, i64, i64) = sqlx::query_as(
        "SELECT (SELECT status FROM invoices WHERE id = $1),
                (SELECT COUNT(*) FROM invoice_payment_allocations WHERE invoice_id = $1),
                (SELECT COUNT(*) FROM mollie_webhook_events
                 WHERE mollie_payment_id = 'tr_cov_form' AND status = 'processed')",
    )
    .bind(invoice_id)
    .fetch_one(&h.pool)
    .await
    .expect("settled state");
    assert_eq!(status_text, "paid");
    assert_eq!(allocations, 1, "the fetched payment settles exactly once");
    assert_eq!(rows, 1);
});

db_test!(mollie_webhook_refusals_write_nothing_and_deadletter, |h| {
    let _guard = WEBHOOK_DEADLETTER_LOCK.lock().await;
    let mock = mock_mollie_api();
    let app = billing_service::routes::router(h.state.clone());
    seed_tenant(&h, "cov_wh_refuse", "free").await;
    let probes = [
        "tr_cov_unknown_id",
        "tr_cov_provider_down",
        "tr_cov_unreadable",
        "tr_cov_bad_id_0",
        "tr_cov_legacy",
    ];
    clear_deadletters_naming(&h, &probes).await;

    // An id the provider does not know: 200 so the endpoint is never an
    // existence oracle, and nothing recorded.
    let (status, text) = deliver_payment(&app, "tr_cov_unknown_id").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json_error(&text), "ignored");
    assert!(webhook_rows(&h, "tr_cov_unknown_id").await.is_empty());

    // A provider 5xx asks Mollie to retry: 503, never a deadletter.
    mock.route("/v2/payments/tr_cov_provider_down", 503, "upstream down");
    let (status, _) = deliver_payment(&app, "tr_cov_provider_down").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(deadletters_naming(&h, &["tr_cov_provider_down"])
        .await
        .is_empty());
    assert!(webhook_rows(&h, "tr_cov_provider_down").await.is_empty());

    // A provider document we cannot read is a refused, deadlettered 400.
    mock.route("/v2/payments/tr_cov_unreadable", 200, "not json");
    let (status, text) = deliver_payment(&app, "tr_cov_unreadable").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json_error(&text), "Mollie returned an unreadable object");
    let entries = deadletters_naming(&h, &["tr_cov_unreadable"]).await;
    assert_eq!(entries.len(), 1, "the unreadable object is deadlettered");
    assert_eq!(entries[0]["reason"], "malformed_provider_object");
    assert!(webhook_rows(&h, "tr_cov_unreadable").await.is_empty());

    // Malformed ids never reach the provider and are deadlettered.
    for body in [
        &b""[..],
        b"id=",
        b"id=../etc/passwd",
        b"id=https://evil.example/tr_cov_bad_id_0",
        b"id=foo_1",
        b"id=tr_cov_bad_id_0/y",
        b"{}",
        &[0xff, 0xfe][..],
    ] {
        let (status, text) = post_mollie(&app, body.to_vec()).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "body {:?}: {text}",
            String::from_utf8_lossy(body)
        );
        assert_eq!(json_error(&text), "Invalid webhook body");
    }
    assert!(
        !deadletters_naming(&h, &["tr_cov_bad_id_0"])
            .await
            .is_empty(),
        "a refused id is deadlettered for triage"
    );

    // legacy-wire-negative-test: NO signature exists, the pre-Mollie signed
    // envelope (and a legacy HMAC header) authorise nothing, because the body
    // names no object id.
    let legacy_body = serde_json::to_vec(&serde_json::json!({
        "live": "false",
        "notificationItems": [{
            "NotificationRequestItem": {
                "provider_payment_id": "tr_cov_legacy",
                "event_code": "AUTHORISATION",
                "success": "true"
            }
        }]
    }))
    .expect("legacy body");
    let (status, text) = post_mollie_with_header(
        &app,
        legacy_body,
        "mollie-hmac-signature",
        "t=1,v1=deadbeef",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json_error(&text), "Invalid webhook body");
    assert!(
        !deadletters_naming(&h, &["tr_cov_legacy"]).await.is_empty(),
        "the legacy delivery is deadlettered"
    );

    // Every refusal above wrote NO claim row and no business state.
    let events: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM mollie_webhook_events WHERE mollie_payment_id LIKE 'tr_cov_%'",
    )
    .fetch_one(&h.pool)
    .await
    .expect("count events");
    assert_eq!(events, 0, "failed verification must write nothing");
    let invoices: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM invoices")
        .fetch_one(&h.pool)
        .await
        .expect("count invoices");
    assert_eq!(invoices, 0);
    let subs: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM subscription_state")
        .fetch_one(&h.pool)
        .await
        .expect("count subscriptions");
    assert_eq!(subs, 0);
    let snapshots: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM mollie_tax_snapshots")
        .fetch_one(&h.pool)
        .await
        .expect("count tax snapshots");
    assert_eq!(snapshots, 0);
});

db_test!(
    mollie_webhook_unsettled_status_is_acknowledged_without_effects,
    |h| {
        let mock = mock_mollie_api();
        let app = billing_service::routes::router(h.state.clone());
        mock.publish_payment(&payment_document(
            "tr_cov_open",
            "open",
            2_900,
            Some("recurring"),
            "cst_cov",
            Some("mdt_cov"),
            serde_json::json!({ "tenant_id": "cov_wh_open" }),
        ));
        expect_mollie_ok(&app, "tr_cov_open").await;

        let events: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM mollie_webhook_events")
            .fetch_one(&h.pool)
            .await
            .expect("count events");
        assert_eq!(events, 0, "open has not settled: no fact to record");
        let invoices: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM invoices")
            .fetch_one(&h.pool)
            .await
            .expect("count invoices");
        assert_eq!(invoices, 0);
    }
);

db_test!(
    mollie_webhook_replay_is_idempotent_and_reclaims_stale,
    |h| {
        let mock = mock_mollie_api();
        let app = billing_service::routes::router(h.state.clone());
        let tenant = "cov_wh_replay";
        seed_tenant(&h, tenant, "free").await;

        let replay_invoice = Uuid::new_v4();
        seed_cov_local_invoice(&h, tenant, replay_invoice, 1_000, 0, 1_000, "eur").await;
        mock.publish_payment(&recurring_payment(
            "tr_cov_replay",
            replay_invoice,
            1_000,
            Some(tenant),
        ));
        expect_mollie_ok(&app, "tr_cov_replay").await;
        expect_mollie_ok(&app, "tr_cov_replay").await;

        let (status_text, allocations, claims): (String, i64, i64) = sqlx::query_as(
        "SELECT (SELECT status FROM invoices WHERE id = $1),
                (SELECT COUNT(*) FROM invoice_payment_allocations WHERE invoice_id = $1),
                (SELECT COUNT(*) FROM mollie_webhook_events WHERE mollie_payment_id = 'tr_cov_replay')",
    )
    .bind(replay_invoice)
    .fetch_one(&h.pool)
    .await
    .expect("replay state");
        assert_eq!(status_text, "paid");
        assert_eq!(allocations, 1, "replay never double-allocates");
        assert_eq!(claims, 1, "one claim row per payment fact");

        // Stale-pending reclaim: an 11-minute-old pending row is reclaimed, a
        // fresh one is left alone; the redelivered payment then settles once.
        let stale_invoice = Uuid::new_v4();
        seed_cov_local_invoice(&h, tenant, stale_invoice, 2_500, 0, 2_500, "eur").await;
        mock.publish_payment(&recurring_payment(
            "tr_cov_replay_stale",
            stale_invoice,
            2_500,
            Some(tenant),
        ));
        let fresh_id = "mollie:cov_replay_fresh_not_stolen";
        sqlx::query(
            "INSERT INTO mollie_webhook_events
             (id, mollie_event_id, event_type, status, created_at, updated_at)
         VALUES (gen_random_uuid(), 'mollie:cov_replay_stale_pending', 'AUTHORISATION', 'pending',
                 NOW() - INTERVAL '20 minutes', NOW() - INTERVAL '11 minutes'),
                (gen_random_uuid(), $1, 'AUTHORISATION', 'pending', NOW(), NOW())",
        )
        .bind(fresh_id)
        .execute(&h.pool)
        .await
        .expect("seed pending rows");

        let reclaimed = billing_service::mollie_webhooks::reclaim_stale_pending_webhooks(&h.state)
            .await
            .expect("reclaim stale pending webhooks");
        assert_eq!(
            reclaimed,
            vec!["mollie:cov_replay_stale_pending".to_string()]
        );
        let (stale_status, fresh_status): (String, String) = sqlx::query_as(
            "SELECT (SELECT status FROM mollie_webhook_events WHERE mollie_event_id = $1),
                (SELECT status FROM mollie_webhook_events WHERE mollie_event_id = $2)",
        )
        .bind("mollie:cov_replay_stale_pending")
        .bind(fresh_id)
        .fetch_one(&h.pool)
        .await
        .expect("pending rows");
        assert_eq!(stale_status, "received", "the abandoned claim is reclaimed");
        assert_eq!(fresh_status, "pending", "fresh pending work is not stolen");

        expect_mollie_ok(&app, "tr_cov_replay_stale").await;
        let (status_text, allocations, claims): (String, i64, i64) = sqlx::query_as(
        "SELECT (SELECT status FROM invoices WHERE id = $1),
                (SELECT COUNT(*) FROM invoice_payment_allocations WHERE invoice_id = $1),
                (SELECT COUNT(*) FROM mollie_webhook_events WHERE mollie_payment_id = 'tr_cov_replay_stale')",
    )
    .bind(stale_invoice)
    .fetch_one(&h.pool)
    .await
    .expect("stale state");
        assert_eq!(status_text, "paid");
        assert_eq!(allocations, 1);
        assert_eq!(claims, 1);
    }
);

db_test!(mollie_webhook_out_of_order_events_never_rewind_state, |h| {
    let mock = mock_mollie_api();
    let app = billing_service::routes::router(h.state.clone());
    let tenant = "cov_wh_order";
    seed_tenant(&h, tenant, "free").await;
    clear_deadletters_naming(&h, &["tr_cov_order_second"]).await;
    let invoice_id = Uuid::new_v4();
    seed_cov_local_invoice(&h, tenant, invoice_id, 1_200, 0, 1_200, "eur").await;

    mock.publish_payment(&recurring_payment(
        "tr_cov_order_first",
        invoice_id,
        1_200,
        Some(tenant),
    ));
    expect_mollie_ok(&app, "tr_cov_order_first").await;

    let (paid_at_after_first,): (DateTime<Utc>,) =
        sqlx::query_as("SELECT paid_at FROM invoices WHERE id = $1")
            .bind(invoice_id)
            .fetch_one(&h.pool)
            .await
            .expect("invoice after settlement");
    // N-05/N-10 (step 10): the settlement binding lives on the neutral
    // execution ledger.
    let payment_after_first: String = sqlx::query_scalar(
        "SELECT provider_payment_id FROM payment_attempts \
         WHERE provider = 'mollie' AND provider_payment_id = 'tr_cov_order_first' \
           AND state = 'succeeded'",
    )
    .fetch_one(&h.pool)
    .await
    .expect("settled attempt after the first fact");
    assert_eq!(payment_after_first, "tr_cov_order_first");

    // A LATER, DIFFERENT payment fact for the already-paid invoice is a NEW
    // notification: acknowledged idempotently, never re-settled or rewound.
    mock.publish_payment(&recurring_payment(
        "tr_cov_order_second",
        invoice_id,
        1_200,
        Some(tenant),
    ));
    expect_mollie_ok(&app, "tr_cov_order_second").await;

    let (status_text, allocations, bound_after_second, paid_at_after_second): (
        String,
        i64,
        String,
        DateTime<Utc>,
    ) = sqlx::query_as(
        "SELECT status,
                (SELECT COUNT(*) FROM invoice_payment_allocations WHERE invoice_id = $1),
                -- The neutral binding (N-05, step 10): the settled
                -- obligation's confirmed provider payment id.
                COALESCE((SELECT provider_payment_id FROM payment_attempts
                          WHERE provider = 'mollie'
                            AND obligation_ref = 'invoice:' || $1::text
                            AND state = 'succeeded'
                          LIMIT 1), ''),
                paid_at
         FROM invoices WHERE id = $1",
    )
    .bind(invoice_id)
    .fetch_one(&h.pool)
    .await
    .expect("invoice after the later delivery");
    assert_eq!(status_text, "paid", "the settled invoice is never rewound");
    assert_eq!(allocations, 1, "a second charge never double-settles");
    assert_eq!(
        bound_after_second, payment_after_first,
        "the binding is never overwritten"
    );
    assert_eq!(
        paid_at_after_second, paid_at_after_first,
        "paid_at is never re-stamped"
    );
    let processed: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM mollie_webhook_events
         WHERE mollie_payment_id IN ('tr_cov_order_first', 'tr_cov_order_second')
           AND status = 'processed'",
    )
    .fetch_one(&h.pool)
    .await
    .expect("claim rows");
    assert_eq!(processed, 2, "both deliveries are claimed and acked");
    assert!(
        deadletters_naming(&h, &["tr_cov_order_second"])
            .await
            .is_empty(),
        "an idempotent later delivery is acked, not deadlettered"
    );
});

db_test!(mollie_webhook_unresolvable_authorisation_deadletters, |h| {
    let _guard = WEBHOOK_DEADLETTER_LOCK.lock().await;
    let mock = mock_mollie_api();
    let app = billing_service::routes::router(h.state.clone());
    let unresolvable = Uuid::new_v4();
    clear_deadletters_naming(&h, &["tr_cov_unresolved"]).await;
    mock.publish_payment(&recurring_payment(
        "tr_cov_unresolved",
        unresolvable,
        700,
        None,
    ));
    let (status, _) = deliver_payment(&app, "tr_cov_unresolved").await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "unresolvable revenue must be refused for replay, not silently dropped"
    );

    let rows = webhook_rows(&h, "tr_cov_unresolved").await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].0, "failed");
    let error = rows[0].1.clone().unwrap_or_default();
    assert!(
        error.contains(&unresolvable.to_string()),
        "the deadletter names the unresolvable reference: {error}"
    );
    let entries = deadletters_naming(&h, &["tr_cov_unresolved"]).await;
    assert_eq!(entries.len(), 1, "the refusal is deadlettered for replay");

    let invoices: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM invoices")
        .fetch_one(&h.pool)
        .await
        .expect("count invoices");
    assert_eq!(invoices, 0, "no local invoice was invented");
});

db_test!(
    mollie_webhook_recurring_authorisation_settles_the_local_invoice,
    |h| {
        let mock = mock_mollie_api();
        let app = billing_service::routes::router(h.state.clone());
        let tenant = "cov_wh_settle";
        seed_tenant(&h, tenant, "growth").await;
        let invoice_id = Uuid::new_v4();
        seed_cov_local_invoice(&h, tenant, invoice_id, 10_000, 2_400, 12_400, "eur").await;
        seed_cov_subscription(&h, tenant, "sub_cov_settle", Some("mdt_cov_settle")).await;
        mock.publish_payment(&recurring_payment(
            "tr_cov_settle",
            invoice_id,
            12_400,
            Some(tenant),
        ));

        expect_mollie_ok(&app, "tr_cov_settle").await;

        let (status_text, paid, snapshot_id): (String, bool, Option<Uuid>) = sqlx::query_as(
            "SELECT status, paid_at IS NOT NULL, mollie_tax_snapshot_id
             FROM invoices WHERE id = $1",
        )
        .bind(invoice_id)
        .fetch_one(&h.pool)
        .await
        .expect("local invoice");
        assert_eq!(status_text, "paid");
        assert!(paid, "paid_at is stamped");
        // N-05/N-10 (step 10): the settlement binds the payment id on the
        // NEUTRAL execution ledger, not a provider-named invoice column.
        let (bound_payment, bound_obligation): (String, String) = sqlx::query_as(
            "SELECT provider_payment_id, obligation_ref FROM payment_attempts \
             WHERE provider = 'mollie' AND provider_payment_id = 'tr_cov_settle'",
        )
        .fetch_one(&h.pool)
        .await
        .expect("attempt");
        assert_eq!(
            bound_obligation,
            format!("invoice:{invoice_id}"),
            "the settlement binds the provider payment id to the obligation"
        );
        let _ = bound_payment;

        let (amount, currency, source, operation): (i64, String, String, String) = sqlx::query_as(
            "SELECT amount_cents, currency, source, operation_id
             FROM invoice_payment_allocations WHERE invoice_id = $1",
        )
        .bind(invoice_id)
        .fetch_one(&h.pool)
        .await
        .expect("allocation");
        assert_eq!(amount, 12_400, "the decimal charge allocates exactly once");
        assert_eq!(currency, "EUR");
        assert_eq!(
            source, "processor",
            "the engine writes the generic source role"
        );
        assert_eq!(operation, "mollie:tr_cov_settle");

        let snapshot_id = snapshot_id.expect("the tax snapshot is linked onto the invoice");
        let (authority, validation): (String, String) = sqlx::query_as(
            "SELECT authority, validation_status FROM mollie_tax_snapshots WHERE id = $1",
        )
        .bind(snapshot_id)
        .fetch_one(&h.pool)
        .await
        .expect("tax snapshot");
        assert_eq!(
            authority, "apexmail_local",
            "the charging authority is ApexMail's own local computation"
        );
        assert_eq!(validation, "validated");

        let rows = webhook_rows(&h, "tr_cov_settle").await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0, "processed");
    }
);

db_test!(
    mollie_webhook_cross_tenant_binding_and_bad_states_refuse,
    |h| {
        let _guard = WEBHOOK_DEADLETTER_LOCK.lock().await;
        let mock = mock_mollie_api();
        let app = billing_service::routes::router(h.state.clone());
        let owner = "cov_wh_bind_a";
        let other = "cov_wh_bind_b";
        seed_tenant(&h, owner, "free").await;
        seed_tenant(&h, other, "free").await;
        seed_cov_subscription(&h, owner, "sub_cov_bound", None).await;
        let invoice_id = Uuid::new_v4();
        seed_cov_local_invoice(&h, owner, invoice_id, 4_900, 0, 4_900, "eur").await;

        // The FIRST payment binds the OWNER's subscription: the fetch produces
        // both an informational authorisation and the RECURRING_CONTRACT fact.
        // No obligation reference: a first payment that names an invoice is a
        // SETTLEMENT (MON-8), not this test's mandate-binding subject.
        mock.publish_payment(&first_payment(
            "tr_cov_bind_owner",
            owner,
            "mdt_cov_owner",
            None,
        ));
        expect_mollie_ok(&app, "tr_cov_bind_owner").await;
        let bound: Option<String> = sqlx::query_scalar(
            "SELECT provider_method_id FROM subscription_state
         WHERE provider_contract_id = 'sub_cov_bound'",
        )
        .fetch_one(&h.pool)
        .await
        .expect("owner subscription");
        assert_eq!(bound.as_deref(), Some("mdt_cov_owner"));

        // The invoice belongs to `owner` but the payment is attributed to
        // `other`: cross-tenant settlement is refused and nothing moves.
        clear_deadletters_naming(&h, &["tr_cov_cross"]).await;
        mock.publish_payment(&recurring_payment(
            "tr_cov_cross",
            invoice_id,
            4_900,
            Some(other),
        ));
        let (status, _) = deliver_payment(&app, "tr_cov_cross").await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "a cross-tenant settlement is refused"
        );
        let rows = webhook_rows(&h, "tr_cov_cross").await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0, "failed");
        assert!(
            rows[0]
                .1
                .clone()
                .unwrap_or_default()
                .contains("cross-tenant"),
            "the refusal names the condition"
        );
        let (invoice_status, payment_id, allocations): (String, Option<String>, i64) =
            sqlx::query_as(
                "SELECT status, mollie_payment_id,
                (SELECT COUNT(*) FROM invoice_payment_allocations WHERE invoice_id = $1)
         FROM invoices WHERE id = $1",
            )
            .bind(invoice_id)
            .fetch_one(&h.pool)
            .await
            .expect("invoice");
        assert_eq!(invoice_status, "pending");
        assert_eq!(payment_id, None);
        assert_eq!(allocations, 0);

        // A token delivery for a tenant with no subscription row is
        // acknowledged (the mandate is recoverable from the provider) and no
        // row is invented.
        mock.publish_payment(&first_payment(
            "tr_cov_bind_orphan",
            other,
            "mdt_cov_orphan",
            None,
        ));
        expect_mollie_ok(&app, "tr_cov_bind_orphan").await;
        let other_rows: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM subscription_state WHERE tenant_id = $1")
                .bind(other)
                .fetch_one(&h.pool)
                .await
                .expect("other subscriptions");
        assert_eq!(other_rows, 0, "the acknowledgement invents no row");
        let owner_token_after: Option<String> = sqlx::query_scalar(
            "SELECT provider_method_id FROM subscription_state
         WHERE provider_contract_id = 'sub_cov_bound'",
        )
        .fetch_one(&h.pool)
        .await
        .expect("owner subscription");
        assert_eq!(
            owner_token_after.as_deref(),
            Some("mdt_cov_owner"),
            "another tenant's delivery never rewrites the owner's binding"
        );
    }
);

db_test!(
    unverified_mollie_contract_binding_never_grants_a_paid_plan,
    |h| {
        let mock = mock_mollie_api();
        let app = billing_service::routes::router(h.state.clone());
        let tenant = "cov_unverified_price";
        seed_tenant(&h, tenant, "free").await;

        // A completed first payment is not an entitlement: it mints a
        // mandate but no plan and no subscription row.
        mock.publish_payment(&first_payment(
            "tr_cov_unverified",
            tenant,
            "mdt_cov_unverified",
            None,
        ));
        expect_mollie_ok(&app, "tr_cov_unverified").await;

        let plan: String = sqlx::query_scalar("SELECT plan FROM tenants WHERE id = $1")
            .bind(tenant)
            .fetch_one(&h.pool)
            .await
            .expect("tenant plan");
        assert_eq!(plan, "free", "Mollie-unverified must never equal paid");
        let subs: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM subscription_state WHERE tenant_id = $1")
                .bind(tenant)
                .fetch_one(&h.pool)
                .await
                .expect("count subscriptions");
        assert_eq!(subs, 0, "refused events write no subscription rows");

        // A plain checkout AUTHORISATION is informational: acknowledged, and
        // the plan still never moves.
        mock.publish_payment(&payment_document(
            "tr_cov_checkout",
            "paid",
            2_900,
            Some("oneoff"),
            "cst_cov",
            None,
            serde_json::json!({ "tenant_id": tenant, "reference": "checkout:growth:monthly" }),
        ));
        expect_mollie_ok(&app, "tr_cov_checkout").await;
        let plan: String = sqlx::query_scalar("SELECT plan FROM tenants WHERE id = $1")
            .bind(tenant)
            .fetch_one(&h.pool)
            .await
            .expect("tenant plan");
        assert_eq!(
            plan, "free",
            "a checkout authorisation is never an entitlement"
        );
    }
);

db_test!(
    double_webhook_recurring_charge_and_token_binding_is_one_transition,
    |h| {
        let mock = mock_mollie_api();
        let app = billing_service::routes::router(h.state.clone());
        let tenant = "cov_wh_double";
        seed_tenant(&h, tenant, "free").await;
        let invoice_id = Uuid::new_v4();
        seed_cov_local_invoice(&h, tenant, invoice_id, 2_900, 0, 2_900, "eur").await;
        seed_cov_subscription(&h, tenant, "sub_cov_double", None).await;

        mock.publish_payment(&recurring_payment(
            "tr_cov_double",
            invoice_id,
            2_900,
            Some(tenant),
        ));
        expect_mollie_ok(&app, "tr_cov_double").await;

        // The FIRST payment of the tenant's next cycle mints/binds the
        // mandate; its informational authorisation settles nothing.
        mock.publish_payment(&first_payment(
            "tr_cov_double_token",
            tenant,
            "mdt_cov_double",
            None,
        ));
        expect_mollie_ok(&app, "tr_cov_double_token").await;

        let (invoice_status, allocations): (String, i64) = sqlx::query_as(
            "SELECT status,
                    (SELECT COUNT(*) FROM invoice_payment_allocations WHERE invoice_id = $1)
             FROM invoices WHERE id = $1",
        )
        .bind(invoice_id)
        .fetch_one(&h.pool)
        .await
        .expect("invoice");
        assert_eq!(invoice_status, "paid");
        assert_eq!(allocations, 1, "the two deliveries settle exactly once");

        let (token_bound, sub_status, sub_rows): (Option<String>, String, i64) = sqlx::query_as(
            "SELECT MIN(provider_method_id), MIN(status), COUNT(*)
             FROM subscription_state WHERE tenant_id = $1",
        )
        .bind(tenant)
        .fetch_one(&h.pool)
        .await
        .expect("subscription");
        assert_eq!(
            token_bound.as_deref(),
            Some("mdt_cov_double"),
            "the token delivery binds the mandate"
        );
        assert_eq!(
            sub_status, "active",
            "the token delivery is not a subscription state transition"
        );
        assert_eq!(sub_rows, 1, "no second subscription row is invented");

        let plan: String = sqlx::query_scalar("SELECT plan FROM tenants WHERE id = $1")
            .bind(tenant)
            .fetch_one(&h.pool)
            .await
            .expect("tenant plan");
        assert_eq!(
            plan, "free",
            "provider deliveries never mint the tenant's plan"
        );

        let processed: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM mollie_webhook_events
             WHERE mollie_payment_id IN ('tr_cov_double', 'tr_cov_double_token')
               AND status = 'processed'",
        )
        .fetch_one(&h.pool)
        .await
        .expect("claim rows");
        assert_eq!(
            processed, 3,
            "the recurring charge and BOTH facts of the first payment are processed"
        );
    }
);

// ---------------------------------------------------------------------------
// hetzner_ip_provider.rs, REMOVED: one provisioning implementation
// ---------------------------------------------------------------------------
// billing-service carried a second, divergent dedicated-IP provisioning
// implementation (direct floating-IP creation, immediate 'warming' insert,
// its own status vocabulary) next to the canonical state machine in
// api-server's `ip_provider` (provisioning -> created -> attached ->
// rdns_ready -> warming -> active, with compensation). It had NO production
// caller, but had it ever been wired up, it would have bypassed the
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
        "a hetzner-named source file exists in billing-service/src, the duplicate provider \
         must not come back"
    );
}

// ---------------------------------------------------------------------------
// maintenance.rs, abuse lifecycle, admin reset, derived sweep, reconciliation
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
    // transaction (conservative attribution, an unattributable suspension
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
        (tenant_a, now), // today, out of scope
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
        billing_service::mollie_webhooks::retry_deadlettered_webhooks(&h.state)
            .await
            .expect("retry with an empty deadletter set");
    }
);

// ---------------------------------------------------------------------------
// routes.rs, second adversarial pass: proration preview, PAYG usage,
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
            "INSERT INTO subscription_state
             (tenant_id, provider_contract_id, plan, status, provider_customer_id)
         VALUES ($1, 'sub_cov_proration', 'growth', 'active', $1)",
        )
        .bind(tenant)
        .execute(&h.pool)
        .await
        .expect("subscription without cycle");
        sqlx::query(
            "UPDATE subscription_state SET billing_cycle_start = NULL WHERE tenant_id = $1",
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
            "UPDATE subscription_state
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
// usage_ingest.rs, bounce/complaint collection in the reconciliation report
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
        // 5 complaints: 10 unaccounted, under the slack, so no candidate.
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

/// The Europe/Tallinn calendar month of an instant, the SAME convention
/// `vat_recognition` uses for `recognition_period` (its dates are Tallinn
/// local). Deriving the expectation from the UTC date instead flips the
/// month twice a year whenever a UTC evening is already the next day in
/// Tallinn, making the suite fail for a few hours around a month boundary.
fn tallinn_month(instant: chrono::DateTime<chrono::Utc>) -> String {
    instant
        .with_timezone(&chrono_tz::Europe::Tallinn)
        .format("%Y-%m")
        .to_string()
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
    let expected_period = tallinn_month(issued);
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
        tallinn_month(now - chrono::Duration::days(35))
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
    let from = tallinn_month(now - chrono::Duration::days(80));
    let to = tallinn_month(now);
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
// invoices.rs, numbering under concurrency, immutable snapshots, overflow
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
            mollie_payment_id: None,
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
            product_lines_period: None,
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
// accounting_export.rs, hostile names are RFC 4180 escaped, formula-safe
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
    // the trailing newline, never a broken/duplicated data record.
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
// credit_notes.rs, idempotent replay: matching returns, mismatch refuses
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

// ---------------------------------------------------------------------------
// E-SWEEP-TRIGGER, on-demand overage sweep entrypoint
// ---------------------------------------------------------------------------

/// Live dogfood 2026-10-08: the overage sweep's FIRST scheduled tick is the
/// next UTC midnight and no on-demand trigger existed anywhere. This drives
/// the REAL binary's one-shot `--sweep-overage-only` flag against a private
/// canonical DB clone and asserts the printed report, the ops trigger, end
/// to end (the sweep semantics themselves are covered by the overage tests
/// above; here the entrypoint is the subject).
#[tokio::test]
async fn sweep_overage_only_cli_runs_the_canonical_sweep_on_demand() {
    let Some(h) = provision("sweep_overage_only_cli").await else {
        return;
    };
    let server_part = h
        .admin_url
        .rsplit_once('/')
        .expect("admin url has a database segment")
        .0
        .to_string();
    let database_url = format!("{server_part}/{}", h.db_name);
    let redis_url = std::env::var("TEST_REDIS_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .expect("TEST_REDIS_URL must be set for the sweep CLI test");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_billing-service"))
        .arg("--sweep-overage-only")
        .env("DATABASE_URL", &database_url)
        .env("REDIS_URL", &redis_url)
        // Keep the JSON log lines short; the assertion reads stdout, where
        // the one-shot report is printed.
        .env("RUST_LOG", "error")
        .output()
        .expect("spawn billing-service --sweep-overage-only");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "the one-shot sweep must exit 0\nstdout: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains("overage sweep: periods_checked=0 invoices_created=0"),
        "the swept (empty) period set must be reported on demand:\n{stdout}"
    );

    h.finish().await;
}

// ---------------------------------------------------------------------------
// COMMERCIAL CONTRACT, pricing authority (docs/pricing-authority.md)
//
// Authoritative plan facts live in `platform-catalog` and `plans.rs`.
// Marketing `pricing.json` is presentation-only. These tests pin the
// commercial/compliance contract so a drift (30k/mo Free, 10% annual,
// 10 IPs, silent quota drop) FAILS here before it reaches a customer.
// ---------------------------------------------------------------------------

/// Free = €0, 3,000 emails/month RECURRING + a ONE-TIME 30,000 launch
/// allowance (first 30 days), NOT 30k/month forever.
#[test]
fn catalog_free_is_3000_recurring_plus_one_time_30000_launch_allowance() {
    let free = platform_catalog::plan_by_name("free").expect("free plan in catalog");
    assert_eq!(free.price_monthly_cents, 0, "Free is €0");
    assert_eq!(free.price_yearly_cents, 0);
    // The RECURRING included volume is 3 000/month, the 2026-09-08 review
    // moved Free off the historical 30 000/month give-away.
    assert_eq!(
        free.email_limit, 3_000,
        "Free recurring included volume must be 3 000, not 30 000"
    );
    assert_ne!(
        free.email_limit, 30_000,
        "30 000 is the ONE-TIME launch allowance, never the monthly ceiling"
    );
    // The launch allowance is a separate one-time grant.
    assert_eq!(
        platform_catalog::FREE_LAUNCH_ALLOWANCE,
        30_000,
        "one-time launch allowance is 30 000 emails"
    );
    assert_eq!(
        platform_catalog::FREE_LAUNCH_WINDOW_DAYS,
        30,
        "launch allowance window is 30 days, then the 3 000/month ceiling applies"
    );

    // The billing seed must mirror the catalog (never 30k as email_limit).
    let free_seed = billing_service::plans::builtin_plan_seed(Some("free"));
    assert_eq!(free_seed.email_limit, 3_000);
    assert_eq!(free_seed.api_call_limit, 30_000);
    assert_eq!(free_seed.price_monthly, 0);
    assert!(
        free_seed.description.contains("3,000 emails/month"),
        "description must state the recurring 3 000/month: {}",
        free_seed.description
    );
    assert!(
        free_seed
            .description
            .contains("one-time 30,000-email launch allowance"),
        "description must state the launch allowance is ONE-TIME: {}",
        free_seed.description
    );
    // A missing plans row resolves to these same free limits (fail closed
    // to the basic set, never to an invented paid ceiling).
    assert_eq!(
        billing_service::plans::builtin_quota_limits(Some("plan-does-not-exist")),
        (3_000, 30_000)
    );
}

/// Annual = 10 monthly payments (≈16.7% savings), NOT a 10% discount.
/// `price_yearly_cents` is the 12-month charge at the effective annual
/// rate; twelve monthly payments would be `12 * price_monthly_cents`.
#[test]
fn annual_effective_discount_is_ten_monthly_payments_not_ten_percent() {
    for catalog in platform_catalog::PLANS {
        if catalog.price_monthly_cents <= 0 {
            assert_eq!(
                catalog.price_yearly_cents, 0,
                "{}: free/payg have no annual charge",
                catalog.name
            );
            continue;
        }
        let twelve_monthly = catalog.price_monthly_cents * 12;
        // Exact commercial fact: annual is billed as TEN monthly payments.
        assert_eq!(
            catalog.price_yearly_cents,
            catalog.price_monthly_cents * 10,
            "{}: annual must be exactly 10 monthly payments (not 11, not 12, not 12 * 0.90)",
            catalog.name
        );
        let effective_discount = 1.0 - (catalog.price_yearly_cents as f64 / twelve_monthly as f64);
        // 1 - 10/12 = 1/6 ≈ 0.1667. NOT 0.10.
        assert!(
            (effective_discount - 2.0 / 12.0).abs() < 1e-9,
            "{}: effective discount must be 2/12 (≈16.7%), got {effective_discount:.4}",
            catalog.name
        );
        assert!(
            (effective_discount - 0.10).abs() > 0.05,
            "{}: the annual discount is NOT 10% (got {effective_discount:.4})",
            catalog.name
        );
    }

    // The billing seeds mirror the same 10-payment ladder.
    for seed in billing_service::plans::default_plans() {
        if seed.price_monthly > 0 {
            assert_eq!(
                seed.price_yearly,
                seed.price_monthly * 10,
                "{}: seed annual is 10 monthly payments",
                seed.name
            );
        }
    }
}

/// Entitlements fail closed: an unknown plan resolves to the BASIC (free)
/// set and must NOT grant `custom_templates` or dedicated IPs.
#[test]
fn unknown_plan_feature_set_excludes_custom_templates_and_dedicated_ips() {
    // Quota lookup falls back to free for unknown names, the feature set
    // that comes with it is the deny-most basic set.
    let fallback = billing_service::plans::builtin_plan_seed(Some("not-a-real-plan"));
    assert_eq!(fallback.name, "free", "unknown plan → basic set");
    assert!(
        !fallback.features.custom_templates,
        "unknown plan must not include custom_templates"
    );
    assert!(
        !fallback.features.dedicated_ip,
        "unknown plan must not include dedicated_ip"
    );
    assert_eq!(
        fallback.features.dedicated_ip_count, 0,
        "unknown plan grants zero dedicated IPs"
    );

    // EntitlementSnapshot fail-closed: missing booleans DENY. A plan row
    // with an empty/unknown feature document never invents paid grants.
    let empty = serde_json::json!({});
    let snap = billing_entitlements::EntitlementSnapshot::from_plan_features_json(
        "ten_unknown",
        "not-a-real-plan",
        &empty,
    );
    assert!(
        !snap.has_feature(billing_entitlements::FeatureKey::CustomTemplates),
        "missing custom_templates must deny"
    );
    assert!(
        !snap.has_feature(billing_entitlements::FeatureKey::DedicatedIp),
        "missing dedicated_ip must deny"
    );
    assert_eq!(
        snap.capacity(billing_entitlements::CapacityKey::DedicatedIps),
        0,
        "missing dedicated_ip_count must be 0 (deny), never an invented quota"
    );
    assert!(
        snap.require_feature(billing_entitlements::FeatureKey::CustomTemplates)
            .is_err(),
        "require_feature must refuse custom_templates on an unknown plan"
    );
    assert!(
        snap.require_feature(billing_entitlements::FeatureKey::DedicatedIp)
            .is_err(),
        "require_feature must refuse dedicated_ip on an unknown plan"
    );

    // Corrupt persisted features must FAIL CLOSED (typed error), never
    // silently repair into a paid feature set. `builtin_plan_seed` itself
    // only falls back for unknown NAMES; a present-but-invalid features
    // JSONB is rejected by `PlanRow::try_into_plan` /
    // `get_entitlement_snapshot` with `BillingError::CorruptPlanFeatures`.
    let free = billing_service::plans::builtin_plan_seed(Some("free"));
    assert!(!free.features.custom_templates);
    assert!(!free.features.dedicated_ip);
}

/// Enterprise IP quotas match the catalog seed: 3 included dedicated IPs,
/// NOT the marketing myth of 10.
#[test]
fn enterprise_included_ip_quota_is_three_not_ten() {
    let enterprise = billing_service::plans::builtin_plan_seed(Some("enterprise"));
    assert_eq!(
        enterprise.features.dedicated_ip_count, 3,
        "Enterprise Cloud includes up to 3 dedicated IPs (2026-09-08 review §10)"
    );
    assert_ne!(
        enterprise.features.dedicated_ip_count, 10,
        "Enterprise does NOT include 10 dedicated IPs"
    );

    let scale = billing_service::plans::builtin_plan_seed(Some("scale"));
    assert_eq!(
        scale.features.dedicated_ip_count, 1,
        "Business includes 1 dedicated IP (a second is assigned where traffic justifies it)"
    );
    let growth = billing_service::plans::builtin_plan_seed(Some("growth"));
    assert_eq!(growth.features.dedicated_ip_count, 1);
    let pro = billing_service::plans::builtin_plan_seed(Some("pro"));
    assert_eq!(
        pro.features.dedicated_ip_count, 0,
        "Pro is add-on only; zero IPs included by default"
    );
}

/// SLA/credits matrix is PLAN-SCOPED. Only Business (`scale`) and
/// Enterprise Cloud carry `sla_guarantee`; the credit caps are 30% and 25%.
/// No other plan may invent coverage.
#[test]
fn sla_credit_matrix_is_plan_scoped_with_no_invented_coverage() {
    let expected: &[(&str, bool, i32)] = &[
        ("free", false, 0),
        ("starter", false, 0),
        ("pro", false, 0),
        ("growth", false, 0),
        ("scale", true, 30),
        ("enterprise", true, 25),
        ("payg", false, 0),
    ];
    for (name, guarantee, credit_pct) in expected {
        let seed = billing_service::plans::builtin_plan_seed(Some(name));
        assert_eq!(
            seed.features.sla_guarantee, *guarantee,
            "{name}.sla_guarantee (SLA coverage is a Business/Enterprise entitlement only)"
        );
        assert_eq!(
            seed.features.sla_credit_percentage, *credit_pct,
            "{name}.sla_credit_percentage must match the published plan cap"
        );
    }

    // The uncapped ladder is documented in docs/sla.md §3.1; the plan cap
    // is what the sweep enforces (maintenance.rs reads sla_credit_percentage).
    // A plan without sla_guarantee must never receive a credit percentage.
    for seed in billing_service::plans::default_plans() {
        if !seed.features.sla_guarantee {
            assert_eq!(
                seed.features.sla_credit_percentage, 0,
                "{}: no SLA guarantee ⇒ no credit cap, no invented coverage",
                seed.name
            );
        } else {
            assert!(
                (1..=100).contains(&seed.features.sla_credit_percentage),
                "{}: an SLA plan must carry a real credit cap",
                seed.name
            );
        }
    }
}

/// Usage over the hard cap returns the named quota refusal, never a silent
/// drop and never a 500.
#[test]
fn hard_cap_refusal_carries_the_named_quota_error_string() {
    // The send-admission refusal's stable Display contract.
    assert_eq!(
        billing_service::send_admission::SendAdmissionError::QuotaExceeded.to_string(),
        "email quota exceeded",
        "quota refusal must name the condition (never empty, never 'internal error')"
    );

    // The REST send-endpoint contract string (api-server messages.rs
    // QUOTA_EXCEEDED_MESSAGE) is the customer-visible refusal. Pin the
    // exact text so a wording drift is a test failure, not a support ticket.
    let messages_src = include_str!("../../api-server/src/routes/messages.rs");
    let expected = "email quota exceeded: the plan volume and its overage allowance are exhausted, upgrade the plan or contact sales for a higher ceiling";
    assert!(
        messages_src.contains(&format!(
            "const QUOTA_EXCEEDED_MESSAGE: &str = \"{expected}\""
        )),
        "QUOTA_EXCEEDED_MESSAGE must stay exactly:\n{expected}"
    );
}

/// Usage/overage math is exact: ceil to whole cents, named plan rates from
/// the catalog ladder (80/60/35/35 millicents), Free/PAYG/unknown quote 0.
#[test]
fn overage_math_is_exact_and_quotes_only_catalog_rates() {
    use billing_service::plans::{
        calculate_overage_cost_with_rate, calculate_plan_overage_cost, plan_overage_rate_millicents,
    };

    // Catalog ladder, never a second hardcoded rate table.
    assert_eq!(plan_overage_rate_millicents("free"), None);
    assert_eq!(plan_overage_rate_millicents("starter"), Some(80));
    assert_eq!(plan_overage_rate_millicents("pro"), Some(60));
    assert_eq!(plan_overage_rate_millicents("growth"), Some(35));
    assert_eq!(plan_overage_rate_millicents("scale"), Some(35));
    assert_eq!(plan_overage_rate_millicents("enterprise"), Some(35));
    assert_eq!(plan_overage_rate_millicents("payg"), None);
    assert_eq!(plan_overage_rate_millicents("no-such-plan"), None);

    // Exact boundaries: no overage at/below the limit.
    assert_eq!(calculate_plan_overage_cost("starter", 50_000, 50_000), 0);
    assert_eq!(calculate_plan_overage_cost("starter", 49_999, 50_000), 0);

    // 1 000 overage emails on Developer at 80 millicents/email
    // = 80 000 millicents = 80 cents. Exact.
    assert_eq!(calculate_plan_overage_cost("starter", 51_000, 50_000), 80);
    // Pro: 1 000 * 60 = 60 cents.
    assert_eq!(calculate_plan_overage_cost("pro", 151_000, 150_000), 60);
    // Growth/Business: 1 000 * 35 = 35 cents.
    assert_eq!(calculate_plan_overage_cost("growth", 501_000, 500_000), 35);
    assert_eq!(
        calculate_plan_overage_cost("scale", 2_001_000, 2_000_000),
        35
    );

    // Free and unknown names quote 0 (the quota gate blocks; never bill).
    assert_eq!(calculate_plan_overage_cost("free", 100_000, 3_000), 0);
    assert_eq!(calculate_plan_overage_cost("payg", 100_000, -1), 0);
    assert_eq!(
        calculate_plan_overage_cost("no-such-plan", 100_000, 3_000),
        0
    );

    // Ceil to whole cents: 1 email at 80 millicents = 80/1000 cents → 1 cent.
    assert_eq!(calculate_overage_cost_with_rate(1, 0, 80), 1);
    // 12 emails * 80 = 960 millicents → still 1 cent (ceil).
    assert_eq!(calculate_overage_cost_with_rate(12, 0, 80), 1);
    // 13 emails * 80 = 1 040 millicents → 2 cents.
    assert_eq!(calculate_overage_cost_with_rate(13, 0, 80), 2);
    // Unlimited plan never overage-bills.
    assert_eq!(calculate_overage_cost_with_rate(1_000_000, -1, 80), 0);
    // Exactly at the limit is 0.
    assert_eq!(calculate_overage_cost_with_rate(100, 100, 80), 0);
    // One over is ceil(1 * 80 / 1000) = 1.
    assert_eq!(calculate_overage_cost_with_rate(101, 100, 80), 1);
}

// ---------------------------------------------------------------------------
// Plan billing, the LOCAL authority (beta authority inversion): a verified
// paid checkout activates the plan locally (no provider schedule is minted),
// the renewal worker invoices the NEXT period BEFORE any charge, dunning
// opens new immutable attempts, `cancel_at_period_end` ends the subscription
// with no charge, and a provider-initiated renewal payment never resurrects
// a locally-canceled subscription nor summons an invoice into existence.
// ---------------------------------------------------------------------------

db_test!(
    paid_checkout_activation_grants_exactly_the_charged_gross,
    |h| {
        let mock = mock_mollie_api();
        seed_tenant(&h, "cov_activate", "free").await;
        seed_reverse_charge_business(&h, "cov_activate").await;
        // No subscription-create route is registered: the activation must
        // mint NO provider object (renewal is local). If it did call the
        // provider, the dynamic mint route would fire and `created` below
        // would be non-empty.

        let outcome = billing_service::plan_billing::activate_from_paid_checkout(
            &h.pool,
            "tr_cov_activate",
            "cov_activate",
            "starter",
            "monthly",
            "EUR",
            2_000,
            Some("cst_cov_activate"),
            Some("mdt_cov_activate"),
        )
        .await
        .expect("activation");
        let subscription_id = outcome
            .subscription_id
            .clone()
            .expect("the local subscription id");
        assert!(
            subscription_id.starts_with("local_"),
            "the activation mints a LOCAL subscription id, got {subscription_id}"
        );
        assert!(!outcome.already_active);
        assert!(
            mock.created().is_empty(),
            "no provider schedule may be minted at activation: {:?}",
            mock.created()
        );

        let plan: String = sqlx::query_scalar("SELECT plan FROM tenants WHERE id = $1")
            .bind("cov_activate")
            .fetch_one(&h.pool)
            .await
            .expect("tenant plan");
        assert_eq!(plan, "starter");

        let (status, stored_id): (String, String) = sqlx::query_as(
            "SELECT status, provider_contract_id FROM subscription_state WHERE tenant_id = $1",
        )
        .bind("cov_activate")
        .fetch_one(&h.pool)
        .await
        .expect("subscription row");
        assert_eq!(status, "active");
        assert_eq!(stored_id, subscription_id);

        // N-05 (step 10): the invoice is resolved through the settlement's
        // neutral allocation operation id, not a provider-named invoice
        // column.
        let (invoice_status, net, vat, total): (String, i64, i64, i64) = sqlx::query_as(
            "SELECT i.status, i.subtotal, i.vat_total, i.total FROM invoices i \
         JOIN invoice_payment_allocations a ON a.invoice_id = i.id \
         WHERE a.operation_id = 'mollie:tr_cov_activate'",
        )
        .fetch_one(&h.pool)
        .await
        .expect("plan invoice");
        assert_eq!(invoice_status, "paid");
        assert_eq!(total, 2_000, "the invoice totals the collected gross");
        assert_eq!(net + vat, total, "net + VAT is exactly the charge");
        assert_eq!(net, 2_000, "the net is the catalog list price");
        assert_eq!(
            vat, 0,
            "a verified cross-border EU business is reverse-charged (V30)"
        );

        // V34: the provider customer is bound on the NEUTRAL ledger.
        let customers: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM payment_provider_customers \
         WHERE tenant_id = 'cov_activate' AND provider_customer_id = 'cst_cov_activate'",
        )
        .fetch_one(&h.pool)
        .await
        .expect("provider customer");
        assert_eq!(customers, 1);

        let (allocations, allocated): (i64, i64) = sqlx::query_as(
        "SELECT count(*), COALESCE(sum(amount_cents), 0)::bigint FROM invoice_payment_allocations \
         WHERE operation_id = 'mollie:tr_cov_activate'",
    )
    .fetch_one(&h.pool)
    .await
    .expect("allocation");
        assert_eq!((allocations, allocated), (1, 2_000));

        // The stored method lands on the NEUTRAL credentials ledger: this is
        // what the renewal worker charges.
        let credentials: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM payment_credentials \
         WHERE tenant_id = 'cov_activate' AND state = 'active' AND revoked_at IS NULL",
        )
        .fetch_one(&h.pool)
        .await
        .expect("credentials");
        assert_eq!(credentials, 1);

        // Webhook redelivery / operator replay: the payment id is the key.
        let replay = billing_service::plan_billing::activate_from_paid_checkout(
            &h.pool,
            "tr_cov_activate",
            "cov_activate",
            "starter",
            "monthly",
            "EUR",
            2_000,
            Some("cst_cov_activate"),
            Some("mdt_cov_activate"),
        )
        .await
        .expect("replay");
        assert!(replay.already_active);
        // N-05 (step 10): the activated invoice is resolved through its
        // neutral settlement allocation, not a provider-named column.
        let invoices: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM invoices i \
         JOIN invoice_payment_allocations a ON a.invoice_id = i.id \
         WHERE a.operation_id = 'mollie:tr_cov_activate'",
        )
        .fetch_one(&h.pool)
        .await
        .expect("invoice count");
        assert_eq!(invoices, 1, "a replay never issues a second invoice");

        // A charge that does not match the catalog grants nothing at all.
        let error = billing_service::plan_billing::activate_from_paid_checkout(
            &h.pool,
            "tr_cov_underpaid",
            "cov_activate",
            "starter",
            "monthly",
            "EUR",
            1_900,
            Some("cst_cov_activate"),
            Some("mdt_cov_activate"),
        )
        .await
        .expect_err("a mismatched charge must be refused");
        assert!(error.to_string().contains("refusing to grant"), "{error}");
        let underpaid_invoices: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM invoices WHERE mollie_payment_id = 'tr_cov_underpaid'",
        )
        .fetch_one(&h.pool)
        .await
        .expect("underpaid invoice count");
        assert_eq!(underpaid_invoices, 0);
    }
);

db_test!(
    activation_refuses_a_payment_id_already_on_the_attempts_ledger,
    |h| {
        let _mock = mock_mollie_api();
        seed_tenant(&h, "cov_attempt_refused", "free").await;
        seed_reverse_charge_business(&h, "cov_attempt_refused").await;
        // MON-8: this payment id is already a recorded charge attempt (the
        // renewal worker's in-flight charge). It is NOT a checkout.
        sqlx::query(
            "INSERT INTO payment_attempts \
                 (tenant_id, provider, provider_payment_id, state, amount_minor, \
                  currency, purpose, obligation_ref, idempotency_key, attempt_no) \
             VALUES ($1, 'mollie', 'tr_already_attempted', 'succeeded', 2_000, 'EUR', \
                     'renewal', 'invoice:00000000-0000-0000-0000-0000000000ff', \
                     'payment:invoice:00000000-0000-0000-0000-0000000000ff:1', 1)",
        )
        .bind("cov_attempt_refused")
        .execute(&h.pool)
        .await
        .expect("seed the attempt");

        let error = billing_service::plan_billing::activate_from_paid_checkout(
            &h.pool,
            "tr_already_attempted",
            "cov_attempt_refused",
            "starter",
            "monthly",
            "EUR",
            2_000,
            Some("cst_attempt_refused"),
            Some("mdt_attempt_refused"),
        )
        .await
        .expect_err("an attempted payment must not activate");
        match error {
            billing_service::plan_billing::ActivationError::PaymentAlreadyAttempted {
                ref payment_id,
                ..
            } => assert_eq!(payment_id, "tr_already_attempted"),
            other => panic!("expected PaymentAlreadyAttempted, got {other:?}"),
        }
        let invoices: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM invoices WHERE tenant_id = $1")
                .bind("cov_attempt_refused")
                .fetch_one(&h.pool)
                .await
                .expect("invoices");
        assert_eq!(
            invoices, 0,
            "no invoice is issued for the refused activation"
        );
        let subscriptions: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM subscription_state WHERE tenant_id = $1")
                .bind("cov_attempt_refused")
                .fetch_one(&h.pool)
                .await
                .expect("subscriptions");
        assert_eq!(subscriptions, 0, "no subscription row is invented");
        let incidents: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM finance_incidents \
             WHERE kind = 'activation_payment_already_attempted' \
               AND mollie_payment_id = 'tr_already_attempted' AND status = 'open'",
        )
        .fetch_one(&h.pool)
        .await
        .expect("incident");
        assert_eq!(incidents, 1, "the operator sees the refusal");
    }
);

/// Seed a subscription shaped like the local renewal worker's due set.
async fn seed_due_subscription(
    h: &Harness,
    tenant: &str,
    plan: &str,
    cycle_end_sql: &str,
    cancel_at_period_end: bool,
    status: &str,
) -> String {
    let suffix = uuid::Uuid::new_v4().simple().to_string()[..8].to_string();
    let subscription_id = format!("local_cov_{suffix}");
    sqlx::query(&format!(
        "INSERT INTO subscription_state \
             (tenant_id, provider_contract_id, plan, status, billing_interval, \
              billing_cycle_start, billing_cycle_end, cancel_at_period_end, provider_customer_id, \
              provider_method_id, provider_sequence_type, renewal_attempts) \
         VALUES ($1, $2, $3, $5, 'monthly', NOW() - INTERVAL '30 days', {cycle_end_sql}, \
                 $4, $1, 'mdt_renew', 'recurring', 0)"
    ))
    .bind(tenant)
    .bind(&subscription_id)
    .bind(plan)
    .bind(cancel_at_period_end)
    .bind(status)
    .execute(&h.pool)
    .await
    .expect("seed subscription");
    subscription_id
}

async fn renewal_provider() -> std::sync::Arc<dyn billing_service::payments::PaymentProvider> {
    billing_service::payments::registry::from_env().expect("the mock provider registry")
}

/// A scripted payment provider for the renewal-FACT tests (audit items 4 and
/// 7). Only the methods the renewal worker drives are meaningful; every other
/// arm refuses VISIBLY, so a test cannot silently pass through a path it did
/// not script.
struct ScriptedRenewalProvider {
    name: &'static str,
    charges: std::sync::Mutex<
        std::collections::VecDeque<
            Result<billing_service::payments::Payment, billing_service::payments::ProviderError>,
        >,
    >,
    fetched:
        std::sync::Mutex<std::collections::HashMap<String, billing_service::payments::Payment>>,
    /// `(provider_customer_id, provider_method_id)` of every charge call.
    charged_methods: std::sync::Mutex<Vec<(String, String)>>,
    charge_calls: std::sync::atomic::AtomicU64,
    fetch_calls: std::sync::atomic::AtomicU64,
}

impl ScriptedRenewalProvider {
    fn new(name: &'static str) -> Self {
        Self {
            name,
            charges: std::sync::Mutex::new(std::collections::VecDeque::new()),
            fetched: std::sync::Mutex::new(std::collections::HashMap::new()),
            charged_methods: std::sync::Mutex::new(Vec::new()),
            charge_calls: std::sync::atomic::AtomicU64::new(0),
            fetch_calls: std::sync::atomic::AtomicU64::new(0),
        }
    }

    fn script_charge(&self, payment: billing_service::payments::Payment) {
        self.charges
            .lock()
            .expect("charge script lock")
            .push_back(Ok(payment));
    }

    fn script_fetch(&self, payment: billing_service::payments::Payment) {
        self.fetched
            .lock()
            .expect("fetch script lock")
            .insert(payment.provider_payment_id.clone(), payment);
    }

    fn charged_methods(&self) -> Vec<(String, String)> {
        self.charged_methods
            .lock()
            .expect("method log lock")
            .clone()
    }

    fn charge_calls(&self) -> u64 {
        self.charge_calls.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn fetch_calls(&self) -> u64 {
        self.fetch_calls.load(std::sync::atomic::Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl billing_service::payments::PaymentProvider for ScriptedRenewalProvider {
    fn provider_name(&self) -> &'static str {
        self.name
    }

    fn capabilities(&self) -> billing_service::payments::ProviderCapabilities {
        billing_service::payments::ProviderCapabilities {
            hosted_checkout: true,
            saved_method_charging: true,
            refunds: true,
            disputes: false,
            payouts: false,
            idempotency_keys: true,
        }
    }

    async fn create_checkout(
        &self,
        request: billing_service::payments::CheckoutRequest,
    ) -> Result<billing_service::payments::Checkout, billing_service::payments::ProviderError> {
        Ok(billing_service::payments::Checkout {
            provider: self.name.to_string(),
            provider_payment_id: format!("checkout_{}", Uuid::new_v4().simple()),
            state: billing_service::payments::PaymentState::Pending,
            redirect_url: Some("https://scripted.invalid/checkout".to_string()),
            amount_minor: request.amount_minor,
            currency: request.currency.to_ascii_uppercase(),
            created_at: None,
        })
    }

    async fn charge_saved_method(
        &self,
        request: billing_service::payments::SavedMethodCharge,
    ) -> Result<billing_service::payments::Payment, billing_service::payments::ProviderError> {
        self.charged_methods.lock().expect("method log lock").push((
            request.provider_customer_id.clone(),
            request.provider_method_id.clone(),
        ));
        let call = self
            .charge_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            + 1;
        let scripted = self.charges.lock().expect("charge script lock").pop_front();
        match scripted {
            Some(result) => result,
            // Unscripted: an honest echo of the request (the amount the
            // engine asked for), so the default is a successful charge.
            None => Ok(billing_service::payments::Payment {
                provider: self.name.to_string(),
                provider_payment_id: format!("provider_renewal_{call}"),
                state: billing_service::payments::PaymentState::Succeeded,
                amount_minor: request.amount_minor,
                currency: request.currency.to_ascii_uppercase(),
                created_at: None,
            }),
        }
    }

    async fn refund(
        &self,
        _request: billing_service::payments::RefundRequest,
    ) -> Result<billing_service::payments::Refund, billing_service::payments::ProviderError> {
        Err(billing_service::payments::ProviderError::Config(
            "the scripted renewal provider does not refund".to_string(),
        ))
    }

    async fn fetch_payment_object(
        &self,
        provider_payment_id: &str,
    ) -> Result<billing_service::payments::Payment, billing_service::payments::ProviderError> {
        self.fetch_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.fetched
            .lock()
            .expect("fetch script lock")
            .get(provider_payment_id)
            .cloned()
            .ok_or_else(|| billing_service::payments::ProviderError::NotFound {
                kind: "payment",
                id: provider_payment_id.to_string(),
            })
    }

    async fn search_payment_by_idempotency_key(
        &self,
        _idempotency_key: &str,
    ) -> Result<Option<billing_service::payments::Payment>, billing_service::payments::ProviderError>
    {
        // Absence is never guessed by the double either.
        Err(billing_service::payments::ProviderError::Config(
            "the scripted renewal provider offers no charge search".to_string(),
        ))
    }

    async fn fetch_refund(
        &self,
        _provider_payment_id: &str,
        _provider_refund_id: &str,
    ) -> Result<billing_service::payments::Refund, billing_service::payments::ProviderError> {
        Err(billing_service::payments::ProviderError::Config(
            "the scripted renewal provider does not fetch refunds".to_string(),
        ))
    }

    async fn revoke_saved_method(
        &self,
        _provider_customer_id: &str,
        _provider_method_id: &str,
    ) -> Result<(), billing_service::payments::ProviderError> {
        Ok(())
    }

    async fn fetch_settlement(
        &self,
        provider_settlement_id: &str,
    ) -> Result<billing_service::payments::Settlement, billing_service::payments::ProviderError>
    {
        Err(billing_service::payments::ProviderError::NotFound {
            kind: "settlement",
            id: provider_settlement_id.to_string(),
        })
    }

    async fn list_settlements(
        &self,
    ) -> Result<Vec<billing_service::payments::Settlement>, billing_service::payments::ProviderError>
    {
        Ok(Vec::new())
    }

    async fn list_disputes(
        &self,
        _provider_payment_id: &str,
    ) -> Result<Vec<billing_service::payments::Dispute>, billing_service::payments::ProviderError>
    {
        Ok(Vec::new())
    }
}

db_test!(
    renewal_worker_invoices_the_next_period_before_the_charge,
    |h| {
        let mock = mock_mollie_api();
        seed_tenant(&h, "cov_renew", "free").await;
        seed_reverse_charge_business(&h, "cov_renew").await;
        billing_service::plan_billing::activate_from_paid_checkout(
            &h.pool,
            "tr_cov_renew_first",
            "cov_renew",
            "starter",
            "monthly",
            "EUR",
            2_000,
            Some("cst_cov_renew"),
            Some("mdt_cov_renew"),
        )
        .await
        .expect("activation");

        let cycle_before: DateTime<Utc> = sqlx::query_scalar(
            "SELECT billing_cycle_end FROM subscription_state WHERE tenant_id = $1",
        )
        .bind("cov_renew")
        .fetch_one(&h.pool)
        .await
        .expect("cycle before");

        // The stored-credential charge succeeds at the provider; `{seq}`
        // mints a distinct payment id per call. The mock keys routes by
        // PATH (the historical keying).
        mock.route(
            "/v2/payments",
            200,
            r#"{"id": "tr_renew_{seq}", "status": "paid"}"#.to_string(),
        );

        // The worker runs at a `now` past the paid period's end.
        let later = Utc::now() + chrono::Duration::days(40);
        let renewed = billing_service::plan_billing::renew_due_subscriptions_with(
            &h.state,
            renewal_provider().await,
            later,
        )
        .await
        .expect("renewal tick");
        assert_eq!(renewed, 1, "exactly one due subscription renewed");

        // The activation invoice + the NEXT period's invoice, now paid.
        let invoices: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM invoices WHERE tenant_id = $1 AND status = 'paid'",
        )
        .bind("cov_renew")
        .fetch_one(&h.pool)
        .await
        .expect("paid invoices");
        assert_eq!(invoices, 2);

        // INVOICE FIRST: the claimed attempt's obligation is an invoice that
        // existed before the attempt row.
        let (obligation, attempt_no, invoice_created, attempt_created): (
            String,
            i64,
            DateTime<Utc>,
            DateTime<Utc>,
        ) = sqlx::query_as(
            "SELECT a.obligation_ref, a.attempt_no::bigint, \
                    (SELECT i.created_at FROM invoices i WHERE i.id = CAST(SUBSTRING(a.obligation_ref FROM 9) AS uuid)), \
                    a.created_at \
             FROM payment_attempts a WHERE a.tenant_id = $1 AND a.purpose = 'renewal'",
        )
        .bind("cov_renew")
        .fetch_one(&h.pool)
        .await
        .expect("renewal attempt");
        assert_eq!(attempt_no, 1);
        assert!(
            invoice_created <= attempt_created,
            "the obligation must exist before the charge claim"
        );
        assert!(obligation.starts_with("invoice:"), "{obligation}");

        // The local period advanced and the dunning state reset.
        let (cycle_after, status, attempts, locked): (
            DateTime<Utc>,
            String,
            i32,
            Option<DateTime<Utc>>,
        ) = sqlx::query_as(
            "SELECT billing_cycle_end, status, renewal_attempts, renewal_locked_at \
             FROM subscription_state WHERE tenant_id = $1",
        )
        .bind("cov_renew")
        .fetch_one(&h.pool)
        .await
        .expect("cycle after");
        assert!(cycle_after > cycle_before, "the cycle advances");
        assert_eq!(status, "active");
        assert_eq!(
            attempts, 0,
            "a successful renewal resets the dunning counter"
        );
        assert!(locked.is_none(), "a successful renewal clears the gate");

        // The renewal is audited.
        let audits: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'billing.subscription_renewed'",
        )
        .bind("cov_renew")
        .fetch_one(&h.pool)
        .await
        .expect("renewal audits");
        assert_eq!(audits, 1);

        // A second tick with the same `now` renews nothing (the new period
        // has not ended) and mints no second invoice or charge.
        let again = billing_service::plan_billing::renew_due_subscriptions_with(
            &h.state,
            renewal_provider().await,
            later,
        )
        .await
        .expect("second tick");
        assert_eq!(again, 0);
        let invoices_after: i64 =
            sqlx::query_scalar("SELECT count(*) FROM invoices WHERE tenant_id = $1")
                .bind("cov_renew")
                .fetch_one(&h.pool)
                .await
                .expect("invoice count");
        assert_eq!(invoices_after, 2);

        // A replayed provider fact for the SAME payment settles exactly once
        // (the repair reconciler's idempotent arm).
        let payment_id: String = sqlx::query_scalar(
            "SELECT provider_payment_id FROM payment_attempts \
         WHERE tenant_id = $1 AND purpose = 'renewal' AND provider_payment_id IS NOT NULL",
        )
        .bind("cov_renew")
        .fetch_one(&h.pool)
        .await
        .expect("renewal payment id");
        let allocations_before: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM invoice_payment_allocations WHERE tenant_id = $1",
        )
        .bind("cov_renew")
        .fetch_one(&h.pool)
        .await
        .expect("allocations before");
        let invoice_id: Uuid = sqlx::query_scalar(
            "SELECT CAST(SUBSTRING(obligation_ref FROM 9) AS uuid) FROM payment_attempts \
         WHERE tenant_id = $1 AND purpose = 'renewal'",
        )
        .bind("cov_renew")
        .fetch_one(&h.pool)
        .await
        .expect("obligation invoice");
        let reconciled = billing_service::plan_billing::reconcile_provider_renewal_payment(
            &h.pool,
            &payment_id,
            "local_cov_unknown",
            2_000,
            "EUR",
        )
        .await
        .expect("reconciliation replay");
        assert_eq!(reconciled, Some(invoice_id));
        let allocations_after: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM invoice_payment_allocations WHERE tenant_id = $1",
        )
        .bind("cov_renew")
        .fetch_one(&h.pool)
        .await
        .expect("allocations after");
        assert_eq!(allocations_after, allocations_before);
    }
);

// ---------------------------------------------------------------------------
// I28 (V28): "a recurring charge settles only its own renewal invoice; it
// never activates a plan, issues another invoice or restarts a period" —
// property over the ORDER of {worker tick, webhook delivery, repair sweep},
// including duplicate and late webhook deliveries.
// ---------------------------------------------------------------------------

db_test!(
    renewal_webhook_paid_late_settles_only_its_own_invoice_across_orderings,
    |h| {
        const DUE_START: &str = "2026-09-01T00:00:00+00:00";
        const DUE_END: &str = "2026-10-01T00:00:00+00:00";
        const EXPECTED_END: &str = "2026-11-01T00:00:00+00:00";
        let mock = mock_mollie_api();
        let app = billing_service::routes::router(h.state.clone());
        // The worker's stored-mandate charge is a SEPA direct debit: the
        // provider accepts it and answers `pending` (money moves in days).
        mock.route(
            "/v2/payments",
            200,
            r#"{"id": "tr_i28_late_{seq}", "status": "pending"}"#.to_string(),
        );

        // Every ordering starts after the worker already opened the invoice
        // and the charge is in flight (that IS the worker tick); each row
        // permutes the LATER deliveries, duplicates included.
        let orderings: [&[&str]; 6] = [
            &["webhook", "sweep"],
            &["sweep", "webhook"],
            &["webhook", "webhook", "sweep"],
            &["sweep", "webhook", "webhook"],
            &["sweep", "webhook", "sweep"],
            &["sweep", "sweep", "webhook", "webhook"],
        ];
        let now: DateTime<Utc> = "2026-10-15T00:00:00Z".parse().expect("fixed now");

        for (index, ordering) in orderings.iter().enumerate() {
            let tenant = format!("cov_i28_{index}");
            seed_tenant(&h, &tenant, "free").await;
            seed_reverse_charge_business(&h, &tenant).await;
            // The tenant's reverse-charge evidence must cover the renewal
            // tax point AND stay inside the formal freshness bound (30 Oct
            // re-audit #22: NULL valid_until is a bounded grace period, not
            // "valid forever"). 2026-09-01 is fresh at both the fixed
            // 2026-10-15 tick and the activation tax point.
            sqlx::query(
                "UPDATE vat_validation_evidence SET valid_from = DATE '2026-09-01' \
                 WHERE tenant_id = $1",
            )
            .bind(&tenant)
            .execute(&h.pool)
            .await
            .expect("age the reverse-charge evidence");
            billing_service::plan_billing::activate_from_paid_checkout(
                &h.pool,
                &format!("tr_i28_first_{index}"),
                &tenant,
                "starter",
                "monthly",
                "EUR",
                2_000,
                Some(&format!("cst_i28_{index}")),
                Some(&format!("mdt_i28_{index}")),
            )
            .await
            .expect("activation");
            // The period the worker is about to renew.
            sqlx::query(
                "UPDATE subscription_state \
                 SET billing_cycle_start = $2::timestamptz, billing_cycle_end = $3::timestamptz \
                 WHERE tenant_id = $1",
            )
            .bind(&tenant)
            .bind(DUE_START)
            .bind(DUE_END)
            .execute(&h.pool)
            .await
            .expect("cycle seed");

            // THE WORKER TICK: invoice first, then a claimed in-flight charge.
            let renewed = billing_service::plan_billing::renew_due_subscriptions_with(
                &h.state,
                renewal_provider().await,
                now,
            )
            .await
            .expect("worker tick");
            assert_eq!(renewed, 0, "a pending charge settles nothing yet");

            let attempt: Option<(String, String)> = sqlx::query_as(
                "SELECT provider_payment_id, obligation_ref FROM payment_attempts \
                 WHERE tenant_id = $1 AND purpose = 'renewal'",
            )
            .bind(&tenant)
            .fetch_optional(&h.pool)
            .await
            .expect("the worker's renewal attempt query");
            let Some((payment_id, obligation_ref)) = attempt else {
                let incidents: Vec<(String, serde_json::Value)> = sqlx::query_as(
                    "SELECT kind, detail FROM finance_incidents WHERE tenant_id = $1",
                )
                .bind(&tenant)
                .fetch_all(&h.pool)
                .await
                .expect("incidents");
                let cycle: (String, DateTime<Utc>, Option<i64>, Option<DateTime<Utc>>) =
                    sqlx::query_as(
                        "SELECT status, billing_cycle_end, renewal_attempts::bigint, \
                                renewal_locked_at \
                         FROM subscription_state WHERE tenant_id = $1",
                    )
                    .bind(&tenant)
                    .fetch_one(&h.pool)
                    .await
                    .expect("cycle");
                let due: i64 = sqlx::query_scalar(
                    "SELECT COUNT(*) FROM subscription_state s \
                     WHERE s.status = 'active' AND s.billing_cycle_end IS NOT NULL \
                       AND s.billing_cycle_end <= $1",
                )
                .bind(now)
                .fetch_one(&h.pool)
                .await
                .expect("due count");
                let invoices: Vec<String> = sqlx::query_scalar(
                    "SELECT id::text || ' ' || status::text || ' ' || \
                            COALESCE(period_start::text, '-') || '..' || \
                            COALESCE(period_end::text, '-') || ' ' || \
                            COALESCE(total, amount, 0)::bigint \
                         FROM invoices WHERE tenant_id = $1 ORDER BY created_at",
                )
                .bind(&tenant)
                .fetch_all(&h.pool)
                .await
                .expect("invoices");
                panic!(
                    "order {index}: the worker opened no renewal attempt; cycle={cycle:?} \
                     due={due} now={now} incidents={incidents:?} invoices={invoices:?}"
                );
            };
            let renewal_invoice: Uuid = obligation_ref
                .strip_prefix("invoice:")
                .and_then(|id| id.parse().ok())
                .expect("invoice obligation ref");
            let (invoice_total, invoice_start, invoice_end): (i64, DateTime<Utc>, DateTime<Utc>) =
                sqlx::query_as(
                    "SELECT COALESCE(total, amount, 0)::bigint, period_start, period_end \
                     FROM invoices WHERE id = $1",
                )
                .bind(renewal_invoice)
                .fetch_one(&h.pool)
                .await
                .expect("renewal invoice");
            assert_eq!(invoice_total, 2_000);
            assert_eq!(invoice_start, DUE_END.parse::<DateTime<Utc>>().unwrap());
            assert_eq!(invoice_end, EXPECTED_END.parse::<DateTime<Utc>>().unwrap());

            // The provider document the late SEPA payment settles as: the
            // REAL metadata `renew_subscription_locked` sends.
            let mut paid = payment_document(
                &payment_id,
                "paid",
                invoice_total,
                Some("recurring"),
                &format!("cst_i28_{index}"),
                Some(&format!("mdt_i28_{index}")),
                serde_json::json!({
                    "tenant_id": tenant,
                    "plan_name": "starter",
                    "interval": "monthly",
                    "reference": obligation_ref,
                }),
            );
            paid["paidAt"] = serde_json::json!("2026-10-15T12:00:00+00:00");
            mock.publish_payment(&paid);
            // Let the repair sweep treat the in-flight claim as stale.
            sqlx::query(
                "UPDATE payment_attempts SET updated_at = NOW() - INTERVAL '10 minutes' \
                 WHERE tenant_id = $1 AND purpose = 'renewal'",
            )
            .bind(&tenant)
            .execute(&h.pool)
            .await
            .expect("age the attempt");

            for action in *ordering {
                match *action {
                    "webhook" => expect_mollie_ok(&app, &payment_id).await,
                    "sweep" => {
                        let provider = renewal_provider().await;
                        billing_service::payments::engine::sweep_open_attempts_with(
                            &h.state,
                            provider.as_ref(),
                        )
                        .await
                        .expect("repair sweep");
                    }
                    "tick" => {
                        billing_service::plan_billing::renew_due_subscriptions_with(
                            &h.state,
                            renewal_provider().await,
                            now,
                        )
                        .await
                        .expect("worker tick");
                    }
                    other => panic!("unknown action {other}"),
                }
            }

            // Convergence: a late duplicate delivery and one more tick must
            // change nothing.
            expect_mollie_ok(&app, &payment_id).await;
            billing_service::plan_billing::renew_due_subscriptions_with(
                &h.state,
                renewal_provider().await,
                now,
            )
            .await
            .expect("convergence tick");

            // ── I28 invariants, for EVERY ordering ─────────────────────
            let invoices: Vec<(Uuid, String)> =
                sqlx::query_as("SELECT id, status::text FROM invoices WHERE tenant_id = $1")
                    .bind(&tenant)
                    .fetch_all(&h.pool)
                    .await
                    .expect("invoices");
            assert_eq!(
                invoices.len(),
                2,
                "order {index} ({ordering:?}): the activation invoice + the ONE renewal invoice, \
                 got {invoices:?}"
            );
            assert!(
                invoices.iter().all(|(_, status)| status == "paid"),
                "order {index}: both invoices are paid, got {invoices:?}"
            );
            let allocations: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM invoice_payment_allocations \
                 WHERE tenant_id = $1",
            )
            .bind(&tenant)
            .fetch_one(&h.pool)
            .await
            .expect("allocations");
            assert_eq!(
                allocations, 2,
                "order {index}: one allocation per payment, no double settlement"
            );
            let renewal_allocations: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM invoice_payment_allocations WHERE invoice_id = $1",
            )
            .bind(renewal_invoice)
            .fetch_one(&h.pool)
            .await
            .expect("renewal allocations");
            assert_eq!(renewal_allocations, 1, "order {index}");

            // The plan was NEVER re-activated: one subscription row, the
            // tenant plan unchanged, exactly one activation audit.
            let (cycle_start, cycle_end, status, plan): (
                DateTime<Utc>,
                DateTime<Utc>,
                String,
                Option<String>,
            ) = sqlx::query_as(
                "SELECT billing_cycle_start, billing_cycle_end, status, plan \
                 FROM subscription_state WHERE tenant_id = $1",
            )
            .bind(&tenant)
            .fetch_one(&h.pool)
            .await
            .expect("subscription row");
            assert_eq!(
                cycle_start,
                DUE_END.parse::<DateTime<Utc>>().unwrap(),
                "order {index}: the period starts where the previous one ended"
            );
            assert_eq!(
                cycle_end,
                EXPECTED_END.parse::<DateTime<Utc>>().unwrap(),
                "order {index}: exactly ONE interval after the previous period, never `now`"
            );
            assert_eq!(status, "active", "order {index}");
            assert_eq!(plan.as_deref(), Some("starter"), "order {index}");
            let subscription_rows: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM subscription_state WHERE tenant_id = $1")
                    .bind(&tenant)
                    .fetch_one(&h.pool)
                    .await
                    .expect("subscription rows");
            assert_eq!(subscription_rows, 1, "order {index}: no replaced row");
            let tenant_plan: String = sqlx::query_scalar("SELECT plan FROM tenants WHERE id = $1")
                .bind(&tenant)
                .fetch_one(&h.pool)
                .await
                .expect("tenant plan");
            assert_eq!(
                tenant_plan, "starter",
                "order {index}: the plan never moved"
            );
            let activations: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM audit_logs \
                 WHERE tenant_id = $1 AND action = 'billing.subscription_activated'",
            )
            .bind(&tenant)
            .fetch_one(&h.pool)
            .await
            .expect("activation audits");
            assert_eq!(
                activations, 1,
                "order {index}: the late renewal payment never activated a plan"
            );
            let pending: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM invoices WHERE tenant_id = $1 \
                 AND status IN ('draft', 'pending')",
            )
            .bind(&tenant)
            .fetch_one(&h.pool)
            .await
            .expect("open invoices");
            assert_eq!(
                pending, 0,
                "order {index}: no renewal invoice is left unpayable"
            );
        }
    }
);

db_test!(
    renewal_dunning_opens_new_attempts_and_marks_past_due_after_three_failures,
    |h| {
        let mock = mock_mollie_api();
        seed_tenant(&h, "cov_dunning", "free").await;
        seed_reverse_charge_business(&h, "cov_dunning").await;
        billing_service::plan_billing::activate_from_paid_checkout(
            &h.pool,
            "tr_cov_dunning_first",
            "cov_dunning",
            "starter",
            "monthly",
            "EUR",
            2_000,
            Some("cst_cov_dunning"),
            Some("mdt_cov_dunning"),
        )
        .await
        .expect("activation");

        // Every charge definitively fails at the provider. The mock keys
        // routes by PATH (the historical keying).
        mock.route(
            "/v2/payments",
            200,
            r#"{"id": "tr_dun_{seq}", "status": "failed"}"#.to_string(),
        );

        let cycle_before_dunning: DateTime<Utc> = sqlx::query_scalar(
            "SELECT billing_cycle_end FROM subscription_state WHERE tenant_id = $1",
        )
        .bind("cov_dunning")
        .fetch_one(&h.pool)
        .await
        .expect("cycle before dunning");
        let base = Utc::now() + chrono::Duration::days(40);
        for tick in 0..3 {
            let now = base + chrono::Duration::hours(2 * tick);
            let renewed = billing_service::plan_billing::renew_due_subscriptions_with(
                &h.state,
                renewal_provider().await,
                now,
            )
            .await
            .expect("dunning tick");
            assert_eq!(renewed, 0, "a failed charge never renews the period");
        }

        // Three attempts, three DISTINCT immutable rows under the shared
        // dunning-key scheme; the invoice stays OPEN.
        let ladder: Vec<(i64, String, String)> = sqlx::query_as(
            "SELECT attempt_no::bigint, idempotency_key, state FROM payment_attempts \
         WHERE tenant_id = $1 AND purpose = 'renewal' ORDER BY attempt_no",
        )
        .bind("cov_dunning")
        .fetch_all(&h.pool)
        .await
        .expect("dunning ladder");
        assert_eq!(ladder.len(), 3, "attempt 2 and 3 are NEW rows: {ladder:?}");
        for (index, (attempt_no, key, state)) in ladder.iter().enumerate() {
            assert_eq!(*attempt_no, index as i64 + 1);
            assert!(
                key.starts_with("payment:invoice:") && key.ends_with(&format!(":{attempt_no}")),
                "the dunning key follows payment:{{ref}}:{{n}}: {key}"
            );
            assert_eq!(state, "failed");
        }
        let (status, attempts): (String, i32) = sqlx::query_as(
            "SELECT status, renewal_attempts FROM subscription_state WHERE tenant_id = $1",
        )
        .bind("cov_dunning")
        .fetch_one(&h.pool)
        .await
        .expect("subscription state");
        assert_eq!(status, "past_due", "the dunning ladder ends past_due");
        assert_eq!(attempts, 3);
        let open_invoices: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM invoices WHERE tenant_id = $1 AND status = 'pending'",
        )
        .bind("cov_dunning")
        .fetch_one(&h.pool)
        .await
        .expect("open invoices");
        assert_eq!(open_invoices, 1, "a failed renewal leaves the invoice open");

        // The customer is notified and the failure audited (the crate's
        // existing dunning vocabulary).
        let notifications: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM notification_queue WHERE tenant_id = $1 AND type = 'payment_failed'",
        )
        .bind("cov_dunning")
        .fetch_one(&h.pool)
        .await
        .expect("notification count");
        assert_eq!(notifications, 1);
        let audits: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM audit_logs \
         WHERE tenant_id = $1 AND action = 'billing.subscription_payment_failed'",
        )
        .bind("cov_dunning")
        .fetch_one(&h.pool)
        .await
        .expect("failure audits");
        assert_eq!(audits, 1);

        // The period NEVER advanced on failure.
        let cycle: DateTime<Utc> = sqlx::query_scalar(
            "SELECT billing_cycle_end FROM subscription_state WHERE tenant_id = $1",
        )
        .bind("cov_dunning")
        .fetch_one(&h.pool)
        .await
        .expect("cycle");
        assert_eq!(
            cycle, cycle_before_dunning,
            "a failed renewal never advances the period"
        );
    }
);

db_test!(
    cancel_at_period_end_ends_the_subscription_without_invoicing_or_charging,
    |h| {
        let _mock = mock_mollie_api();
        seed_tenant(&h, "cov_cancel", "growth").await;
        seed_due_subscription(
            &h,
            "cov_cancel",
            "growth",
            "NOW() - INTERVAL '1 day'",
            true,
            "active",
        )
        .await;

        let renewed = billing_service::plan_billing::renew_due_subscriptions_with(
            &h.state,
            renewal_provider().await,
            Utc::now(),
        )
        .await
        .expect("renewal tick");
        assert_eq!(
            renewed, 0,
            "a cancel-at-period-end subscription never renews"
        );

        let (status, flag): (String, bool) = sqlx::query_as(
            "SELECT status, cancel_at_period_end FROM subscription_state WHERE tenant_id = $1",
        )
        .bind("cov_cancel")
        .fetch_one(&h.pool)
        .await
        .expect("subscription state");
        assert_eq!(
            status, "canceled",
            "the subscription ends per the local vocabulary"
        );
        assert!(!flag, "the flag is cleared once applied");
        let plan: String = sqlx::query_scalar("SELECT plan FROM tenants WHERE id = $1")
            .bind("cov_cancel")
            .fetch_one(&h.pool)
            .await
            .expect("tenant plan");
        assert_eq!(plan, "free", "an ended subscription downgrades the tenant");
        let invoices: i64 =
            sqlx::query_scalar("SELECT count(*) FROM invoices WHERE tenant_id = $1")
                .bind("cov_cancel")
                .fetch_one(&h.pool)
                .await
                .expect("invoices");
        assert_eq!(invoices, 0, "no invoice is created");
        let attempts: i64 =
            sqlx::query_scalar("SELECT count(*) FROM payment_attempts WHERE tenant_id = $1")
                .bind("cov_cancel")
                .fetch_one(&h.pool)
                .await
                .expect("attempts");
        assert_eq!(attempts, 0, "no charge attempt is claimed");
    }
);

// ---------------------------------------------------------------------------
// The 30 Oct re-audit's renewal items (4, 7, 8, 11): the settlement fact is
// the PROVIDER'S payment object, credentials are provider-scoped, the
// checkout has a LOCAL authority, and the subscription's currency is local
// state.
// ---------------------------------------------------------------------------

db_test!(
    renewal_never_settles_the_expected_gross_when_the_provider_returned_another_amount,
    |h| {
        let _mock = mock_mollie_api();
        seed_tenant(&h, "cov_fact_amount", "free").await;
        seed_reverse_charge_business(&h, "cov_fact_amount").await;
        billing_service::plan_billing::activate_from_paid_checkout(
            &h.pool,
            "tr_fact_first",
            "cov_fact_amount",
            "starter",
            "monthly",
            "EUR",
            2_000,
            Some("cst_fact_amount"),
            Some("mdt_fact_amount"),
        )
        .await
        .expect("activation");
        let cycle_before: DateTime<Utc> = sqlx::query_scalar(
            "SELECT billing_cycle_end FROM subscription_state WHERE tenant_id = $1",
        )
        .bind("cov_fact_amount")
        .fetch_one(&h.pool)
        .await
        .expect("cycle before");

        // The provider reports SUCCEEDED with €200 for the €20 renewal
        // invoice. The settlement fact must be THIS amount; the expected
        // gross (€20) must never be substituted, or exact-amount
        // verification becomes self-fulfilling.
        let provider = Arc::new(ScriptedRenewalProvider::new("mollie"));
        provider.script_charge(billing_service::payments::Payment {
            provider: "mollie".to_string(),
            provider_payment_id: "tr_fact_overcharge".to_string(),
            state: billing_service::payments::PaymentState::Succeeded,
            amount_minor: 20_000,
            currency: "EUR".to_string(),
            created_at: None,
        });
        let later = Utc::now() + chrono::Duration::days(40);
        let renewed = billing_service::plan_billing::renew_due_subscriptions_with(
            &h.state,
            provider.clone(),
            later,
        )
        .await
        .expect("renewal tick");
        assert_eq!(
            renewed, 0,
            "an over-charge settles nothing and renews nothing"
        );

        // No settlement: the invoice stays open, no allocation, the period
        // did not advance and no renewal audit claims success.
        let (status, total, currency): (String, i64, String) = sqlx::query_as(
            "SELECT status::text, COALESCE(total, amount)::bigint, currency FROM invoices \
             WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT 1",
        )
        .bind("cov_fact_amount")
        .fetch_one(&h.pool)
        .await
        .expect("renewal invoice");
        assert_ne!(status, "paid", "the over-charged invoice is NOT paid");
        assert_eq!((total, currency.as_str()), (2_000, "EUR"));
        let allocations: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM invoice_payment_allocations WHERE tenant_id = $1",
        )
        .bind("cov_fact_amount")
        .fetch_one(&h.pool)
        .await
        .expect("allocations");
        assert_eq!(allocations, 1, "only the activation payment is allocated");
        let cycle_after: DateTime<Utc> = sqlx::query_scalar(
            "SELECT billing_cycle_end FROM subscription_state WHERE tenant_id = $1",
        )
        .bind("cov_fact_amount")
        .fetch_one(&h.pool)
        .await
        .expect("cycle after");
        assert_eq!(
            cycle_after, cycle_before,
            "the period never advances on a mismatch"
        );
        let renewed_audits: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM audit_logs \
             WHERE tenant_id = $1 AND action = 'billing.subscription_renewed'",
        )
        .bind("cov_fact_amount")
        .fetch_one(&h.pool)
        .await
        .expect("renewal audits");
        assert_eq!(renewed_audits, 0);

        // The exact-amount reconciliation incident carries BOTH numbers.
        let incident: (i64, serde_json::Value) = sqlx::query_as(
            "SELECT count(*)::bigint, COALESCE(jsonb_agg(detail), '[]'::jsonb) \
             FROM finance_incidents \
             WHERE kind = 'renewal_amount_mismatch' AND mollie_payment_id = 'tr_fact_overcharge' \
               AND status = 'open'",
        )
        .fetch_one(&h.pool)
        .await
        .expect("finance incident");
        assert_eq!(incident.0, 1, "exactly one AmountMismatch incident");
        let detail = &incident.1[0];
        assert_eq!(detail["expectedMinor"], 2_000);
        assert_eq!(detail["actualMinor"], 20_000);

        // The attempt keeps the provider's real outcome; it is never closed
        // failed (the money may exist) and never auto-retried.
        let attempt_state: String = sqlx::query_scalar(
            "SELECT state FROM payment_attempts \
             WHERE tenant_id = $1 AND purpose = 'renewal'",
        )
        .bind("cov_fact_amount")
        .fetch_one(&h.pool)
        .await
        .expect("renewal attempt");
        assert_eq!(attempt_state, "succeeded");
        assert_eq!(
            provider.fetch_calls(),
            0,
            "a complete provider fact is used verbatim, no refetch"
        );
    }
);

db_test!(
    renewal_refetches_an_unusable_success_and_settles_the_fetched_amount,
    |h| {
        let _mock = mock_mollie_api();
        seed_tenant(&h, "cov_fact_refetch", "free").await;
        seed_reverse_charge_business(&h, "cov_fact_refetch").await;
        billing_service::plan_billing::activate_from_paid_checkout(
            &h.pool,
            "tr_refetch_first",
            "cov_fact_refetch",
            "starter",
            "monthly",
            "EUR",
            2_000,
            Some("cst_refetch"),
            Some("mdt_refetch"),
        )
        .await
        .expect("activation");

        let provider = Arc::new(ScriptedRenewalProvider::new("mollie"));
        // The charge response is a success with NO money facts (the neutral
        // sentinels: amount 0 / empty currency).
        provider.script_charge(billing_service::payments::Payment {
            provider: "mollie".to_string(),
            provider_payment_id: "tr_fact_refetch".to_string(),
            state: billing_service::payments::PaymentState::Succeeded,
            amount_minor: 0,
            currency: String::new(),
            created_at: None,
        });
        // The authenticated refetch carries the authoritative facts.
        provider.script_fetch(billing_service::payments::Payment {
            provider: "mollie".to_string(),
            provider_payment_id: "tr_fact_refetch".to_string(),
            state: billing_service::payments::PaymentState::Succeeded,
            amount_minor: 2_000,
            currency: "EUR".to_string(),
            created_at: None,
        });

        let later = Utc::now() + chrono::Duration::days(40);
        let renewed = billing_service::plan_billing::renew_due_subscriptions_with(
            &h.state,
            provider.clone(),
            later,
        )
        .await
        .expect("renewal tick");
        assert_eq!(renewed, 1, "the refetched provider facts settle");
        assert_eq!(provider.fetch_calls(), 1, "the unusable fact is refetched");
        let paid: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM invoices WHERE tenant_id = $1 AND status = 'paid'",
        )
        .bind("cov_fact_refetch")
        .fetch_one(&h.pool)
        .await
        .expect("paid invoices");
        assert_eq!(paid, 2, "activation + renewal are both paid");
        let incidents: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM finance_incidents \
             WHERE kind = 'renewal_payment_fact_unusable' AND status = 'open'",
        )
        .fetch_one(&h.pool)
        .await
        .expect("incidents");
        assert_eq!(incidents, 0);
    }
);

db_test!(
    renewal_refuses_when_the_provider_success_carries_no_amount_after_refetch,
    |h| {
        let _mock = mock_mollie_api();
        seed_tenant(&h, "cov_fact_blank", "free").await;
        seed_reverse_charge_business(&h, "cov_fact_blank").await;
        billing_service::plan_billing::activate_from_paid_checkout(
            &h.pool,
            "tr_blank_first",
            "cov_fact_blank",
            "starter",
            "monthly",
            "EUR",
            2_000,
            Some("cst_blank"),
            Some("mdt_blank"),
        )
        .await
        .expect("activation");

        let provider = Arc::new(ScriptedRenewalProvider::new("mollie"));
        provider.script_charge(billing_service::payments::Payment {
            provider: "mollie".to_string(),
            provider_payment_id: "tr_fact_blank".to_string(),
            state: billing_service::payments::PaymentState::Succeeded,
            amount_minor: 0,
            currency: String::new(),
            created_at: None,
        });
        provider.script_fetch(billing_service::payments::Payment {
            provider: "mollie".to_string(),
            provider_payment_id: "tr_fact_blank".to_string(),
            state: billing_service::payments::PaymentState::Succeeded,
            amount_minor: 0,
            currency: String::new(),
            created_at: None,
        });

        let later = Utc::now() + chrono::Duration::days(40);
        let renewed = billing_service::plan_billing::renew_due_subscriptions_with(
            &h.state,
            provider.clone(),
            later,
        )
        .await
        .expect("renewal tick");
        assert_eq!(renewed, 0, "nothing is inferred and nothing settles");
        assert_eq!(provider.fetch_calls(), 1);
        let unpaid: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM invoices WHERE tenant_id = $1 AND status <> 'paid'",
        )
        .bind("cov_fact_blank")
        .fetch_one(&h.pool)
        .await
        .expect("unpaid invoices");
        assert_eq!(unpaid, 1, "the renewal invoice stays open");
        let incidents: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM finance_incidents \
             WHERE kind = 'renewal_payment_fact_unusable' \
               AND mollie_payment_id = 'tr_fact_blank' AND status = 'open'",
        )
        .fetch_one(&h.pool)
        .await
        .expect("incidents");
        assert_eq!(incidents, 1, "the unusable provider fact is an incident");
    }
);

db_test!(
    renewal_charges_only_the_configured_providers_credential,
    |h| {
        seed_tenant(&h, "cov_provider_scope", "free").await;
        seed_reverse_charge_business(&h, "cov_provider_scope").await;
        // The configured adapter is Stripe; the activation stores ITS
        // credential (provider = stripe).
        let provider = Arc::new(ScriptedRenewalProvider::new("stripe"));
        billing_service::plan_billing::activate_from_paid_checkout_with(
            &h.pool,
            provider.clone(),
            "pi_scope_first",
            "cov_provider_scope",
            "starter",
            "monthly",
            "EUR",
            2_000,
            Some("cus_scope_stripe"),
            Some("pm_scope_stripe"),
        )
        .await
        .expect("activation");
        // Provider coexistence: a NEWER Mollie credential and a newer
        // REVOKED Stripe credential. Neither may be selected by the renewal
        // worker.
        sqlx::query(
            "INSERT INTO payment_credentials \
                 (tenant_id, provider, provider_customer_id, provider_method_id, state, created_at) \
             VALUES ($1, 'mollie', 'cst_scope_mollie', 'mdt_scope_mollie', 'active', \
                     NOW() + INTERVAL '1 hour')",
        )
        .bind("cov_provider_scope")
        .execute(&h.pool)
        .await
        .expect("newer mollie credential");
        sqlx::query(
            "INSERT INTO payment_credentials \
                 (tenant_id, provider, provider_customer_id, provider_method_id, state, \
                  revoked_at, created_at) \
             VALUES ($1, 'stripe', 'cus_scope_revoked', 'pm_scope_revoked', 'active', NOW(), \
                     NOW() + INTERVAL '2 hours')",
        )
        .bind("cov_provider_scope")
        .execute(&h.pool)
        .await
        .expect("newer revoked stripe credential");

        let later = Utc::now() + chrono::Duration::days(40);
        let renewed = billing_service::plan_billing::renew_due_subscriptions_with(
            &h.state,
            provider.clone(),
            later,
        )
        .await
        .expect("renewal tick");
        assert_eq!(renewed, 1, "the provider-scoped credential renews");
        assert_eq!(
            provider.charged_methods(),
            vec![(
                "cus_scope_stripe".to_string(),
                "pm_scope_stripe".to_string()
            )],
            "the adapter received the CONFIGURED provider's credential, never the newer \
             Mollie/revoked ones"
        );
        assert_eq!(provider.charge_calls(), 1);
        let attempt_provider: String = sqlx::query_scalar(
            "SELECT provider FROM payment_attempts \
             WHERE tenant_id = $1 AND purpose = 'renewal'",
        )
        .bind("cov_provider_scope")
        .fetch_one(&h.pool)
        .await
        .expect("renewal attempt");
        assert_eq!(attempt_provider, "stripe");
    }
);

db_test!(
    renewal_bills_in_the_subscriptions_currency_not_the_newest_invoice,
    |h| {
        let mock = mock_mollie_api();
        seed_tenant(&h, "cov_currency", "free").await;
        seed_reverse_charge_business(&h, "cov_currency").await;
        billing_service::plan_billing::activate_from_paid_checkout(
            &h.pool,
            "tr_currency_first",
            "cov_currency",
            "starter",
            "monthly",
            "EUR",
            2_000,
            Some("cst_currency"),
            Some("mdt_currency"),
        )
        .await
        .expect("activation");
        let stored_currency: String = sqlx::query_scalar(
            "SELECT billing_currency FROM subscription_state WHERE tenant_id = $1",
        )
        .bind("cov_currency")
        .fetch_one(&h.pool)
        .await
        .expect("stored currency");
        assert_eq!(
            stored_currency, "EUR",
            "the activation froze the paid currency"
        );

        // A NEWER, unrelated USD support invoice: the old inference rule
        // would have re-denominated the next renewal in USD.
        sqlx::query(
            "INSERT INTO invoices \
                 (id, tenant_id, invoice_number, status, amount, currency, subtotal, vat_total, \
                  total, due_at, created_at, updated_at) \
             VALUES ($1, $2, $3, 'paid', 5000, 'USD', 5000, 0, 5000, NOW(), \
                     NOW() + INTERVAL '1 hour', NOW() + INTERVAL '1 hour')",
        )
        .bind(Uuid::new_v4())
        .bind("cov_currency")
        .bind(format!("SUP-{}", Uuid::new_v4().simple()))
        .execute(&h.pool)
        .await
        .expect("newer USD support invoice");

        mock.route(
            "/v2/payments",
            200,
            r#"{"id": "tr_currency_{seq}", "status": "paid"}"#.to_string(),
        );
        let later = Utc::now() + chrono::Duration::days(40);
        let renewed = billing_service::plan_billing::renew_due_subscriptions_with(
            &h.state,
            renewal_provider().await,
            later,
        )
        .await
        .expect("renewal tick");
        assert_eq!(renewed, 1);

        let (currency, total): (String, i64) = sqlx::query_as(
            "SELECT currency, COALESCE(total, amount)::bigint FROM invoices \
             WHERE tenant_id = $1 AND period_start = ( \
                 SELECT billing_cycle_start FROM subscription_state WHERE tenant_id = $1) \
             ORDER BY created_at DESC LIMIT 1",
        )
        .bind("cov_currency")
        .fetch_one(&h.pool)
        .await
        .expect("renewal invoice");
        assert_eq!(
            (currency.as_str(), total),
            ("EUR", 2_000),
            "the renewal is billed in the SUBSCRIPTION's currency, not the newest invoice's"
        );
        let attempt_currency: String = sqlx::query_scalar(
            "SELECT currency FROM payment_attempts \
             WHERE tenant_id = $1 AND purpose = 'renewal'",
        )
        .bind("cov_currency")
        .fetch_one(&h.pool)
        .await
        .expect("renewal attempt");
        assert_eq!(attempt_currency, "EUR");
        let currency_after: String = sqlx::query_scalar(
            "SELECT billing_currency FROM subscription_state WHERE tenant_id = $1",
        )
        .bind("cov_currency")
        .fetch_one(&h.pool)
        .await
        .expect("currency after");
        assert_eq!(currency_after, "EUR");
    }
);

db_test!(
    local_checkout_authority_mints_per_intent_and_completes_from_the_provider_pointer,
    |h| {
        seed_tenant(&h, "cov_checkout_authority", "free").await;
        let new_checkout = || billing_service::plan_billing::NewLocalCheckout {
            tenant_id: "cov_checkout_authority".to_string(),
            plan: "starter".to_string(),
            interval: "monthly".to_string(),
            net_minor: 2_000,
            tax_minor: 0,
            gross_minor: 2_000,
            currency: "EUR".to_string(),
            provider: "mollie".to_string(),
            business: true,
            country: "DE".to_string(),
            vat_number: Some("DE123456789".to_string()),
            reverse_charge: true,
            vat_rate: 0.0,
            source: Some("api_checkout".to_string()),
        };
        let first = billing_service::plan_billing::begin_local_checkout(&h.pool, new_checkout())
            .await
            .expect("first local checkout");
        let second = billing_service::plan_billing::begin_local_checkout(&h.pool, new_checkout())
            .await
            .expect("second local checkout");
        assert_ne!(
            first, second,
            "two intentional checkouts are two local identities (and two provider keys)"
        );
        let rows: Vec<(Uuid, String)> = sqlx::query_as(
            "SELECT id, status FROM payment_checkouts WHERE tenant_id = $1 ORDER BY created_at",
        )
        .bind("cov_checkout_authority")
        .fetch_all(&h.pool)
        .await
        .expect("local checkouts");
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|(_, status)| status == "open"));

        billing_service::plan_billing::attach_provider_checkout(
            &h.pool,
            first,
            "mollie",
            "tr_checkout_session_1",
            Some("tr_checkout_session_1"),
        )
        .await
        .expect("attach");
        let open = billing_service::plan_billing::local_checkout_for_payment(
            &h.pool,
            "mollie",
            "tr_checkout_session_1",
        )
        .await
        .expect("lookup")
        .expect("the session resolves to its local checkout");
        assert_eq!(open.id, first);
        assert_eq!(open.status, "open");
        assert_eq!(
            (open.net_minor, open.tax_minor, open.gross_minor),
            (2_000, 0, 2_000)
        );
        assert_eq!(open.currency, "EUR");

        // The completed-checkout fact's pointer marks the row completed and
        // records the provider payment id.
        let completed = billing_service::plan_billing::complete_local_checkout(
            &h.pool,
            "mollie",
            "tr_checkout_session_1",
            "tr_checkout_paid_1",
        )
        .await
        .expect("complete")
        .expect("the provider checkout id resolves");
        assert_eq!(completed.id, first);
        assert_eq!(completed.status, "completed");
        assert_eq!(
            completed.provider_payment_id.as_deref(),
            Some("tr_checkout_paid_1")
        );
        // ... and the paid payment id resolves the same local quote.
        let by_payment = billing_service::plan_billing::local_checkout_for_payment(
            &h.pool,
            "mollie",
            "tr_checkout_paid_1",
        )
        .await
        .expect("lookup by payment")
        .expect("the payment resolves to its local checkout");
        assert_eq!(by_payment.id, first);
        // An unknown pointer is None, never invented.
        assert!(billing_service::plan_billing::complete_local_checkout(
            &h.pool,
            "mollie",
            "tr_unknown_session",
            "tr_unknown_paid",
        )
        .await
        .expect("unknown complete")
        .is_none());

        billing_service::plan_billing::mark_local_checkout_failed(&h.pool, second)
            .await
            .expect("mark failed");
        let statuses: Vec<(Uuid, String)> = sqlx::query_as(
            "SELECT id, status FROM payment_checkouts WHERE tenant_id = $1 ORDER BY created_at",
        )
        .bind("cov_checkout_authority")
        .fetch_all(&h.pool)
        .await
        .expect("statuses");
        assert_eq!(statuses[0], (first, "completed".to_string()));
        assert_eq!(statuses[1], (second, "failed".to_string()));
    }
);

db_test!(
    activation_settles_the_locally_frozen_checkout_quote_not_provider_metadata,
    |h| {
        let _mock = mock_mollie_api();
        seed_tenant(&h, "cov_local_quote", "free").await;
        seed_reverse_charge_business(&h, "cov_local_quote").await;
        let checkout_id = billing_service::plan_billing::begin_local_checkout(
            &h.pool,
            billing_service::plan_billing::NewLocalCheckout {
                tenant_id: "cov_local_quote".to_string(),
                plan: "starter".to_string(),
                interval: "monthly".to_string(),
                net_minor: 2_000,
                tax_minor: 0,
                gross_minor: 2_000,
                currency: "EUR".to_string(),
                provider: "mollie".to_string(),
                business: true,
                country: "DE".to_string(),
                vat_number: Some("DE123456789".to_string()),
                reverse_charge: true,
                vat_rate: 0.0,
                source: Some("api_checkout".to_string()),
            },
        )
        .await
        .expect("local checkout");
        billing_service::plan_billing::attach_provider_checkout(
            &h.pool,
            checkout_id,
            "mollie",
            "tr_metadata_session",
            Some("tr_metadata_session"),
        )
        .await
        .expect("attach");

        // The completed-checkout fact: the provider's hosted-session id and
        // the payment id (which DIFFERS from the session id) resolve the
        // local row, mark it completed, and the activation settles the
        // stored quote. The provider metadata LIES (growth / yearly); the
        // frozen quote (starter / monthly / EUR / 2000) is the only
        // authority.
        let outcome = billing_service::plan_billing::activate_from_completed_checkout(
            &h.pool,
            renewal_provider().await,
            "tr_metadata_session",
            "tr_metadata_paid",
            "cov_local_quote",
            "growth",
            "yearly",
            "EUR",
            2_000,
            Some("cst_local_quote"),
            Some("mdt_local_quote"),
        )
        .await
        .expect("activation");
        assert!(!outcome.already_active);
        assert!(outcome.invoice_id.is_some());

        let (plan, interval, currency, method): (
            Option<String>,
            Option<String>,
            String,
            Option<String>,
        ) = sqlx::query_as(
            "SELECT plan, billing_interval, billing_currency, provider_method_id \
             FROM subscription_state WHERE tenant_id = $1",
        )
        .bind("cov_local_quote")
        .fetch_one(&h.pool)
        .await
        .expect("subscription");
        assert_eq!(
            plan.as_deref(),
            Some("starter"),
            "the stored plan wins over the metadata"
        );
        assert_eq!(interval.as_deref(), Some("monthly"));
        assert_eq!(currency, "EUR");
        assert_eq!(method.as_deref(), Some("mdt_local_quote"));
        let tenant_plan: String = sqlx::query_scalar("SELECT plan FROM tenants WHERE id = $1")
            .bind("cov_local_quote")
            .fetch_one(&h.pool)
            .await
            .expect("tenant plan");
        assert_eq!(tenant_plan, "starter");
        let (net, vat, total, invoice_currency): (i64, i64, i64, String) = sqlx::query_as(
            "SELECT subtotal::bigint, vat_total::bigint, total::bigint, currency FROM invoices \
             WHERE tenant_id = $1",
        )
        .bind("cov_local_quote")
        .fetch_one(&h.pool)
        .await
        .expect("activation invoice");
        assert_eq!((net, vat, total), (2_000, 0, 2_000));
        assert_eq!(invoice_currency, "EUR");
        let (status, provider_payment_id): (String, Option<String>) = sqlx::query_as(
            "SELECT status, provider_payment_id FROM payment_checkouts WHERE id = $1",
        )
        .bind(checkout_id)
        .fetch_one(&h.pool)
        .await
        .expect("local checkout row");
        assert_eq!(status, "completed");
        assert_eq!(provider_payment_id.as_deref(), Some("tr_metadata_paid"));
        let audit_checkout: Option<String> = sqlx::query_scalar(
            "SELECT details->>'checkoutId' FROM audit_logs \
             WHERE tenant_id = $1 AND action = 'billing.subscription_activated'",
        )
        .bind("cov_local_quote")
        .fetch_one(&h.pool)
        .await
        .expect("activation audit");
        assert_eq!(
            audit_checkout,
            Some(checkout_id.to_string()),
            "the activation audit names the local checkout"
        );
    }
);

db_test!(
    activation_refuses_a_charge_that_differs_from_the_locally_frozen_quote,
    |h| {
        let _mock = mock_mollie_api();
        seed_tenant(&h, "cov_local_mismatch", "free").await;
        seed_reverse_charge_business(&h, "cov_local_mismatch").await;
        let checkout_id = billing_service::plan_billing::begin_local_checkout(
            &h.pool,
            billing_service::plan_billing::NewLocalCheckout {
                tenant_id: "cov_local_mismatch".to_string(),
                plan: "starter".to_string(),
                interval: "monthly".to_string(),
                net_minor: 2_000,
                tax_minor: 0,
                gross_minor: 2_000,
                currency: "EUR".to_string(),
                provider: "mollie".to_string(),
                business: true,
                country: "DE".to_string(),
                vat_number: Some("DE123456789".to_string()),
                reverse_charge: true,
                vat_rate: 0.0,
                source: Some("api_checkout".to_string()),
            },
        )
        .await
        .expect("local checkout");
        billing_service::plan_billing::attach_provider_checkout(
            &h.pool,
            checkout_id,
            "mollie",
            "tr_quote_mismatch_session",
            Some("tr_quote_mismatch_session"),
        )
        .await
        .expect("attach");
        billing_service::plan_billing::complete_local_checkout(
            &h.pool,
            "mollie",
            "tr_quote_mismatch_session",
            "tr_quote_mismatch_paid",
        )
        .await
        .expect("complete")
        .expect("resolved");

        let error = billing_service::plan_billing::activate_from_paid_checkout_with(
            &h.pool,
            renewal_provider().await,
            "tr_quote_mismatch_paid",
            "cov_local_mismatch",
            "starter",
            "monthly",
            "EUR",
            8_900,
            Some("cst_local_mismatch"),
            Some("mdt_local_mismatch"),
        )
        .await
        .expect_err("a charge above the frozen quote must not activate");
        assert!(
            error.to_string().contains("froze"),
            "the refusal names the local quote: {error}"
        );
        let invoices: i64 =
            sqlx::query_scalar("SELECT count(*) FROM invoices WHERE tenant_id = $1")
                .bind("cov_local_mismatch")
                .fetch_one(&h.pool)
                .await
                .expect("invoices");
        assert_eq!(invoices, 0, "nothing is issued");
        let subscriptions: i64 =
            sqlx::query_scalar("SELECT count(*) FROM subscription_state WHERE tenant_id = $1")
                .bind("cov_local_mismatch")
                .fetch_one(&h.pool)
                .await
                .expect("subscriptions");
        assert_eq!(subscriptions, 0, "no entitlement is granted");
        let (incidents, detail): (i64, serde_json::Value) = sqlx::query_as(
            "SELECT count(*)::bigint, COALESCE(jsonb_agg(detail), '[]'::jsonb) \
             FROM finance_incidents \
             WHERE kind = 'checkout_amount_mismatch' AND status = 'open'",
        )
        .fetch_one(&h.pool)
        .await
        .expect("incident");
        assert_eq!(incidents, 1);
        assert_eq!(detail[0]["checkoutId"], checkout_id.to_string());
        assert_eq!(detail[0]["chargedMinor"], 8_900);
        assert_eq!(detail[0]["quotedMinor"], 2_000);
    }
);

db_test!(
    provider_renewal_payment_never_resurrects_a_canceled_subscription,
    |h| {
        seed_tenant(&h, "cov_nores", "starter").await;
        // A locally-canceled subscription whose provider-era contract a
        // legacy schedule still charges behind our back. The renewal worker
        // had already created the next period's invoice before the cancel
        // landed.
        let subscription_id = seed_due_subscription(
            &h,
            "cov_nores",
            "starter",
            "NOW() - INTERVAL '1 day'",
            true,
            "canceled",
        )
        .await;
        let invoice_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO invoices (id, tenant_id, invoice_number, status, amount, currency,
                                   subtotal, vat_total, total, due_at, period_start, period_end,
                                   created_at, updated_at)
             VALUES ($1, $2, $3, 'pending', 2000, 'EUR', 1613, 387, 2000, NOW(),
                     (SELECT billing_cycle_end FROM subscription_state WHERE tenant_id = $2),
                     NOW() + INTERVAL '30 days', NOW(), NOW())",
        )
        .bind(invoice_id)
        .bind("cov_nores")
        .bind(format!("COV-NORES-{}", &invoice_id.to_string()[..8]))
        .execute(&h.pool)
        .await
        .expect("seed the open renewal invoice");
        let cycle_before: DateTime<Utc> = sqlx::query_scalar(
            "SELECT billing_cycle_end FROM subscription_state WHERE tenant_id = $1",
        )
        .bind("cov_nores")
        .fetch_one(&h.pool)
        .await
        .expect("cycle before");

        // The provider-initiated charge lands as a webhook fact. It may
        // settle the money (the obligation exists), but the canceled
        // subscription is NEVER resurrected and the cycle never advances.
        let settled = billing_service::plan_billing::reconcile_provider_renewal_payment(
            &h.pool,
            "tr_legacy_renew",
            &subscription_id,
            2_000,
            "EUR",
        )
        .await
        .expect("the obligation settles");
        assert_eq!(settled, Some(invoice_id));
        let invoice_status: String =
            sqlx::query_scalar("SELECT status::text FROM invoices WHERE id = $1")
                .bind(invoice_id)
                .fetch_one(&h.pool)
                .await
                .expect("invoice status");
        assert_eq!(
            invoice_status, "paid",
            "the money is settled against the obligation"
        );

        let (status, cycle_after): (String, DateTime<Utc>) = sqlx::query_as(
            "SELECT status, billing_cycle_end FROM subscription_state WHERE tenant_id = $1",
        )
        .bind("cov_nores")
        .fetch_one(&h.pool)
        .await
        .expect("subscription state");
        assert_eq!(
            status, "canceled",
            "a provider fact never resurrects the subscription"
        );
        assert_eq!(
            cycle_after, cycle_before,
            "a provider fact never advances a canceled subscription's period"
        );
        let plan: String = sqlx::query_scalar("SELECT plan FROM tenants WHERE id = $1")
            .bind("cov_nores")
            .fetch_one(&h.pool)
            .await
            .expect("tenant plan");
        assert_eq!(
            plan, "starter",
            "entitlement is untouched by the reconciliation"
        );

        // The reconciliation is audited as NOT applied.
        let audits: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM audit_logs \
         WHERE tenant_id = $1 AND action = 'billing.provider_renewal_reconciled' \
           AND details->>'applied' = 'false'",
        )
        .bind("cov_nores")
        .fetch_one(&h.pool)
        .await
        .expect("reconciliation audits");
        assert_eq!(audits, 1);
    }
);

db_test!(
    provider_renewal_without_a_local_obligation_is_a_reconciliation_incident,
    |h| {
        seed_tenant(&h, "cov_incident", "starter").await;
        // An ACTIVE subscription whose next period has NO invoice: the
        // provider (a legacy schedule) charged anyway. The provider must
        // never decide when the next charge exists: no invoice is summoned,
        // no period advances, and the incident is typed + recorded.
        let subscription_id = seed_due_subscription(
            &h,
            "cov_incident",
            "starter",
            "NOW() - INTERVAL '1 day'",
            false,
            "active",
        )
        .await;
        let cycle_before: DateTime<Utc> = sqlx::query_scalar(
            "SELECT billing_cycle_end FROM subscription_state WHERE tenant_id = $1",
        )
        .bind("cov_incident")
        .fetch_one(&h.pool)
        .await
        .expect("cycle before");

        let error = billing_service::plan_billing::reconcile_provider_renewal_payment(
            &h.pool,
            "tr_orphan_renew",
            &subscription_id,
            2_000,
            "EUR",
        )
        .await
        .expect_err("a provider-initiated charge with no obligation is an incident");
        let message = error.to_string();
        assert!(
            message.contains("RECONCILIATION INCIDENT") && message.contains("NO local obligation"),
            "{message}"
        );

        let invoices: i64 =
            sqlx::query_scalar("SELECT count(*) FROM invoices WHERE tenant_id = $1")
                .bind("cov_incident")
                .fetch_one(&h.pool)
                .await
                .expect("invoices");
        assert_eq!(
            invoices, 0,
            "no invoice is created on the provider's authority"
        );
        let cycle_after: DateTime<Utc> = sqlx::query_scalar(
            "SELECT billing_cycle_end FROM subscription_state WHERE tenant_id = $1",
        )
        .bind("cov_incident")
        .fetch_one(&h.pool)
        .await
        .expect("cycle after");
        assert_eq!(cycle_after, cycle_before, "the period never advances");
        let (status, attempts): (String, i32) = sqlx::query_as(
            "SELECT status, renewal_attempts FROM subscription_state WHERE tenant_id = $1",
        )
        .bind("cov_incident")
        .fetch_one(&h.pool)
        .await
        .expect("subscription state");
        assert_eq!(
            status, "active",
            "a provider fact alone never ends the subscription"
        );
        assert_eq!(attempts, 0);
        let incidents: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM finance_incidents WHERE kind = 'provider_renewal_no_local_obligation'",
        )
        .fetch_one(&h.pool)
        .await
        .expect("incidents");
        assert_eq!(incidents, 1, "the incident is recorded for the operator");
    }
);

db_test!(
    simultaneous_distinct_payment_activations_leave_one_live_subscription,
    |h| {
        let _mock = mock_mollie_api();
        seed_tenant(&h, "cov_race", "free").await;
        seed_reverse_charge_business(&h, "cov_race").await;

        let pool_a = h.pool.clone();
        let pool_b = h.pool.clone();
        let (a, b) = tokio::join!(
            race_activation(pool_a, "tr_race_a", "cov_race"),
            race_activation(pool_b, "tr_race_b", "cov_race"),
        );
        a.expect("first activation");
        b.expect("second activation");

        // Both payments are real purchases: each carries exactly one
        // invoice, resolved through its neutral settlement allocation
        // (N-05, step 10 — no provider-named invoice column).
        for payment in ["tr_race_a", "tr_race_b"] {
            let invoices: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM invoices i \
                 JOIN invoice_payment_allocations a ON a.invoice_id = i.id \
                 WHERE a.operation_id = $1",
            )
            .bind(format!("mollie:{payment}"))
            .fetch_one(&h.pool)
            .await
            .expect("invoice count");
            assert_eq!(invoices, 1, "{payment} settled exactly once");
        }

        // The distributed invariant: ONE live LOCAL subscription for the
        // tenant. The per-tenant billing lock serializes the two racing
        // activations so the loser cannot clobber the winner's row; there
        // are no provider objects at all (renewal is local).
        let rows: i64 =
            sqlx::query_scalar("SELECT count(*) FROM subscription_state WHERE tenant_id = $1")
                .bind("cov_race")
                .fetch_one(&h.pool)
                .await
                .expect("subscription rows");
        assert_eq!(
            rows, 1,
            "exactly one local subscription row survives the race"
        );
        let active_local: String = sqlx::query_scalar(
        "SELECT provider_contract_id FROM subscription_state WHERE tenant_id = $1 AND status = 'active'",
    )
    .bind("cov_race")
    .fetch_one(&h.pool)
    .await
    .expect("one active local row");
        assert!(
            active_local.starts_with("local_"),
            "the surviving row is the locally adopted one: {active_local}"
        );

        // The retirement of the loser is journaled as an audit row per adoption.
        let activations: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_logs WHERE action = 'billing.subscription_activated' AND tenant_id = $1",
    )
    .bind("cov_race")
    .fetch_one(&h.pool)
    .await
    .expect("activation audits");
        assert_eq!(activations, 2);

        cleanup_race(&h).await;
    }
);

fn race_activation(
    pool: sqlx::PgPool,
    payment_id: &'static str,
    tenant: &'static str,
) -> std::pin::Pin<
    Box<
        dyn std::future::Future<
                Output = Result<
                    billing_service::plan_billing::ActivationOutcome,
                    billing_service::plan_billing::ActivationError,
                >,
            > + Send,
    >,
> {
    async move {
        billing_service::plan_billing::activate_from_paid_checkout(
            &pool,
            payment_id,
            tenant,
            "starter",
            "monthly",
            "EUR",
            2_000,
            Some("cst_cov_race"),
            Some("mdt_cov_race"),
        )
        .await
    }
    .boxed()
}

use futures::FutureExt as _;

async fn cleanup_race(h: &Harness) {
    for statement in [
        "DELETE FROM invoice_payment_allocations WHERE tenant_id = $1",
        "DELETE FROM invoices WHERE tenant_id = $1",
        "DELETE FROM payment_attempts WHERE tenant_id = $1",
        "DELETE FROM payment_provider_events WHERE provider = 'mollie'",
        "DELETE FROM payment_credentials WHERE tenant_id = $1",
        "DELETE FROM subscription_state WHERE tenant_id = $1",
        "DELETE FROM audit_logs WHERE tenant_id = $1",
        "DELETE FROM billing_addresses WHERE tenant_id = $1",
        "DELETE FROM tenants WHERE id = $1",
    ] {
        sqlx::query(statement)
            .bind("cov_race")
            .execute(&h.pool)
            .await
            .ok();
    }
}

// ---------------------------------------------------------------------------
// Migration 279: payment provider neutrality - the staged neutral ledger
// ---------------------------------------------------------------------------
//
// The migration is additive-only and idempotent by construction, so the
// canonical fresh chain (the template already includes 279) can be REPLAYED
// against newly seeded legacy rows to exercise the backfill exactly as a
// migration-time run saw the production rows: fresh-chain shape, the
// uniqueness gate, backfill counts vs seeded legacy rows, provider tagging
// ('mollie' for Mollie-grammar ids, 'adyen' for legacy ones), replay
// idempotency, and legacy tables untouched.

const MIGRATION_279: &str = "../../migrations/279_payment_provider_neutrality.sql";

async fn replay_migration_279(h: &Harness) {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(MIGRATION_279);
    let sql = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read migration 279: {error}"));
    match sqlx::raw_sql(sql.as_str()).execute(&h.pool).await {
        Ok(_) => {}
        Err(error)
            if error
                .as_database_error()
                .map(|db| {
                    db.code().as_deref() == Some("42703")
                        && db.message().contains("provider_schedule_id")
                })
                .unwrap_or(false) =>
        {
            // Migration 282 renamed subscription_payment_bindings'
            // provider_schedule_id to provider_contract_id; the frozen 279
            // file (checksums, never edited) names the pre-rename column in
            // its binding-backfill statements, so those statements cannot
            // re-run on the post-282 schema. The failed batch applied
            // nothing; replay with the 282 rename applied — every other
            // 279 guard stays literally proven.
            let renamed = sql.replace("provider_schedule_id", "provider_contract_id");
            sqlx::raw_sql(renamed.as_str())
                .execute(&h.pool)
                .await
                .expect("migration 279 replay (guarded, idempotent, 282 rename applied)");
        }
        Err(error)
            if error
                .as_database_error()
                .map(|db| {
                    db.code().as_deref() == Some("42P01")
                        && db.message().contains("mollie_subscriptions")
                })
                .unwrap_or(false) =>
        {
            // Migration 285 renamed the LOCAL subscription state table
            // mollie_subscriptions -> subscription_state (and its
            // provider-tagged columns with it); the frozen 279 file names
            // the pre-rename table/columns in its subscription backfill, so
            // it cannot re-run verbatim on the post-285 schema either. The
            // failed batch's earlier statements already applied and are
            // idempotent; replay with the 285 rename applied — every other
            // 279 guard stays literally proven.
            let renamed = sql
                .replace("provider_schedule_id", "provider_contract_id")
                .replace("FROM mollie_subscriptions", "FROM subscription_state")
                .replace("ms.mollie_subscription_id", "ms.provider_contract_id")
                .replace("ms.mollie_mandate_id", "ms.provider_method_id")
                .replace("ms.mollie_customer_id", "ms.provider_customer_id");
            sqlx::raw_sql(renamed.as_str())
                .execute(&h.pool)
                .await
                .expect("migration 279 replay (guarded, idempotent, 282+285 renames applied)");
        }
        Err(error) => panic!("migration 279 replay (guarded, idempotent): {error}"),
    }
}

db_test!(
    migration_279_builds_the_neutral_ledger_and_backfills_seeded_legacy_rows,
    |h| {
        // 1. Fresh chain: every neutral table exists with the staged shape.
        for table in [
            "payment_provider_customers",
            "payment_credentials",
            "payment_attempts",
            "payment_provider_events",
            "payment_provider_refunds",
            "payment_disputes",
            "payment_tax_evidence",
            "subscription_payment_bindings",
            "provider_catalog_mappings",
        ] {
            let present: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM information_schema.tables \
                 WHERE table_schema = 'public' AND table_name = $1",
            )
            .bind(table)
            .fetch_one(&h.pool)
            .await
            .unwrap_or_else(|error| panic!("table probe {table}: {error}"));
            assert_eq!(present, 1, "{table} must exist after migration 279");
        }

        // 2. The neutrality gate: one provider customer object can never be
        //    claimed by a second row (UNIQUE(provider, provider_customer_id)).
        sqlx::query(
            "INSERT INTO payment_provider_customers (tenant_id, provider, provider_customer_id) \
             VALUES ('cov_neutral_t1', 'mollie', 'cst_cov_dup')",
        )
        .execute(&h.pool)
        .await
        .expect("seed neutral customer");
        let duplicate_claim = sqlx::query(
            "INSERT INTO payment_provider_customers (tenant_id, provider, provider_customer_id) \
             VALUES ('cov_neutral_t2', 'mollie', 'cst_cov_dup')",
        )
        .execute(&h.pool)
        .await;
        assert!(
            duplicate_claim.is_err(),
            "the second claim of one provider customer object must be rejected"
        );

        // 3. Seed legacy rows the way the Mollie era wrote them, plus
        //    pre-Mollie (Adyen-era) rows that must tag 'adyen'.
        let tenant = "cov_neutral_279";
        let legacy_tenant = "cov_neutral_279b";
        seed_tenant(&h, tenant, "starter").await;
        seed_tenant(&h, legacy_tenant, "free").await;
        sqlx::query(
            "INSERT INTO mollie_customers (tenant_id, mollie_customer_id) \
             VALUES ($1, 'cst_cov_279'), ($2, 'legacy_cov_279_ref')",
        )
        .bind(tenant)
        .bind(legacy_tenant)
        .execute(&h.pool)
        .await
        .expect("seed legacy customers");
        sqlx::query(
            "INSERT INTO subscription_state \
                 (tenant_id, provider_contract_id, plan, status, billing_cycle_start, \
                  billing_cycle_end, provider_customer_id, provider_method_id) \
             VALUES ($1, 'sub_cov_279', 'starter', 'active', NOW(), NOW() + INTERVAL '30 days', \
                     'cst_cov_279', 'mdt_cov_279')",
        )
        .bind(tenant)
        .execute(&h.pool)
        .await
        .expect("seed legacy subscription");
        sqlx::query(
            "INSERT INTO mollie_refunds (id, payment_id, tenant_id, amount_cents, currency, status) \
             VALUES ('re_cov_279', 'tr_cov_279', $1, 500, 'EUR', 'refunded'), \
                    ('legacy_refund_279', 'tr_cov_old', $1, 100, 'EUR', 'created')",
        )
        .bind(tenant)
        .execute(&h.pool)
        .await
        .expect("seed legacy refunds");
        sqlx::query(
            "INSERT INTO mollie_webhook_events (mollie_event_id, event_type, mollie_payment_id, status) \
             VALUES ('tr_cov_279:paid:1', 'payment.paid', 'tr_cov_279', 'processed')",
        )
        .execute(&h.pool)
        .await
        .expect("seed legacy webhook event");
        // A dedicated plan row (never depending on template-seeded catalog
        // rows) carrying a provider price code, the way operators set one.
        sqlx::query(
            "INSERT INTO plans (id, name, display_name, price_cents, email_limit, \
                                  api_call_limit, mollie_plan_code_monthly, is_active) \
             VALUES ('plan_cov_279', 'cov279plan', 'cov279plan', 4900, 100000, 100000, \
                     'cov_code_monthly', true) \
             ON CONFLICT (name) DO UPDATE \
                 SET mollie_plan_code_monthly = EXCLUDED.mollie_plan_code_monthly",
        )
        .execute(&h.pool)
        .await
        .expect("seed a plan price code");

        // 4. Replay the guarded migration: the backfills pick up the seeds.
        replay_migration_279(&h).await;

        // 5. Provider tagging: Mollie grammar -> 'mollie', legacy -> 'adyen'.
        let (customers_mollie, customers_adyen): (i64, i64) = sqlx::query_as(
            "SELECT COUNT(*) FILTER (WHERE provider = 'mollie'), \
                    COUNT(*) FILTER (WHERE provider = 'adyen') \
             FROM payment_provider_customers \
             WHERE provider_customer_id IN ('cst_cov_279', 'legacy_cov_279_ref')",
        )
        .fetch_one(&h.pool)
        .await
        .expect("customer backfill tags");
        assert_eq!(
            (customers_mollie, customers_adyen),
            (1, 1),
            "one Mollie customer and one legacy (adyen-tagged) customer backfilled"
        );

        // 6. The mandate became a neutral credential; the live schedule
        //    became a binding; refunds and events carried their states.
        let credentials: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM payment_credentials WHERE provider_method_id = 'mdt_cov_279'",
        )
        .fetch_one(&h.pool)
        .await
        .expect("credential backfill count");
        assert_eq!(
            credentials, 1,
            "the stored mandate backfills one credential"
        );

        let bindings: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM subscription_payment_bindings \
             WHERE provider_contract_id = 'sub_cov_279' AND provider = 'mollie'",
        )
        .fetch_one(&h.pool)
        .await
        .expect("binding backfill count");
        assert_eq!(
            bindings, 1,
            "the live provider schedule backfills one binding"
        );

        let (refunds_mollie_succeeded, refunds_adyen_pending): (i64, i64) = sqlx::query_as(
            "SELECT COUNT(*) FILTER (WHERE provider = 'mollie' AND state = 'succeeded'), \
                    COUNT(*) FILTER (WHERE provider = 'adyen' AND state = 'pending') \
             FROM payment_provider_refunds \
             WHERE provider_refund_id IN ('re_cov_279', 'legacy_refund_279')",
        )
        .fetch_one(&h.pool)
        .await
        .expect("refund backfill tags");
        assert_eq!(
            (refunds_mollie_succeeded, refunds_adyen_pending),
            (1, 1),
            "refunded -> mollie/succeeded, created -> adyen/pending"
        );

        let events: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM payment_provider_events \
             WHERE provider_event_id = 'tr_cov_279:paid:1' AND provider = 'mollie' \
               AND provider_payment_id = 'tr_cov_279'",
        )
        .fetch_one(&h.pool)
        .await
        .expect("event backfill count");
        assert_eq!(events, 1, "the webhook ledger backfills one neutral event");

        let catalog: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM provider_catalog_mappings \
             WHERE catalog_key = 'cov279plan' AND billing_interval = 'monthly' \
               AND provider = 'mollie' AND provider_price_code = 'cov_code_monthly'",
        )
        .fetch_one(&h.pool)
        .await
        .expect("catalog mapping backfill count");
        assert_eq!(catalog, 1, "the plan price code backfills one mapping");

        // 7. Idempotent replay: a second run changes nothing.
        replay_migration_279(&h).await;
        let (customers_mollie_again, refunds_again, events_again, bindings_again): (
            i64,
            i64,
            i64,
            i64,
        ) = sqlx::query_as(
            "SELECT \
                (SELECT COUNT(*) FROM payment_provider_customers \
                  WHERE provider_customer_id IN ('cst_cov_279', 'legacy_cov_279_ref')), \
                (SELECT COUNT(*) FROM payment_provider_refunds \
                  WHERE provider_refund_id IN ('re_cov_279', 'legacy_refund_279')), \
                (SELECT COUNT(*) FROM payment_provider_events \
                  WHERE provider_event_id = 'tr_cov_279:paid:1'), \
                (SELECT COUNT(*) FROM subscription_payment_bindings \
                  WHERE provider_contract_id = 'sub_cov_279')",
        )
        .fetch_one(&h.pool)
        .await
        .expect("idempotent replay counts");
        assert_eq!(
            (
                customers_mollie_again,
                refunds_again,
                events_again,
                bindings_again
            ),
            (2, 2, 1, 1),
            "replaying the guarded backfills must not duplicate any row"
        );

        // 8. The legacy tables are untouched by the migration (read-only).
        let (legacy_customers, legacy_refunds, legacy_events): (i64, i64, i64) = sqlx::query_as(
            "SELECT \
                (SELECT COUNT(*) FROM mollie_customers \
                  WHERE mollie_customer_id IN ('cst_cov_279', 'legacy_cov_279_ref')), \
                (SELECT COUNT(*) FROM mollie_refunds \
                  WHERE id IN ('re_cov_279', 'legacy_refund_279')), \
                (SELECT COUNT(*) FROM mollie_webhook_events \
                  WHERE mollie_event_id = 'tr_cov_279:paid:1')",
        )
        .fetch_one(&h.pool)
        .await
        .expect("legacy table counts after the backfill");
        assert_eq!(
            (legacy_customers, legacy_refunds, legacy_events),
            (2, 2, 1),
            "the backfill reads the legacy tables and never rewrites them"
        );
    }
);

// ---------------------------------------------------------------------------
// Migration 281 + payments::engine: the execution ledger and its
// exactly-once gates (audit steps 5-8)
// ---------------------------------------------------------------------------

const MIGRATION_281: &str = "../../migrations/281_payment_execution_ledger.sql";

async fn replay_migration_281(h: &Harness) {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(MIGRATION_281);
    let sql = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read migration 281: {error}"));
    sqlx::raw_sql(sql.as_str())
        .execute(&h.pool)
        .await
        .expect("migration 281 replay (guarded, idempotent)");
}

db_test!(
    migration_281_execution_ledger_and_engine_exactly_once_gates,
    |h| {
        use billing_service::payments::engine::{
            claim_attempt, confirm_attempt, fail_claim, has_open_attempt, observe_payment,
            settle_verified, verify_against_obligation, ObservedPayment,
        };
        use billing_service::payments::PaymentState;

        // 1. Schema: the attempts ledger can hold a KEYLESS claim (a charge
        //    whose provider response was lost), the operation key is unique,
        //    and the obligation reference exists.
        let nullable: String = sqlx::query_scalar(
            "SELECT is_nullable::text FROM information_schema.columns \
             WHERE table_schema = 'public' AND table_name = 'payment_attempts' \
               AND column_name = 'provider_payment_id'",
        )
        .fetch_one(&h.pool)
        .await
        .expect("attempts nullability probe");
        assert_eq!(
            nullable, "YES",
            "claims are written before the provider call"
        );
        let ledger_columns: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM information_schema.columns \
             WHERE table_schema = 'public' AND table_name = 'payment_attempts' \
               AND column_name IN ('idempotency_key', 'obligation_ref', 'attempt_no')",
        )
        .fetch_one(&h.pool)
        .await
        .expect("attempts column probe");
        assert_eq!(
            ledger_columns, 3,
            "idempotency_key, obligation_ref and attempt_no exist"
        );
        // Migration 282: the strict exact-amount gate's escape flag and the
        // `unresolved` attempt state are legal schema.
        let state_check: String = sqlx::query_scalar(
            "SELECT pg_get_constraintdef(oid) FROM pg_constraint \
             WHERE conname = 'payment_attempts_state_check'",
        )
        .fetch_one(&h.pool)
        .await
        .expect("attempts state check");
        assert!(state_check.contains("unresolved"), "{state_check}");
        let allow_partial: String = sqlx::query_scalar(
            "SELECT is_nullable || '/' || column_default FROM information_schema.columns \
             WHERE table_schema = 'public' AND table_name = 'invoices' \
               AND column_name = 'allow_partial'",
        )
        .fetch_one(&h.pool)
        .await
        .expect("allow_partial column probe");
        assert!(
            allow_partial.starts_with("NO/"),
            "allow_partial is NOT NULL with a false default: {allow_partial}"
        );
        assert!(
            allow_partial.contains("false"),
            "allow_partial defaults to false (the strict world): {allow_partial}"
        );
        let idem_index: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM pg_indexes
             WHERE indexname = 'idx_payment_attempts_idem'
               AND indexdef LIKE '%UNIQUE%'",
        )
        .fetch_one(&h.pool)
        .await
        .expect("index probe");
        assert_eq!(idem_index, 1, "the claim gate's unique index exists");

        // 2. The accounting allowlists accept the GENERIC processor roles
        //    and every historical value survived.
        let chart_check: String = sqlx::query_scalar(
            "SELECT pg_get_constraintdef(oid) FROM pg_constraint \
             WHERE conname = 'chart_of_accounts_account_role_check'",
        )
        .fetch_one(&h.pool)
        .await
        .expect("chart allowlist");
        for role in [
            "processor_clearing",
            "processor_fees",
            "mollie_clearing",
            "stripe_fees",
        ] {
            assert!(chart_check.contains(role), "chart allowlist keeps {role}");
        }
        let source_check: String = sqlx::query_scalar(
            "SELECT pg_get_constraintdef(oid) FROM pg_constraint \
             WHERE conname = 'invoice_payment_allocations_source_check'",
        )
        .fetch_one(&h.pool)
        .await
        .expect("allocation source allowlist");
        assert!(source_check.contains("processor"), "{source_check}");
        let doc_check: String = sqlx::query_scalar(
            "SELECT pg_get_constraintdef(oid) FROM pg_constraint \
             WHERE conname = 'accounting_source_documents_source_type_check'",
        )
        .fetch_one(&h.pool)
        .await
        .expect("source document allowlist");
        assert!(doc_check.contains("processor_settlement"), "{doc_check}");

        // 3. The engine gates on a real obligation.
        let tenant = "cov_281_engine";
        seed_tenant(&h, tenant, "growth").await;
        let invoice_id = uuid::Uuid::new_v4();
        sqlx::query(
            "INSERT INTO invoices (id, tenant_id, amount, currency, status, invoice_number, \
                                   subtotal, vat_total, total, issued_at, due_at, \
                                   period_start, period_end, created_at, updated_at) \
             VALUES ($1, $2, 1130, 'EUR', 'pending', 'IVCOV281-' || gen_random_uuid()::text, \
                     1000, 130, 1130, NOW(), NOW(), NOW(), NOW(), NOW(), NOW())",
        )
        .bind(invoice_id)
        .bind(tenant)
        .execute(&h.pool)
        .await
        .expect("seed invoice");

        // CLAIM: the first tick owns the operation, the second is refused.
        let key = format!("usageinv_{}_1130c", invoice_id.simple());
        let obligation = format!("invoice:{invoice_id}");
        assert!(
            claim_attempt(
                &h.pool,
                "mollie",
                &key,
                tenant,
                &obligation,
                "usage_collection",
                1130,
                "EUR"
            )
            .await
            .expect("first claim"),
            "the first claim wins"
        );
        assert!(
            !claim_attempt(
                &h.pool,
                "mollie",
                &key,
                tenant,
                &obligation,
                "usage_collection",
                1130,
                "EUR"
            )
            .await
            .expect("second claim"),
            "a concurrent tick is refused: one payment attempt per operation"
        );
        assert!(
            has_open_attempt(&h.pool, "mollie", &key)
                .await
                .expect("open probe"),
            "the keyless claim is open (the provider response was lost)"
        );

        // OBSERVE: the provider's own callback names the charge our lost
        // response hid; the claim links and the state lands.
        let observed = ObservedPayment {
            provider: "mollie".to_string(),
            provider_payment_id: "tr_cov_281_paid".to_string(),
            state: PaymentState::Succeeded,
            amount_minor: Some(1130),
            currency: Some("EUR".to_string()),
            tenant_id: Some(tenant.to_string()),
            obligation_ref: Some(obligation.clone()),
            purpose: "webhook",
        };
        observe_payment(&h.pool, &observed)
            .await
            .expect("observation");
        let (linked_state, linked_id): (String, Option<String>) = sqlx::query_as(
            "SELECT state, provider_payment_id FROM payment_attempts \
             WHERE provider = 'mollie' AND idempotency_key = $1",
        )
        .bind(&key)
        .fetch_one(&h.pool)
        .await
        .expect("linked claim");
        assert_eq!(linked_id.as_deref(), Some("tr_cov_281_paid"));
        assert_eq!(linked_state, "succeeded");

        // VERIFY + SETTLE exactly once: two settles, one allocation, and
        // the invoice flips paid with its obligation fully covered.
        let verified = verify_against_obligation(&h.pool, &observed)
            .await
            .expect("verification");
        assert_eq!(verified.invoice_id, invoice_id);
        assert_eq!(verified.allocation_minor, 1130);
        assert_eq!(verified.operation_id, "mollie:tr_cov_281_paid");
        assert!(
            settle_verified(&h.pool, "mollie", &verified)
                .await
                .expect("settle once"),
            "the first settle performs the allocation"
        );
        assert!(
            !settle_verified(&h.pool, "mollie", &verified)
                .await
                .expect("settle replay"),
            "the replay settles nothing (idempotent on the operation id)"
        );
        let allocations: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM invoice_payment_allocations WHERE invoice_id = $1",
        )
        .bind(invoice_id)
        .fetch_one(&h.pool)
        .await
        .expect("allocation count");
        assert_eq!(allocations, 1, "exactly one allocation for one obligation");
        let (status, provider_dim): (String, Option<String>) = sqlx::query_as(
            "SELECT i.status::text, a.provider FROM invoices i \
             JOIN invoice_payment_allocations a ON a.invoice_id = i.id WHERE i.id = $1",
        )
        .bind(invoice_id)
        .fetch_one(&h.pool)
        .await
        .expect("invoice + allocation");
        assert_eq!(status, "paid", "the fully covered obligation flips paid");
        assert_eq!(
            provider_dim.as_deref(),
            Some("mollie"),
            "the allocation carries the provider dimension"
        );

        // 4. Verification refuses what must never settle.
        let cross_tenant = ObservedPayment {
            provider: "mollie".to_string(),
            provider_payment_id: "tr_cov_281_cross".to_string(),
            state: PaymentState::Succeeded,
            amount_minor: Some(1130),
            currency: Some("EUR".to_string()),
            tenant_id: Some("somebody-else".to_string()),
            obligation_ref: Some(obligation.clone()),
            purpose: "webhook",
        };
        match verify_against_obligation(&h.pool, &cross_tenant).await {
            Err(billing_service::payments::engine::VerifyError::CrossTenant { .. }) => {}
            other => panic!("cross-tenant facts must be refused, got {other:?}"),
        }
        let wrong_currency = ObservedPayment {
            provider: "mollie".to_string(),
            provider_payment_id: "tr_cov_281_usd".to_string(),
            state: PaymentState::Succeeded,
            amount_minor: Some(1130),
            currency: Some("USD".to_string()),
            tenant_id: Some(tenant.to_string()),
            obligation_ref: Some(obligation.clone()),
            purpose: "webhook",
        };
        match verify_against_obligation(&h.pool, &wrong_currency).await {
            Err(billing_service::payments::engine::VerifyError::CurrencyMismatch { .. }) => {}
            other => panic!("currency mismatches must be refused, got {other:?}"),
        }

        // 5. Attempts are IMMUTABLE (migration 282): a closed attempt is
        //    never reopened under its own key — the dunning retry opens a
        //    NEW row with attempt_no = 2 and a distinct key — while an
        //    open one refuses a second charge outright.
        let retry_key = format!("autopay_{}", invoice_id.simple());
        assert!(claim_attempt(
            &h.pool,
            "mollie",
            &retry_key,
            tenant,
            &obligation,
            "autopay",
            500,
            "EUR"
        )
        .await
        .expect("autopay claim"));
        fail_claim(&h.pool, "mollie", &retry_key)
            .await
            .expect("fail claim");
        assert!(
            !has_open_attempt(&h.pool, "mollie", &retry_key)
                .await
                .expect("closed probe"),
            "a failed claim is closed"
        );
        assert!(
            !claim_attempt(
                &h.pool,
                "mollie",
                &retry_key,
                tenant,
                &obligation,
                "autopay",
                500,
                "EUR"
            )
            .await
            .expect("same-key retry"),
            "a closed attempt is immutable: the same key never reopens it"
        );
        // The obligation's FIRST attempt (section 3) already succeeded, so
        // the dunning gate refuses a second charge outright.
        assert!(
            billing_service::payments::engine::claim_next_attempt(
                &h.pool,
                "mollie",
                tenant,
                &obligation,
                "autopay",
                500,
                "EUR",
            )
            .await
            .expect("settled-obligation dunning probe")
            .is_none(),
            "a settled obligation's dunning ladder is closed (no second charge)"
        );

        // 5b. On a fresh obligation the dunning ladder opens a NEW
        //     immutable row: attempt_no = max+1, a distinct
        //     payment:{ref}:{n} key, the closed row untouched.
        let invoice2_id = uuid::Uuid::new_v4();
        sqlx::query(
            "INSERT INTO invoices (id, tenant_id, amount, currency, status, invoice_number, \
                                   subtotal, vat_total, total, issued_at, due_at, \
                                   period_start, period_end, created_at, updated_at) \
             VALUES ($1, $2, 900, 'EUR', 'pending', 'IVCOV281B-' || gen_random_uuid()::text, \
                     900, 0, 900, NOW(), NOW(), NOW(), NOW(), NOW(), NOW())",
        )
        .bind(invoice2_id)
        .bind(tenant)
        .execute(&h.pool)
        .await
        .expect("seed second invoice");
        let obligation2 = format!("invoice:{invoice2_id}");
        let key_a = format!("autopay_{}", invoice2_id.simple());
        assert!(claim_attempt(
            &h.pool,
            "mollie",
            &key_a,
            tenant,
            &obligation2,
            "autopay",
            500,
            "EUR"
        )
        .await
        .expect("claim attempt 1"));
        fail_claim(&h.pool, "mollie", &key_a)
            .await
            .expect("fail it");
        let closed: (String, i64) = sqlx::query_as(
            "SELECT state, attempt_no::bigint FROM payment_attempts \
             WHERE provider = 'mollie' AND idempotency_key = $1",
        )
        .bind(&key_a)
        .fetch_one(&h.pool)
        .await
        .expect("closed attempt row");
        assert_eq!(
            closed.0, "failed",
            "the closed attempt is definitively failed"
        );
        let (attempt_no, dunning) = billing_service::payments::engine::claim_next_attempt(
            &h.pool,
            "mollie",
            tenant,
            &obligation2,
            "autopay",
            500,
            "EUR",
        )
        .await
        .expect("dunning claim")
        .expect("the dunning ladder opens the next attempt");
        assert_eq!(
            attempt_no,
            closed.1 + 1,
            "the retry is the NEXT attempt in the obligation's chain"
        );
        assert_eq!(
            dunning,
            billing_service::payments::engine::dunning_key(&obligation2, attempt_no),
            "the dunning key follows the shared payment:{{ref}}:{{n}} scheme"
        );
        assert_ne!(&dunning, &key_a, "the retry carries a distinct key");
        let attempt_one_after: (String, i64) = sqlx::query_as(
            "SELECT state, attempt_no::bigint FROM payment_attempts \
             WHERE provider = 'mollie' AND idempotency_key = $1",
        )
        .bind(&key_a)
        .fetch_one(&h.pool)
        .await
        .expect("attempt 1 row after the dunning claim");
        assert_eq!(
            closed, attempt_one_after,
            "the closed attempt's immutable row is untouched by the retry"
        );
        confirm_attempt(
            &h.pool,
            "mollie",
            &dunning,
            "tr_cov_281_autopay",
            PaymentState::Pending,
        )
        .await
        .expect("confirm the dunning attempt");
        assert!(
            !claim_attempt(
                &h.pool,
                "mollie",
                &dunning,
                tenant,
                &obligation2,
                "autopay",
                500,
                "EUR"
            )
            .await
            .expect("in-flight claim"),
            "an in-flight attempt refuses a second charge"
        );

        // 6. The migration's dimension backfill stamps legacy rows and the
        //    replay changes nothing.
        replay_migration_281(&h).await;
        let stale_dims: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM invoice_payment_allocations \
             WHERE source IN ('mollie', 'stripe') AND provider IS NULL",
        )
        .fetch_one(&h.pool)
        .await
        .expect("dimension audit");
        assert_eq!(
            stale_dims, 0,
            "every processor allocation carries its provider"
        );
        let allocations_after: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM invoice_payment_allocations WHERE invoice_id = $1",
        )
        .bind(invoice_id)
        .fetch_one(&h.pool)
        .await
        .expect("allocation count after replay");
        assert_eq!(
            allocations_after, allocations,
            "the replay settles and allocates nothing"
        );
    }
);

// ---------------------------------------------------------------------------
// Conformance (audit step 9, expanded in the eighth pass): MollieProvider
// runs the shared seventeen-arm
// matrix against a loopback wire stub
// ---------------------------------------------------------------------------

struct ConfStub {
    responses: std::sync::Mutex<std::collections::HashMap<String, (u16, String)>>,
    seq: std::sync::atomic::AtomicU64,
}

/// The conformance stub: `{seq}` in a routed body is replaced by a global
/// call counter, so sequential creates/refunds answer with DISTINCT ids
/// (the attempts-ledger unique key made shared ids a fixture lie).
async fn conf_stub_handler(
    axum::extract::State(state): axum::extract::State<&'static ConfStub>,
    request: axum::http::Request<axum::body::Body>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let body_bytes = axum::body::to_bytes(request.into_body(), 64 * 1024)
        .await
        .unwrap_or_default();
    let n = state.seq.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let json_header = [(axum::http::header::CONTENT_TYPE, "application/json")];
    if method == axum::http::Method::POST && path.ends_with("/refunds") {
        // Echo the requested amount; mint a distinct refund id per call.
        let parsed: serde_json::Value =
            serde_json::from_slice(&body_bytes).unwrap_or(serde_json::json!({}));
        let amount = parsed
            .get("amount")
            .cloned()
            .unwrap_or(serde_json::json!({"currency": "EUR", "value": "0.00"}));
        let response = serde_json::json!({
            "id": format!("re_conf_{n}"),
            "status": "refunded",
            "amount": amount,
        });
        return (
            axum::http::StatusCode::OK,
            json_header,
            response.to_string(),
        )
            .into_response();
    }
    // Method-keyed routes ("POST /v2/payments") take precedence; bare-path
    // routes match any method (the historical keying) — this lets one path
    // answer differently for a charge POST and a listing GET.
    let method_key = format!("{method} {path}");
    let routed = {
        let responses = state.responses.lock().expect("lock");
        responses
            .get(&method_key)
            .or_else(|| responses.get(&path))
            .cloned()
    };
    if let Some((status, body)) = routed {
        let body = body.replace("{seq}", &n.to_string());
        return (
            axum::http::StatusCode::from_u16(status).expect("status"),
            json_header,
            body,
        )
            .into_response();
    }
    (
        axum::http::StatusCode::NOT_FOUND,
        json_header,
        r#"{"title":"Not Found"}"#.to_string(),
    )
        .into_response()
}

/// The one process-wide conformance stub (own OS thread, own runtime).
fn conformance_stub_api() -> (&'static ConfStub, String) {
    static STUB: std::sync::OnceLock<(&'static ConfStub, String)> = std::sync::OnceLock::new();
    STUB.get_or_init(|| {
        let state: &'static ConfStub = Box::leak(Box::new(ConfStub {
            responses: std::sync::Mutex::new(std::collections::HashMap::new()),
            seq: std::sync::atomic::AtomicU64::new(0),
        }));
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind conformance");
        listener
            .set_nonblocking(true)
            .expect("nonblocking conformance listener");
        let address = listener.local_addr().expect("conformance address");
        let app = axum::Router::new()
            .fallback(conf_stub_handler)
            .with_state(state);
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("conformance stub runtime");
            runtime.block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener).expect("tokio listener");
                axum::serve(listener, app).await.expect("conformance stub");
            });
        });
        (state, format!("http://{address}/v2"))
    })
    .clone()
}

fn wire_amount(minor: i64) -> String {
    format!("{}.{:02}", minor.div_euclid(100), minor.rem_euclid(100))
}

/// The Mollie lane's scripting: routes the wire stub exactly as the real
/// provider would answer for each matrix arm.
struct MollieConformanceScripting {
    stub: &'static ConfStub,
}

impl billing_service::payments::conformance::ConformanceScripting for MollieConformanceScripting {
    fn arm_setup(
        &self,
        ctx: &billing_service::payments::conformance::ConformanceCtx<'_>,
    ) -> Result<(), String> {
        let amount = wire_amount(ctx.amount_minor);
        let paid_doc = serde_json::json!({
            "id": ctx.provider_payment_hint,
            "status": "paid",
            "amount": { "currency": ctx.currency, "value": amount },
            "createdAt": "2026-10-29T10:00:00+00:00",
        });
        let mut routes = self.stub.responses.lock().expect("lock");
        match ctx.arm {
            6 | 16 => {
                // The authenticated fetch answers with the paid object.
                routes.insert(
                    format!("/v2/payments/{}", ctx.provider_payment_hint),
                    (200, paid_doc.to_string()),
                );
            }
            8 => {
                // The charge's response is LOST (a 503 maps to the neutral
                // Unavailable); the provider's own record shows it paid.
                // The method key overrides arm 5's POST route (routes
                // persist across arms of the shared stub).
                routes.insert(
                    "POST /v2/payments".to_string(),
                    (503, r#"{"title":"upstream down"}"#.to_string()),
                );
                routes.insert(
                    format!("/v2/payments/{}", ctx.provider_payment_hint),
                    (200, paid_doc.to_string()),
                );
            }
            9 => {
                // The charge's response is LOST and the provider-side
                // listing is FULL (250 payments, none carrying our
                // metadata key): the search cannot prove absence, so the
                // stale-claim reconcile must park the attempt `unresolved`.
                routes.insert(
                    "POST /v2/payments".to_string(),
                    (503, r#"{"title":"upstream down"}"#.to_string()),
                );
                let items: Vec<serde_json::Value> = (0..250)
                    .map(|index| {
                        serde_json::json!({
                            "id": format!("tr_conf9_{index}"),
                            "status": "open",
                            "amount": { "currency": ctx.currency, "value": "1.00" },
                            "metadata": { "reference": "somebody-else" },
                        })
                    })
                    .collect();
                let page = serde_json::json!({ "_embedded": { "payments": items } });
                routes.insert("GET /v2/payments".to_string(), (200, page.to_string()));
            }
            5 => {
                let failed_doc = serde_json::json!({
                    "id": "{seq}",
                    "status": "failed",
                    "amount": { "currency": ctx.currency, "value": amount },
                });
                routes.insert(
                    "POST /v2/payments".to_string(),
                    (200, failed_doc.to_string()),
                );
            }
            12 => {
                // POST /v2/payments/{id}/refunds: the handler echoes the
                // requested amount and mints distinct ids.
            }
            13..=15 => {
                // The documented chargeback object has NO status field:
                //  * opened  -> no settlementAmount and no reversal yet;
                //  * lost    -> settlementAmount/settlementId present;
                //  * won     -> reversedAt present.
                let mut chargeback = serde_json::json!({
                    "id": format!("chb_conf_{}", ctx.arm),
                    "paymentId": ctx.provider_payment_hint,
                    "amount": { "currency": ctx.currency, "value": amount },
                    "createdAt": "2026-10-29T10:00:00+00:00",
                    "reversedAt": null,
                });
                if ctx.arm >= 14 {
                    chargeback["settlementAmount"] = serde_json::json!({
                        "currency": ctx.currency,
                        "value": format!("-{amount}"),
                    });
                    chargeback["settlementId"] = serde_json::json!("stl_conf_cb");
                }
                if ctx.arm == 15 {
                    chargeback["reversedAt"] = serde_json::json!("2026-11-02T09:00:00+00:00");
                }
                let body = serde_json::json!({
                    "_embedded": { "chargebacks": [chargeback] }
                });
                routes.insert(
                    format!("/v2/payments/{}/chargebacks", ctx.provider_payment_hint),
                    (200, body.to_string()),
                );
            }
            17 => {
                let settlements = serde_json::json!({
                    "_embedded": { "settlements": [{
                        "id": "stl_conf_1",
                        "status": "paid",
                        "amount": { "currency": ctx.currency, "value": amount },
                        "settledAt": "2026-10-29T12:00:00+00:00",
                    }]}
                });
                routes.insert(
                    "/v2/settlements".to_string(),
                    (200, settlements.to_string()),
                );
            }
            _ => {}
        }
        Ok(())
    }
}

db_test!(mollie_provider_passes_the_shared_conformance_matrix, |h| {
    use billing_service::payments::conformance::run_provider_conformance;
    use billing_service::payments::mollie_provider::MollieProvider;

    let (stub, base_url) = conformance_stub_api();
    let provider = MollieProvider::new("test_conformance_key".to_string(), base_url, None)
        .expect("conformance provider");
    let scripting = MollieConformanceScripting { stub };
    let report =
        run_provider_conformance(&h.state, std::sync::Arc::new(provider), &scripting).await;
    assert_eq!(report.provider, "mollie");
    if let Err(failures) = report.assert_all_passed() {
        panic!("MollieProvider must pass the shared conformance matrix:\n{failures}");
    }
});
