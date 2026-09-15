//! Adversarial tests for the analytics crate: ClickHouse query building with
//! hostile filters, the QueryEngine facade, reconciliation arithmetic,
//! churn/send-time model edges, and reply-tracking dedupe.
//!
//! ClickHouse is skipped only when `CLICKHOUSE_TEST_URL` is unset; a
//! configured-but-unreachable server PANICS (workspace convention).  The
//! Postgres tests use `TEST_DATABASE_URL` the same way.

use analytics::churn_prediction::ChurnPredictionEngine;
use analytics::clickhouse_engine::{ClickHouseEngine, ClickHouseEvent};
use analytics::config::ClickHouseConfig;
use analytics::query_engine::QueryEngine;
use analytics::reconciliation::ReconciliationWorker;
use analytics::send_time_optimizer::SendTimeOptimizer;
use analytics::types::{AnalyticsQuery, RiskTier};
use chrono::{TimeDelta, Utc};
use sqlx::PgPool;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Infrastructure
// ---------------------------------------------------------------------------

fn clickhouse_config(database: &str) -> Option<ClickHouseConfig> {
    let url = std::env::var("CLICKHOUSE_TEST_URL").ok()?;
    if url.trim().is_empty() {
        return None;
    }
    Some(ClickHouseConfig {
        url,
        database: database.to_string(),
        user: std::env::var("CLICKHOUSE_TEST_USER").unwrap_or_else(|_| "default".into()),
        password: std::env::var("CLICKHOUSE_TEST_PASSWORD").unwrap_or_default(),
        max_connections: 5,
        query_timeout_secs: 30,
        insert_timeout_seconds: 30,
        tls_enabled: false,
        ca_cert_path: String::new(),
    })
}

/// Build a ClickHouse engine against a freshly created `apexmail_test`
/// database. Panics when the server is configured but unreachable.
async fn clickhouse_engine() -> Option<ClickHouseEngine> {
    let Some(config) = clickhouse_config("apexmail_test") else {
        eprintln!("skipping: CLICKHOUSE_TEST_URL is not configured");
        return None;
    };
    let bootstrap = clickhouse::Client::default()
        .with_url(&config.url)
        .with_user(&config.user)
        .with_database("default");
    let bootstrap = if config.password.is_empty() {
        bootstrap
    } else {
        bootstrap.with_password(&config.password)
    };
    bootstrap
        .query("CREATE DATABASE IF NOT EXISTS apexmail_test")
        .execute()
        .await
        .unwrap_or_else(|error| {
            panic!(
                "CLICKHOUSE_TEST_URL is configured but unreachable at {}: {error}",
                config.url
            )
        });
    Some(
        ClickHouseEngine::new(config)
            .await
            .expect("ClickHouse engine init"),
    )
}

/// Each DB test provisions its own canonical database (private per test AND
/// process id — a shared name has raced before).
async fn pg_pool(test_name: &str) -> Option<PgPool> {
    match migrator::test_support::fresh_canonical_pool(
        "analytics_adversarial",
        &format!("analytics_adv_{test_name}_{}", std::process::id()),
    )
    .await
    {
        Ok(pool) => pool,
        Err(error) => panic!("{}", error.panic_message()),
    }
}

async fn redis_pool() -> Option<deadpool_redis::Pool> {
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

fn ch_event(
    tenant: &str,
    message: &str,
    event_type: &str,
    recipient: &str,
    at: chrono::DateTime<Utc>,
) -> ClickHouseEvent {
    ClickHouseEvent {
        id: Uuid::new_v4().to_string(),
        tenant_id: tenant.to_string(),
        message_id: message.to_string(),
        event_type: event_type.to_string(),
        timestamp: time::OffsetDateTime::from_unix_timestamp(at.timestamp())
            .expect("valid timestamp")
            + time::Duration::nanoseconds(at.timestamp_subsec_nanos() as i64),
        recipient: recipient.to_string(),
        recipient_domain: recipient.split('@').nth(1).unwrap_or("").to_string(),
        link_id: String::new(),
        user_agent: "adversarial".to_string(),
        ip_address: "198.51.100.7".to_string(),
        country: "EE".to_string(),
        device_type: "desktop".to_string(),
        campaign_id: "c-1".to_string(),
        metadata: "{}".to_string(),
    }
}

// ---------------------------------------------------------------------------
// 1. ClickHouse query building with hostile filters
// ---------------------------------------------------------------------------

#[tokio::test]
async fn clickhouse_queries_survive_hostile_filters_and_empty_datasets() {
    let Some(engine) = clickhouse_engine().await else {
        return;
    };
    let tenant = format!("adv_ch_{}", Uuid::new_v4().simple());
    let empty_tenant = format!("adv_empty_{}", Uuid::new_v4().simple());
    let now = Utc::now();
    let start = now - TimeDelta::try_minutes(30).unwrap();
    let end = now + TimeDelta::try_minutes(30).unwrap();

    // Empty dataset edges: every aggregate answers 0/empty, never an error.
    let empty_series = engine
        .time_series(&empty_tenant, start, end, "hour", None)
        .await
        .expect("empty time series");
    assert!(empty_series.is_empty());
    let empty_dims = engine
        .aggregate_by_dimension(&empty_tenant, start, end, "event_type")
        .await
        .expect("empty dimensions");
    assert!(empty_dims.is_empty());
    let empty_metrics = engine
        .deliverability_metrics(&empty_tenant, start, end)
        .await
        .expect("empty metrics");
    assert_eq!(empty_metrics.delivery_rate, 0.0);
    assert_eq!(empty_metrics.bounce_rate, 0.0);
    assert_eq!(empty_metrics.open_rate, 0.0);
    let empty_hist = engine
        .engagement_histogram(&empty_tenant, start, end)
        .await
        .expect("empty histogram");
    assert!(empty_hist.is_empty());
    let empty_stats = engine
        .realtime_stats(&empty_tenant)
        .await
        .expect("empty realtime");
    assert_eq!(empty_stats.this_hour.sent, 0);
    assert_eq!(empty_stats.today.delivered, 0);
    assert_eq!(
        engine
            .event_count(&empty_tenant, start, end)
            .await
            .expect("empty count"),
        0
    );
    let empty_funnel = engine
        .funnel_analysis(&empty_tenant, start, end, &["sent", "delivered"])
        .await
        .expect("empty funnel");
    assert_eq!(empty_funnel.len(), 2);
    assert_eq!(empty_funnel[0].count, 0);
    assert_eq!(empty_funnel[0].percentage, 0.0);

    // Insert a controlled dataset through the real insert path (which also
    // masks IPs at ingest).
    let events = vec![
        ch_event(&tenant, "m1", "sent", "a@x.example", now),
        ch_event(&tenant, "m1", "delivered", "a@x.example", now),
        ch_event(&tenant, "m1", "opened", "a@x.example", now),
        ch_event(&tenant, "m1", "clicked", "a@x.example", now),
        ch_event(&tenant, "m2", "sent", "b@y.example", now),
        ch_event(&tenant, "m2", "bounced", "b@y.example", now),
        ch_event(&tenant, "m2", "complained", "b@y.example", now),
    ];
    engine.insert_events(&events).await.expect("insert");
    // Inserting an empty batch is a no-op, not an error.
    engine.insert_events(&[]).await.expect("empty insert");

    assert_eq!(
        engine
            .event_count(&tenant, start, end)
            .await
            .expect("count"),
        7
    );

    // Hostile event-type filter values are dropped by the allowlist (the
    // valid ones still apply) — no SQL is ever string-interpolated.
    let hostile = vec![
        "'; DROP TABLE events; --".to_string(),
        "sent".to_string(),
        "delivered".to_string(),
    ];
    let filtered = engine
        .time_series(&tenant, start, end, "hour", Some(&hostile))
        .await
        .expect("hostile filter");
    assert_eq!(filtered.len(), 1, "{filtered:?}");
    // sent (m1, m2) + delivered (m1) = 3; the hostile token is inert.
    assert_eq!(filtered[0].value, 3, "sent+delivered only");

    // An all-hostile filter degrades to no filter (all events).
    let all_hostile = vec![
        "nope".to_string(),
        "'; SELECT * FROM system.users".to_string(),
    ];
    let unfiltered = engine
        .time_series(&tenant, start, end, "hour", Some(&all_hostile))
        .await
        .expect("all-hostile filter");
    assert_eq!(unfiltered[0].value, 7);

    // Hostile dimension falls back to event_type.
    let hostile_dims = engine
        .aggregate_by_dimension(&tenant, start, end, "event_type; DROP TABLE events")
        .await
        .expect("hostile dimension");
    assert!(!hostile_dims.is_empty());
    let total: i64 = hostile_dims.iter().map(|row| row.count).sum();
    assert_eq!(total, 7);
    // Percentages sum to ~100 for a single grouping.
    let pct: f64 = hostile_dims.iter().filter_map(|row| row.percentage).sum();
    assert!((pct - 100.0).abs() < 0.01, "{hostile_dims:?}");

    // Hostile funnel stages are filtered; empty/all-invalid stages are empty.
    assert!(engine
        .funnel_analysis(&tenant, start, end, &[])
        .await
        .expect("empty stages")
        .is_empty());
    assert!(engine
        .funnel_analysis(&tenant, start, end, &["'; DROP TABLE events; --"])
        .await
        .expect("hostile stages")
        .is_empty());
    let funnel = engine
        .funnel_analysis(
            &tenant,
            start,
            end,
            &[
                "sent",
                "'; DROP TABLE events; --",
                "delivered",
                "opened",
                "clicked",
            ],
        )
        .await
        .expect("mixed stages");
    assert_eq!(funnel.len(), 5);
    assert_eq!(funnel[1].count, 0, "the hostile stage is inert");
    assert_eq!(funnel[0].count, 2, "two unique sent messages");
    assert_eq!(funnel[2].count, 1);
    // Non-monotonic funnels never exceed 100%.
    assert!(funnel.iter().all(|stage| stage.percentage <= 100.0));

    // Deliverability metrics: exact rates with safe division.
    let metrics = engine
        .deliverability_metrics(&tenant, start, end)
        .await
        .expect("metrics");
    assert!((metrics.delivery_rate - 0.5).abs() < 1e-9, "{metrics:?}");
    assert!((metrics.bounce_rate - 0.5).abs() < 1e-9);
    assert!((metrics.complaint_rate - 0.5).abs() < 1e-9);
    assert!((metrics.open_rate - 1.0).abs() < 1e-9);
    assert!((metrics.click_rate - 1.0).abs() < 1e-9);

    // Histogram + realtime reflect the dataset.
    let histogram = engine
        .engagement_histogram(&tenant, start, end)
        .await
        .expect("histogram");
    let hist_total: i64 = histogram.iter().map(|bucket| bucket.count).sum();
    assert_eq!(hist_total, 2, "two recipients bucketed");

    let realtime = engine.realtime_stats(&tenant).await.expect("realtime");
    assert_eq!(realtime.this_hour.sent, 2);
    assert_eq!(realtime.this_hour.delivered, 1);
    assert_eq!(realtime.today.bounced, 1);

    // Storage stats + health answer on the live server.
    let stats = engine.storage_stats().await.expect("storage stats");
    assert!(stats.total_events >= 7);
    assert!(engine.health_check().await.expect("health"));

    // GDPR: the ingested IP is masked, never the full address.
    let raw = clickhouse::Client::default()
        .with_url(&clickhouse_config("apexmail_test").expect("config").url)
        .with_database("apexmail_test");
    let stored_ip: String = raw
        .query("SELECT ip_address FROM events WHERE tenant_id = ? LIMIT 1")
        .bind(&tenant)
        .fetch_one()
        .await
        .expect("stored ip");
    // IPv4 is truncated to /24 (last octet zeroed), keeping the network.
    assert_eq!(stored_ip, "198.51.100.0", "IPs must be masked at ingest");
}

// ---------------------------------------------------------------------------
// 2. QueryEngine facade delegates (and maps errors)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn query_engine_facade_delegates_every_query() {
    let Some(engine) = clickhouse_engine().await else {
        return;
    };
    let tenant = format!("adv_qe_{}", Uuid::new_v4().simple());
    let now = Utc::now();
    let start = now - TimeDelta::try_minutes(30).unwrap();
    let end = now + TimeDelta::try_minutes(30).unwrap();
    engine
        .insert_events(&[
            ch_event(&tenant, "m1", "sent", "a@x.example", now),
            ch_event(&tenant, "m1", "delivered", "a@x.example", now),
        ])
        .await
        .expect("insert");

    let query_engine = QueryEngine::new(engine);
    let query = AnalyticsQuery {
        tenant_id: tenant.clone(),
        start_date: start,
        end_date: end,
        group_by: Some("hour".to_string()),
        event_types: Some(vec!["sent".to_string()]),
        dimensions: None,
        limit: None,
    };

    let series = query_engine
        .get_time_series(&query)
        .await
        .expect("time series");
    assert_eq!(series.len(), 1);
    assert_eq!(series[0].value, 1);

    // aggregate_by_dimension ignores the event-type filter (its signature
    // has no such parameter): both rows are grouped.
    let aggregation = query_engine
        .get_aggregation(&query, "event_type")
        .await
        .expect("aggregation");
    assert_eq!(aggregation.len(), 2);
    let total: i64 = aggregation.iter().map(|row| row.count).sum();
    assert_eq!(total, 2);

    // The facade uses the fixed stage list (queued→clicked).
    let funnel = query_engine
        .get_funnel_analysis(&query)
        .await
        .expect("funnel");
    assert_eq!(funnel.len(), 5);
    assert_eq!(funnel[0].stage, "queued");
    assert_eq!(funnel[0].count, 0, "no queued event was recorded");
    assert_eq!(funnel[1].stage, "sent");
    assert_eq!(funnel[1].count, 1, "one sent message");

    // Deliverability metrics deliberately ignore the event-type filter
    // (the facade passes no filter): 1 sent, 1 delivered → 100%.
    let metrics = query_engine
        .get_deliverability_metrics(&query)
        .await
        .expect("metrics");
    assert_eq!(metrics.delivery_rate, 1.0);

    let histogram = query_engine
        .get_engagement_histogram(&query)
        .await
        .expect("histogram");
    assert_eq!(histogram.iter().map(|b| b.count).sum::<i64>(), 1);

    let realtime = query_engine
        .get_realtime_stats(&tenant)
        .await
        .expect("realtime");
    assert_eq!(realtime.today.sent, 1);
}

// ---------------------------------------------------------------------------
// 3. Reconciliation: exact-once chain verification
// ---------------------------------------------------------------------------

async fn insert_event(pool: &PgPool, tenant: &str, message_id: &str, event_type: &str) {
    sqlx::query(
        "INSERT INTO events (id, tenant_id, message_id, event_type, recipient, timestamp) \
         VALUES ($1, $2, $3, $4, 'user@example.com', NOW())",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(tenant)
    .bind(message_id)
    .bind(event_type)
    .execute(pool)
    .await
    .expect("event insert");
}

#[tokio::test]
async fn reconciliation_reports_incomplete_chains_and_repairs_them() {
    let Some(pool) = pg_pool("reconciliation").await else {
        return;
    };
    let Some(redis) = redis_pool().await else {
        eprintln!("skipping reconciliation redis assertions: TEST_REDIS_URL unset");
        return;
    };
    let worker = ReconciliationWorker::new(pool.clone(), redis);
    let tag = Uuid::new_v4().simple().to_string();

    // A queued message whose chain never completes: missing sent+delivered.
    let incomplete = format!("adv-msg-incomplete-{tag}");
    insert_event(&pool, "adv-tenant", &incomplete, "queued").await;

    // A complete chain: queued → sent → delivered.
    let complete = format!("adv-msg-complete-{tag}");
    for event_type in ["queued", "sent", "delivered"] {
        insert_event(&pool, "adv-tenant", &complete, event_type).await;
    }

    // A bounced chain is complete (terminal, not a discrepancy).
    let bounced = format!("adv-msg-bounced-{tag}");
    for event_type in ["queued", "sent", "bounced"] {
        insert_event(&pool, "adv-tenant", &bounced, event_type).await;
    }

    let result = worker.run().await.expect("reconciliation run");
    let reported: Vec<&str> = result
        .discrepancies
        .iter()
        .map(|detail| detail.message_id.as_str())
        .collect();
    assert!(reported.contains(&incomplete.as_str()), "{reported:?}");
    assert!(!reported.contains(&complete.as_str()));
    assert!(!reported.contains(&bounced.as_str()));
    assert!(result.discrepancies_found >= 1);
    let detail = result
        .discrepancies
        .iter()
        .find(|detail| detail.message_id == incomplete)
        .expect("detail");
    assert_eq!(detail.missing_events, vec!["sent", "delivered"]);
    assert_eq!(detail.expected_events.len(), 3);
    assert_eq!(detail.tenant_id, "adv-tenant");

    // The health snapshot is real JSON with the documented keys.
    let health = &result.health_check;
    assert!(health["healthy"].is_boolean());
    assert!(health["orphaned_messages"].is_i64());
    assert!(health["avg_event_lag_seconds"].is_number());
    assert!(health["queue_backlog"].is_i64());
    assert!(health["checked_at"].is_string());

    // Completing the chain removes it from the next run's discrepancies.
    insert_event(&pool, "adv-tenant", &incomplete, "sent").await;
    insert_event(&pool, "adv-tenant", &incomplete, "delivered").await;
    let second = worker.run().await.expect("second run");
    assert!(
        !second
            .discrepancies
            .iter()
            .any(|detail| detail.message_id == incomplete),
        "a completed chain must stop being reported"
    );
}

// ---------------------------------------------------------------------------
// 4. Churn prediction: model edges, tenant scope, cache
// ---------------------------------------------------------------------------

async fn insert_churn_event(
    pool: &PgPool,
    tenant: &str,
    recipient: &str,
    event_type: &str,
    days_ago: i64,
) {
    sqlx::query(
        "INSERT INTO events (id, tenant_id, message_id, event_type, recipient, timestamp) \
         VALUES ($1, $2, $3, $4, $5, NOW() - make_interval(days => $6))",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(tenant)
    .bind(Uuid::new_v4().to_string())
    .bind(event_type)
    .bind(recipient)
    .bind(days_ago as i32)
    .execute(pool)
    .await
    .expect("churn event");
}

#[tokio::test]
async fn churn_model_edges_are_bounded_and_tenant_scoped() {
    let Some(pool) = pg_pool("churn").await else {
        return;
    };
    let Some(redis) = redis_pool().await else {
        eprintln!("skipping churn assertions: TEST_REDIS_URL unset");
        return;
    };
    let engine = ChurnPredictionEngine::new(pool.clone(), redis);
    let tag = Uuid::new_v4().simple().to_string();

    // Empty dataset: high inactivity (365 days) but a bounded probability.
    let ghost = format!("ghost-{tag}@example.com");
    let prediction = engine
        .predict("adv-tenant-a", &ghost)
        .await
        .expect("predict cold start");
    assert!(
        (0.0..=1.0).contains(&prediction.probability),
        "probability out of range: {}",
        prediction.probability
    );
    assert!(
        prediction.probability > 0.0 && prediction.probability < 1.0,
        "bounded probability"
    );
    assert_eq!(prediction.signals.len(), 4);
    let names: Vec<&str> = prediction
        .signals
        .iter()
        .map(|signal| signal.name.as_str())
        .collect();
    assert_eq!(names, vec!["complaint", "bounce", "inactivity", "decay"]);
    assert!(matches!(
        prediction.risk_tier,
        RiskTier::Low | RiskTier::Medium | RiskTier::High | RiskTier::Critical
    ));

    // A highly engaged contact: low inactivity/decay, low probability.
    let engaged = format!("engaged-{tag}@example.com");
    for _ in 0..4 {
        insert_churn_event(&pool, "adv-tenant-a", &engaged, "opened", 5).await;
        insert_churn_event(&pool, "adv-tenant-a", &engaged, "clicked", 3).await;
    }
    let active = engine
        .predict("adv-tenant-a", &engaged)
        .await
        .expect("predict engaged");
    assert!(
        active.probability < prediction.probability,
        "engagement must lower churn risk: {} vs {}",
        active.probability,
        prediction.probability
    );
    assert!(active.engagement_velocity > 0.0);

    // Complaint/bounce caps: a flood of bad events cannot exceed weight 1.0
    // per signal (the score stays bounded ≤ 100 → probability ≤ sigmoid(100)).
    let angry = format!("angry-{tag}@example.com");
    for _ in 0..10 {
        insert_churn_event(&pool, "adv-tenant-a", &angry, "complained", 2).await;
        insert_churn_event(&pool, "adv-tenant-a", &angry, "bounced", 2).await;
    }
    let worst = engine
        .predict("adv-tenant-a", &angry)
        .await
        .expect("predict angry");
    let complaint = worst
        .signals
        .iter()
        .find(|signal| signal.name == "complaint")
        .expect("complaint signal");
    let bounce = worst
        .signals
        .iter()
        .find(|signal| signal.name == "bounce")
        .expect("bounce signal");
    assert_eq!(complaint.value, 1.0, "complaint signal caps at 1.0");
    assert_eq!(bounce.value, 1.0, "bounce signal caps at 1.0");
    assert!(worst.probability <= 1.0);
    assert!(
        worst.probability > prediction.probability,
        "complaints+bounces must outrank mere inactivity: {} vs {}",
        worst.probability,
        prediction.probability
    );

    // The second call is served from the cache (same predicted_at), even
    // though the underlying events changed the model's opinion.
    let cached = engine
        .predict("adv-tenant-a", &engaged)
        .await
        .expect("cached predict");
    assert_eq!(cached.predicted_at, active.predicted_at, "cache hit");

    // Tenant scope: the same address under another tenant is a distinct
    // prediction (different events → different signals).
    let other_tenant = engine
        .predict("adv-tenant-b", &engaged)
        .await
        .expect("other tenant predict");
    assert_ne!(other_tenant.tenant_id, active.tenant_id);
    assert!((0.0..=1.0).contains(&other_tenant.probability));
}

// ---------------------------------------------------------------------------
// 5. Send-time optimizer: local-hour buckets, cold start, tenant offset
// ---------------------------------------------------------------------------

#[tokio::test]
async fn send_time_windows_respect_tenant_offset_and_cold_start() {
    let Some(pool) = pg_pool("sto").await else {
        return;
    };
    let Some(redis) = redis_pool().await else {
        eprintln!("skipping send-time assertions: TEST_REDIS_URL unset");
        return;
    };
    let optimizer = SendTimeOptimizer::new(pool.clone(), redis.clone());
    let tag = Uuid::new_v4().simple().to_string();
    let tenant = format!("sto{tag:.22}");
    let with_offset = format!("stl{tag:.22}");
    sqlx::query(
        "INSERT INTO tenants (id, name, settings) VALUES ($1, 'STO', $2), ($3, 'STO2', $4) \
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(&tenant)
    .bind(serde_json::json!({}))
    .bind(&with_offset)
    .bind(serde_json::json!({ "utc_offset_minutes": 120 }))
    .execute(&pool)
    .await
    .expect("tenants");

    // Cold start: fewer than 5 events → the documented Tuesday 10:00 window
    // with zero confidence, regardless of the events that exist.
    let cold = format!("cold-{tag}@example.com");
    insert_churn_event(&pool, &tenant, &cold, "opened", 3).await;
    let cold_start = optimizer
        .get_optimal_window(&cold)
        .await
        .expect("cold window");
    assert_eq!(cold_start.windows.len(), 1);
    assert_eq!(cold_start.windows[0].hour, 10, "cold start is 10:00 local");
    assert_eq!(cold_start.windows[0].confidence, 0.0);
    assert_eq!(cold_start.utc_offset_minutes, 0);
    // The window itself carries zero confidence (prior-only); the result
    // confidence is the usual events/(events+100) smoothing.
    assert!(cold_start.confidence > 0.0 && cold_start.confidence < 0.05);

    // Warm profile: all engagement at 14:00 UTC → 14:00 is the top window
    // for an offset-0 tenant.
    let warm = format!("warm-{tag}@example.com");
    for _ in 0..8 {
        sqlx::query(
            "INSERT INTO events (id, tenant_id, message_id, event_type, recipient, timestamp) \
             VALUES ($1, $2, $3, 'opened', $4, TIMESTAMPTZ '2026-06-16 14:00:00+00')",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(&tenant)
        .bind(Uuid::new_v4().to_string())
        .bind(&warm)
        .execute(&pool)
        .await
        .expect("warm event");
    }
    let warm_utc = optimizer
        .get_optimal_window(&warm)
        .await
        .expect("warm window");
    assert_eq!(warm_utc.windows[0].hour, 14);
    assert!(warm_utc.windows[0].confidence > 0.0);

    // The same recipient under a +120-minute tenant is bucketed at 16:00
    // local, and the offset is labelled on the result.
    let warm_local = optimizer
        .get_optimal_window_for_tenant(&with_offset, &warm)
        .await
        .expect("offset window");
    assert_eq!(warm_local.utc_offset_minutes, 120);
    assert_eq!(
        warm_local.windows[0].hour, 16,
        "14:00 UTC is 16:00 at +02:00"
    );

    // The offset-0 tenant keeps its 14:00 bucket (tenant caches are scoped).
    let warm_uk = optimizer
        .get_optimal_window_for_tenant(&tenant, &warm)
        .await
        .expect("uk window");
    assert_eq!(warm_uk.utc_offset_minutes, 0);
    assert_eq!(warm_uk.windows[0].hour, 14);

    // Unknown tenant: offset defaults to 0, never an error.
    let unknown = optimizer
        .get_optimal_window_for_tenant(&format!("missing-tenant-{tag}"), &warm)
        .await
        .expect("unknown tenant");
    assert_eq!(unknown.utc_offset_minutes, 0);
    assert_eq!(unknown.windows[0].hour, 14);

    // Replays are cache hits (same windows).
    let replay = optimizer
        .get_optimal_window_for_tenant(&with_offset, &warm)
        .await
        .expect("cached");
    assert_eq!(replay.email_hash, warm_local.email_hash);
    assert_eq!(replay.windows.len(), warm_local.windows.len());
    assert_eq!(replay.windows[0].hour, warm_local.windows[0].hour);
    assert_eq!(replay.windows[0].day, warm_local.windows[0].day);
    assert!((replay.windows[0].score - warm_local.windows[0].score).abs() < 1e-12);
}
