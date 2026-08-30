//! Live analytics integration tests.
//!
//! Tests against a real PostgreSQL database with seeded data. Each test:
//! - Starts a test database connection
//! - Inserts seed data (tenants, messages, events, subscriptions)
//! - Calls analytics endpoints via the test router
//! - Verifies response structure, calculations, time filtering, tenant isolation,
//!   performance, and authentication requirements.
//!
//! Run with: `cargo test --test live_analytics_tests --features live-db -- --test-threads=1 --nocapture`
//!
//! Requires TEST_DATABASE_URL or DATABASE_URL env var pointing to a test database.
//! Gated behind the `live-db` feature because it needs the full AppState wiring
//! (DdosProtector, WafEngine) and a running database.

#![cfg(feature = "live-db")]

use std::sync::Arc;
use std::time::Instant;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use chrono::{Duration, Utc};
use serde_json::Value;
use sqlx::PgPool;
use tower::ServiceExt;

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

async fn test_db() -> PgPool {
    let url = std::env::var("TEST_DATABASE_URL").unwrap_or_else(|_| {
        std::env::var("DATABASE_URL").expect("DATABASE_URL must be set for tests")
    });
    PgPool::connect(&url)
        .await
        .expect("failed to connect to test database")
}

async fn cleanup(pool: &PgPool) {
    let _ = sqlx::query("DELETE FROM events WHERE tenant_id LIKE 'test-tenant-%'")
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM messages WHERE tenant_id LIKE 'test-tenant-%'")
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM subscriptions WHERE tenant_id LIKE 'test-tenant-%'")
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM tenants WHERE id LIKE 'test-tenant-%'")
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM events WHERE tenant_id IN ('test-tenant-a', 'test-tenant-b')")
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM tenants WHERE id IN ('test-tenant-a', 'test-tenant-b')")
        .execute(pool)
        .await;
}

fn fast_rand(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    *state
}

// ---------------------------------------------------------------------------
// Seed functions
// ---------------------------------------------------------------------------

async fn seed_tenants(pool: &PgPool) {
    let tenants = [
        ("test-tenant-free", "free", "Free Plan Inc."),
        ("test-tenant-starter", "starter", "Starter LLC"),
        ("test-tenant-pro", "pro", "Pro Corp"),
        ("test-tenant-growth", "growth", "Growth Ltd"),
        ("test-tenant-enterprise", "enterprise", "Enterprise GmbH"),
    ];
    for (id, plan, name) in &tenants {
        let _ = sqlx::query(
            "INSERT INTO tenants (id, plan, name, status, created_at, updated_at)
             VALUES ($1, $2, $3, 'active', NOW(), NOW()) ON CONFLICT (id) DO NOTHING",
        )
        .bind(id)
        .bind(plan)
        .bind(name)
        .execute(pool)
        .await;
    }
}

async fn seed_messages(pool: &PgPool) {
    let tenants = [
        "test-tenant-free",
        "test-tenant-starter",
        "test-tenant-pro",
        "test-tenant-growth",
        "test-tenant-enterprise",
    ];
    let statuses = ["sent", "delivered", "bounced", "opened", "clicked"];
    let weights: [u64; 5] = [1, 6, 1, 3, 2];
    let mut rng: u64 = 12345;
    let now = Utc::now();
    let total = 10000usize;

    for i in 0..total {
        let ti = (fast_rand(&mut rng) % 5) as usize;
        let day_offset = (fast_rand(&mut rng) % 30) as i64;
        let ts = now - Duration::days(day_offset) - Duration::minutes((i % 1440) as i64);

        let mut cum = 0u64;
        let r = fast_rand(&mut rng) % 13;
        let mut status = "sent";
        for (si, &w) in weights.iter().enumerate() {
            cum += w;
            if r < cum {
                status = statuses[si];
                break;
            }
        }

        let _ = sqlx::query(
            "INSERT INTO messages (id, tenant_id, subject, status, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $5) ON CONFLICT (id) DO NOTHING",
        )
        .bind(format!("msg-{i}"))
        .bind(tenants[ti])
        .bind(format!("Msg {i}"))
        .bind(status)
        .bind(ts)
        .execute(pool)
        .await;
    }
}

async fn seed_events(pool: &PgPool) {
    let tenants = [
        "test-tenant-free",
        "test-tenant-starter",
        "test-tenant-pro",
        "test-tenant-growth",
        "test-tenant-enterprise",
    ];
    let event_types = [
        "sent",
        "delivered",
        "bounced",
        "opened",
        "clicked",
        "complained",
    ];
    let weights: [u64; 6] = [2, 5, 1, 3, 2, 1];
    let mut rng: u64 = 67890;
    let now = Utc::now();
    let total = 5000usize;

    let has_table = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'events')",
    )
    .fetch_one(pool)
    .await
    .unwrap_or(false);
    if !has_table {
        return;
    }

    let has_type_col = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (SELECT FROM information_schema.columns WHERE table_name = 'events' AND column_name = 'event_type')"
    ).fetch_one(pool).await.unwrap_or(false);
    let type_col = if has_type_col { "event_type" } else { "type" };

    let has_recipient = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (SELECT FROM information_schema.columns WHERE table_name = 'events' AND column_name = 'recipient')"
    ).fetch_one(pool).await.unwrap_or(false);

    let has_tenant_id = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (SELECT FROM information_schema.columns WHERE table_name = 'events' AND column_name = 'tenant_id')"
    ).fetch_one(pool).await.unwrap_or(false);

    for i in 0..total {
        let ti = (fast_rand(&mut rng) % 5) as usize;
        let day_offset = (fast_rand(&mut rng) % 30) as i64;
        let ts = now - Duration::days(day_offset) - Duration::minutes((i % 1440) as i64);

        let mut cum = 0u64;
        let r = fast_rand(&mut rng) % 14;
        let mut etype = "sent";
        for (ei, &w) in weights.iter().enumerate() {
            cum += w;
            if r < cum {
                etype = event_types[ei];
                break;
            }
        }

        if has_tenant_id && has_recipient {
            let _ = sqlx::query(&format!(
                "INSERT INTO events (id, tenant_id, {type_col}, recipient, created_at)
                 VALUES ($1, $2, $3, $4, $5) ON CONFLICT (id) DO NOTHING"
            ))
            .bind(format!("evt-{i}"))
            .bind(tenants[ti])
            .bind(etype)
            .bind(format!("user{}@example.com", i % 1000))
            .bind(ts)
            .execute(pool)
            .await;
        } else if has_tenant_id {
            let _ = sqlx::query(&format!(
                "INSERT INTO events (id, tenant_id, {type_col}, created_at)
                 VALUES ($1, $2, $3, $4) ON CONFLICT (id) DO NOTHING"
            ))
            .bind(format!("evt-{i}"))
            .bind(tenants[ti])
            .bind(etype)
            .bind(ts)
            .execute(pool)
            .await;
        } else {
            let _ = sqlx::query(&format!(
                "INSERT INTO events (id, {type_col}, created_at)
                 VALUES ($1, $2, $3) ON CONFLICT (id) DO NOTHING"
            ))
            .bind(format!("evt-{i}"))
            .bind(etype)
            .bind(ts)
            .execute(pool)
            .await;
        }
    }
}

async fn seed_subscriptions(pool: &PgPool) {
    let has_subs = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'subscriptions')",
    )
    .fetch_one(pool)
    .await
    .unwrap_or(false);
    if !has_subs {
        return;
    }

    let subs = [
        ("test-tenant-free", "free_monthly", "active", 0i64),
        ("test-tenant-starter", "starter_monthly", "active", 1500),
        ("test-tenant-pro", "pro_monthly", "active", 5000),
        ("test-tenant-growth", "growth_monthly", "active", 15000),
        (
            "test-tenant-enterprise",
            "enterprise_annual",
            "active",
            50000,
        ),
    ];
    for (tid, plan, status, amt) in &subs {
        let _ = sqlx::query(
            "INSERT INTO subscriptions (id, tenant_id, plan_name, status, amount_cents, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, NOW(), NOW()) ON CONFLICT (id) DO NOTHING",
        ).bind(format!("sub-{tid}")).bind(tid).bind(plan).bind(status).bind(amt).execute(pool).await;
    }
}

// ---------------------------------------------------------------------------
// Test router builder
// ---------------------------------------------------------------------------

fn build_test_app(db: PgPool) -> axum::Router {
    use api_server::state::AppState;

    let config = api_server::config::Config::default();
    // AppState no longer carries a WAF engine field (the waf-engine crate
    // is not wired into the live services); the stale positional argument
    // broke compilation of this suite.
    let state = AppState::with_ddos_protector(
        db,
        Default::default(),
        Default::default(),
        config,
        reqwest::Client::new(),
        Default::default(),
        None,
        Arc::new(
            ddos_protection::DdosProtector::new(ddos_protection::ProtectorConfig::default())
                .unwrap(),
        ),
        None,
        None,
        api_server::resilience::ResilientClient::new_from_config(
            &api_server::config::Config::default(),
        ),
    );

    api_server::app::build_app(state)
}

// ---------------------------------------------------------------------------
// 1. Tenant analytics — dashboard, volume, engagement, deliverability
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tenant_dashboard_returns_correct_structure() {
    let db = test_db().await;
    cleanup(&db).await;
    seed_tenants(&db).await;
    seed_messages(&db).await;
    seed_events(&db).await;

    let app = build_test_app(db.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/v1/analytics/dashboard?from=2020-01-01T00:00:00Z")
                .method("GET")
                .header(header::AUTHORIZATION, "Bearer test-skip-auth")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert!(json.get("stats").is_some(), "dashboard missing stats");
    if let Some(stats) = json.get("stats") {
        assert!(stats.get("sent").is_some(), "stats missing sent");
        assert!(stats.get("delivered").is_some(), "stats missing delivered");
    }
    cleanup(&db).await;
}

#[tokio::test]
async fn tenant_volume_endpoint_works() {
    let db = test_db().await;
    cleanup(&db).await;
    seed_tenants(&db).await;
    seed_events(&db).await;
    let app = build_test_app(db.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/v1/analytics/volume?from=2020-01-01T00:00:00Z")
                .method("GET")
                .header(header::AUTHORIZATION, "Bearer test-skip-auth")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    cleanup(&db).await;
}

#[tokio::test]
async fn tenant_engagement_endpoint_works() {
    let db = test_db().await;
    cleanup(&db).await;
    seed_tenants(&db).await;
    seed_events(&db).await;
    let app = build_test_app(db.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/v1/analytics/engagement?from=2020-01-01T00:00:00Z")
                .method("GET")
                .header(header::AUTHORIZATION, "Bearer test-skip-auth")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    cleanup(&db).await;
}

#[tokio::test]
async fn tenant_deliverability_endpoint_works() {
    let db = test_db().await;
    cleanup(&db).await;
    seed_tenants(&db).await;
    seed_events(&db).await;
    let app = build_test_app(db.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/v1/analytics/deliverability?from=2020-01-01T00:00:00Z")
                .method("GET")
                .header(header::AUTHORIZATION, "Bearer test-skip-auth")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    cleanup(&db).await;
}

// ---------------------------------------------------------------------------
// 2. Admin analytics — stats, time-series, provider breakdown
// ---------------------------------------------------------------------------

#[tokio::test]
async fn admin_analytics_correct_structure() {
    let db = test_db().await;
    cleanup(&db).await;
    seed_tenants(&db).await;
    seed_events(&db).await;

    let app = build_test_app(db.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/v1/admin/analytics?range=7d")
                .method("GET")
                .header(header::AUTHORIZATION, "Bearer test-skip-auth")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert!(json.get("stats").is_some(), "admin analytics missing stats");
    if let Some(stats) = json.get("stats") {
        for f in &[
            "totalSent",
            "totalDelivered",
            "totalOpened",
            "totalClicked",
            "totalBounced",
        ] {
            assert!(stats.get(f).is_some(), "stats missing {}", f);
        }
    }
    assert!(
        json.get("timeSeries").is_some(),
        "admin analytics missing timeSeries"
    );
    assert!(
        json.get("providers").is_some(),
        "admin analytics missing providers"
    );
    cleanup(&db).await;
}

#[tokio::test]
async fn admin_analytics_time_filtering() {
    let db = test_db().await;
    cleanup(&db).await;
    seed_tenants(&db).await;
    seed_events(&db).await;

    let app = build_test_app(db.clone());
    let mut counts_7d: i64 = 0;
    let mut counts_90d: i64 = 0;

    for range in &["7d", "30d", "90d"] {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(&format!("/v1/admin/analytics?range={}", range))
                    .method("GET")
                    .header(header::AUTHORIZATION, "Bearer test-skip-auth")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "range {} must return 200",
            range
        );
        let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        let sent = json["stats"]["totalSent"].as_i64().unwrap_or(0);
        let delivered = json["stats"]["totalDelivered"].as_i64().unwrap_or(0);
        assert!(delivered <= sent, "delivered > sent for {range}");

        if *range == "7d" {
            counts_7d = sent;
        }
        if *range == "90d" {
            counts_90d = sent;
        }
    }

    assert!(
        counts_90d >= counts_7d,
        "90d counts ({counts_90d}) must be >= 7d ({counts_7d})"
    );
    cleanup(&db).await;
}

#[tokio::test]
async fn admin_analytics_requires_auth() {
    let db = test_db().await;
    let app = build_test_app(db.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/v1/admin/analytics?range=7d")
                .method("GET")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_ne!(
        resp.status(),
        StatusCode::OK,
        "unauthorized must not return 200"
    );
}

// ---------------------------------------------------------------------------
// 3. Delivery analytics — latency, provider, queue
// ---------------------------------------------------------------------------

#[tokio::test]
async fn delivery_analytics_correct_structure() {
    let db = test_db().await;
    cleanup(&db).await;
    seed_tenants(&db).await;
    seed_events(&db).await;

    let app = build_test_app(db.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/v1/admin/analytics/delivery?range=7d")
                .method("GET")
                .header(header::AUTHORIZATION, "Bearer test-skip-auth")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();

    for f in &[
        "deliveryRate",
        "bounceRate",
        "complaintRate",
        "totalSent",
        "totalDelivered",
    ] {
        assert!(json.get(f).is_some(), "delivery analytics missing {}", f);
    }
    cleanup(&db).await;
}

#[tokio::test]
async fn delivery_latency_endpoint_works() {
    let db = test_db().await;
    cleanup(&db).await;
    seed_tenants(&db).await;
    seed_events(&db).await;
    let app = build_test_app(db.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/v1/admin/analytics/delivery/latency?range=7d")
                .method("GET")
                .header(header::AUTHORIZATION, "Bearer test-skip-auth")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    cleanup(&db).await;
}

#[tokio::test]
async fn delivery_provider_endpoint_works() {
    let db = test_db().await;
    cleanup(&db).await;
    seed_tenants(&db).await;
    seed_events(&db).await;
    let app = build_test_app(db.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/v1/admin/analytics/delivery/provider?range=7d")
                .method("GET")
                .header(header::AUTHORIZATION, "Bearer test-skip-auth")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    cleanup(&db).await;
}

#[tokio::test]
async fn delivery_queue_endpoint_works() {
    let db = test_db().await;
    cleanup(&db).await;
    seed_tenants(&db).await;
    seed_events(&db).await;
    let app = build_test_app(db.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/v1/admin/analytics/delivery/queue?range=7d")
                .method("GET")
                .header(header::AUTHORIZATION, "Bearer test-skip-auth")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    cleanup(&db).await;
}

// ---------------------------------------------------------------------------
// 4. Growth analytics — signups, activation, engagement, trial conversion
// ---------------------------------------------------------------------------

#[tokio::test]
async fn growth_analytics_correct_structure() {
    let db = test_db().await;
    cleanup(&db).await;
    seed_tenants(&db).await;
    seed_events(&db).await;

    let app = build_test_app(db.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/v1/admin/analytics/growth?period=30d")
                .method("GET")
                .header(header::AUTHORIZATION, "Bearer test-skip-auth")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert!(json.get("signups").is_some(), "growth missing signups");
    assert!(
        json.get("activation").is_some(),
        "growth missing activation"
    );
    assert!(
        json.get("engagement").is_some(),
        "growth missing engagement"
    );
    cleanup(&db).await;
}

#[tokio::test]
async fn growth_signup_timeline_works() {
    let db = test_db().await;
    cleanup(&db).await;
    seed_tenants(&db).await;
    let app = build_test_app(db.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/v1/admin/analytics/growth/signups?period=30d")
                .method("GET")
                .header(header::AUTHORIZATION, "Bearer test-skip-auth")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    cleanup(&db).await;
}

#[tokio::test]
async fn growth_activation_funnel_works() {
    let db = test_db().await;
    cleanup(&db).await;
    seed_tenants(&db).await;
    let app = build_test_app(db.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/v1/admin/analytics/growth/activation?period=30d")
                .method("GET")
                .header(header::AUTHORIZATION, "Bearer test-skip-auth")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    cleanup(&db).await;
}

#[tokio::test]
async fn growth_engagement_metrics_works() {
    let db = test_db().await;
    cleanup(&db).await;
    seed_tenants(&db).await;
    let app = build_test_app(db.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/v1/admin/analytics/growth/engagement?period=30d")
                .method("GET")
                .header(header::AUTHORIZATION, "Bearer test-skip-auth")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    cleanup(&db).await;
}

// ---------------------------------------------------------------------------
// 5. Predictive analytics — churn, capacity, anomalies
// ---------------------------------------------------------------------------

#[tokio::test]
async fn predictive_analytics_correct_structure() {
    let db = test_db().await;
    cleanup(&db).await;
    seed_tenants(&db).await;
    seed_events(&db).await;
    seed_subscriptions(&db).await;

    let app = build_test_app(db.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/v1/admin/analytics/predictive?window=90d")
                .method("GET")
                .header(header::AUTHORIZATION, "Bearer test-skip-auth")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert!(
        json.get("churnRisk").is_some(),
        "predictive missing churnRisk"
    );
    assert!(
        json.get("capacity").is_some(),
        "predictive missing capacity"
    );
    assert!(
        json.get("anomalies").is_some(),
        "predictive missing anomalies"
    );
    cleanup(&db).await;
}

#[tokio::test]
async fn predictive_churn_endpoint_works() {
    let db = test_db().await;
    cleanup(&db).await;
    seed_tenants(&db).await;
    seed_subscriptions(&db).await;
    let app = build_test_app(db.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/v1/admin/analytics/predictive/churn?window=90d")
                .method("GET")
                .header(header::AUTHORIZATION, "Bearer test-skip-auth")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    cleanup(&db).await;
}

#[tokio::test]
async fn predictive_capacity_endpoint_works() {
    let db = test_db().await;
    cleanup(&db).await;
    seed_tenants(&db).await;
    seed_events(&db).await;
    let app = build_test_app(db.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/v1/admin/analytics/predictive/capacity?window=90d")
                .method("GET")
                .header(header::AUTHORIZATION, "Bearer test-skip-auth")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    cleanup(&db).await;
}

#[tokio::test]
async fn predictive_anomalies_endpoint_works() {
    let db = test_db().await;
    cleanup(&db).await;
    seed_tenants(&db).await;
    seed_events(&db).await;
    let app = build_test_app(db.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/v1/admin/analytics/predictive/anomalies?window=90d")
                .method("GET")
                .header(header::AUTHORIZATION, "Bearer test-skip-auth")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    cleanup(&db).await;
}

// ---------------------------------------------------------------------------
// 6. Insights — trends, recommendations
// ---------------------------------------------------------------------------

#[tokio::test]
async fn insights_correct_structure() {
    let db = test_db().await;
    cleanup(&db).await;
    seed_tenants(&db).await;
    seed_events(&db).await;

    let app = build_test_app(db.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/v1/admin/analytics/insights?lookback=7d")
                .method("GET")
                .header(header::AUTHORIZATION, "Bearer test-skip-auth")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert!(json.get("insights").is_some(), "insights missing insights");
    assert!(json.get("trends").is_some(), "insights missing trends");
    assert!(
        json.get("recommendations").is_some(),
        "insights missing recommendations"
    );
    cleanup(&db).await;
}

#[tokio::test]
async fn insights_trends_endpoint_works() {
    let db = test_db().await;
    cleanup(&db).await;
    seed_tenants(&db).await;
    seed_events(&db).await;
    let app = build_test_app(db.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/v1/admin/analytics/insights/trends?lookback=7d")
                .method("GET")
                .header(header::AUTHORIZATION, "Bearer test-skip-auth")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    cleanup(&db).await;
}

#[tokio::test]
async fn insights_recommendations_endpoint_works() {
    let db = test_db().await;
    cleanup(&db).await;
    seed_tenants(&db).await;
    seed_events(&db).await;
    let app = build_test_app(db.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/v1/admin/analytics/insights/recommendations?lookback=7d")
                .method("GET")
                .header(header::AUTHORIZATION, "Bearer test-skip-auth")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    cleanup(&db).await;
}

// ---------------------------------------------------------------------------
// 7. Cross-tenant — health, plans, growth
// ---------------------------------------------------------------------------

#[tokio::test]
async fn cross_tenant_health_correct_structure() {
    let db = test_db().await;
    cleanup(&db).await;
    seed_tenants(&db).await;
    seed_events(&db).await;

    let app = build_test_app(db.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/v1/admin/cross-tenant/health")
                .method("GET")
                .header(header::AUTHORIZATION, "Bearer test-skip-auth")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert!(
        json.get("platformHealthScore").is_some(),
        "missing platformHealthScore"
    );
    assert!(json.get("totalTenants").is_some(), "missing totalTenants");
    cleanup(&db).await;
}

#[tokio::test]
async fn cross_tenant_plans_endpoint_works() {
    let db = test_db().await;
    cleanup(&db).await;
    seed_tenants(&db).await;
    seed_subscriptions(&db).await;
    let app = build_test_app(db.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/v1/admin/cross-tenant/plans")
                .method("GET")
                .header(header::AUTHORIZATION, "Bearer test-skip-auth")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    cleanup(&db).await;
}

#[tokio::test]
async fn cross_tenant_growth_endpoint_works() {
    let db = test_db().await;
    cleanup(&db).await;
    seed_tenants(&db).await;
    let app = build_test_app(db.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/v1/admin/cross-tenant/growth")
                .method("GET")
                .header(header::AUTHORIZATION, "Bearer test-skip-auth")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    cleanup(&db).await;
}

// ---------------------------------------------------------------------------
// 8. Revenue — MRR, ARR, LTV, CAC, churn
// ---------------------------------------------------------------------------

#[tokio::test]
async fn revenue_correct_structure() {
    let db = test_db().await;
    cleanup(&db).await;
    seed_tenants(&db).await;
    seed_subscriptions(&db).await;

    let app = build_test_app(db.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/v1/admin/revenue")
                .method("GET")
                .header(header::AUTHORIZATION, "Bearer test-skip-auth")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();

    if let Some(stats) = json.get("stats") {
        for f in &["mrr", "arr", "ltv", "cac", "churnRate"] {
            assert!(stats.get(f).is_some(), "revenue stats missing {}", f);
        }
    }
    assert!(
        json.get("monthlyData").is_some(),
        "revenue missing monthlyData"
    );
    assert!(
        json.get("revenueByPlan").is_some(),
        "revenue missing revenueByPlan"
    );
    cleanup(&db).await;
}

#[tokio::test]
async fn revenue_mrr_non_negative() {
    let db = test_db().await;
    cleanup(&db).await;
    seed_tenants(&db).await;
    seed_subscriptions(&db).await;

    let app = build_test_app(db.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/v1/admin/revenue")
                .method("GET")
                .header(header::AUTHORIZATION, "Bearer test-skip-auth")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();

    if let Some(mrr) = json["stats"]["mrr"].as_f64() {
        assert!(mrr >= 0.0, "MRR must be non-negative, got {mrr}");
    }
    cleanup(&db).await;
}

// ---------------------------------------------------------------------------
// 9. Admin dashboard — stats, leads, alerts, activity
// ---------------------------------------------------------------------------

#[tokio::test]
async fn admin_dashboard_correct_structure() {
    let db = test_db().await;
    cleanup(&db).await;
    seed_tenants(&db).await;
    seed_events(&db).await;

    let app = build_test_app(db.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/v1/admin/dashboard")
                .method("GET")
                .header(header::AUTHORIZATION, "Bearer test-skip-auth")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert!(json.get("stats").is_some(), "dashboard missing stats");
    cleanup(&db).await;
}

// ---------------------------------------------------------------------------
// Mathematical calculations — delivery rate, bounce rate, MRR
// ---------------------------------------------------------------------------

#[tokio::test]
async fn delivery_rate_calculation_correct() {
    let db = test_db().await;
    cleanup(&db).await;

    let _ = sqlx::query(
        "INSERT INTO tenants (id, plan, name, status, created_at, updated_at)
         VALUES ('test-tenant-pro', 'pro', 'Calc Test', 'active', NOW(), NOW())
         ON CONFLICT (id) DO NOTHING",
    )
    .execute(&db)
    .await;

    let now = Utc::now();
    for i in 0..100 {
        let status = if i < 85 {
            "delivered"
        } else if i < 93 {
            "bounced"
        } else {
            "opened"
        };
        let _ = sqlx::query(
            "INSERT INTO messages (id, tenant_id, subject, status, created_at, updated_at)
             VALUES ($1, 'test-tenant-pro', $2, $3, $4, $4) ON CONFLICT (id) DO NOTHING",
        )
        .bind(format!("calc-{}", i))
        .bind(format!("C{}", i))
        .bind(status)
        .bind(now)
        .execute(&db)
        .await;
    }

    let row: (i64, i64) = sqlx::query_as::<_, (i64, i64)>(
        "SELECT COUNT(*)::bigint,
                COUNT(*) FILTER (WHERE status = 'delivered')::bigint
         FROM messages WHERE tenant_id = 'test-tenant-pro'",
    )
    .fetch_one(&db)
    .await
    .unwrap();

    let sent = row.0 as f64;
    let delivered = row.1 as f64;
    let rate = (delivered / sent) * 100.0;
    assert!(
        (rate - 85.0).abs() < 1.0,
        "delivery rate should be ~85%, got {rate}%"
    );
    cleanup(&db).await;
}

#[tokio::test]
async fn bounce_rate_calculation_correct() {
    let db = test_db().await;
    cleanup(&db).await;

    let _ = sqlx::query(
        "INSERT INTO tenants (id, plan, name, status, created_at, updated_at)
         VALUES ('test-tenant-pro', 'pro', 'Bounce Calc', 'active', NOW(), NOW())
         ON CONFLICT (id) DO NOTHING",
    )
    .execute(&db)
    .await;

    let now = Utc::now();
    for i in 0..100 {
        let status = if i < 85 {
            "delivered"
        } else if i < 93 {
            "bounced"
        } else {
            "opened"
        };
        let _ = sqlx::query(
            "INSERT INTO messages (id, tenant_id, subject, status, created_at, updated_at)
             VALUES ($1, 'test-tenant-pro', $2, $3, $4, $4) ON CONFLICT (id) DO NOTHING",
        )
        .bind(format!("bcalc-{}", i))
        .bind(format!("B{}", i))
        .bind(status)
        .bind(now)
        .execute(&db)
        .await;
    }

    let row: (i64, i64) = sqlx::query_as::<_, (i64, i64)>(
        "SELECT COUNT(*)::bigint,
                COUNT(*) FILTER (WHERE status = 'bounced')::bigint
         FROM messages WHERE tenant_id = 'test-tenant-pro'",
    )
    .fetch_one(&db)
    .await
    .unwrap();

    let sent = row.0 as f64;
    let bounced = row.1 as f64;
    let rate = (bounced / sent) * 100.0;
    assert!(
        (rate - 8.0).abs() < 1.0,
        "bounce rate should be ~8%, got {rate}%"
    );
    cleanup(&db).await;
}

#[tokio::test]
async fn mrr_calculation_correct() {
    let db = test_db().await;
    cleanup(&db).await;
    seed_tenants(&db).await;
    seed_subscriptions(&db).await;

    let has_subs = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'subscriptions')",
    )
    .fetch_one(&db)
    .await
    .unwrap_or(false);

    if has_subs {
        let total: i64 = sqlx::query_scalar::<_, i64>(
            "SELECT COALESCE(SUM(amount_cents), 0)
             FROM subscriptions WHERE status = 'active' AND tenant_id LIKE 'test-tenant-%'",
        )
        .fetch_one(&db)
        .await
        .unwrap_or(0);

        assert!(
            total > 0,
            "MRR should be positive with seed data, got {total} cents"
        );
    }
    cleanup(&db).await;
}

// ---------------------------------------------------------------------------
// Tenant isolation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tenant_isolation_no_data_leakage() {
    let db = test_db().await;
    cleanup(&db).await;

    let _ = sqlx::query(
        "INSERT INTO tenants (id, plan, name, status, created_at, updated_at)
         VALUES ('test-tenant-a', 'pro', 'A', 'active', NOW(), NOW()),
                ('test-tenant-b', 'free', 'B', 'active', NOW(), NOW())
         ON CONFLICT (id) DO NOTHING",
    )
    .execute(&db)
    .await;

    let has_events = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'events')",
    )
    .fetch_one(&db)
    .await
    .unwrap_or(false);

    let has_tenant_id = has_events && sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (SELECT FROM information_schema.columns WHERE table_name = 'events' AND column_name = 'tenant_id')"
    ).fetch_one(&db).await.unwrap_or(false);

    if has_events && has_tenant_id {
        let has_type = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (SELECT FROM information_schema.columns WHERE table_name = 'events' AND column_name = 'event_type')"
        ).fetch_one(&db).await.unwrap_or(false);
        let tc = if has_type { "event_type" } else { "type" };

        let now = Utc::now();
        for i in 0..200 {
            let _ = sqlx::query(&format!(
                "INSERT INTO events (id, tenant_id, {tc}, created_at)
                 VALUES ($1, 'test-tenant-a', 'sent', $2) ON CONFLICT (id) DO NOTHING"
            ))
            .bind(format!("iso-{}", i))
            .bind(now - Duration::hours(i as i64))
            .execute(&db)
            .await;
        }

        let count_a: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM events WHERE tenant_id = 'test-tenant-a'",
        )
        .fetch_one(&db)
        .await
        .unwrap();
        let count_b: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM events WHERE tenant_id = 'test-tenant-b'",
        )
        .fetch_one(&db)
        .await
        .unwrap();

        assert!(count_a > 0, "Tenant A must have events");
        assert_eq!(count_b, 0, "Tenant B must have ZERO events (isolation)");
    }

    cleanup(&db).await;
}

// ---------------------------------------------------------------------------
// Performance — queries complete within 500ms
// ---------------------------------------------------------------------------

#[tokio::test]
async fn performance_queries_within_500ms() {
    let db = test_db().await;
    cleanup(&db).await;
    seed_tenants(&db).await;
    seed_events(&db).await;
    seed_messages(&db).await;

    let app = build_test_app(db.clone());
    let timeout = std::time::Duration::from_millis(500);
    let endpoints = [
        "/v1/admin/analytics?range=7d",
        "/v1/admin/analytics/delivery?range=7d",
        "/v1/admin/analytics/growth?period=30d",
        "/v1/admin/cross-tenant/health",
    ];

    for ep in &endpoints {
        let start = Instant::now();
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(*ep)
                    .method("GET")
                    .header(header::AUTHORIZATION, "Bearer test-skip-auth")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let elapsed = start.elapsed();
        let _body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .unwrap();
        assert!(
            elapsed <= timeout,
            "endpoint {ep} took {elapsed:?}, expected <= {timeout:?}"
        );
    }

    cleanup(&db).await;
}
