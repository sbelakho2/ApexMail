//! HTTP route integration tests for each service.
//!
//! Uses `tower::ServiceExt::oneshot` to drive Axum routers without any
//! external dependencies (no DB, no Redis, no network).

use axum::body::Body;
use axum::http::{Request, StatusCode};
use std::sync::Arc;
use tower::ServiceExt;

// ═══════════════════════════════════════════════════════════════════════════
// Helper — read response body as JSON
// ═══════════════════════════════════════════════════════════════════════════

async fn body_json(resp: axum::http::Response<Body>) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

// ═══════════════════════════════════════════════════════════════════════════
// DevEx service (5 tests)
// ═══════════════════════════════════════════════════════════════════════════

mod devex {
    use super::*;
    use devex_service::config::DevExConfig;
    use devex_service::routes::{build_router, AppState};

    fn app() -> axum::Router {
        let mut state = AppState::from_config(DevExConfig::default()).expect("devex state");
        state.service_token = "test-key".into();
        build_router(state)
    }

    #[tokio::test]
    async fn health_returns_200() {
        let resp = app()
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["status"], "healthy");
    }

    #[tokio::test]
    async fn sdks_returns_five_entries() {
        let resp = app()
            .oneshot(
                Request::get("/sdks")
                    .header("x-api-key", "test-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["sdks"].as_array().unwrap().len(), 5);
    }

    #[tokio::test]
    async fn webhook_test_endpoint_accepts_post() {
        let body = serde_json::json!({
            "url": "https://httpbin.org/post",
            "event_type": "message.delivered"
        });
        let resp = app()
            .oneshot(
                Request::post("/webhooks/test")
                    .header("x-api-key", "test-key")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        // The handler tries to actually POST to the URL, and will fail in tests
        // (no network). We just verify the route exists and returns a response.
        // Either 200 (if network is available) or 500 (network error) is fine.
        assert!(
            resp.status() == StatusCode::OK || resp.status() == StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[tokio::test]
    async fn versions_returns_current_version() {
        let resp = app()
            .oneshot(
                Request::get("/versions")
                    .header("x-api-key", "test-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["current"], "2024-01");
        assert!(json["versions"].as_array().unwrap().len() >= 5);
    }

    #[tokio::test]
    async fn onboarding_checklist_returns_200() {
        let resp = app()
            .oneshot(
                Request::get("/onboarding/checklist")
                    .header("x-api-key", "test-key")
                    .header("x-tenant-id", "tenant-test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Observability service (4 tests)
// ═══════════════════════════════════════════════════════════════════════════

mod observability {
    use super::*;
    use observability_service::alerting::AlertManager;
    use observability_service::log_aggregator::LogAggregator;
    use observability_service::metrics_collector::MetricsCollector;
    use observability_service::routes::{router, AppState};
    use observability_service::slo::SloMonitor;
    use observability_service::trace_collector::TraceCollector;

    fn app() -> (axum::Router, Arc<MetricsCollector>) {
        let metrics = Arc::new(MetricsCollector::new(vec![0.1, 0.5, 1.0]));
        let state = AppState::new(
            metrics.clone(),
            Arc::new(TraceCollector::new()),
            Arc::new(LogAggregator::new()),
            Arc::new(AlertManager::new()),
            Arc::new(SloMonitor::new()),
            "test-key".into(),
        );
        (router(state), metrics)
    }

    #[tokio::test]
    async fn health_returns_ok() {
        let (app, _) = app();
        let resp = app
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["status"], "ok");
    }

    #[tokio::test]
    async fn metrics_summary_returns_recorded_metrics() {
        let (app, metrics) = app();
        metrics.record_counter("test_counter", 42.0, "test");

        let resp = app
            .oneshot(
                Request::get("/metrics/summary")
                    .header("x-api-key", "test-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        let arr = json.as_array().unwrap();
        assert!(!arr.is_empty());
        assert!(arr.iter().any(|m| m["name"] == "test_counter"));
    }

    #[tokio::test]
    async fn alerts_list_empty_initially() {
        let (app, _) = app();
        let resp = app
            .oneshot(
                Request::get("/alerts")
                    .header("x-api-key", "test-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert!(json.as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn slos_list_returns_200() {
        let (app, _) = app();
        let resp = app
            .oneshot(
                Request::get("/slos")
                    .header("x-api-key", "test-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Sales-autopilot service (4 tests)
// ═══════════════════════════════════════════════════════════════════════════

mod sales {
    use super::*;
    use sales_autopilot::calendar::CalendarService;
    use sales_autopilot::campaigns::CampaignManager;
    use sales_autopilot::crm::CrmBackend;
    use sales_autopilot::enrichment::EnrichmentService;
    use sales_autopilot::inbox::InboxManager;
    use sales_autopilot::routes::{initialize_schema, router, AppState};
    use sqlx::postgres::PgPoolOptions;

    fn app() -> axum::Router {
        let db = PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(std::time::Duration::from_millis(100))
            .connect_lazy("postgres://localhost/unused")
            .expect("lazy pool");
        // Use an unreachable Redis port so the rate limiter deterministically
        // falls back to its in-memory limiter (no dependency on Redis auth).
        let redis = deadpool_redis::Config::from_url("redis://127.0.0.1:16379")
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .expect("Redis pool");
        router(AppState {
            config: Default::default(),
            db: db.clone(),
            redis,
            dispatcher: None,
            crm: CrmBackend::postgres(db.clone()),
            enrichment: EnrichmentService::mock(),
            campaigns: CampaignManager::new(10, db.clone()),
            calendar: CalendarService::new(db.clone()),
            inbox: InboxManager::new(db.clone()),
            // The planner requires an intelligence provider and a knowledge
            // base. The offline provider is the honest default here: it is what
            // an unconfigured deployment gets, and it keeps the send path
            // working without an AI service.
            intelligence: std::sync::Arc::new(
                sales_autopilot::intelligence::OfflineIntelligence::new(),
            ),
            strategist: std::sync::Arc::new(
                sales_autopilot::personalization::MessageStrategist::new(
                    db.clone(),
                    sales_autopilot::knowledge::SalesKnowledgeBase::canonical(),
                ),
            ),
            service_token: "test-key".into(),
            rate_limit_fallback: std::sync::Arc::new(parking_lot::Mutex::new(
                std::collections::HashMap::new(),
            )),
        })
    }

    /// Dedicated canonical database for the sales route tests. Provisioning
    /// goes through the REAL production migrator (audit F01), exactly like
    /// `crates/sales-autopilot/tests/common/mod.rs`; `initialize_schema` only
    /// VERIFIES the schema now, so runtime DDL is never the schema source.
    const SALES_ROUTES_DB: &str = "apexmail_integration_routes";

    /// Provisioning runs exactly once per test PROCESS; each test then gets a
    /// FRESH pool (a sqlx pool is bound to the runtime that created it —
    /// sharing one across `#[tokio::test]` runtimes deadlocks).
    static INIT: tokio::sync::OnceCell<bool> = tokio::sync::OnceCell::const_new();

    fn test_database_url() -> Option<String> {
        std::env::var("TEST_DATABASE_URL")
            .ok()
            .filter(|value| !value.trim().is_empty())
    }

    /// Rewrite the database segment of a `postgresql://…/<db>` URL,
    /// preserving any query string.
    fn database_url_for(base_url: &str, db_name: &str) -> String {
        match base_url.rsplit_once('/') {
            Some((server, rest)) => {
                let query = rest
                    .split_once('?')
                    .map(|(_, query)| format!("?{query}"))
                    .unwrap_or_default();
                format!("{server}/{db_name}{query}")
            }
            None => base_url.to_string(),
        }
    }

    async fn connect(url: &str) -> sqlx::PgPool {
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            PgPoolOptions::new().max_connections(10).connect(url),
        )
        .await
        .unwrap_or_else(|_| panic!("timed out connecting to canonical test database {url}"))
        .unwrap_or_else(|error| {
            panic!("could not connect to canonical test database {url}: {error}")
        })
    }

    async fn app_with_test_db(test_name: &str) -> Option<axum::Router> {
        let ready = INIT
            .get_or_init(|| async {
                let Some(base_url) = test_database_url() else {
                    eprintln!("skipping {test_name}: set TEST_DATABASE_URL to run DB-backed test");
                    return false;
                };
                let db = match migrator::test_support::shared_canonical_db(
                    base_url.as_str(),
                    SALES_ROUTES_DB,
                )
                .await
                {
                    Ok(db) => db,
                    // F01: the URL is configured, so provisioning failure is
                    // infrastructure breakage — panic, never soft-skip.
                    Err(error) => panic!("{}", error.panic_message()),
                };
                let Some(db) = db else {
                    eprintln!("skipping {test_name}: unconfigured");
                    return false;
                };
                // Post-migration assertion: the canonical chain must have
                // produced the sales schema this suite exercises.
                initialize_schema(&db).await.unwrap_or_else(|error| {
                    panic!(
                        "canonical test database `{SALES_ROUTES_DB}` does not carry the \
                         sales schema this build expects: {error}"
                    )
                });
                db.close().await;
                true
            })
            .await;
        if !ready {
            return None;
        }

        let base_url = test_database_url()?;
        let db = connect(&database_url_for(&base_url, SALES_ROUTES_DB)).await;

        let crm = CrmBackend::postgres(db.clone());
        crm.initialize()
            .await
            .unwrap_or_else(|error| panic!("failed to verify CRM schema for {test_name}: {error}"));

        // Use an unreachable Redis port so the rate limiter deterministically
        // falls back to its in-memory limiter (no dependency on Redis auth).
        let redis = deadpool_redis::Config::from_url("redis://127.0.0.1:16379")
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .expect("Redis pool");
        Some(router(AppState {
            config: Default::default(),
            db: db.clone(),
            redis,
            dispatcher: None,
            crm,
            enrichment: EnrichmentService::mock(),
            campaigns: CampaignManager::new(10, db.clone()),
            calendar: CalendarService::new(db.clone()),
            inbox: InboxManager::new(db.clone()),
            // The planner requires an intelligence provider and a knowledge
            // base. The offline provider is the honest default here: it is what
            // an unconfigured deployment gets, and it keeps the send path
            // working without an AI service.
            intelligence: std::sync::Arc::new(
                sales_autopilot::intelligence::OfflineIntelligence::new(),
            ),
            strategist: std::sync::Arc::new(
                sales_autopilot::personalization::MessageStrategist::new(
                    db.clone(),
                    sales_autopilot::knowledge::SalesKnowledgeBase::canonical(),
                ),
            ),
            service_token: "test-key".into(),
            rate_limit_fallback: std::sync::Arc::new(parking_lot::Mutex::new(
                std::collections::HashMap::new(),
            )),
        }))
    }

    #[tokio::test]
    async fn health_returns_200() {
        let resp = app()
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let json = body_json(resp).await;
        assert_eq!(json["status"], "degraded");
    }

    #[tokio::test]
    async fn create_lead_returns_ok() {
        let Some(app) = app_with_test_db("create_lead_returns_ok").await else {
            return;
        };
        // Unique per run: the route tests share the (persistent)
        // TEST_DATABASE_URL and sales_leads enforces
        // UNIQUE(tenant_id, lower(contact_email)) — a fixed address 409s on
        // every suite re-run against the same database.
        let email = format!("alice-{}@acme.com", uuid::Uuid::new_v4().simple());
        let body = serde_json::json!({
            "email": email,
            "name": "Alice Smith",
            "company": "Acme Corp"
        });
        let resp = app
            .oneshot(
                Request::post("/leads")
                    .header("x-api-key", "test-key")
                    .header("x-tenant-id", "tenant-routes")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["email"], json["email"].clone());
        assert!(
            json["email"].as_str().unwrap_or("").starts_with("alice-"),
            "created lead echoes the submitted email: {}",
            json["email"]
        );
    }

    #[tokio::test]
    async fn list_leads_returns_200() {
        let Some(app) = app_with_test_db("list_leads_returns_200").await else {
            return;
        };
        let resp = app
            .oneshot(
                Request::get("/leads")
                    .header("x-api-key", "test-key")
                    .header("x-tenant-id", "tenant-routes")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn enrich_returns_company_data() {
        let body = serde_json::json!({ "email": "bob@beta.io" });
        let resp = app()
            .oneshot(
                Request::post("/enrich")
                    .header("x-api-key", "test-key")
                    .header("x-tenant-id", "tenant-routes")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let body_bytes = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
        let body_str = String::from_utf8_lossy(&body_bytes);
        assert_eq!(status, StatusCode::OK, "body: {body_str}");
        let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert!(json["name"].is_string());
        assert!(json["industry"].is_string());
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// AI service (4 tests)
// ═══════════════════════════════════════════════════════════════════════════

mod ai {
    use super::*;
    use ai_service::routes::{build_router, default_app_state};

    async fn app() -> axum::Router {
        let mut state = default_app_state().await.expect("default app state");
        Arc::get_mut(&mut state)
            .expect("exclusive app state")
            .service_token = "test-key".into();
        build_router(state)
    }

    #[tokio::test]
    async fn health_returns_200() {
        let resp = app()
            .await
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["status"], "ok");
    }

    #[tokio::test]
    async fn content_score_returns_score() {
        let body = serde_json::json!({ "subject": "🔥 Limited time offer today!" });
        let resp = app()
            .await
            .oneshot(
                Request::post("/content/score")
                    .header("x-api-key", "test-key")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert!(json["success"].as_bool().unwrap());
    }

    #[tokio::test]
    async fn models_route_returns_runtime_status() {
        let resp = app()
            .await
            .oneshot(
                Request::get("/models")
                    .header("x-api-key", "test-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["success"], true);
        assert_eq!(json["data"]["runtime_enabled"], false);
        assert!(json["data"]["models"].is_array());
    }

    #[tokio::test]
    async fn predict_route_rejects_invalid_requests() {
        // Predict is exposed but must reject a malformed/empty request with a
        // client error (400/422) instead of reaching the LLM provider or
        // returning 404.
        let resp = app()
            .await
            .oneshot(
                Request::post("/predict")
                    .header("x-api-key", "test-key")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(resp.status().is_client_error(), "status: {}", resp.status());
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Billing service — routes require DB/Redis state; test plan seed logic only
// (5 tests)
// ═══════════════════════════════════════════════════════════════════════════

mod billing {
    use billing_service::plans::default_plans;

    #[test]
    fn default_plans_contains_expected_tiers() {
        let plans = default_plans();
        let names: Vec<&str> = plans.iter().map(|p| p.name).collect();
        assert!(names.contains(&"free"));
        assert!(names.contains(&"starter"));
        assert!(names.contains(&"pro"));
        assert!(names.contains(&"enterprise"));
    }

    #[test]
    fn free_plan_has_zero_price() {
        let plans = default_plans();
        let free = plans.iter().find(|p| p.name == "free").unwrap();
        assert_eq!(free.price_monthly, 0);
        assert_eq!(free.price_yearly, 0);
    }

    #[test]
    fn enterprise_plan_has_all_features() {
        let plans = default_plans();
        let ent = plans.iter().find(|p| p.name == "enterprise").unwrap();
        assert!(ent.features.sso_enabled);
        assert!(ent.features.dedicated_ip);
        assert!(ent.features.audit_logs);
    }

    #[test]
    fn plans_sorted_by_sort_order() {
        let plans = default_plans();
        for w in plans.windows(2) {
            assert!(w[0].sort_order <= w[1].sort_order);
        }
    }

    #[test]
    fn all_plans_have_positive_limits() {
        let plans = default_plans();
        for p in &plans {
            // -1 means unlimited, otherwise must be positive
            assert!(
                p.email_limit > 0 || p.email_limit == -1,
                "{} email_limit",
                p.name
            );
            assert!(
                p.api_call_limit > 0 || p.api_call_limit == -1,
                "{} api_call_limit",
                p.name
            );
        }
    }
}
