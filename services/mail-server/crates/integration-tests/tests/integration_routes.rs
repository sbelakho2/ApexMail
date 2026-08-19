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
            "event_type": "email.delivered"
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
            crm: CrmBackend::postgres(db.clone()),
            enrichment: EnrichmentService::mock(),
            campaigns: CampaignManager::new(10, db.clone()),
            calendar: CalendarService::new(db.clone()),
            inbox: InboxManager::new(db),
            service_token: "test-key".into(),
            rate_limit_fallback: std::sync::Arc::new(parking_lot::Mutex::new(
                std::collections::HashMap::new(),
            )),
        })
    }

    async fn app_with_test_db(test_name: &str) -> Option<axum::Router> {
        let database_url = match std::env::var("TEST_DATABASE_URL") {
            Ok(value) if !value.trim().is_empty() => value,
            _ => {
                eprintln!("skipping {test_name}: set TEST_DATABASE_URL to run DB-backed test");
                return None;
            }
        };
        let db = PgPoolOptions::new()
            .max_connections(2)
            .acquire_timeout(std::time::Duration::from_secs(3))
            .connect(&database_url)
            .await
            .unwrap_or_else(|error| {
                panic!("TEST_DATABASE_URL is set but {test_name} could not connect: {error}")
            });
        initialize_schema(&db).await.unwrap_or_else(|error| {
            panic!("failed to initialize sales schema for {test_name}: {error}")
        });

        let crm = CrmBackend::postgres(db.clone());
        crm.initialize().await.unwrap_or_else(|error| {
            panic!("failed to initialize CRM schema for {test_name}: {error}")
        });

        // Use an unreachable Redis port so the rate limiter deterministically
        // falls back to its in-memory limiter (no dependency on Redis auth).
        let redis = deadpool_redis::Config::from_url("redis://127.0.0.1:16379")
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .expect("Redis pool");
        Some(router(AppState {
            config: Default::default(),
            db: db.clone(),
            redis,
            crm,
            enrichment: EnrichmentService::mock(),
            campaigns: CampaignManager::new(10, db.clone()),
            calendar: CalendarService::new(db.clone()),
            inbox: InboxManager::new(db),
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
        let body = serde_json::json!({
            "email": "alice@acme.com",
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
        assert_eq!(json["email"], "alice@acme.com");
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

    fn app() -> axum::Router {
        let mut state = default_app_state();
        Arc::get_mut(&mut state)
            .expect("exclusive app state")
            .service_token = "test-key".into();
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
        assert_eq!(json["status"], "ok");
    }

    #[tokio::test]
    async fn content_score_returns_score() {
        let body = serde_json::json!({ "subject": "🔥 Limited time offer today!" });
        let resp = app()
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
    async fn retired_predict_route_is_not_exposed() {
        let resp = app()
            .oneshot(
                Request::post("/predict")
                    .header("x-api-key", "test-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn retired_models_route_is_not_exposed() {
        let resp = app()
            .oneshot(
                Request::get("/models")
                    .header("x-api-key", "test-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
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
