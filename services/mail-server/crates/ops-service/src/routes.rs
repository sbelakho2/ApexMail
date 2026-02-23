//! Axum HTTP routes for the operations service.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

use crate::health::HealthChecker;
use crate::incidents::IncidentManager;
use crate::slo::SloTracker;
use crate::status::StatusPageGenerator;
use crate::trust::{TenantMetrics, TrustScorer};
use crate::types::IncidentSeverity;
use crate::warmup::IpWarmupManager;

/// Shared application state available to all route handlers.
#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub health: HealthChecker,
    pub incidents: IncidentManager,
    pub slo: SloTracker,
    pub warmup: IpWarmupManager,
}

/// Build the full [`Router`] with all ops endpoints.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health/checks", get(get_health_checks))
        .route("/incidents", get(get_incidents).post(create_incident))
        .route("/slos", get(get_slos))
        .route("/status", get(get_status))
        .route("/warmup/{ip}", get(get_warmup))
        .route("/trust/{tenant_id}", get(get_trust))
        .with_state(Arc::new(state))
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn get_health_checks(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let checks = state.health.latest_checks();
    Json(serde_json::json!({ "checks": checks }))
}

async fn get_incidents(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let active = state.incidents.list_active();
    Json(serde_json::json!({ "incidents": active, "count": active.len() }))
}

#[derive(Debug, Deserialize)]
struct CreateIncidentPayload {
    title: String,
    severity: IncidentSeverity,
    affected_services: Vec<String>,
}

#[derive(Debug, Serialize)]
struct CreateIncidentResponse {
    id: Uuid,
}

async fn create_incident(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<CreateIncidentPayload>,
) -> Result<(StatusCode, Json<CreateIncidentResponse>), StatusCode> {
    match state.incidents.create_incident(
        payload.title,
        payload.severity,
        payload.affected_services,
    ).await {
        Ok(id) => Ok((StatusCode::CREATED, Json(CreateIncidentResponse { id }))),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

async fn get_slos(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let slos = state.slo.list_all();
    Json(serde_json::json!({ "slos": slos }))
}

async fn get_status(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let checks = state.health.latest_checks();
    let page = StatusPageGenerator::generate_page(&checks);
    Json(serde_json::json!(page))
}

async fn get_warmup(
    State(state): State<Arc<AppState>>,
    Path(ip): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let schedules = state.warmup.list_schedules();
    let schedule = schedules.into_iter().find(|s| s.ip == ip);
    match schedule {
        Some(s) => Ok(Json(serde_json::json!(s))),
        None => Err(StatusCode::NOT_FOUND),
    }
}

async fn get_trust(
    State(state): State<Arc<AppState>>,
    Path(tenant_id): Path<Uuid>,
) -> Json<serde_json::Value> {
    // Query real metrics from the analytics database
    let metrics_row: Option<(f64, f64, f64, i64, i32)> = sqlx::query_as(
        "WITH recent_stats AS (
            SELECT
                COUNT(*) FILTER (WHERE event_type = 'bounce')::float / NULLIF(COUNT(*), 0) as bounce_rate,
                COUNT(*) FILTER (WHERE event_type = 'complaint')::float / NULLIF(COUNT(*), 0) as complaint_rate,
                COUNT(*) FILTER (WHERE event_type IN ('open', 'click'))::float / NULLIF(COUNT(*), 0) as engagement_rate,
                COUNT(*) as volume
            FROM events
            WHERE tenant_id = $1 AND timestamp > NOW() - INTERVAL '30 days'
        ),
        tenant_age AS (
            SELECT EXTRACT(DAY FROM NOW() - created_at)::int as age_days
            FROM tenants WHERE id = $1
        )
        SELECT
            COALESCE(rs.bounce_rate, 0.0) as bounce_rate,
            COALESCE(rs.complaint_rate, 0.0) as complaint_rate,
            COALESCE(rs.engagement_rate, 0.0) as engagement_rate,
            COALESCE(rs.volume, 0) as volume,
            COALESCE(ta.age_days, 0) as age_days
        FROM recent_stats rs, tenant_age ta"
    )
        .bind(tenant_id)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten();

    let metrics = match metrics_row {
        Some((bounce_rate, complaint_rate, engagement_rate, volume, age_days)) => TenantMetrics {
            tenant_id,
            bounce_rate,
            complaint_rate,
            engagement_rate,
            age_days,
            volume,
        },
        None => {
            // Fallback for new tenants with no data
            TenantMetrics {
                tenant_id,
                bounce_rate: 0.0,
                complaint_rate: 0.0,
                engagement_rate: 0.0,
                age_days: 0,
                volume: 0,
            }
        }
    };

    let score = TrustScorer::compute_score(&metrics);

    // Store the computed score in trust_metrics table for historical tracking
    let _ = sqlx::query(
        "INSERT INTO trust_metrics (tenant_id, trust_score, bounce_rate, complaint_rate, engagement_rate, send_volume, computed_at)
         VALUES ($1, $2, $3, $4, $5, $6, NOW())
         ON CONFLICT (tenant_id, computed_at) DO UPDATE SET trust_score = $2"
    )
        .bind(tenant_id)
        .bind(score.overall)
        .bind(metrics.bounce_rate)
        .bind(metrics.complaint_rate)
        .bind(metrics.engagement_rate)
        .bind(metrics.volume)
        .execute(&state.db)
        .await;

    Json(serde_json::json!(score))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt; // for `oneshot`

    async fn test_state() -> AppState {
        // Use test database or a dummy pool for unit tests
        let db = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&std::env::var("TEST_DATABASE_URL").unwrap_or_else(|_| {
                "postgres://localhost/apexmail_test".to_string()
            }))
            .await
            .unwrap_or_else(|_| {
                // For unit tests without DB, create a minimal pool that will error on use
                // In real integration tests, ensure DB is available
                panic!("TEST_DATABASE_URL not set and default connection failed")
            });

        AppState {
            db: db.clone(),
            health: HealthChecker::new(100),
            incidents: IncidentManager::new(db.clone()),
            slo: SloTracker::new(),
            warmup: IpWarmupManager::new(db),
        }
    }

    #[tokio::test]
    async fn test_get_health_checks() {
        let app = router(test_state().await);
        let req = Request::builder()
            .uri("/health/checks")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_create_and_list_incidents() {
        let state = test_state().await;
        let app = router(state);

        let body = serde_json::json!({
            "title": "Test incident",
            "severity": "P2",
            "affected_services": ["api"]
        });

        let req = Request::builder()
            .method("POST")
            .uri("/incidents")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn test_get_status_page() {
        let app = router(test_state().await);
        let req = Request::builder()
            .uri("/status")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
