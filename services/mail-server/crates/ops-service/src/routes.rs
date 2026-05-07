//! Axum HTTP routes for the operations service.

use apexmail_lib::crypto::timing_safe_compare;
use axum::middleware::Next;
use axum::{
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{HeaderMap, StatusCode},
    middleware,
    response::Response,
    routing::get,
    Json, Router,
};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tower_http::timeout::TimeoutLayer;
use uuid::Uuid;

use crate::health::HealthChecker;
use crate::incidents::IncidentManager;
use crate::slo::SloTracker;
use crate::status::StatusPageGenerator;
use crate::trust::{TenantMetrics, TrustScorer};
use crate::types::{IncidentSeverity, TrustScore};
use crate::warmup::IpWarmupManager;

/// Shared application state available to all route handlers.
#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub health: HealthChecker,
    pub incidents: IncidentManager,
    pub slo: SloTracker,
    pub warmup: IpWarmupManager,
    pub api_key: String,
    /// All valid API keys including the legacy single key and rotation keys (O-23.5).
    pub api_keys: Vec<String>,
    pub trust_cache: Arc<DashMap<Uuid, TrustCacheEntry>>,
}

#[derive(Debug, Clone)]
pub struct TrustCacheEntry {
    pub score: TrustScore,
    pub cached_at: Instant,
}

const TRUST_CACHE_TTL: Duration = Duration::from_secs(60);

/// Build the full [`Router`] with all ops endpoints.
pub fn router(state: AppState) -> Router {
    let shared = Arc::new(state);
    Router::new()
        .route("/health/checks", get(get_health_checks))
        .route("/incidents", get(get_incidents).post(create_incident))
        .route("/slos", get(get_slos))
        .route("/status", get(get_status))
        .route("/warmup/{ip}", get(get_warmup))
        .route("/trust/{tenant_id}", get(get_trust))
        .with_state(shared.clone())
        .layer(DefaultBodyLimit::max(256 * 1024)) // 256 KB
        .layer(TimeoutLayer::new(Duration::from_secs(30)))
        .layer(middleware::from_fn_with_state(shared, require_api_key))
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn get_health_checks(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let checks = state.health.latest_checks();
    Json(serde_json::json!({ "checks": checks }))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ListQuery {
    limit: Option<usize>,
    offset: Option<usize>,
}

async fn get_incidents(
    State(state): State<Arc<AppState>>,
    Query(q): Query<ListQuery>,
) -> Json<serde_json::Value> {
    let limit = q.limit.unwrap_or(50).clamp(1, 200);
    let offset = q.offset.unwrap_or(0);
    let active = state.incidents.list_active(limit, offset);
    Json(serde_json::json!({ "incidents": active, "count": active.len() }))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
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
) -> Result<(StatusCode, Json<CreateIncidentResponse>), (StatusCode, Json<serde_json::Value>)> {
    match state
        .incidents
        .create_incident(payload.title, payload.severity, payload.affected_services)
        .await
    {
        Ok(id) => Ok((StatusCode::CREATED, Json(CreateIncidentResponse { id }))),
        Err(err) => {
            tracing::error!(error = %err, "Failed to create incident");
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "failed to create incident"})),
            ))
        }
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
    if let Some(entry) = state.trust_cache.get(&tenant_id) {
        if entry.cached_at.elapsed() < TRUST_CACHE_TTL {
            return Json(serde_json::json!(entry.score));
        }
        state.trust_cache.remove(&tenant_id);
    }
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
            age_days: age_days as u64,
            volume: volume as u64,
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

    // O-23.6: Use default weights for scoring.
    let score = TrustScorer::compute_score_default(&metrics);

    // Store the computed score in trust_metrics table for historical tracking
    if let Err(error) = sqlx::query(
        "INSERT INTO trust_metrics (tenant_id, trust_score, bounce_rate, complaint_rate, engagement_rate, send_volume, computed_at)
         VALUES ($1, $2, $3, $4, $5, $6, NOW())
         ON CONFLICT (tenant_id, computed_at) DO UPDATE SET trust_score = $2"
    )
        .bind(tenant_id)
        .bind(score.score)
        .bind(metrics.bounce_rate)
        .bind(metrics.complaint_rate)
        .bind(metrics.engagement_rate)
        .bind(metrics.volume as i64)
        .execute(&state.db)
        .await
    {
        tracing::warn!(tenant_id = %tenant_id, error = %error, "Failed to persist trust score snapshot");
    }

    state.trust_cache.insert(
        tenant_id,
        TrustCacheEntry {
            score: score.clone(),
            cached_at: Instant::now(),
        },
    );

    Json(serde_json::json!(score))
}

async fn require_api_key(
    State(state): State<Arc<AppState>>,
    req: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let provided = extract_api_key(req.headers());

    // Fast-path: if the legacy single key is set, check it first with timing-safe comparison.
    if let Some(ref key) = provided {
        if !state.api_key.is_empty() && timing_safe_compare(key, &state.api_key) {
            return Ok(next.run(req).await);
        }
        // O-23.5: Also check rotation keys via timing-safe comparison.
        for rotation_key in &state.api_keys {
            if timing_safe_compare(key, rotation_key) {
                return Ok(next.run(req).await);
            }
        }
    }

    Err(StatusCode::UNAUTHORIZED)
}

fn extract_api_key(headers: &HeaderMap) -> Option<String> {
    if let Some(value) = headers.get("x-api-key") {
        return value.to_str().ok().map(|s| s.to_string());
    }
    if let Some(value) = headers.get(axum::http::header::AUTHORIZATION) {
        if let Ok(raw) = value.to_str() {
            let raw = raw.trim();
            if let Some(token) = raw.strip_prefix("Bearer ") {
                return Some(token.to_string());
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use tower::ServiceExt; // for `oneshot`

    async fn test_state() -> Result<AppState, sqlx::Error> {
        let db_url = std::env::var("TEST_DATABASE_URL").ok();
        let db = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy(
                db_url
                    .as_deref()
                    .unwrap_or("postgres://localhost/apexmail_test"),
            )?;
        Ok(AppState {
            db: db.clone(),
            health: HealthChecker::new(100),
            incidents: IncidentManager::new_in_memory(),
            slo: SloTracker::new(),
            warmup: IpWarmupManager::new_in_memory(),
            api_key: "test-key".into(),
            api_keys: vec!["rotation-key-1".into(), "rotation-key-2".into()],
            trust_cache: Arc::new(DashMap::new()),
        })
    }

    #[tokio::test]
    async fn test_get_health_checks() {
        let state = test_state().await;
        assert!(state.is_ok());
        let app = if let Ok(state) = state {
            router(state)
        } else {
            return;
        };
        let req = Request::builder()
            .uri("/health/checks")
            .header("x-api-key", "test-key")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_create_and_list_incidents() {
        let state = test_state().await;
        assert!(state.is_ok());
        let app = if let Ok(state) = state {
            router(state)
        } else {
            return;
        };

        let body = serde_json::json!({
            "title": "Test incident",
            "severity": "P2",
            "affected_services": ["api"]
        });

        let req = Request::builder()
            .method("POST")
            .uri("/incidents")
            .header("content-type", "application/json")
            .header("x-api-key", "test-key")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();

        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        let req = Request::builder()
            .uri("/incidents")
            .header("x-api-key", "test-key")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(payload["count"], serde_json::json!(1));
        assert_eq!(
            payload["incidents"][0]["title"],
            serde_json::json!("Test incident")
        );
        assert_eq!(payload["incidents"][0]["severity"], serde_json::json!("P2"));
    }

    #[tokio::test]
    async fn test_get_status_page() {
        let state = test_state().await;
        assert!(state.is_ok());
        let app = if let Ok(state) = state {
            router(state)
        } else {
            return;
        };
        let req = Request::builder()
            .uri("/status")
            .header("x-api-key", "test-key")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
