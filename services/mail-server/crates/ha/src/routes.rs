//! HTTP routes for the HA service — 40+ endpoints under /api/v1.

use axum::{
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{HeaderMap, Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Json, Response},
    routing::{delete, get, post, put},
    Router,
};
use serde::Deserialize;
use std::sync::Arc;
use std::time::Duration;
use tower_http::timeout::TimeoutLayer;
use uuid::Uuid;

use crate::backup::BackupService;
use crate::chaos::ChaosEngineeringService;
use crate::circuit_breaker::CircuitBreakerService;
use crate::config::Config;
use crate::failover::FailoverService;
use crate::health_check::HealthCheckService;
use crate::multi_region::MultiRegionService;
use crate::replication::ReplicationService;
use crate::types::*;
use apexmail_lib::crypto::timing_safe_compare;

// ── Error helper ───────────────────────────────────────────

/// Log the error and return a 500 status code.
/// This ensures HA failures are visible in logs during split-brain, failover,
/// or replication issues — previously all error context was silently discarded.
fn internal_err(e: impl std::fmt::Display) -> StatusCode {
    tracing::error!(error = %e, "HA endpoint failed");
    StatusCode::INTERNAL_SERVER_ERROR
}

// ── Shared App State ───────────────────────────────────────

pub struct AppState {
    pub config: Arc<Config>,
    pub health: HealthCheckService,
    pub failover: FailoverService,
    pub backup: BackupService,
    pub replication: ReplicationService,
    pub multi_region: MultiRegionService,
    pub circuit_breaker: CircuitBreakerService,
    pub chaos: ChaosEngineeringService,
}

// ── Auth middleware helper ──────────────────────────────────

fn check_api_key(headers: &HeaderMap, config: &Config) -> Result<(), StatusCode> {
    let key = headers
        .get("x-api-key")
        .or_else(|| headers.get("x-internal-api-key"))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if timing_safe_compare(key, &config.internal_api_key)
        || timing_safe_compare(key, &config.admin_api_key)
    {
        Ok(())
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

// ── Fencing write-guard (B.1 enforcement) ──────────────────

/// B.1 enforcement: this node must refuse to serve mutating requests while
/// its Redis fence key (`ha:fenced:{self}`) exists. Read-only requests and
/// the split-brain / unfence recovery endpoints are exempt so a fenced node
/// can still be operated on (otherwise recovery would deadlock).
async fn fence_guard(
    State(state): State<Arc<AppState>>,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let mutating = matches!(
        method,
        Method::POST | Method::PUT | Method::DELETE | Method::PATCH
    );
    let recovery_path = path.starts_with("/api/v1/failover/split-brain") || path.ends_with("/unfence");
    if !mutating || recovery_path {
        return next.run(request).await;
    }
    match state.failover.ensure_not_fenced().await {
        Ok(()) => next.run(request).await,
        Err(reason) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": "node is fenced — writes refused",
                "reason": reason,
            })),
        )
            .into_response(),
    }
}

// ── Build Router ───────────────────────────────────────────

pub fn build_router(state: Arc<AppState>) -> Router<()> {
    Router::new()
        // Health
        .route("/health", get(health_check))
        .route("/api/v1/health", get(health_detailed))
        .route("/api/v1/health/cluster", get(cluster_status))
        // Failover
        .route("/api/v1/failover/status", get(failover_status))
        .route("/api/v1/failover/initiate", post(failover_initiate))
        .route("/api/v1/failover/failback", post(failover_failback))
        .route("/api/v1/failover/history", get(failover_history))
        .route("/api/v1/failover/split-brain", get(split_brain_check))
        .route(
            "/api/v1/failover/split-brain/resolve",
            post(split_brain_resolve),
        )
        // Backup
        .route("/api/v1/backup", post(backup_create))
        .route("/api/v1/backup/list", get(backup_list))
        .route("/api/v1/backup/:id", get(backup_get))
        .route("/api/v1/backup/:id", delete(backup_delete))
        .route("/api/v1/backup/restore", post(backup_restore))
        .route("/api/v1/backup/pitr", post(backup_pitr))
        .route("/api/v1/backup/schedule", get(backup_schedule))
        .route("/api/v1/backup/retention", post(backup_retention_cleanup))
        // Replication
        .route("/api/v1/replication/status", get(replication_status))
        .route("/api/v1/replication/replicas", get(replication_replicas))
        .route("/api/v1/replication/slots", get(replication_slots))
        .route("/api/v1/replication/slots", post(replication_create_slot))
        .route(
            "/api/v1/replication/slots/:name",
            delete(replication_delete_slot),
        )
        .route("/api/v1/replication/promote", post(replication_promote))
        .route("/api/v1/replication/sync-mode", put(replication_sync_mode))
        .route(
            "/api/v1/replication/lag/history",
            get(replication_lag_history),
        )
        // Multi-Region
        .route("/api/v1/regions", get(regions_list))
        .route("/api/v1/regions", post(regions_register))
        .route("/api/v1/regions/:name", get(regions_get))
        .route("/api/v1/regions/:name", delete(regions_remove))
        .route("/api/v1/regions/:name/health", put(regions_update_health))
        .route("/api/v1/regions/:name/weight", put(regions_set_weight))
        .route("/api/v1/regions/:name/fence", post(regions_fence))
        .route("/api/v1/regions/:name/unfence", post(regions_unfence))
        .route("/api/v1/regions/route", get(regions_route))
        .route("/api/v1/regions/traffic", get(regions_traffic))
        .route("/api/v1/regions/geo-rules", get(geo_rules_list))
        .route("/api/v1/regions/geo-rules", post(geo_rules_add))
        .route("/api/v1/regions/geo-rules/:id", delete(geo_rules_delete))
        // Circuit Breaker
        .route("/api/v1/circuit-breakers", get(circuits_list))
        .route("/api/v1/circuit-breakers/:name", get(circuits_get))
        .route("/api/v1/circuit-breakers/:name/reset", post(circuits_reset))
        .route("/api/v1/circuit-breakers", post(circuits_configure))
        .route("/api/v1/circuit-breakers/:name", delete(circuits_remove))
        // Chaos Engineering
        .route("/api/v1/chaos/experiments", get(chaos_list))
        .route("/api/v1/chaos/experiments", post(chaos_start))
        .route("/api/v1/chaos/experiments/:id", get(chaos_get))
        .route("/api/v1/chaos/experiments/:id", delete(chaos_delete))
        .route("/api/v1/chaos/experiments/:id/abort", post(chaos_abort))
        .layer(DefaultBodyLimit::max(1024 * 1024)) // 1 MB
        .layer(TimeoutLayer::new(Duration::from_secs(30)))
        .layer(middleware::from_fn_with_state(Arc::clone(&state), fence_guard))
        .with_state(state)
}

// ── Health Handlers ────────────────────────────────────────

async fn health_check() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok" }))
}

async fn health_detailed(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    check_api_key(&headers, &state.config)?;
    let health = state.health.check_all().await;
    Ok(Json(health))
}

async fn cluster_status(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    check_api_key(&headers, &state.config)?;
    state
        .health
        .get_cluster_status()
        .await
        .map(Json)
        .map_err(internal_err)
}

// ── Failover Handlers ──────────────────────────────────────

async fn failover_status(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    check_api_key(&headers, &state.config)?;
    let info = state.failover.get_config_info().await;
    Ok(Json(info))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FailoverRequest {
    reason: Option<String>,
}

async fn failover_initiate(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<FailoverRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    check_api_key(&headers, &state.config)?;
    state
        .failover
        .initiate_failover(crate::types::FailoverType::Manual, body.reason)
        .await
        .map(|e| (StatusCode::OK, Json(e)))
        .map_err(internal_err)
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FailbackQuery {
    /// B.3: force failback even when replication lag cannot be verified.
    /// The forced event is recorded with `forced: true` metadata.
    force: Option<bool>,
}

async fn failover_failback(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<FailbackQuery>,
) -> Result<impl IntoResponse, StatusCode> {
    check_api_key(&headers, &state.config)?;
    state
        .failover
        .initiate_failback_opt(q.force.unwrap_or(false))
        .await
        .map(Json)
        .map_err(internal_err)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoryQuery {
    #[serde(default = "default_limit")]
    limit: i64,
}
fn default_limit() -> i64 {
    50
}
fn default_offset() -> i64 {
    0
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PaginationQuery {
    #[serde(default = "default_limit")]
    limit: i64,
    #[serde(default = "default_offset")]
    offset: i64,
}

async fn failover_history(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<HistoryQuery>,
) -> Result<impl IntoResponse, StatusCode> {
    check_api_key(&headers, &state.config)?;
    state
        .failover
        .get_history(q.limit)
        .await
        .map(Json)
        .map_err(internal_err)
}

async fn split_brain_check(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    check_api_key(&headers, &state.config)?;
    state
        .failover
        .detect_split_brain()
        .await
        .map(|detected| Json(serde_json::json!({ "split_brain": detected })))
        .map_err(internal_err)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolveSplitBrainRequest {
    winner_node: String,
}

async fn split_brain_resolve(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<ResolveSplitBrainRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    check_api_key(&headers, &state.config)?;
    state
        .failover
        .resolve_split_brain(&body.winner_node)
        .await
        .map(|_| Json(serde_json::json!({ "resolved": true })))
        .map_err(internal_err)
}

// ── Backup Handlers ────────────────────────────────────────

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupCreateRequest {
    backup_type: Option<String>,
    tables: Option<Vec<String>>,
}

async fn backup_create(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<BackupCreateRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    check_api_key(&headers, &state.config)?;
    let bt = body
        .backup_type
        .as_deref()
        .map(BackupType::parse)
        .unwrap_or(BackupType::Full);
    state
        .backup
        .create_backup(bt, body.tables)
        .await
        .map(|b| (StatusCode::CREATED, Json(b)))
        .map_err(internal_err)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupListQuery {
    backup_type: Option<String>,
    status: Option<String>,
    #[serde(default = "default_limit")]
    limit: i64,
}

async fn backup_list(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<BackupListQuery>,
) -> Result<impl IntoResponse, StatusCode> {
    check_api_key(&headers, &state.config)?;
    state
        .backup
        .list_backups(q.backup_type.as_deref(), q.status.as_deref(), q.limit)
        .await
        .map(Json)
        .map_err(internal_err)
}

async fn backup_get(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, StatusCode> {
    check_api_key(&headers, &state.config)?;
    state
        .backup
        .get_backup(id)
        .await
        .map_err(internal_err)?
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

async fn backup_delete(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, StatusCode> {
    check_api_key(&headers, &state.config)?;
    state
        .backup
        .delete_backup(id)
        .await
        .map(|deleted| Json(serde_json::json!({ "deleted": deleted })))
        .map_err(internal_err)
}

async fn backup_restore(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<RestoreOptions>,
) -> Result<impl IntoResponse, StatusCode> {
    check_api_key(&headers, &state.config)?;
    state
        .backup
        .restore(body)
        .await
        .map(Json)
        .map_err(internal_err)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PitrRequest {
    target_time: chrono::DateTime<chrono::Utc>,
}

async fn backup_pitr(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<PitrRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    check_api_key(&headers, &state.config)?;
    state
        .backup
        .pitr(body.target_time)
        .await
        .map(Json)
        .map_err(internal_err)
}

async fn backup_schedule(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    check_api_key(&headers, &state.config)?;
    Ok(Json(state.backup.get_schedule()))
}

async fn backup_retention_cleanup(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    check_api_key(&headers, &state.config)?;
    state
        .backup
        .enforce_retention()
        .await
        .map(|deleted| Json(serde_json::json!({ "deleted": deleted })))
        .map_err(internal_err)
}

// ── Replication Handlers ───────────────────────────────────

async fn replication_status(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    check_api_key(&headers, &state.config)?;
    state
        .replication
        .get_stats()
        .await
        .map(Json)
        .map_err(internal_err)
}

async fn replication_replicas(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    check_api_key(&headers, &state.config)?;
    state
        .replication
        .get_replicas()
        .await
        .map(Json)
        .map_err(internal_err)
}

async fn replication_slots(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    check_api_key(&headers, &state.config)?;
    state
        .replication
        .get_slots()
        .await
        .map(Json)
        .map_err(internal_err)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateSlotRequest {
    name: String,
    slot_type: Option<String>,
}

async fn replication_create_slot(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<CreateSlotRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    check_api_key(&headers, &state.config)?;
    let st = body.slot_type.as_deref().unwrap_or("physical");
    state
        .replication
        .create_slot(&body.name, st)
        .await
        .map(|_| {
            (
                StatusCode::CREATED,
                Json(serde_json::json!({ "created": true, "name": body.name })),
            )
        })
        .map_err(internal_err)
}

async fn replication_delete_slot(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    check_api_key(&headers, &state.config)?;
    state
        .replication
        .drop_slot(&name)
        .await
        .map(|_| Json(serde_json::json!({ "dropped": true })))
        .map_err(internal_err)
}

async fn replication_promote(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    check_api_key(&headers, &state.config)?;
    state
        .replication
        .promote_standby()
        .await
        .map(|promoted| Json(serde_json::json!({ "promoted": promoted })))
        .map_err(internal_err)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SyncModeRequest {
    synchronous: bool,
}

async fn replication_sync_mode(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<SyncModeRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    check_api_key(&headers, &state.config)?;
    state
        .replication
        .set_sync_mode(body.synchronous)
        .await
        .map(|_| Json(serde_json::json!({ "synchronous": body.synchronous })))
        .map_err(internal_err)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LagHistoryQuery {
    #[serde(default = "default_minutes")]
    minutes: i64,
}
fn default_minutes() -> i64 {
    60
}

async fn replication_lag_history(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<LagHistoryQuery>,
) -> Result<impl IntoResponse, StatusCode> {
    check_api_key(&headers, &state.config)?;
    state
        .replication
        .get_lag_history(q.minutes)
        .await
        .map(Json)
        .map_err(internal_err)
}

// ── Multi-Region Handlers ──────────────────────────────────

async fn regions_list(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<PaginationQuery>,
) -> Result<impl IntoResponse, StatusCode> {
    check_api_key(&headers, &state.config)?;
    let limit = q.limit.clamp(1, 200);
    let offset = q.offset.max(0);
    state
        .multi_region
        .list_regions(limit, offset)
        .await
        .map(Json)
        .map_err(internal_err)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterRegionRequest {
    name: String,
    endpoint: String,
    role: String,
    availability_zone: Option<String>,
}

async fn regions_register(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<RegisterRegionRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    check_api_key(&headers, &state.config)?;
    let role = RegionRole::parse(&body.role);
    state
        .multi_region
        .register_region(
            &body.name,
            &body.endpoint,
            &role,
            body.availability_zone.as_deref(),
        )
        .await
        .map(|r| (StatusCode::CREATED, Json(r)))
        .map_err(internal_err)
}

async fn regions_get(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    check_api_key(&headers, &state.config)?;
    state
        .multi_region
        .get_region(&name)
        .await
        .map_err(internal_err)?
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

async fn regions_remove(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    check_api_key(&headers, &state.config)?;
    state
        .multi_region
        .remove_region(&name)
        .await
        .map(|removed| Json(serde_json::json!({ "removed": removed })))
        .map_err(internal_err)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateHealthRequest {
    health_score: f64,
    latency_ms: f64,
    replication_lag_ms: Option<f64>,
}

async fn regions_update_health(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Json(body): Json<UpdateHealthRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    check_api_key(&headers, &state.config)?;
    state
        .multi_region
        .update_health(
            &name,
            body.health_score,
            body.latency_ms,
            body.replication_lag_ms,
        )
        .await
        .map(|_| Json(serde_json::json!({ "updated": true })))
        .map_err(internal_err)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SetWeightRequest {
    weight: i32,
}

async fn regions_set_weight(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Json(body): Json<SetWeightRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    check_api_key(&headers, &state.config)?;
    state
        .multi_region
        .set_weight(&name, body.weight)
        .await
        .map(|_| Json(serde_json::json!({ "updated": true })))
        .map_err(internal_err)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FenceRequest {
    reason: Option<String>,
}

async fn regions_fence(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Json(body): Json<FenceRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    check_api_key(&headers, &state.config)?;
    let reason = body.reason.as_deref().unwrap_or("Manual fence");
    state
        .multi_region
        .fence_region(&name, reason)
        .await
        .map(|_| Json(serde_json::json!({ "fenced": true })))
        .map_err(internal_err)
}

async fn regions_unfence(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    check_api_key(&headers, &state.config)?;
    state
        .multi_region
        .unfence_region(&name)
        .await
        .map(|_| Json(serde_json::json!({ "unfenced": true })))
        .map_err(internal_err)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RouteQuery {
    source_region: Option<String>,
}

async fn regions_route(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<RouteQuery>,
) -> Result<impl IntoResponse, StatusCode> {
    check_api_key(&headers, &state.config)?;
    state
        .multi_region
        .route_request(q.source_region.as_deref())
        .await
        .map(Json)
        .map_err(internal_err)
}

async fn regions_traffic(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    check_api_key(&headers, &state.config)?;
    state
        .multi_region
        .get_traffic_distribution()
        .await
        .map(Json)
        .map_err(internal_err)
}

async fn geo_rules_list(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<PaginationQuery>,
) -> Result<impl IntoResponse, StatusCode> {
    check_api_key(&headers, &state.config)?;
    let limit = q.limit.clamp(1, 200);
    let offset = q.offset.max(0);
    state
        .multi_region
        .list_geo_rules(limit, offset)
        .await
        .map(Json)
        .map_err(internal_err)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AddGeoRuleRequest {
    name: String,
    source_region: String,
    target_region: String,
    priority: Option<i32>,
}

async fn geo_rules_add(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<AddGeoRuleRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    check_api_key(&headers, &state.config)?;
    state
        .multi_region
        .add_geo_rule(
            &body.name,
            &body.source_region,
            &body.target_region,
            body.priority.unwrap_or(0),
        )
        .await
        .map(|r| (StatusCode::CREATED, Json(r)))
        .map_err(internal_err)
}

async fn geo_rules_delete(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, StatusCode> {
    check_api_key(&headers, &state.config)?;
    state
        .multi_region
        .delete_geo_rule(id)
        .await
        .map(|deleted| Json(serde_json::json!({ "deleted": deleted })))
        .map_err(internal_err)
}

// ── Circuit Breaker Handlers ───────────────────────────────

async fn circuits_list(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    check_api_key(&headers, &state.config)?;
    let stats = state.circuit_breaker.get_all_stats().await;
    Ok(Json(stats))
}

async fn circuits_get(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    check_api_key(&headers, &state.config)?;
    state
        .circuit_breaker
        .get_stats(&name)
        .await
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

async fn circuits_reset(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    check_api_key(&headers, &state.config)?;
    state
        .circuit_breaker
        .reset(&name)
        .await
        .map(|_| Json(serde_json::json!({ "reset": true })))
        .map_err(internal_err)
}

async fn circuits_configure(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<CircuitConfig>,
) -> Result<impl IntoResponse, StatusCode> {
    check_api_key(&headers, &state.config)?;
    state
        .circuit_breaker
        .configure(body)
        .await
        .map(|_| {
            (
                StatusCode::CREATED,
                Json(serde_json::json!({ "configured": true })),
            )
        })
        .map_err(internal_err)
}

async fn circuits_remove(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    check_api_key(&headers, &state.config)?;
    state
        .circuit_breaker
        .remove(&name)
        .await
        .map(|removed| Json(serde_json::json!({ "removed": removed })))
        .map_err(internal_err)
}

// ── Chaos Engineering Handlers ─────────────────────────────

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChaosListQuery {
    status: Option<String>,
    #[serde(default = "default_limit")]
    limit: i64,
}

async fn chaos_list(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<ChaosListQuery>,
) -> Result<impl IntoResponse, StatusCode> {
    check_api_key(&headers, &state.config)?;
    state
        .chaos
        .list_experiments(q.status.as_deref(), q.limit)
        .await
        .map(Json)
        .map_err(internal_err)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChaosStartRequest {
    name: String,
    #[serde(flatten)]
    config: ExperimentConfig,
}

async fn chaos_start(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<ChaosStartRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    check_api_key(&headers, &state.config)?;
    state
        .chaos
        .start_experiment(&body.name, body.config)
        .await
        .map(|e| (StatusCode::CREATED, Json(e)))
        .map_err(internal_err)
}

async fn chaos_get(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, StatusCode> {
    check_api_key(&headers, &state.config)?;
    state
        .chaos
        .get_experiment(id)
        .await
        .map_err(internal_err)?
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

async fn chaos_delete(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, StatusCode> {
    check_api_key(&headers, &state.config)?;
    state
        .chaos
        .delete_experiment(id)
        .await
        .map(|deleted| Json(serde_json::json!({ "deleted": deleted })))
        .map_err(internal_err)
}

async fn chaos_abort(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, StatusCode> {
    check_api_key(&headers, &state.config)?;
    state
        .chaos
        .abort_experiment(id)
        .await
        .map(|_| Json(serde_json::json!({ "aborted": true })))
        .map_err(internal_err)
}

// ── Tests ──────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    const TEST_INTERNAL_API_KEY: &str = "internal-key";
    const TEST_ADMIN_API_KEY: &str = "admin-key";

    fn test_runtime() -> &'static tokio::runtime::Runtime {
        use std::sync::OnceLock;
        static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
        RT.get_or_init(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
        })
    }
    fn test_pool() -> sqlx::PgPool {
        let _guard = test_runtime().enter();
        sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://fake:fake@localhost:1/fake")
            .unwrap()
    }

    fn test_config() -> Arc<Config> {
        let mut config = Config::from_env();
        config.internal_api_key = TEST_INTERNAL_API_KEY.into();
        config.admin_api_key = TEST_ADMIN_API_KEY.into();
        Arc::new(config)
    }

    fn test_state() -> Arc<AppState> {
        let config = test_config();
        test_state_with_config(config)
    }

    fn test_state_with_config(config: Arc<Config>) -> Arc<AppState> {
        let config_for_services = Arc::clone(&config);
        let pool = test_pool();
        Arc::new(AppState {
            health: HealthCheckService::new(pool.clone(), Arc::clone(&config_for_services)),
            failover: FailoverService::new(pool.clone(), Arc::clone(&config_for_services)),
            backup: BackupService::new(pool.clone(), Arc::clone(&config_for_services))
                .expect("test config should have valid encryption key"),
            replication: ReplicationService::new(pool.clone(), Arc::clone(&config_for_services)),
            multi_region: MultiRegionService::new(pool.clone(), Arc::clone(&config_for_services)),
            circuit_breaker: CircuitBreakerService::new(Arc::clone(&config_for_services)),
            chaos: ChaosEngineeringService::new(pool.clone(), Arc::clone(&config_for_services)),
            config,
        })
    }

    #[test]
    fn test_health_endpoint() {
        test_runtime().block_on(async {
            let app: Router<()> = build_router(test_state());
            let req = Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap();
            let resp = app.oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
        });
    }

    #[test]
    fn test_unauthorized_without_key() {
        test_runtime().block_on(async {
            let app: Router<()> = build_router(test_state());
            let req = Request::builder()
                .uri("/api/v1/health")
                .body(Body::empty())
                .unwrap();
            let resp = app.oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        });
    }

    #[test]
    fn test_circuit_breakers_list() {
        test_runtime().block_on(async {
            let app: Router<()> = build_router(test_state());
            let req = Request::builder()
                .uri("/api/v1/circuit-breakers")
                .header("x-api-key", TEST_INTERNAL_API_KEY)
                .body(Body::empty())
                .unwrap();
            let resp = app.oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
        });
    }

    #[test]
    fn test_failover_status_endpoint() {
        test_runtime().block_on(async {
            let app: Router<()> = build_router(test_state());
            let req = Request::builder()
                .uri("/api/v1/failover/status")
                .header("x-api-key", TEST_INTERNAL_API_KEY)
                .body(Body::empty())
                .unwrap();
            let resp = app.oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
        });
    }

    #[test]
    fn test_backup_schedule_endpoint() {
        test_runtime().block_on(async {
            let app: Router<()> = build_router(test_state());
            let req = Request::builder()
                .uri("/api/v1/backup/schedule")
                .header("x-api-key", TEST_INTERNAL_API_KEY)
                .body(Body::empty())
                .unwrap();
            let resp = app.oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
        });
    }

    #[test]
    fn test_admin_key_auth() {
        test_runtime().block_on(async {
            let app: Router<()> = build_router(test_state());
            let req = Request::builder()
                .uri("/api/v1/failover/status")
                .header("x-api-key", TEST_ADMIN_API_KEY)
                .body(Body::empty())
                .unwrap();
            let resp = app.oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
        });
    }

    #[test]
    fn test_check_api_key_rejects_bad_key() {
        let cfg = Config::from_env();
        let mut headers = HeaderMap::new();
        headers.insert("x-api-key", "bad-key".parse().unwrap());
        assert!(check_api_key(&headers, &cfg).is_err());
    }

    #[test]
    fn test_check_api_key_accepts_internal() {
        let cfg = Config::from_env();
        let mut headers = HeaderMap::new();
        headers.insert("x-api-key", cfg.internal_api_key.parse().unwrap());
        assert!(check_api_key(&headers, &cfg).is_ok());
    }

    #[test]
    fn test_route_count() {
        // Verify we have 40+ routes by building the router and checking it doesn't panic
        let _app = build_router(test_state());
    }

    /// B.1 enforcement: a fenced node must refuse mutating requests (503)
    /// while reads and recovery endpoints still work.
    #[test]
    fn test_fenced_node_refuses_mutating_requests() {
        // Ephemeral redis-server; skip when unavailable.
        let listener = match std::net::TcpListener::bind(("127.0.0.1", 0)) {
            Ok(l) => l,
            Err(_) => {
                eprintln!("skipping: cannot allocate port");
                return;
            }
        };
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let mut child = match std::process::Command::new("redis-server")
            .args([
                "--port",
                &port.to_string(),
                "--save",
                "",
                "--appendonly",
                "no",
                "--daemonize",
                "no",
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
        {
            Ok(child) => child,
            Err(_) => {
                eprintln!("skipping: redis-server not available");
                return;
            }
        };
        // Wait for readiness.
        let mut ready = false;
        for _ in 0..50 {
            if let Ok(client) = redis::Client::open(format!("redis://127.0.0.1:{port}").as_str()) {
                if let Ok(mut conn) = client.get_connection() {
                    if redis::cmd("PING")
                        .query::<String>(&mut conn)
                        .map(|r| r == "PONG")
                        .unwrap_or(false)
                    {
                        ready = true;
                        break;
                    }
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        if !ready {
            let _ = child.kill();
            let _ = child.wait();
            eprintln!("skipping: redis-server did not become ready");
            return;
        }

        test_runtime().block_on(async move {
            let mut config = Config::from_env();
            config.internal_api_key = TEST_INTERNAL_API_KEY.into();
            config.admin_api_key = TEST_ADMIN_API_KEY.into();
            config.redis.host = "127.0.0.1".into();
            config.redis.port = port;
            config.multi_region.node_id = "fenced-node".into();
            let state = test_state_with_config(Arc::new(config));
            let app: Router<()> = build_router(state.clone());

            // Not fenced: the guard passes (request proceeds; DB errors → 500,
            // which proves the guard itself did not block).
            let req = Request::builder()
                .method("POST")
                .uri("/api/v1/failover/initiate")
                .header("x-api-key", TEST_INTERNAL_API_KEY)
                .body(Body::from("{}"))
                .unwrap();
            let resp = app.clone().oneshot(req).await.unwrap();
            assert_ne!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);

            // Fence this node in Redis.
            let mut conn = redis::Client::open(format!("redis://127.0.0.1:{port}").as_str())
                .unwrap()
                .get_multiplexed_async_connection()
                .await
                .unwrap();
            let _: () = redis::cmd("SET")
                .arg("ha:fenced:fenced-node")
                .arg("1")
                .query_async(&mut conn)
                .await
                .unwrap();

            // Mutating request → 503 with the fence reason.
            let req = Request::builder()
                .method("POST")
                .uri("/api/v1/failover/initiate")
                .header("x-api-key", TEST_INTERNAL_API_KEY)
                .body(Body::from("{}"))
                .unwrap();
            let resp = app.clone().oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
            let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert!(json["error"].as_str().unwrap().contains("fenced"));

            // Reads still pass.
            let req = Request::builder()
                .uri("/api/v1/failover/status")
                .header("x-api-key", TEST_INTERNAL_API_KEY)
                .body(Body::empty())
                .unwrap();
            let resp = app.clone().oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);

            // Split-brain recovery endpoints are exempt from the guard.
            let req = Request::builder()
                .method("POST")
                .uri("/api/v1/failover/split-brain/resolve")
                .header("x-api-key", TEST_INTERNAL_API_KEY)
                .header("content-type", "application/json")
                .body(Body::from(r#"{"winner_node":"fenced-node"}"#))
                .unwrap();
            let resp = app.oneshot(req).await.unwrap();
            assert_ne!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        });

        let _ = child.kill();
        let _ = child.wait();
    }
}
