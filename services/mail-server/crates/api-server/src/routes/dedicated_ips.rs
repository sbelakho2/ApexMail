//! Dedicated IP management routes.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{delete, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::ApiError;
use crate::middleware::auth::{require_scopes, AuthUser};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", post(allocate_ip).get(list_ips))
        .route("/:id", delete(release_ip))
        .route("/:id/warmup", post(start_warmup))
}

// ─── Types ─────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct AllocateIpRequest {
    #[serde(default)]
    pub region: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DedicatedIpResponse {
    pub id: Uuid,
    pub ip_address: String,
    pub region: String,
    pub status: String,
    pub warmup_progress: f64,
    pub allocated_at: String,
}

#[derive(Debug, Serialize)]
pub struct WarmupResponse {
    pub id: Uuid,
    pub ip_address: String,
    pub warmup_status: String,
    pub warmup_progress: f64,
    pub estimated_completion: String,
}

// ─── Handlers ──────────────────────────────────────────────────

async fn allocate_ip(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<AllocateIpRequest>,
) -> Result<(StatusCode, Json<DedicatedIpResponse>), ApiError> {
    require_scopes(&auth, &["dedicated_ips:write"])?;

    let id = Uuid::new_v4();
    let now = Utc::now();
    let region = body.region.unwrap_or_else(|| "us-east-1".into());

    // In production, this would allocate from an IP pool.
    let ip_address = format!("198.51.100.{}", (id.as_bytes()[0] % 254) + 1);

    sqlx::query(
        "INSERT INTO dedicated_ips (id, tenant_id, ip_address, region, status, warmup_progress, allocated_at)
         VALUES ($1,$2,$3,$4,'allocated',0.0,$5)",
    )
    .bind(id)
    .bind(auth.tenant_id)
    .bind(&ip_address)
    .bind(&region)
    .bind(now)
    .execute(&state.db)
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(DedicatedIpResponse {
            id,
            ip_address,
            region,
            status: "allocated".into(),
            warmup_progress: 0.0,
            allocated_at: now.to_rfc3339(),
        }),
    ))
}

async fn list_ips(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Vec<DedicatedIpResponse>>, ApiError> {
    require_scopes(&auth, &["dedicated_ips:read"])?;

    let rows = sqlx::query_as::<_, DedicatedIpRow>(
        "SELECT id, ip_address, region, status, warmup_progress, allocated_at
         FROM dedicated_ips WHERE tenant_id = $1 ORDER BY allocated_at DESC",
    )
    .bind(auth.tenant_id)
    .fetch_all(&state.db)
    .await?;

    Ok(Json(rows.into_iter().map(Into::into).collect()))
}

async fn release_ip(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    require_scopes(&auth, &["dedicated_ips:write"])?;

    let result = sqlx::query(
        "DELETE FROM dedicated_ips WHERE id = $1 AND tenant_id = $2",
    )
    .bind(id)
    .bind(auth.tenant_id)
    .execute(&state.db)
    .await?;

    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound("dedicated IP not found".into()));
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn start_warmup(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<WarmupResponse>, ApiError> {
    require_scopes(&auth, &["dedicated_ips:write"])?;

    let row = sqlx::query_as::<_, DedicatedIpRow>(
        "SELECT id, ip_address, region, status, warmup_progress, allocated_at
         FROM dedicated_ips WHERE id = $1 AND tenant_id = $2",
    )
    .bind(id)
    .bind(auth.tenant_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NotFound("dedicated IP not found".into()))?;

    sqlx::query(
        "UPDATE dedicated_ips SET status = 'warming_up', warmup_progress = 0.01 WHERE id = $1",
    )
    .bind(id)
    .execute(&state.db)
    .await?;

    let est_days = 30; // Standard IP warmup ~30 days
    let est_completion = Utc::now() + chrono::Duration::days(est_days);

    Ok(Json(WarmupResponse {
        id: row.id,
        ip_address: row.ip_address,
        warmup_status: "warming_up".into(),
        warmup_progress: 0.01,
        estimated_completion: est_completion.to_rfc3339(),
    }))
}

// ─── Row types ─────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct DedicatedIpRow {
    id: Uuid,
    ip_address: String,
    region: String,
    status: String,
    warmup_progress: f64,
    allocated_at: DateTime<Utc>,
}

impl From<DedicatedIpRow> for DedicatedIpResponse {
    fn from(r: DedicatedIpRow) -> Self {
        Self {
            id: r.id,
            ip_address: r.ip_address,
            region: r.region,
            status: r.status,
            warmup_progress: r.warmup_progress,
            allocated_at: r.allocated_at.to_rfc3339(),
        }
    }
}

// ─── Tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allocate_ip_deser_defaults() {
        let json = r#"{}"#;
        let req: AllocateIpRequest = serde_json::from_str(json).unwrap();
        assert!(req.region.is_none());
    }

    #[test]
    fn test_ip_response_serialisation() {
        let resp = DedicatedIpResponse {
            id: Uuid::nil(),
            ip_address: "198.51.100.1".into(),
            region: "us-east-1".into(),
            status: "allocated".into(),
            warmup_progress: 0.0,
            allocated_at: "2026-01-01T00:00:00Z".into(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["ip_address"], "198.51.100.1");
    }

    #[test]
    fn test_warmup_response_serialisation() {
        let resp = WarmupResponse {
            id: Uuid::nil(),
            ip_address: "198.51.100.1".into(),
            warmup_status: "warming_up".into(),
            warmup_progress: 0.5,
            estimated_completion: "2026-02-01T00:00:00Z".into(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["warmup_progress"], 0.5);
    }
}
