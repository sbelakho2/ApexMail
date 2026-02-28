//! Dedicated IP management routes.
//!
//! Provides full lifecycle management for dedicated sending IPs:
//! allocation (via AWS SES), warmup, monitoring, and release.
//!
//! ## Plan gating
//!
//! Only plans with `dedicated_ip = true` in their feature set may
//! allocate IPs. IPs within the plan's `dedicated_ip_count` are
//! marked `included` (no charge); additional IPs are `pending_charge`
//! and billed at $30/mo via the billing service.
//!
//! ## AWS SES integration
//!
//! Each tenant gets a dedicated SES IP pool named `apexmail-{tid}`.
//! IPs are drawn from a pre-provisioned `ses_ip_inventory` table
//! and assigned to the tenant's pool via `PutDedicatedIpInPool`.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{delete, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::info;
use uuid::Uuid;

use crate::error::ApiError;
use crate::middleware::auth::{require_scopes, AuthUser};
use crate::ses_provider::SesProviderError;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", post(allocate_ip).get(list_ips))
        .route("/:id", delete(release_ip))
        .route("/:id/warmup", post(start_warmup))
}

// ─── Request / response types ──────────────────────────────────

#[derive(Debug, Deserialize, Default)]
pub struct AllocateIpRequest {
    #[serde(default)]
    pub region: Option<String>,
}

/// Per-IP response matching the console's `DedicatedIpResponse` interface.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DedicatedIpResponse {
    pub id: Uuid,
    pub ip_address: String,
    pub ptr_record: Option<String>,
    pub status: String,
    pub warmup: WarmupDetail,
    pub reputation: ReputationDetail,
    pub stats: IpStats,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WarmupDetail {
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
    pub progress_percent: f64,
    pub current_daily_limit: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct ReputationDetail {
    pub score: f64,
    pub blocklisted: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IpStats {
    pub emails_sent_total: i64,
    pub bounces_total: i64,
    pub complaints_total: i64,
}

/// Plan allocation summary returned alongside the IP list.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AllocationResponse {
    pub included: i32,
    pub active: i64,
    pub add_on_available: bool,
    pub add_on_price_monthly: i32,
}

/// Top-level envelope matching the console's `ListResponse`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListResponse {
    pub dedicated_ips: Vec<DedicatedIpResponse>,
    pub allocation: Option<AllocationResponse>,
    pub pagination: PaginationMeta,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PaginationMeta {
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
    pub has_more: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WarmupResponse {
    pub id: Uuid,
    pub ip_address: String,
    pub warmup_status: String,
    pub warmup_progress: f64,
    pub estimated_completion: String,
}

#[derive(Debug, Deserialize)]
pub struct ListIpsQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 {
    50
}

fn clamp_limit(limit: i64, max: i64) -> i64 {
    limit.clamp(1, max)
}

/// Dedicated IP add-on price in cents/month (matches billing service constant).
const ADD_ON_PRICE_CENTS: i32 = 3000;

// ─── Handlers ──────────────────────────────────────────────────

/// `POST /v1/dedicated-ips` — Allocate a new dedicated IP for the tenant.
///
/// Plan-gated: checks subscription → plan → `dedicated_ip` feature flag.
/// IPs within `dedicated_ip_count` are `included`; extras are `pending_charge`.
async fn allocate_ip(
    State(state): State<AppState>,
    auth: AuthUser,
    body: Option<Json<AllocateIpRequest>>,
) -> Result<(StatusCode, Json<DedicatedIpResponse>), ApiError> {
    require_scopes(&auth, &["dedicated_ips:write"])?;

    let region = body
        .and_then(|b| b.0.region)
        .unwrap_or_else(|| state.config.aws_region.clone());

    // Delegate to SES provider (handles plan check, inventory pick, SES API call)
    let allocated = state
        .ses_provider
        .allocate_ip(auth.tenant_id, Some(&region))
        .await
        .map_err(ses_to_api_error)?;

    // Fetch the just-created DB row for the full response
    let row = sqlx::query_as::<_, DedicatedIpRow>(
        "SELECT id, ip_address, ptr_record, region, ses_pool_name, status,
                warmup_progress, warmup_started_at, warmup_completed_at,
                billing_status, allocated_at, created_at, updated_at
         FROM dedicated_ips
         WHERE tenant_id = $1 AND ip_address = $2
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(auth.tenant_id)
    .bind(&allocated.ip_address)
    .fetch_one(&state.db)
    .await?;

    info!(
        ip = %allocated.ip_address,
        pool = %allocated.ses_pool_name,
        tenant_id = %auth.tenant_id,
        "Dedicated IP allocated via SES"
    );

    Ok((StatusCode::CREATED, Json(row.into_response())))
}

/// `GET /v1/dedicated-ips` — List tenant's dedicated IPs with allocation summary.
///
/// Returns the enriched `ListResponse` envelope expected by the console.
async fn list_ips(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<ListIpsQuery>,
) -> Result<Json<ListResponse>, ApiError> {
    require_scopes(&auth, &["dedicated_ips:read"])?;

    let limit = clamp_limit(params.limit, 200);
    let offset = params.offset.clamp(0, 100_000);

    // Count total IPs (non-retired) for pagination
    let (total,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM dedicated_ips
         WHERE tenant_id = $1 AND status != 'retired'",
    )
    .bind(auth.tenant_id)
    .fetch_one(&state.db)
    .await?;

    // Fetch IPs (include retired for history, most recent first)
    let rows = sqlx::query_as::<_, DedicatedIpRow>(
        "SELECT id, ip_address, ptr_record, region, ses_pool_name, status,
                warmup_progress, warmup_started_at, warmup_completed_at,
                billing_status, allocated_at, created_at, updated_at
         FROM dedicated_ips
         WHERE tenant_id = $1
         ORDER BY created_at DESC
         LIMIT $2 OFFSET $3",
    )
    .bind(auth.tenant_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.db)
    .await?;

    // Build allocation summary from the tenant's plan
    let allocation = build_allocation_summary(&state, auth.tenant_id).await?;

    let ips: Vec<DedicatedIpResponse> = rows.into_iter().map(|r| r.into_response()).collect();

    Ok(Json(ListResponse {
        dedicated_ips: ips,
        allocation,
        pagination: PaginationMeta {
            total,
            limit,
            offset,
            has_more: offset + limit < total,
        },
    }))
}

/// `DELETE /v1/dedicated-ips/:id` — Release a dedicated IP.
///
/// Moves the IP out of the tenant's SES pool, marks billing as `pending_cancel`,
/// and returns the IP to the available inventory.
async fn release_ip(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    require_scopes(&auth, &["dedicated_ips:write"])?;

    state
        .ses_provider
        .release_ip(id, auth.tenant_id)
        .await
        .map_err(ses_to_api_error)?;

    info!(
        id = %id,
        tenant_id = %auth.tenant_id,
        "Dedicated IP released"
    );

    Ok(StatusCode::NO_CONTENT)
}

/// `POST /v1/dedicated-ips/:id/warmup` — Start or resume IP warmup.
///
/// Triggers SES warmup and updates local tracking.
async fn start_warmup(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<WarmupResponse>, ApiError> {
    require_scopes(&auth, &["dedicated_ips:write"])?;

    let ses_status = state
        .ses_provider
        .start_warmup(id, auth.tenant_id)
        .await
        .map_err(ses_to_api_error)?;

    let est_days: i64 = state.config.ses_default_warmup_days as i64;
    let est_completion = Utc::now() + chrono::Duration::days(est_days);

    Ok(Json(WarmupResponse {
        id,
        ip_address: ses_status.ip_address,
        warmup_status: "warming".into(),
        warmup_progress: ses_status.warmup_percentage as f64 / 100.0,
        estimated_completion: est_completion.to_rfc3339(),
    }))
}

// ─── Helpers ───────────────────────────────────────────────────

/// Build the `AllocationResponse` for a tenant from their active plan.
async fn build_allocation_summary(
    state: &AppState,
    tenant_id: Uuid,
) -> Result<Option<AllocationResponse>, ApiError> {
    let plan_row: Option<(bool, i32)> = sqlx::query_as(
        "SELECT
            COALESCE((p.features->>'dedicated_ip')::boolean, false),
            COALESCE((p.features->>'dedicated_ip_count')::int, 0)
         FROM subscriptions s
         JOIN plans p ON p.name = s.plan_name
         WHERE s.tenant_id = $1 AND s.status = 'active'
         ORDER BY s.created_at DESC LIMIT 1",
    )
    .bind(tenant_id)
    .fetch_optional(&state.db)
    .await?;

    let (allowed, included) = match plan_row {
        Some(row) => row,
        None => return Ok(None),
    };

    if !allowed {
        return Ok(None);
    }

    let (active,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM dedicated_ips
         WHERE tenant_id = $1 AND status NOT IN ('retired', 'releasing')",
    )
    .bind(tenant_id)
    .fetch_one(&state.db)
    .await?;

    Ok(Some(AllocationResponse {
        included,
        active,
        add_on_available: true,
        add_on_price_monthly: ADD_ON_PRICE_CENTS,
    }))
}

/// Convert SES provider errors to API errors.
fn ses_to_api_error(e: SesProviderError) -> ApiError {
    match e {
        SesProviderError::PlanNotEligible => {
            ApiError::Forbidden("your plan does not include dedicated IP access — please upgrade to Pro or above".into())
        }
        SesProviderError::LimitReached { limit, .. } => {
            ApiError::BadRequest(format!(
                "dedicated IP limit reached ({limit}). Contact support to increase your allocation."
            ))
        }
        SesProviderError::NoAvailableIps { region } => {
            ApiError::ServiceUnavailable(format!(
                "no dedicated IPs currently available in {region}. Please try again shortly or contact support."
            ))
        }
        SesProviderError::IpNotFound { .. } => {
            ApiError::NotFound("dedicated IP not found".into())
        }
        SesProviderError::SesApi(msg) => {
            tracing::error!(error = %msg, "SES API error during dedicated IP operation");
            ApiError::Internal("failed to communicate with IP provisioning service".into())
        }
        SesProviderError::Database(err) => {
            tracing::error!(error = %err, "database error in dedicated IP operation");
            ApiError::Internal("database error".into())
        }
    }
}

// ─── Row types ─────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct DedicatedIpRow {
    id: Uuid,
    ip_address: String,
    ptr_record: Option<String>,
    #[allow(dead_code)]
    region: String,
    #[allow(dead_code)]
    ses_pool_name: Option<String>,
    status: String,
    warmup_progress: f64,
    warmup_started_at: Option<DateTime<Utc>>,
    warmup_completed_at: Option<DateTime<Utc>>,
    #[allow(dead_code)]
    billing_status: Option<String>,
    #[allow(dead_code)]
    allocated_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl DedicatedIpRow {
    fn into_response(self) -> DedicatedIpResponse {
        DedicatedIpResponse {
            id: self.id,
            ip_address: self.ip_address,
            ptr_record: self.ptr_record,
            status: self.status.clone(),
            warmup: WarmupDetail {
                started_at: self.warmup_started_at.map(|d| d.to_rfc3339()),
                completed_at: self.warmup_completed_at.map(|d| d.to_rfc3339()),
                progress_percent: self.warmup_progress * 100.0,
                current_daily_limit: None, // Populated by warmup sync job
            },
            reputation: ReputationDetail {
                score: 100.0, // Default score; updated by reputation monitoring
                blocklisted: false,
            },
            stats: IpStats {
                emails_sent_total: 0, // Populated from analytics aggregation
                bounces_total: 0,
                complaints_total: 0,
            },
            created_at: self.created_at.to_rfc3339(),
            updated_at: self.updated_at.to_rfc3339(),
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
            ip_address: "1.2.3.4".into(),
            ptr_record: Some("mail.example.com".into()),
            status: "active".into(),
            warmup: WarmupDetail {
                started_at: Some("2026-01-01T00:00:00Z".into()),
                completed_at: Some("2026-01-15T00:00:00Z".into()),
                progress_percent: 100.0,
                current_daily_limit: None,
            },
            reputation: ReputationDetail {
                score: 100.0,
                blocklisted: false,
            },
            stats: IpStats {
                emails_sent_total: 1_500,
                bounces_total: 2,
                complaints_total: 0,
            },
            created_at: "2026-01-01T00:00:00Z".into(),
            updated_at: "2026-01-15T00:00:00Z".into(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["ipAddress"], "1.2.3.4");
        assert_eq!(json["warmup"]["progressPercent"], 100.0);
        assert_eq!(json["reputation"]["score"], 100.0);
        assert_eq!(json["stats"]["emailsSentTotal"], 1500);
    }

    #[test]
    fn test_warmup_response_serialisation() {
        let resp = WarmupResponse {
            id: Uuid::nil(),
            ip_address: "1.2.3.4".into(),
            warmup_status: "warming".into(),
            warmup_progress: 0.5,
            estimated_completion: "2026-02-01T00:00:00Z".into(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["warmupProgress"], 0.5);
    }

    #[test]
    fn test_list_response_serialisation() {
        let resp = ListResponse {
            dedicated_ips: vec![],
            allocation: Some(AllocationResponse {
                included: 1,
                active: 2,
                add_on_available: true,
                add_on_price_monthly: 3000,
            }),
            pagination: PaginationMeta {
                total: 0,
                limit: 50,
                offset: 0,
                has_more: false,
            },
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["allocation"]["included"], 1);
        assert_eq!(json["allocation"]["addOnPriceMonthly"], 3000);
        assert_eq!(json["pagination"]["hasMore"], false);
    }

    #[test]
    fn test_ses_to_api_error_plan_not_eligible() {
        let err = ses_to_api_error(SesProviderError::PlanNotEligible);
        match err {
            ApiError::Forbidden(msg) => assert!(msg.contains("upgrade")),
            other => panic!("expected Forbidden, got {other:?}"),
        }
    }

    #[test]
    fn test_ses_to_api_error_no_ips() {
        let err = ses_to_api_error(SesProviderError::NoAvailableIps {
            region: "us-east-1".into(),
        });
        match err {
            ApiError::ServiceUnavailable(msg) => assert!(msg.contains("us-east-1")),
            other => panic!("expected ServiceUnavailable, got {other:?}"),
        }
    }
}
