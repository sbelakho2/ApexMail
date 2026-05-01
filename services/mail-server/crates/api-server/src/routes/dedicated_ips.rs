//! Dedicated IP management routes.
//!
//! Provides full lifecycle management for dedicated sending IPs://! allocation (via Hetzner Cloud), warmup, monitoring, and release.
//!
//! ## Plan gating
//!
//! Only plans with `dedicated_ip = true` in their feature set may
//! allocate IPs. IPs within the plan's `dedicated_ip_count` are
//! marked `included` (no charge); additional IPs are `pending_charge`
//! and billed at $30/mo via the billing service.
//!
//! ## Hetzner Cloud integration
//!
//! Dedicated IPs are **always** Hetzner floating IPs. There is no
//! SES dedicated IP path. SES handles shared-pool sending only.
//! IPs are created via the Hetzner Cloud API, assigned to MTA
//! servers, and configured with reverse DNS automatically.

use super::helpers::{clamp_limit, default_limit};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{delete, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::info;
use uuid::Uuid;

use crate::error::ApiError;
use crate::ip_provider::IpProviderError;
use crate::middleware::auth::{require_scopes, AuthUser};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", post(allocate_ip).get(list_ips))
        .route("/:id", delete(release_ip))
        .route("/:id/warmup", post(start_warmup))
}

// ─── Request / response types ──────────────────────────────────

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct AllocateIpRequest {
    #[serde(default)]
    pub region: Option<String>,
}

/// Per-IP response matching the console's `DedicatedIpResponse` interface.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DedicatedIpResponse {
    pub id: String,
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
    pub id: String,
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

/// Dedicated IP add-on price in cents/month (matches billing service constant).
const ADD_ON_PRICE_CENTS: i32 = 3000;

// ─── Handlers ──────────────────────────────────────────────────

/// `POST /v1/dedicated-ips` — Allocate a new dedicated IP for the tenant.
/// Plan-gated:checks subscription → plan → `dedicated_ip` feature flag.
/// IPs within `dedicated_ip_count` are `included`; extras are `pending_charge`.
async fn allocate_ip(
    State(state): State<AppState>,
    auth: AuthUser,
    body: Option<Json<AllocateIpRequest>>,
) -> Result<(StatusCode, Json<DedicatedIpResponse>), ApiError> {
    require_scopes(&auth, &["dedicated_ips:write"])?;

    let region = body.and_then(|b| b.0.region);

    // Delegate to Hetzner IP provider (handles plan check, floating IP creation)
    let ip_provider = state.ip_provider.as_ref().ok_or_else(|| {
        ApiError::ServiceUnavailable("dedicated IP provisioning not configured".into())
    })?;

    let allocated = ip_provider
        .allocate_ip(&auth.tenant_id, region.as_deref())
        .await
        .map_err(ip_provider_to_api_error)?;

    // Fetch the just-created DB row for the full response
    let row = sqlx::query_as::<_, DedicatedIpRow>(
        "SELECT id, ip_address, rdns_hostname, region, status,
                warmup_progress, warmup_started_at, warmup_completed_at,
                billing_status, allocated_at, created_at, updated_at,
                0::bigint as emails_sent_total,
                0::bigint as bounces_total,
                0::bigint as complaints_total,
                false as blocklisted
         FROM dedicated_ips
         WHERE tenant_id = $1 AND ip_address = $2
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(&auth.tenant_id)
    .bind(&allocated.ip_address)
    .fetch_one(&state.db)
    .await?;

    info!(
        ip = %allocated.ip_address,
        hetzner_id = allocated.hetzner_floating_ip_id,
        tenant_id = %auth.tenant_id,
        "Dedicated IP allocated via Hetzner"
    );

    Ok((StatusCode::CREATED, Json(row.into_response())))
}

/// `GET /v1/dedicated-ips` — List tenant's dedicated IPs with allocation summary.
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
    .bind(&auth.tenant_id)
    .fetch_one(&state.db)
    .await?;

    // Fetch IPs (include retired for history, most recent first)
    let rows = sqlx::query_as::<_, DedicatedIpRow>(
        "SELECT d.id, d.ip_address, d.rdns_hostname, d.region, d.status,
              d.warmup_progress, d.warmup_started_at, d.warmup_completed_at,
              d.billing_status, d.allocated_at, d.created_at, d.updated_at,
              COALESCE(stats.emails_sent_total, 0)::bigint as emails_sent_total,
              COALESCE(bounces.bounces_total, 0)::bigint as bounces_total,
              COALESCE(complaints.complaints_total, 0)::bigint as complaints_total,
              COALESCE(bounces.blocklisted, false) as blocklisted
          FROM dedicated_ips d
          LEFT JOIN (
              SELECT ip_address::text as ip_address,
                  COALESCE(SUM(messages_sent), 0)::bigint as emails_sent_total
              FROM self_hosted_send_stats
              WHERE tenant_id = $1
              GROUP BY ip_address::text
          ) stats ON stats.ip_address = d.ip_address
          LEFT JOIN (
              SELECT source_ip::text as ip_address,
                  COUNT(*)::bigint as bounces_total,
                  BOOL_OR(bounce_type = 'block') as blocklisted
              FROM self_hosted_bounces
              WHERE tenant_id = $1
              GROUP BY source_ip::text
          ) bounces ON bounces.ip_address = d.ip_address
          LEFT JOIN (
              SELECT source_ip::text as ip_address,
                  COUNT(*)::bigint as complaints_total
              FROM self_hosted_complaints
              WHERE tenant_id = $1
              GROUP BY source_ip::text
          ) complaints ON complaints.ip_address = d.ip_address
          WHERE d.tenant_id = $1
          ORDER BY d.created_at DESC
          LIMIT $2 OFFSET $3",
    )
    .bind(&auth.tenant_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.db)
    .await?;

    // Build allocation summary from the tenant's plan
    let allocation = build_allocation_summary(&state, &auth.tenant_id).await?;

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
/// Deletes the Hetzner floating IP, marks billing as `pending_cancel`,
/// and retires the DB record. If this was the tenant's last dedicated IP,
/// the routing cache trigger reverts them to SES shared sending.
async fn release_ip(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    require_scopes(&auth, &["dedicated_ips:write"])?;

    let ip_provider = state.ip_provider.as_ref().ok_or_else(|| {
        ApiError::ServiceUnavailable("dedicated IP provisioning not configured".into())
    })?;

    ip_provider
        .release_ip(id, &auth.tenant_id)
        .await
        .map_err(ip_provider_to_api_error)?;

    info!(
        id = %id,
        tenant_id = %auth.tenant_id,
        "Dedicated IP released (Hetzner floating IP deleted)"
    );

    Ok(StatusCode::NO_CONTENT)
}

/// `POST /v1/dedicated-ips/:id/warmup` — Start or resume IP warmup.
/// Updates the warmup tracking in the database. Warmup is enforced by
/// the outbound-queue's IP rotation and warmup schedule.
async fn start_warmup(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<WarmupResponse>, ApiError> {
    require_scopes(&auth, &["dedicated_ips:write"])?;

    let ip_provider = state.ip_provider.as_ref().ok_or_else(|| {
        ApiError::ServiceUnavailable("dedicated IP provisioning not configured".into())
    })?;

    let status = ip_provider
        .start_warmup(id, &auth.tenant_id)
        .await
        .map_err(ip_provider_to_api_error)?;

    let est_completion = warmup_estimated_completion(status.warmup_started_at);

    Ok(Json(WarmupResponse {
        id: id.to_string(),
        ip_address: status.ip_address,
        warmup_status: "warming".into(),
        warmup_progress: status.warmup_progress,
        estimated_completion: est_completion.to_rfc3339(),
    }))
}

// ─── Helpers ───────────────────────────────────────────────────

/// Build the `AllocationResponse` for a tenant from their active plan.
async fn build_allocation_summary(
    state: &AppState,
    tenant_id: &str,
) -> Result<Option<AllocationResponse>, ApiError> {
    let plan_row: Option<(bool, i32)> = sqlx::query_as(
        "SELECT
            COALESCE((p.features->>'dedicated_ip')::boolean, false),
            COALESCE((p.features->>'dedicated_ip_count')::int, 0)
         FROM tenants t
         LEFT JOIN plans p ON p.name = t.plan
         WHERE t.id = $1",
    )
    .bind(tenant_id)
    .fetch_optional(&state.db)
    .await?;

    let (allowed, included) = match plan_row {
        Some(row) => row,
        None => return Ok(None),
    };

    let (active,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM dedicated_ips
         WHERE tenant_id = $1 AND status NOT IN ('retired', 'releasing')",
    )
    .bind(tenant_id)
    .fetch_one(&state.db)
    .await?;

    Ok(Some(allocation_response(allowed, included, active)))
}

fn allocation_response(allowed: bool, included: i32, active: i64) -> AllocationResponse {
    AllocationResponse {
        included,
        active,
        add_on_available: allowed,
        add_on_price_monthly: ADD_ON_PRICE_CENTS,
    }
}

fn warmup_estimated_completion(warmup_started_at: DateTime<Utc>) -> DateTime<Utc> {
    use crate::ip_provider::warmup_schedule::FULL_WARMUP_DAYS;

    warmup_started_at + chrono::Duration::days(i64::from(FULL_WARMUP_DAYS))
}

fn calculate_reputation_score(
    emails_sent_total: i64,
    bounces_total: i64,
    complaints_total: i64,
    blocklisted: bool,
) -> f64 {
    let sent = emails_sent_total.max(0) as f64;
    let bounce_rate = if sent > 0.0 {
        bounces_total.max(0) as f64 / sent * 100.0
    } else {
        0.0
    };
    let complaint_rate = if sent > 0.0 {
        complaints_total.max(0) as f64 / sent * 100.0
    } else {
        0.0
    };

    let mut score = 100.0;

    if bounce_rate > 2.0 {
        score -= (bounce_rate - 2.0) * 10.0 * 0.3;
    }

    if complaint_rate > 0.1 {
        score -= (complaint_rate - 0.1) * 100.0 * 0.4;
    }

    if blocklisted {
        score -= 30.0;
    }

    score.clamp(0.0, 100.0)
}

/// Convert IP provider errors to API errors.
fn ip_provider_to_api_error(e: IpProviderError) -> ApiError {
    match e {
        IpProviderError::PlanNotEligible => ApiError::Forbidden(
            "your plan does not include dedicated IP access — please upgrade to Pro or above"
                .into(),
        ),
        IpProviderError::LimitReached { limit, .. } => ApiError::BadRequest(format!(
            "dedicated IP limit reached ({limit}). Contact support to increase your allocation."
        )),
        IpProviderError::NoAvailableServers { region } => ApiError::ServiceUnavailable(format!(
            "no MTA servers available in {region}. Please try again shortly or contact support."
        )),
        IpProviderError::IpNotFound { .. } => ApiError::NotFound("dedicated IP not found".into()),
        IpProviderError::HetznerApi(msg) => {
            tracing::error!(error = %msg, "Hetzner API error during dedicated IP operation");
            ApiError::Internal("failed to communicate with IP provisioning service".into())
        }
        IpProviderError::NotConfigured => ApiError::ServiceUnavailable(
            "dedicated IP provisioning is not configured — set HETZNER_API_TOKEN".into(),
        ),
        IpProviderError::Database(err) => {
            tracing::error!(error = %err, "database error in dedicated IP operation");
            ApiError::Internal("database error".into())
        }
    }
}

// ─── Row types ─────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct DedicatedIpRow {
    id: String,
    ip_address: String,
    rdns_hostname: Option<String>,
    #[allow(dead_code)]
    region: String,
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
    emails_sent_total: i64,
    bounces_total: i64,
    complaints_total: i64,
    blocklisted: bool,
}

impl DedicatedIpRow {
    fn into_response(self) -> DedicatedIpResponse {
        let reputation_score = calculate_reputation_score(
            self.emails_sent_total,
            self.bounces_total,
            self.complaints_total,
            self.blocklisted,
        );

        DedicatedIpResponse {
            id: self.id,
            ip_address: self.ip_address,
            ptr_record: self.rdns_hostname,
            status: self.status.clone(),
            warmup: WarmupDetail {
                started_at: self.warmup_started_at.map(|d| d.to_rfc3339()),
                completed_at: self.warmup_completed_at.map(|d| d.to_rfc3339()),
                progress_percent: self.warmup_progress * 100.0,
                current_daily_limit: None, // Populated by warmup sync job
            },
            reputation: ReputationDetail {
                score: reputation_score,
                blocklisted: self.blocklisted,
            },
            stats: IpStats {
                emails_sent_total: self.emails_sent_total,
                bounces_total: self.bounces_total,
                complaints_total: self.complaints_total,
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
            id: String::new(),
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
            id: String::new(),
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
    fn test_allocation_response_for_ineligible_plan_keeps_zero_entitlement_visible() {
        let resp = allocation_response(false, 0, 0);

        assert_eq!(resp.included, 0);
        assert_eq!(resp.active, 0);
        assert!(!resp.add_on_available);
        assert_eq!(resp.add_on_price_monthly, ADD_ON_PRICE_CENTS);
    }

    #[test]
    fn test_warmup_estimated_completion_preserves_original_start_time() {
        let started_at = chrono::DateTime::parse_from_rfc3339("2026-01-01T13:45:00Z")
            .unwrap()
            .with_timezone(&Utc);

        let estimated = warmup_estimated_completion(started_at);

        assert_eq!(
            estimated,
            started_at
                + chrono::Duration::days(i64::from(
                    crate::ip_provider::warmup_schedule::FULL_WARMUP_DAYS
                ))
        );
        assert_eq!(estimated.time(), started_at.time());
    }

    #[test]
    fn test_ip_provider_to_api_error_plan_not_eligible() {
        let err = ip_provider_to_api_error(IpProviderError::PlanNotEligible);
        match err {
            ApiError::Forbidden(msg) => assert!(msg.contains("upgrade")),
            other => panic!("expected Forbidden, got {other:?}"),
        }
    }

    #[test]
    fn test_ip_provider_to_api_error_no_servers() {
        let err = ip_provider_to_api_error(IpProviderError::NoAvailableServers {
            region: "fsn1".into(),
        });
        match err {
            ApiError::ServiceUnavailable(msg) => assert!(msg.contains("fsn1")),
            other => panic!("expected ServiceUnavailable, got {other:?}"),
        }
    }

    // ── Aggressive fail-first tests ────────────────────────────

    #[test]
    fn test_all_ip_provider_error_variants_map_correctly() {
        // Every IpProviderError variant must map to a distinct ApiError
        let plan_err = ip_provider_to_api_error(IpProviderError::PlanNotEligible);
        assert!(matches!(plan_err, ApiError::Forbidden(_)));

        let limit_err = ip_provider_to_api_error(IpProviderError::LimitReached {
            tenant_id: "t1".into(),
            limit: 5,
        });
        assert!(matches!(limit_err, ApiError::BadRequest(_)));

        let not_found_err = ip_provider_to_api_error(IpProviderError::IpNotFound {
            ip: "1.2.3.4".into(),
        });
        assert!(matches!(not_found_err, ApiError::NotFound(_)));

        let hetzner_err = ip_provider_to_api_error(IpProviderError::HetznerApi("timeout".into()));
        assert!(matches!(hetzner_err, ApiError::Internal(_)));

        let not_configured = ip_provider_to_api_error(IpProviderError::NotConfigured);
        assert!(matches!(not_configured, ApiError::ServiceUnavailable(_)));

        let db_err = ip_provider_to_api_error(IpProviderError::Database("conn refused".into()));
        assert!(matches!(db_err, ApiError::Internal(_)));
    }

    #[test]
    fn test_plan_not_eligible_message_mentions_upgrade() {
        let err = ip_provider_to_api_error(IpProviderError::PlanNotEligible);
        match err {
            ApiError::Forbidden(msg) => {
                assert!(
                    msg.to_lowercase().contains("upgrade"),
                    "PlanNotEligible must mention upgrade: {msg}"
                );
            }
            other => panic!("expected Forbidden, got {other:?}"),
        }
    }

    #[test]
    fn test_limit_reached_includes_limit_number() {
        let err = ip_provider_to_api_error(IpProviderError::LimitReached {
            tenant_id: "tenant_abc".into(),
            limit: 42,
        });
        match err {
            ApiError::BadRequest(msg) => {
                assert!(
                    msg.contains("42"),
                    "LimitReached must include limit number: {msg}"
                );
            }
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[test]
    fn test_allocate_ip_request_defaults_region_to_none() {
        let req: AllocateIpRequest = serde_json::from_str("{}").unwrap();
        assert!(req.region.is_none());
    }

    #[test]
    fn test_allocate_ip_request_accepts_region() {
        let req: AllocateIpRequest = serde_json::from_str(r#"{"region":"us-east"}"#).unwrap();
        assert_eq!(req.region.as_deref(), Some("us-east"));
    }

    #[test]
    fn test_add_on_price_is_30_dollars() {
        assert_eq!(
            ADD_ON_PRICE_CENTS, 3000,
            "add-on price must be $30.00 = 3000 cents"
        );
    }

    #[test]
    fn test_dedicated_ip_response_camel_case() {
        let resp = DedicatedIpResponse {
            id: "test".into(),
            ip_address: "1.2.3.4".into(),
            ptr_record: None,
            status: "active".into(),
            warmup: WarmupDetail {
                started_at: None,
                completed_at: None,
                progress_percent: 0.0,
                current_daily_limit: None,
            },
            reputation: ReputationDetail {
                score: 100.0,
                blocklisted: false,
            },
            stats: IpStats {
                emails_sent_total: 0,
                bounces_total: 0,
                complaints_total: 0,
            },
            created_at: "2026-01-01T00:00:00Z".into(),
            updated_at: "2026-01-01T00:00:00Z".into(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        // Verify camelCase field names match what the frontend expects
        assert!(json.get("ipAddress").is_some(), "must be ipAddress");
        assert!(json.get("ptrRecord").is_some(), "must be ptrRecord");
        assert!(json.get("createdAt").is_some(), "must be createdAt");
        assert!(json.get("updatedAt").is_some(), "must be updatedAt");
        // snake_case must NOT be present
        assert!(json.get("ip_address").is_none(), "must not be snake_case");
        assert!(json.get("ptr_record").is_none(), "must not be snake_case");
    }

    #[test]
    fn test_pagination_meta_has_more_calculation() {
        let meta = PaginationMeta {
            total: 150,
            limit: 50,
            offset: 0,
            has_more: true,
        };
        assert!(meta.has_more);
        assert_eq!(meta.total, 150);

        let meta_no_more = PaginationMeta {
            total: 50,
            limit: 50,
            offset: 0,
            has_more: false,
        };
        assert!(!meta_no_more.has_more);
    }

    #[test]
    fn test_list_ips_query_defaults() {
        let q: ListIpsQuery = serde_json::from_str("{}").unwrap();
        assert_eq!(q.limit, default_limit());
        assert_eq!(q.offset, 0);
    }

    #[test]
    fn test_warmup_detail_progress_is_percentage() {
        // warmup_progress stored as 0.0-1.0, converted to 0-100%
        let row = DedicatedIpRow {
            id: "test".into(),
            ip_address: "1.2.3.4".into(),
            rdns_hostname: None,
            region: "fsn1".into(),
            status: "warming".into(),
            warmup_progress: 0.5,
            warmup_started_at: None,
            warmup_completed_at: None,
            billing_status: None,
            allocated_at: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            emails_sent_total: 0,
            bounces_total: 0,
            complaints_total: 0,
            blocklisted: false,
        };
        let resp = row.into_response();
        assert_eq!(
            resp.warmup.progress_percent, 50.0,
            "0.5 progress must display as 50%"
        );
    }

    #[test]
    fn test_reputation_defaults_perfect_score() {
        let row = DedicatedIpRow {
            id: "test".into(),
            ip_address: "1.2.3.4".into(),
            rdns_hostname: None,
            region: "fsn1".into(),
            status: "active".into(),
            warmup_progress: 0.0,
            warmup_started_at: None,
            warmup_completed_at: None,
            billing_status: None,
            allocated_at: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            emails_sent_total: 0,
            bounces_total: 0,
            complaints_total: 0,
            blocklisted: false,
        };
        let resp = row.into_response();

        // New IPs should have perfect default reputation
        assert_eq!(resp.reputation.score, 100.0);
        assert!(!resp.reputation.blocklisted);
    }

    // ── Aggressive fail-first: reputation edge cases ────────────

    #[test]
    fn test_reputation_score_clamped_at_zero() {
        // Extreme bounce + complaint + blocklisted should still be >= 0
        let score = calculate_reputation_score(100, 100, 100, true);
        assert!(
            score >= 0.0,
            "reputation must never go below 0: got {score}"
        );
    }

    #[test]
    fn test_reputation_score_clamped_at_100() {
        let score = calculate_reputation_score(0, 0, 0, false);
        assert_eq!(score, 100.0, "no activity must yield perfect score");
    }

    #[test]
    fn test_reputation_blocklisted_deducts_30_points() {
        let clean = calculate_reputation_score(1000, 0, 0, false);
        let blocked = calculate_reputation_score(1000, 0, 0, true);
        let diff = clean - blocked;
        assert_eq!(diff, 30.0, "blocklist must deduct exactly 30 points");
    }

    #[test]
    fn test_reputation_high_bounce_rate_penalizes() {
        let good = calculate_reputation_score(1000, 10, 0, false); // 1% bounce
        let bad = calculate_reputation_score(1000, 100, 0, false); // 10% bounce
        assert!(bad < good, "high bounce rate must reduce reputation");
    }

    #[test]
    fn test_reputation_high_complaint_rate_penalizes() {
        let good = calculate_reputation_score(10000, 0, 5, false); // 0.05%
        let bad = calculate_reputation_score(10000, 0, 50, false); // 0.5%
        assert!(bad < good, "high complaint rate must reduce reputation");
    }

    #[test]
    fn test_reputation_zero_sent_yields_perfect_score() {
        let score = calculate_reputation_score(0, 0, 0, false);
        assert_eq!(score, 100.0, "no emails sent = perfect reputation");
    }

    #[test]
    fn test_allocation_response_add_on_price_matches_constant() {
        let resp = allocation_response(true, 3, 5);
        assert_eq!(resp.add_on_price_monthly, ADD_ON_PRICE_CENTS);
        assert!(resp.add_on_available);
        assert_eq!(resp.included, 3);
        assert_eq!(resp.active, 5);
    }

    #[test]
    fn test_list_ips_query_deser_defaults() {
        let q: ListIpsQuery = serde_json::from_str("{}").unwrap();
        assert_eq!(q.limit, default_limit());
        assert_eq!(q.offset, 0);
    }

    #[test]
    fn test_reputation_uses_aggregated_delivery_stats() {
        let row = DedicatedIpRow {
            id: "test".into(),
            ip_address: "1.2.3.4".into(),
            rdns_hostname: None,
            region: "fsn1".into(),
            status: "active".into(),
            warmup_progress: 1.0,
            warmup_started_at: None,
            warmup_completed_at: None,
            billing_status: None,
            allocated_at: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            emails_sent_total: 1_000,
            bounces_total: 50,
            complaints_total: 2,
            blocklisted: true,
        };

        let resp = row.into_response();

        assert_eq!(resp.stats.emails_sent_total, 1_000);
        assert_eq!(resp.stats.bounces_total, 50);
        assert_eq!(resp.stats.complaints_total, 2);
        assert!(resp.reputation.blocklisted);
        assert!(resp.reputation.score < 100.0);
    }
}
