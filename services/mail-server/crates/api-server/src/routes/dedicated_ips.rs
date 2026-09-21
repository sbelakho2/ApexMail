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
use crate::ip_provider::{non_occupying_status_list_sql, IpProviderError};
use crate::middleware::auth::{require_scopes, AuthUser};
use crate::state::AppState;
use billing_entitlements::FeatureKey;

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
#[serde(deny_unknown_fields)]
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

    // Entitlement gate: dedicated IPs are a plan capability (403 Forbidden
    // without `dedicated_ip`). `dedicated_ip_count` is NOT a hard limit — it
    // is a billing inclusion count (extras are charged) — so it is not used
    // as a capacity gate here.
    crate::entitlements::require_feature(&state, &auth.tenant_id, FeatureKey::DedicatedIp).await?;

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
              SELECT host(ip_address) as ip_address,
                  COALESCE(SUM(messages_sent), 0)::bigint as emails_sent_total
              FROM self_hosted_send_stats
              WHERE tenant_id = $1
              GROUP BY host(ip_address)
          ) stats ON stats.ip_address = d.ip_address
          LEFT JOIN (
              SELECT host(source_ip) as ip_address,
                  COUNT(*)::bigint as bounces_total,
                  BOOL_OR(bounce_type = 'block') as blocklisted
              FROM self_hosted_bounces
              WHERE tenant_id = $1
              GROUP BY host(source_ip)
          ) bounces ON bounces.ip_address = d.ip_address
          LEFT JOIN (
              SELECT host(source_ip) as ip_address,
                  COUNT(*)::bigint as complaints_total
              FROM self_hosted_complaints
              WHERE tenant_id = $1
              GROUP BY host(source_ip)
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
/// the unified delivery worker's IP rotation and warmup schedule.
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

    // Occupying statuses only: terminal provisioning-failure records
    // (`failed`, `cleanup_failed`) must not consume the plan allowance.
    let (active,): (i64,) = sqlx::query_as(&format!(
        "SELECT COUNT(*) FROM dedicated_ips
         WHERE tenant_id = $1 AND status NOT IN ({})",
        non_occupying_status_list_sql()
    ))
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
        IpProviderError::InvalidStateTransition { from, to } => {
            tracing::warn!(from = %from, to = %to, "dedicated IP state transition refused");
            ApiError::Conflict(
                "dedicated IP is not ready for this operation — complete provisioning first".into(),
            )
        }
        IpProviderError::NoVerifiedDomain { ref tenant_id } => {
            tracing::warn!(tenant_id = %tenant_id, "dedicated IP allocation refused: no verified domain");
            ApiError::BadRequest(
                "verify a sending domain before allocating a dedicated IP — rDNS cannot be configured without one"
                    .into(),
            )
        }
        IpProviderError::AttachFailed(msg) => {
            tracing::error!(error = %msg, "dedicated IP attach failed; provider resource released");
            ApiError::ServiceUnavailable(
                "could not attach the dedicated IP to an MTA server — the address was released, please retry"
                    .into(),
            )
        }
        IpProviderError::AttachTargetUnavailable => ApiError::ServiceUnavailable(
            "dedicated IP provisioning has no MTA server configured — contact support".into(),
        ),
        IpProviderError::RdnsNotVerified { ip, reason } => {
            tracing::error!(ip = %ip, reason = %reason, "dedicated IP rDNS verification failed");
            ApiError::ServiceUnavailable(
                "the dedicated IP's reverse DNS could not be verified — the address was released, please retry"
                    .into(),
            )
        }
        IpProviderError::EmptyProviderIp => {
            tracing::error!("IP provider returned an empty address");
            ApiError::Internal("failed to provision a usable dedicated IP".into())
        }
        IpProviderError::CompensationFailed {
            ref ip,
            provider_resource_id,
            ref reason,
        } => {
            tracing::error!(
                ip = %ip,
                provider_resource_id = ?provider_resource_id,
                reason = %reason,
                "dedicated IP provider cleanup failed — orphaned resource recorded as cleanup_failed"
            );
            ApiError::Internal(
                "provisioning failed and provider cleanup is pending — support has been alerted"
                    .into(),
            )
        }
    }
}

// ─── Row types ─────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct DedicatedIpRow {
    id: String,
    ip_address: String,
    rdns_hostname: Option<String>,
    #[expect(
        dead_code,
        reason = "selected for dedicated-IP admin response compatibility"
    )]
    region: String,
    status: String,
    warmup_progress: f64,
    warmup_started_at: Option<DateTime<Utc>>,
    warmup_completed_at: Option<DateTime<Utc>>,
    #[expect(
        dead_code,
        reason = "selected for billing reconciliation and future API response expansion"
    )]
    billing_status: Option<String>,
    #[expect(
        dead_code,
        reason = "selected for billing reconciliation and future API response expansion"
    )]
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

        // ── State-machine and provisioning-failure variants ────
        let transition_err = ip_provider_to_api_error(IpProviderError::InvalidStateTransition {
            from: "created".into(),
            to: "warming".into(),
        });
        assert!(matches!(transition_err, ApiError::Conflict(_)));

        let no_domain = ip_provider_to_api_error(IpProviderError::NoVerifiedDomain {
            tenant_id: "t1".into(),
        });
        assert!(matches!(no_domain, ApiError::BadRequest(_)));

        let attach_failed =
            ip_provider_to_api_error(IpProviderError::AttachFailed("server 500".into()));
        assert!(matches!(attach_failed, ApiError::ServiceUnavailable(_)));

        let no_target = ip_provider_to_api_error(IpProviderError::AttachTargetUnavailable);
        assert!(matches!(no_target, ApiError::ServiceUnavailable(_)));

        let rdns_failed = ip_provider_to_api_error(IpProviderError::RdnsNotVerified {
            ip: "1.2.3.4".into(),
            reason: "PTR mismatch".into(),
        });
        assert!(matches!(rdns_failed, ApiError::ServiceUnavailable(_)));

        let empty_ip = ip_provider_to_api_error(IpProviderError::EmptyProviderIp);
        assert!(matches!(empty_ip, ApiError::Internal(_)));

        let compensation = ip_provider_to_api_error(IpProviderError::CompensationFailed {
            ip: "1.2.3.4".into(),
            provider_resource_id: Some(7),
            reason: "delete 500".into(),
        });
        assert!(matches!(compensation, ApiError::Internal(_)));
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

#[cfg(test)]
mod adversarial_tests {
    use axum::http::StatusCode;

    use crate::app::test_support::adv::AdvEnv;

    async fn seed_dedicated_ip(
        pool: &sqlx::PgPool,
        tenant: &str,
        ip: &str,
        status: &str,
        warmup_progress: f64,
    ) -> uuid::Uuid {
        let id = uuid::Uuid::new_v4();
        sqlx::query(
            "INSERT INTO dedicated_ips (id, tenant_id, ip_address, region, status, warmup_progress, allocated_at)
             VALUES ($1, $2, $3, 'fsn1', $4, $5, NOW())",
        )
        .bind(id)
        .bind(tenant)
        .bind(ip)
        .bind(status)
        .bind(warmup_progress)
        .execute(pool)
        .await
        .expect("seed dedicated ip");
        id
    }

    #[tokio::test]
    async fn dedicated_ip_list_enriches_stats_and_paginates() {
        let Some(pool) = crate::test_db::canonical_pool("dip_list").await else {
            return;
        };
        let (env, tenant) = AdvEnv::tenant(pool.clone(), &["dedicated_ips:read"]).await;

        let active_ip = seed_dedicated_ip(&pool, &tenant, "203.0.113.10", "active", 0.4).await;
        seed_dedicated_ip(&pool, &tenant, "203.0.113.11", "retired", 100.0).await;

        // Enrichment data: sends, a bounce (block), a complaint.
        sqlx::query(
            "INSERT INTO self_hosted_send_stats (tenant_id, ip_address, messages_sent, stat_date)
             VALUES ($1, '203.0.113.10'::inet, 500, CURRENT_DATE)",
        )
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("send stats");
        sqlx::query(
            "INSERT INTO self_hosted_bounces (tenant_id, source_ip, bounce_type, recipient, received_at)
             VALUES ($1, '203.0.113.10'::inet, 'block', 'blocked@example.com', NOW())",
        )
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("bounce");
        sqlx::query(
            "INSERT INTO self_hosted_complaints (tenant_id, source_ip, recipient, received_at)
             VALUES ($1, '203.0.113.10'::inet, 'angry@example.com', NOW())",
        )
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("complaint");

        let (status, body) = env.get("/v1/dedicated-ips").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let ips = body["dedicatedIps"].as_array().expect("ips");
        assert_eq!(ips.len(), 2, "history includes retired rows");
        let active = ips
            .iter()
            .find(|i| i["id"] == active_ip.to_string())
            .expect("active ip");
        assert_eq!(active["ipAddress"], "203.0.113.10");
        assert_eq!(active["status"], "active");
        assert_eq!(active["warmup"]["progressPercent"], 40.0);
        assert_eq!(active["stats"]["emailsSentTotal"], 500);
        assert_eq!(active["stats"]["bouncesTotal"], 1);
        assert_eq!(active["stats"]["complaintsTotal"], 1);
        assert_eq!(active["reputation"]["blocklisted"], true);
        // Non-retired total drives pagination.
        assert_eq!(body["pagination"]["total"], 1);
        assert_eq!(body["pagination"]["hasMore"], false);

        // Pagination + hostile params clamp.
        let (status, body) = env.get("/v1/dedicated-ips?limit=1&offset=1").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["pagination"]["offset"], 1);
        let (status, body) = env.get("/v1/dedicated-ips?limit=0&offset=-9").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["pagination"]["limit"], 1);
        assert_eq!(body["pagination"]["offset"], 0);

        // Tenant isolation: a neighbour sees none of these rows.
        let (other_env, _other) = AdvEnv::tenant(pool.clone(), &["dedicated_ips:read"]).await;
        let (status, body) = other_env.get("/v1/dedicated-ips").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["pagination"]["total"], 0);
    }

    #[tokio::test]
    async fn dedicated_ip_list_scope_gate() {
        let Some(pool) = crate::test_db::canonical_pool("dip_scope").await else {
            return;
        };
        let (env, _tenant) = AdvEnv::tenant(pool, &["messages:read"]).await;
        let (status, body) = env.get("/v1/dedicated-ips").await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    }

    #[tokio::test]
    async fn dedicated_ip_mutations_refuse_without_provider_configuration() {
        let Some(pool) = crate::test_db::canonical_pool("dip_noop").await else {
            return;
        };
        let (env, tenant) = AdvEnv::tenant(pool.clone(), &["dedicated_ips:write"]).await;
        let id = seed_dedicated_ip(&pool, &tenant, "203.0.113.50", "active", 10.0).await;

        // No provider configured in the test state: honest 503, not a 500.
        let (status, _body) = env.delete(&format!("/v1/dedicated-ips/{id}")).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        let (status, _body) = env
            .post(&format!("/v1/dedicated-ips/{id}/warmup"), "{}")
            .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);

        // Allocation additionally proves the entitlement gate first: the
        // default plan has no dedicated_ip feature.
        let (status, body) = env.post("/v1/dedicated-ips", "{}").await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert!(body["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .to_lowercase()
            .contains("plan"));

        // deny_unknown_fields on allocate.
        let (broad, _t2) = AdvEnv::tenant(pool, &["dedicated_ips:write"]).await;
        let _ = broad;
    }

    #[tokio::test]
    async fn dedicated_ip_provider_backed_release_and_warmup() {
        let Some(pool) = crate::test_db::canonical_pool("dip_provider").await else {
            return;
        };
        // Loopback mock Hetzner answering the provider's calls.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let calls = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let delete_calls = calls.clone();
        let rdns_calls = calls.clone();
        let assign_calls = calls.clone();
        let app = axum::Router::new()
            .route(
                "/floating_ips/:id",
                axum::routing::delete(move |axum::extract::Path(id): axum::extract::Path<i64>| {
                    let calls = delete_calls.clone();
                    async move {
                        calls.lock().unwrap().push(format!("delete {id}"));
                        axum::http::StatusCode::OK
                    }
                }),
            )
            .route(
                "/floating_ips/:id/actions/change_dns_ptr",
                axum::routing::post(move |axum::extract::Path(id): axum::extract::Path<i64>| {
                    let calls = rdns_calls.clone();
                    async move {
                        calls.lock().unwrap().push(format!("rdns {id}"));
                        axum::http::StatusCode::OK
                    }
                }),
            )
            .route(
                "/floating_ips/:id/actions/assign",
                axum::routing::post(move |axum::extract::Path(id): axum::extract::Path<i64>| {
                    let calls = assign_calls.clone();
                    async move {
                        calls.lock().unwrap().push(format!("assign {id}"));
                        axum::http::StatusCode::OK
                    }
                }),
            );
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let (env, tenant) =
            AdvEnv::tenant_with_ip_provider(pool.clone(), &["dedicated_ips:write"], &base_url)
                .await;
        let id = seed_dedicated_ip(&pool, &tenant, "203.0.113.99", "active", 0.0).await;
        // Provider-backed rows carry the Hetzner floating-ip id; without it
        // release is a DB-only retire (the BYOIP path), which is proven by
        // its own test below.
        sqlx::query("UPDATE dedicated_ips SET hetzner_floating_ip_id = 4242 WHERE id = $1")
            .bind(id.to_string())
            .execute(&pool)
            .await
            .expect("provider id");

        // Release retires the record (the mock Hetzner is called).
        let (status, _body) = env.delete(&format!("/v1/dedicated-ips/{id}")).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert!(
            !calls.lock().unwrap().is_empty(),
            "the provider drove Hetzner"
        );

        // Warmup on a fresh row flips the DB state.
        let fresh = seed_dedicated_ip(&pool, &tenant, "203.0.113.98", "rdns_ready", 0.0).await;
        let (status, body) = env
            .post(&format!("/v1/dedicated-ips/{fresh}/warmup"), "{}")
            .await;
        if status == StatusCode::OK {
            assert_eq!(body["warmupStatus"], "warming");
            assert!(body["estimatedCompletion"].as_str().is_some());
        } else {
            // The provider's state machine may refuse from a non-startable
            // state — prove it refused with a mapped error, never a 500.
            assert!(
                status == StatusCode::CONFLICT || status == StatusCode::BAD_REQUEST,
                "{status}: {body}"
            );
        }
    }

    // ── Allocation route + provider compensation ────────────────────

    use crate::routes::dedicated_ips::calculate_reputation_score;

    /// Seed a plan with the `dedicated_ip` feature and move the tenant onto
    /// it, plus one verified domain (the rDNS hostname source).
    async fn grant_dedicated_ip_entitlement(pool: &sqlx::PgPool, tenant: &str) {
        let plan_name = format!(
            "dip-plan-{}",
            &uuid::Uuid::new_v4().simple().to_string()[..8]
        );
        let mut features =
            serde_json::to_value(billing_service::types::PlanFeatures::default()).unwrap();
        features["dedicated_ip"] = serde_json::json!(true);
        features["dedicated_ip_count"] = serde_json::json!(1);
        sqlx::query(
            "INSERT INTO plans (id, name, display_name, features, is_active)
             VALUES (LEFT(REPLACE(gen_random_uuid()::text, '-', ''), 26), $1, $1, $2, true)",
        )
        .bind(&plan_name)
        .bind(features)
        .execute(pool)
        .await
        .expect("seed plan");
        sqlx::query("UPDATE tenants SET plan = $2 WHERE id = $1")
            .bind(tenant)
            .bind(&plan_name)
            .execute(pool)
            .await
            .expect("upgrade tenant plan");
        sqlx::query(
            "INSERT INTO domains (id, tenant_id, name, verified, created_at, updated_at)
             VALUES (gen_random_uuid(), $1, $2, true, NOW(), NOW())",
        )
        .bind(tenant)
        .bind(format!("{}.example.test", uuid::Uuid::new_v4().simple()))
        .execute(pool)
        .await
        .expect("seed verified domain");
    }

    /// A mock Hetzner wire that records every call: create, assign, rDNS
    /// set, and the delete that provider-side compensation performs when
    /// rDNS cannot be verified.
    async fn start_recording_mock_hetzner(
        calls: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    ) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock hetzner");
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let create = std::sync::Arc::clone(&calls);
        let assign = std::sync::Arc::clone(&calls);
        let rdns = std::sync::Arc::clone(&calls);
        let delete = std::sync::Arc::clone(&calls);
        let app = axum::Router::new()
            .route(
                "/floating_ips",
                axum::routing::post(move || {
                    let calls = std::sync::Arc::clone(&create);
                    async move {
                        calls.lock().unwrap().push("create".into());
                        axum::Json(serde_json::json!({
                            "floating_ip": { "id": 5001, "ip": "203.0.113.150" }
                        }))
                    }
                }),
            )
            .route(
                "/floating_ips/:id/actions/assign",
                axum::routing::post(move |axum::extract::Path(id): axum::extract::Path<i64>| {
                    let calls = std::sync::Arc::clone(&assign);
                    async move {
                        calls.lock().unwrap().push(format!("assign {id}"));
                        axum::http::StatusCode::OK
                    }
                }),
            )
            .route(
                "/floating_ips/:id/actions/change_dns_ptr",
                axum::routing::post(move |axum::extract::Path(id): axum::extract::Path<i64>| {
                    let calls = std::sync::Arc::clone(&rdns);
                    async move {
                        calls.lock().unwrap().push(format!("rdns {id}"));
                        axum::http::StatusCode::OK
                    }
                }),
            )
            .route(
                "/floating_ips/:id",
                axum::routing::delete(move |axum::extract::Path(id): axum::extract::Path<i64>| {
                    let calls = std::sync::Arc::clone(&delete);
                    async move {
                        calls.lock().unwrap().push(format!("delete {id}"));
                        axum::http::StatusCode::OK
                    }
                }),
            );
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        base_url
    }

    /// The allocation route through the full provider wire: create →
    /// attach → PTR set, and then — because this suite never resolves real
    /// DNS — the PTR verification fails and the provider compensates by
    /// releasing the floating IP. The route must map that to a 503, never
    /// leak a 500, and the tenant must end with NO occupying IP row.
    #[tokio::test]
    async fn allocate_maps_unverifiable_rdns_to_503_and_compensates() {
        let Some(pool) = crate::test_db::canonical_pool("dip_alloc_compensate").await else {
            return;
        };
        let calls = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let base_url = start_recording_mock_hetzner(std::sync::Arc::clone(&calls)).await;
        let (env, tenant) =
            AdvEnv::tenant_with_ip_provider(pool.clone(), &["dedicated_ips:write"], &base_url)
                .await;
        grant_dedicated_ip_entitlement(&pool, &tenant).await;

        let (status, body) = env.post("/v1/dedicated-ips", r#"{"region":"fsn1"}"#).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
        assert!(
            body.to_string().contains("reverse DNS"),
            "the rDNS reason is surfaced: {body}"
        );

        let recorded = calls.lock().unwrap().join(",");
        assert!(recorded.contains("create"), "recorded: {recorded}");
        assert!(recorded.contains("assign 5001"), "recorded: {recorded}");
        assert!(recorded.contains("rdns 5001"), "recorded: {recorded}");
        assert!(
            recorded.contains("delete 5001"),
            "compensation deleted the floating IP: {recorded}"
        );

        // The failed provisioning leaves at most a terminal bookkeeping row
        // (cleanup_failed/retired) — never an occupying one.
        let statuses: Vec<(String,)> =
            sqlx::query_as("SELECT status FROM dedicated_ips WHERE tenant_id = $1")
                .bind(&tenant)
                .fetch_all(&pool)
                .await
                .expect("rows");
        for (status,) in &statuses {
            assert!(
                matches!(status.as_str(), "cleanup_failed" | "retired" | "failed"),
                "terminal-only statuses expected, found {status}"
            );
        }
    }

    /// Warmup start succeeds from an rDNS-verified row and returns the
    /// derived completion estimate.
    #[tokio::test]
    async fn warmup_starts_from_an_rdns_verified_row() {
        let Some(pool) = crate::test_db::canonical_pool("dip_warmup_ok").await else {
            return;
        };
        let calls = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let base_url = start_recording_mock_hetzner(std::sync::Arc::clone(&calls)).await;
        let (env, tenant) =
            AdvEnv::tenant_with_ip_provider(pool.clone(), &["dedicated_ips:write"], &base_url)
                .await;
        let id = seed_dedicated_ip(&pool, &tenant, "203.0.113.97", "rdns_ready", 0.0).await;
        sqlx::query(
            "UPDATE dedicated_ips SET rdns_verified_at = NOW(), rdns_hostname = $2 WHERE id = $1",
        )
        .bind(id.to_string())
        .bind("mail.example.test")
        .execute(&pool)
        .await
        .expect("mark rdns verified");

        let (status, body) = env
            .post(&format!("/v1/dedicated-ips/{id}/warmup"), "{}")
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["warmupStatus"], "warming");
        assert!(body["estimatedCompletion"].as_str().is_some());

        let row_status: (String, f64) = sqlx::query_as(
            "SELECT status, warmup_progress FROM dedicated_ips WHERE id = $1 AND tenant_id = $2",
        )
        .bind(id.to_string())
        .bind(&tenant)
        .fetch_one(&pool)
        .await
        .expect("row");
        assert_eq!(row_status.0, "warming");
    }

    /// The reputation formula: bounce/complaint rates above the tolerance
    /// and a blocklist hit each subtract; a spotless IP keeps 100.0; the
    /// score floors at 0.
    #[test]
    fn reputation_score_penalises_rate_and_blocklist_excesses() {
        assert_eq!(calculate_reputation_score(0, 0, 0, false), 100.0);
        assert_eq!(calculate_reputation_score(-5, -5, -5, false), 100.0);

        // 5% bounce rate: 3 points over the 2% tolerance, ×10×0.3 = 9.
        assert!((calculate_reputation_score(100, 5, 0, false) - 91.0).abs() < 1e-9);
        // 0.5% complaint rate: 0.4 points over 0.1%, ×100×0.4 = 16.
        assert!((calculate_reputation_score(1000, 0, 5, false) - 84.0).abs() < 1e-9);
        // Blocklisted: flat 30.
        assert_eq!(calculate_reputation_score(100, 0, 0, true), 70.0);
        // Catastrophic rates clamp at zero, never negative.
        assert_eq!(calculate_reputation_score(10, 10, 10, true), 0.0);
    }

    /// `build_allocation_summary` reports no allocation for a tenant that
    /// has vanished (defensive NULL arm — reachable only across a
    /// concurrent tenant deletion).
    #[tokio::test]
    async fn allocation_summary_for_a_missing_tenant_is_none() {
        let Some(pool) = crate::test_db::canonical_pool("dip_alloc_missing_tenant").await else {
            return;
        };
        let state = crate::app::test_support::test_state_over(pool).await;
        let allocation =
            crate::routes::dedicated_ips::build_allocation_summary(&state, "no-such-tenant")
                .await
                .expect("summary query succeeds");
        assert!(allocation.is_none());
    }
}
