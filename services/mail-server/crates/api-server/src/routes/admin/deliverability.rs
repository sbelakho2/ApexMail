//! Operator interface for the per-provider outbound throttle.
//!
//! The live decision engine is `outbound_mta::throttle` (shared by the relay
//! daemon and the worker's SES transport). It reads
//! `outbound_provider_throttle_overrides` on every cache miss; these endpoints
//! are the only writer. Semantics:
//!
//! * `throttle_pct = 0` — send everything to the provider;
//! * `throttle_pct = 100` — block everything to the provider;
//! * `1..=99` — defer that percentage of submissions. The roll is a stable
//!   hash of the send unit WITHIN a five-minute retry window (a duplicated
//!   attempt gets one verdict) and re-rolls at the next window, so a
//!   persistent throttle cannot starve the same submission forever.
//!
//! `target` selects the tenant scope: `null`, `"global"` or `"*"` writes the
//! global override; any other value is a tenant id. A tenant-specific row
//! wins over the global row. Expired rows (`expires_at <= NOW()`) are inert
//! and are omitted from the default listing.
//!
//! Every mutation writes an `audit_logs` row in the same transaction — an
//! override changes what mail leaves the platform, so the operator who
//! ordered it must be on record.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::error::ApiError;
use crate::middleware::auth::{require_scopes, require_system_tenant, AuthUser};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(list_overrides).put(upsert_override))
        .route("/:id", axum::routing::delete(delete_override))
}

/// Recipient provider buckets `outbound_mta::throttle::classify_provider`
/// can return. An override for anything else could never match a live send;
/// `other` from migration 041's comment is refused for that reason.
const PROVIDERS: [&str; 5] = ["google", "microsoft", "yahoo", "apple", "aol"];
/// Tenant ids are `varchar(26)` in the canonical schema; the override table
/// inherited that width (migration 058/041 convergence), so a longer target
/// must be refused here instead of failing the INSERT with a 500.
const TARGET_MAX_LEN: usize = 26;
const REASON_MAX_LEN: usize = 500;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ListQuery {
    #[serde(default)]
    pub provider: Option<String>,
    /// Tenant id, or `global` / `*` for the global row.
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub include_expired: bool,
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 {
    50
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OverrideDto {
    pub id: String,
    pub provider: String,
    /// `None` = the global override.
    pub target: Option<String>,
    pub throttle_pct: i32,
    pub reason: String,
    pub expires_at: Option<String>,
    pub created_by: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub active: bool,
}

type OverrideRow = (
    String,
    Option<String>,
    String,
    i32,
    String,
    Option<DateTime<Utc>>,
    Option<String>,
    DateTime<Utc>,
    DateTime<Utc>,
);

const COLUMNS: &str = "id::text, tenant_id, provider, throttle_pct, reason, expires_at, \
     created_by, created_at, updated_at";

impl OverrideDto {
    fn from_row(row: OverrideRow) -> Self {
        let active = row.5.is_none_or(|expires_at| expires_at > Utc::now());
        Self {
            id: row.0,
            target: row.1,
            provider: row.2,
            throttle_pct: row.3,
            reason: row.4,
            expires_at: row.5.map(|value| value.to_rfc3339()),
            created_by: row.6,
            created_at: row.7.to_rfc3339(),
            updated_at: row.8.to_rfc3339(),
            active,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct UpsertBody {
    pub provider: String,
    /// Tenant scope. Absent / `null` / `"global"` / `"*"` = global.
    #[serde(default)]
    pub target: Option<String>,
    pub throttle_pct: i32,
    pub reason: String,
    #[serde(default)]
    pub expires_at: Option<String>,
}

/// Validate and normalize the provider bucket.
pub(crate) fn validate_provider(raw: &str) -> Result<String, String> {
    let provider = raw.trim().to_ascii_lowercase();
    if PROVIDERS.contains(&provider.as_str()) {
        Ok(provider)
    } else {
        Err(format!(
            "unsupported provider \"{raw}\"; the throttle engine classifies {} — \
             an override for any other value could never match a send",
            PROVIDERS.join(", ")
        ))
    }
}

/// Validate and normalize the tenant target. `None` = global.
pub(crate) fn validate_target(raw: Option<&str>) -> Result<Option<String>, String> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let target = raw.trim();
    if target.is_empty() || target.eq_ignore_ascii_case("global") || target == "*" {
        return Ok(None);
    }
    if target.len() > TARGET_MAX_LEN {
        return Err(format!(
            "target must be at most {TARGET_MAX_LEN} characters"
        ));
    }
    if !target
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':' | '@'))
    {
        return Err("target must be a tenant id ([A-Za-z0-9._:@-]) or \"global\"".to_string());
    }
    Ok(Some(target.to_string()))
}

/// Validate the throttle percentage.
pub(crate) fn validate_pct(pct: i32) -> Result<u8, String> {
    u8::try_from(pct)
        .ok()
        .filter(|pct| *pct <= 100)
        .ok_or_else(|| "throttlePct must be an integer between 0 and 100".to_string())
}

/// Validate the operator reason (non-empty, bounded).
pub(crate) fn validate_reason(raw: &str) -> Result<String, String> {
    let reason = raw.trim();
    if reason.is_empty() {
        return Err("reason is required: record why the override was pinned".into());
    }
    if reason.chars().count() > REASON_MAX_LEN {
        return Err(format!(
            "reason must be at most {REASON_MAX_LEN} characters"
        ));
    }
    Ok(reason.to_string())
}

/// Parse and validate an optional expiry. An expiry in the past would create
/// a row that is inert the moment it is written — refuse it.
pub(crate) fn validate_expiry(
    raw: Option<&str>,
    now: DateTime<Utc>,
) -> Result<Option<DateTime<Utc>>, String> {
    let Some(raw) = raw.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    let parsed = DateTime::parse_from_rfc3339(raw)
        .map_err(|_| "expiresAt must be an RFC 3339 timestamp".to_string())?
        .with_timezone(&Utc);
    if parsed <= now {
        return Err("expiresAt must be in the future".into());
    }
    Ok(Some(parsed))
}

#[cfg(test)]
fn target_scope(target: &Option<String>) -> &str {
    target.as_deref().unwrap_or("")
}

async fn list_overrides(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<ListQuery>,
) -> Result<Json<Vec<OverrideDto>>, ApiError> {
    require_scopes(&auth, &["*"])?;
    require_system_tenant(&state, &auth).await?;

    let provider = params
        .provider
        .as_deref()
        .map(validate_provider)
        .transpose()
        .map_err(ApiError::BadRequest)?;
    let target = params
        .target
        .as_deref()
        .map(|raw| validate_target(Some(raw)))
        .transpose()
        .map_err(ApiError::BadRequest)?;
    // Distinguish "no target filter" from "only the global row".
    let target_filter = params.target.map(|_| target.flatten());

    let rows: Vec<OverrideRow> = sqlx::query_as(&format!(
        "SELECT {COLUMNS}
         FROM outbound_provider_throttle_overrides
         WHERE ($1::text IS NULL OR provider = $1)
           AND ($2::bool = FALSE OR expires_at IS NULL OR expires_at > NOW())
           AND (
                $3::bool = FALSE
                OR ($4::bool = TRUE AND tenant_id IS NULL)
                OR ($4::bool = FALSE AND tenant_id = $5)
           )
         ORDER BY updated_at DESC, created_at DESC, id
         LIMIT $6 OFFSET $7"
    ))
    .bind(provider.as_deref())
    .bind(!params.include_expired)
    .bind(target_filter.is_some())
    .bind(
        target_filter
            .as_ref()
            .map(|target| target.is_none())
            .unwrap_or(false),
    )
    .bind(target_filter.as_ref().and_then(|target| target.as_deref()))
    .bind(params.limit.clamp(1, 200))
    .bind(params.offset.max(0))
    .fetch_all(&state.db)
    .await?;

    Ok(Json(rows.into_iter().map(OverrideDto::from_row).collect()))
}

async fn upsert_override(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<UpsertBody>,
) -> Result<Json<OverrideDto>, ApiError> {
    require_scopes(&auth, &["*"])?;
    require_system_tenant(&state, &auth).await?;

    let provider = validate_provider(&body.provider).map_err(ApiError::BadRequest)?;
    let target = validate_target(body.target.as_deref()).map_err(ApiError::BadRequest)?;
    let throttle_pct = i32::from(validate_pct(body.throttle_pct).map_err(ApiError::BadRequest)?);
    let reason = validate_reason(&body.reason).map_err(ApiError::BadRequest)?;
    let expires_at =
        validate_expiry(body.expires_at.as_deref(), Utc::now()).map_err(ApiError::BadRequest)?;

    let mut tx = state.db.begin().await?;

    // One ACTIVE row per (provider, tenant) — migration 267 guarantees the
    // uniqueness; this select-update-first shape adopts an existing row
    // (including its id) instead of churning ids on every PUT.
    let existing: Option<String> = sqlx::query_scalar(
        "SELECT id::text
         FROM outbound_provider_throttle_overrides
         WHERE provider = $1
           AND tenant_id IS NOT DISTINCT FROM $2::text
           AND (expires_at IS NULL OR expires_at > NOW())
         ORDER BY updated_at DESC
         LIMIT 1
         FOR UPDATE",
    )
    .bind(&provider)
    .bind(target.as_deref())
    .fetch_optional(&mut *tx)
    .await?;

    let id = match existing {
        Some(id) => {
            sqlx::query(
                "UPDATE outbound_provider_throttle_overrides
                 SET throttle_pct = $1, reason = $2, expires_at = $3,
                     created_by = COALESCE(created_by, $4), updated_at = NOW()
                 WHERE id = $5::uuid",
            )
            .bind(throttle_pct)
            .bind(&reason)
            .bind(expires_at)
            .bind(auth.user_id.as_deref())
            .bind(&id)
            .execute(&mut *tx)
            .await?;
            id
        }
        None => {
            let inserted: Option<String> = sqlx::query_scalar(
                "INSERT INTO outbound_provider_throttle_overrides
                   (tenant_id, provider, throttle_pct, reason, expires_at, created_by)
                 VALUES ($1, $2, $3, $4, $5, $6)
                 ON CONFLICT DO NOTHING
                 RETURNING id::text",
            )
            .bind(target.as_deref())
            .bind(&provider)
            .bind(throttle_pct)
            .bind(&reason)
            .bind(expires_at)
            .bind(auth.user_id.as_deref())
            .fetch_optional(&mut *tx)
            .await?;
            match inserted {
                Some(id) => id,
                None => {
                    // A concurrent writer won the unique-key race: adopt its
                    // row rather than returning a 500.
                    let id: String = sqlx::query_scalar(
                        "SELECT id::text
                         FROM outbound_provider_throttle_overrides
                         WHERE provider = $1
                           AND tenant_id IS NOT DISTINCT FROM $2::text
                           AND (expires_at IS NULL OR expires_at > NOW())
                         ORDER BY updated_at DESC
                         LIMIT 1
                         FOR UPDATE",
                    )
                    .bind(&provider)
                    .bind(target.as_deref())
                    .fetch_one(&mut *tx)
                    .await?;
                    sqlx::query(
                        "UPDATE outbound_provider_throttle_overrides
                         SET throttle_pct = $1, reason = $2, expires_at = $3,
                             created_by = COALESCE(created_by, $4), updated_at = NOW()
                         WHERE id = $5::uuid",
                    )
                    .bind(throttle_pct)
                    .bind(&reason)
                    .bind(expires_at)
                    .bind(auth.user_id.as_deref())
                    .bind(&id)
                    .execute(&mut *tx)
                    .await?;
                    id
                }
            }
        }
    };

    crate::audit_log::insert_audit_log_in_tx_with_env(
        &mut tx,
        state.config.environment.is_production(),
        Some(auth.tenant_id.as_str()),
        auth.user_id.as_deref(),
        "admin.deliverability.throttle_override.upsert",
        "outbound_provider_throttle_override",
        Some(&id),
        json!({
            "provider": provider,
            "target": target,
            "throttle_pct": throttle_pct,
            "reason": reason,
            "expires_at": expires_at.map(|value| value.to_rfc3339()),
        }),
        None,
        None,
        Utc::now(),
    )
    .await?;

    let row: OverrideRow = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM outbound_provider_throttle_overrides WHERE id = $1::uuid"
    ))
    .bind(&id)
    .fetch_one(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(Json(OverrideDto::from_row(row)))
}

/// `DELETE /:id` — removes one override (active or expired).
async fn delete_override(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    require_scopes(&auth, &["*"])?;
    require_system_tenant(&state, &auth).await?;

    Uuid::parse_str(&id).map_err(|_| ApiError::BadRequest("override id must be a UUID".into()))?;

    let mut tx = state.db.begin().await?;
    let row: Option<(Option<String>, String, i32, String)> = sqlx::query_as(
        "SELECT tenant_id, provider, throttle_pct, reason
         FROM outbound_provider_throttle_overrides
         WHERE id = $1::uuid
         FOR UPDATE",
    )
    .bind(&id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((target, provider, throttle_pct, reason)) = row else {
        return Err(ApiError::NotFound(
            "No throttle override with that id.".into(),
        ));
    };

    sqlx::query("DELETE FROM outbound_provider_throttle_overrides WHERE id = $1::uuid")
        .bind(&id)
        .execute(&mut *tx)
        .await?;

    crate::audit_log::insert_audit_log_in_tx_with_env(
        &mut tx,
        state.config.environment.is_production(),
        Some(auth.tenant_id.as_str()),
        auth.user_id.as_deref(),
        "admin.deliverability.throttle_override.delete",
        "outbound_provider_throttle_override",
        Some(&id),
        json!({
            "provider": provider,
            "target": target,
            "throttle_pct": throttle_pct,
            "reason": reason,
        }),
        None,
        None,
        Utc::now(),
    )
    .await?;

    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_validation_accepts_live_buckets_only() {
        for provider in PROVIDERS {
            assert_eq!(validate_provider(provider), Ok(provider.to_string()));
            assert_eq!(
                validate_provider(&provider.to_ascii_uppercase()),
                Ok(provider.to_string())
            );
        }
        for rejected in ["other", "gmail", "", "google;drop"] {
            assert!(
                validate_provider(rejected).is_err(),
                "{rejected:?} must be refused"
            );
        }
    }

    #[test]
    fn target_validation_distinguishes_global_from_tenant_ids() {
        assert_eq!(validate_target(None), Ok(None));
        for global in ["", "  ", "global", "GLOBAL", "*"] {
            assert_eq!(validate_target(Some(global)), Ok(None), "{global:?}");
        }
        assert_eq!(
            validate_target(Some("  tenant-1 ")),
            Ok(Some("tenant-1".to_string()))
        );
        assert_eq!(
            validate_target(Some("0b6f0e4e-1a2b-4c3d-8e9f-01")),
            Ok(Some("0b6f0e4e-1a2b-4c3d-8e9f-01".to_string()))
        );
        // The canonical tenant id column is varchar(26): a longer value could
        // never be a tenant id and would fail the INSERT at runtime.
        assert!(validate_target(Some("0b6f0e4e-1a2b-4c3d-8e9f-0123456789ab")).is_err());
        assert!(validate_target(Some("tenant 1")).is_err());
        assert!(validate_target(Some(&"x".repeat(TARGET_MAX_LEN + 1))).is_err());
    }

    #[test]
    fn pct_is_bounded_zero_to_one_hundred() {
        assert_eq!(validate_pct(0), Ok(0));
        assert_eq!(validate_pct(50), Ok(50));
        assert_eq!(validate_pct(100), Ok(100));
        assert!(validate_pct(-1).is_err());
        assert!(validate_pct(101).is_err());
    }

    #[test]
    fn reason_must_be_non_empty_and_bounded() {
        assert_eq!(validate_reason("  incident  "), Ok("incident".into()));
        assert!(validate_reason("   ").is_err());
        assert!(validate_reason(&"x".repeat(REASON_MAX_LEN + 1)).is_err());
    }

    #[test]
    fn expiry_must_be_rfc3339_and_in_the_future() {
        let now = DateTime::parse_from_rfc3339("2026-10-18T00:00:00Z")
            .expect("fixed now")
            .with_timezone(&Utc);
        assert_eq!(validate_expiry(None, now), Ok(None));
        assert_eq!(validate_expiry(Some("  "), now), Ok(None));
        assert_eq!(
            validate_expiry(Some("2026-10-19T00:00:00Z"), now),
            Ok(Some(
                DateTime::parse_from_rfc3339("2026-10-19T00:00:00Z")
                    .expect("future")
                    .with_timezone(&Utc)
            ))
        );
        assert!(validate_expiry(Some("2026-10-17T00:00:00Z"), now).is_err());
        assert!(validate_expiry(Some("2026-10-18T00:00:00Z"), now).is_err());
        assert!(validate_expiry(Some("tomorrow"), now).is_err());
    }

    #[test]
    fn target_scope_renders_global_as_empty() {
        assert_eq!(target_scope(&None), "");
        assert_eq!(target_scope(&Some("tenant-1".into())), "tenant-1");
    }

    async fn operator_auth() -> AuthUser {
        AuthUser {
            tenant_id: "system".into(),
            user_id: Some("operator-1".into()),
            api_key_id: None,
            session_id: None,
            scopes: vec!["*".into()],
        }
    }

    /// Upsert is idempotent per (provider, target), every mutation writes an
    /// audit row, and delete removes the row. The shared `_api` test database
    /// is seeded with a unique tenant target and cleaned up.
    #[tokio::test]
    async fn upsert_list_delete_round_trip_with_audit() {
        let Some(pool) = crate::test_db::optional_pg_pool("admin_throttle_overrides").await else {
            return;
        };
        let state = crate::app::test_support::test_state_over(pool.clone()).await;
        let auth = operator_auth().await;
        let target = format!(
            "tenant-{}",
            &uuid::Uuid::new_v4().simple().to_string()[..19]
        );
        sqlx::query("DELETE FROM outbound_provider_throttle_overrides WHERE tenant_id = $1")
            .bind(&target)
            .execute(&pool)
            .await
            .expect("clear stale override");

        let created = upsert_override(
            State(state.clone()),
            auth.clone(),
            Json(UpsertBody {
                provider: "Google".into(),
                target: Some(target.clone()),
                throttle_pct: 25,
                reason: "incident drill".into(),
                expires_at: None,
            }),
        )
        .await
        .expect("create")
        .0;
        assert_eq!(created.provider, "google", "provider is normalized");
        assert_eq!(created.target.as_deref(), Some(target.as_str()));
        assert_eq!(created.throttle_pct, 25);
        assert!(created.active);

        // A second PUT adopts the same row (no duplicate active override).
        let updated = upsert_override(
            State(state.clone()),
            auth.clone(),
            Json(UpsertBody {
                provider: "google".into(),
                target: Some(target.clone()),
                throttle_pct: 75,
                reason: "escalated".into(),
                expires_at: None,
            }),
        )
        .await
        .expect("update")
        .0;
        assert_eq!(updated.id, created.id, "upsert keeps one row per key");
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM outbound_provider_throttle_overrides WHERE tenant_id = $1",
        )
        .bind(&target)
        .fetch_one(&pool)
        .await
        .expect("count");
        assert_eq!(count, 1);

        let listed = list_overrides(
            State(state.clone()),
            auth.clone(),
            Query(ListQuery {
                provider: None,
                target: Some(target.clone()),
                include_expired: false,
                limit: 50,
                offset: 0,
            }),
        )
        .await
        .expect("list")
        .0;
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].throttle_pct, 75);
        assert_eq!(listed[0].reason, "escalated");

        let audit_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM audit_logs
             WHERE action = 'admin.deliverability.throttle_override.upsert'
               AND resource_id = $1",
        )
        .bind(&created.id)
        .fetch_one(&pool)
        .await
        .expect("audit count");
        assert_eq!(audit_count, 2, "one audit row per mutation");

        let status = delete_override(State(state.clone()), auth, Path(created.id.clone()))
            .await
            .expect("delete");
        assert_eq!(status, StatusCode::NO_CONTENT);
        let remaining: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM outbound_provider_throttle_overrides WHERE id = $1::uuid",
        )
        .bind(&created.id)
        .fetch_one(&pool)
        .await
        .expect("remaining");
        assert_eq!(remaining, 0);
        let delete_audit: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM audit_logs
             WHERE action = 'admin.deliverability.throttle_override.delete'
               AND resource_id = $1",
        )
        .bind(&created.id)
        .fetch_one(&pool)
        .await
        .expect("delete audit");
        assert_eq!(delete_audit, 1);
    }
}
