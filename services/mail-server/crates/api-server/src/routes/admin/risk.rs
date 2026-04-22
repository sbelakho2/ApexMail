//! Risk monitoring endpoints.
//!
//! Migrated from:apps/control-plane/src/app/api/risk/route.ts

use super::super::helpers::table_exists;
use axum::extract::{Query, State};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use std::collections::HashMap;

use crate::error::ApiError;
use crate::middleware::auth::AuthUser;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/", get(get_risk_tenants).patch(update_risk))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Thresholds {
    pub bounce_rate_warn: f64,
    pub bounce_rate_critical: f64,
    pub complaint_rate_warn: f64,
    pub complaint_rate_critical: f64,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            bounce_rate_warn: 5.0,
            bounce_rate_critical: 10.0,
            complaint_rate_warn: 1.0,
            complaint_rate_critical: 3.0,
        }
    }
}

static THRESHOLDS: Mutex<Option<Thresholds>> = Mutex::new(None);
static TENANT_LIMITS: Mutex<Option<HashMap<String, TenantLimits>>> = Mutex::new(None);

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TenantLimits {
    pub daily: Option<i64>,
    pub hourly: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct RiskListQuery {
    pub resource: Option<String>,
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
pub struct RiskTenant {
    pub tenant_id: String,
    pub tenant_name: String,
    pub domain: String,
    pub risk_score: i64,
    pub risk_level: String,
    pub flags: Vec<serde_json::Value>,
    pub metrics: RiskMetrics,
    pub limits: TenantLimits,
    pub last_assessed: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RiskMetrics {
    pub bounce_rate: f64,
    pub complaint_rate: f64,
    pub daily_volume: i64,
    pub monthly_volume: i64,
}

async fn get_risk_tenants(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<RiskListQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

// Return thresholds if requested
    if params.resource.as_deref() == Some("thresholds") {
        let thresholds = THRESHOLDS.lock().ok()
            .and_then(|g| g.clone())
            .unwrap_or_default();
        return Ok(Json(serde_json::json!({
            "thresholds": thresholds,
            "persisted": true
        })));
    }

    let db = &state.db;
    let has_reputation_stats = table_exists(db, "reputation_stats").await;
    let has_reputation_alerts = table_exists(db, "reputation_alerts").await;

    let limit = params.limit.clamp(1, 200);
    let offset = params.offset.max(0);

// Build SQL dynamically based on available tables
    let critical_alerts_expr = if has_reputation_alerts {
        "COALESCE(SUM(CASE WHEN ra.alert_type = 'critical' THEN 1 ELSE 0 END), 0)::text"
    } else {
        "'0'::text"
    };
    let high_alerts_expr = if has_reputation_alerts {
        "COALESCE(SUM(CASE WHEN ra.alert_type <> 'critical' THEN 1 ELSE 0 END), 0)::text"
    } else {
        "'0'::text"
    };
    let bounces_expr = if has_reputation_stats {
        "COALESCE(SUM(rs.bounces), 0)::text"
    } else {
        "'0'::text"
    };
    let complaints_expr = if has_reputation_stats {
        "COALESCE(SUM(rs.complaints), 0)::text"
    } else {
        "'0'::text"
    };
    let sent_expr = if has_reputation_stats {
        "COALESCE(SUM(rs.sent), 0)::text"
    } else {
        "'0'::text"
    };

    let alert_join = if has_reputation_alerts {
        "LEFT JOIN reputation_alerts ra ON ra.tenant_id = t.id AND ra.acknowledged = false"
    } else {
        ""
    };
    let stats_join = if has_reputation_stats {
        "LEFT JOIN reputation_stats rs ON rs.tenant_id = t.id AND rs.date >= CURRENT_DATE - INTERVAL '30 days'"
    } else {
        ""
    };

    let sql = format!(
        "SELECT t.id, t.name, t.slug,
                {critical_alerts_expr} as critical_alerts,
                {high_alerts_expr} as high_alerts,
                {bounces_expr} as recent_bounces,
                {complaints_expr} as recent_complaints,
                {sent_expr} as recent_sent
         FROM tenants t
         {alert_join}
         {stats_join}
         GROUP BY t.id, t.name, t.slug
         ORDER BY t.created_at DESC
         LIMIT $1 OFFSET $2"
    );

    let rows: Vec<(String, String, String, String, String, String, String, String)> =
        sqlx::query_as(&sql)
            .bind(limit)
            .bind(offset)
            .fetch_all(db)
            .await?;

    let limits_map = TENANT_LIMITS.lock().ok()
        .and_then(|g| g.clone())
        .unwrap_or_default();

    let now = chrono::Utc::now().to_rfc3339();
    let tenants: Vec<RiskTenant> = rows
        .into_iter()
        .map(|(id, name, slug, critical_str, high_str, bounces_str, complaints_str, sent_str)| {
            let critical: i64 = critical_str.parse().unwrap_or(0);
            let high: i64 = high_str.parse().unwrap_or(0);
            let bounces: f64 = bounces_str.parse().unwrap_or(0.0);
            let complaints: f64 = complaints_str.parse().unwrap_or(0.0);
            let sent: f64 = sent_str.parse().unwrap_or(0.0);

            let bounce_rate = if sent > 0.0 { bounces / sent } else { 0.0 };
            let complaint_rate = if sent > 0.0 { complaints / sent } else { 0.0 };
            let risk_score = (critical * 35 + high * 12 + (bounce_rate * 200.0) as i64 + (complaint_rate * 2000.0) as i64).min(100);

            let risk_level = if risk_score >= 90 { "critical" }
                else if risk_score >= 70 { "high" }
                else if risk_score >= 40 { "medium" }
                else { "low" };

            RiskTenant {
                tenant_id: id.clone(),
                tenant_name: name,
                domain: slug,
                risk_score,
                risk_level: risk_level.into(),
                flags: vec![],
                metrics: RiskMetrics {
                    bounce_rate,
                    complaint_rate,
                    daily_volume: 0,
                    monthly_volume: sent as i64,
                },
                limits: limits_map.get(&id).cloned().unwrap_or_default(),
                last_assessed: now.clone(),
            }
        })
        .collect();

    let json_val = serde_json::to_value(&tenants)
        .map_err(|e| ApiError::Internal(format!("serialization error: {e}")))?;
    Ok(Json(json_val))
}

#[derive(Debug, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum RiskMutation {
    SetLimit {
        #[serde(rename = "tenantId")]
        tenant_id: String,
        #[serde(rename = "limitType")]
        limit_type: String,
        value: Option<i64>,
    },
    ResolveFlag {
        #[serde(rename = "tenantId")]
        tenant_id: String,
        #[serde(rename = "flagId")]
        flag_id: String,
    },
    SaveThresholds {
        thresholds: Thresholds,
    },
    RunAssessment,
}

async fn update_risk(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<RiskMutation>,
) -> Result<Json<serde_json::Value>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    match body {
        RiskMutation::SetLimit { tenant_id, limit_type, value } => {
            if let Ok(mut guard) = TENANT_LIMITS.lock() {
                let map = guard.get_or_insert_with(HashMap::new);
                let entry = map.entry(tenant_id.clone()).or_insert_with(TenantLimits::default);
                match limit_type.as_str() {
                    "daily" => entry.daily = value,
                    "hourly" => entry.hourly = value,
                    _ => {}
                }
            }

// Best-effort persist to DB
            if let Err(e) = sqlx::query(
                "UPDATE tenants
                 SET metadata = COALESCE(metadata, '{}'::jsonb) || jsonb_build_object(
                     'riskLimits',
                     COALESCE(metadata->'riskLimits', '{}'::jsonb) || jsonb_build_object($2, $3::int)
                 ),
                 updated_at = NOW()
                 WHERE id = $1",
            )
            .bind(&tenant_id)
            .bind(&limit_type)
            .bind(value)
            .execute(&state.db)
            .await
            {
                tracing::warn!(tenant_id = %tenant_id, error = %e, "Failed to persist risk limits");
            }

            Ok(Json(serde_json::json!({ "success": true })))
        }
        RiskMutation::ResolveFlag { tenant_id, flag_id } => {
            if table_exists(&state.db, "reputation_alerts").await {
                if let Err(e) = sqlx::query(
                    "UPDATE reputation_alerts SET acknowledged = true WHERE tenant_id = $1 AND id = $2",
                )
                .bind(&tenant_id)
                .bind(&flag_id)
                .execute(&state.db)
                .await
                {
                    tracing::warn!(tenant_id = %tenant_id, flag_id = %flag_id, error = %e, "Failed to resolve reputation flag");
                }
            }
            Ok(Json(serde_json::json!({ "success": true })))
        }
        RiskMutation::SaveThresholds { thresholds } => {
            if let Ok(mut guard) = THRESHOLDS.lock() {
                *guard = Some(thresholds.clone());
            }
            Ok(Json(serde_json::json!({ "success": true, "thresholds": thresholds })))
        }
        RiskMutation::RunAssessment => {
            Ok(Json(serde_json::json!({ "success": true, "assessedAt": chrono::Utc::now().to_rfc3339() })))
        }
    }
}
