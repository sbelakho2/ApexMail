//! Risk monitoring endpoints.
//!

use super::super::helpers::table_exists;
use axum::extract::{Query, State};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::sync::OnceLock;

use crate::error::ApiError;
use crate::middleware::auth::AuthUser;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/", get(get_risk_tenants).patch(update_risk))
}

#[derive(Debug, PartialEq)]
struct RiskAuditEntry {
    action: &'static str,
    resource_id: Option<String>,
    tenant_id: Option<String>,
    metadata: serde_json::Value,
}

fn build_risk_audit_entry(mutation: &RiskMutation) -> RiskAuditEntry {
    match mutation {
        RiskMutation::SetLimit {
            tenant_id,
            limit_type,
            value,
        } => RiskAuditEntry {
            action: "control_plane.risk.limit_set",
            resource_id: Some(tenant_id.clone()),
            tenant_id: Some(tenant_id.clone()),
            metadata: json!({
                "limitType": limit_type,
                "value": value,
            }),
        },
        RiskMutation::ResolveFlag { tenant_id, flag_id } => RiskAuditEntry {
            action: "control_plane.risk.flag_resolved",
            resource_id: Some(flag_id.clone()),
            tenant_id: Some(tenant_id.clone()),
            metadata: json!({
                "tenantId": tenant_id,
            }),
        },
        RiskMutation::SaveThresholds { thresholds } => RiskAuditEntry {
            action: "control_plane.risk.thresholds_saved",
            resource_id: None,
            tenant_id: None,
            metadata: json!({ "thresholds": thresholds }),
        },
        RiskMutation::RunAssessment => RiskAuditEntry {
            action: "control_plane.risk.assessment_queued",
            resource_id: None,
            tenant_id: None,
            metadata: json!({}),
        },
    }
}

async fn log_risk_audit(state: &AppState, mutation: &RiskMutation) {
    let entry = build_risk_audit_entry(mutation);

    crate::audit_log::insert_audit_log_best_effort(
        &state.db,
        entry.tenant_id.as_deref(),
        None,
        entry.action,
        "risk",
        entry.resource_id.as_deref(),
        entry.metadata,
        None,
        None,
    )
    .await;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TenantLimits {
    pub daily: Option<i64>,
    pub hourly: Option<i64>,
}

#[derive(Debug, Clone)]
struct RiskSettings {
    thresholds: Thresholds,
    last_assessed_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone)]
struct RiskAssessmentRow {
    tenant_id: String,
    tenant_name: String,
    domain: String,
    critical_alerts: i64,
    high_alerts: i64,
    bounces: i64,
    complaints: i64,
    sent: i64,
}

/// API-114/115: Track whether risk settings table has been ensured to avoid
/// running DDL on every request (causes latency and lock contention).
static RISK_TABLE_ENSURE: OnceLock<()> = OnceLock::new();

async fn ensure_risk_settings_table(db: &sqlx::PgPool) -> Result<(), ApiError> {
    if RISK_TABLE_ENSURE.get().is_some() {
        return Ok(());
    }
    sqlx::query(
        "INSERT INTO risk_settings (tenant_id, thresholds, updated_at)
         VALUES ('system', '{}'::jsonb, NOW())
         ON CONFLICT (tenant_id) DO NOTHING",
    )
    .execute(db)
    .await?;

    let _ = RISK_TABLE_ENSURE.set(());
    Ok(())
}

async fn load_risk_settings(db: &sqlx::PgPool) -> Result<RiskSettings, ApiError> {
    ensure_risk_settings_table(db).await?;

    let row: Option<(serde_json::Value, Option<chrono::DateTime<chrono::Utc>>)> = sqlx::query_as(
        "SELECT thresholds, last_assessed_at FROM risk_settings WHERE tenant_id = 'system'",
    )
    .fetch_optional(db)
    .await?;

    Ok(match row {
        Some((thresholds_json, last_assessed_at)) => RiskSettings {
            thresholds: serde_json::from_value(thresholds_json).unwrap_or_default(),
            last_assessed_at,
        },
        None => RiskSettings {
            thresholds: Thresholds::default(),
            last_assessed_at: None,
        },
    })
}

async fn save_thresholds(db: &sqlx::PgPool, thresholds: &Thresholds) -> Result<(), ApiError> {
    ensure_risk_settings_table(db).await?;

    sqlx::query(
        "UPDATE risk_settings
         SET thresholds = $1::jsonb,
             updated_at = NOW()
         WHERE tenant_id = 'system'",
    )
    .bind(serde_json::to_value(thresholds)?)
    .execute(db)
    .await?;

    Ok(())
}

async fn save_last_assessed_at(
    db: &sqlx::PgPool,
    assessed_at: chrono::DateTime<chrono::Utc>,
) -> Result<(), ApiError> {
    ensure_risk_settings_table(db).await?;

    sqlx::query(
        "UPDATE risk_settings
         SET last_assessed_at = $1,
             updated_at = NOW()
         WHERE tenant_id = 'system'",
    )
    .bind(assessed_at)
    .execute(db)
    .await?;

    Ok(())
}

async fn load_tenant_limits(db: &sqlx::PgPool) -> Result<HashMap<String, TenantLimits>, ApiError> {
    let rows: Vec<(String, serde_json::Value)> = sqlx::query_as(
        "SELECT id, COALESCE(metadata->'riskLimits', '{}'::jsonb)
         FROM tenants",
    )
    .fetch_all(db)
    .await?;

    Ok(rows
        .into_iter()
        .filter_map(|(tenant_id, limits_json)| {
            let limits = serde_json::from_value::<TenantLimits>(limits_json).ok()?;
            if limits.daily.is_none() && limits.hourly.is_none() {
                None
            } else {
                Some((tenant_id, limits))
            }
        })
        .collect())
}

fn build_risk_rows_sql(
    has_reputation_stats: bool,
    has_reputation_alerts: bool,
    paginated: bool,
) -> String {
    let critical_alerts_expr = if has_reputation_alerts {
        "COALESCE(ra.critical_alerts, 0)::bigint"
    } else {
        "0::bigint"
    };
    let high_alerts_expr = if has_reputation_alerts {
        "COALESCE(ra.high_alerts, 0)::bigint"
    } else {
        "0::bigint"
    };
    let bounces_expr = if has_reputation_stats {
        "COALESCE(rs.recent_bounces, 0)::bigint"
    } else {
        "0::bigint"
    };
    let complaints_expr = if has_reputation_stats {
        "COALESCE(rs.recent_complaints, 0)::bigint"
    } else {
        "0::bigint"
    };
    let sent_expr = if has_reputation_stats {
        "COALESCE(rs.recent_sent, 0)::bigint"
    } else {
        "0::bigint"
    };

    let alert_join = if has_reputation_alerts {
        "LEFT JOIN (
            SELECT tenant_id,
                   COUNT(*) FILTER (WHERE acknowledged = false AND alert_type = 'critical')::bigint AS critical_alerts,
                   COUNT(*) FILTER (WHERE acknowledged = false AND alert_type <> 'critical')::bigint AS high_alerts
            FROM reputation_alerts
            GROUP BY tenant_id
        ) ra ON ra.tenant_id = t.id"
    } else {
        ""
    };
    let stats_join = if has_reputation_stats {
        "LEFT JOIN (
            SELECT tenant_id,
                   COALESCE(SUM(bounces), 0)::bigint AS recent_bounces,
                   COALESCE(SUM(complaints), 0)::bigint AS recent_complaints,
                   COALESCE(SUM(sent), 0)::bigint AS recent_sent
            FROM reputation_stats
            WHERE date >= CURRENT_DATE - INTERVAL '30 days'
            GROUP BY tenant_id
        ) rs ON rs.tenant_id = t.id"
    } else {
        ""
    };
    let pagination = if paginated { " LIMIT $1 OFFSET $2" } else { "" };

    format!(
        "SELECT t.id, t.name, t.slug,
                {critical_alerts_expr} AS critical_alerts,
                {high_alerts_expr} AS high_alerts,
                {bounces_expr} AS recent_bounces,
                {complaints_expr} AS recent_complaints,
                {sent_expr} AS recent_sent
         FROM tenants t
         {alert_join}
         {stats_join}
         ORDER BY t.created_at DESC{pagination}"
    )
}

async fn load_risk_rows(
    db: &sqlx::PgPool,
    limit: Option<i64>,
    offset: Option<i64>,
) -> Result<Vec<RiskAssessmentRow>, ApiError> {
    let has_reputation_stats = table_exists(db, "reputation_stats").await;
    let has_reputation_alerts = table_exists(db, "reputation_alerts").await;
    let sql = build_risk_rows_sql(has_reputation_stats, has_reputation_alerts, limit.is_some());

    let mut query = sqlx::query_as::<_, (String, String, String, i64, i64, i64, i64, i64)>(&sql);
    if let Some(limit) = limit {
        query = query.bind(limit);
    }
    if let Some(offset) = offset {
        query = query.bind(offset);
    }

    let rows = query.fetch_all(db).await?;

    Ok(rows
        .into_iter()
        .map(
            |(
                tenant_id,
                tenant_name,
                domain,
                critical_alerts,
                high_alerts,
                bounces,
                complaints,
                sent,
            )| RiskAssessmentRow {
                tenant_id,
                tenant_name,
                domain,
                critical_alerts,
                high_alerts,
                bounces,
                complaints,
                sent,
            },
        )
        .collect())
}

fn build_risk_metrics(bounces: i64, complaints: i64, sent: i64) -> RiskMetrics {
    let sent_f = sent as f64;
    let bounce_rate = if sent > 0 {
        bounces as f64 / sent_f
    } else {
        0.0
    };
    let complaint_rate = if sent > 0 {
        complaints as f64 / sent_f
    } else {
        0.0
    };

    RiskMetrics {
        bounce_rate,
        complaint_rate,
        daily_volume: 0,
        monthly_volume: sent,
    }
}

fn compute_risk_score(
    critical_alerts: i64,
    high_alerts: i64,
    metrics: &RiskMetrics,
    thresholds: &Thresholds,
) -> i64 {
    let bounce_rate_pct = metrics.bounce_rate * 100.0;
    let complaint_rate_pct = metrics.complaint_rate * 100.0;
    let mut score = critical_alerts * 20 + high_alerts * 10;

    if bounce_rate_pct >= thresholds.bounce_rate_critical {
        score += 25;
    } else if bounce_rate_pct >= thresholds.bounce_rate_warn {
        score += 12;
    }

    if complaint_rate_pct >= thresholds.complaint_rate_critical {
        score += 35;
    } else if complaint_rate_pct >= thresholds.complaint_rate_warn {
        score += 18;
    }

    score.min(100)
}

fn risk_level_for_score(score: i64) -> &'static str {
    if score >= 90 {
        "critical"
    } else if score >= 70 {
        "high"
    } else if score >= 40 {
        "medium"
    } else {
        "low"
    }
}

fn build_assessment_alerts(
    metrics: &RiskMetrics,
    thresholds: &Thresholds,
) -> Vec<(&'static str, f64, f64)> {
    let mut alerts = Vec::new();
    let bounce_rate_pct = metrics.bounce_rate * 100.0;
    let complaint_rate_pct = metrics.complaint_rate * 100.0;

    if bounce_rate_pct >= thresholds.bounce_rate_critical {
        alerts.push(("critical", bounce_rate_pct, thresholds.bounce_rate_critical));
    } else if bounce_rate_pct >= thresholds.bounce_rate_warn {
        alerts.push(("high", bounce_rate_pct, thresholds.bounce_rate_warn));
    }

    if complaint_rate_pct >= thresholds.complaint_rate_critical {
        alerts.push((
            "critical",
            complaint_rate_pct,
            thresholds.complaint_rate_critical,
        ));
    } else if complaint_rate_pct >= thresholds.complaint_rate_warn {
        alerts.push(("high", complaint_rate_pct, thresholds.complaint_rate_warn));
    }

    alerts
}

async fn run_risk_assessment(
    db: &sqlx::PgPool,
    thresholds: &Thresholds,
) -> Result<(chrono::DateTime<chrono::Utc>, usize, usize), ApiError> {
    let rows = load_risk_rows(db, None, None).await?;
    let assessed_at = chrono::Utc::now();
    let mut alerts_created = 0usize;

    if table_exists(db, "reputation_alerts").await {
        let mut tx = db.begin().await?;

        for row in &rows {
            let metrics = build_risk_metrics(row.bounces, row.complaints, row.sent);
            let alerts = build_assessment_alerts(&metrics, thresholds);

            sqlx::query(
                "DELETE FROM reputation_alerts
                 WHERE tenant_id = $1
                   AND acknowledged = false
                   AND alert_type IN ('high', 'critical')",
            )
            .bind(&row.tenant_id)
            .execute(&mut *tx)
            .await?;

            for (alert_type, value, threshold) in alerts {
                sqlx::query(
                    "INSERT INTO reputation_alerts (id, tenant_id, alert_type, value, threshold, acknowledged, created_at)
                     VALUES ($1, $2, $3, $4, $5, false, $6)",
                )
                .bind(apexmail_lib::id::generate_id("", 26))
                .bind(&row.tenant_id)
                .bind(alert_type)
                .bind(value)
                .bind(threshold)
                .bind(assessed_at)
                .execute(&mut *tx)
                .await?;

                alerts_created += 1;
            }
        }

        tx.commit().await?;
    }

    save_last_assessed_at(db, assessed_at).await?;

    Ok((assessed_at, rows.len(), alerts_created))
}

fn enqueue_risk_assessment(state: AppState, thresholds: Thresholds) -> String {
    let job_id = apexmail_lib::id::generate_id("riskjob_", 26);
    let worker_job_id = job_id.clone();

    tokio::spawn(async move {
        tracing::info!(job_id = %worker_job_id, "risk assessment worker started");
        match run_risk_assessment(&state.db, &thresholds).await {
            Ok((assessed_at, tenants_assessed, alerts_created)) => {
                tracing::info!(
                    job_id = %worker_job_id,
                    assessed_at = %assessed_at,
                    tenants_assessed,
                    alerts_created,
                    "risk assessment worker completed"
                );
            }
            Err(error) => {
                tracing::error!(job_id = %worker_job_id, error = %error, "risk assessment worker failed");
            }
        }
    });

    job_id
}

fn queued_risk_assessment_response(job_id: &str) -> serde_json::Value {
    serde_json::json!({
        "success": true,
        "status": "queued",
        "jobId": job_id,
    })
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
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
    crate::middleware::auth::require_system_tenant(&state, &auth).await?;

    let settings = load_risk_settings(&state.db).await?;

    // Return thresholds if requested
    if params.resource.as_deref() == Some("thresholds") {
        return Ok(Json(serde_json::json!({
            "thresholds": settings.thresholds,
            "persisted": true
        })));
    }

    let db = &state.db;

    let limit = params.limit.clamp(1, 200);
    let offset = params.offset.max(0);
    let rows = load_risk_rows(db, Some(limit), Some(offset)).await?;
    let limits_map = load_tenant_limits(db).await?;
    let last_assessed = settings
        .last_assessed_at
        .unwrap_or_else(chrono::Utc::now)
        .to_rfc3339();

    let tenants: Vec<RiskTenant> = rows
        .into_iter()
        .map(|row| {
            let metrics = build_risk_metrics(row.bounces, row.complaints, row.sent);
            let risk_score = compute_risk_score(
                row.critical_alerts,
                row.high_alerts,
                &metrics,
                &settings.thresholds,
            );
            let risk_level = risk_level_for_score(risk_score);

            RiskTenant {
                tenant_id: row.tenant_id.clone(),
                tenant_name: row.tenant_name,
                domain: row.domain,
                risk_score,
                risk_level: risk_level.into(),
                flags: vec![],
                metrics,
                limits: limits_map.get(&row.tenant_id).cloned().unwrap_or_default(),
                last_assessed: last_assessed.clone(),
            }
        })
        .collect();

    let json_val = serde_json::to_value(&tenants)
        .map_err(|e| ApiError::Internal(format!("serialization error: {e}")))?;
    Ok(Json(json_val))
}

#[derive(Debug, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
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
    crate::middleware::auth::require_system_tenant(&state, &auth).await?;

    match body {
        RiskMutation::SetLimit {
            tenant_id,
            limit_type,
            value,
        } => {
            if !matches!(limit_type.as_str(), "daily" | "hourly") {
                return Err(ApiError::Validation(vec!["Invalid limit type".into()]));
            }

            let result = sqlx::query(
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
            .await?;

            if result.rows_affected() == 0 {
                return Err(ApiError::NotFound("tenant not found".into()));
            }

            log_risk_audit(
                &state,
                &RiskMutation::SetLimit {
                    tenant_id,
                    limit_type,
                    value,
                },
            )
            .await;

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

            log_risk_audit(&state, &RiskMutation::ResolveFlag { tenant_id, flag_id }).await;
            Ok(Json(serde_json::json!({ "success": true })))
        }
        RiskMutation::SaveThresholds { thresholds } => {
            save_thresholds(&state.db, &thresholds).await?;

            log_risk_audit(
                &state,
                &RiskMutation::SaveThresholds {
                    thresholds: thresholds.clone(),
                },
            )
            .await;
            Ok(Json(
                serde_json::json!({ "success": true, "thresholds": thresholds }),
            ))
        }
        RiskMutation::RunAssessment => {
            let thresholds = load_risk_settings(&state.db).await?.thresholds;
            let job_id = enqueue_risk_assessment(state.clone(), thresholds);
            log_risk_audit(&state, &RiskMutation::RunAssessment).await;
            Ok(Json(queued_risk_assessment_response(&job_id)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_risk_audit_entry_for_set_limit_includes_target_and_value() {
        let entry = build_risk_audit_entry(&RiskMutation::SetLimit {
            tenant_id: "tenant_123".into(),
            limit_type: "daily".into(),
            value: Some(5000),
        });

        assert_eq!(entry.action, "control_plane.risk.limit_set");
        assert_eq!(entry.resource_id.as_deref(), Some("tenant_123"));
        assert_eq!(entry.tenant_id.as_deref(), Some("tenant_123"));
        assert_eq!(entry.metadata["limitType"], "daily");
        assert_eq!(entry.metadata["value"], 5000);
    }

    #[test]
    fn build_risk_audit_entry_for_run_assessment_is_global() {
        let entry = build_risk_audit_entry(&RiskMutation::RunAssessment);

        assert_eq!(entry.action, "control_plane.risk.assessment_queued");
        assert!(entry.resource_id.is_none());
        assert!(entry.tenant_id.is_none());
        assert_eq!(entry.metadata, json!({}));
    }

    #[test]
    fn compute_risk_score_uses_threshold_bands() {
        let metrics = RiskMetrics {
            bounce_rate: 0.08,
            complaint_rate: 0.02,
            daily_volume: 0,
            monthly_volume: 1000,
        };
        let strict = Thresholds::default();
        let lenient = Thresholds {
            bounce_rate_warn: 12.0,
            bounce_rate_critical: 20.0,
            complaint_rate_warn: 5.0,
            complaint_rate_critical: 8.0,
        };

        assert!(
            compute_risk_score(0, 0, &metrics, &strict)
                > compute_risk_score(0, 0, &metrics, &lenient)
        );
    }

    #[test]
    fn build_assessment_alerts_emits_warning_and_critical_breaches() {
        let metrics = RiskMetrics {
            bounce_rate: 0.11,
            complaint_rate: 0.015,
            daily_volume: 0,
            monthly_volume: 1000,
        };

        let alerts = build_assessment_alerts(&metrics, &Thresholds::default());

        assert_eq!(alerts.len(), 2);
        assert!(alerts
            .iter()
            .any(|(severity, _, _)| *severity == "critical"));
        assert!(alerts.iter().any(|(severity, _, _)| *severity == "high"));
    }

    #[test]
    fn queued_risk_assessment_response_reports_background_job() {
        let response = queued_risk_assessment_response("riskjob_123");

        assert_eq!(response["success"], true);
        assert_eq!(response["status"], "queued");
        assert_eq!(response["jobId"], "riskjob_123");
    }
}
