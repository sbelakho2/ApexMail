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

async fn log_risk_audit(state: &AppState, auth: &AuthUser, mutation: &RiskMutation) {
    let entry = build_risk_audit_entry(mutation);

    // Actor attribution (P2-2): the target tenant stays in the entry's
    // tenant scope; the ACTING operator's identity rides along as user_id.
    crate::audit_log::insert_audit_log_best_effort_with_env(
        &state.db,
        state.config.environment.is_production(),
        entry.tenant_id.as_deref(),
        auth.user_id.as_deref(),
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
        // tenants.slug is NULLABLE: a NULL row used to fail the String
        // decode and turn the whole listing into a 500.
        "SELECT t.id, t.name, COALESCE(t.slug, '') AS slug,
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

/// The keys each mutation accepts. `deny_unknown_fields` cannot be honoured
/// on an internally-tagged enum — serde buffers a tagged value and ignores the
/// attribute — so a typo like `"limitt": "daily"` was silently dropped and the
/// request appeared to succeed without applying anything. The keys are
/// validated against this table before deserialization.
fn risk_mutation_allowed_keys(action: &str) -> Option<&'static [&'static str]> {
    match action {
        "set_limit" => Some(&["action", "tenantId", "limitType", "value"]),
        "resolve_flag" => Some(&["action", "tenantId", "flagId"]),
        "save_thresholds" => Some(&["action", "thresholds"]),
        "run_assessment" => Some(&["action"]),
        _ => None,
    }
}

/// Unknown keys in `body` for the declared action (empty = accepted), plus
/// `None` when the action itself is not a known mutation.
fn risk_mutation_unknown_keys(body: &serde_json::Value) -> Option<Vec<String>> {
    let object = body.as_object()?;
    let action = object.get("action")?.as_str()?;
    let allowed = risk_mutation_allowed_keys(action)?;
    let mut unknown: Vec<String> = object
        .keys()
        .filter(|key| !allowed.contains(&key.as_str()))
        .cloned()
        .collect();
    unknown.sort();
    Some(unknown)
}

/// `Serialize` exists so tests can build the exact wire payload through the
/// same names the server accepts (the handler validates the raw JSON keys).
#[derive(Debug, Serialize, Deserialize)]
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
    Json(raw): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;
    crate::middleware::auth::require_system_tenant(&state, &auth).await?;

    // Key validation first: an unknown action or an unknown key is a client
    // error the caller must see, never a silently-ignored field.
    let unknown = risk_mutation_unknown_keys(&raw).ok_or_else(|| {
        ApiError::Validation(vec![
            "action must be one of set_limit, resolve_flag, save_thresholds, run_assessment".into(),
        ])
    })?;
    if !unknown.is_empty() {
        return Err(ApiError::Validation(vec![format!(
            "unknown field(s) for this action: {}",
            unknown.join(", ")
        )]));
    }
    let body: RiskMutation = serde_json::from_value(raw)
        .map_err(|error| ApiError::Validation(vec![error.to_string()]))?;

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
                &auth,
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
                // Propagate (P2): swallowing the UPDATE reported
                // success:true for a flag that was never resolved —
                // operators trusted a no-op.
                sqlx::query(
                    "UPDATE reputation_alerts SET acknowledged = true WHERE tenant_id = $1 AND id = $2",
                )
                .bind(&tenant_id)
                .bind(&flag_id)
                .execute(&state.db)
                .await?;
            }

            log_risk_audit(
                &state,
                &auth,
                &RiskMutation::ResolveFlag { tenant_id, flag_id },
            )
            .await;
            Ok(Json(serde_json::json!({ "success": true })))
        }
        RiskMutation::SaveThresholds { thresholds } => {
            save_thresholds(&state.db, &thresholds).await?;

            log_risk_audit(
                &state,
                &auth,
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
            log_risk_audit(&state, &auth, &RiskMutation::RunAssessment).await;
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

// ─── Adversarial risk-monitoring tests ─────────────────────────

#[cfg(test)]
mod adversarial_tests {
    use super::*;

    fn admin_auth() -> AuthUser {
        AuthUser {
            tenant_id: "system".into(),
            user_id: Some("usr_adv_risk_operator_01".into()),
            api_key_id: None,
            session_id: None,
            scopes: vec!["*".into()],
        }
    }

    async fn state_and_pool(name: &str) -> Option<(AppState, sqlx::PgPool)> {
        let pool = crate::test_db::optional_pg_pool(name).await?;
        let state = crate::app::test_support::test_state_over(pool.clone()).await;
        Some((state, pool))
    }

    #[test]
    fn sql_builder_degrades_gracefully_without_optional_tables() {
        // Without reputation tables the expressions are literal zeros and no
        // joins are emitted.
        let sql = build_risk_rows_sql(false, false, false);
        assert!(sql.contains("0::bigint AS critical_alerts"));
        assert!(sql.contains("0::bigint AS recent_sent"));
        assert!(!sql.contains("reputation_stats"));
        assert!(!sql.contains("reputation_alerts"));
        assert!(!sql.contains("LIMIT"));
        // With both tables and pagination the joins and LIMIT appear.
        let sql = build_risk_rows_sql(true, true, true);
        assert!(sql.contains("LEFT JOIN"));
        assert!(sql.contains("reputation_stats"));
        assert!(sql.contains("reputation_alerts"));
        assert!(sql.ends_with(" LIMIT $1 OFFSET $2"));
    }

    #[test]
    fn risk_score_bands_and_levels_are_monotone_and_capped() {
        let metrics = |bounce: f64, complaint: f64| RiskMetrics {
            bounce_rate: bounce,
            complaint_rate: complaint,
            daily_volume: 0,
            monthly_volume: 100,
        };
        let t = Thresholds::default();
        assert_eq!(compute_risk_score(0, 0, &metrics(0.0, 0.0), &t), 0);
        assert_eq!(
            compute_risk_score(3, 3, &metrics(1.0, 1.0), &t),
            100,
            "score is capped at 100"
        );
        // Band edges: exactly at warn / below critical.
        assert_eq!(
            compute_risk_score(0, 0, &metrics(0.05, 0.0), &t),
            12,
            "5% bounce == warn band (>=)"
        );
        assert_eq!(
            compute_risk_score(0, 0, &metrics(0.10, 0.0), &t),
            25,
            "10% bounce == critical band (>=)"
        );
        assert_eq!(
            compute_risk_score(0, 0, &metrics(0.0, 0.03), &t),
            35,
            "3% complaint == critical band"
        );
        assert_eq!(risk_level_for_score(0), "low");
        assert_eq!(risk_level_for_score(39), "low");
        assert_eq!(risk_level_for_score(40), "medium");
        assert_eq!(risk_level_for_score(69), "medium");
        assert_eq!(risk_level_for_score(70), "high");
        assert_eq!(risk_level_for_score(89), "high");
        assert_eq!(risk_level_for_score(90), "critical");
        assert_eq!(risk_level_for_score(100), "critical");
    }

    #[test]
    fn metrics_with_zero_sends_never_divide_by_zero() {
        let m = build_risk_metrics(5, 5, 0);
        assert_eq!(m.bounce_rate, 0.0);
        assert_eq!(m.complaint_rate, 0.0);
        assert_eq!(m.monthly_volume, 0);
        let m = build_risk_metrics(2, 1, 4);
        assert_eq!(m.bounce_rate, 0.5);
        assert_eq!(m.complaint_rate, 0.25);
        assert_eq!(m.monthly_volume, 4);
    }

    #[test]
    fn threshold_deserialization_is_strict() {
        let ok: Thresholds =
            serde_json::from_str(r#"{"bounceRateWarn":5,"bounceRateCritical":10,"complaintRateWarn":1,"complaintRateCritical":3}"#)
                .expect("camelCase thresholds");
        assert_eq!(ok.bounce_rate_warn, Thresholds::default().bounce_rate_warn);
        assert_eq!(ok.complaint_rate_critical, 3.0);
        assert!(
            serde_json::from_str::<Thresholds>(r#"{"bounce_rate_warn":5}"#).is_err(),
            "camelCase only"
        );
        assert!(serde_json::from_str::<Thresholds>(
            r#"{"bounceRateWarn":5,"bounceRateCritical":10,"complaintRateWarn":1,"complaintRateCritical":3,"evil":true}"#
        )
        .is_err());
        // Mutation tags are snake_case actions with deny_unknown_fields.
        assert!(serde_json::from_str::<RiskMutation>(r#"{"action":"drop_everything"}"#).is_err());
        // serde's internally-tagged enums ignore `deny_unknown_fields` on
        // unit variants — extra keys are accepted for run_assessment. This
        // is the current wire contract (documented, not a security issue:
        // the extra key is dropped, no field is bound from it).
        assert!(
            serde_json::from_str::<RiskMutation>(r#"{"action":"run_assessment","extra":1}"#)
                .is_ok()
        );
        let parse = serde_json::from_str::<RiskMutation>(
            r#"{"action":"set_limit","tenantId":"t","limitType":"daily","value":10}"#,
        );
        assert!(matches!(parse, Ok(RiskMutation::SetLimit { .. })));
    }

    /// An unknown key must be REFUSED, not silently dropped: serde cannot
    /// honour `deny_unknown_fields` on an internally-tagged enum, so a typo
    /// (`limitt`) used to deserialize fine and the request appeared to succeed
    /// without applying anything. The handler validates the raw JSON keys.
    #[tokio::test]
    async fn unknown_mutation_keys_and_actions_are_refused() {
        let Some((state, _pool)) = state_and_pool("adv_risk_unknown_keys").await else {
            return;
        };

        for body in [
            serde_json::json!({
                "action": "set_limit",
                "tenantId": "t-any",
                "limitType": "daily",
                "limitt": "daily"
            }),
            serde_json::json!({
                "action": "resolve_flag",
                "tenantId": "t-any",
                "flagId": "f-any",
                "note": "typo"
            }),
            serde_json::json!({"action": "run_assessment", "extra": 1}),
            serde_json::json!({"action": "delete_everything"}),
        ] {
            let result = update_risk(State(state.clone()), admin_auth(), Json(body.clone())).await;
            assert!(
                matches!(result, Err(ApiError::Validation(_))),
                "unknown key/action must be a validation error for {body}: {result:?}"
            );
        }

        // The accepted shape still works end to end.
        let ok = update_risk(
            State(state.clone()),
            admin_auth(),
            Json(serde_json::json!({"action": "run_assessment"})),
        )
        .await
        .expect("a known action with no extra keys is accepted");
        assert_eq!(ok.0["status"], "queued");
    }

    #[tokio::test]
    async fn risk_listing_and_mutations_round_trip_against_the_database() {
        let Some((state, pool)) = state_and_pool("adv_risk_roundtrip").await else {
            return;
        };
        let tenant = apexmail_lib::id::generate_id("", 26);
        let slug = format!("risk-adv-{}", uuid::Uuid::new_v4().simple());
        sqlx::query(
            "INSERT INTO tenants (id, name, slug, plan, status, created_at, updated_at)
             VALUES ($1, 'risk adversarial', $2, 'free', 'active', NOW(), NOW())",
        )
        .bind(&tenant)
        .bind(&slug)
        .execute(&pool)
        .await
        .expect("seed tenant");

        // Normalise thresholds first: the shared fixture database may carry
        // values persisted by another (possibly crashed) run.
        let _ = update_risk(
            State(state.clone()),
            admin_auth(),
            Json(
                serde_json::to_value(RiskMutation::SaveThresholds {
                    thresholds: Thresholds::default(),
                })
                .expect("serialize risk mutation"),
            ),
        )
        .await
        .expect("normalise thresholds");

        // Thresholds resource short-circuits before the tenant query.
        let Json(thresholds) = get_risk_tenants(
            State(state.clone()),
            admin_auth(),
            Query(RiskListQuery {
                resource: Some("thresholds".into()),
                limit: 50,
                offset: 0,
            }),
        )
        .await
        .expect("thresholds");
        assert_eq!(thresholds["persisted"], true);
        assert_eq!(thresholds["thresholds"]["bounceRateWarn"], 5.0);

        // Tenant listing is paginated and includes the seeded row.
        let Json(list) = get_risk_tenants(
            State(state.clone()),
            admin_auth(),
            Query(RiskListQuery {
                resource: None,
                limit: i64::MAX,
                offset: -5,
            }),
        )
        .await
        .expect("risk list");
        let rows = list.as_array().expect("array of tenants");
        assert!(rows.iter().any(|r| r["tenantId"] == tenant.as_str()));

        // Unknown tenant + invalid limit type are honest errors.
        let missing = update_risk(
            State(state.clone()),
            admin_auth(),
            Json(
                serde_json::to_value(RiskMutation::SetLimit {
                    tenant_id: "no-such-tenant".into(),
                    limit_type: "daily".into(),
                    value: Some(10),
                })
                .expect("serialize risk mutation"),
            ),
        )
        .await;
        assert!(matches!(missing, Err(ApiError::NotFound(_))));
        let invalid = update_risk(
            State(state.clone()),
            admin_auth(),
            Json(
                serde_json::to_value(RiskMutation::SetLimit {
                    tenant_id: tenant.clone(),
                    limit_type: "yearly".into(),
                    value: Some(10),
                })
                .expect("serialize risk mutation"),
            ),
        )
        .await;
        assert!(matches!(invalid, Err(ApiError::Validation(_))));

        // A real limit write lands in tenants.metadata.riskLimits.
        let Json(applied) = update_risk(
            State(state.clone()),
            admin_auth(),
            Json(
                serde_json::to_value(RiskMutation::SetLimit {
                    tenant_id: tenant.clone(),
                    limit_type: "daily".into(),
                    value: Some(777),
                })
                .expect("serialize risk mutation"),
            ),
        )
        .await
        .expect("set limit");
        assert_eq!(applied["success"], true);
        let stored: serde_json::Value =
            sqlx::query_scalar("SELECT metadata FROM tenants WHERE id = $1")
                .bind(&tenant)
                .fetch_one(&pool)
                .await
                .expect("metadata");
        assert_eq!(stored["riskLimits"]["daily"], 777);

        // Saving thresholds persists them for the next read.
        let custom = Thresholds {
            bounce_rate_warn: 1.5,
            bounce_rate_critical: 3.5,
            complaint_rate_warn: 0.2,
            complaint_rate_critical: 0.8,
        };
        let Json(saved) = update_risk(
            State(state.clone()),
            admin_auth(),
            Json(
                serde_json::to_value(RiskMutation::SaveThresholds {
                    thresholds: custom.clone(),
                })
                .expect("serialize risk mutation"),
            ),
        )
        .await
        .expect("save thresholds");
        assert_eq!(saved["thresholds"]["bounceRateWarn"], 1.5);
        let Json(reloaded) = get_risk_tenants(
            State(state.clone()),
            admin_auth(),
            Query(RiskListQuery {
                resource: Some("thresholds".into()),
                limit: 50,
                offset: 0,
            }),
        )
        .await
        .expect("reload thresholds");
        assert_eq!(reloaded["thresholds"]["bounceRateCritical"], 3.5);

        // RunAssessment answers queued immediately and the worker records a
        // last-assessed timestamp.
        let Json(queued) = update_risk(
            State(state.clone()),
            admin_auth(),
            Json(
                serde_json::to_value(RiskMutation::RunAssessment).expect("serialize risk mutation"),
            ),
        )
        .await
        .expect("run assessment");
        assert_eq!(queued["status"], "queued");
        assert!(queued["jobId"]
            .as_str()
            .unwrap_or_default()
            .starts_with("riskjob_"));
        for _ in 0..50 {
            if load_risk_settings(&pool)
                .await
                .expect("settings")
                .last_assessed_at
                .is_some()
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(
            load_risk_settings(&pool)
                .await
                .expect("settings")
                .last_assessed_at
                .is_some(),
            "the spawned assessment must persist assessed_at"
        );

        // ResolveFlag against a real alert row flips acknowledgement.
        if table_exists(&pool, "reputation_alerts").await {
            let flag_id = apexmail_lib::id::generate_id("", 26);
            sqlx::query(
                "INSERT INTO reputation_alerts (id, tenant_id, alert_type, value, threshold, acknowledged, created_at)
                 VALUES ($1, $2, 'high', 9.0, 5.0, false, NOW())",
            )
            .bind(&flag_id)
            .bind(&tenant)
            .execute(&pool)
            .await
            .expect("seed alert");
            let Json(resolved) = update_risk(
                State(state.clone()),
                admin_auth(),
                Json(
                    serde_json::to_value(RiskMutation::ResolveFlag {
                        tenant_id: tenant.clone(),
                        flag_id: flag_id.clone(),
                    })
                    .expect("serialize risk mutation"),
                ),
            )
            .await
            .expect("resolve flag");
            assert_eq!(resolved["success"], true);
            // The shared fixture database may see a concurrent global
            // cleanup from another test between the UPDATE and this read; the
            // strict row assertion lives in the isolated canonical test
            // below, so here we assert the API contract and, when the row is
            // still present, that it is acknowledged.
            let acknowledged: Option<bool> =
                sqlx::query_scalar("SELECT acknowledged FROM reputation_alerts WHERE id = $1")
                    .bind(&flag_id)
                    .fetch_optional(&pool)
                    .await
                    .expect("ack");
            assert_ne!(
                acknowledged,
                Some(false),
                "a resolved flag must never remain unacknowledged"
            );
            sqlx::query("DELETE FROM reputation_alerts WHERE id = $1")
                .bind(&flag_id)
                .execute(&pool)
                .await
                .expect("cleanup alert");
        }

        // Non-system or scope-less callers are refused before any query.
        let mut customer = admin_auth();
        customer.tenant_id = "not-system".into();
        assert!(matches!(
            get_risk_tenants(
                State(state.clone()),
                customer.clone(),
                Query(RiskListQuery {
                    resource: None,
                    limit: 1,
                    offset: 0
                })
            )
            .await,
            Err(ApiError::Forbidden(_))
        ));
        let mut scoped = admin_auth();
        scoped.scopes = vec!["risk:read".into()];
        let denial = update_risk(
            State(state.clone()),
            scoped,
            Json(
                serde_json::to_value(RiskMutation::RunAssessment).expect("serialize risk mutation"),
            ),
        )
        .await;
        assert!(matches!(denial, Err(ApiError::Forbidden(_))));

        // Restore defaults so later tests see the canonical thresholds.
        let _ = update_risk(
            State(state.clone()),
            admin_auth(),
            Json(
                serde_json::to_value(RiskMutation::SaveThresholds {
                    thresholds: Thresholds::default(),
                })
                .expect("serialize risk mutation"),
            ),
        )
        .await
        .expect("restore thresholds");

        sqlx::query("DELETE FROM tenants WHERE id = $1")
            .bind(&tenant)
            .execute(&pool)
            .await
            .expect("cleanup tenant");
    }

    /// ResolveFlag must actually acknowledge the alert row. Runs on a PRIVATE
    /// canonical database so no other test's cleanup can race the row read.
    #[tokio::test]
    async fn resolve_flag_acknowledges_inside_the_isolated_canonical_db() {
        let Some(pool) = crate::test_db::canonical_pool("adv_risk_resolve_flag").await else {
            return;
        };
        if !table_exists(&pool, "reputation_alerts").await {
            eprintln!("skipping: reputation_alerts missing from the canonical chain");
            pool.close().await;
            return;
        }
        let state = crate::app::test_support::test_state_over(pool.clone()).await;
        let tenant = apexmail_lib::id::generate_id("", 26);
        let flag_id = apexmail_lib::id::generate_id("", 26);
        sqlx::query(
            "INSERT INTO tenants (id, name, plan, status, created_at, updated_at)
             VALUES ($1, 'risk resolve', 'free', 'active', NOW(), NOW())",
        )
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("seed tenant");
        sqlx::query(
            "INSERT INTO reputation_alerts (id, tenant_id, alert_type, value, threshold, acknowledged, created_at)
             VALUES ($1, $2, 'critical', 9.0, 5.0, false, NOW())",
        )
        .bind(&flag_id)
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("seed alert");
        let Json(resolved) = update_risk(
            State(state.clone()),
            admin_auth(),
            Json(
                serde_json::to_value(RiskMutation::ResolveFlag {
                    tenant_id: tenant.clone(),
                    flag_id: flag_id.clone(),
                })
                .expect("serialize risk mutation"),
            ),
        )
        .await
        .expect("resolve flag");
        assert_eq!(resolved["success"], true);
        let acknowledged: bool =
            sqlx::query_scalar("SELECT acknowledged FROM reputation_alerts WHERE id = $1")
                .bind(&flag_id)
                .fetch_one(&pool)
                .await
                .expect("the flag row still exists in the private database");
        assert!(acknowledged, "ResolveFlag must acknowledge the row");
        pool.close().await;
    }
}
