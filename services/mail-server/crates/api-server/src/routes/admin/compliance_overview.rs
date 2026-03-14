//! Compliance overview endpoint.
//!
//! Migrated from: apps/control-plane/src/app/api/compliance/overview/route.ts

use super::super::helpers::table_exists;
use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;

use crate::error::ApiError;
use crate::middleware::auth::AuthUser;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/", get(get_compliance_overview))
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RiskSummary {
    pub low: i64,
    pub medium: i64,
    pub high: i64,
    pub critical: i64,
}

#[derive(Debug, Serialize)]
pub struct GdprRequestSummary {
    pub pending: i64,
    pub processing: i64,
    pub completed: i64,
    pub overdue: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditStats {
    pub today_events: i64,
    pub week_events: i64,
    pub alerts_triggered: i64,
}

#[derive(Debug, Serialize)]
pub struct PolicyCompliance {
    pub name: String,
    pub compliant: i64,
    pub total: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AlertEntry {
    pub id: String,
    #[serde(rename = "type")]
    pub alert_type: String,
    pub message: String,
    pub severity: String,
    pub tenant_id: Option<String>,
    pub timestamp: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceOverview {
    pub risk_summary: RiskSummary,
    pub gdpr_requests: GdprRequestSummary,
    pub audit_stats: AuditStats,
    pub policy_compliance: Vec<PolicyCompliance>,
    pub recent_alerts: Vec<AlertEntry>,
}

async fn get_compliance_overview(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<ComplianceOverview>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    let db = &state.db;

    let has_gdpr = table_exists(db, "gdpr_requests").await;
    let has_alerts = table_exists(db, "system_alerts").await;
    let has_domains = table_exists(db, "domains").await;

    // Risk summary
    let mut risk_summary = RiskSummary { low: 0, medium: 0, high: 0, critical: 0 };
    if has_alerts {
        let rows: Vec<(String, String)> = sqlx::query_as(
            "SELECT CASE
                WHEN severity = 'critical' THEN 'critical'
                WHEN severity = 'high' THEN 'high'
                WHEN severity = 'medium' THEN 'medium'
                ELSE 'low'
             END as risk_level,
             COUNT(*)::text
             FROM system_alerts WHERE acknowledged = false
             GROUP BY risk_level",
        )
        .fetch_all(db)
        .await
        ?;

        for (level, count_str) in &rows {
            let count: i64 = count_str.parse().unwrap_or(0);
            match level.as_str() {
                "low" => risk_summary.low = count,
                "medium" => risk_summary.medium = count,
                "high" => risk_summary.high = count,
                "critical" => risk_summary.critical = count,
                _ => {}
            }
        }
    }

    // GDPR requests summary
    let mut gdpr_requests = GdprRequestSummary { pending: 0, processing: 0, completed: 0, overdue: 0 };
    if has_gdpr {
        let rows: Vec<(String, String)> = sqlx::query_as(
            "SELECT status, COUNT(*)::text FROM gdpr_requests GROUP BY status",
        )
        .fetch_all(db)
        .await
        ?;

        for (status, count_str) in &rows {
            let count: i64 = count_str.parse().unwrap_or(0);
            match status.as_str() {
                "pending" => gdpr_requests.pending = count,
                "processing" => gdpr_requests.processing = count,
                "completed" => gdpr_requests.completed = count,
                "overdue" => gdpr_requests.overdue = count,
                _ => {}
            }
        }
    }

    // Audit stats
    let audit_row: (String, String) = sqlx::query_as(
        "SELECT COUNT(*) FILTER (WHERE timestamp >= CURRENT_DATE)::text,
                COUNT(*) FILTER (WHERE timestamp >= NOW() - INTERVAL '7 days')::text
         FROM audit_logs",
    )
    .fetch_one(db)
    .await
    .unwrap_or(("0".into(), "0".into()));

    let alerts_triggered = if has_alerts {
        sqlx::query_scalar::<_, String>(
            "SELECT COUNT(*)::text FROM system_alerts WHERE created_at >= NOW() - INTERVAL '24 hours' AND severity IN ('high', 'critical')",
        )
        .fetch_one(db)
        .await
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0i64)
    } else { 0 };

    let audit_stats = AuditStats {
        today_events: audit_row.0.parse().unwrap_or(0),
        week_events: audit_row.1.parse().unwrap_or(0),
        alerts_triggered,
    };

    // Policy compliance (domains)
    let policy_compliance = if has_domains {
        let row: Option<(String, String, String, String, String)> = sqlx::query_as(
            "SELECT COUNT(*)::text,
                    COUNT(*) FILTER (WHERE spf_configured = true)::text,
                    COUNT(*) FILTER (WHERE dkim_selector IS NOT NULL AND dkim_selector <> '')::text,
                    COUNT(*) FILTER (WHERE dmarc_configured = true)::text,
                    COUNT(*) FILTER (WHERE is_verified = true)::text
             FROM domains",
        )
        .fetch_optional(db)
        .await?;

        if let Some((total_str, spf, dkim, dmarc, verified)) = row {
            let total: i64 = total_str.parse().unwrap_or(0);
            vec![
                PolicyCompliance { name: "SPF Records".into(), compliant: spf.parse().unwrap_or(0), total },
                PolicyCompliance { name: "DKIM Signing".into(), compliant: dkim.parse().unwrap_or(0), total },
                PolicyCompliance { name: "DMARC Policy".into(), compliant: dmarc.parse().unwrap_or(0), total },
                PolicyCompliance { name: "Domain Verification".into(), compliant: verified.parse().unwrap_or(0), total },
            ]
        } else {
            vec![]
        }
    } else {
        vec![]
    };

    // Recent alerts
    let recent_alerts = if has_alerts {
        let rows: Vec<(String, String, Option<String>, String, Option<serde_json::Value>, chrono::DateTime<chrono::Utc>)> =
            sqlx::query_as(
                "SELECT id, alert_type, message, severity, metadata, created_at
                 FROM system_alerts ORDER BY created_at DESC LIMIT 10",
            )
            .fetch_all(db)
            .await
            ?;

        rows.into_iter()
            .map(|(id, alert_type, message, severity, metadata, created_at)| {
                let tenant_id = metadata
                    .as_ref()
                    .and_then(|m| m.get("tenantId"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                AlertEntry {
                    id,
                    alert_type,
                    message: message.unwrap_or_default(),
                    severity,
                    tenant_id,
                    timestamp: created_at.to_rfc3339(),
                }
            })
            .collect()
    } else {
        vec![]
    };

    Ok(Json(ComplianceOverview {
        risk_summary,
        gdpr_requests,
        audit_stats,
        policy_compliance,
        recent_alerts,
    }))
}
