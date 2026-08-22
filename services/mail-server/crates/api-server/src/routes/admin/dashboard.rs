//! Dashboard stats endpoint.
//!

use super::super::helpers::{column_exists, table_exists};
use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;
use std::time::Instant;
use tokio::sync::Mutex;

use crate::error::ApiError;
use crate::middleware::auth::AuthUser;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/stats", get(get_dashboard_stats))
        // Realtime SSE streams for dashboard metrics and alerts. Mounted here
        // (rather than as a separate nest in app.rs) so they are reachable
        // through the single `/v1/admin/dashboard` nest.
        .nest("/sse", super::sse::router())
}

static CACHE: Mutex<Option<(Instant, DashboardStats)>> = Mutex::const_new(None);
const CACHE_TTL_SECS: u64 = 5;

pub(crate) async fn invalidate_dashboard_cache() {
    let mut guard = CACHE.lock().await;
    *guard = None;
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SalesStats {
    pub active_leads: i64,
    pub leads_this_week: i64,
    pub campaigns_running: i64,
    pub demos_scheduled: i64,
    pub conversion_rate: f64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceStats {
    pub risk_alerts: i64,
    pub critical_tenants: i64,
    pub gdpr_pending: i64,
    pub audit_events_today: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlatformStats {
    pub active_tenants: i64,
    pub total_emails: i64,
    pub mrr: f64,
    pub health_status: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ActivityEntry {
    pub id: String,
    #[serde(rename = "type")]
    pub entry_type: String,
    pub message: String,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PipelineStats {
    pub prospect: i64,
    pub outreach: i64,
    pub engaged: i64,
    pub demo: i64,
    pub closed: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DashboardStats {
    pub sales: SalesStats,
    pub compliance: ComplianceStats,
    pub platform: PlatformStats,
    pub recent_activity: Vec<ActivityEntry>,
    pub pipeline: PipelineStats,
}

async fn fetch_count_or_zero(db: &sqlx::PgPool, sql: &str) -> i64 {
    sqlx::query_scalar::<_, i64>(sql)
        .fetch_one(db)
        .await
        .unwrap_or(0)
}

fn build_subscription_mrr_sql(has_billing_interval: bool) -> String {
    let billing_interval_expr = if has_billing_interval {
        "COALESCE(NULLIF(s.billing_interval, ''), 'monthly')"
    } else {
        "'monthly'"
    };

    format!(
        "SELECT COALESCE(SUM(
                CASE
                    WHEN {billing_interval_expr} IN ('year', 'yearly') THEN COALESCE(p.price_yearly, 0) / 12
                    ELSE COALESCE(p.price_monthly, 0)
                END
            ), 0)::bigint
         FROM subscriptions s
         LEFT JOIN plans p ON p.name = s.plan_name
         WHERE s.status IN ('active', 'trialing', 'past_due')"
    )
}

async fn fetch_dashboard_mrr(db: &sqlx::PgPool) -> f64 {
    if !(table_exists(db, "subscriptions").await && table_exists(db, "plans").await) {
        return 0.0;
    }

    let has_billing_interval = column_exists(db, "subscriptions", "billing_interval").await;
    let sql = build_subscription_mrr_sql(has_billing_interval);

    sqlx::query_scalar::<_, i64>(&sql)
        .fetch_one(db)
        .await
        .map(|cents| cents as f64 / 100.0)
        .unwrap_or(0.0)
}

async fn get_dashboard_stats(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<DashboardStats>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;
    crate::middleware::auth::require_system_tenant(&auth)?;

    // Check cache
    {
        let guard = CACHE.lock().await;
        if let Some((ts, ref cached)) = *guard {
            if ts.elapsed().as_secs() < CACHE_TTL_SECS {
                return Ok(Json(cached.clone()));
            }
        }
        drop(guard);
    }

    let db = &state.db;

    let has_sales_leads = table_exists(db, "sales_leads").await;
    let has_drip_campaigns = table_exists(db, "drip_campaigns").await;
    let has_gdpr_requests = table_exists(db, "gdpr_requests").await;
    let has_system_alerts = table_exists(db, "system_alerts").await;

    // Aggregate counts
    let active_leads = if has_sales_leads {
        fetch_count_or_zero(
            db,
            "SELECT COUNT(*)::bigint FROM sales_leads WHERE status NOT IN ('converted', 'lost', 'unqualified')",
        )
        .await
    } else {
        0
    };

    let leads_this_week = if has_sales_leads {
        fetch_count_or_zero(
            db,
            "SELECT COUNT(*)::bigint FROM sales_leads WHERE created_at >= NOW() - INTERVAL '7 days'",
        )
        .await
    } else {
        0
    };

    let campaigns_running = if has_drip_campaigns {
        fetch_count_or_zero(
            db,
            "SELECT COUNT(*)::bigint FROM drip_campaigns WHERE status = 'active'",
        )
        .await
    } else {
        0
    };

    let demos_scheduled = if has_sales_leads {
        fetch_count_or_zero(
            db,
            "SELECT COUNT(*)::bigint FROM sales_leads WHERE status IN ('demo_scheduled', 'demo_booked', 'demo')",
        )
        .await
    } else {
        0
    };

    let conversion_rate: f64 = if has_sales_leads {
        sqlx::query_scalar::<_, f64>(
            "SELECT COALESCE(
                COUNT(*) FILTER (WHERE status = 'converted')::double precision /
                NULLIF(COUNT(*) FILTER (WHERE status IN ('contacted', 'qualified', 'converted')), 0)::double precision,
                0.0
             )
             FROM sales_leads",
        )
        .fetch_one(db)
        .await
        .unwrap_or(0.0)
    } else {
        0.0
    };

    let audit_events_today = fetch_count_or_zero(
        db,
        "SELECT COUNT(*)::bigint FROM audit_logs WHERE timestamp >= CURRENT_DATE",
    )
    .await;

    let active_tenants = fetch_count_or_zero(
        db,
        "SELECT COUNT(*)::bigint FROM tenants WHERE status = 'active'",
    )
    .await;

    let total_emails = fetch_count_or_zero(
        db,
        "SELECT COUNT(*)::bigint FROM messages WHERE status IN ('sent', 'delivered')",
    )
    .await;

    let mrr = fetch_dashboard_mrr(db).await;

    // Risk / health
    let (mut risk_alerts, mut critical_tenants) = (0i64, 0i64);
    let mut critical_alert_count = 0i64;
    let mut warning_alert_count = 0i64;

    if has_system_alerts {
        let rows: Vec<(String, i64)> = sqlx::query_as(
            "SELECT severity, COUNT(*)::bigint
             FROM system_alerts
             WHERE acknowledged = false AND severity IN ('warning', 'critical')
             GROUP BY severity",
        )
        .fetch_all(db)
        .await?;

        for (severity, count) in &rows {
            risk_alerts += count;
            if severity == "critical" {
                critical_alert_count += count;
                critical_tenants += count;
            } else if severity == "warning" {
                warning_alert_count += count;
            }
        }
    }

    let health_status = if critical_alert_count >= 5 {
        "down"
    } else if critical_alert_count > 0 || warning_alert_count > 0 {
        "degraded"
    } else {
        "healthy"
    };

    let gdpr_pending = if has_gdpr_requests {
        fetch_count_or_zero(
            db,
            "SELECT COUNT(*)::bigint FROM gdpr_requests WHERE status = 'pending'",
        )
        .await
    } else {
        0
    };

    // Pipeline
    let mut pipeline = PipelineStats {
        prospect: 0,
        outreach: 0,
        engaged: 0,
        demo: 0,
        closed: 0,
    };

    if has_sales_leads {
        let rows: Vec<(String, i64)> =
            sqlx::query_as("SELECT status, COUNT(*)::bigint FROM sales_leads GROUP BY status")
                .fetch_all(db)
                .await?;

        for (status, count) in &rows {
            match status.as_str() {
                "new" | "prospect" | "identified" => pipeline.prospect += count,
                "contacted" | "outreach" | "attempted" => pipeline.outreach += count,
                "engaged" | "qualified" | "responded" => pipeline.engaged += count,
                "demo_scheduled" | "demo_booked" | "demo" => pipeline.demo += count,
                "converted" | "closed_won" => pipeline.closed += count,
                _ => {}
            }
        }
    }

    // Recent activity (simple — latest leads)
    let mut recent_activity: Vec<ActivityEntry> = Vec::new();

    if has_sales_leads {
        let leads: Vec<(String, String, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(
            "SELECT id, company_name, created_at FROM sales_leads ORDER BY created_at DESC LIMIT 5",
        )
        .fetch_all(db)
        .await?;

        for (id, name, ts) in leads {
            recent_activity.push(ActivityEntry {
                id,
                entry_type: "lead".into(),
                message: format!("New lead: {name}"),
                timestamp: ts.to_rfc3339(),
            });
        }
    }

    recent_activity.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
    recent_activity.truncate(10);

    let stats = DashboardStats {
        sales: SalesStats {
            active_leads,
            leads_this_week,
            campaigns_running,
            demos_scheduled,
            conversion_rate,
        },
        compliance: ComplianceStats {
            risk_alerts,
            critical_tenants,
            gdpr_pending,
            audit_events_today,
        },
        platform: PlatformStats {
            active_tenants,
            total_emails,
            mrr,
            health_status: health_status.into(),
        },
        recent_activity,
        pipeline,
    };

    // Update cache
    let mut guard = CACHE.lock().await;
    *guard = Some((Instant::now(), stats.clone()));
    drop(guard);

    Ok(Json(stats))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_stats() -> DashboardStats {
        DashboardStats {
            sales: SalesStats {
                active_leads: 1,
                leads_this_week: 1,
                campaigns_running: 1,
                demos_scheduled: 1,
                conversion_rate: 0.5,
            },
            compliance: ComplianceStats {
                risk_alerts: 1,
                critical_tenants: 1,
                gdpr_pending: 1,
                audit_events_today: 1,
            },
            platform: PlatformStats {
                active_tenants: 1,
                total_emails: 1,
                mrr: 1.0,
                health_status: "healthy".into(),
            },
            recent_activity: Vec::new(),
            pipeline: PipelineStats {
                prospect: 1,
                outreach: 1,
                engaged: 1,
                demo: 1,
                closed: 1,
            },
        }
    }

    #[tokio::test]
    async fn invalidate_dashboard_cache_clears_cached_value() {
        {
            let mut guard = CACHE.lock().await;
            *guard = Some((Instant::now(), sample_stats()));
        }

        invalidate_dashboard_cache().await;

        let guard = CACHE.lock().await;
        assert!(guard.is_none());
    }

    #[test]
    fn dashboard_cache_ttl_stays_short() {
        assert_eq!(CACHE_TTL_SECS, 5);
    }

    #[test]
    fn dashboard_subscription_mrr_sql_uses_plan_prices() {
        let sql = build_subscription_mrr_sql(true);

        assert!(sql.contains("FROM subscriptions s"));
        assert!(sql.contains("LEFT JOIN plans p"));
        assert!(sql.contains("price_yearly"));
        assert!(sql.contains("billing_interval"));
    }
}
