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

/// MRR computed from `stripe_subscriptions` — the table the billing-service
/// webhook writers actually populate — mirroring the proven pattern in
/// billing-service `routes.rs` (`get_mrr_report`): joined via
/// `tenants.plan` to `plans` pricing, with yearly prices normalized to
/// monthly via `ROUND(price_yearly / 12.0)` (round-half-up, not truncation).
/// The legacy `subscriptions` table has no writer and always read as zero.
fn build_subscription_mrr_sql(has_billing_interval: bool) -> String {
    let billing_interval_expr = if has_billing_interval {
        "COALESCE(NULLIF(s.billing_interval, ''), 'monthly')"
    } else {
        "'monthly'"
    };

    format!(
        "SELECT COALESCE(SUM(
                CASE
                    WHEN {billing_interval_expr} IN ('year', 'yearly') THEN ROUND(p.price_yearly / 12.0)::bigint
                    ELSE p.price_monthly
                END
            ), 0)::bigint
         FROM stripe_subscriptions s
         JOIN tenants t ON t.id = s.tenant_id
         JOIN plans p ON p.name = t.plan
         WHERE s.status IN ('active', 'trialing', 'past_due')"
    )
}

async fn fetch_dashboard_mrr(db: &sqlx::PgPool) -> f64 {
    if !(table_exists(db, "stripe_subscriptions").await && table_exists(db, "plans").await) {
        return 0.0;
    }

    let has_billing_interval = column_exists(db, "stripe_subscriptions", "billing_interval").await;
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
    crate::middleware::auth::require_system_tenant(&state, &auth).await?;

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
    // Canonical sales campaign model. `drip_campaigns` was the control plane's
    // own execution path and was dropped in migration 200; counting it here
    // would silently report zero forever.
    let has_sales_campaigns = table_exists(db, "sales_campaigns").await;
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

    let campaigns_running = if has_sales_campaigns {
        fetch_count_or_zero(
            db,
            "SELECT COUNT(*)::bigint FROM sales_campaigns WHERE status = 'active'",
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

        // Reads the table billing actually writes, with proper yearly rounding.
        assert!(sql.contains("FROM stripe_subscriptions s"));
        assert!(sql.contains("JOIN tenants t ON t.id = s.tenant_id"));
        assert!(sql.contains("JOIN plans p ON p.name = t.plan"));
        assert!(sql.contains("ROUND(p.price_yearly / 12.0)::bigint"));
        assert!(sql.contains("billing_interval"));
        assert!(
            !sql.contains("FROM subscriptions"),
            "must not read the writerless legacy table"
        );
    }
}

// ─── Adversarial dashboard-stats tests ─────────────────────────

#[cfg(test)]
mod adversarial_tests {
    use super::*;

    fn admin_auth() -> AuthUser {
        AuthUser {
            tenant_id: "system".into(),
            user_id: None,
            api_key_id: Some("key_adversarial".into()),
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
    fn mrr_sql_normalizes_yearly_prices_with_rounding() {
        let sql = build_subscription_mrr_sql(true);
        assert!(sql.contains("ROUND(p.price_yearly / 12.0)::bigint"));
        assert!(sql.contains("COALESCE(NULLIF(s.billing_interval, ''), 'monthly')"));
        assert!(sql.contains("s.status IN ('active', 'trialing', 'past_due')"));
        // Without the column the expression degrades to the monthly price.
        let sql = build_subscription_mrr_sql(false);
        assert!(sql.contains("'monthly'"));
        assert!(!sql.contains("billing_interval"));
        assert!(sql.contains("ELSE p.price_monthly"));
    }

    #[tokio::test]
    async fn unreadable_count_queries_degrade_to_zero() {
        let Some((_state, pool)) = state_and_pool("adv_dashboard_zero").await else {
            return;
        };
        assert_eq!(
            fetch_count_or_zero(&pool, "SELECT COUNT(*)::bigint FROM no_such_table_adv").await,
            0
        );
        assert_eq!(
            fetch_count_or_zero(&pool, "this is not sql at all").await,
            0
        );
    }

    #[tokio::test]
    async fn stats_aggregate_seeded_platform_rows_and_are_gated() {
        let Some((state, pool)) = state_and_pool("adv_dashboard_stats").await else {
            return;
        };
        invalidate_dashboard_cache().await;

        let tag = uuid::Uuid::new_v4().simple().to_string();
        let plan_name = format!("adv-dash-plan-{tag}");
        let tenant = apexmail_lib::id::generate_id("", 26);
        sqlx::query(
            "INSERT INTO tenants (id, name, plan, status, created_at, updated_at)
             VALUES ($1, 'dash adversarial', $2, 'active', NOW(), NOW())",
        )
        .bind(&tenant)
        .bind(&plan_name)
        .execute(&pool)
        .await
        .expect("seed tenant");
        sqlx::query(
            "INSERT INTO plans (id, name, price_monthly, price_yearly, features)
             VALUES ($1, $2, 1500, 18000, '{}'::jsonb)",
        )
        .bind(apexmail_lib::id::generate_id("", 26))
        .bind(&plan_name)
        .execute(&pool)
        .await
        .expect("seed plan");
        sqlx::query(
            "INSERT INTO stripe_subscriptions (tenant_id, stripe_subscription_id, plan, status, billing_interval, created_at, updated_at)
             VALUES ($1, $2, $3, 'active', 'monthly', NOW(), NOW())",
        )
        .bind(&tenant)
        .bind(format!("sub_dash_{tag}"))
        .bind(&plan_name)
        .execute(&pool)
        .await
        .expect("seed subscription");
        sqlx::query(
            "INSERT INTO messages (tenant_id, from_email, to_emails, status, created_at, updated_at)
             VALUES ($1, 'a@example.com', '[\"b@example.com\"]'::jsonb, 'delivered', NOW(), NOW())",
        )
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("seed message");
        sqlx::query(
            "INSERT INTO system_alerts (alert_type, message, severity, acknowledged, tenant_id, created_at)
             VALUES ('adv', 'critical', 'critical', false, $1, NOW()),
                    ('adv', 'warning', 'warning', false, $1, NOW())",
        )
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("seed alerts");

        let Json(stats) = get_dashboard_stats(State(state.clone()), admin_auth())
            .await
            .expect("stats");
        assert!(stats.platform.active_tenants >= 1);
        assert!(stats.platform.total_emails >= 1);
        assert!(
            stats.platform.mrr >= 15.0,
            "seeded MRR included: {}",
            stats.platform.mrr
        );
        assert!(stats.compliance.risk_alerts >= 2);
        assert!(stats.compliance.critical_tenants >= 1);
        assert!(
            stats.platform.health_status == "healthy"
                || stats.platform.health_status == "degraded"
                || stats.platform.health_status == "down",
            "documented health vocabulary: {}",
            stats.platform.health_status
        );

        // A second call inside the TTL is served from the cache (same shape).
        let Json(cached) = get_dashboard_stats(State(state.clone()), admin_auth())
            .await
            .expect("cached stats");
        assert_eq!(
            cached.platform.active_tenants,
            stats.platform.active_tenants
        );

        // Gate: customer tenant and scope-less keys are refused.
        let mut customer = admin_auth();
        customer.tenant_id = tenant.clone();
        assert!(matches!(
            get_dashboard_stats(State(state.clone()), customer).await,
            Err(ApiError::Forbidden(_))
        ));
        let mut no_scope = admin_auth();
        no_scope.scopes = vec![];
        assert!(matches!(
            get_dashboard_stats(State(state.clone()), no_scope).await,
            Err(ApiError::Forbidden(_))
        ));

        sqlx::query("DELETE FROM system_alerts WHERE tenant_id = $1")
            .bind(&tenant)
            .execute(&pool)
            .await
            .expect("cleanup alerts");
        sqlx::query("DELETE FROM messages WHERE tenant_id = $1")
            .bind(&tenant)
            .execute(&pool)
            .await
            .expect("cleanup messages");
        sqlx::query("DELETE FROM stripe_subscriptions WHERE tenant_id = $1")
            .bind(&tenant)
            .execute(&pool)
            .await
            .expect("cleanup subs");
        sqlx::query("DELETE FROM plans WHERE name = $1")
            .bind(&plan_name)
            .execute(&pool)
            .await
            .expect("cleanup plan");
        sqlx::query("DELETE FROM tenants WHERE id = $1")
            .bind(&tenant)
            .execute(&pool)
            .await
            .expect("cleanup tenant");
        invalidate_dashboard_cache().await;
    }
}
