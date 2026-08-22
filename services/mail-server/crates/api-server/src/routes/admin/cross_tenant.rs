//! Cross-tenant analytics aggregation endpoints.
//!
//! Platform-wide analytics computed from database queries across all tenants.
//! All values come from real PostgreSQL queries with zero hardcoded data.
//!
//! - `GET /v1/admin/cross-tenant/health` — platform-wide health score with bottom 5 tenants
//! - `GET /v1/admin/cross-tenant/plans` — plan distribution, revenue, velocity, lifetime
//! - `GET /v1/admin/cross-tenant/growth` — aggregate growth metrics across all tenants

use std::collections::HashMap;

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use chrono::{DateTime, Duration, Utc};
use serde::Serialize;

use crate::error::ApiError;
use crate::middleware::auth::{require_scopes, AuthUser};
use crate::routes::helpers::{column_exists, table_exists};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/health", get(get_cross_tenant_health))
        .route("/plans", get(get_cross_tenant_plans))
        .route("/growth", get(get_cross_tenant_growth))
}

// ── Health ─────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CrossTenantHealthResponse {
    pub platform_health_score: f64,
    pub total_tenants: i64,
    pub overall_delivery_rate: f64,
    pub total_emails_sent: i64,
    pub total_emails_delivered: i64,
    pub total_bounces: i64,
    pub bottom_5_tenants: Vec<TenantHealthScore>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantHealthScore {
    pub tenant_id: String,
    pub emails_sent: i64,
    pub emails_delivered: i64,
    pub delivery_rate: f64,
    pub bounce_count: i64,
    pub bounce_rate: f64,
}

async fn get_cross_tenant_health(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<CrossTenantHealthResponse>, ApiError> {
    require_scopes(&auth, &["*"])?;

    let db = &state.db;
    let cutoff = Utc::now() - Duration::days(30);

    let total_tenants: i64 =
        sqlx::query_scalar("SELECT COUNT(*)::bigint FROM tenants WHERE status = 'active'")
            .fetch_one(db)
            .await
            .unwrap_or(0);

    let has_messages = table_exists(db, "messages").await;
    let has_events = table_exists(db, "events").await;
    let has_tenants_table = table_exists(db, "tenants").await;

    let (total_emails_sent, total_emails_delivered, total_bounces) = if has_messages {
        let sent = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*)::bigint FROM messages WHERE created_at >= $1",
        )
        .bind(cutoff)
        .fetch_one(db)
        .await
        .unwrap_or(0);

        let delivered = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*)::bigint FROM messages WHERE status = 'delivered' AND created_at >= $1",
        )
        .bind(cutoff)
        .fetch_one(db)
        .await
        .unwrap_or(0);

        let bounces = if has_events {
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*)::bigint FROM events WHERE event_type IN ('bounce', 'bounced', 'hard_bounce', 'soft_bounce') AND timestamp >= $1",
            )
            .bind(cutoff)
            .fetch_one(db)
            .await
            .unwrap_or(0)
        } else {
            0
        };

        (sent, delivered, bounces)
    } else {
        (0, 0, 0)
    };

    let overall_delivery_rate = if total_emails_sent > 0 {
        total_emails_delivered as f64 / total_emails_sent as f64
    } else {
        0.0
    };

    let bottom_5_tenants = if has_messages && has_tenants_table {
        let rows: Vec<(String, i64, i64)> = sqlx::query_as(
            "SELECT m.tenant_id::text,
                    COUNT(*)::bigint as sent,
                    COUNT(*) FILTER (WHERE m.status = 'delivered')::bigint as delivered
             FROM messages m
             JOIN tenants t ON t.id::text = m.tenant_id::text
             WHERE m.created_at >= $1
             GROUP BY m.tenant_id
             HAVING COUNT(*)::bigint > 0
             ORDER BY CASE WHEN COUNT(*)::bigint > 0
                 THEN COUNT(*) FILTER (WHERE m.status = 'delivered')::float8 / COUNT(*)::float8
                 ELSE 1.0 END ASC
             LIMIT 5",
        )
        .bind(cutoff)
        .fetch_all(db)
        .await
        .unwrap_or_default();

        let bounce_data: HashMap<String, i64> = if has_events {
            sqlx::query_as::<_, (String, i64)>(
                "SELECT tenant_id::text, COUNT(*)::bigint
                 FROM events
                 WHERE event_type IN ('bounce', 'bounced', 'hard_bounce', 'soft_bounce')
                   AND timestamp >= $1
                 GROUP BY tenant_id",
            )
            .bind(cutoff)
            .fetch_all(db)
            .await
            .unwrap_or_default()
            .into_iter()
            .collect()
        } else {
            HashMap::new()
        };

        rows.into_iter()
            .map(|(tenant_id, sent, delivered)| {
                let bounce_count = bounce_data.get(&tenant_id).copied().unwrap_or(0);
                let delivery_rate = if sent > 0 {
                    delivered as f64 / sent as f64
                } else {
                    0.0
                };
                let bounce_rate = if sent > 0 {
                    bounce_count as f64 / sent as f64
                } else {
                    0.0
                };

                TenantHealthScore {
                    tenant_id,
                    emails_sent: sent,
                    emails_delivered: delivered,
                    delivery_rate,
                    bounce_count,
                    bounce_rate,
                }
            })
            .collect()
    } else {
        Vec::new()
    };

    let platform_health_score = if total_emails_sent > 0 {
        let bounce_rate = total_bounces as f64 / total_emails_sent as f64;
        let weighted_delivery = overall_delivery_rate * 0.7;
        let bounce_penalty = (1.0 - bounce_rate.min(1.0)) * 0.3;
        (weighted_delivery + bounce_penalty) * 100.0
    } else {
        0.0
    };

    Ok(Json(CrossTenantHealthResponse {
        platform_health_score: (platform_health_score * 100.0).round() / 100.0,
        total_tenants,
        overall_delivery_rate,
        total_emails_sent,
        total_emails_delivered,
        total_bounces,
        bottom_5_tenants,
    }))
}

// ── Plans ──────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CrossTenantPlansResponse {
    pub plans: Vec<PlanBreakdown>,
    pub total_revenue: f64,
    pub total_tenants: i64,
    /// Plan-change upgrade count. Omitted (not zero): the `plan.changed`
    /// audit action these were derived from is never emitted by any writer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upgrade_count_30d: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub downgrade_count_30d: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub velocity: Option<f64>,
    pub avg_tenant_lifetime_days: f64,
    /// Honest data-omission notes surfaced to the caller.
    pub notes: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlanBreakdown {
    pub plan: String,
    pub tenant_count: i64,
    pub active_subscriptions: i64,
    pub monthly_revenue: f64,
    pub revenue_share: f64,
    pub avg_lifetime_days: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upgrades_30d: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub downgrades_30d: Option<i64>,
}

fn monthly_revenue_cents(
    billing_interval: Option<&str>,
    price_monthly: i64,
    price_yearly: i64,
) -> i64 {
    match billing_interval {
        // Round-half-up yearly normalization, mirroring billing-service's
        // yearly_price_to_monthly_mrr (no truncation).
        Some(interval)
            if interval.eq_ignore_ascii_case("yearly") || interval.eq_ignore_ascii_case("year") =>
        {
            (price_yearly + 6) / 12
        }
        _ => price_monthly,
    }
}

fn cents_to_dollars(cents: i64) -> f64 {
    cents as f64 / 100.0
}

async fn get_cross_tenant_plans(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<CrossTenantPlansResponse>, ApiError> {
    require_scopes(&auth, &["*"])?;

    let db = &state.db;

    let has_tenants = table_exists(db, "tenants").await;
    let has_subs = table_exists(db, "stripe_subscriptions").await;
    let has_plans = table_exists(db, "plans").await;

    let plan_tenant_counts: HashMap<String, i64> = if has_tenants {
        sqlx::query_as::<_, (String, i64)>(
            "SELECT COALESCE(NULLIF(plan, ''), 'free') as plan, COUNT(*)::bigint as tenants
             FROM tenants GROUP BY 1",
        )
        .fetch_all(db)
        .await
        .unwrap_or_default()
        .into_iter()
        .collect()
    } else {
        HashMap::new()
    };

    #[derive(Debug, sqlx::FromRow)]
    struct SubRow {
        plan_name: String,
        status: String,
        billing_interval: Option<String>,
        price_monthly: i64,
        price_yearly: i64,
        created_at: DateTime<Utc>,
    }

    // Subscriptions are read from stripe_subscriptions (the table billing
    // webhooks write), joined via tenants.plan to plans pricing — mirroring
    // billing-service's get_mrr_report pattern with proper yearly rounding.
    let subscriptions = if has_subs && has_plans {
        let has_billing_interval =
            column_exists(db, "stripe_subscriptions", "billing_interval").await;
        let billing_col = if has_billing_interval {
            "COALESCE(NULLIF(s.billing_interval, ''), 'monthly')"
        } else {
            "'monthly'"
        };

        let has_price_monthly = column_exists(db, "plans", "price_monthly").await;
        let has_price_yearly = column_exists(db, "plans", "price_yearly").await;
        let price_monthly_col = if has_price_monthly {
            "COALESCE(p.price_monthly, 0)"
        } else {
            "0"
        };
        let price_yearly_col = if has_price_yearly {
            "COALESCE(p.price_yearly, 0)"
        } else {
            "0"
        };

        let sql = format!(
            "SELECT COALESCE(NULLIF(s.plan, ''), NULLIF(t.plan, ''), 'free') as plan_name,
                    s.status,
                    {billing_col} as billing_interval,
                    {price_monthly_col} as price_monthly,
                    {price_yearly_col} as price_yearly,
                    s.created_at
             FROM stripe_subscriptions s
             JOIN tenants t ON t.id = s.tenant_id
             LEFT JOIN plans p ON p.name = t.plan"
        );

        sqlx::query_as::<_, SubRow>(&sql)
            .fetch_all(db)
            .await
            .unwrap_or_default()
    } else {
        Vec::new()
    };

    // Plan-change velocity is omitted with an honest note: the `plan.changed`
    // audit action it was derived from is never emitted by any writer, and
    // stripe_webhook_events stores only event ids/types (no plan payload).
    let notes: Vec<String> = vec![
        "plan-change velocity (upgrades, downgrades, velocity) omitted: no writer \
         records plan-change history"
            .into(),
    ];

    let mut plan_revenue: HashMap<String, i64> = HashMap::new();
    let mut plan_active_subs: HashMap<String, i64> = HashMap::new();
    let mut plan_lifetime_days: HashMap<String, Vec<f64>> = HashMap::new();

    for sub in &subscriptions {
        let plan = &sub.plan_name;
        let is_active = matches!(sub.status.as_str(), "active" | "trialing" | "past_due");
        if is_active {
            let rev = monthly_revenue_cents(
                sub.billing_interval.as_deref(),
                sub.price_monthly,
                sub.price_yearly,
            );
            *plan_revenue.entry(plan.clone()).or_default() += rev;
            *plan_active_subs.entry(plan.clone()).or_default() += 1;
        }

        let lifetime = (Utc::now() - sub.created_at).num_hours() as f64 / 24.0;
        if lifetime > 0.0 {
            plan_lifetime_days
                .entry(plan.clone())
                .or_default()
                .push(lifetime);
        }
    }

    let total_revenue_cents: i64 = plan_revenue.values().sum();
    let total_tenants_count: i64 = plan_tenant_counts.values().sum();

    let mut all_plans: Vec<String> = plan_tenant_counts.keys().cloned().collect();
    for plan in plan_revenue.keys() {
        if !all_plans.contains(plan) {
            all_plans.push(plan.clone());
        }
    }
    for plan in plan_active_subs.keys() {
        if !all_plans.contains(plan) {
            all_plans.push(plan.clone());
        }
    }

    let total_lifetimes: Vec<f64> = plan_lifetime_days.values().flatten().copied().collect();
    let avg_tenant_lifetime_days = if total_lifetimes.is_empty() {
        0.0
    } else {
        total_lifetimes.iter().sum::<f64>() / total_lifetimes.len() as f64
    };

    let mut plans: Vec<PlanBreakdown> = all_plans
        .into_iter()
        .map(|plan| {
            let tenant_count = plan_tenant_counts.get(&plan).copied().unwrap_or(0);
            let active_subs = plan_active_subs.get(&plan).copied().unwrap_or(0);
            let rev_cents = plan_revenue.get(&plan).copied().unwrap_or(0);
            let monthly_revenue = cents_to_dollars(rev_cents);
            let revenue_share = if total_revenue_cents > 0 {
                rev_cents as f64 / total_revenue_cents as f64
            } else {
                0.0
            };
            let lifetimes = plan_lifetime_days.get(&plan);
            let avg_lifetime = match lifetimes {
                Some(vals) if !vals.is_empty() => vals.iter().sum::<f64>() / vals.len() as f64,
                _ => 0.0,
            };

            PlanBreakdown {
                plan,
                tenant_count,
                active_subscriptions: active_subs,
                monthly_revenue,
                revenue_share,
                avg_lifetime_days: avg_lifetime,
                // No plan-change history source exists (see note).
                upgrades_30d: None,
                downgrades_30d: None,
            }
        })
        .collect();

    plans.sort_by(|a, b| {
        b.monthly_revenue
            .partial_cmp(&a.monthly_revenue)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.plan.cmp(&b.plan))
    });

    Ok(Json(CrossTenantPlansResponse {
        plans,
        total_revenue: cents_to_dollars(total_revenue_cents),
        total_tenants: total_tenants_count,
        upgrade_count_30d: None,
        downgrade_count_30d: None,
        velocity: None,
        avg_tenant_lifetime_days,
        notes,
    }))
}

// ── Growth ─────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CrossTenantGrowthResponse {
    pub total_emails_sent_daily: i64,
    pub total_emails_sent_weekly: i64,
    pub total_emails_sent_monthly: i64,
    pub new_tenant_signups_daily: i64,
    pub new_tenant_signups_weekly: i64,
    pub new_tenant_signups_monthly: i64,
    pub total_active_tenants: i64,
    pub platform_revenue_growth_rate: f64,
    pub churn_rate: f64,
    pub churned_tenants_count_30d: i64,
    pub emails_timeline_daily: Vec<EmailsTimelinePoint>,
    pub signups_timeline_daily: Vec<SignupsTimelinePoint>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EmailsTimelinePoint {
    pub date: String,
    pub count: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignupsTimelinePoint {
    pub date: String,
    pub count: i64,
}

async fn get_cross_tenant_growth(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<CrossTenantGrowthResponse>, ApiError> {
    require_scopes(&auth, &["*"])?;

    let db = &state.db;
    let now = Utc::now();
    let cutoff_30 = now - Duration::days(30);

    let has_messages = table_exists(db, "messages").await;
    let has_tenants = table_exists(db, "tenants").await;
    let has_subs = table_exists(db, "stripe_subscriptions").await;
    let has_plans = table_exists(db, "plans").await;

    let total_emails_daily = if has_messages {
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*)::bigint FROM messages WHERE created_at >= CURRENT_DATE",
        )
        .fetch_one(db)
        .await
        .unwrap_or(0)
    } else {
        0
    };

    let total_emails_weekly = if has_messages {
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*)::bigint FROM messages WHERE created_at >= NOW() - INTERVAL '7 days'",
        )
        .fetch_one(db)
        .await
        .unwrap_or(0)
    } else {
        0
    };

    let total_emails_monthly = if has_messages {
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*)::bigint FROM messages WHERE created_at >= NOW() - INTERVAL '30 days'",
        )
        .fetch_one(db)
        .await
        .unwrap_or(0)
    } else {
        0
    };

    let new_signups_daily = if has_tenants {
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*)::bigint FROM tenants WHERE created_at >= CURRENT_DATE",
        )
        .fetch_one(db)
        .await
        .unwrap_or(0)
    } else {
        0
    };

    let new_signups_weekly = if has_tenants {
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*)::bigint FROM tenants WHERE created_at >= NOW() - INTERVAL '7 days'",
        )
        .fetch_one(db)
        .await
        .unwrap_or(0)
    } else {
        0
    };

    let new_signups_monthly = if has_tenants {
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*)::bigint FROM tenants WHERE created_at >= NOW() - INTERVAL '30 days'",
        )
        .fetch_one(db)
        .await
        .unwrap_or(0)
    } else {
        0
    };

    let total_active_tenants = if has_tenants {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*)::bigint FROM tenants WHERE status = 'active'")
            .fetch_one(db)
            .await
            .unwrap_or(0)
    } else {
        0
    };

    let churned_30d = if has_tenants {
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*)::bigint FROM tenants
             WHERE status != 'active'
               AND updated_at >= $1",
        )
        .bind(cutoff_30)
        .fetch_one(db)
        .await
        .unwrap_or(0)
    } else if has_subs {
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*)::bigint FROM stripe_subscriptions
             WHERE status = 'canceled'
               AND COALESCE(canceled_at, updated_at) >= $1",
        )
        .bind(cutoff_30)
        .fetch_one(db)
        .await
        .unwrap_or(0)
    } else {
        0
    };

    let churn_rate = if total_active_tenants > 0 {
        churned_30d as f64 / total_active_tenants as f64
    } else {
        0.0
    };

    let platform_revenue_growth_rate = if has_subs && has_plans {
        // MRR growth from stripe_subscriptions (billing's writer table),
        // mirroring billing-service's get_mrr_report pattern.
        let has_billing_interval =
            column_exists(db, "stripe_subscriptions", "billing_interval").await;
        let billing_expr = if has_billing_interval {
            "COALESCE(NULLIF(s.billing_interval, ''), 'monthly')"
        } else {
            "'monthly'"
        };

        let sql_current = format!(
            "SELECT COALESCE(SUM(
                    CASE
                        WHEN {billing_expr} IN ('year', 'yearly') THEN ROUND(p.price_yearly / 12.0)::bigint
                        ELSE p.price_monthly
                    END
                ), 0)::bigint
             FROM stripe_subscriptions s
             JOIN tenants t ON t.id = s.tenant_id
             JOIN plans p ON p.name = t.plan
             WHERE s.status IN ('active', 'trialing', 'past_due')"
        );

        let sql_previous = format!(
            "SELECT COALESCE(SUM(
                    CASE
                        WHEN {billing_expr} IN ('year', 'yearly') THEN ROUND(p.price_yearly / 12.0)::bigint
                        ELSE p.price_monthly
                    END
                ), 0)::bigint
             FROM stripe_subscriptions s
             JOIN tenants t ON t.id = s.tenant_id
             JOIN plans p ON p.name = t.plan
             WHERE s.status IN ('active', 'trialing', 'past_due')
               AND s.created_at < $1"
        );

        let current_mrr = sqlx::query_scalar::<_, i64>(&sql_current)
            .fetch_one(db)
            .await
            .unwrap_or(0);

        let previous_mrr = sqlx::query_scalar::<_, i64>(&sql_previous)
            .bind(cutoff_30)
            .fetch_one(db)
            .await
            .unwrap_or(0);

        if previous_mrr > 0 {
            (current_mrr - previous_mrr) as f64 / previous_mrr as f64
        } else {
            0.0
        }
    } else {
        0.0
    };

    let emails_timeline = if has_messages {
        sqlx::query_as::<_, (String, i64)>(
            "SELECT DATE(created_at)::text as date, COUNT(*)::bigint
             FROM messages
             WHERE created_at >= NOW() - INTERVAL '30 days'
             GROUP BY DATE(created_at) ORDER BY 1",
        )
        .fetch_all(db)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|(date, count)| EmailsTimelinePoint { date, count })
        .collect()
    } else {
        Vec::new()
    };

    let signups_timeline = if has_tenants {
        sqlx::query_as::<_, (String, i64)>(
            "SELECT DATE(created_at)::text as date, COUNT(*)::bigint
             FROM tenants
             WHERE created_at >= NOW() - INTERVAL '30 days'
             GROUP BY DATE(created_at) ORDER BY 1",
        )
        .fetch_all(db)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|(date, count)| SignupsTimelinePoint { date, count })
        .collect()
    } else {
        Vec::new()
    };

    Ok(Json(CrossTenantGrowthResponse {
        total_emails_sent_daily: total_emails_daily,
        total_emails_sent_weekly: total_emails_weekly,
        total_emails_sent_monthly: total_emails_monthly,
        new_tenant_signups_daily: new_signups_daily,
        new_tenant_signups_weekly: new_signups_weekly,
        new_tenant_signups_monthly: new_signups_monthly,
        total_active_tenants,
        platform_revenue_growth_rate,
        churn_rate,
        churned_tenants_count_30d: churned_30d,
        emails_timeline_daily: emails_timeline,
        signups_timeline_daily: signups_timeline,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn monthly_revenue_cents_rounds_yearly_half_up() {
        // Yearly €25 000 → 2 083 cents/month (not truncated 2 082),
        // mirroring billing-service's yearly normalization.
        assert_eq!(monthly_revenue_cents(Some("yearly"), 2_500, 25_000), 2_083);
        assert_eq!(monthly_revenue_cents(Some("year"), 2_500, 25_000), 2_083);
        assert_eq!(monthly_revenue_cents(Some("monthly"), 2_500, 25_000), 2_500);
        assert_eq!(monthly_revenue_cents(None, 2_500, 25_000), 2_500);
    }

    #[test]
    fn plans_response_omits_velocity_without_a_data_source() {
        let response = CrossTenantPlansResponse {
            plans: Vec::new(),
            total_revenue: 0.0,
            total_tenants: 0,
            upgrade_count_30d: None,
            downgrade_count_30d: None,
            velocity: None,
            avg_tenant_lifetime_days: 0.0,
            notes: Vec::new(),
        };

        // Omitted (None), not a fabricated zero velocity.
        assert!(response.velocity.is_none());
        assert!(response.upgrade_count_30d.is_none());
        let json = serde_json::to_value(&response).unwrap();
        assert!(json.get("velocity").is_none());
        assert!(json.get("upgradeCount30d").is_none());
    }
}
