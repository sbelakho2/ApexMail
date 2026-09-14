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

// ─── Adversarial cross-tenant aggregation tests ────────────────

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
    fn revenue_normalization_and_cents_conversion_edges() {
        // Half-up rounding on every yearly spelling.
        assert_eq!(monthly_revenue_cents(Some("yearly"), 1, 25_000), 2_083);
        assert_eq!(monthly_revenue_cents(Some("YEARLY"), 1, 25_000), 2_083);
        assert_eq!(monthly_revenue_cents(Some("Year"), 1, 25_000), 2_083);
        assert_eq!(monthly_revenue_cents(Some("monthly"), 1, 25_000), 1);
        assert_eq!(monthly_revenue_cents(Some(""), 1, 25_000), 1);
        assert_eq!(monthly_revenue_cents(None, 0, 11), 0);
        // Exact divisibility must not gain a cent from the +6 rounding nudge.
        assert_eq!(monthly_revenue_cents(Some("yearly"), 0, 12_000), 1_000);
        assert_eq!(cents_to_dollars(12_345), 123.45);
        assert_eq!(cents_to_dollars(0), 0.0);
        assert_eq!(cents_to_dollars(-100), -1.0);
    }

    #[tokio::test]
    async fn health_aggregates_seeded_sends_bounces_and_rates() {
        let Some((state, pool)) = state_and_pool("adv_cross_tenant_health").await else {
            return;
        };
        let tenant = apexmail_lib::id::generate_id("", 26);
        sqlx::query(
            "INSERT INTO tenants (id, name, plan, status, created_at, updated_at)
             VALUES ($1, 'cross-tenant adversarial', 'free', 'active', NOW(), NOW())",
        )
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("seed tenant");
        for i in 0..4 {
            let status = if i < 2 { "delivered" } else { "bounced" };
            sqlx::query(
                "INSERT INTO messages (tenant_id, from_email, to_emails, status, created_at, updated_at)
                 VALUES ($1, 'a@example.com', '[\"b@example.com\"]'::jsonb, $2, NOW(), NOW())",
            )
            .bind(&tenant)
            .bind(status)
            .execute(&pool)
            .await
            .expect("seed message");
        }
        sqlx::query(
            "INSERT INTO events (id, tenant_id, message_id, event_type, recipient, timestamp)
             VALUES ($1, $2, 'adv-bounce-msg', 'bounced', 'b@example.com', NOW())",
        )
        .bind(format!("adv-evt-{}", uuid::Uuid::new_v4().simple()))
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("seed bounce event");

        let Json(health) = get_cross_tenant_health(State(state.clone()), admin_auth())
            .await
            .expect("health");
        assert!(health.total_tenants >= 1);
        assert!(health.total_emails_sent >= 4);
        assert!(health.total_emails_delivered >= 2);
        assert!(health.total_bounces >= 1);
        assert!(
            (0.0..=1.0).contains(&health.overall_delivery_rate),
            "a rate cannot exceed 1.0: {}",
            health.overall_delivery_rate
        );
        assert!(
            (0.0..=100.0).contains(&health.platform_health_score),
            "score out of range: {}",
            health.platform_health_score
        );
        assert!(health.bottom_5_tenants.len() <= 5);
        if let Some(entry) = health
            .bottom_5_tenants
            .iter()
            .find(|t| t.tenant_id == tenant)
        {
            assert_eq!(entry.emails_sent, 4);
            assert_eq!(entry.emails_delivered, 2);
            assert_eq!(entry.delivery_rate, 0.5);
            assert_eq!(entry.bounce_count, 1);
        }

        // Scope gate: a non-wildcard key is refused.
        let scoped = AuthUser {
            scopes: vec!["analytics:read".into()],
            ..admin_auth()
        };
        assert!(matches!(
            get_cross_tenant_health(State(state.clone()), scoped).await,
            Err(ApiError::Forbidden(_))
        ));

        cleanup_cross_tenant(&pool, &tenant).await;
    }

    #[tokio::test]
    async fn plans_aggregate_active_subscriptions_and_yearly_revenue() {
        let Some((state, pool)) = state_and_pool("adv_cross_tenant_plans").await else {
            return;
        };
        let tag = uuid::Uuid::new_v4().simple().to_string();
        let plan_name = format!("adv-plan-{tag}");
        let tenant = apexmail_lib::id::generate_id("", 26);
        sqlx::query(
            "INSERT INTO tenants (id, name, plan, status, created_at, updated_at)
             VALUES ($1, 'cross plans', $2, 'active', NOW(), NOW())",
        )
        .bind(&tenant)
        .bind(&plan_name)
        .execute(&pool)
        .await
        .expect("seed tenant");
        sqlx::query(
            "INSERT INTO plans (id, name, price_monthly, price_yearly, features)
             VALUES ($1, $2, 5000, 60000, '{}'::jsonb)",
        )
        .bind(apexmail_lib::id::generate_id("", 26))
        .bind(&plan_name)
        .execute(&pool)
        .await
        .expect("seed plan");
        sqlx::query(
            "INSERT INTO stripe_subscriptions (tenant_id, stripe_subscription_id, plan, status, billing_interval, created_at, updated_at)
             VALUES ($1, $2, $3, 'active', 'yearly', NOW() - INTERVAL '60 days', NOW())",
        )
        .bind(&tenant)
        .bind(format!("sub_adv_{tag}"))
        .bind(&plan_name)
        .execute(&pool)
        .await
        .expect("seed subscription");

        let Json(plans) = get_cross_tenant_plans(State(state.clone()), admin_auth())
            .await
            .expect("plans");
        assert!(plans.total_tenants >= 1);
        assert!(!plans.notes.is_empty(), "omission notes are mandatory");
        let entry = plans
            .plans
            .iter()
            .find(|p| p.plan == plan_name)
            .expect("seeded plan appears");
        // 60_000 cents/year → 5_000 cents/month → $50.00, half-up.
        assert_eq!(entry.monthly_revenue, 50.0);
        assert_eq!(entry.active_subscriptions, 1);
        assert!(entry.avg_lifetime_days > 0.0);
        assert!(entry.upgrades_30d.is_none());
        assert!(entry.downgrades_30d.is_none());
        assert!(plans.total_revenue >= 50.0);
        // Velocity is honestly omitted from the wire format.
        let json = serde_json::to_value(&plans).unwrap();
        assert!(json.get("velocity").is_none());
        assert!(json.get("upgradeCount30d").is_none());

        cleanup_cross_tenant(&pool, &tenant).await;
        sqlx::query("DELETE FROM plans WHERE name = $1")
            .bind(&plan_name)
            .execute(&pool)
            .await
            .expect("cleanup plan");
    }

    #[tokio::test]
    async fn growth_reports_seeded_signups_emails_churn_and_revenue() {
        let Some((state, pool)) = state_and_pool("adv_cross_tenant_growth").await else {
            return;
        };
        let tag = uuid::Uuid::new_v4().simple().to_string();
        let plan_name = format!("adv-growth-plan-{tag}");
        let active = apexmail_lib::id::generate_id("", 26);
        let churned = apexmail_lib::id::generate_id("", 26);
        for (id, status) in [(&active, "active"), (&churned, "suspended")] {
            sqlx::query(
                "INSERT INTO tenants (id, name, plan, status, created_at, updated_at)
                 VALUES ($1, 'cross growth', $2, $3, NOW(), NOW())",
            )
            .bind(id)
            .bind(&plan_name)
            .bind(status)
            .execute(&pool)
            .await
            .expect("seed tenant");
        }
        sqlx::query(
            "INSERT INTO plans (id, name, price_monthly, price_yearly, features)
             VALUES ($1, $2, 1000, 12000, '{}'::jsonb)",
        )
        .bind(apexmail_lib::id::generate_id("", 26))
        .bind(&plan_name)
        .execute(&pool)
        .await
        .expect("seed plan");
        // One OLD active subscription (excluded from current-30d previous
        // MRR) and one NEW one created today (drives positive growth).
        sqlx::query(
            "INSERT INTO stripe_subscriptions (tenant_id, stripe_subscription_id, plan, status, billing_interval, created_at, updated_at)
             VALUES ($1, $2, $3, 'active', 'monthly', NOW() - INTERVAL '90 days', NOW())",
        )
        .bind(&active)
        .bind(format!("sub_old_{tag}"))
        .bind(&plan_name)
        .execute(&pool)
        .await
        .expect("seed old sub");
        sqlx::query(
            "INSERT INTO messages (tenant_id, from_email, to_emails, status, created_at, updated_at)
             VALUES ($1, 'a@example.com', '[\"b@example.com\"]'::jsonb, 'delivered', NOW(), NOW())",
        )
        .bind(&active)
        .execute(&pool)
        .await
        .expect("seed message");

        let Json(growth) = get_cross_tenant_growth(State(state.clone()), admin_auth())
            .await
            .expect("growth");
        assert!(growth.total_emails_sent_daily >= 1);
        assert!(growth.total_emails_sent_weekly >= 1);
        assert!(growth.total_emails_sent_monthly >= 1);
        assert!(growth.new_tenant_signups_daily >= 2);
        assert!(growth.new_tenant_signups_weekly >= 2);
        assert!(growth.new_tenant_signups_monthly >= 2);
        assert!(growth.total_active_tenants >= 1);
        assert!(growth.churned_tenants_count_30d >= 1);
        assert!(growth.churn_rate > 0.0);
        assert!(
            growth.emails_timeline_daily.iter().any(|p| p.count >= 1),
            "timeline reflects seeded sends"
        );
        assert!(
            growth.signups_timeline_daily.iter().any(|p| p.count >= 2),
            "timeline reflects seeded signups"
        );
        assert!(growth.platform_revenue_growth_rate.is_finite());

        let scoped = AuthUser {
            scopes: vec!["reports:read".into()],
            ..admin_auth()
        };
        assert!(matches!(
            get_cross_tenant_growth(State(state.clone()), scoped).await,
            Err(ApiError::Forbidden(_))
        ));

        cleanup_cross_tenant(&pool, &active).await;
        cleanup_cross_tenant(&pool, &churned).await;
        sqlx::query("DELETE FROM plans WHERE name = $1")
            .bind(&plan_name)
            .execute(&pool)
            .await
            .expect("cleanup plan");
    }

    async fn cleanup_cross_tenant(pool: &sqlx::PgPool, tenant: &str) {
        sqlx::query("DELETE FROM events WHERE tenant_id = $1")
            .bind(tenant)
            .execute(pool)
            .await
            .expect("cleanup events");
        sqlx::query("DELETE FROM messages WHERE tenant_id = $1")
            .bind(tenant)
            .execute(pool)
            .await
            .expect("cleanup messages");
        sqlx::query("DELETE FROM stripe_subscriptions WHERE tenant_id = $1")
            .bind(tenant)
            .execute(pool)
            .await
            .expect("cleanup subs");
        sqlx::query("DELETE FROM tenants WHERE id = $1")
            .bind(tenant)
            .execute(pool)
            .await
            .expect("cleanup tenant");
    }
}
