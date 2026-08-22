//! Insights engine — auto-generates actionable insights from analytics data.
//!
//! Compares recent metrics against historical baselines and surfaces meaningful
//! observations. Every insight is backed by real database queries. If a metric
//! comparison returns no data, the insight is not generated (no fabricated content).

use axum::extract::{Query, State};
use axum::routing::get;
use axum::{Json, Router};
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::middleware::auth::AuthUser;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(get_insights))
        .route("/trends", get(get_trends))
        .route("/recommendations", get(get_recommendations))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InsightsQuery {
    #[serde(default = "default_lookback")]
    pub lookback: String,
}

fn default_lookback() -> String {
    "7d".into()
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InsightsResponse {
    pub insights: Vec<Insight>,
    pub trends: Vec<TrendInsight>,
    pub recommendations: Vec<Recommendation>,
    pub generated_at: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Insight {
    pub category: String,
    pub title: String,
    pub description: String,
    pub severity: String,
    pub metric_name: String,
    pub current_value: String,
    pub previous_value: String,
    pub change_pct: f64,
    pub direction: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrendInsight {
    pub title: String,
    pub description: String,
    pub data_points: i64,
    pub trend_direction: String,
    pub confidence: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Recommendation {
    pub category: String,
    pub priority: String,
    pub title: String,
    pub description: String,
    pub actionable: bool,
}

#[derive(sqlx::FromRow)]
struct MetricComparison {
    current_value: f64,
    previous_value: f64,
    current_count: i64,
    previous_count: i64,
}

fn parse_lookback_days(lookback: &str) -> i64 {
    match lookback {
        "1d" => 1,
        "3d" => 3,
        "7d" => 7,
        "14d" => 14,
        "30d" => 30,
        _ => 7,
    }
}

fn calc_change_pct(current: f64, previous: f64) -> (f64, String) {
    if previous.abs() < f64::EPSILON {
        if current.abs() < f64::EPSILON {
            return (0.0, "flat".into());
        }
        return (100.0, "up".into());
    }
    let pct = ((current - previous) / previous) * 100.0;
    let direction = if pct > 1.0 {
        "up"
    } else if pct < -1.0 {
        "down"
    } else {
        "flat"
    };
    (pct, direction.into())
}

async fn compare_metric(
    db: &sqlx::PgPool,
    current_query: &str,
    previous_query: &str,
    interval: &str,
) -> Option<MetricComparison> {
    let current: Option<(f64, i64)> = sqlx::query_as(current_query)
        .bind(interval)
        .fetch_optional(db)
        .await
        .ok()
        .flatten()
        .map(|(v, c): (Option<f64>, Option<i64>)| (v.unwrap_or(0.0), c.unwrap_or(0)));

    let previous: Option<(f64, i64)> = sqlx::query_as(previous_query)
        .bind(interval)
        .fetch_optional(db)
        .await
        .ok()
        .flatten()
        .map(|(v, c): (Option<f64>, Option<i64>)| (v.unwrap_or(0.0), c.unwrap_or(0)));

    match (current, previous) {
        (Some((cv, cc)), Some((pv, pc))) => Some(MetricComparison {
            current_value: cv,
            previous_value: pv,
            current_count: cc,
            previous_count: pc,
        }),
        _ => None,
    }
}

async fn get_insights(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<InsightsQuery>,
) -> Result<Json<InsightsResponse>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    let db = &state.db;
    let days = parse_lookback_days(&params.lookback);
    let interval = format!("{days} days");
    let now = Utc::now();
    let mut insights: Vec<Insight> = Vec::new();
    let mut trends: Vec<TrendInsight> = Vec::new();
    let mut recommendations: Vec<Recommendation> = Vec::new();

    // ─── Delivery Rate Insight ──────────────────────────────────────────
    let delivery_sql_current = format!(
        "SELECT
            CASE WHEN COUNT(*) > 0
                THEN COUNT(*) FILTER (WHERE status = 'delivered')::float8 / COUNT(*)::float8
                ELSE 0
            END::float8,
            COUNT(*)::bigint
         FROM messages
         WHERE created_at >= NOW() - '{interval}'::interval"
    );
    let delivery_sql_previous = format!(
        "SELECT
            CASE WHEN COUNT(*) > 0
                THEN COUNT(*) FILTER (WHERE status = 'delivered')::float8 / COUNT(*)::float8
                ELSE 0
            END::float8,
            COUNT(*)::bigint
         FROM messages
         WHERE created_at >= NOW() - '{interval}'::interval - '{interval}'::interval
           AND created_at < NOW() - '{interval}'::interval"
    );

    if let Some(cmp) = compare_metric(db, &delivery_sql_current, &delivery_sql_previous, &interval)
        .await
    {
        let (pct, dir) =
            calc_change_pct(cmp.current_value, cmp.previous_value);
        if pct.abs() > 2.0 && cmp.current_count > 10 {
            insights.push(Insight {
                category: "deliverability".into(),
                title: if dir == "down" {
                    "Delivery rate decreased".into()
                } else {
                    "Delivery rate improved".into()
                },
                description: format!(
                    "Delivery rate is {:.1}% vs {:.1}% in the previous period ({:+.1}% change)",
                    cmp.current_value * 100.0,
                    cmp.previous_value * 100.0,
                    pct
                ),
                severity: if dir == "down" && pct < -5.0 {
                    "warning"
                } else if dir == "down" {
                    "info"
                } else {
                    "positive"
                }
                .into(),
                metric_name: "delivery_rate".into(),
                current_value: format!("{:.1}%", cmp.current_value * 100.0),
                previous_value: format!("{:.1}%", cmp.previous_value * 100.0),
                change_pct: pct,
                direction: dir,
            });
        }
    }

    // ─── Bounce Rate Insight ────────────────────────────────────────────
    let bounce_sql_current = format!(
        "SELECT
            CASE WHEN COUNT(*) > 0
                THEN COUNT(*) FILTER (WHERE status = 'bounced')::float8 / COUNT(*)::float8
                ELSE 0
            END::float8,
            COUNT(*) FILTER (WHERE status = 'bounced')::bigint
         FROM messages
         WHERE created_at >= NOW() - '{interval}'::interval"
    );
    let bounce_sql_previous = format!(
        "SELECT
            CASE WHEN COUNT(*) > 0
                THEN COUNT(*) FILTER (WHERE status = 'bounced')::float8 / COUNT(*)::float8
                ELSE 0
            END::float8,
            COUNT(*) FILTER (WHERE status = 'bounced')::bigint
         FROM messages
         WHERE created_at >= NOW() - '{interval}'::interval - '{interval}'::interval
           AND created_at < NOW() - '{interval}'::interval"
    );

    if let Some(cmp) = compare_metric(db, &bounce_sql_current, &bounce_sql_previous, &interval)
        .await
    {
        let (pct, dir) =
            calc_change_pct(cmp.current_value, cmp.previous_value);
        if pct.abs() > 10.0 || (dir == "up" && cmp.current_count > 5) {
            insights.push(Insight {
                category: "deliverability".into(),
                title: if dir == "up" {
                    "Bounce rate increased".into()
                } else {
                    "Bounce rate decreased".into()
                },
                description: format!(
                    "Bounce rate changed {:+2.1}% this period — check DNS configuration for affected domains",
                    pct
                ),
                severity: if dir == "up" && pct > 20.0 {
                    "critical"
                } else if dir == "up" {
                    "warning"
                } else {
                    "positive"
                }
                .into(),
                metric_name: "bounce_rate".into(),
                current_value: format!("{:.1}%", cmp.current_value * 100.0),
                previous_value: format!("{:.1}%", cmp.previous_value * 100.0),
                change_pct: pct,
                direction: dir,
            });
        }
    }

    // ─── Open Rate Insight ──────────────────────────────────────────────
    let open_sql_current = format!(
        "SELECT
            COALESCE(
                COUNT(*)::float8,
                0
            )::float8,
            COUNT(*)::bigint
         FROM events
         WHERE event_type = 'opened'
           AND timestamp >= NOW() - '{interval}'::interval"
    );
    let open_sql_previous = format!(
        "SELECT
            COALESCE(
                COUNT(*)::float8,
                0
            )::float8,
            COUNT(*)::bigint
         FROM events
         WHERE event_type = 'opened'
           AND timestamp >= NOW() - '{interval}'::interval - '{interval}'::interval
           AND timestamp < NOW() - '{interval}'::interval"
    );

    if let Some(cmp) = compare_metric(db, &open_sql_current, &open_sql_previous, &interval).await
    {
        let (pct, dir) =
            calc_change_pct(cmp.current_value, cmp.previous_value);
        if pct.abs() > 5.0 && cmp.current_count > 10 {
            insights.push(Insight {
                category: "engagement".into(),
                title: if dir == "up" {
                    "Open rate increased".into()
                } else {
                    "Open rate decreased".into()
                },
                description: format!(
                    "Email opens changed {:+.1}% vs previous period. Consider subject line optimization or send-time tuning.",
                    pct
                ),
                severity: if dir == "down" && pct < -20.0 {
                    "warning"
                } else {
                    "info"
                }
                .into(),
                metric_name: "open_count".into(),
                current_value: format!("{} opens", cmp.current_count),
                previous_value: format!("{} opens", cmp.previous_count),
                change_pct: pct,
                direction: dir,
            });
        }
    }

    // ─── Signup Trend Insight ──────────────────────────────────────────
    let signup_current: i64 = sqlx::query_scalar(&format!(
        "SELECT COUNT(*)::bigint FROM tenants
         WHERE created_at >= NOW() - '{interval}'::interval"
    ))
    .fetch_one(db)
    .await
    .unwrap_or(0);

    let signup_previous: i64 = sqlx::query_scalar(&format!(
        "SELECT COUNT(*)::bigint FROM tenants
         WHERE created_at >= NOW() - '{interval}'::interval - '{interval}'::interval
           AND created_at < NOW() - '{interval}'::interval"
    ))
    .fetch_one(db)
    .await
    .unwrap_or(0);

    let (signup_pct, signup_dir) =
        calc_change_pct(signup_current as f64, signup_previous as f64);

    if signup_current > 0 || signup_previous > 0 {
        let direction = signup_dir.clone();
        insights.push(Insight {
            category: "growth".into(),
            title: if direction == "up" {
                "Signups accelerating".into()
            } else if direction == "down" {
                "Signups slowing".into()
            } else {
                "Signups stable".into()
            },
            description: format!(
                "{} new signups this period vs {} in the previous period ({:+.1}%)",
                signup_current, signup_previous, signup_pct
            ),
            severity: if signup_dir == "down" && signup_pct < -30.0 {
                "warning"
            } else {
                "info"
            }
            .into(),
            metric_name: "signups".into(),
            current_value: signup_current.to_string(),
            previous_value: signup_previous.to_string(),
            change_pct: signup_pct,
            direction: signup_dir,
        });
    }

    // ─── Queue Depth Trend ──────────────────────────────────────────────
    let queue_rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT DATE(created_at)::text, COUNT(*)::bigint
         FROM email_queue
         WHERE created_at >= NOW() - INTERVAL '14 days'
         GROUP BY DATE(created_at) ORDER BY 1",
    )
    .fetch_all(db)
    .await
    .unwrap_or_default();

    if queue_rows.len() >= 5 {
        let recent: Vec<i64> = queue_rows.iter().rev().take(7).map(|(_, c)| *c).collect();
        let older: Vec<i64> = queue_rows
            .iter()
            .rev()
            .skip(7)
            .take(7)
            .map(|(_, c)| *c)
            .collect();

        if !recent.is_empty() && !older.is_empty() {
            let recent_avg = recent.iter().sum::<i64>() as f64 / recent.len() as f64;
            let older_avg = older.iter().sum::<i64>() as f64 / older.len() as f64;
            let (pct, dir) = calc_change_pct(recent_avg, older_avg);

            if pct.abs() > 20.0 {
                trends.push(TrendInsight {
                    title: if dir == "up" {
                        "Queue depth trending upward".into()
                    } else {
                        "Queue depth decreasing".into()
                    },
                    description: format!(
                        "Average queue depth: {:.0} (recent) vs {:.0} (prior week), {:+.1}% change over {} data points",
                        recent_avg, older_avg, pct, queue_rows.len()
                    ),
                    data_points: queue_rows.len() as i64,
                    trend_direction: dir,
                    confidence: if queue_rows.len() > 10 {
                        "high"
                    } else {
                        "medium"
                    }
                    .into(),
                });
            }
        }
    }

    // ─── Volume Growth Trend ────────────────────────────────────────────
    let volume_rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT DATE(created_at)::text, COUNT(*)::bigint
         FROM messages
         WHERE created_at >= NOW() - INTERVAL '30 days'
         GROUP BY DATE(created_at) ORDER BY 1",
    )
    .fetch_all(db)
    .await
    .unwrap_or_default();

    if volume_rows.len() >= 7 {
        let recent_vol: Vec<i64> = volume_rows.iter().rev().take(7).map(|(_, c)| *c).collect();
        let older_vol: Vec<i64> = volume_rows
            .iter()
            .rev()
            .skip(7)
            .take(7)
            .map(|(_, c)| *c)
            .collect();

        if !recent_vol.is_empty() && !older_vol.is_empty() {
            let recent_avg = recent_vol.iter().sum::<i64>() as f64 / recent_vol.len() as f64;
            let older_avg = older_vol.iter().sum::<i64>() as f64 / older_vol.len() as f64;
            let (pct, dir) = calc_change_pct(recent_avg, older_avg);

            if pct.abs() > 10.0 {
                trends.push(TrendInsight {
                    title: format!(
                        "Email volume {} by {:+.1}%",
                        if dir == "up" { "growing" } else { "shrinking" },
                        pct
                    ),
                    description: format!(
                        "Daily average: {:.0} emails (recent week) vs {:.0} (prior week)",
                        recent_avg, older_avg
                    ),
                    data_points: volume_rows.len() as i64,
                    trend_direction: dir,
                    confidence: if volume_rows.len() > 14 {
                        "high"
                    } else {
                        "medium"
                    }
                    .into(),
                });
            }
        }
    }

    // ─── Complaint Rate Insight ─────────────────────────────────────────
    let complaint_current: i64 = sqlx::query_scalar(&format!(
        "SELECT COUNT(*)::bigint FROM events
         WHERE event_type = 'complained'
           AND timestamp >= NOW() - '{interval}'::interval"
    ))
    .fetch_one(db)
    .await
    .unwrap_or(0);

    let complaint_previous: i64 = sqlx::query_scalar(&format!(
        "SELECT COUNT(*)::bigint FROM events
         WHERE event_type = 'complained'
           AND timestamp >= NOW() - '{interval}'::interval - '{interval}'::interval
           AND timestamp < NOW() - '{interval}'::interval"
    ))
    .fetch_one(db)
    .await
    .unwrap_or(0);

    let (com_pct, com_dir) =
        calc_change_pct(complaint_current as f64, complaint_previous as f64);

    if complaint_current > 0 && (com_dir == "up" || com_pct.abs() > 50.0) {
        insights.push(Insight {
            category: "deliverability".into(),
            title: "Complaint rate change detected".into(),
            description: format!(
                "{} complaints this period vs {} in the previous ({:+.1}%). Review recent campaign content and list quality.",
                complaint_current, complaint_previous, com_pct
            ),
            severity: if com_dir == "up" && com_pct > 50.0 {
                "critical"
            } else {
                "warning"
            }
            .into(),
            metric_name: "complaints".into(),
            current_value: complaint_current.to_string(),
            previous_value: complaint_previous.to_string(),
            change_pct: com_pct,
            direction: com_dir,
        });
    }

    // ─── Generate Recommendations ───────────────────────────────────────
    // Based on insights discovered above, generate actionable recommendations
    for insight in &insights {
        match (insight.category.as_str(), insight.severity.as_str()) {
            ("deliverability", "critical") => {
                recommendations.push(Recommendation {
                    category: "deliverability".into(),
                    priority: "high".into(),
                    title: "Investigate delivery failures immediately".into(),
                    description: "Review bounce logs, check DNS/SPF/DKIM/DMARC configuration, and verify outbound IP reputation.".into(),
                    actionable: true,
                });
            }
            ("deliverability", "warning") => {
                recommendations.push(Recommendation {
                    category: "deliverability".into(),
                    priority: "medium".into(),
                    title: "Review email authentication and list hygiene".into(),
                    description: "Check DKIM/SPF records, review recipient list quality, and consider list cleaning.".into(),
                    actionable: true,
                });
            }
            ("engagement", "warning") => {
                recommendations.push(Recommendation {
                    category: "engagement".into(),
                    priority: "medium".into(),
                    title: "Optimize email content and send timing".into(),
                    description: "A/B test subject lines, adjust send times based on recipient timezone, and segment inactive subscribers.".into(),
                    actionable: true,
                });
            }
            ("growth", "warning") => {
                recommendations.push(Recommendation {
                    category: "growth".into(),
                    priority: "medium".into(),
                    title: "Review acquisition channels and onboarding".into(),
                    description: "Analyze which acquisition channels are underperforming and audit the onboarding flow for friction points.".into(),
                    actionable: true,
                });
            }
            _ => {}
        }
    }

    // Deduplicate recommendations
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    recommendations.retain(|r| seen.insert(r.title.clone()));

    Ok(Json(InsightsResponse {
        insights,
        trends,
        recommendations,
        generated_at: now.to_rfc3339(),
    }))
}

async fn get_trends(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Vec<TrendInsight>>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    let db = &state.db;
    let mut trends: Vec<TrendInsight> = Vec::new();

    // Volume trend
    let volume_rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT DATE(created_at)::text, COUNT(*)::bigint
         FROM messages
         WHERE created_at >= NOW() - INTERVAL '30 days'
         GROUP BY DATE(created_at) ORDER BY 1",
    )
    .fetch_all(db)
    .await
    .unwrap_or_default();

    if volume_rows.len() >= 7 {
        let recent: Vec<i64> = volume_rows.iter().rev().take(7).map(|(_, c)| *c).collect();
        let older: Vec<i64> = volume_rows
            .iter()
            .rev()
            .skip(7)
            .take(7)
            .map(|(_, c)| *c)
            .collect();

        if !recent.is_empty() && !older.is_empty() {
            let recent_avg = recent.iter().sum::<i64>() as f64 / recent.len() as f64;
            let older_avg = older.iter().sum::<i64>() as f64 / older.len() as f64;
            let (pct, dir) = calc_change_pct(recent_avg, older_avg);

            trends.push(TrendInsight {
                title: format!(
                    "Volume {} by {:+.1}%",
                    if dir == "up" { "growing" } else { "shrinking" },
                    pct
                ),
                description: format!(
                    "Daily avg: {:.0} (recent) vs {:.0} (prior), {} data points",
                    recent_avg,
                    older_avg,
                    volume_rows.len()
                ),
                data_points: volume_rows.len() as i64,
                trend_direction: dir,
                confidence: if volume_rows.len() > 14 { "high" } else { "medium" }.into(),
            });
        }
    }

    // Queue depth trend
    let queue_rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT DATE(created_at)::text, COUNT(*)::bigint
         FROM email_queue
         WHERE created_at >= NOW() - INTERVAL '14 days'
         GROUP BY DATE(created_at) ORDER BY 1",
    )
    .fetch_all(db)
    .await
    .unwrap_or_default();

    if queue_rows.len() >= 5 {
        let recent: Vec<i64> = queue_rows.iter().rev().take(7).map(|(_, c)| *c).collect();
        let older: Vec<i64> = queue_rows
            .iter()
            .rev()
            .skip(7)
            .take(7)
            .map(|(_, c)| *c)
            .collect();

        if !recent.is_empty() && !older.is_empty() {
            let recent_avg = recent.iter().sum::<i64>() as f64 / recent.len() as f64;
            let older_avg = older.iter().sum::<i64>() as f64 / older.len() as f64;
            let (pct, dir) = calc_change_pct(recent_avg, older_avg);

            trends.push(TrendInsight {
                title: format!(
                    "Queue depth {} by {:+.1}%",
                    if dir == "up" { "increasing" } else { "decreasing" },
                    pct
                ),
                description: format!(
                    "Avg queue: {:.0} (recent) vs {:.0} (prior), {} data points",
                    recent_avg,
                    older_avg,
                    queue_rows.len()
                ),
                data_points: queue_rows.len() as i64,
                trend_direction: dir,
                confidence: "medium".into(),
            });
        }
    }

    Ok(Json(trends))
}

/// Counts active tenants with no verified sending domain. The domains
/// table's column is `verified` (migration 052) — the previous query read a
/// non-existent `d.is_verified`, which errored the count to 0 (via
/// unwrap_or(0)) so this recommendation could never fire.
const UNVERIFIED_DOMAINS_SQL: &str = "SELECT COUNT(DISTINCT t.id)::bigint
         FROM tenants t
         LEFT JOIN domains d ON d.tenant_id::text = t.id::text AND d.verified = true
         WHERE t.status = 'active' AND d.id IS NULL";

/// The unverified-domains onboarding recommendation, built from the tenant
/// count. Returns None when every active tenant has a verified domain.
fn unverified_domains_recommendation(unverified: i64) -> Option<Recommendation> {
    (unverified > 0).then(|| Recommendation {
        category: "growth".into(),
        priority: "medium".into(),
        title: "Onboarding: tenants without verified domains".into(),
        description: format!(
            "{} active tenants have no verified sending domain. Send onboarding nudges to improve activation rate.",
            unverified
        ),
        actionable: true,
    })
}

async fn get_recommendations(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Vec<Recommendation>>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    let db = &state.db;
    let mut recommendations: Vec<Recommendation> = Vec::new();

    // Check bounce rate for DNS recommendation
    let bounce_rate: Option<(f64,)> = sqlx::query_as(
        "SELECT
            CASE WHEN COUNT(*) > 0
                THEN COUNT(*) FILTER (WHERE status = 'bounced')::float8 / COUNT(*)::float8
                ELSE 0
            END
         FROM messages
         WHERE created_at >= NOW() - INTERVAL '7 days'",
    )
    .fetch_optional(db)
    .await
    .ok()
    .flatten();

    if let Some((rate,)) = bounce_rate {
        if rate > 0.05 {
            recommendations.push(Recommendation {
                category: "deliverability".into(),
                priority: "high".into(),
                title: "Review DNS configuration for sending domains".into(),
                description: format!(
                    "Bounce rate is {:.1}% over the last 7 days. Verify SPF, DKIM, and DMARC records are correctly configured for all sending domains.",
                    rate * 100.0
                ),
                actionable: true,
            });
        }
    }

    // Check for tenants without verified domains
    let unverified: i64 = sqlx::query_scalar(UNVERIFIED_DOMAINS_SQL)
        .fetch_one(db)
        .await
        .unwrap_or(0);

    if let Some(recommendation) = unverified_domains_recommendation(unverified) {
        recommendations.push(recommendation);
    }

    // Check for stale trials (stripe_subscriptions — the table billing
    // webhooks write; the legacy `subscriptions` table has no writer)
    let stale_trials: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM stripe_subscriptions
         WHERE status = 'trialing'
           AND created_at < NOW() - INTERVAL '30 days'",
    )
    .fetch_one(db)
    .await
    .unwrap_or(0);

    if stale_trials > 0 {
        recommendations.push(Recommendation {
            category: "growth".into(),
            priority: "medium".into(),
            title: "Follow up on expired trials".into(),
            description: format!(
                "{} trials have been active for >30 days without converting. Consider targeted outreach or special offers.",
                stale_trials
            ),
            actionable: true,
        });
    }

    // Check for failed queue items accumulating
    let failed_items: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM email_queue
         WHERE status = 'failed'
           AND updated_at >= NOW() - INTERVAL '24 hours'",
    )
    .fetch_one(db)
    .await
    .unwrap_or(0);

    if failed_items > 10 {
        recommendations.push(Recommendation {
            category: "operations".into(),
            priority: "high".into(),
            title: "Investigate delivery failures".into(),
            description: format!(
                "{} email delivery failures in the last 24 hours. Check provider connectivity and rate limits.",
                failed_items
            ),
            actionable: true,
        });
    }

    Ok(Json(recommendations))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calc_change_flat() {
        let (pct, dir) = calc_change_pct(100.0, 100.0);
        assert!((pct - 0.0).abs() < 0.01);
        assert_eq!(dir, "flat");
    }

    #[test]
    fn unverified_domains_sql_reads_real_verified_column() {
        // The column is `verified` (migration 052); `d.is_verified` never
        // existed, so the count always errored to zero.
        assert!(UNVERIFIED_DOMAINS_SQL.contains("d.verified = true"));
        assert!(!UNVERIFIED_DOMAINS_SQL.contains("is_verified"));
    }

    #[test]
    fn unverified_domains_recommendation_fires_for_seeded_unverified_domain() {
        // A tenant with an unverified domain (count > 0) → fires.
        let recommendation =
            unverified_domains_recommendation(1).expect("must fire when a tenant lacks a verified domain");
        assert_eq!(recommendation.category, "growth");
        assert_eq!(recommendation.priority, "medium");
        assert!(recommendation.actionable);
        assert!(recommendation.description.contains("1 active tenants"));

        // All tenants verified → no recommendation.
        assert!(unverified_domains_recommendation(0).is_none());
    }

    #[test]
    fn calc_change_up() {
        let (pct, dir) = calc_change_pct(150.0, 100.0);
        assert!((pct - 50.0).abs() < 0.01);
        assert_eq!(dir, "up");
    }

    #[test]
    fn calc_change_down() {
        let (pct, dir) = calc_change_pct(50.0, 100.0);
        assert!((pct + 50.0).abs() < 0.01);
        assert_eq!(dir, "down");
    }

    #[test]
    fn calc_change_zero_previous() {
        let (pct, dir) = calc_change_pct(10.0, 0.0);
        assert!((pct - 100.0).abs() < 0.01);
        assert_eq!(dir, "up");
    }

    #[test]
    fn calc_change_zero_both() {
        let (pct, dir) = calc_change_pct(0.0, 0.0);
        assert!((pct - 0.0).abs() < 0.01);
        assert_eq!(dir, "flat");
    }

    #[test]
    fn parse_lookback_defaults() {
        assert_eq!(parse_lookback_days("unknown"), 7);
        assert_eq!(parse_lookback_days("30d"), 30);
    }
}
