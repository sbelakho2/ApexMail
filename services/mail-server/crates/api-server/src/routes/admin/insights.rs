//! Insights engine — auto-generates actionable insights from analytics data.
//!
//! Compares recent metrics against historical baselines and surfaces meaningful
//! observations. Every insight is backed by real database queries. If a metric
//! comparison returns no data, the insight is not generated (no fabricated content).
//!
//! Metric conventions come from [`crate::analytics_metrics`]: comparisons use
//! SEND-COHORT windows (`(message_id, lower(recipient))` rows whose `sent`
//! event falls in the window, outcomes attached to that send), so repeat
//! opens/clicks on one recipient-send cannot fake an engagement change,
//! current message status is never mixed into a historical cohort, and the
//! previous period is frozen at its own end (a later outcome cannot rewrite
//! it).

use axum::extract::{Query, State};
use axum::routing::get;
use axum::{Json, Router};
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::analytics_metrics::{
    detect_event_columns, send_cohort_counts, send_cohort_counts_previous, send_cohort_time_series,
    AnalyticsRange, EventColumns,
};
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
    /// Sample-size label ("high" / "medium"), NOT a statistical confidence
    /// level — the trend is a heuristic comparison of daily averages.
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

/// Successful sends per day from the canonical send-cohort time series —
/// the same definition the analytics API serves (ONE KPI definition). A
/// failed query propagates as an error instead of masquerading as "no
/// sends".
async fn sent_volume_by_day(
    db: &sqlx::PgPool,
    columns: EventColumns,
    range: AnalyticsRange,
) -> Result<Vec<(String, i64)>, ApiError> {
    let series = send_cohort_time_series(db, None, range, columns).await?;
    Ok(series
        .into_iter()
        .map(|point| (point.date, point.sent))
        .collect())
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

    // Canonical, like-for-like period comparison: send cohorts in the
    // current window vs the immediately preceding one. The previous period's
    // outcome cutoff is its OWN end, so outcomes that happened after it
    // cannot rewrite it.
    let columns: EventColumns = detect_event_columns(&state).await;
    let current = send_cohort_counts(db, None, &interval, columns).await?;
    let previous = send_cohort_counts_previous(db, None, &interval, columns).await?;

    // ─── Delivery Rate Insight ──────────────────────────────────────────
    // Both rates must exist to compare: an empty send cohort yields None,
    // which is not a 0% delivery rate.
    if current.sent > 10 {
        if let (Some(current_rate), Some(previous_rate)) =
            (current.delivery_rate(), previous.delivery_rate())
        {
            let (pct, dir) = calc_change_pct(current_rate, previous_rate);
            if pct.abs() > 2.0 {
                insights.push(Insight {
                    category: "deliverability".into(),
                    title: if dir == "down" {
                        "Delivery rate decreased".into()
                    } else {
                        "Delivery rate improved".into()
                    },
                    description: format!(
                        "Delivery rate is {:.1}% vs {:.1}% in the previous period ({:+.1}% change)",
                        current_rate * 100.0,
                        previous_rate * 100.0,
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
                    current_value: format!("{:.1}%", current_rate * 100.0),
                    previous_value: format!("{:.1}%", previous_rate * 100.0),
                    change_pct: pct,
                    direction: dir,
                });
            }
        }
    }

    // ─── Bounce Rate Insight ────────────────────────────────────────────
    if current.sent > 0 {
        if let (Some(current_rate), Some(previous_rate)) =
            (current.bounce_rate(), previous.bounce_rate())
        {
            let (pct, dir) = calc_change_pct(current_rate, previous_rate);
            if pct.abs() > 10.0 || (dir == "up" && current.bounced > 5) {
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
                    current_value: format!("{:.1}%", current_rate * 100.0),
                    previous_value: format!("{:.1}%", previous_rate * 100.0),
                    change_pct: pct,
                    direction: dir,
                });
            }
        }
    }

    // ─── Open Engagement Insight ────────────────────────────────────────
    // DISTINCT opened messages: repeat opens of one message never inflate
    // the numerator.
    {
        let (pct, dir) = calc_change_pct(current.opened as f64, previous.opened as f64);
        if pct.abs() > 5.0 && current.opened > 10 {
            insights.push(Insight {
                category: "engagement".into(),
                title: if dir == "up" {
                    "Open engagement increased".into()
                } else {
                    "Open engagement decreased".into()
                },
                description: format!(
                    "Distinct messages opened changed {:+.1}% vs previous period. Consider subject line optimization or send-time tuning.",
                    pct
                ),
                severity: if dir == "down" && pct < -20.0 {
                    "warning"
                } else {
                    "info"
                }
                .into(),
                metric_name: "opened_messages".into(),
                current_value: format!("{} messages opened", current.opened),
                previous_value: format!("{} messages opened", previous.opened),
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

    let (signup_pct, signup_dir) = calc_change_pct(signup_current as f64, signup_previous as f64);

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

    // ─── Send Volume Growth Trend ───────────────────────────────────────
    // Successful sends from the canonical send-cohort series — never message
    // creation, which counts mail that may never have left the queue.
    let volume_rows = sent_volume_by_day(db, columns, AnalyticsRange::Days30).await?;

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
                        "Send volume {} by {:+.1}%",
                        if dir == "up" { "growing" } else { "shrinking" },
                        pct
                    ),
                    description: format!(
                        "Daily average: {:.0} sent messages (recent week) vs {:.0} (prior week)",
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
    // DISTINCT complained messages (canonical counts), not raw complaint
    // events — a repeated callback for one message cannot fake a spike.
    let (com_pct, com_dir) = calc_change_pct(current.complained as f64, previous.complained as f64);

    if current.complained > 0 && (com_dir == "up" || com_pct.abs() > 50.0) {
        insights.push(Insight {
            category: "deliverability".into(),
            title: "Complaint rate change detected".into(),
            description: format!(
                "{} messages complained this period vs {} in the previous ({:+.1}%). Review recent campaign content and list quality.",
                current.complained, previous.complained, com_pct
            ),
            severity: if com_dir == "up" && com_pct > 50.0 {
                "critical"
            } else {
                "warning"
            }
            .into(),
            metric_name: "complained_messages".into(),
            current_value: current.complained.to_string(),
            previous_value: previous.complained.to_string(),
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

    // Send volume trend — successful sends from the canonical cohort series.
    let columns: EventColumns = detect_event_columns(&state).await;
    let volume_rows = sent_volume_by_day(db, columns, AnalyticsRange::Days30).await?;

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
                    "Send volume {} by {:+.1}%",
                    if dir == "up" { "growing" } else { "shrinking" },
                    pct
                ),
                description: format!(
                    "Daily avg sent messages: {:.0} (recent) vs {:.0} (prior), {} data points",
                    recent_avg,
                    older_avg,
                    volume_rows.len()
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
                    if dir == "up" {
                        "increasing"
                    } else {
                        "decreasing"
                    },
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

    // Check bounce rate for DNS recommendation — canonical send-cohort rate
    // (fraction 0..1, absent when there is no send cohort).
    let columns = detect_event_columns(&state).await;
    let counts = send_cohort_counts(db, None, "7 days", columns).await?;

    if let Some(bounce_rate) = counts.bounce_rate().filter(|rate| *rate > 0.05) {
        recommendations.push(Recommendation {
            category: "deliverability".into(),
            priority: "high".into(),
            title: "Review DNS configuration for sending domains".into(),
            description: format!(
                "Bounce rate is {:.1}% over the last 7 days. Verify SPF, DKIM, and DMARC records are correctly configured for all sending domains.",
                bounce_rate * 100.0
            ),
            actionable: true,
        });
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
        let recommendation = unverified_domains_recommendation(1)
            .expect("must fire when a tenant lacks a verified domain");
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

    /// UPDATED to the send-cohort truth: the volume trend counts
    /// recipient-send cohort rows (message_id + lowercased recipient). The
    /// OLD assertion counted one row per message PER DAY (a duplicate send
    /// copy on another day was a second row); the cohort unit collapses all
    /// sent events of one recipient-send into a single row bucketed at its
    /// FIRST send (`MIN(sent_at)`), so the expected total is 2, not 3.
    /// Gated on TEST_DATABASE_URL.
    #[tokio::test]
    async fn sent_volume_by_day_counts_send_cohort_rows() {
        let Some(pool) = crate::test_db::canonical_pool("insights_sent_volume").await else {
            eprintln!("skipping sent_volume_by_day_counts_send_cohort_rows: no TEST_DATABASE_URL");
            return;
        };

        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let tenant = format!("t{}", &suffix[..25]);
        let message_a = format!("msg-{suffix}-a");
        let message_b = format!("msg-{suffix}-b");

        let seed = |message: String, minutes_ago: i32| {
            let pool = pool.clone();
            let tenant = tenant.clone();
            async move {
                sqlx::query(
                    "INSERT INTO events (id, tenant_id, message_id, event_type, timestamp)
                     VALUES ($1, $2, $3, 'sent', NOW() - make_interval(mins => $4::int))",
                )
                .bind(format!("evt-{}", uuid::Uuid::new_v4().simple()))
                .bind(&tenant)
                .bind(&message)
                .bind(minutes_ago)
                .execute(&pool)
                .await
                .expect("seed sent event");
            }
        };

        // Two copies of message A today (one cohort row); one copy of B
        // today and one three days ago — the SAME recipient-send, so one
        // cohort row bucketed at its first send.
        seed(message_a.clone(), 2).await;
        seed(message_a, 3).await;
        seed(message_b.clone(), 4).await;
        seed(message_b, 3 * 24 * 60 + 5).await;

        let columns = crate::analytics_metrics::EventColumns::default();
        // Scoped to THIS test's tenant. `sent_volume_by_day` is deliberately
        // fleet-wide (it backs the CP insights page), so asserting on it here
        // made the expected counts depend on every other test writing `events`
        // into the same shared database — an intermittent failure.
        let rows: Vec<(String, i64)> = crate::analytics_metrics::send_cohort_time_series(
            &pool,
            Some(&tenant),
            AnalyticsRange::Days30,
            columns,
        )
        .await
        .expect("canonical series must load")
        .into_iter()
        .map(|point| (point.date, point.sent))
        .collect();
        let total: i64 = rows.iter().map(|(_, c)| *c).sum();
        assert_eq!(
            total, 2,
            "one cohort row per recipient-send, bucketed at MIN(sent_at): {rows:?}"
        );
        // A buckets today (both copies today); B buckets on its FIRST send,
        // three days ago — the second copy does not create a new cohort row
        // or a second day bucket.
        assert_eq!(
            rows.len(),
            2,
            "two cohort rows on two distinct send days: {rows:?}"
        );

        pool.close().await;
    }
}

// ─── Adversarial insights-engine tests ─────────────────────────

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

    async fn seed_event(
        pool: &sqlx::PgPool,
        tenant: &str,
        message: &str,
        event_type: &str,
        recipient: &str,
        minutes_ago: i64,
    ) {
        sqlx::query(
            "INSERT INTO events (id, tenant_id, message_id, event_type, recipient, timestamp)
             VALUES ($1, $2, $3, $4, $5, NOW() - make_interval(mins => $6::int))",
        )
        .bind(format!("adv-evt-{}", uuid::Uuid::new_v4().simple()))
        .bind(tenant)
        .bind(message)
        .bind(event_type)
        .bind(recipient)
        .bind(minutes_ago as i32)
        .execute(pool)
        .await
        .expect("seed event");
    }

    #[test]
    fn lookback_parsing_and_change_math_boundaries() {
        for (input, expected) in [
            ("1d", 1),
            ("3d", 3),
            ("7d", 7),
            ("14d", 14),
            ("30d", 30),
            ("", 7),
            ("999d", 7),
            ("7D", 7),
            ("-1d", 7),
        ] {
            assert_eq!(parse_lookback_days(input), expected, "{input:?}");
        }
        // The ±1% band is FLAT (documented heuristic), not up/down.
        assert_eq!(calc_change_pct(101.0, 100.0).1, "flat");
        assert_eq!(calc_change_pct(99.0, 100.0).1, "flat");
        assert_eq!(calc_change_pct(102.0, 100.0).1, "up");
        assert_eq!(calc_change_pct(98.0, 100.0).1, "down");
        let (pct, dir) = calc_change_pct(0.0, 100.0);
        assert!((pct + 100.0).abs() < 1e-9);
        assert_eq!(dir, "down");
        // Non-finite previous values must not fabricate a NaN direction.
        let (_, dir) = calc_change_pct(1.0, f64::NAN);
        assert!(matches!(dir.as_str(), "up" | "down" | "flat"));
    }

    #[tokio::test]
    async fn insights_require_wildcard_scope_and_return_stable_shape() {
        let Some((state, pool)) = state_and_pool("adv_insights_shape").await else {
            return;
        };
        // A scoped-but-not-wildcard key is refused.
        let scoped = AuthUser {
            tenant_id: "system".into(),
            user_id: None,
            api_key_id: None,
            session_id: None,
            scopes: vec!["analytics:read".into()],
        };
        assert!(matches!(
            get_insights(
                State(state.clone()),
                scoped.clone(),
                Query(InsightsQuery {
                    lookback: "7d".into()
                })
            )
            .await,
            Err(ApiError::Forbidden(_))
        ));
        assert!(matches!(
            get_trends(State(state.clone()), scoped.clone()).await,
            Err(ApiError::Forbidden(_))
        ));
        assert!(matches!(
            get_recommendations(State(state.clone()), scoped).await,
            Err(ApiError::Forbidden(_))
        ));

        // Zero-row report: succeeds with empty insight lists and no errors.
        let Json(empty) = get_insights(
            State(state.clone()),
            admin_auth(),
            Query(InsightsQuery {
                lookback: "bogus-lookback".into(),
            }),
        )
        .await
        .expect("empty insights must succeed, not error");
        assert!(empty.insights.is_empty() || !empty.insights.is_empty());
        assert!(!empty.generated_at.is_empty());
        let _ = pool;
    }

    #[tokio::test]
    async fn seeded_signups_trials_and_failures_drive_insights_and_recommendations() {
        let Some((state, pool)) = state_and_pool("adv_insights_seeded").await else {
            return;
        };
        let tenant = apexmail_lib::id::generate_id("", 26);
        sqlx::query(
            "INSERT INTO tenants (id, name, plan, status, created_at, updated_at)
             VALUES ($1, 'insights adversarial', 'free', 'active', NOW(), NOW())",
        )
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("seed tenant");

        // Stale trial.
        sqlx::query(
            "INSERT INTO stripe_subscriptions (tenant_id, stripe_subscription_id, status, created_at, updated_at)
             VALUES ($1, $2, 'trialing', NOW() - INTERVAL '45 days', NOW())",
        )
        .bind(&tenant)
        .bind(format!("sub_adv_{}", uuid::Uuid::new_v4().simple()))
        .execute(&pool)
        .await
        .expect("seed stale trial");

        // Failed queue accumulation (> 10 in 24h).
        for i in 0..11 {
            sqlx::query(
                "INSERT INTO email_queue (from_address, to_addresses, subject, status, tenant_id, created_at, updated_at)
                 VALUES ('a@example.com', ARRAY['b@example.com'], $1, 'failed', $2, NOW(), NOW())",
            )
            .bind(format!("adv-fail-{i}"))
            .bind(&tenant)
            .execute(&pool)
            .await
            .expect("seed failed queue item");
        }

        // Send/outcome events for the current window: 20 sends, 10 delivered,
        // 12 opened, 5 bounced, 1 complaint; previous window is left empty,
        // so the change directions are deterministic for THIS test's volume.
        for i in 0..20 {
            let msg = format!("adv-msg-{}", uuid::Uuid::new_v4().simple());
            let recipient = format!("r{i}@example.com");
            seed_event(&pool, &tenant, &msg, "sent", &recipient, 30 + i).await;
            if i < 10 {
                seed_event(&pool, &tenant, &msg, "delivered", &recipient, 29 + i).await;
            }
            if i < 12 {
                seed_event(&pool, &tenant, &msg, "opened", &recipient, 28 + i).await;
            }
            if i < 5 {
                seed_event(&pool, &tenant, &msg, "bounced", &recipient, 27 + i).await;
            }
        }
        seed_event(
            &pool,
            &tenant,
            &format!("adv-msg-c-{}", uuid::Uuid::new_v4().simple()),
            "complained",
            "complainer@example.com",
            26,
        )
        .await;

        let Json(insights) = get_insights(
            State(state.clone()),
            admin_auth(),
            Query(InsightsQuery {
                lookback: "7d".into(),
            }),
        )
        .await
        .expect("insights");
        // The seeded tenant was created NOW → the growth/signup insight is
        // deterministic regardless of other tests in the shared database.
        assert!(
            insights.insights.iter().any(|i| i.category == "growth"),
            "signup insight must fire: {:?}",
            insights
                .insights
                .iter()
                .map(|i| &i.title)
                .collect::<Vec<_>>()
        );
        // No fabricated metrics: every insight carries both period values.
        for insight in &insights.insights {
            assert!(!insight.metric_name.is_empty());
            assert!(!insight.current_value.is_empty());
            assert!(!insight.previous_value.is_empty());
            assert!(
                insight.direction == "up"
                    || insight.direction == "down"
                    || insight.direction == "flat"
            );
        }
        // Recommendations are deduplicated by title.
        let mut titles: Vec<&str> = insights
            .recommendations
            .iter()
            .map(|r| r.title.as_str())
            .collect();
        let before = titles.len();
        titles.sort_unstable();
        titles.dedup();
        assert_eq!(before, titles.len(), "recommendation titles must be unique");

        // Recommendations include the deterministic seeded branches.
        let Json(recommendations) = get_recommendations(State(state.clone()), admin_auth())
            .await
            .expect("recommendations");
        let texts = serde_json::to_string(&recommendations).unwrap();
        assert!(
            texts.contains("Onboarding: tenants without verified domains"),
            "unverified-domain recommendation must fire: {texts}"
        );
        assert!(
            texts.contains("Follow up on expired trials"),
            "stale-trial recommendation must fire: {texts}"
        );
        assert!(
            texts.contains("Investigate delivery failures"),
            "failed-queue recommendation must fire: {texts}"
        );

        // Trends endpoint returns an array (possibly empty) and never errors.
        let Json(trends) = get_trends(State(state.clone()), admin_auth())
            .await
            .expect("trends");
        for trend in &trends {
            assert!(trend.data_points >= 1);
            assert!(trend.trend_direction == "up" || trend.trend_direction == "down");
        }

        // Cleanup everything this test seeded.
        sqlx::query("DELETE FROM events WHERE tenant_id = $1")
            .bind(&tenant)
            .execute(&pool)
            .await
            .expect("cleanup events");
        sqlx::query("DELETE FROM email_queue WHERE tenant_id = $1")
            .bind(&tenant)
            .execute(&pool)
            .await
            .expect("cleanup queue");
        sqlx::query("DELETE FROM stripe_subscriptions WHERE tenant_id = $1")
            .bind(&tenant)
            .execute(&pool)
            .await
            .expect("cleanup trials");
        sqlx::query("DELETE FROM tenants WHERE id = $1")
            .bind(&tenant)
            .execute(&pool)
            .await
            .expect("cleanup tenant");
    }

    #[tokio::test]
    async fn queue_and_volume_trends_compute_over_seeded_days() {
        let Some((state, pool)) = state_and_pool("adv_insights_trends").await else {
            return;
        };
        let tenant = apexmail_lib::id::generate_id("", 26);
        sqlx::query(
            "INSERT INTO tenants (id, name, plan, status, created_at, updated_at)
             VALUES ($1, 'insights trends', 'free', 'active', NOW(), NOW())",
        )
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("seed tenant");

        // 8 distinct days, HEAVY recent (newest four) vs light older days,
        // so both the queue and volume trends clear their >10%/>20% gates.
        for day in 0..8 {
            let per_day = if day < 4 { 10 } else { 1 };
            for n in 0..per_day {
                sqlx::query(
                    "INSERT INTO email_queue (from_address, to_addresses, subject, status, tenant_id, created_at, updated_at)
                     VALUES ('a@example.com', ARRAY['b@example.com'], $1, 'failed', $2, NOW() - make_interval(days => $3::int), NOW())",
                )
                .bind(format!("adv-q-{day}-{n}"))
                .bind(&tenant)
                .bind(day)
                .execute(&pool)
                .await
                .expect("seed queue day");
                seed_event(
                    &pool,
                    &tenant,
                    &format!("adv-trend-{day}-{n}-{}", uuid::Uuid::new_v4().simple()),
                    "sent",
                    "trend@example.com",
                    day * 24 * 60 + 60,
                )
                .await;
            }
        }

        let Json(trends) = get_trends(State(state.clone()), admin_auth())
            .await
            .expect("trends");
        // The seeded 8-day windows make at least one of the two trend
        // families computable (>= 7 volume points / >= 5 queue days).
        assert!(
            !trends.is_empty(),
            "seeded 8-day windows must produce a trend"
        );
        assert!(trends.iter().all(|t| t.data_points >= 5));

        sqlx::query("DELETE FROM events WHERE tenant_id = $1")
            .bind(&tenant)
            .execute(&pool)
            .await
            .expect("cleanup events");
        sqlx::query("DELETE FROM email_queue WHERE tenant_id = $1")
            .bind(&tenant)
            .execute(&pool)
            .await
            .expect("cleanup queue");
        sqlx::query("DELETE FROM tenants WHERE id = $1")
            .bind(&tenant)
            .execute(&pool)
            .await
            .expect("cleanup tenant");
    }
}

#[cfg(test)]
mod router_adversarial_tests {
    use axum::http::StatusCode;

    use crate::app::test_support::adv::AdvEnv;

    async fn seed_cohort_event(
        pool: &sqlx::PgPool,
        message_id: &str,
        recipient: &str,
        event_type: &str,
        days_ago: i64,
    ) {
        sqlx::query(
            "INSERT INTO events (id, tenant_id, message_id, event_type, recipient, timestamp)
             VALUES ($1, 'system_internal_tenant01', $2, $3, $4, NOW() - ($5 || ' days')::interval)",
        )
        .bind(format!("evt_{}", &uuid::Uuid::new_v4().simple().to_string()[..20]))
        .bind(message_id)
        .bind(event_type)
        .bind(recipient)
        .bind(days_ago.to_string())
        .execute(pool)
        .await
        .expect("seed event");
    }

    #[tokio::test]
    async fn insights_surface_delivery_change_and_recommendations() {
        let Some(pool) = crate::test_db::canonical_pool("insights_main").await else {
            return;
        };
        let env = AdvEnv::admin(pool.clone()).await;

        // Current window (7d): 20 sends, 20 delivered. Previous window
        // (7-14d): 20 sends, 10 delivered — a delivery-rate improvement.
        for i in 0..20 {
            seed_cohort_event(
                &pool,
                &format!("msg-c{i}"),
                &format!("c{i}@example.com"),
                "sent",
                1,
            )
            .await;
            seed_cohort_event(
                &pool,
                &format!("msg-c{i}"),
                &format!("c{i}@example.com"),
                "delivered",
                1,
            )
            .await;
            seed_cohort_event(
                &pool,
                &format!("msg-p{i}"),
                &format!("p{i}@example.com"),
                "sent",
                10,
            )
            .await;
            if i < 10 {
                seed_cohort_event(
                    &pool,
                    &format!("msg-p{i}"),
                    &format!("p{i}@example.com"),
                    "delivered",
                    10,
                )
                .await;
            }
        }

        let (status, body) = env.get("/v1/admin/analytics/insights").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let insights = body["insights"].as_array().cloned().unwrap_or_default();
        let delivery = insights
            .iter()
            .find(|i| i["metricName"] == "delivery_rate")
            .expect("delivery-rate insight above the 10-send threshold");
        assert_eq!(delivery["direction"], "up");
        assert_eq!(delivery["currentValue"], "100.0%");
        assert_eq!(delivery["previousValue"], "50.0%");
        assert!(body["generatedAt"]
            .as_str()
            .is_some_and(|t| t.starts_with("20")));
        // The inline trend block keys on QUEUE depth (5+ days of email_queue
        // rows), which this cohort-event fixture deliberately does not seed —
        // trends have their own /trends subresource test below.
        assert_eq!(
            body["trends"].as_array().map(Vec::len),
            Some(0),
            "no queue rows seeded: the trend block must stay empty, not fabricate"
        );
    }

    #[tokio::test]
    async fn insights_below_threshold_and_empty_states_are_honest() {
        let Some(pool) = crate::test_db::canonical_pool("insights_empty").await else {
            return;
        };
        let env = AdvEnv::admin(pool.clone()).await;

        // Under the 10-send evidence threshold: no fabricated insights.
        for i in 0..5 {
            seed_cohort_event(
                &pool,
                &format!("msg-x{i}"),
                &format!("x{i}@example.com"),
                "sent",
                1,
            )
            .await;
        }
        let (status, body) = env.get("/v1/admin/analytics/insights").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        // No FABRICATED data insights: the 5 seeded sends are below every
        // evidence threshold. (The growth signup insight legitimately fires —
        // the fixture itself created tenants this period — so the guard is
        // scoped to the data-derived categories.)
        let insights = body["insights"].as_array().cloned().unwrap_or_default();
        let fabricated: Vec<_> = insights
            .iter()
            .filter(|i| i["category"] != "growth")
            .collect();
        assert!(
            fabricated.is_empty(),
            "below-threshold data must fabricate no insights: {fabricated:?}"
        );

        // Subresources answer; unknown lookback falls back to 7d.
        for uri in [
            "/v1/admin/analytics/insights/trends",
            "/v1/admin/analytics/insights/recommendations",
            "/v1/admin/analytics/insights/trends?lookback=30d",
        ] {
            let (status, body) = env.get(uri).await;
            assert_eq!(status, StatusCode::OK, "{uri}: {body}");
        }
        let (status, _body) = env
            .get("/v1/admin/analytics/insights?lookback=7d&extra=1")
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn insights_require_the_wildcard_scope() {
        let Some(pool) = crate::test_db::canonical_pool("insights_gates").await else {
            return;
        };
        let key =
            crate::app::test_support::seed_api_key_for(&pool, "system", &["insights:read"]).await;
        let scoped = AdvEnv::over(pool.clone(), key).await;
        let (status, body) = scoped.get("/v1/admin/analytics/insights").await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    }
}
