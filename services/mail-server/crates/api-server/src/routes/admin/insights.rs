//! Insights engine — auto-generates actionable insights from analytics data.
//!
//! Compares recent metrics against historical baselines and surfaces meaningful
//! observations. Every insight is backed by real database queries. If a metric
//! comparison returns no data, the insight is not generated (no fabricated content).
//!
//! Metric conventions come from [`crate::analytics_metrics`]: comparisons use
//! event-occurrence windows over DISTINCT messages, so repeat opens/clicks on
//! one message cannot fake an engagement change and current message status is
//! never mixed into a historical cohort.

use axum::extract::{Query, State};
use axum::routing::get;
use axum::{Json, Router};
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::analytics_metrics::{
    detect_event_columns, distinct_message_counts, distinct_message_counts_previous, EventColumns,
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

/// Successful sends per day, by event occurrence (DISTINCT messages).
/// `days` is bound, never rendered into SQL.
async fn sent_volume_by_day(
    db: &sqlx::PgPool,
    columns: EventColumns,
    days: i32,
) -> Vec<(String, i64)> {
    let type_col = columns.type_col.as_sql();
    let time_col = columns.time_col.as_sql();

    sqlx::query_as::<_, (String, i64)>(&format!(
        "SELECT DATE({time_col})::text, COUNT(DISTINCT message_id)::bigint
         FROM events
         WHERE {type_col} = 'sent' AND {time_col} >= NOW() - make_interval(days => $1::int)
         GROUP BY DATE({time_col}) ORDER BY 1"
    ))
    .bind(days)
    .fetch_all(db)
    .await
    .unwrap_or_default()
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

    // Canonical, like-for-like period comparison: DISTINCT messages bucketed
    // by event occurrence, current window vs the immediately preceding one.
    let columns: EventColumns = detect_event_columns(&state).await;
    let current = distinct_message_counts(db, None, &interval, columns).await?;
    let previous = distinct_message_counts_previous(db, None, &interval, columns).await?;

    // ─── Delivery Rate Insight ──────────────────────────────────────────
    if current.sent > 10 {
        let (pct, dir) = calc_change_pct(current.delivery_rate(), previous.delivery_rate());
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
                    current.delivery_rate() * 100.0,
                    previous.delivery_rate() * 100.0,
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
                current_value: format!("{:.1}%", current.delivery_rate() * 100.0),
                previous_value: format!("{:.1}%", previous.delivery_rate() * 100.0),
                change_pct: pct,
                direction: dir,
            });
        }
    }

    // ─── Bounce Rate Insight ────────────────────────────────────────────
    if current.sent > 0 {
        let (pct, dir) = calc_change_pct(current.bounce_rate(), previous.bounce_rate());
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
                current_value: format!("{:.1}%", current.bounce_rate() * 100.0),
                previous_value: format!("{:.1}%", previous.bounce_rate() * 100.0),
                change_pct: pct,
                direction: dir,
            });
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
    // Successful sends bucketed by event occurrence — never message
    // creation, which counts mail that may never have left the queue.
    let volume_rows = sent_volume_by_day(db, columns, 30).await;

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

    // Send volume trend — successful sends by event occurrence.
    let columns: EventColumns = detect_event_columns(&state).await;
    let volume_rows = sent_volume_by_day(db, columns, 30).await;

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

    // Check bounce rate for DNS recommendation — canonical distinct-message
    // rate over event occurrence (fraction 0..1).
    let columns = detect_event_columns(&state).await;
    let counts = distinct_message_counts(db, None, "7 days", columns).await?;
    let bounce_rate = counts.bounce_rate();

    if bounce_rate > 0.05 {
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

    /// The volume trend counts DISTINCT successfully-sent messages by event
    /// occurrence: two send copies of one message on one day count once.
    /// Gated on TEST_DATABASE_URL.
    #[tokio::test]
    async fn sent_volume_by_day_counts_distinct_messages() {
        let Some(pool) = crate::test_db::canonical_pool("insights_sent_volume").await else {
            eprintln!("skipping sent_volume_by_day_counts_distinct_messages: no TEST_DATABASE_URL");
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

        // Two copies of message A today (count once), one copy of B today,
        // one copy of B three days ago (separate day bucket).
        seed(message_a.clone(), 2).await;
        seed(message_a, 3).await;
        seed(message_b.clone(), 4).await;
        seed(message_b, 3 * 24 * 60 + 5).await;

        let columns = crate::analytics_metrics::EventColumns::default();
        let rows = sent_volume_by_day(&pool, columns, 30).await;
        let total: i64 = rows.iter().map(|(_, c)| *c).sum();
        assert_eq!(total, 3, "duplicate send copies must count once: {rows:?}");

        pool.close().await;
    }
}
