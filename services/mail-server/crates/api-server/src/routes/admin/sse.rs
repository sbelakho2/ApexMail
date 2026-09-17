//! Server-Sent Events (SSE) endpoints for real-time admin dashboard and alert streaming.
//!
//! All endpoints require admin authentication. SSE streams push JSON events
//! at regular intervals with keep-alive pings for connection health.
//!
//! Mounted under the dashboard router (see `dashboard.rs`):
//! - `GET /v1/admin/dashboard/sse/dashboard` — live dashboard metrics every 5 seconds
//! - `GET /v1/admin/dashboard/sse/alerts` — real-time alert stream every 10 seconds

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::routing::get;
use axum::Router;
use chrono::{DateTime, Utc};
use futures::StreamExt;
use serde::Serialize;
use serde_json;
use tokio::sync::Mutex;

use crate::error::ApiError;
use crate::middleware::auth::{require_scopes, AuthUser};
use crate::routes::helpers::table_exists;
use crate::state::AppState;

/// Consecutive poll failures tolerated before the stream closes. Erroring
/// polls previously rendered healthy zeros (`unwrap_or(0)`), which is worse
/// than no dashboard: operators trust a silently dead metric.
const MAX_CONSECUTIVE_POLL_ERRORS: u32 = 3;

/// Hard lifetime cap for one SSE connection. The browser's EventSource
/// reconnects automatically, which re-runs the auth/scope gates.
const MAX_STREAM_DURATION: Duration = Duration::from_secs(30 * 60);

/// Live alerts poll interval.
const ALERTS_POLL_INTERVAL: Duration = Duration::from_secs(10);

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/dashboard", get(sse_dashboard))
        .route("/alerts", get(sse_alerts))
}

// ── Dashboard SSE ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct DashboardSsePayload {
    mrr: f64,
    tenants: i64,
    queue: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    health_status: Option<String>,
}

/// Errors PROPAGATE (P2): every query previously degraded to `unwrap_or(0)`,
/// so a DB outage rendered a healthy-looking all-zero dashboard.
async fn query_dashboard_snapshot(db: &sqlx::PgPool) -> Result<DashboardSsePayload, sqlx::Error> {
    let tenants = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*)::bigint FROM tenants WHERE status = 'active'",
    )
    .fetch_one(db)
    .await?;

    let queue = if table_exists(db, "queue_jobs").await {
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*)::bigint FROM queue_jobs WHERE status = 'pending'",
        )
        .fetch_one(db)
        .await?
    } else {
        0
    };

    // MRR from stripe_subscriptions — the table the billing webhook writers
    // populate — mirroring billing-service's get_mrr_report pattern (tenants.plan
    // → plans pricing, ROUND(price_yearly / 12.0) yearly normalization).
    // The legacy `subscriptions` table has no writer and always read as zero.
    let mrr = if table_exists(db, "stripe_subscriptions").await && table_exists(db, "plans").await {
        let has_billing_interval =
            crate::routes::helpers::column_exists(db, "stripe_subscriptions", "billing_interval")
                .await;

        let billing_interval_expr = if has_billing_interval {
            "COALESCE(NULLIF(s.billing_interval, ''), 'monthly')"
        } else {
            "'monthly'"
        };

        let sql = format!(
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
        );

        let cents = sqlx::query_scalar::<_, i64>(&sql).fetch_one(db).await?;
        cents as f64 / 100.0
    } else {
        0.0
    };

    let health_status = if table_exists(db, "system_alerts").await {
        let critical_count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*)::bigint FROM system_alerts WHERE acknowledged = false AND severity = 'critical'",
        )
        .fetch_one(db)
        .await?;

        let high_count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*)::bigint FROM system_alerts WHERE acknowledged = false AND severity = 'high'",
        )
        .fetch_one(db)
        .await?;

        Some(if critical_count >= 5 {
            "down".to_string()
        } else if critical_count > 0 || high_count > 0 {
            "degraded".to_string()
        } else {
            "healthy".to_string()
        })
    } else {
        None
    };

    Ok(DashboardSsePayload {
        mrr,
        tenants,
        queue,
        health_status,
    })
}

async fn sse_dashboard(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Sse<impl futures::Stream<Item = Result<Event, Infallible>>>, ApiError> {
    require_scopes(&auth, &["*"])?;

    let db = state.db.clone();
    // Bounded stream (P2): ends at MAX_STREAM_DURATION or after
    // MAX_CONSECUTIVE_POLL_ERRORS failing polls (degraded comment events in
    // between) — the browser's EventSource reconnects, which both resets
    // the window and re-runs the auth/scope gates. `unfold` owns the poll
    // state (scan's closure bounds reject futures that borrow it).
    let stream = futures::stream::unfold(
        (db, tokio::time::Instant::now() + MAX_STREAM_DURATION, 0u32),
        |mut poll_state| async move {
            tokio::time::sleep(Duration::from_secs(5)).await;
            if tokio::time::Instant::now() >= poll_state.1 {
                tracing::info!("admin dashboard SSE stream reached its time cap; closing");
                return None;
            }
            let event = match query_dashboard_snapshot(&poll_state.0).await {
                Ok(snapshot) => {
                    poll_state.2 = 0;
                    let json = serde_json::to_string(&snapshot).unwrap_or_default();
                    Ok(Event::default().data(json).event("dashboard"))
                }
                Err(error) => {
                    poll_state.2 += 1;
                    tracing::warn!(
                        error = %error,
                        consecutive_errors = poll_state.2,
                        "dashboard SSE poll failed"
                    );
                    if poll_state.2 >= MAX_CONSECUTIVE_POLL_ERRORS {
                        tracing::error!("dashboard SSE closing after repeated poll failures");
                        return Some((
                            Ok(Event::default().comment("dashboard-unavailable-stream-closing")),
                            poll_state,
                        ));
                    }
                    Ok(Event::default().comment("dashboard-unavailable"))
                }
            };
            Some((event, poll_state))
        },
    );

    Ok(Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keep-alive"),
    ))
}

// ── Alerts SSE ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
struct AlertSsePayload {
    id: String,
    severity: String,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    component: Option<String>,
    timestamp: String,
    acknowledged: bool,
}

/// system_alerts has no `timestamp` column — its time column is `created_at`
/// (and `component` only exists after migration 108; fall back to
/// alert_type). The query aliases both, mirroring system_health.rs.
const NEW_ALERTS_SQL: &str = "SELECT id::text, severity, COALESCE(component, alert_type) as component, message, created_at AS timestamp, acknowledged
         FROM system_alerts
         WHERE created_at > $1
         ORDER BY created_at ASC
         LIMIT 50";

async fn query_new_alerts(
    db: &sqlx::PgPool,
    since: DateTime<Utc>,
) -> Result<Vec<AlertSsePayload>, sqlx::Error> {
    if !table_exists(db, "system_alerts").await {
        return Ok(Vec::new());
    }

    let rows: Vec<(String, String, String, String, DateTime<Utc>, bool)> =
        sqlx::query_as(NEW_ALERTS_SQL)
            .bind(since)
            .fetch_all(db)
            .await?;

    Ok(rows
        .into_iter()
        .map(
            |(id, severity, component, message, timestamp, acknowledged)| AlertSsePayload {
                id,
                severity,
                message,
                component: if component.is_empty() {
                    None
                } else {
                    Some(component)
                },
                timestamp: timestamp.to_rfc3339(),
                acknowledged,
            },
        )
        .collect())
}

async fn sse_alerts(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Sse<impl futures::Stream<Item = Result<Event, Infallible>>>, ApiError> {
    require_scopes(&auth, &["*"])?;

    let db = state.db.clone();
    let now = Utc::now();

    // Initial backlog errors propagate to the HTTP response (no stream on a
    // broken DB); poll errors below degrade to comments and close the
    // stream after repeated failures.
    let initial_alerts = query_new_alerts(&db, now - chrono::Duration::hours(24)).await?;

    let last_seen = Arc::new(Mutex::new(now));
    let poll_db = db.clone();
    let poll: AlertPollFn = Arc::new(move |since| {
        let db = poll_db.clone();
        Box::pin(async move { query_new_alerts(&db, since).await })
    });

    let stream = build_alerts_stream(initial_alerts, last_seen, poll);

    Ok(Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keep-alive"),
    ))
}

/// Boxed future produced by one live-alerts poll.
type AlertPollFuture = std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<Vec<AlertSsePayload>, sqlx::Error>> + Send>,
>;

/// The injectable poll used by [`build_alerts_stream`] (the handler wires it
/// to [`query_new_alerts`]; tests supply a counting fake).
type AlertPollFn = Arc<dyn Fn(DateTime<Utc>) -> AlertPollFuture + Send + Sync>;

/// Build the alerts SSE stream: the initial backlog, then a bounded
/// live-poll loop that stops at [`MAX_STREAM_DURATION`] or after
/// [`MAX_CONSECUTIVE_POLL_ERRORS`] failing polls. Extracted from the
/// handler so the deadline/cap behavior is testable under paused time
/// without a database.
fn build_alerts_stream(
    initial_alerts: Vec<AlertSsePayload>,
    last_seen: Arc<Mutex<DateTime<Utc>>>,
    poll: AlertPollFn,
) -> impl futures::Stream<Item = Result<Event, Infallible>> {
    let initial = futures::stream::iter(
        initial_alerts
            .into_iter()
            .map(|alert| {
                let json = serde_json::to_string(&alert).unwrap_or_default();
                Ok(Event::default().data(json).event("alert"))
            })
            .collect::<Vec<_>>(),
    );
    initial.chain(
        // Same bounded-poll contract as the dashboard stream; unfold owns
        // the state (see sse_dashboard).
        futures::stream::unfold(
            (
                last_seen,
                // CRITICAL: the deadline is the END of the polling window —
                // `Instant::now()` here closed the stream right after the
                // initial backlog instead of polling for MAX_STREAM_DURATION.
                tokio::time::Instant::now() + MAX_STREAM_DURATION,
                0u32,
            ),
            move |mut poll_state| {
                let poll = Arc::clone(&poll);
                async move {
                    tokio::time::sleep(ALERTS_POLL_INTERVAL).await;
                    if tokio::time::Instant::now() >= poll_state.1 {
                        tracing::info!("admin alerts SSE stream reached its time cap; closing");
                        return None;
                    }
                    let (last_seen, consecutive_errors) = (&poll_state.0, &mut poll_state.2);
                    let since = *last_seen.lock().await;
                    let outcome = match poll(since).await {
                        Ok(alerts) => {
                            *consecutive_errors = 0;
                            if let Some(latest) = alerts
                                .iter()
                                .filter_map(|a| {
                                    chrono::DateTime::parse_from_rfc3339(&a.timestamp)
                                        .ok()
                                        .map(|t| t.with_timezone(&Utc))
                                })
                                .max()
                            {
                                *last_seen.lock().await = latest;
                            }

                            let events: Vec<Result<Event, Infallible>> = alerts
                                .into_iter()
                                .map(|alert| {
                                    let json = serde_json::to_string(&alert).unwrap_or_default();
                                    Ok(Event::default().data(json).event("alert"))
                                })
                                .collect();

                            if events.is_empty() {
                                vec![Ok(Event::default().comment("no-new-alerts"))]
                            } else {
                                events
                            }
                        }
                        Err(error) => {
                            *consecutive_errors += 1;
                            tracing::warn!(
                                error = %error,
                                consecutive_errors,
                                "alerts SSE poll failed"
                            );
                            if *consecutive_errors >= MAX_CONSECUTIVE_POLL_ERRORS {
                                tracing::error!("alerts SSE closing after repeated poll failures");
                                vec![Ok(
                                    Event::default().comment("alerts-unavailable-stream-closing")
                                )]
                            } else {
                                vec![Ok(Event::default().comment("alerts-unavailable"))]
                            }
                        }
                    };
                    Some((futures::stream::iter(outcome), poll_state))
                }
            },
        )
        .flatten(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn alerts_sql_aliases_real_system_alerts_columns() {
        // system_alerts has created_at (not timestamp) and gained `component`
        // in migration 108 — the query must reference real columns only.
        assert!(NEW_ALERTS_SQL.contains("created_at AS timestamp"));
        assert!(NEW_ALERTS_SQL.contains("COALESCE(component, alert_type)"));
        assert!(!NEW_ALERTS_SQL.contains("WHERE timestamp"));
    }

    fn backlog_alert() -> AlertSsePayload {
        AlertSsePayload {
            id: "alert-backlog-1".into(),
            severity: "high".into(),
            message: "backlog".into(),
            component: None,
            timestamp: Utc::now().to_rfc3339(),
            acknowledged: false,
        }
    }

    /// Fix 5 regression: the live-poll deadline must be the END of the
    /// 30-minute window. Initializing it to `Instant::now()` closed the
    /// stream right after the first sleep (before any live poll); this test
    /// runs under paused time and proves polling continues past the initial
    /// backlog and stops only at the MAX_STREAM_DURATION cap.
    #[tokio::test(start_paused = true)]
    async fn alerts_stream_polls_after_backlog_and_stops_at_cap() {
        let poll_calls = Arc::new(AtomicUsize::new(0));
        let calls = Arc::clone(&poll_calls);
        let poll: AlertPollFn = Arc::new(move |_since| {
            let calls = Arc::clone(&calls);
            Box::pin(async move {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(Vec::new())
            })
        });

        let mut stream = Box::pin(build_alerts_stream(
            vec![backlog_alert()],
            Arc::new(Mutex::new(Utc::now())),
            poll,
        ));

        // The backlog is emitted first, before any live poll.
        let first = stream
            .next()
            .await
            .expect("initial backlog event")
            .expect("infallible event");
        assert!(format!("{first:?}").contains("alert-backlog-1"));
        assert_eq!(poll_calls.load(Ordering::SeqCst), 0);

        // Drain the rest under paused time: tokio auto-advances to each 10s
        // sleep, so the whole 30-minute window runs without real waiting.
        let mut live_events = 0usize;
        while stream.next().await.is_some() {
            live_events += 1;
        }

        let polls = poll_calls.load(Ordering::SeqCst);
        assert!(
            polls >= 1,
            "live polling must continue after the initial backlog \
             (the deadline was previously initialized to now)"
        );
        assert_eq!(
            live_events, polls,
            "each empty poll emits exactly one comment event"
        );
        assert_eq!(
            polls,
            (MAX_STREAM_DURATION.as_secs() / ALERTS_POLL_INTERVAL.as_secs()) as usize - 1,
            "the stream must stop only at the MAX_STREAM_DURATION cap"
        );
    }
}

#[cfg(test)]
mod adversarial_tests {
    use super::{query_dashboard_snapshot, query_new_alerts};
    use axum::http::StatusCode;
    use futures::StreamExt;
    use tower::ServiceExt;

    use crate::app::test_support::adv::AdvEnv;

    /// Issue an SSE request and return (status, content-type, FIRST stream
    /// frame text). Only the first frame is awaited: the live-poll loop
    /// sleeps 5-10s per tick by design, so a full drain would be a slow
    /// test; the bounded-stream semantics are already pinned by the
    /// paused-time tests on `build_alerts_stream` above.
    async fn sse_first_frame(env: &AdvEnv, uri: &str) -> (StatusCode, String, Option<String>) {
        let request = axum::http::Request::get(uri)
            .header("x-api-key", &env.credential)
            .body(axum::body::Body::empty())
            .unwrap();
        let response = env.app.clone().oneshot(request).await.expect("response");
        let status = response.status();
        let content_type = response
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        let (mut parts, body) = response.into_parts();
        let _ = &mut parts;
        let mut stream = body.into_data_stream();
        let mut first = String::new();
        // The alerts backlog is emitted immediately; the dashboard's first
        // snapshot arrives after its 5s tick, so take whatever is ready.
        if let Ok(Some(Ok(bytes))) =
            tokio::time::timeout(std::time::Duration::from_millis(50), stream.next()).await
        {
            first = String::from_utf8_lossy(&bytes).to_string();
        }
        (
            status,
            content_type,
            if first.is_empty() { None } else { Some(first) },
        )
    }

    #[tokio::test]
    async fn dashboard_sse_answers_with_an_event_stream() {
        let Some(pool) = crate::test_db::canonical_pool("sse_dash").await else {
            return;
        };
        let env = AdvEnv::admin(pool.clone()).await;
        sqlx::query(
            "INSERT INTO tenants (id, name, slug, plan, status) VALUES ($1, 'sse probe', $2, 'free', 'active')",
        )
        .bind(format!("sset{}", &uuid::Uuid::new_v4().simple().to_string()[..17]))
        .bind("sse-slug")
        .execute(&pool)
        .await
        .expect("seed tenant");

        let (status, content_type, _first) =
            sse_first_frame(&env, "/v1/admin/dashboard/sse/dashboard").await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            content_type.starts_with("text/event-stream"),
            "{content_type}"
        );
    }

    #[tokio::test]
    async fn alerts_sse_replays_the_backlog_immediately() {
        let Some(pool) = crate::test_db::canonical_pool("sse_alerts").await else {
            return;
        };
        let env = AdvEnv::admin(pool.clone()).await;
        // Canonical severity vocabulary: info/warning/critical.
        sqlx::query(
            "INSERT INTO system_alerts (id, severity, alert_type, message, acknowledged, created_at)
             VALUES ($1, 'critical', 'delivery', 'alert backlog probe', false, NOW())",
        )
        .bind(uuid::Uuid::new_v4())
        .execute(&pool)
        .await
        .expect("seed alert");

        let (status, content_type, first) =
            sse_first_frame(&env, "/v1/admin/dashboard/sse/alerts").await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            content_type.starts_with("text/event-stream"),
            "{content_type}"
        );
        let first = first.expect("the 24h backlog streams immediately");
        assert!(first.contains("event: alert"), "{first}");
        assert!(first.contains("alert backlog probe"), "{first}");
        assert!(first.contains("\"severity\":\"critical\""), "{first}");
        // component falls back to alert_type when the column is empty.
        assert!(first.contains("\"component\":\"delivery\""), "{first}");
    }

    #[tokio::test]
    async fn sse_routes_require_the_wildcard_scope() {
        let Some(pool) = crate::test_db::canonical_pool("sse_scope").await else {
            return;
        };
        let key =
            crate::app::test_support::seed_api_key_for(&pool, "system", &["dashboard:read"]).await;
        let env = AdvEnv::over(pool, key).await;
        for uri in [
            "/v1/admin/dashboard/sse/dashboard",
            "/v1/admin/dashboard/sse/alerts",
        ] {
            let (status, _ct, _first) = sse_first_frame(&env, uri).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{uri}");
        }
    }

    // ── The snapshot queries the streams poll (direct, deterministic) ──

    #[tokio::test]
    async fn dashboard_snapshot_aggregates_tenants_queue_mrr_and_health() {
        let Some(pool) = crate::test_db::canonical_pool("sse_snapshot").await else {
            return;
        };
        // One active tenant (the seeded system tenant is active already);
        // seed plan + active stripe subscription so MRR is non-zero.
        sqlx::query(
            "INSERT INTO plans (id, name, display_name, description, price_monthly, price_yearly,
                                email_limit, api_call_limit, features, is_active, sort_order)
             VALUES ('plan_sse_probe', 'sse-probe', 'SSE Probe', '', 12000, 120000, 0, 0,
                     '{}'::jsonb, true, 0)
             ON CONFLICT (name) DO NOTHING",
        )
        .execute(&pool)
        .await
        .expect("seed plan");
        sqlx::query("UPDATE tenants SET plan = 'sse-probe' WHERE id = 'system_internal_tenant01'")
            .execute(&pool)
            .await
            .expect("set plan");
        sqlx::query(
            "INSERT INTO stripe_subscriptions
                (id, tenant_id, stripe_subscription_id, status, billing_interval)
             VALUES ($1, 'system_internal_tenant01', 'sub_sse_probe', 'active', 'monthly')",
        )
        .bind(uuid::Uuid::new_v4())
        .execute(&pool)
        .await
        .expect("seed subscription");

        // No unacknowledged critical/high alerts: healthy.
        let snapshot = query_dashboard_snapshot(&pool).await.expect("snapshot");
        assert!(snapshot.tenants >= 1);
        assert_eq!(snapshot.mrr, 120.0, "monthly price in currency units");
        assert_eq!(snapshot.queue, 0);
        assert_eq!(snapshot.health_status.as_deref(), Some("healthy"));

        // One unacknowledged critical alert degrades health.
        sqlx::query(
            "INSERT INTO system_alerts (id, severity, alert_type, message, acknowledged)
             VALUES ($1, 'critical', 'delivery', 'degrade probe', false)",
        )
        .bind(uuid::Uuid::new_v4())
        .execute(&pool)
        .await
        .expect("seed critical alert");
        let snapshot = query_dashboard_snapshot(&pool).await.expect("snapshot");
        assert_eq!(snapshot.health_status.as_deref(), Some("degraded"));

        // Five unacknowledged critical alerts take it down.
        for _ in 0..4 {
            sqlx::query(
                "INSERT INTO system_alerts (id, severity, alert_type, message, acknowledged)
                 VALUES ($1, 'critical', 'delivery', 'downward probe', false)",
            )
            .bind(uuid::Uuid::new_v4())
            .execute(&pool)
            .await
            .expect("seed critical alert");
        }
        let snapshot = query_dashboard_snapshot(&pool).await.expect("snapshot");
        assert_eq!(snapshot.health_status.as_deref(), Some("down"));

        // Acknowledged alerts never count.
        sqlx::query("UPDATE system_alerts SET acknowledged = true")
            .execute(&pool)
            .await
            .expect("acknowledge all");
        let snapshot = query_dashboard_snapshot(&pool).await.expect("snapshot");
        assert_eq!(snapshot.health_status.as_deref(), Some("healthy"));

        // Yearly subscriptions normalise to price_yearly/12.
        sqlx::query("UPDATE stripe_subscriptions SET billing_interval = 'yearly'")
            .execute(&pool)
            .await
            .expect("flip interval");
        let snapshot = query_dashboard_snapshot(&pool).await.expect("snapshot");
        assert_eq!(snapshot.mrr, 100.0, "120000 cents / 12 months / 100");
    }

    #[tokio::test]
    async fn new_alerts_query_scopes_by_time_and_maps_fields() {
        let Some(pool) = crate::test_db::canonical_pool("sse_new_alerts").await else {
            return;
        };
        let fresh = query_new_alerts(&pool, chrono::Utc::now() - chrono::Duration::hours(1))
            .await
            .expect("query");
        assert!(fresh.is_empty(), "no backlog in a fresh database");

        sqlx::query(
            "INSERT INTO system_alerts (id, severity, alert_type, message, acknowledged, created_at)
             VALUES ($1, 'warning', 'backup', 'fresh warning', false, NOW())",
        )
        .bind(uuid::Uuid::new_v4())
        .execute(&pool)
        .await
        .expect("seed warning");
        sqlx::query(
            "INSERT INTO system_alerts (id, severity, alert_type, message, acknowledged, created_at)
             VALUES ($1, 'info', 'legacy', 'ancient info', false, NOW() - INTERVAL '3 days')",
        )
        .bind(uuid::Uuid::new_v4())
        .execute(&pool)
        .await
        .expect("seed old info");

        let since = chrono::Utc::now() - chrono::Duration::hours(24);
        let alerts = query_new_alerts(&pool, since).await.expect("query");
        assert_eq!(alerts.len(), 1, "only the in-window alert is returned");
        assert_eq!(alerts[0].severity, "warning");
        assert_eq!(alerts[0].message, "fresh warning");
        assert_eq!(alerts[0].component.as_deref(), Some("backup"));
        assert!(!alerts[0].acknowledged);
        assert!(alerts[0].timestamp.contains('T'));
    }
}
