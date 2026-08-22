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

/// A stream that yields `()` every `period`, implemented with `futures`
/// primitives so this crate does not need a `tokio-stream` dependency.
fn interval_stream(period: Duration) -> impl futures::Stream<Item = ()> {
    futures::stream::unfold((), move |_| async move {
        tokio::time::sleep(period).await;
        Some(((), ()))
    })
}

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

async fn query_dashboard_snapshot(db: &sqlx::PgPool) -> DashboardSsePayload {
    let tenants = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*)::bigint FROM tenants WHERE status = 'active'",
    )
    .fetch_one(db)
    .await
    .unwrap_or(0);

    let queue = if table_exists(db, "queue_jobs").await {
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*)::bigint FROM queue_jobs WHERE status = 'pending'",
        )
        .fetch_one(db)
        .await
        .unwrap_or(0)
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

        let cents = sqlx::query_scalar::<_, i64>(&sql)
            .fetch_one(db)
            .await
            .unwrap_or(0);
        cents as f64 / 100.0
    } else {
        0.0
    };

    let health_status = if table_exists(db, "system_alerts").await {
        let critical_count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*)::bigint FROM system_alerts WHERE acknowledged = false AND severity = 'critical'",
        )
        .fetch_one(db)
        .await
        .unwrap_or(0);

        let high_count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*)::bigint FROM system_alerts WHERE acknowledged = false AND severity = 'high'",
        )
        .fetch_one(db)
        .await
        .unwrap_or(0);

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

    DashboardSsePayload {
        mrr,
        tenants,
        queue,
        health_status,
    }
}

async fn sse_dashboard(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Sse<impl futures::Stream<Item = Result<Event, Infallible>>>, ApiError> {
    require_scopes(&auth, &["*"])?;

    let db = state.db.clone();
    let stream = interval_stream(Duration::from_secs(5)).then(move |_| {
        let db = db.clone();
        async move {
            let snapshot = query_dashboard_snapshot(&db).await;
            let json = serde_json::to_string(&snapshot).unwrap_or_default();
            Ok(Event::default().data(json).event("dashboard"))
        }
    });

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

    let initial_alerts = query_new_alerts(&db, now - chrono::Duration::hours(24))
        .await
        .unwrap_or_default();

    let last_seen = Arc::new(Mutex::new(now));

    let stream = futures::stream::iter(
        initial_alerts
            .into_iter()
            .map(|alert| {
                let json = serde_json::to_string(&alert).unwrap_or_default();
                Ok(Event::default().data(json).event("alert"))
            })
            .collect::<Vec<_>>(),
    )
    .chain(
        interval_stream(Duration::from_secs(10))
            .then({
                let db = db.clone();
                let last_seen = Arc::clone(&last_seen);
                move |_| {
                    let db = db.clone();
                    let last_seen = Arc::clone(&last_seen);
                    async move {
                        let mut ls = last_seen.lock().await;
                        let alerts = query_new_alerts(&db, *ls).await.unwrap_or_default();

                        if let Some(latest) = alerts
                            .iter()
                            .filter_map(|a| {
                                chrono::DateTime::parse_from_rfc3339(&a.timestamp)
                                    .ok()
                                    .map(|t| t.with_timezone(&Utc))
                            })
                            .max()
                        {
                            *ls = latest;
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
                }
            })
            .flat_map(futures::stream::iter),
    );

    Ok(Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keep-alive"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alerts_sql_aliases_real_system_alerts_columns() {
        // system_alerts has created_at (not timestamp) and gained `component`
        // in migration 108 — the query must reference real columns only.
        assert!(NEW_ALERTS_SQL.contains("created_at AS timestamp"));
        assert!(NEW_ALERTS_SQL.contains("COALESCE(component, alert_type)"));
        assert!(!NEW_ALERTS_SQL.contains("WHERE timestamp"));
    }
}
