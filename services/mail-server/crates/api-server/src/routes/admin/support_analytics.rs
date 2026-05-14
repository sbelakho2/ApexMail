//! Support ticket analytics endpoint.
//!

use axum::extract::{Query, State};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::time::Instant;
use tokio::sync::Mutex;

use crate::error::ApiError;
use crate::middleware::auth::AuthUser;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/", get(get_support_analytics))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupportAnalyticsQuery {
    #[serde(default = "default_days")]
    pub days: i64,
}

fn default_days() -> i64 {
    30
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SupportAnalytics {
    pub total_tickets: i64,
    pub open_tickets: i64,
    pub in_progress_tickets: i64,
    pub waiting_tickets: i64,
    pub resolved_tickets: i64,
    pub closed_tickets: i64,
    pub urgent_tickets: i64,
    pub avg_resolution_hours: f64,
    pub tickets_by_category: serde_json::Value,
    pub tickets_by_priority: serde_json::Value,
    pub tickets_over_time: Vec<TicketsOverTime>,
    pub top_tenants: Vec<TopTenant>,
    pub recent_tickets: Vec<RecentTicket>,
    pub response_time_buckets: serde_json::Value,
}

#[derive(Debug, Serialize, Clone)]
pub struct TicketsOverTime {
    pub date: String,
    pub count: i64,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct TopTenant {
    pub tenant_name: String,
    pub count: i64,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RecentTicket {
    pub id: String,
    pub subject: String,
    pub tenant_name: Option<String>,
    pub status: String,
    pub priority: String,
    pub category: Option<String>,
    pub created_at: String,
}

// 60-second in-memory cache
static CACHE: Mutex<Option<(Instant, i64, SupportAnalytics)>> = Mutex::const_new(None);

async fn get_support_analytics(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<SupportAnalyticsQuery>,
) -> Result<Json<SupportAnalytics>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    let days = params.days.clamp(1, 365);

    // Check cache
    let guard = CACHE.lock().await;
    if let Some((ts, cached_days, ref data)) = *guard {
        if ts.elapsed().as_secs() < 60 && cached_days == days {
            return Ok(Json(data.clone()));
        }
    }
    drop(guard);

    // Status counts
    let status_row = sqlx::query_as::<_, (i64, i64, i64, i64, i64, i64, i64)>(
        "SELECT
                COUNT(*),
                SUM(CASE WHEN status = 'open' THEN 1 ELSE 0 END),
                SUM(CASE WHEN status = 'in_progress' THEN 1 ELSE 0 END),
                SUM(CASE WHEN status = 'pending_customer' THEN 1 ELSE 0 END),
                SUM(CASE WHEN status = 'resolved' THEN 1 ELSE 0 END),
                SUM(CASE WHEN status = 'closed' THEN 1 ELSE 0 END),
                SUM(CASE WHEN priority = 'urgent' THEN 1 ELSE 0 END)
             FROM support_tickets WHERE created_at >= NOW() - $1::interval",
    )
    .bind(format!("{days} days"))
    .fetch_optional(&state.db)
    .await?
    .unwrap_or((0, 0, 0, 0, 0, 0, 0));

    // Average resolution time
    let avg_res: Option<(Option<f64>,)> = sqlx::query_as(
        "SELECT AVG(EXTRACT(EPOCH FROM (updated_at - created_at)) / 3600)
         FROM support_tickets WHERE status IN ('resolved', 'closed')",
    )
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten();

    // Category breakdown
    let cat_rows = sqlx::query_as::<_, (Option<String>, i64)>(
        "SELECT COALESCE(category, 'uncategorized'), COUNT(*)
             FROM support_tickets WHERE created_at >= NOW() - $1::interval
             GROUP BY category",
    )
    .bind(format!("{days} days"))
    .fetch_all(&state.db)
    .await?;

    let mut cat_map = serde_json::Map::new();
    for (k, v) in &cat_rows {
        cat_map.insert(k.clone().unwrap_or_default(), serde_json::json!(v));
    }

    // Priority breakdown
    let pri_rows = sqlx::query_as::<_, (String, i64)>(
        "SELECT priority, COUNT(*)
             FROM support_tickets WHERE created_at >= NOW() - $1::interval
             GROUP BY priority",
    )
    .bind(format!("{days} days"))
    .fetch_all(&state.db)
    .await?;

    let mut pri_map = serde_json::Map::new();
    for (k, v) in &pri_rows {
        pri_map.insert(k.clone(), serde_json::json!(v));
    }

    // Timeline
    let timeline = sqlx::query_as::<_, (String, i64)>(
        "SELECT DATE(created_at)::text, COUNT(*)
             FROM support_tickets WHERE created_at >= NOW() - $1::interval
             GROUP BY DATE(created_at) ORDER BY DATE(created_at)",
    )
    .bind(format!("{days} days"))
    .fetch_all(&state.db)
    .await?;

    // Top tenants
    let top = sqlx::query_as::<_, (Option<String>, i64)>(
        "SELECT COALESCE(tenant_name, 'Unknown'), COUNT(*)
             FROM support_tickets WHERE created_at >= NOW() - $1::interval
             GROUP BY tenant_name ORDER BY COUNT(*) DESC LIMIT 10",
    )
    .bind(format!("{days} days"))
    .fetch_all(&state.db)
    .await?;

    // Recent tickets
    let recent = sqlx::query_as::<
        _,
        (
            String,
            String,
            Option<String>,
            String,
            String,
            Option<String>,
            chrono::DateTime<chrono::Utc>,
        ),
    >(
        "SELECT id::text, subject, tenant_name, status, priority, category, created_at
         FROM support_tickets ORDER BY created_at DESC LIMIT 10",
    )
    .fetch_all(&state.db)
    .await?;

    // Response time buckets
    let buckets = sqlx::query_as::<_, (Option<String>, i64)>(
        "SELECT
            CASE
              WHEN EXTRACT(EPOCH FROM (stm.created_at - st.created_at)) / 3600 < 1 THEN '< 1h'
              WHEN EXTRACT(EPOCH FROM (stm.created_at - st.created_at)) / 3600 < 4 THEN '1-4h'
              WHEN EXTRACT(EPOCH FROM (stm.created_at - st.created_at)) / 3600 < 24 THEN '4-24h'
              WHEN EXTRACT(EPOCH FROM (stm.created_at - st.created_at)) / 3600 < 72 THEN '1-3d'
              ELSE '> 3d'
            END as bucket, COUNT(*)
         FROM support_tickets st
         JOIN support_ticket_messages stm ON stm.ticket_id = st.id
         WHERE stm.author_type = 'agent'
         GROUP BY bucket",
    )
    .fetch_all(&state.db)
    .await?;

    let mut bucket_map = serde_json::Map::new();
    for (k, v) in &buckets {
        bucket_map.insert(k.clone().unwrap_or_default(), serde_json::json!(v));
    }

    let result = SupportAnalytics {
        total_tickets: status_row.0,
        open_tickets: status_row.1,
        in_progress_tickets: status_row.2,
        waiting_tickets: status_row.3,
        resolved_tickets: status_row.4,
        closed_tickets: status_row.5,
        urgent_tickets: status_row.6,
        avg_resolution_hours: avg_res.and_then(|r| r.0).unwrap_or(0.0),
        tickets_by_category: serde_json::Value::Object(cat_map),
        tickets_by_priority: serde_json::Value::Object(pri_map),
        tickets_over_time: timeline
            .into_iter()
            .map(|(d, c)| TicketsOverTime { date: d, count: c })
            .collect(),
        top_tenants: top
            .into_iter()
            .map(|(n, c)| TopTenant {
                tenant_name: n.unwrap_or_default(),
                count: c,
            })
            .collect(),
        recent_tickets: recent
            .into_iter()
            .map(|(id, subj, tn, st, pri, cat, ca)| RecentTicket {
                id,
                subject: subj,
                tenant_name: tn,
                status: st,
                priority: pri,
                category: cat,
                created_at: ca.to_rfc3339(),
            })
            .collect(),
        response_time_buckets: serde_json::Value::Object(bucket_map),
    };

    // Update cache
    let mut guard = CACHE.lock().await;
    *guard = Some((Instant::now(), days, result.clone()));
    drop(guard);

    Ok(Json(result))
}
