//! User-facing dashboard stats route.
//!
//! GET / → aggregated stats for the authenticated tenant's dashboard

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;

use crate::error::ApiError;
use crate::middleware::auth::{require_scopes, AuthUser};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/stats", get(dashboard_stats))
}

// ─── Types ─────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct DashboardStats {
    pub total_messages_sent: i64,
    pub total_messages_delivered: i64,
    pub total_messages_bounced: i64,
    pub total_messages_complained: i64,
    pub delivery_rate: f64,
    pub bounce_rate: f64,
    pub open_rate: f64,
    pub click_rate: f64,
    pub total_contacts: i64,
    pub total_lists: i64,
    pub total_campaigns: i64,
    pub total_templates: i64,
    pub active_domains: i64,
    pub period: String,
}

#[derive(sqlx::FromRow)]
struct DashboardMessageStats {
    total: i64,
    delivered: i64,
    bounced: i64,
    complained: i64,
    opened: i64,
    clicked: i64,
}

/// Row for the single combined resource-count query (audit: the dashboard
/// used to run six sequential COUNT queries per request — five scalar
/// resource counts plus the messages aggregate).
#[derive(sqlx::FromRow)]
struct DashboardResourceCounts {
    contacts: i64,
    lists: i64,
    campaigns: i64,
    templates: i64,
    active_domains: i64,
}

// ─── Handler ───────────────────────────────────────────────────

async fn dashboard_stats(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<DashboardStats>, ApiError> {
    require_scopes(&auth, &["analytics:read"])?;

    // Message stats (last 30 days)
    let msg_stats = sqlx::query_as::<_, DashboardMessageStats>(
        r#"SELECT
            COUNT(*)::bigint AS total,
            COUNT(*) FILTER (WHERE status = 'delivered')::bigint AS delivered,
            COUNT(*) FILTER (WHERE status = 'bounced')::bigint AS bounced,
            COUNT(*) FILTER (WHERE status = 'complained')::bigint AS complained,
            COUNT(*) FILTER (WHERE first_opened_at IS NOT NULL)::bigint AS opened,
            COUNT(*) FILTER (WHERE first_clicked_at IS NOT NULL)::bigint AS clicked
           FROM messages
           WHERE tenant_id = $1
             AND created_at >= NOW() - INTERVAL '30 days'"#,
    )
    .bind(auth.tenant_id.to_string())
    .fetch_one(&state.db)
    .await?;

    let total = msg_stats.total as f64;
    let delivery_rate = if msg_stats.total > 0 {
        msg_stats.delivered as f64 / total
    } else {
        0.0
    };
    let bounce_rate = if msg_stats.total > 0 {
        msg_stats.bounced as f64 / total
    } else {
        0.0
    };
    let open_rate = if msg_stats.total > 0 {
        msg_stats.opened as f64 / total
    } else {
        0.0
    };
    let click_rate = if msg_stats.total > 0 {
        msg_stats.clicked as f64 / total
    } else {
        0.0
    };

    // Resource counts — one round-trip instead of five sequential COUNTs.
    let counts = sqlx::query_as::<_, DashboardResourceCounts>(
        r#"SELECT
            (SELECT COUNT(*)::bigint FROM contacts WHERE tenant_id = $1) AS contacts,
            (SELECT COUNT(*)::bigint FROM lists WHERE tenant_id = $1) AS lists,
            (SELECT COUNT(*)::bigint FROM campaigns WHERE tenant_id = $1) AS campaigns,
            (SELECT COUNT(*)::bigint FROM templates WHERE tenant_id = $1) AS templates,
            (SELECT COUNT(*)::bigint FROM domains WHERE tenant_id = $1 AND status = 'verified') AS active_domains"#,
    )
    .bind(auth.tenant_id.to_string())
    .fetch_one(&state.db)
    .await?;

    Ok(Json(DashboardStats {
        total_messages_sent: msg_stats.total,
        total_messages_delivered: msg_stats.delivered,
        total_messages_bounced: msg_stats.bounced,
        total_messages_complained: msg_stats.complained,
        delivery_rate,
        bounce_rate,
        open_rate,
        click_rate,
        total_contacts: counts.contacts,
        total_lists: counts.lists,
        total_campaigns: counts.campaigns,
        total_templates: counts.templates,
        active_domains: counts.active_domains,
        period: "last_30_days".into(),
    }))
}
