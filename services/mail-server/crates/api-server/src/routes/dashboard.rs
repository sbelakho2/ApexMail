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

#[cfg(test)]
mod adversarial_tests {
    use axum::http::StatusCode;

    use crate::app::test_support::adv::AdvEnv;

    async fn seed_message(
        pool: &sqlx::PgPool,
        tenant: &str,
        status: &str,
        opened: bool,
        clicked: bool,
        days_ago: i32,
    ) {
        sqlx::query(
            "INSERT INTO messages (id, tenant_id, from_email, to_emails, subject, status,
                                   first_opened_at, first_clicked_at, created_at)
             VALUES ($1::uuid, $2, 'sender@example.com', '[]', 'stat probe', $3, $4, $5,
                     NOW() - ($6 || ' days')::interval)",
        )
        .bind(uuid::Uuid::new_v4())
        .bind(tenant)
        .bind(status)
        .bind(opened.then(chrono::Utc::now))
        .bind(clicked.then(chrono::Utc::now))
        .bind(days_ago.to_string())
        .execute(pool)
        .await
        .expect("seed message");
    }

    #[tokio::test]
    async fn stats_are_tenant_scoped_and_rate_arithmetic_holds() {
        let Some(pool) = crate::test_db::canonical_pool("dash_stats").await else {
            return;
        };
        let (env, tenant) = AdvEnv::tenant(pool.clone(), &["analytics:read"]).await;
        // A second tenant's rows must not leak into the first's stats.
        let (other_env, other_tenant) = AdvEnv::tenant(pool.clone(), &["analytics:read"]).await;
        seed_message(&pool, &other_tenant, "delivered", true, false, 1).await;

        // In-window mix: 2 delivered (1 opened+clicked), 1 bounced,
        // 1 complained, 1 queued-but-unopened. 5 total, in-window.
        seed_message(&pool, &tenant, "delivered", true, true, 0).await;
        seed_message(&pool, &tenant, "delivered", false, false, 5).await;
        seed_message(&pool, &tenant, "bounced", false, false, 10).await;
        seed_message(&pool, &tenant, "complained", false, false, 20).await;
        seed_message(&pool, &tenant, "queued", false, false, 29).await;
        // Out-of-window rows are excluded entirely (40 days > 30-day window).
        seed_message(&pool, &tenant, "delivered", true, true, 40).await;

        let (status, body) = env.get("/v1/dashboard/stats").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["total_messages_sent"], 5);
        assert_eq!(body["total_messages_delivered"], 2);
        assert_eq!(body["total_messages_bounced"], 1);
        assert_eq!(body["total_messages_complained"], 1);
        assert_eq!(body["delivery_rate"], 0.4);
        assert_eq!(body["bounce_rate"], 0.2);
        assert_eq!(body["open_rate"], 0.2);
        assert_eq!(body["click_rate"], 0.2);
        assert_eq!(body["period"], "last_30_days");

        // The neighbouring tenant sees ONLY its own single delivered row.
        let (status, body) = other_env.get("/v1/dashboard/stats").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["total_messages_sent"], 1);
        assert_eq!(body["delivery_rate"], 1.0);
    }

    #[tokio::test]
    async fn stats_are_zero_when_the_tenant_has_no_messages() {
        let Some(pool) = crate::test_db::canonical_pool("dash_empty").await else {
            return;
        };
        let (env, _tenant) = AdvEnv::tenant(pool, &["analytics:read"]).await;
        let (status, body) = env.get("/v1/dashboard/stats").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["total_messages_sent"], 0);
        assert_eq!(body["delivery_rate"], 0.0);
        assert_eq!(body["bounce_rate"], 0.0);
        assert_eq!(body["open_rate"], 0.0);
        assert_eq!(body["click_rate"], 0.0);
        // Resource counters (verified domains only count as active).
        assert_eq!(body["total_contacts"], 0);
        assert_eq!(body["total_lists"], 0);
        assert_eq!(body["total_campaigns"], 0);
        assert_eq!(body["total_templates"], 0);
        assert_eq!(body["active_domains"], 0);
    }

    #[tokio::test]
    async fn stats_count_resource_rows_for_the_tenant_only() {
        let Some(pool) = crate::test_db::canonical_pool("dash_counts").await else {
            return;
        };
        let (env, tenant) = AdvEnv::tenant(pool.clone(), &["analytics:read"]).await;
        let (other_env, other_tenant) = AdvEnv::tenant(pool.clone(), &["analytics:read"]).await;

        for table in ["contacts", "lists", "campaigns", "templates"] {
            let uuid = uuid::Uuid::new_v4();
            let name_col = if table == "contacts" { "email" } else { "name" };
            // templates ids are VARCHAR(26) (ULID-style); every other
            // canonical resource id is a UUID — bind per table shape.
            if table == "templates" {
                // templates.subject is NOT NULL on the canonical schema.
                sqlx::query(&format!(
                    "INSERT INTO {table} (id, tenant_id, {name_col}, subject, html_body) VALUES ($1, $2, 'dash-probe', 'dash-probe', '<p>probe</p>')"
                ))
                .bind(uuid.simple().to_string()[..26].to_string())
                .bind(&tenant)
                .execute(&pool)
                .await
                .unwrap_or_else(|e| panic!("seed {table}: {e}"));
            } else {
                sqlx::query(&format!(
                    "INSERT INTO {table} (id, tenant_id, {name_col}) VALUES ($1, $2, 'dash-probe')"
                ))
                .bind(uuid)
                .bind(&tenant)
                .execute(&pool)
                .await
                .unwrap_or_else(|e| panic!("seed {table}: {e}"));
            }
        }
        // Verified domain counts; pending does not; other tenant's does not.
        sqlx::query("INSERT INTO domains (id, tenant_id, name, status) VALUES ($1, $2, 'dash-ok.example', 'verified')")
            .bind(uuid::Uuid::new_v4())
            .bind(&tenant)
            .execute(&pool)
            .await
            .expect("seed verified domain");
        sqlx::query("INSERT INTO domains (id, tenant_id, name, status) VALUES ($1, $2, 'dash-pending.example', 'pending')")
            .bind(uuid::Uuid::new_v4())
            .bind(&tenant)
            .execute(&pool)
            .await
            .expect("seed pending domain");
        sqlx::query("INSERT INTO domains (id, tenant_id, name, status) VALUES ($1, $2, 'dash-other.example', 'verified')")
            .bind(uuid::Uuid::new_v4())
            .bind(&other_tenant)
            .execute(&pool)
            .await
            .expect("seed other tenant domain");

        let (status, body) = env.get("/v1/dashboard/stats").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["total_contacts"], 1);
        assert_eq!(body["total_lists"], 1);
        assert_eq!(body["total_campaigns"], 1);
        assert_eq!(body["total_templates"], 1);
        assert_eq!(body["active_domains"], 1);

        let (status, body) = other_env.get("/v1/dashboard/stats").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["total_contacts"], 0);
        assert_eq!(body["active_domains"], 1);
    }

    #[tokio::test]
    async fn stats_require_the_analytics_read_scope() {
        let Some(pool) = crate::test_db::canonical_pool("dash_scope").await else {
            return;
        };
        let (env, _tenant) = AdvEnv::tenant(pool, &["messages:read"]).await;
        let (status, body) = env.get("/v1/dashboard/stats").await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    }

    #[tokio::test]
    async fn stats_require_authentication() {
        let Some(pool) = crate::test_db::canonical_pool("dash_anon").await else {
            return;
        };
        let (mut env, _tenant) = AdvEnv::tenant(pool, &["analytics:read"]).await;
        env.credential = "am_not_a_real_key".into();
        let (status, _body) = env.get("/v1/dashboard/stats").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
}
