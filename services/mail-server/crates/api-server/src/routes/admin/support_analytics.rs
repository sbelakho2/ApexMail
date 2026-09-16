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
    crate::middleware::auth::require_system_tenant(&state, &auth).await?;

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
        // COALESCE every SUM: over zero matching rows each SUM is NULL, and
        // the row decodes as non-optional i64 — without this, any empty
        // window (a fresh deployment, a quiet week) made the whole console
        // 500 with a decode error instead of reporting zeroes.
        "SELECT
                COUNT(*),
                COALESCE(SUM(CASE WHEN status = 'open' THEN 1 ELSE 0 END), 0),
                COALESCE(SUM(CASE WHEN status = 'in_progress' THEN 1 ELSE 0 END), 0),
                COALESCE(SUM(CASE WHEN status = 'pending_customer' THEN 1 ELSE 0 END), 0),
                COALESCE(SUM(CASE WHEN status = 'resolved' THEN 1 ELSE 0 END), 0),
                COALESCE(SUM(CASE WHEN status = 'closed' THEN 1 ELSE 0 END), 0),
                COALESCE(SUM(CASE WHEN priority = 'urgent' THEN 1 ELSE 0 END), 0)
             FROM support_tickets WHERE created_at >= NOW() - $1::interval",
    )
    .bind(format!("{days} days"))
    .fetch_optional(&state.db)
    .await?
    .unwrap_or((0, 0, 0, 0, 0, 0, 0));

    // Average resolution time. The EXTRACT result is NUMERIC on Postgres 14:
    // without the ::double precision cast sqlx cannot decode it as f64, and
    // the previous `.ok()` swallowed that decode error — the console reported
    // 0.0 average resolution for EVERY real dataset while appearing healthy.
    let avg_res: Option<(Option<f64>,)> = sqlx::query_as(
        "SELECT AVG(EXTRACT(EPOCH FROM (updated_at - created_at))::double precision / 3600.0)
         FROM support_tickets WHERE status IN ('resolved', 'closed')",
    )
    .fetch_optional(&state.db)
    .await?;

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
             GROUP BY tenant_name ORDER BY COUNT(*) DESC, COALESCE(tenant_name, 'Unknown') LIMIT 10",
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

// ─── Adversarial handler tests (canonical schema, per-test databases) ──────

#[cfg(test)]
mod adversarial_tests {
    use super::*;
    use axum::extract::{Query, State};

    fn system_auth() -> AuthUser {
        AuthUser {
            tenant_id: "system".into(),
            user_id: None,
            api_key_id: None,
            session_id: None,
            scopes: vec!["*".into()],
        }
    }

    /// Every test uses a UNIQUE `days` value: the 60-second in-memory cache
    /// keys on (ts, days) and `cargo test` runs suite threads in one process.
    async fn seed_ticket(
        pool: &sqlx::PgPool,
        id: &str,
        tenant_name: &str,
        status: &str,
        priority: &str,
        category: Option<&str>,
        created_minutes_ago: i64,
    ) {
        sqlx::query(
            "INSERT INTO support_tickets (id, subject, description, tenant_name, status, priority, category, created_at, updated_at)
             VALUES ($1, $2, 'body', $3, $4, $5, $6,
                     NOW() - make_interval(mins => $7::int),
                     NOW() - make_interval(mins => $7::int))",
        )
        .bind(id)
        .bind(format!("subject {id}"))
        .bind(tenant_name)
        .bind(status)
        .bind(priority)
        .bind(category)
        .bind(created_minutes_ago)
        .execute(pool)
        .await
        .expect("seed ticket");
    }

    #[tokio::test]
    async fn empty_dataset_reports_zeroed_counts_and_absent_average() {
        let Some(pool) = crate::test_db::canonical_pool("support_empty").await else {
            eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
            return;
        };
        let state = crate::app::test_support::test_state_over(pool.clone()).await;

        let Json(analytics) = get_support_analytics(
            State(state),
            system_auth(),
            Query(SupportAnalyticsQuery { days: 28 }),
        )
        .await
        .expect("empty analytics must succeed");

        assert_eq!(analytics.total_tickets, 0);
        assert_eq!(analytics.open_tickets, 0);
        assert_eq!(analytics.urgent_tickets, 0);
        assert_eq!(analytics.avg_resolution_hours, 0.0);
        assert!(analytics.tickets_by_category.is_object());
        assert!(analytics.tickets_over_time.is_empty());
        assert!(analytics.top_tenants.is_empty());
        assert!(analytics.recent_tickets.is_empty());
        pool.close().await;
    }

    /// The surface is operator-only: a customer wildcard key is refused by the
    /// system-tenant gate with 403 and never sees ticket data.
    #[tokio::test]
    async fn customer_wildcard_key_is_refused_by_the_system_tenant_gate() {
        let Some(pool) = crate::test_db::canonical_pool("support_gate").await else {
            eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
            return;
        };
        let state = crate::app::test_support::test_state_over(pool.clone()).await;
        let customer = crate::app::test_support::seed_api_tenant(&pool, &["*"]).await;
        let auth = AuthUser {
            tenant_id: customer.0,
            user_id: None,
            api_key_id: None,
            session_id: None,
            scopes: vec!["*".into()],
        };

        let err = get_support_analytics(
            State(state),
            auth,
            Query(SupportAnalyticsQuery { days: 27 }),
        )
        .await
        .expect_err("customer tenants must not read support analytics");
        assert!(
            matches!(err, ApiError::Forbidden(ref message) if message.contains("system tenant")),
            "the refusal must name the tenant gate: {err:?}"
        );
        pool.close().await;
    }

    #[tokio::test]
    async fn seeded_tickets_drive_every_breakdown_exactly() {
        let Some(pool) = crate::test_db::canonical_pool("support_seeded").await else {
            eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
            return;
        };
        let state = crate::app::test_support::test_state_over(pool.clone()).await;

        // Two urgent open tickets for Acme (one old, outside a 1-day window),
        // one resolved ticket with an agent reply 2h later, one closed ticket
        // without replies, plus a blank-category ticket.
        seed_ticket(
            &pool,
            "tic_support_adv_000001",
            "Acme",
            "open",
            "urgent",
            Some("billing"),
            10,
        )
        .await;
        seed_ticket(
            &pool,
            "tic_support_adv_000002",
            "Acme",
            "in_progress",
            "normal",
            Some("billing"),
            30,
        )
        .await;
        seed_ticket(
            &pool,
            "tic_support_adv_000003",
            "Beta",
            "resolved",
            "low",
            Some("technical"),
            60,
        )
        .await;
        seed_ticket(
            &pool,
            "tic_support_adv_000004",
            "Beta",
            "pending_customer",
            "urgent",
            None,
            90,
        )
        .await;

        // Resolved 1h after creation; agent message 2h after creation.
        sqlx::query("UPDATE support_tickets SET resolved_at = NOW() - make_interval(mins => 59), updated_at = NOW() - make_interval(mins => 59) WHERE id = 'tic_support_adv_000003'")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO support_ticket_messages (ticket_id, content, author, author_type, created_at)
             VALUES ('tic_support_adv_000003', 'reply', 'agent@example.com', 'agent', NOW())",
        )
        .execute(&pool)
        .await
        .unwrap();

        let Json(analytics) = get_support_analytics(
            State(state),
            system_auth(),
            Query(SupportAnalyticsQuery { days: 26 }),
        )
        .await
        .expect("seeded analytics");

        assert_eq!(analytics.total_tickets, 4);
        assert_eq!(analytics.open_tickets, 1);
        assert_eq!(analytics.in_progress_tickets, 1);
        assert_eq!(analytics.waiting_tickets, 1);
        assert_eq!(analytics.resolved_tickets, 1);
        assert_eq!(analytics.urgent_tickets, 2);
        // Resolved 1h after creation → avg resolution is exactly 1h.
        assert!(
            (analytics.avg_resolution_hours - 1.0).abs() < 0.05,
            "avg resolution must be ~1h, got {}",
            analytics.avg_resolution_hours
        );
        assert_eq!(
            analytics.tickets_by_category["billing"],
            serde_json::json!(2)
        );
        assert_eq!(
            analytics.tickets_by_category["technical"],
            serde_json::json!(1)
        );
        assert_eq!(
            analytics.tickets_by_category["uncategorized"],
            serde_json::json!(1)
        );
        assert_eq!(
            analytics.tickets_by_priority["urgent"],
            serde_json::json!(2)
        );
        assert_eq!(
            analytics.tickets_by_priority["normal"],
            serde_json::json!(1)
        );
        // Top tenants are ordered by count; Acme leads with 2.
        assert_eq!(analytics.top_tenants[0].tenant_name, "Acme");
        assert_eq!(analytics.top_tenants[0].count, 2);
        // Recent tickets: newest first, capped at 10.
        assert_eq!(analytics.recent_tickets.len(), 4);
        assert_eq!(analytics.recent_tickets[0].id, "tic_support_adv_000001");
        assert_eq!(
            analytics.recent_tickets[0].tenant_name.as_deref(),
            Some("Acme")
        );
        // Agent reply exactly 1h after creation → the "1-4h" response
        // bucket (the CASE's first arm is strictly < 1h).
        assert_eq!(
            analytics.response_time_buckets["1-4h"],
            serde_json::json!(1)
        );
        pool.close().await;
    }

    /// The cache serves a repeat call for the SAME window; a different window
    /// (different days) recomputes and sees new data.
    #[tokio::test]
    async fn repeat_call_hits_the_cache_and_new_window_recomputes() {
        let Some(pool) = crate::test_db::canonical_pool("support_cache").await else {
            eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
            return;
        };
        let state = crate::app::test_support::test_state_over(pool.clone()).await;

        let Json(first) = get_support_analytics(
            State(state.clone()),
            system_auth(),
            Query(SupportAnalyticsQuery { days: 25 }),
        )
        .await
        .expect("first call");
        assert_eq!(first.total_tickets, 0);

        // A ticket appears between the two calls.
        seed_ticket(
            &pool,
            "tic_support_adv_cache01",
            "CacheCo",
            "open",
            "normal",
            None,
            1,
        )
        .await;

        // Same days → cached zero result (still 0).
        let Json(cached) = get_support_analytics(
            State(state.clone()),
            system_auth(),
            Query(SupportAnalyticsQuery { days: 25 }),
        )
        .await
        .expect("cached call");
        assert_eq!(
            cached.total_tickets, 0,
            "the 60s cache serves the repeat call"
        );

        // Different days → recompute sees the new ticket.
        let Json(fresh) = get_support_analytics(
            State(state),
            system_auth(),
            Query(SupportAnalyticsQuery { days: 24 }),
        )
        .await
        .expect("fresh window");
        assert_eq!(fresh.total_tickets, 1);
        pool.close().await;
    }

    /// Hostile `days` values clamp to the documented 1..=365 range instead of
    /// erroring or producing absurd SQL intervals.
    #[test]
    fn days_parameter_is_clamped_not_trusted() {
        for (input, expected) in [(0, 1), (-5, 1), (100_000, 365), (30, 30)] {
            let clamped = SupportAnalyticsQuery { days: input }.days.clamp(1, 365);
            assert_eq!(clamped, expected, "days={input}");
        }
    }

    /// Unknown query parameters are refused (deny_unknown_fields), so a probe
    /// cannot smuggle extra filters.
    #[test]
    fn query_rejects_unknown_fields() {
        assert!(
            serde_json::from_str::<SupportAnalyticsQuery>(r#"{"days": 3}"#).is_ok(),
            "days alone is accepted"
        );
        for hostile in [
            r#"{"days": 3, "tenantId": "other"}"#,
            r#"{"days": 3, "sql": "1=1"}"#,
        ] {
            assert!(
                serde_json::from_str::<SupportAnalyticsQuery>(hostile).is_err(),
                "unknown fields must be rejected: {hostile}"
            );
        }
    }
}
