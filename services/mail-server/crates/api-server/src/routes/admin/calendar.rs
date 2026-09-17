//! Calendar endpoints.
//!

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;

use crate::error::ApiError;
use crate::middleware::auth::AuthUser;
use crate::routes::helpers::{column_exists, table_exists};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/", get(get_calendar))
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CalendarEvent {
    pub id: String,
    pub title: String,
    #[serde(rename = "type")]
    pub event_type: String,
    pub start_time: String,
    pub end_time: Option<String>,
    pub description: Option<String>,
    pub attendees: Option<serde_json::Value>,
    pub created_at: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AvailabilitySlot {
    pub id: String,
    pub day_of_week: i32,
    pub start_time: String,
    pub end_time: String,
}

#[derive(Debug, Serialize)]
pub struct CalendarResponse {
    pub events: Vec<CalendarEvent>,
    pub availability: Vec<AvailabilitySlot>,
}

fn build_calendar_events_sql(scoped_by_tenant: bool) -> &'static str {
    if scoped_by_tenant {
        "SELECT id::text AS id, title, type, start_time, end_time, description, attendees, created_at
         FROM calendar_events
         WHERE tenant_id = $1
         ORDER BY start_time DESC
         LIMIT 100"
    } else {
        "SELECT id::text AS id, title, type, start_time, end_time, description, attendees, created_at
         FROM calendar_events
         ORDER BY start_time DESC
         LIMIT 100"
    }
}

fn build_availability_slots_sql(scoped_by_tenant: bool) -> &'static str {
    if scoped_by_tenant {
        "SELECT id::text AS id, day_of_week, start_time::text, end_time::text
         FROM availability_slots
         WHERE tenant_id = $1
         ORDER BY day_of_week, start_time"
    } else {
        "SELECT id::text AS id, day_of_week, start_time::text, end_time::text
         FROM availability_slots
         ORDER BY day_of_week, start_time"
    }
}

async fn get_calendar(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<CalendarResponse>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    let db = &state.db;
    // Slug-aware system-tenant resolution (audit F1): human operators are
    // `system_internal_tenant01`, so the literal check always scoped them.
    let should_scope_to_tenant =
        !crate::routes::web::is_system_tenant(&state, &auth.tenant_id).await;
    let events_table_exists = table_exists(db, "calendar_events").await;
    let slots_table_exists = table_exists(db, "availability_slots").await;
    let events_have_tenant_id =
        events_table_exists && column_exists(db, "calendar_events", "tenant_id").await;
    let slots_have_tenant_id =
        slots_table_exists && column_exists(db, "availability_slots", "tenant_id").await;
    let scope_events = should_scope_to_tenant && events_have_tenant_id;
    let scope_slots = should_scope_to_tenant && slots_have_tenant_id;

    let event_rows: Vec<(
        String,
        String,
        String,
        chrono::DateTime<chrono::Utc>,
        Option<chrono::DateTime<chrono::Utc>>,
        Option<String>,
        Option<serde_json::Value>,
        chrono::DateTime<chrono::Utc>,
    )> = if events_table_exists {
        let sql = build_calendar_events_sql(scope_events);
        if scope_events {
            sqlx::query_as(sql)
                .bind(&auth.tenant_id)
                .fetch_all(db)
                .await?
        } else {
            sqlx::query_as(sql).fetch_all(db).await?
        }
    } else {
        Vec::new()
    };

    let events: Vec<CalendarEvent> = event_rows
        .into_iter()
        .map(
            |(id, title, event_type, start_time, end_time, description, attendees, created_at)| {
                CalendarEvent {
                    id,
                    title,
                    event_type,
                    start_time: start_time.to_rfc3339(),
                    end_time: end_time.map(|t| t.to_rfc3339()),
                    description,
                    attendees,
                    created_at: created_at.to_rfc3339(),
                }
            },
        )
        .collect();

    let slot_rows: Vec<(String, i32, String, String)> = if slots_table_exists {
        let sql = build_availability_slots_sql(scope_slots);
        if scope_slots {
            sqlx::query_as(sql)
                .bind(&auth.tenant_id)
                .fetch_all(db)
                .await?
        } else {
            sqlx::query_as(sql).fetch_all(db).await?
        }
    } else {
        Vec::new()
    };

    let availability: Vec<AvailabilitySlot> = slot_rows
        .into_iter()
        .map(|(id, day_of_week, start_time, end_time)| AvailabilitySlot {
            id,
            day_of_week,
            start_time,
            end_time,
        })
        .collect();

    Ok(Json(CalendarResponse {
        events,
        availability,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calendar_events_sql_adds_tenant_filter_when_scoped() {
        assert!(build_calendar_events_sql(true).contains("WHERE tenant_id = $1"));
        assert!(!build_calendar_events_sql(false).contains("WHERE tenant_id = $1"));
        // canonical ids are UUIDs; the row decodes String.
        assert!(build_calendar_events_sql(true).contains("id::text AS id"));
    }

    #[test]
    fn availability_slots_sql_adds_tenant_filter_when_scoped() {
        assert!(build_availability_slots_sql(true).contains("WHERE tenant_id = $1"));
        assert!(!build_availability_slots_sql(false).contains("WHERE tenant_id = $1"));
        assert!(build_availability_slots_sql(true).contains("id::text AS id"));
    }

    mod adversarial_tests {
        use axum::http::StatusCode;

        use crate::app::test_support::adv::AdvEnv;

        #[tokio::test]
        async fn calendar_lists_events_and_slots_for_the_system_operator() {
            let Some(pool) = crate::test_db::canonical_pool("cal_admin_ok").await else {
                return;
            };
            let env = AdvEnv::admin(pool.clone()).await;

            sqlx::query(
                "INSERT INTO calendar_events (id, tenant_id, title, type, start_time, end_time, description, attendees)
                 VALUES ($1, 'system_internal_tenant01', 'Quarterly ops review', 'meeting',
                         NOW() + INTERVAL '2 days', NOW() + INTERVAL '3 hours' + INTERVAL '2 days',
                         'calendar adversarial probe', '[\"ops@example.com\"]'::jsonb)",
            )
            .bind(uuid::Uuid::new_v4())
            .execute(&pool)
            .await
            .expect("seed calendar event");

            sqlx::query(
                "INSERT INTO availability_slots (id, tenant_id, day_of_week, start_time, end_time)
                 VALUES ($1, 'system_internal_tenant01', 1, '09:00', '17:00')",
            )
            .bind(uuid::Uuid::new_v4())
            .execute(&pool)
            .await
            .expect("seed availability slot");

            let (status, body) = env.get("/v1/admin/calendar").await;
            assert_eq!(status, StatusCode::OK, "{body}");
            let events = body["events"].as_array().expect("events array");
            assert_eq!(events.len(), 1);
            assert_eq!(events[0]["title"], "Quarterly ops review");
            assert_eq!(events[0]["type"], "meeting");
            assert_eq!(events[0]["description"], "calendar adversarial probe");
            assert!(events[0]["startTime"]
                .as_str()
                .is_some_and(|t| t.starts_with("20")));
            assert!(events[0]["endTime"].as_str().is_some());
            let slots = body["availability"].as_array().expect("slots array");
            assert_eq!(slots.len(), 1);
            assert_eq!(slots[0]["dayOfWeek"], 1);
            assert_eq!(slots[0]["startTime"], "09:00:00");
            assert_eq!(slots[0]["endTime"], "17:00:00");
        }

        #[tokio::test]
        async fn calendar_with_empty_tables_returns_empty_arrays() {
            let Some(pool) = crate::test_db::canonical_pool("cal_admin_empty").await else {
                return;
            };
            let env = AdvEnv::admin(pool).await;
            let (status, body) = env.get("/v1/admin/calendar").await;
            assert_eq!(status, StatusCode::OK, "{body}");
            assert_eq!(body["events"].as_array().map(Vec::len), Some(0));
            assert_eq!(body["availability"].as_array().map(Vec::len), Some(0));
        }

        #[tokio::test]
        async fn calendar_orders_events_by_start_time_descending() {
            let Some(pool) = crate::test_db::canonical_pool("cal_admin_order").await else {
                return;
            };
            let env = AdvEnv::admin(pool.clone()).await;
            // DESC by start_time: the event further in the future (10 days
            // out) is listed first, tomorrow's second.
            for (title, offset) in [("farther-event", "10 days"), ("sooner-event", "1 day")] {
                sqlx::query(
                    "INSERT INTO calendar_events (id, tenant_id, title, type, start_time)
                     VALUES ($1, NULL, $2, 'meeting', NOW() + ($3 || ' days')::interval)",
                )
                .bind(uuid::Uuid::new_v4())
                .bind(title)
                .bind(offset)
                .execute(&pool)
                .await
                .expect("seed event");
            }
            let (status, body) = env.get("/v1/admin/calendar").await;
            assert_eq!(status, StatusCode::OK, "{body}");
            let events = body["events"].as_array().expect("events");
            assert_eq!(events.len(), 2);
            assert_eq!(events[0]["title"], "farther-event");
            assert_eq!(events[1]["title"], "sooner-event");

            // The response is served as JSON (raw-bytes helper proves the
            // content type, not just the decoded body).
            let (status, headers, _bytes) = env.get_raw("/v1/admin/calendar").await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(
                headers
                    .get(axum::http::header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok()),
                Some("application/json")
            );
        }

        #[tokio::test]
        async fn calendar_requires_the_wildcard_scope() {
            let Some(pool) = crate::test_db::canonical_pool("cal_scope").await else {
                return;
            };
            let key =
                crate::app::test_support::seed_api_key_for(&pool, "system", &["messages:read"])
                    .await;
            let env = AdvEnv::over(pool, key).await;
            let (status, body) = env.get("/v1/admin/calendar").await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        }

        #[tokio::test]
        async fn calendar_rejects_customer_tenants_before_the_handler() {
            let Some(pool) = crate::test_db::canonical_pool("cal_tenant").await else {
                return;
            };
            // A customer tenant key carrying the wildcard scope must be
            // stopped by the control-plane tenant gate, not by the handler.
            let (env, _tenant) = crate::app::test_support::adv::AdvEnv::tenant(pool, &["*"]).await;
            let (status, body) = env.get("/v1/admin/calendar").await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
            assert!(
                body["error"]["message"]
                    .as_str()
                    .unwrap_or_default()
                    .contains("system tenant"),
                "rejection must name the control-plane gate: {body}"
            );
        }

        #[tokio::test]
        async fn calendar_requires_authentication() {
            let Some(pool) = crate::test_db::canonical_pool("cal_anon").await else {
                return;
            };
            let env = AdvEnv::over(pool, "am_bogus_key".into()).await;
            let (status, _body) = env.get("/v1/admin/calendar").await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
        }
    }
}
