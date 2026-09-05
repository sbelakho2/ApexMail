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
        "SELECT id, title, type, start_time, end_time, description, attendees, created_at
         FROM calendar_events
         WHERE tenant_id = $1
         ORDER BY start_time DESC
         LIMIT 100"
    } else {
        "SELECT id, title, type, start_time, end_time, description, attendees, created_at
         FROM calendar_events
         ORDER BY start_time DESC
         LIMIT 100"
    }
}

fn build_availability_slots_sql(scoped_by_tenant: bool) -> &'static str {
    if scoped_by_tenant {
        "SELECT id, day_of_week, start_time::text, end_time::text
         FROM availability_slots
         WHERE tenant_id = $1
         ORDER BY day_of_week, start_time"
    } else {
        "SELECT id, day_of_week, start_time::text, end_time::text
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
    let should_scope_to_tenant = !crate::routes::web::is_system_tenant(&state, &auth.tenant_id).await;
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
    }

    #[test]
    fn availability_slots_sql_adds_tenant_filter_when_scoped() {
        assert!(build_availability_slots_sql(true).contains("WHERE tenant_id = $1"));
        assert!(!build_availability_slots_sql(false).contains("WHERE tenant_id = $1"));
    }
}
