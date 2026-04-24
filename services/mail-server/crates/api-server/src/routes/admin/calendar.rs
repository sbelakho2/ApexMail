//! Calendar endpoints.
//!

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;

use crate::error::ApiError;
use crate::middleware::auth::AuthUser;
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

async fn get_calendar(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<CalendarResponse>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    let db = &state.db;

    let event_rows: Vec<(String, String, String, chrono::DateTime<chrono::Utc>, Option<chrono::DateTime<chrono::Utc>>, Option<String>, Option<serde_json::Value>, chrono::DateTime<chrono::Utc>)> =
        sqlx::query_as(
            "SELECT id, title, type, start_time, end_time, description, attendees, created_at
             FROM calendar_events
             ORDER BY start_time DESC
             LIMIT 100",
        )
        .fetch_all(db)
        .await
        ?;

    let events: Vec<CalendarEvent> = event_rows
        .into_iter()
        .map(|(id, title, event_type, start_time, end_time, description, attendees, created_at)| {
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
        })
        .collect();

    let slot_rows: Vec<(String, i32, String, String)> = sqlx::query_as(
        "SELECT id, day_of_week, start_time::text, end_time::text FROM availability_slots ORDER BY day_of_week, start_time",
    )
    .fetch_all(db)
    .await
    ?;

    let availability: Vec<AvailabilitySlot> = slot_rows
        .into_iter()
        .map(|(id, day_of_week, start_time, end_time)| AvailabilitySlot {
            id,
            day_of_week,
            start_time,
            end_time,
        })
        .collect();

    Ok(Json(CalendarResponse { events, availability }))
}
