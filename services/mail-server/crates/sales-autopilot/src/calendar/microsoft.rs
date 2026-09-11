//! Microsoft Graph calendar provider (`CalendarProvider`).
//!
//! # Authority
//!
//! When configured (`SALES_CALENDAR_PROVIDER=microsoft` +
//! `SALES_MICROSOFT_GRAPH_ACCESS_TOKEN`), the Microsoft/Outlook calendar is
//! the **authoritative** source of the salesperson's availability:
//! `availability` reads `getSchedule` free/busy from the real Graph API and
//! intersects it with the internal store of record. Every booking is mirrored
//! into `sales_calendar_events` + `sales_meetings` through
//! [`super::internal::InternalCalendarProvider`] (the store of record).
//!
//! # API usage
//!
//! * availability: `POST {base}/{user}/calendar/getSchedule`
//! * booking: `POST {base}/{user}/events` with `isOnlineMeeting: true`
//! * reschedule: `PATCH {base}/{user}/events/{event_id}`
//! * cancel: `DELETE {base}/{user}/events/{event_id}`
//!
//! Credentials are read directly from the environment because
//! [`crate::config::SalesConfig`] has no calendar field (out of this change's
//! scope): `SALES_MICROSOFT_GRAPH_ACCESS_TOKEN` (required),
//! `SALES_MICROSOFT_USER_ID` (default `me`),
//! `SALES_MICROSOFT_GRAPH_BASE_URL` (default the real Graph API).

use std::sync::Arc;
use std::time::Duration as StdDuration;

use chrono::{DateTime, NaiveDateTime, Utc};
use serde_json::json;
use uuid::Uuid;

use super::availability::{generate_slots, AvailabilityRequest, BusyInterval, TimeSlot};
use super::internal::InternalCalendarProvider;
use super::timezone::local_day_bounds;
use super::{BookedEvent, CalendarConfig, CalendarError, CalendarProvider, CreateEventRequest};

const DEFAULT_GRAPH_BASE_URL: &str = "https://graph.microsoft.com/v1.0";
const HTTP_TIMEOUT_SECS: u64 = 15;

pub struct MicrosoftCalendarProvider {
    client: reqwest::Client,
    base_url: String,
    user_id: String,
    access_token: String,
    internal: Arc<InternalCalendarProvider>,
    config: CalendarConfig,
}

impl std::fmt::Debug for MicrosoftCalendarProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MicrosoftCalendarProvider")
            .field("base_url", &self.base_url)
            .field("user_id", &self.user_id)
            .field("timezone", &self.config.timezone.name())
            .finish_non_exhaustive()
    }
}

impl MicrosoftCalendarProvider {
    pub fn from_env(
        config: CalendarConfig,
        internal: Arc<InternalCalendarProvider>,
    ) -> Option<Self> {
        // Mirrors `config.rs`'s `read_env` pattern: SALES_-prefixed production
        // name first, then the short local-development alias.
        let access_token = read_env(&[
            "SALES_MICROSOFT_GRAPH_ACCESS_TOKEN",
            "MICROSOFT_GRAPH_ACCESS_TOKEN",
        ])?;
        let base_url = read_env(&["SALES_MICROSOFT_GRAPH_BASE_URL", "MICROSOFT_GRAPH_BASE_URL"])
            .map(|raw| raw.trim_end_matches('/').to_string())
            .unwrap_or_else(|| DEFAULT_GRAPH_BASE_URL.to_string());
        let user_id = read_env(&["SALES_MICROSOFT_USER_ID", "MICROSOFT_USER_ID"])
            .unwrap_or_else(|| "me".into());
        let client = reqwest::Client::builder()
            .timeout(StdDuration::from_secs(HTTP_TIMEOUT_SECS))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Some(Self {
            client,
            base_url,
            user_id,
            access_token,
            internal,
            config,
        })
    }

    fn user_base(&self) -> String {
        format!("{}/{}", self.base_url, self.user_id.trim_matches('/'))
    }

    fn events_url(&self) -> String {
        format!("{}/events", self.user_base())
    }

    async fn busy_from_graph(
        &self,
        request: &AvailabilityRequest,
    ) -> Result<Vec<BusyInterval>, CalendarError> {
        let (day_start, day_end) =
            local_day_bounds(request.timezone, request.date).ok_or_else(|| {
                CalendarError::InvalidInput("the local day cannot be resolved".into())
            })?;
        let body = json!({
            "schedules": [self.user_id],
            "startTime": { "dateTime": day_start.to_rfc3339(), "timeZone": "UTC" },
            "endTime": { "dateTime": day_end.to_rfc3339(), "timeZone": "UTC" },
            "availabilityViewInterval": request.policy.slot_minutes.clamp(5, 1440),
        });
        let response = self
            .client
            .post(format!("{}/calendar/getSchedule", self.user_base()))
            .bearer_auth(&self.access_token)
            .json(&body)
            .send()
            .await
            .map_err(|e| CalendarError::Provider(format!("graph getSchedule failed: {e}")))?;
        let status = response.status();
        let payload: serde_json::Value = response.json().await.map_err(|e| {
            CalendarError::Provider(format!("graph getSchedule returned invalid JSON: {e}"))
        })?;
        if !status.is_success() {
            return Err(CalendarError::Provider(format!(
                "graph getSchedule returned HTTP {status}"
            )));
        }
        let mut busy = Vec::new();
        if let Some(schedules) = payload.get("value").and_then(|v| v.as_array()) {
            for schedule in schedules {
                if let Some(items) = schedule.get("scheduleItems").and_then(|v| v.as_array()) {
                    for item in items {
                        // `status` is `busy|tentative|oof|workingElsewhere|free`.
                        let is_free = item
                            .get("status")
                            .and_then(|v| v.as_str())
                            .is_some_and(|status| status.eq_ignore_ascii_case("free"));
                        if is_free {
                            continue;
                        }
                        let start = item
                            .pointer("/start/dateTime")
                            .and_then(|v| v.as_str())
                            .and_then(parse_graph_datetime);
                        let end = item
                            .pointer("/end/dateTime")
                            .and_then(|v| v.as_str())
                            .and_then(parse_graph_datetime);
                        if let (Some(start), Some(end)) = (start, end) {
                            if end > start {
                                busy.push(BusyInterval::new(start, end));
                            }
                        }
                    }
                }
            }
        }
        Ok(busy)
    }

    async fn merged_busy(
        &self,
        request: &AvailabilityRequest,
    ) -> Result<Vec<BusyInterval>, CalendarError> {
        let mut busy = self.internal.busy_intervals(request).await?;
        busy.extend(self.busy_from_graph(request).await?);
        Ok(busy)
    }
}

#[async_trait::async_trait]
impl CalendarProvider for MicrosoftCalendarProvider {
    fn id(&self) -> &'static str {
        "microsoft"
    }

    async fn availability(
        &self,
        request: &AvailabilityRequest,
    ) -> Result<Vec<TimeSlot>, CalendarError> {
        let busy = self.merged_busy(request).await?;
        let loads = self.internal.salesperson_loads(request).await?;
        Ok(generate_slots(request, &busy, busy.len(), &loads))
    }

    async fn create_event(
        &self,
        request: &CreateEventRequest,
    ) -> Result<BookedEvent, CalendarError> {
        if request.end <= request.start {
            return Err(CalendarError::InvalidInput(
                "end_at must be after start_at".into(),
            ));
        }
        let body = json!({
            "subject": request.title,
            "start": {
                "dateTime": request.start.to_rfc3339(),
                "timeZone": "UTC",
            },
            "end": {
                "dateTime": request.end.to_rfc3339(),
                "timeZone": "UTC",
            },
            "attendees": request
                .attendees_all()
                .into_iter()
                .map(|email| json!({
                    "emailAddress": { "address": email },
                    "type": "required",
                }))
                .collect::<Vec<_>>(),
            "isOnlineMeeting": true,
            "onlineMeetingProvider": "teamsForBusiness",
        });
        let response = self
            .client
            .post(self.events_url())
            .bearer_auth(&self.access_token)
            .json(&body)
            .send()
            .await
            .map_err(|e| CalendarError::Provider(format!("graph event insert failed: {e}")))?;
        let status = response.status();
        let payload: serde_json::Value = response.json().await.map_err(|e| {
            CalendarError::Provider(format!("graph event insert returned invalid JSON: {e}"))
        })?;
        if !status.is_success() {
            return Err(CalendarError::Provider(format!(
                "graph event insert returned HTTP {status}"
            )));
        }
        let provider_event_id = payload
            .get("id")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .ok_or_else(|| CalendarError::Provider("graph event insert returned no id".into()))?;
        // An empty link means Graph did not return a join URL; the internal
        // store generates the deterministic handle from the real meeting id.
        let link = payload
            .pointer("/onlineMeeting/joinUrl")
            .or_else(|| payload.get("onlineMeetingUrl"))
            .and_then(|v| v.as_str())
            .filter(|link| !link.trim().is_empty())
            .unwrap_or("")
            .to_string();

        match self
            .internal
            .record_event(request, "microsoft", Some(&provider_event_id), link)
            .await
        {
            Ok(booked) => Ok(booked),
            Err(error) => {
                // Compensate: keep the real calendar consistent with the
                // rejected internal booking.
                let _ = self
                    .client
                    .delete(format!("{}/{}", self.events_url(), provider_event_id))
                    .bearer_auth(&self.access_token)
                    .send()
                    .await;
                Err(error)
            }
        }
    }

    async fn reschedule(
        &self,
        event_id: &str,
        new_start: DateTime<Utc>,
    ) -> Result<BookedEvent, CalendarError> {
        let id = Uuid::parse_str(event_id)
            .map_err(|_| CalendarError::InvalidInput("event id must be a UUID".into()))?;
        let row: Option<(Option<String>, DateTime<Utc>, DateTime<Utc>)> = sqlx::query_as(
            "SELECT provider_event_id, start_at, end_at FROM sales_meetings WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(self.internal.db())
        .await
        .map_err(|e| CalendarError::Database(e.to_string()))?;
        let (provider_event_id, old_start, old_end) =
            row.ok_or_else(|| CalendarError::EventNotFound(event_id.to_string()))?;
        let provider_event_id = provider_event_id
            .ok_or_else(|| CalendarError::Provider("meeting has no graph event id".into()))?;
        let new_end = new_start + (old_end - old_start);
        let body = json!({
            "start": { "dateTime": new_start.to_rfc3339(), "timeZone": "UTC" },
            "end": { "dateTime": new_end.to_rfc3339(), "timeZone": "UTC" },
        });
        let response = self
            .client
            .patch(format!("{}/{}", self.events_url(), provider_event_id))
            .bearer_auth(&self.access_token)
            .json(&body)
            .send()
            .await
            .map_err(|e| CalendarError::Provider(format!("graph event patch failed: {e}")))?;
        if !response.status().is_success() {
            return Err(CalendarError::Provider(format!(
                "graph event patch returned HTTP {}",
                response.status()
            )));
        }
        self.internal.reschedule_recorded(event_id, new_start).await
    }

    async fn cancel(&self, event_id: &str) -> Result<(), CalendarError> {
        let id = Uuid::parse_str(event_id)
            .map_err(|_| CalendarError::InvalidInput("event id must be a UUID".into()))?;
        let provider_event_id: Option<String> =
            sqlx::query_scalar("SELECT provider_event_id FROM sales_meetings WHERE id = $1")
                .bind(id)
                .fetch_optional(self.internal.db())
                .await
                .map_err(|e| CalendarError::Database(e.to_string()))?
                .flatten();
        if let Some(provider_event_id) = provider_event_id {
            let response = self
                .client
                .delete(format!("{}/{}", self.events_url(), provider_event_id))
                .bearer_auth(&self.access_token)
                .send()
                .await
                .map_err(|e| CalendarError::Provider(format!("graph event delete failed: {e}")))?;
            if !response.status().is_success()
                && response.status() != reqwest::StatusCode::NOT_FOUND
            {
                return Err(CalendarError::Provider(format!(
                    "graph event delete returned HTTP {}",
                    response.status()
                )));
            }
        }
        self.internal.cancel_recorded(event_id).await
    }
}

/// First present, non-empty variable among `names` (same semantics as
/// `crate::config::read_env`).
fn read_env(names: &[&str]) -> Option<String> {
    names.iter().find_map(|name| {
        std::env::var(name)
            .ok()
            .map(|raw| raw.trim().to_string())
            .filter(|raw| !raw.is_empty())
    })
}

/// Graph returns UTC date-times without a timezone suffix and with up to 7
/// fractional-second digits (e.g. `2031-01-13T08:00:00.0000000`), which
/// `parse_from_rfc3339` rejects. Normalise before parsing.
fn parse_graph_datetime(raw: &str) -> Option<DateTime<Utc>> {
    if let Ok(dt) = DateTime::parse_from_rfc3339(raw) {
        return Some(dt.with_timezone(&Utc));
    }
    let trimmed = raw.trim().trim_end_matches('Z').trim_end_matches('z');
    NaiveDateTime::parse_from_str(trimmed, "%Y-%m-%dT%H:%M:%S%.f")
        .ok()
        .map(|naive| naive.and_utc())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn graph_datetime_formats_parse() {
        let expected = DateTime::parse_from_rfc3339("2031-01-13T08:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        for raw in [
            "2031-01-13T08:00:00Z",
            "2031-01-13T08:00:00.0000000",
            "2031-01-13T08:00:00.000Z",
        ] {
            assert_eq!(parse_graph_datetime(raw), Some(expected), "raw={raw}");
        }
        assert_eq!(parse_graph_datetime(""), None);
        assert_eq!(parse_graph_datetime("tomorrow"), None);
    }

    #[tokio::test]
    async fn from_env_requires_a_token() {
        if std::env::var("SALES_MICROSOFT_GRAPH_ACCESS_TOKEN").is_ok() {
            return;
        }
        let config = CalendarConfig::default();
        let db = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://localhost/unused")
            .expect("lazy pool");
        let internal = Arc::new(InternalCalendarProvider::new(db, config.clone()));
        assert!(MicrosoftCalendarProvider::from_env(config, internal).is_none());
    }
}
