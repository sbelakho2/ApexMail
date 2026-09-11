//! Google Calendar provider (`CalendarProvider`).
//!
//! # Authority
//!
//! When configured (`SALES_CALENDAR_PROVIDER=google` +
//! `SALES_GOOGLE_CALENDAR_ACCESS_TOKEN`), the Google calendar is the
//! **authoritative** source of the salesperson's availability: `availability`
//! reads `freeBusy` from the real API and intersects it with the internal
//! store of record, so the prospect can never be offered a time that
//! conflicts with the salesperson's actual calendar. Every booking is
//! mirrored into `sales_calendar_events` + `sales_meetings` (the store of
//! record) through [`super::internal::InternalCalendarProvider`].
//!
//! # API usage
//!
//! * availability: `POST {base}/freeBusy`
//! * booking: `POST {base}/calendars/{calendar_id}/events?conferenceDataVersion=1`
//!   requesting a Google Meet link (`conferenceData.createRequest`)
//! * reschedule: `PATCH {base}/calendars/{calendar_id}/events/{event_id}`
//! * cancel: `DELETE {base}/calendars/{calendar_id}/events/{event_id}`
//!
//! Credentials are read directly from the environment because
//! [`crate::config::SalesConfig`] has no calendar field (out of this change's
//! scope): `SALES_GOOGLE_CALENDAR_ACCESS_TOKEN` (required),
//! `SALES_GOOGLE_CALENDAR_ID` (default `primary`),
//! `SALES_GOOGLE_CALENDAR_BASE_URL` (default the real API).

use std::sync::Arc;
use std::time::Duration as StdDuration;

use chrono::{DateTime, Utc};
use serde_json::json;
use uuid::Uuid;

use super::availability::{generate_slots, AvailabilityRequest, BusyInterval, TimeSlot};
use super::internal::InternalCalendarProvider;
use super::timezone::local_day_bounds;
use super::{BookedEvent, CalendarConfig, CalendarError, CalendarProvider, CreateEventRequest};

const DEFAULT_GOOGLE_CALENDAR_BASE_URL: &str = "https://www.googleapis.com/calendar/v3";
const HTTP_TIMEOUT_SECS: u64 = 15;

pub struct GoogleCalendarProvider {
    client: reqwest::Client,
    base_url: String,
    calendar_id: String,
    access_token: String,
    internal: Arc<InternalCalendarProvider>,
    config: CalendarConfig,
}

impl std::fmt::Debug for GoogleCalendarProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GoogleCalendarProvider")
            .field("base_url", &self.base_url)
            .field("calendar_id", &self.calendar_id)
            .finish_non_exhaustive()
    }
}

impl GoogleCalendarProvider {
    /// Build from the documented environment variables. `None` when the
    /// access token is absent (the caller falls back to the internal
    /// provider).
    pub fn from_env(
        config: CalendarConfig,
        internal: Arc<InternalCalendarProvider>,
    ) -> Option<Self> {
        // Mirrors `config.rs`'s `read_env` pattern: the SALES_-prefixed
        // production name first, then the short local-development alias.
        let access_token = read_env(&[
            "SALES_GOOGLE_CALENDAR_ACCESS_TOKEN",
            "GOOGLE_CALENDAR_ACCESS_TOKEN",
        ])?;
        let base_url = read_env(&["SALES_GOOGLE_CALENDAR_BASE_URL", "GOOGLE_CALENDAR_BASE_URL"])
            .map(|raw| raw.trim_end_matches('/').to_string())
            .unwrap_or_else(|| DEFAULT_GOOGLE_CALENDAR_BASE_URL.to_string());
        let calendar_id = read_env(&["SALES_GOOGLE_CALENDAR_ID", "GOOGLE_CALENDAR_ID"])
            .unwrap_or_else(|| "primary".into());
        let client = reqwest::Client::builder()
            .timeout(StdDuration::from_secs(HTTP_TIMEOUT_SECS))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Some(Self {
            client,
            base_url,
            calendar_id,
            access_token,
            internal,
            config,
        })
    }

    fn events_url(&self) -> String {
        format!(
            "{}/calendars/{}/events",
            self.base_url,
            urlencoding(&self.calendar_id)
        )
    }

    /// Busy intervals from the real Google calendar for the request's local
    /// day. Errors are surfaced (fail closed) rather than silently offering
    /// potentially conflicting slots.
    pub async fn busy_from_google(
        &self,
        request: &AvailabilityRequest,
    ) -> Result<Vec<BusyInterval>, CalendarError> {
        let (day_start, day_end) =
            local_day_bounds(request.timezone, request.date).ok_or_else(|| {
                CalendarError::InvalidInput("the local day cannot be resolved".into())
            })?;
        let body = json!({
            "timeMin": day_start.to_rfc3339(),
            "timeMax": day_end.to_rfc3339(),
            "items": [{ "id": self.calendar_id }],
        });
        let response = self
            .client
            .post(format!("{}/freeBusy", self.base_url))
            .bearer_auth(&self.access_token)
            .json(&body)
            .send()
            .await
            .map_err(|e| CalendarError::Provider(format!("google freeBusy request failed: {e}")))?;
        let status = response.status();
        let payload: serde_json::Value = response.json().await.map_err(|e| {
            CalendarError::Provider(format!("google freeBusy returned invalid JSON: {e}"))
        })?;
        if !status.is_success() {
            return Err(CalendarError::Provider(format!(
                "google freeBusy returned HTTP {status}"
            )));
        }
        let mut busy = Vec::new();
        if let Some(entries) = payload
            .get("calendars")
            .and_then(|calendars| calendars.get(&self.calendar_id))
            .and_then(|calendar| calendar.get("busy"))
            .and_then(|busy| busy.as_array())
        {
            for entry in entries {
                let start = entry
                    .get("start")
                    .and_then(|v| v.as_str())
                    .and_then(parse_rfc3339);
                let end = entry
                    .get("end")
                    .and_then(|v| v.as_str())
                    .and_then(parse_rfc3339);
                if let (Some(start), Some(end)) = (start, end) {
                    if end > start {
                        busy.push(BusyInterval::new(start, end));
                    }
                }
            }
        }
        Ok(busy)
    }

    /// Merge Google's busy intervals with the internal store of record. A
    /// slot is offered only when BOTH calendars are free.
    async fn merged_busy(
        &self,
        request: &AvailabilityRequest,
    ) -> Result<Vec<BusyInterval>, CalendarError> {
        let mut busy = self.internal.busy_intervals(request).await?;
        busy.extend(self.busy_from_google(request).await?);
        Ok(busy)
    }
}

#[async_trait::async_trait]
impl CalendarProvider for GoogleCalendarProvider {
    fn id(&self) -> &'static str {
        "google"
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
            "summary": request.title,
            "start": {
                "dateTime": request.start.to_rfc3339(),
                "timeZone": request.timezone.name(),
            },
            "end": {
                "dateTime": request.end.to_rfc3339(),
                "timeZone": request.timezone.name(),
            },
            "attendees": request
                .attendees_all()
                .into_iter()
                .map(|email| json!({ "email": email }))
                .collect::<Vec<_>>(),
            "conferenceData": {
                "createRequest": {
                    "requestId": Uuid::new_v4().to_string(),
                    "conferenceSolutionKey": { "type": "hangoutsMeet" },
                }
            },
            "extendedProperties": {
                "private": {
                    "apexmailTenant": request.tenant_id,
                }
            },
        });
        let response = self
            .client
            .post(format!("{}?conferenceDataVersion=1", self.events_url()))
            .bearer_auth(&self.access_token)
            .json(&body)
            .send()
            .await
            .map_err(|e| CalendarError::Provider(format!("google event insert failed: {e}")))?;
        let status = response.status();
        let payload: serde_json::Value = response.json().await.map_err(|e| {
            CalendarError::Provider(format!("google event insert returned invalid JSON: {e}"))
        })?;
        if !status.is_success() {
            return Err(CalendarError::Provider(format!(
                "google event insert returned HTTP {status}"
            )));
        }
        let provider_event_id = payload
            .get("id")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .ok_or_else(|| CalendarError::Provider("google event insert returned no id".into()))?;
        // An empty link means the API did not return a Meet link (e.g.
        // conferenceData not honoured); the internal store generates the
        // deterministic handle from the real meeting id in that case.
        let link = payload
            .get("hangoutLink")
            .and_then(|v| v.as_str())
            .filter(|link| !link.trim().is_empty())
            .unwrap_or("")
            .to_string();

        // Store of record. If the internal mirror hits the exclusion
        // constraint (someone else booked the slot), compensate by removing
        // the Google event so the real calendar stays consistent.
        match self
            .internal
            .record_event(request, "google", Some(&provider_event_id), link)
            .await
        {
            Ok(booked) => Ok(booked),
            Err(error) => {
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
        let row: Option<(String, DateTime<Utc>, DateTime<Utc>)> = sqlx::query_as(
            "SELECT provider_event_id, start_at, end_at FROM sales_meetings WHERE id = $1",
        )
        .bind(
            Uuid::parse_str(event_id)
                .map_err(|_| CalendarError::InvalidInput("event id must be a UUID".into()))?,
        )
        .fetch_optional(self.internal.db())
        .await
        .map_err(|e| CalendarError::Database(e.to_string()))?;
        let (provider_event_id, old_start, old_end) =
            row.ok_or_else(|| CalendarError::EventNotFound(event_id.to_string()))?;
        let new_end = new_start + (old_end - old_start);
        let body = json!({
            "start": { "dateTime": new_start.to_rfc3339(), "timeZone": self.config.timezone.name() },
            "end": { "dateTime": new_end.to_rfc3339(), "timeZone": self.config.timezone.name() },
        });
        let response = self
            .client
            .patch(format!("{}/{}", self.events_url(), provider_event_id))
            .bearer_auth(&self.access_token)
            .json(&body)
            .send()
            .await
            .map_err(|e| CalendarError::Provider(format!("google event patch failed: {e}")))?;
        if !response.status().is_success() {
            return Err(CalendarError::Provider(format!(
                "google event patch returned HTTP {}",
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
                .map_err(|e| CalendarError::Provider(format!("google event delete failed: {e}")))?;
            // 404/410 mean the event is already gone in Google; the internal
            // record still needs to be cancelled.
            if !response.status().is_success()
                && response.status() != reqwest::StatusCode::NOT_FOUND
                && response.status() != reqwest::StatusCode::GONE
            {
                return Err(CalendarError::Provider(format!(
                    "google event delete returned HTTP {}",
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

fn parse_rfc3339(raw: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(raw)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

/// Minimal percent-encoding for path segments (`primary` needs none; custom
/// calendar ids contain `@` and `.`).
fn urlencoding(value: &str) -> String {
    value
        .chars()
        .map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' | '@' => c.to_string(),
            other => other
                .to_string()
                .bytes()
                .map(|b| format!("%{b:02X}"))
                .collect(),
        })
        .collect()
}

#[allow(dead_code)]
fn duration_minutes(start: DateTime<Utc>, end: DateTime<Utc>) -> i64 {
    (end - start).num_minutes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn from_env_requires_a_token() {
        // Serialize with other env-mutating tests via a unique variable name
        // is impossible; this test only checks the None path when the
        // variable is absent, which is the default in CI.
        if std::env::var("SALES_GOOGLE_CALENDAR_ACCESS_TOKEN").is_ok() {
            return;
        }
        let config = CalendarConfig::default();
        let db = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://localhost/unused")
            .expect("lazy pool");
        let internal = Arc::new(InternalCalendarProvider::new(db, config.clone()));
        assert!(GoogleCalendarProvider::from_env(config, internal).is_none());
    }

    #[test]
    fn urls_and_parsing() {
        assert_eq!(urlencoding("primary"), "primary");
        assert_eq!(urlencoding("a@b.com"), "a@b.com");
        assert!(parse_rfc3339("2031-01-13T08:00:00Z").is_some());
        assert!(parse_rfc3339("not-a-date").is_none());
        let start = parse_rfc3339("2031-01-13T08:00:00Z").unwrap();
        let end = parse_rfc3339("2031-01-13T08:30:00Z").unwrap();
        assert_eq!(duration_minutes(start, end), 30);
    }
}
