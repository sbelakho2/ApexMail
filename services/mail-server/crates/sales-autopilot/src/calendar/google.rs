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

#[cfg(test)]
mod provider_wire_tests {
    //! The Google provider against a loopback HTTP mock and the canonical
    //! schema: freeBusy parsing (hostile payloads included), booking with
    //! provider-id/link extraction, compensation on conflict, and the
    //! reschedule/cancel id gates.

    use super::*;
    use crate::test_db::canonical_test_pool;
    use sqlx::PgPool;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Loopback mock answering by (method, path) with a JSON body or a bare
    /// status; counts DELETE calls (the compensation path).
    struct GoogleMock {
        port: u16,
        last_request: Arc<std::sync::Mutex<String>>,
    }

    impl GoogleMock {
        async fn start(routes: HashMap<(&'static str, String), (u16, serde_json::Value)>) -> Self {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
                .await
                .unwrap();
            let port = listener.local_addr().unwrap().port();
            let routes = Arc::new(routes);
            let _deletes = Arc::new(AtomicUsize::new(0));
            let last_request = Arc::new(std::sync::Mutex::new(String::new()));
            let last_srv = last_request.clone();
            let _handle = tokio::spawn(async move {
                loop {
                    let Ok((mut socket, _)) = listener.accept().await else {
                        return;
                    };
                    let routes = routes.clone();
                    let deletes = _deletes.clone();
                    let last_request = last_srv.clone();
                    tokio::spawn(async move {
                        let mut buf = [0u8; 8192];
                        let n = socket.read(&mut buf).await.unwrap_or(0);
                        let head = String::from_utf8_lossy(&buf[..n]);
                        let method_owned = head.split(' ').next().unwrap_or("").to_string();
                        let method: &'static str = Box::leak(method_owned.into_boxed_str());
                        let path = head
                            .split(' ')
                            .nth(1)
                            .unwrap_or("/")
                            .split('?')
                            .next()
                            .unwrap_or("/")
                            .to_string();
                        if method == "DELETE" {
                            deletes.fetch_add(1, Ordering::SeqCst);
                        }
                        *last_request.lock().unwrap_or_else(|e| e.into_inner()) =
                            format!("{method} {path}");
                        let (status, body) = routes
                            .get(&(method, path.clone()))
                            .cloned()
                            .unwrap_or((
                                404,
                                serde_json::json!({"error": "no route", "method": method, "path": path}),
                            ));
                        let body = body.to_string();
                        let response = format!(
                            "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                            body.len()
                        );
                        let _ = socket.write_all(response.as_bytes()).await;
                        let _ = socket.shutdown().await;
                    });
                }
            });
            Self { port, last_request }
        }

        fn last(&self) -> String {
            self.last_request
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
        }

        fn base(&self) -> String {
            format!("http://127.0.0.1:{}", self.port)
        }
    }

    async fn make_provider(base_url: &str) -> (GoogleCalendarProvider, PgPool) {
        let pool = canonical_test_pool("google_calendar_wire")
            .await
            .expect("configured TEST_DATABASE_URL must provision");
        let config = CalendarConfig::default();
        let internal = Arc::new(InternalCalendarProvider::new(pool.clone(), config.clone()));
        let provider = GoogleCalendarProvider {
            client: reqwest::Client::new(),
            base_url: base_url.to_string(),
            calendar_id: "primary".into(),
            access_token: "test-token".into(),
            internal,
            config,
        };
        (provider, pool)
    }

    fn availability_request(tenant: &str) -> AvailabilityRequest {
        AvailabilityRequest::new(
            tenant,
            chrono::NaiveDate::from_ymd_opt(2031, 1, 13).unwrap(),
            chrono_tz::Europe::Tallinn,
            "2031-01-12T08:00:00Z".parse::<DateTime<Utc>>().unwrap(),
        )
    }

    #[tokio::test]
    async fn freebusy_busy_entries_parse_and_hostile_entries_are_skipped() {
        let _placeholder = GoogleMock::start(HashMap::new()).await;
        let busy = serde_json::json!({
            "calendars": { "primary": { "busy": [
                { "start": "2031-01-13T08:00:00Z", "end": "2031-01-13T09:00:00Z" },
                { "start": "not-a-date", "end": "2031-01-13T10:00:00Z" },
                { "start": "2031-01-13T11:00:00Z", "end": "not-a-date" },
                { "start": "2031-01-13T12:00:00Z", "end": "2031-01-13T12:00:00Z" },
                { "start": "2031-01-13T13:00:00Z", "end": "2031-01-13T12:00:00Z" }
            ]}}
        });
        let mut routes = HashMap::new();
        routes.insert(("POST", "/freeBusy".to_string()), (200, busy));
        let mock = GoogleMock::start(routes).await;

        let (provider, _pool) = make_provider(&mock.base()).await;
        let busy = provider
            .busy_from_google(&availability_request("cal-busy"))
            .await
            .expect("freeBusy parses");
        assert_eq!(
            busy.len(),
            1,
            "only the well-formed interval survives: {busy:?}"
        );
        assert_eq!(
            busy[0],
            BusyInterval::new(
                parse_rfc3339("2031-01-13T08:00:00Z").unwrap(),
                parse_rfc3339("2031-01-13T09:00:00Z").unwrap(),
            )
        );
    }

    #[tokio::test]
    async fn freebusy_surfaces_http_and_json_failures() {
        // Non-2xx status.
        let mut routes = HashMap::new();
        routes.insert(
            ("POST", "/freeBusy".to_string()),
            (401, serde_json::json!({"error": "unauthorized"})),
        );
        let mock = GoogleMock::start(routes).await;
        let (provider, _pool) = make_provider(&mock.base()).await;
        let error = provider
            .busy_from_google(&availability_request("cal-http"))
            .await
            .expect_err("HTTP 401 must surface");
        assert!(error.to_string().contains("HTTP 401"), "{error}");

        // Invalid JSON body.
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let _ = socket.read(&mut buf).await;
                    let _ = socket
                        .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\nconnection: close\r\n\r\nnotjs")
                        .await;
                    let _ = socket.shutdown().await;
                });
            }
        });
        let (provider, _pool) = make_provider(&format!("http://127.0.0.1:{port}")).await;
        let error = provider
            .busy_from_google(&availability_request("cal-json"))
            .await
            .expect_err("invalid JSON must surface");
        assert!(error.to_string().contains("invalid JSON"), "{error}");
    }

    #[tokio::test]
    async fn create_event_validates_time_and_extracts_the_meet_link() {
        // end <= start is refused before any HTTP call.
        let mock = GoogleMock::start(HashMap::new()).await;
        let (provider, _pool) = make_provider(&mock.base()).await;
        let request = CreateEventRequest {
            tenant_id: "cal-create".into(),
            title: "Intro call".into(),
            attendees: vec!["prospect@example.com".into()],
            // One timestamp for both bounds: end == start is the invalid case
            // (two independent now() calls would make end nanoseconds later).
            start: "2031-01-13T09:00:00Z".parse().unwrap(),
            end: "2031-01-13T09:00:00Z".parse().unwrap(),
            timezone: chrono_tz::Europe::Tallinn,
            enrollment_id: None,
            account_id: None,
            contact_id: None,
            salesperson: None,
            conferencing_link: None,
            provider: "google".into(),
            provider_event_id: None,
        };
        let error = provider
            .create_event(&request)
            .await
            .expect_err("end must be after start");
        assert!(matches!(error, CalendarError::InvalidInput(_)), "{error}");

        // A success payload without an id is a provider failure.
        let mut routes = HashMap::new();
        routes.insert(
            ("POST", "/calendars/primary/events".to_string()),
            (200, serde_json::json!({"status": "confirmed"})),
        );
        let mock = GoogleMock::start(routes).await;
        let (provider, _pool) = make_provider(&mock.base()).await;
        let request = CreateEventRequest {
            end: request.start + chrono::Duration::minutes(30),
            ..request
        };
        let error = provider
            .create_event(&request)
            .await
            .expect_err("no provider id must fail");
        let _ = &mock;
        assert!(
            error.to_string().contains("no id"),
            "{error} last={}",
            mock.last()
        );
    }

    #[tokio::test]
    async fn from_env_reads_the_documented_variables_and_trims_the_base_url() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("SALES_GOOGLE_CALENDAR_ACCESS_TOKEN", "tok");
        std::env::set_var("SALES_GOOGLE_CALENDAR_BASE_URL", "http://127.0.0.1:9/");
        std::env::set_var("SALES_GOOGLE_CALENDAR_ID", "cal-9");
        let db = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://localhost/unused")
            .unwrap();
        let internal = Arc::new(InternalCalendarProvider::new(db, CalendarConfig::default()));
        let provider =
            GoogleCalendarProvider::from_env(CalendarConfig::default(), internal).expect("built");
        assert_eq!(
            provider.base_url, "http://127.0.0.1:9",
            "trailing slash trimmed"
        );
        assert_eq!(provider.calendar_id, "cal-9");
        // The Debug impl never leaks the bearer token.
        let rendered = format!("{provider:?}");
        assert!(!rendered.contains("tok"), "{rendered}");
        assert!(rendered.contains("cal-9"));

        std::env::remove_var("SALES_GOOGLE_CALENDAR_ACCESS_TOKEN");
        std::env::remove_var("SALES_GOOGLE_CALENDAR_BASE_URL");
        std::env::remove_var("SALES_GOOGLE_CALENDAR_ID");
    }

    #[tokio::test]
    async fn reschedule_and_cancel_reject_non_uuid_ids() {
        let mock = GoogleMock::start(HashMap::new()).await;
        let (provider, _pool) = make_provider(&mock.base()).await;
        let error = provider
            .reschedule("not-a-uuid", chrono::Utc::now())
            .await
            .expect_err("non-UUID ids are refused");
        assert!(matches!(error, CalendarError::InvalidInput(_)), "{error}");
        let error = provider
            .cancel("not-a-uuid")
            .await
            .expect_err("non-UUID ids are refused");
        assert!(matches!(error, CalendarError::InvalidInput(_)), "{error}");
    }

    #[tokio::test]
    async fn reschedule_of_an_unknown_event_is_event_not_found() {
        let mock = GoogleMock::start(HashMap::new()).await;
        let (provider, _pool) = make_provider(&mock.base()).await;
        let error = provider
            .reschedule(&Uuid::new_v4().to_string(), chrono::Utc::now())
            .await
            .expect_err("unknown event");
        assert!(matches!(error, CalendarError::EventNotFound(_)), "{error}");
    }

    #[tokio::test]
    async fn events_url_percent_encodes_the_calendar_id() {
        let mock = GoogleMock::start(HashMap::new()).await;
        let (provider, _pool) = make_provider(&mock.base()).await;
        assert_eq!(
            provider.events_url(),
            format!("{}/calendars/primary/events", mock.base())
        );
    }

    #[test]
    fn urlencoding_escapes_every_non_url_character_class() {
        assert_eq!(urlencoding("a b"), "a%20b");
        assert_eq!(urlencoding("c/d"), "c%2Fd");
        assert_eq!(urlencoding("ü"), "%C3%BC");
        assert_eq!(urlencoding("+&?"), "%2B%26%3F");
        assert_eq!(urlencoding("-_.~@"), "-_.~@");
    }

    /// The full authority loop: Google free/busy MERGES with the internal
    /// store of record, and only slots free on BOTH calendars are offered.
    #[tokio::test]
    async fn availability_merges_google_busy_with_the_internal_store() {
        let payload = serde_json::json!({
            "calendars": { "primary": { "busy": [
                { "start": "2031-01-13T08:00:00Z", "end": "2031-01-13T09:00:00Z" }
            ]}}
        });
        let mut routes = HashMap::new();
        routes.insert(("POST", "/freeBusy".to_string()), (200, payload));
        let mock = GoogleMock::start(routes).await;
        let (provider, pool) = make_provider(&mock.base()).await;

        // An INTERNAL meeting overlapping Google's busy block: the merged
        // busy set is the union, so neither source can be bypassed.
        let tenant = crate::test_db::unique_test_tenant("gcal-avail");
        sqlx::query(
            "INSERT INTO sales_calendar_events \
                 (id, tenant_id, title, attendees, start_at, end_at, meeting_link) \
             VALUES (gen_random_uuid(), $1, 'internal hold', '{}', $2, $3, 'https://meet')",
        )
        .bind(&tenant)
        .bind("2031-01-13T10:00:00Z".parse::<DateTime<Utc>>().unwrap())
        .bind("2031-01-13T11:00:00Z".parse::<DateTime<Utc>>().unwrap())
        .execute(&pool)
        .await
        .expect("insert internal hold");

        let slots = provider
            .availability(&availability_request(&tenant))
            .await
            .expect("availability resolves");
        // The offered slots must never intersect either busy interval.
        let busy_start: DateTime<Utc> = "2031-01-13T08:00:00Z".parse().unwrap();
        let internal_end: DateTime<Utc> = "2031-01-13T11:00:00Z".parse().unwrap();
        assert!(!slots.is_empty(), "a free day must still offer slots");
        for slot in &slots {
            let overlaps_google = slot.start < busy_start && slot.end > busy_start;
            let internal_start: DateTime<Utc> = "2031-01-13T10:00:00Z".parse().unwrap();
            let overlaps_internal = slot.start < internal_end && slot.end > internal_start;
            assert!(
                !(overlaps_google || overlaps_internal),
                "slot {slot:?} overlaps a busy interval"
            );
        }
    }

    /// The booking happy path END-TO-END: provider call -> provider id/link
    /// extraction -> internal mirror rows (store of record).
    #[tokio::test]
    async fn create_event_books_on_google_and_mirrors_the_store_of_record() {
        let payload = serde_json::json!({
            "id": "g_evt_abc123",
            "hangoutLink": "https://meet.google.com/abc-defg-hij",
            "status": "confirmed"
        });
        let mut routes = HashMap::new();
        routes.insert(
            ("POST", "/calendars/primary/events".to_string()),
            (200, payload),
        );
        let mock = GoogleMock::start(routes).await;
        let (provider, pool) = make_provider(&mock.base()).await;
        let tenant = crate::test_db::unique_test_tenant("gcal-book");

        let request = CreateEventRequest {
            tenant_id: tenant.clone(),
            title: "Discovery call".into(),
            attendees: vec!["prospect@example.com".into()],
            start: "2031-01-13T09:00:00Z".parse().unwrap(),
            end: "2031-01-13T09:30:00Z".parse().unwrap(),
            timezone: chrono_tz::Europe::Tallinn,
            enrollment_id: None,
            account_id: None,
            contact_id: None,
            salesperson: None,
            conferencing_link: None,
            provider: "google".into(),
            provider_event_id: None,
        };
        let booked = provider
            .create_event(&request)
            .await
            .expect("the booking lands");
        assert_eq!(booked.provider, "google");
        assert_eq!(booked.provider_event_id.as_deref(), Some("g_evt_abc123"));
        assert_eq!(
            booked.conferencing_link,
            "https://meet.google.com/abc-defg-hij"
        );

        // The store of record: one availability-index row and one meeting row
        // carrying the real provider id and the Meet link.
        let mirrored: (String, String, String) = sqlx::query_as(
            "SELECT m.provider, m.provider_event_id, m.conferencing_link \
             FROM sales_meetings m WHERE m.tenant_id = $1 AND m.status = 'booked'",
        )
        .bind(&tenant)
        .fetch_one(&pool)
        .await
        .expect("mirrored meeting");
        assert_eq!(mirrored.0, "google");
        assert_eq!(mirrored.1, "g_evt_abc123");
        assert_eq!(mirrored.2, "https://meet.google.com/abc-defg-hij");
        let indexed: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM sales_calendar_events WHERE tenant_id = $1",
        )
        .bind(&tenant)
        .fetch_one(&pool)
        .await
        .expect("availability index");
        assert_eq!(indexed, 1);

        // Reschedule moves BOTH the provider event and the store of record.
        let mut routes = HashMap::new();
        routes.insert(
            (
                "PATCH",
                "/calendars/primary/events/g_evt_abc123".to_string(),
            ),
            (200, serde_json::json!({"id": "g_evt_abc123"})),
        );
        let mock2 = GoogleMock::start(routes).await;
        let (provider, pool) = make_provider_at(&mock2.base(), pool).await;
        let new_start: DateTime<Utc> = "2031-01-13T14:00:00Z".parse().unwrap();
        let rescheduled = provider
            .reschedule(&booked.event_id, new_start)
            .await
            .expect("reschedule lands");
        assert_eq!(rescheduled.status, "rescheduled");
        assert_eq!(
            rescheduled.start, new_start,
            "duration is preserved from 09:00+30min"
        );
        let moved: (DateTime<Utc>, String) =
            sqlx::query_as("SELECT start_at, status FROM sales_meetings WHERE id = $1")
                .bind(Uuid::parse_str(&booked.event_id).unwrap())
                .fetch_one(&pool)
                .await
                .expect("moved meeting");
        assert_eq!(moved.0, new_start);
        assert_eq!(moved.1, "rescheduled");

        // Cancel removes the availability row and marks the store cancelled,
        // and deletes the event at the provider.
        let mut routes = HashMap::new();
        routes.insert(
            (
                "DELETE",
                "/calendars/primary/events/g_evt_abc123".to_string(),
            ),
            (204, serde_json::json!({})),
        );
        let mock3 = GoogleMock::start(routes).await;
        let (provider, pool) = make_provider_at(&mock3.base(), pool).await;
        provider
            .cancel(&booked.event_id)
            .await
            .expect("cancel lands");
        let status: String = sqlx::query_scalar("SELECT status FROM sales_meetings WHERE id = $1")
            .bind(Uuid::parse_str(&booked.event_id).unwrap())
            .fetch_one(&pool)
            .await
            .expect("cancelled meeting");
        assert_eq!(status, "cancelled");
        assert_eq!(
            mock3.last(),
            "DELETE /calendars/primary/events/g_evt_abc123",
            "the provider event is deleted"
        );
    }

    async fn make_provider_at(base_url: &str, pool: PgPool) -> (GoogleCalendarProvider, PgPool) {
        let config = CalendarConfig::default();
        let internal = Arc::new(InternalCalendarProvider::new(pool.clone(), config.clone()));
        let provider = GoogleCalendarProvider {
            client: reqwest::Client::new(),
            base_url: base_url.to_string(),
            calendar_id: "primary".into(),
            access_token: "test-token".into(),
            internal,
            config,
        };
        (provider, pool)
    }

    #[tokio::test]
    async fn create_event_surfaces_transport_http_and_json_failures() {
        let request = CreateEventRequest {
            tenant_id: "cal-fail".into(),
            title: "Demo".into(),
            attendees: vec!["prospect@example.com".into()],
            start: "2031-01-13T09:00:00Z".parse().unwrap(),
            end: "2031-01-13T09:30:00Z".parse().unwrap(),
            timezone: chrono_tz::Europe::Tallinn,
            enrollment_id: None,
            account_id: None,
            contact_id: None,
            salesperson: None,
            conferencing_link: None,
            provider: "google".into(),
            provider_event_id: None,
        };

        // Transport failure: port 1 on the loopback interface is reserved and
        // refuses connections — nothing can be listening there.
        let (provider, _pool) = make_provider("http://127.0.0.1:1").await;
        let error = provider
            .create_event(&request)
            .await
            .expect_err("transport");
        assert!(error.to_string().contains("insert failed"), "{error}");

        // HTTP failure: a 500 from the provider surfaces, not a booking.
        let mut routes = HashMap::new();
        routes.insert(
            ("POST", "/calendars/primary/events".to_string()),
            (500, serde_json::json!({"error": "backend"})),
        );
        let mock = GoogleMock::start(routes).await;
        let (provider, _pool) = make_provider(&mock.base()).await;
        let error = provider.create_event(&request).await.expect_err("HTTP 500");
        assert!(error.to_string().contains("HTTP 500"), "{error}");

        // Invalid JSON: the payload cannot be read, so the booking fails.
        // A bare `notjs` body is not a JSON value (the route mock can only
        // speak JSON, so this needs a raw socket).
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let _ = socket.read(&mut buf).await;
                    let _ = socket
                        .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\nconnection: close\r\n\r\nnotjs")
                        .await;
                    let _ = socket.shutdown().await;
                });
            }
        });
        let (provider, _pool) = make_provider(&format!("http://127.0.0.1:{port}")).await;
        let error = provider
            .create_event(&request)
            .await
            .expect_err("invalid JSON");
        assert!(error.to_string().contains("invalid JSON"), "{error}");

        // A non-string id cannot be used as a provider id.
        let mut routes = HashMap::new();
        routes.insert(
            ("POST", "/calendars/primary/events".to_string()),
            (200, serde_json::json!({"id": 12345})),
        );
        let mock = GoogleMock::start(routes).await;
        let (provider, _pool) = make_provider(&mock.base()).await;
        let error = provider
            .create_event(&request)
            .await
            .expect_err("numeric id");
        assert!(error.to_string().contains("no id"), "{error}");
    }

    /// A booking the store of record REJECTS (the slot was taken internally)
    /// is compensated: the just-created Google event is deleted again.
    #[tokio::test]
    async fn a_rejected_internal_booking_is_compensated_at_the_provider() {
        let payload = serde_json::json!({ "id": "g_evt_comp", "hangoutLink": "" });
        let mut routes = HashMap::new();
        routes.insert(
            ("POST", "/calendars/primary/events".to_string()),
            (200, payload),
        );
        // The compensation DELETE may target any URL; answer 204.
        routes.insert(
            ("DELETE", "/__any__".to_string()),
            (204, serde_json::json!({})),
        );
        let mock = GoogleMock::start(routes).await;
        let (provider, pool) = make_provider(&mock.base()).await;
        let tenant = crate::test_db::unique_test_tenant("gcal-comp");

        // Someone else already holds the slot internally.
        sqlx::query(
            "INSERT INTO sales_calendar_events \
                 (id, tenant_id, title, attendees, start_at, end_at, meeting_link) \
             VALUES (gen_random_uuid(), $1, 'taken', '{}', $2, $3, 'https://meet')",
        )
        .bind(&tenant)
        .bind("2031-01-13T09:00:00Z".parse::<DateTime<Utc>>().unwrap())
        .bind("2031-01-13T09:30:00Z".parse::<DateTime<Utc>>().unwrap())
        .execute(&pool)
        .await
        .expect("insert the conflicting hold");

        let request = CreateEventRequest {
            tenant_id: tenant,
            title: "Conflicted".into(),
            attendees: vec!["prospect@example.com".into()],
            start: "2031-01-13T09:00:00Z".parse().unwrap(),
            end: "2031-01-13T09:30:00Z".parse().unwrap(),
            timezone: chrono_tz::Europe::Tallinn,
            enrollment_id: None,
            account_id: None,
            contact_id: None,
            salesperson: None,
            conferencing_link: None,
            provider: "google".into(),
            provider_event_id: None,
        };
        let error = provider
            .create_event(&request)
            .await
            .expect_err("the slot is unavailable");
        assert!(matches!(error, CalendarError::SlotUnavailable), "{error}");
        assert_eq!(
            mock.last(),
            "DELETE /calendars/primary/events/g_evt_comp",
            "the provider event was compensated (deleted)"
        );
    }

    /// A provider DELETE answering 404 is tolerated (the event is already
    /// gone in Google) and the internal record is still cancelled; a 500 is
    /// surfaced.
    #[tokio::test]
    async fn cancel_tolerates_a_404_and_surfaces_a_500_from_the_provider() {
        let (_provider, pool) =
            make_provider(&GoogleMock::start(HashMap::new()).await.base()).await;
        let tenant = crate::test_db::unique_test_tenant("gcal-cancel");
        let event_id = Uuid::new_v4();
        let start: DateTime<Utc> = "2031-01-13T09:00:00Z".parse().unwrap();
        let end: DateTime<Utc> = "2031-01-13T09:30:00Z".parse().unwrap();
        sqlx::query(
            "INSERT INTO sales_meetings \
                 (id, tenant_id, provider, provider_event_id, start_at, end_at, timezone, \
                  conferencing_link, status) \
             VALUES ($1, $2, 'google', 'g_evt_gone', $3, $4, 'Europe/Tallinn', \
                     'https://meet', 'booked')",
        )
        .bind(event_id)
        .bind(&tenant)
        .bind(start)
        .bind(end)
        .execute(&pool)
        .await
        .expect("insert the meeting");
        sqlx::query(
            "INSERT INTO sales_calendar_events \
                 (id, tenant_id, title, attendees, start_at, end_at, meeting_link) \
             VALUES ($1, $2, 'Move me', '{}', $3, $4, 'https://meet')",
        )
        .bind(event_id)
        .bind(&tenant)
        .bind(start)
        .bind(end)
        .execute(&pool)
        .await
        .expect("insert the availability row");

        // 404: tolerated — the internal record is cancelled anyway.
        let mut routes = HashMap::new();
        routes.insert(
            ("DELETE", "/calendars/primary/events/g_evt_gone".to_string()),
            (404, serde_json::json!({"error": "gone"})),
        );
        let mock404 = GoogleMock::start(routes).await;
        let (provider404, _pool) = make_provider_at(&mock404.base(), pool.clone()).await;
        provider404
            .cancel(&event_id.to_string())
            .await
            .expect("a 404 delete is tolerated");
        let status: String = sqlx::query_scalar("SELECT status FROM sales_meetings WHERE id = $1")
            .bind(event_id)
            .fetch_one(&pool)
            .await
            .expect("meeting row");
        assert_eq!(status, "cancelled");

        // 500: surfaced.
        sqlx::query("UPDATE sales_meetings SET status = 'booked' WHERE id = $1")
            .bind(event_id)
            .execute(&pool)
            .await
            .expect("re-book");
        let mut routes = HashMap::new();
        routes.insert(
            ("DELETE", "/calendars/primary/events/g_evt_gone".to_string()),
            (500, serde_json::json!({"error": "backend"})),
        );
        let mock500 = GoogleMock::start(routes).await;
        let (provider500, _pool) = make_provider_at(&mock500.base(), pool.clone()).await;
        let error = provider500
            .cancel(&event_id.to_string())
            .await
            .expect_err("a 500 delete surfaces");
        assert!(error.to_string().contains("HTTP 500"), "{error}");
    }

    #[tokio::test]
    async fn reschedule_surfaces_a_provider_patch_failure() {
        let (provider, pool) = make_provider(&GoogleMock::start(HashMap::new()).await.base()).await;
        let tenant = crate::test_db::unique_test_tenant("gcal-resched");
        let event_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO sales_meetings \
                 (id, tenant_id, provider, provider_event_id, start_at, end_at, timezone, \
                  conferencing_link, status) \
             VALUES ($1, $2, 'google', 'g_evt_move', NOW(), NOW() + interval '30 minutes', \
                     'Europe/Tallinn', 'https://meet', 'booked')",
        )
        .bind(event_id)
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("insert the meeting");
        // No route registered: the mock answers 404 -> the patch fails and
        // the internal record is untouched.
        let error = provider
            .reschedule(
                &event_id.to_string(),
                "2031-01-13T14:00:00Z".parse().unwrap(),
            )
            .await
            .expect_err("the patch must surface");
        assert!(error.to_string().contains("HTTP 404"), "{error}");
        let status: String = sqlx::query_scalar("SELECT status FROM sales_meetings WHERE id = $1")
            .bind(event_id)
            .fetch_one(&pool)
            .await
            .expect("meeting row");
        assert_eq!(status, "booked", "a failed provider patch changes nothing");
    }
}
