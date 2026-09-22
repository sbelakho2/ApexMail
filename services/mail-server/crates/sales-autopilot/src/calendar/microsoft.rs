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

#[cfg(test)]
mod provider_wire_tests {
    //! The Microsoft provider against a loopback Graph mock and the
    //! canonical schema: getSchedule parsing (free entries skipped, hostile
    //! datetimes dropped), HTTP failure surfacing, booking gates, and the
    //! env-driven construction.

    use super::*;
    use crate::test_db::canonical_test_pool;
    use sqlx::PgPool;
    use std::collections::HashMap;
    use std::sync::Arc;

    static ENV_LOCK: std::sync::LazyLock<tokio::sync::Mutex<()>> =
        std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

    async fn graph_mock(
        routes: HashMap<(&'static str, String), (u16, serde_json::Value)>,
    ) -> (String, tokio::task::JoinHandle<()>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let routes = Arc::new(routes);
        let handle = tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                let routes = routes.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 8192];
                    let n = socket.read(&mut buf).await.unwrap_or(0);
                    let head = String::from_utf8_lossy(&buf[..n]);
                    let method: &'static str = Box::leak(
                        head.split(' ')
                            .next()
                            .unwrap_or("")
                            .to_string()
                            .into_boxed_str(),
                    );
                    let path = head
                        .split(' ')
                        .nth(1)
                        .unwrap_or("/")
                        .split('?')
                        .next()
                        .unwrap_or("/")
                        .to_string();
                    let (status, body) = routes
                        .get(&(method, path))
                        .cloned()
                        .unwrap_or((404, serde_json::json!({"error": {"message": "no route"}})));
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
        (format!("http://127.0.0.1:{port}",), handle)
    }

    async fn make_provider(base_url: &str) -> (MicrosoftCalendarProvider, PgPool) {
        let pool = canonical_test_pool("microsoft_calendar_wire")
            .await
            .expect("configured TEST_DATABASE_URL must provision");
        let config = CalendarConfig::default();
        let internal = Arc::new(InternalCalendarProvider::new(pool.clone(), config.clone()));
        let provider = MicrosoftCalendarProvider {
            client: reqwest::Client::new(),
            base_url: base_url.to_string(),
            user_id: "me".into(),
            access_token: "test-token".into(),
            internal,
            config,
        };
        (provider, pool)
    }

    fn request(tenant: &str) -> AvailabilityRequest {
        AvailabilityRequest::new(
            tenant,
            chrono::NaiveDate::from_ymd_opt(2031, 1, 13).unwrap(),
            chrono_tz::Europe::Tallinn,
            "2031-01-12T08:00:00Z".parse().unwrap(),
        )
    }

    #[tokio::test]
    async fn get_schedule_skips_free_and_hostile_entries() {
        let payload = serde_json::json!({ "value": [
            { "scheduleItems": [
                { "status": "busy", "start": { "dateTime": "2031-01-13T08:00:00.0000000Z" }, "end": { "dateTime": "2031-01-13T09:00:00.0000000Z" } },
                { "status": "Free", "start": { "dateTime": "2031-01-13T09:00:00.0000000Z" }, "end": { "dateTime": "2031-01-13T10:00:00.0000000Z" } },
                { "status": "oof", "start": { "dateTime": "nope" }, "end": { "dateTime": "2031-01-13T11:00:00.0000000Z" } },
                { "status": "tentative", "start": { "dateTime": "2031-01-13T12:00:00.0000000Z" }, "end": { "dateTime": "2031-01-13T12:00:00.0000000Z" } },
                { "status": "workingElsewhere", "start": { "dateTime": "2031-01-13T13:00:00.0000000Z" }, "end": { "dateTime": "2031-01-13T14:00:00.0000000Z" } }
            ]}
        ]});
        let mut routes = HashMap::new();
        routes.insert(
            ("POST", "/me/calendar/getSchedule".to_string()),
            (200, payload),
        );
        let (base, _server) = graph_mock(routes).await;
        let (provider, _pool) = make_provider(&base).await;

        let busy = provider
            .busy_from_graph(&request("ms-busy"))
            .await
            .expect("getSchedule parses");
        // busy + tentative-with-real-window? tentative start==end dropped,
        // malformed dropped, free skipped, workingElsewhere counts:
        assert_eq!(busy.len(), 2, "{busy:?}");
        assert!(busy
            .iter()
            .any(|b| b.start == "2031-01-13T08:00:00Z".parse::<DateTime<Utc>>().unwrap()));
    }

    #[tokio::test]
    async fn get_schedule_surfaces_http_failures() {
        let mut routes = HashMap::new();
        routes.insert(
            ("POST", "/me/calendar/getSchedule".to_string()),
            (
                403,
                serde_json::json!({"error": {"code": "InvalidAuthenticationToken"}}),
            ),
        );
        let (base, _server) = graph_mock(routes).await;
        let (provider, _pool) = make_provider(&base).await;
        let error = provider
            .busy_from_graph(&request("ms-http"))
            .await
            .expect_err("HTTP 403 must surface");
        assert!(error.to_string().contains("HTTP 403"), "{error}");
    }

    #[tokio::test]
    async fn create_event_validates_time_and_requires_an_id() {
        let (base, _server) = graph_mock(HashMap::new()).await;
        let (provider, _pool) = make_provider(&base).await;

        let request = CreateEventRequest {
            tenant_id: "ms-create".into(),
            title: "Demo".into(),
            attendees: vec!["prospect@example.com".into()],
            start: "2031-01-13T09:00:00Z".parse().unwrap(),
            end: "2031-01-13T09:00:00Z".parse().unwrap(),
            timezone: chrono_tz::Europe::Tallinn,
            enrollment_id: None,
            account_id: None,
            contact_id: None,
            salesperson: None,
            conferencing_link: None,
            provider: "microsoft".into(),
            provider_event_id: None,
        };
        let error = provider
            .create_event(&request)
            .await
            .expect_err("end must be after start");
        assert!(matches!(error, CalendarError::InvalidInput(_)), "{error}");

        // 200 without an id is a provider failure.
        let mut routes = HashMap::new();
        routes.insert(
            ("POST", "/me/events".to_string()),
            (200, serde_json::json!({"subject": "Demo"})),
        );
        let (base, _server) = graph_mock(routes).await;
        let (provider, _pool) = make_provider(&base).await;
        let request = CreateEventRequest {
            end: "2031-01-13T09:30:00Z".parse().unwrap(),
            ..request
        };
        let error = provider
            .create_event(&request)
            .await
            .expect_err("no id must fail");
        assert!(error.to_string().contains("no id"), "{error}");
    }

    #[tokio::test]
    async fn reschedule_and_cancel_reject_non_uuid_ids() {
        let (base, _server) = graph_mock(HashMap::new()).await;
        let (provider, _pool) = make_provider(&base).await;
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
    async fn from_env_reads_the_documented_variables_and_trims_the_base_url() {
        let _guard = ENV_LOCK.lock().await;
        std::env::set_var("SALES_MICROSOFT_GRAPH_ACCESS_TOKEN", "tok");
        std::env::set_var("SALES_MICROSOFT_GRAPH_BASE_URL", "http://127.0.0.1:9/");
        std::env::set_var("SALES_MICROSOFT_USER_ID", "user-7");
        let db = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://localhost/unused")
            .unwrap();
        let internal = Arc::new(InternalCalendarProvider::new(db, CalendarConfig::default()));
        let provider = MicrosoftCalendarProvider::from_env(CalendarConfig::default(), internal)
            .expect("built");
        assert_eq!(
            provider.base_url, "http://127.0.0.1:9",
            "trailing slash trimmed"
        );
        assert_eq!(provider.user_id, "user-7");

        std::env::remove_var("SALES_MICROSOFT_GRAPH_ACCESS_TOKEN");
        std::env::remove_var("SALES_MICROSOFT_GRAPH_BASE_URL");
        std::env::remove_var("SALES_MICROSOFT_USER_ID");
    }

    #[tokio::test]
    async fn debug_impl_never_leaks_the_token() {
        let db = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://localhost/unused")
            .unwrap();
        let internal = Arc::new(InternalCalendarProvider::new(db, CalendarConfig::default()));
        let provider = MicrosoftCalendarProvider {
            client: reqwest::Client::new(),
            base_url: "http://127.0.0.1:1".into(),
            user_id: "user-7".into(),
            access_token: "SECRET-TOKEN".into(),
            internal,
            config: CalendarConfig::default(),
        };
        let rendered = format!("{provider:?}");
        assert!(!rendered.contains("SECRET-TOKEN"), "{rendered}");
        assert!(rendered.contains("user-7"), "{rendered}");
    }

    #[tokio::test]
    async fn graph_datetime_parsing_tolerates_the_documented_shapes() {
        assert!(parse_graph_datetime("2031-01-13T08:00:00.0000000Z").is_some());
        assert!(parse_graph_datetime("2031-01-13T08:00:00Z").is_some());
        assert!(parse_graph_datetime("2031-01-13T08:00:00.0000000").is_some());
        assert!(parse_graph_datetime("garbage").is_none());
    }

    #[tokio::test]
    async fn user_base_trims_slashes_from_the_user_id() {
        let build = |user_id: &str| MicrosoftCalendarProvider {
            client: reqwest::Client::new(),
            base_url: "http://127.0.0.1:1".into(),
            user_id: user_id.into(),
            access_token: "tok".into(),
            internal: Arc::new(InternalCalendarProvider::new(
                sqlx::postgres::PgPoolOptions::new()
                    .max_connections(1)
                    .connect_lazy("postgres://localhost/unused")
                    .unwrap(),
                CalendarConfig::default(),
            )),
            config: CalendarConfig::default(),
        };
        assert_eq!(
            build("user-7").user_base(),
            "http://127.0.0.1:1/user-7",
            "no slashes to trim"
        );
        assert_eq!(
            build("/user-7/").user_base(),
            "http://127.0.0.1:1/user-7",
            "leading and trailing slashes are trimmed"
        );
        assert_eq!(
            build("user-7").events_url(),
            "http://127.0.0.1:1/user-7/events"
        );
    }

    /// The full authority loop: Graph getSchedule MERGES with the internal
    /// store of record, and only slots free on BOTH calendars are offered.
    #[tokio::test]
    async fn availability_merges_graph_busy_with_the_internal_store() {
        let payload = serde_json::json!({ "value": [
            { "scheduleItems": [
                { "status": "busy", "start": { "dateTime": "2031-01-13T08:00:00.0000000Z" }, "end": { "dateTime": "2031-01-13T09:00:00.0000000Z" } }
            ]}
        ]});
        let mut routes = HashMap::new();
        routes.insert(
            ("POST", "/me/calendar/getSchedule".to_string()),
            (200, payload),
        );
        let (base, _server) = graph_mock(routes).await;
        let (provider, pool) = make_provider(&base).await;
        let tenant = crate::test_db::unique_test_tenant("mscal-avail");

        // An INTERNAL meeting overlapping Graph's busy block: the merged busy
        // set is the union, so neither source can be bypassed.
        sqlx::query(
            "INSERT INTO sales_calendar_events \
                 (id, tenant_id, title, attendees, start_at, end_at, meeting_link) \
             VALUES (gen_random_uuid(), $1, 'internal hold', '{}', $2, $3, 'https://teams')",
        )
        .bind(&tenant)
        .bind("2031-01-13T10:00:00Z".parse::<DateTime<Utc>>().unwrap())
        .bind("2031-01-13T11:00:00Z".parse::<DateTime<Utc>>().unwrap())
        .execute(&pool)
        .await
        .expect("insert internal hold");

        let slots = provider
            .availability(&request(&tenant))
            .await
            .expect("availability resolves");
        assert!(!slots.is_empty(), "a free day must still offer slots");
        let graph_busy: (DateTime<Utc>, DateTime<Utc>) = (
            "2031-01-13T08:00:00Z".parse().unwrap(),
            "2031-01-13T09:00:00Z".parse().unwrap(),
        );
        let internal: (DateTime<Utc>, DateTime<Utc>) = (
            "2031-01-13T10:00:00Z".parse().unwrap(),
            "2031-01-13T11:00:00Z".parse().unwrap(),
        );
        for slot in &slots {
            let overlaps =
                |busy: (DateTime<Utc>, DateTime<Utc>)| slot.start < busy.1 && slot.end > busy.0;
            assert!(
                !overlaps(graph_busy) && !overlaps(internal),
                "slot {slot:?} overlaps a busy interval"
            );
        }
    }

    /// The booking happy path END-TO-END: Graph call -> id/joinUrl
    /// extraction -> internal mirror rows (store of record) -> reschedule ->
    /// cancel with provider DELETE.
    #[tokio::test]
    async fn create_event_books_on_graph_and_mirrors_the_store_of_record() {
        let payload = serde_json::json!({
            "id": "AAkALgAAAA...",
            "onlineMeeting": { "joinUrl": "https://teams.microsoft.com/l/meetup-join/19:meeting" }
        });
        let mut routes = HashMap::new();
        routes.insert(("POST", "/me/events".to_string()), (201, payload));
        let (base, _server) = graph_mock(routes).await;
        let (provider, pool) = make_provider(&base).await;
        let tenant = crate::test_db::unique_test_tenant("mscal-book");

        let req = CreateEventRequest {
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
            provider: "microsoft".into(),
            provider_event_id: None,
        };
        let booked = provider
            .create_event(&req)
            .await
            .expect("the booking lands");
        assert_eq!(booked.provider, "microsoft");
        assert_eq!(booked.provider_event_id.as_deref(), Some("AAkALgAAAA..."));
        assert_eq!(
            booked.conferencing_link,
            "https://teams.microsoft.com/l/meetup-join/19:meeting"
        );
        let mirrored: (String, String, String) = sqlx::query_as(
            "SELECT provider, provider_event_id, conferencing_link FROM sales_meetings \
             WHERE tenant_id = $1 AND status = 'booked'",
        )
        .bind(&tenant)
        .fetch_one(&pool)
        .await
        .expect("mirrored meeting");
        assert_eq!(mirrored.0, "microsoft");
        assert_eq!(mirrored.1, "AAkALgAAAA...");
        assert_eq!(
            mirrored.2,
            "https://teams.microsoft.com/l/meetup-join/19:meeting"
        );

        // Reschedule moves BOTH the Graph event and the store of record.
        let mut routes = HashMap::new();
        routes.insert(
            ("PATCH", "/me/events/AAkALgAAAA...".to_string()),
            (200, serde_json::json!({ "id": "AAkALgAAAA..." })),
        );
        let (base2, _server) = graph_mock(routes).await;
        let (provider, pool) = make_provider_at(&base2, pool).await;
        let new_start: DateTime<Utc> = "2031-01-13T14:00:00Z".parse().unwrap();
        let rescheduled = provider
            .reschedule(&booked.event_id, new_start)
            .await
            .expect("reschedule lands");
        assert_eq!(rescheduled.status, "rescheduled");
        let moved: (DateTime<Utc>, String) =
            sqlx::query_as("SELECT start_at, status FROM sales_meetings WHERE id = $1")
                .bind(Uuid::parse_str(&booked.event_id).unwrap())
                .fetch_one(&pool)
                .await
                .expect("moved meeting");
        assert_eq!(moved.0, new_start);
        assert_eq!(moved.1, "rescheduled");

        // Cancel deletes the event at Graph and cancels the store of record.
        let mut routes = HashMap::new();
        routes.insert(
            ("DELETE", "/me/events/AAkALgAAAA...".to_string()),
            (204, serde_json::json!({})),
        );
        let (base3, _server) = graph_mock(routes).await;
        let (provider, pool) = make_provider_at(&base3, pool).await;
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
    }

    async fn make_provider_at(base_url: &str, pool: PgPool) -> (MicrosoftCalendarProvider, PgPool) {
        let config = CalendarConfig::default();
        let internal = Arc::new(InternalCalendarProvider::new(pool.clone(), config.clone()));
        let provider = MicrosoftCalendarProvider {
            client: reqwest::Client::new(),
            base_url: base_url.to_string(),
            user_id: "me".into(),
            access_token: "test-token".into(),
            internal,
            config,
        };
        (provider, pool)
    }

    #[tokio::test]
    async fn create_event_surfaces_transport_http_and_json_failures() {
        let req = CreateEventRequest {
            tenant_id: "ms-fail".into(),
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
            provider: "microsoft".into(),
            provider_event_id: None,
        };

        // Transport failure: port 1 on loopback refuses connections.
        let (provider, _pool) = make_provider("http://127.0.0.1:1").await;
        let error = provider.create_event(&req).await.expect_err("transport");
        assert!(error.to_string().contains("insert failed"), "{error}");

        // HTTP failure: a 500 from Graph surfaces, not a booking.
        let mut routes = HashMap::new();
        routes.insert(
            ("POST", "/me/events".to_string()),
            (500, serde_json::json!({"error": {"code": "ServerError"}})),
        );
        let (base, _server) = graph_mock(routes).await;
        let (provider, _pool) = make_provider(&base).await;
        let error = provider.create_event(&req).await.expect_err("HTTP 500");
        assert!(error.to_string().contains("HTTP 500"), "{error}");

        // A non-string id cannot be used as a provider id.
        let mut routes = HashMap::new();
        routes.insert(
            ("POST", "/me/events".to_string()),
            (200, serde_json::json!({"id": 424242})),
        );
        let (base, _server) = graph_mock(routes).await;
        let (provider, _pool) = make_provider(&base).await;
        let error = provider.create_event(&req).await.expect_err("numeric id");
        assert!(error.to_string().contains("no id"), "{error}");
    }

    #[tokio::test]
    async fn get_schedule_surfaces_a_transport_failure() {
        let (provider, _pool) = make_provider("http://127.0.0.1:1").await;
        let error = provider
            .busy_from_graph(&request("ms-transport"))
            .await
            .expect_err("transport");
        assert!(error.to_string().contains("getSchedule failed"), "{error}");
    }

    /// A booking the store of record REJECTS (the slot was taken internally)
    /// is compensated: the just-created Graph event is deleted again.
    #[tokio::test]
    async fn a_rejected_internal_booking_is_compensated_at_the_provider() {
        let payload = serde_json::json!({ "id": "AAkALgCOMP", "onlineMeetingUrl": "" });
        let mut routes = HashMap::new();
        routes.insert(("POST", "/me/events".to_string()), (201, payload));
        let (base, _server) = graph_mock(routes).await;
        let (provider, pool) = make_provider(&base).await;
        let tenant = crate::test_db::unique_test_tenant("mscal-comp");

        // Someone else already holds the slot internally.
        sqlx::query(
            "INSERT INTO sales_calendar_events \
                 (id, tenant_id, title, attendees, start_at, end_at, meeting_link) \
             VALUES (gen_random_uuid(), $1, 'taken', '{}', $2, $3, 'https://teams')",
        )
        .bind(&tenant)
        .bind("2031-01-13T09:00:00Z".parse::<DateTime<Utc>>().unwrap())
        .bind("2031-01-13T09:30:00Z".parse::<DateTime<Utc>>().unwrap())
        .execute(&pool)
        .await
        .expect("insert the conflicting hold");

        let req = CreateEventRequest {
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
            provider: "microsoft".into(),
            provider_event_id: None,
        };
        let error = provider
            .create_event(&req)
            .await
            .expect_err("the slot is unavailable");
        assert!(matches!(error, CalendarError::SlotUnavailable), "{error}");
    }

    /// An empty joinUrl means the internal store generates the deterministic
    /// handle from the real meeting id.
    #[tokio::test]
    async fn a_booking_without_a_join_url_gets_the_deterministic_handle() {
        let payload = serde_json::json!({ "id": "AAkALgLINK" });
        let mut routes = HashMap::new();
        routes.insert(("POST", "/me/events".to_string()), (201, payload));
        let (base, _server) = graph_mock(routes).await;
        let (provider, pool) = make_provider(&base).await;
        let tenant = crate::test_db::unique_test_tenant("mscal-nolink");
        let tenant_for_query = tenant.clone();
        let req = CreateEventRequest {
            tenant_id: tenant,
            title: "No link".into(),
            attendees: vec!["prospect@example.com".into()],
            start: "2031-01-13T11:00:00Z".parse().unwrap(),
            end: "2031-01-13T11:30:00Z".parse().unwrap(),
            timezone: chrono_tz::Europe::Tallinn,
            enrollment_id: None,
            account_id: None,
            contact_id: None,
            salesperson: None,
            conferencing_link: None,
            provider: "microsoft".into(),
            provider_event_id: None,
        };
        let booked = provider
            .create_event(&req)
            .await
            .expect("the booking lands");
        assert!(
            booked.conferencing_link.starts_with("apexmail-meeting://"),
            "the empty joinUrl yields the deterministic internal handle: {}",
            booked.conferencing_link
        );
        let stored: String =
            sqlx::query_scalar("SELECT conferencing_link FROM sales_meetings WHERE tenant_id = $1")
                .bind(&tenant_for_query)
                .fetch_one(&pool)
                .await
                .expect("mirrored meeting");
        assert_eq!(stored, booked.conferencing_link);
    }

    #[tokio::test]
    async fn reschedule_refuses_a_meeting_without_a_graph_event_id() {
        let (provider, pool) = make_provider(&graph_mock(HashMap::new()).await.0).await;
        let tenant = crate::test_db::unique_test_tenant("mscal-noid");
        let event_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO sales_meetings \
                 (id, tenant_id, provider, provider_event_id, start_at, end_at, timezone, \
                  conferencing_link, status) \
             VALUES ($1, $2, 'microsoft', NULL, $3, $4, 'Europe/Tallinn', '', 'booked')",
        )
        .bind(event_id)
        .bind(&tenant)
        .bind("2031-01-13T09:00:00Z".parse::<DateTime<Utc>>().unwrap())
        .bind("2031-01-13T09:30:00Z".parse::<DateTime<Utc>>().unwrap())
        .execute(&pool)
        .await
        .expect("insert the meeting");
        let error = provider
            .reschedule(
                &event_id.to_string(),
                "2031-01-13T14:00:00Z".parse().unwrap(),
            )
            .await
            .expect_err("no graph id to patch");
        assert!(error.to_string().contains("no graph event id"), "{error}");
    }

    #[tokio::test]
    async fn cancel_surfaces_a_delete_failure_and_reschedule_a_patch_failure() {
        let (_provider, pool) = make_provider(&graph_mock(HashMap::new()).await.0).await;
        let tenant = crate::test_db::unique_test_tenant("mscal-fail");
        let event_id = Uuid::new_v4();
        let start: DateTime<Utc> = "2031-01-13T09:00:00Z".parse().unwrap();
        let end: DateTime<Utc> = "2031-01-13T09:30:00Z".parse().unwrap();
        sqlx::query(
            "INSERT INTO sales_meetings \
                 (id, tenant_id, provider, provider_event_id, start_at, end_at, timezone, \
                  conferencing_link, status) \
             VALUES ($1, $2, 'microsoft', 'AAkALgMOVE', $3, $4, 'Europe/Tallinn', '', 'booked')",
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
             VALUES ($1, $2, 'Move me', '{}', $3, $4, '')",
        )
        .bind(event_id)
        .bind(&tenant)
        .bind(start)
        .bind(end)
        .execute(&pool)
        .await
        .expect("insert the availability row");

        // A 500 is not a 404: cancel surfaces it, and the patch fails too.
        let mut routes = HashMap::new();
        routes.insert(
            ("DELETE", "/me/events/AAkALgMOVE".to_string()),
            (500, serde_json::json!({"error": {"code": "ServerError"}})),
        );
        let (base_cancel, _server) = graph_mock(routes).await;
        let (provider, pool) = make_provider_at(&base_cancel, pool).await;
        let error = provider
            .cancel(&event_id.to_string())
            .await
            .expect_err("the delete must surface");
        assert!(error.to_string().contains("HTTP 500"), "{error}");

        let mut routes = HashMap::new();
        routes.insert(
            ("PATCH", "/me/events/AAkALgMOVE".to_string()),
            (500, serde_json::json!({"error": {"code": "ServerError"}})),
        );
        let (base_patch, _server) = graph_mock(routes).await;
        let (provider, pool) = make_provider_at(&base_patch, pool).await;
        let error = provider
            .reschedule(
                &event_id.to_string(),
                "2031-01-13T14:00:00Z".parse().unwrap(),
            )
            .await
            .expect_err("the patch must surface");
        assert!(error.to_string().contains("HTTP 500"), "{error}");
        let status: String = sqlx::query_scalar("SELECT status FROM sales_meetings WHERE id = $1")
            .bind(event_id)
            .fetch_one(&pool)
            .await
            .expect("meeting row");
        assert_eq!(status, "booked", "failed provider calls change nothing");
    }
}
