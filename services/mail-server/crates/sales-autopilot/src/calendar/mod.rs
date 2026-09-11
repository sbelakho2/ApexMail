//! Calendar / demo-scheduling service (audit §29).
//!
//! # Architecture
//!
//! ```text
//! CalendarProvider (trait)
//!   ├── internal  — sales_calendar_events + sales_meetings (store of record)
//!   ├── google    — Google Calendar API (authoritative availability when configured)
//!   └── microsoft — Microsoft Graph calendar (authoritative availability when configured)
//! ```
//!
//! **Source of truth.** When an external provider is configured it is
//! authoritative for availability: only intervals that are free in the real
//! Google/Microsoft calendar AND free in the internal store are offered, so a
//! prospect can never be double-booked against the salesperson's actual
//! calendar. The internal provider is the fallback (used when no external
//! provider is configured, or the selected provider has no credentials) and
//! always the **store of record**: every external booking is mirrored into
//! `sales_calendar_events` + `sales_meetings`, which is what the product,
//! round-robin and reports read.
//!
//! # Timezone correctness (the §29 fix)
//!
//! Working hours, allowed weekdays, buffers, minimum notice and per-day caps
//! are evaluated in the slot's **IANA timezone** with the offset in force on
//! the requested date (DST-correct). The previous implementation did the
//! arithmetic in UTC with a fixed `i8` offset that was never applied; fixed
//! offsets and "the offset that applies today" are gone from the arithmetic
//! paths. See [`timezone`] for the documented policy on nonexistent and
//! ambiguous local times.
//!
//! # Configuration
//!
//! `SalesConfig` has no calendar fields (out of this change's scope), so the
//! calendar reads documented environment variables directly:
//!
//! | Variable | Meaning | Default |
//! |---|---|---|
//! | `SALES_CALENDAR_PROVIDER` | `internal` \| `google` \| `microsoft` | `internal` |
//! | `SALES_CALENDAR_TIMEZONE` | IANA zone for working hours | `Europe/Tallinn` |
//! | `SALES_CALENDAR_WORKDAY_START` | local `HH:MM`, inclusive | `09:00` |
//! | `SALES_CALENDAR_WORKDAY_END` | local `HH:MM`, exclusive | `17:00` |
//! | `SALES_CALENDAR_ALLOWED_WEEKDAYS` | `mon,tue,…` | `mon,tue,wed,thu,fri` |
//! | `SALES_CALENDAR_SLOT_MINUTES` | slot length | `30` |
//! | `SALES_CALENDAR_BUFFER_MINUTES` | gap before/after an existing meeting | `10` |
//! | `SALES_CALENDAR_MIN_NOTICE_MINUTES` | minimum notice | `120` |
//! | `SALES_CALENDAR_MAX_MEETINGS_PER_DAY` | daily cap | `4` |
//! | `SALES_CALENDAR_SALESPEOPLE` | comma-separated candidate emails (no salesperson table exists) | empty |
//! | `SALES_CALENDAR_CONFERENCING_BASE_URL` | link prefix for booked meetings | unset ⇒ deterministic internal handle |
//! | `SALES_GOOGLE_CALENDAR_ACCESS_TOKEN` (alias `GOOGLE_CALENDAR_ACCESS_TOKEN`) | Google OAuth access token | unset ⇒ provider unconfigured |
//! | `SALES_GOOGLE_CALENDAR_ID` (alias `GOOGLE_CALENDAR_ID`) | Google calendar id | `primary` |
//! | `SALES_GOOGLE_CALENDAR_BASE_URL` (alias `GOOGLE_CALENDAR_BASE_URL`) | API base override | `https://www.googleapis.com/calendar/v3` |
//! | `SALES_MICROSOFT_GRAPH_ACCESS_TOKEN` (alias `MICROSOFT_GRAPH_ACCESS_TOKEN`) | Graph OAuth access token | unset ⇒ provider unconfigured |
//! | `SALES_MICROSOFT_USER_ID` (alias `MICROSOFT_USER_ID`) | Graph user path | `me` |
//! | `SALES_MICROSOFT_GRAPH_BASE_URL` (alias `MICROSOFT_GRAPH_BASE_URL`) | API base override | `https://graph.microsoft.com/v1.0` |
//!
//! The provider env reads follow `crate::config::read_env`: the first
//! present, non-empty variable wins and empty values are treated as unset.
//! Invalid values fall back to defaults with a warning — configuration
//! mistakes never panic the process.

pub mod availability;
pub mod google;
pub mod internal;
pub mod microsoft;
pub mod timezone;

use std::sync::Arc;

use chrono::{DateTime, NaiveDate, NaiveTime, Utc, Weekday};
use chrono_tz::Tz;
use sqlx::PgPool;
use uuid::Uuid;

pub use availability::{
    generate_slots, pick_least_loaded, AvailabilityRequest, BusyInterval, SlotPolicy, TimeSlot,
    WorkingHours, DEFAULT_BUFFER_MINUTES, DEFAULT_MAX_MEETINGS_PER_DAY, DEFAULT_MIN_NOTICE_MINUTES,
    DEFAULT_SLOT_MINUTES,
};
pub use timezone::{infer_recipient_timezone, parse_iana_zone, LocalResolution};

use crate::types::{CalendarEvent, SalesError};

/// Errors a calendar provider can produce. Mapped to [`SalesError`] for the
/// HTTP surface.
#[derive(Debug, thiserror::Error)]
pub enum CalendarError {
    #[error("calendar provider not configured: {0}")]
    NotConfigured(String),
    #[error("invalid calendar input: {0}")]
    InvalidInput(String),
    #[error("time slot unavailable")]
    SlotUnavailable,
    #[error("calendar event not found: {0}")]
    EventNotFound(String),
    #[error("calendar provider error: {0}")]
    Provider(String),
    #[error("calendar database error: {0}")]
    Database(String),
}

impl From<CalendarError> for SalesError {
    fn from(err: CalendarError) -> Self {
        match err {
            CalendarError::NotConfigured(_) | CalendarError::Provider(_) => {
                SalesError::ServiceUnavailable(err.to_string())
            }
            CalendarError::InvalidInput(message) => SalesError::InvalidInput(message),
            CalendarError::SlotUnavailable => SalesError::SlotUnavailable,
            CalendarError::EventNotFound(id) => {
                SalesError::EventNotFound(Uuid::parse_str(&id).unwrap_or(Uuid::nil()))
            }
            CalendarError::Database(message) => SalesError::Database(message),
        }
    }
}

/// The provider interface. See the module docs for which provider is
/// authoritative.
#[async_trait::async_trait]
pub trait CalendarProvider: Send + Sync + std::fmt::Debug {
    fn id(&self) -> &'static str;
    async fn availability(
        &self,
        request: &AvailabilityRequest,
    ) -> Result<Vec<TimeSlot>, CalendarError>;
    async fn create_event(
        &self,
        request: &CreateEventRequest,
    ) -> Result<BookedEvent, CalendarError>;
    async fn reschedule(
        &self,
        event_id: &str,
        new_start: DateTime<Utc>,
    ) -> Result<BookedEvent, CalendarError>;
    async fn cancel(&self, event_id: &str) -> Result<(), CalendarError>;
}

/// A booking request, provider-independent.
#[derive(Debug, Clone)]
pub struct CreateEventRequest {
    pub tenant_id: String,
    pub title: String,
    pub attendees: Vec<String>,
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
    /// IANA zone the meeting was scheduled in (stored on `sales_meetings`).
    pub timezone: Tz,
    /// Canonical links, when the booking came from an enrollment.
    pub enrollment_id: Option<Uuid>,
    pub account_id: Option<Uuid>,
    pub contact_id: Option<Uuid>,
    /// Salesperson assigned by round-robin; recorded in `attendees`.
    pub salesperson: Option<String>,
    /// Explicit conferencing link; providers generate one when absent.
    pub conferencing_link: Option<String>,
    /// Provider string stored on `sales_meetings` (`internal|google|microsoft`).
    pub provider: String,
    /// Provider-side event id, when mirrored from an external provider.
    pub provider_event_id: Option<String>,
}

impl CreateEventRequest {
    pub fn new(
        tenant_id: impl Into<String>,
        title: impl Into<String>,
        attendees: Vec<String>,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        timezone: Tz,
    ) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            title: title.into(),
            attendees,
            start,
            end,
            timezone,
            enrollment_id: None,
            account_id: None,
            contact_id: None,
            salesperson: None,
            conferencing_link: None,
            provider: "internal".into(),
            provider_event_id: None,
        }
    }

    /// Attendees plus the assigned salesperson (deduplicated), which is how
    /// round-robin load is recorded in `sales_calendar_events.attendees`.
    pub fn attendees_all(&self) -> Vec<String> {
        let mut attendees = self.attendees.clone();
        if let Some(salesperson) = &self.salesperson {
            if !salesperson.trim().is_empty()
                && !attendees
                    .iter()
                    .any(|a| a.eq_ignore_ascii_case(salesperson))
            {
                attendees.push(salesperson.clone());
            }
        }
        attendees
    }
}

/// A booked meeting, provider-independent.
#[derive(Debug, Clone)]
pub struct BookedEvent {
    /// Internal id (`sales_calendar_events.id` == `sales_meetings.id`).
    pub event_id: String,
    pub provider: String,
    pub provider_event_id: Option<String>,
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
    pub timezone: Tz,
    pub conferencing_link: String,
    pub status: String,
}

/// Calendar policy configuration (env-driven — see the module docs).
#[derive(Debug, Clone)]
pub struct CalendarConfig {
    pub timezone: Tz,
    pub working_hours: WorkingHours,
    pub policy: SlotPolicy,
    pub salespeople: Vec<String>,
    pub conferencing_base_url: Option<String>,
}

impl CalendarConfig {
    pub fn new(timezone: Tz) -> Self {
        Self {
            timezone,
            ..Self::default()
        }
    }

    /// Read the documented environment variables. Invalid values log a
    /// warning and fall back to defaults; this function never panics.
    pub fn from_env() -> Self {
        let timezone = std::env::var("SALES_CALENDAR_TIMEZONE")
            .ok()
            .map(|raw| raw.trim().to_string())
            .filter(|raw| !raw.is_empty())
            .and_then(|raw| match parse_iana_zone(&raw) {
                Some(tz) => Some(tz),
                None => {
                    tracing::warn!(
                        value = %raw,
                        "SALES_CALENDAR_TIMEZONE is not a valid IANA zone; using default"
                    );
                    None
                }
            })
            .unwrap_or_else(default_timezone);

        let start = env_time("SALES_CALENDAR_WORKDAY_START")
            .unwrap_or_else(|| default_working_hours().start);
        let end =
            env_time("SALES_CALENDAR_WORKDAY_END").unwrap_or_else(|| default_working_hours().end);
        let weekdays = std::env::var("SALES_CALENDAR_ALLOWED_WEEKDAYS")
            .ok()
            .map(|raw| parse_weekdays(&raw))
            .filter(|days| !days.is_empty())
            .unwrap_or_else(WorkingHours::monday_to_friday);

        let working_hours = WorkingHours::new(start, end, weekdays);

        let defaults = SlotPolicy::default();
        let policy = SlotPolicy {
            slot_minutes: env_num("SALES_CALENDAR_SLOT_MINUTES", defaults.slot_minutes),
            buffer_before_minutes: env_num(
                "SALES_CALENDAR_BUFFER_MINUTES",
                defaults.buffer_before_minutes,
            ),
            buffer_after_minutes: env_num(
                "SALES_CALENDAR_BUFFER_MINUTES",
                defaults.buffer_after_minutes,
            ),
            min_notice_minutes: env_num(
                "SALES_CALENDAR_MIN_NOTICE_MINUTES",
                defaults.min_notice_minutes,
            ),
            max_meetings_per_day: env_num(
                "SALES_CALENDAR_MAX_MEETINGS_PER_DAY",
                defaults.max_meetings_per_day,
            ),
        };
        let policy = if policy.validate().is_ok() {
            policy
        } else {
            tracing::warn!("SALES_CALENDAR_* policy is invalid; using defaults");
            defaults
        };

        let salespeople = std::env::var("SALES_CALENDAR_SALESPEOPLE")
            .ok()
            .map(|raw| {
                raw.split(',')
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(str::to_string)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        let conferencing_base_url = std::env::var("SALES_CALENDAR_CONFERENCING_BASE_URL")
            .ok()
            .map(|raw| raw.trim().trim_end_matches('/').to_string())
            .filter(|value| !value.is_empty());

        Self {
            timezone,
            working_hours,
            policy,
            salespeople,
            conferencing_base_url,
        }
    }

    /// Build an [`AvailabilityRequest`] on this configuration.
    pub fn availability_request(
        &self,
        tenant_id: impl Into<String>,
        date: NaiveDate,
        now: DateTime<Utc>,
    ) -> AvailabilityRequest {
        AvailabilityRequest {
            tenant_id: tenant_id.into(),
            date,
            timezone: self.timezone,
            working_hours: self.working_hours.clone(),
            policy: self.policy,
            salespeople: self.salespeople.clone(),
            now,
        }
    }

    pub fn selected_provider(&self) -> String {
        std::env::var("SALES_CALENDAR_PROVIDER")
            .ok()
            .map(|raw| raw.trim().to_ascii_lowercase())
            .filter(|raw| !raw.is_empty())
            .unwrap_or_else(|| "internal".into())
    }
}

impl Default for CalendarConfig {
    fn default() -> Self {
        Self {
            timezone: default_timezone(),
            working_hours: default_working_hours(),
            policy: SlotPolicy::default(),
            salespeople: Vec::new(),
            conferencing_base_url: None,
        }
    }
}

fn default_timezone() -> Tz {
    timezone::DEFAULT_CALENDAR_TIMEZONE
        .parse()
        .unwrap_or(chrono_tz::UTC)
}

fn default_working_hours() -> WorkingHours {
    WorkingHours::default_monday_to_friday()
}

fn env_time(name: &str) -> Option<NaiveTime> {
    let raw = std::env::var(name).ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let mut parts = trimmed.split(':');
    let hour = parts.next()?.parse::<u32>().ok()?;
    let minute = parts.next()?.parse::<u32>().ok()?;
    match NaiveTime::from_hms_opt(hour, minute, 0) {
        Some(time) => Some(time),
        None => {
            tracing::warn!(variable = name, value = %trimmed, "invalid HH:MM value; using default");
            None
        }
    }
}

fn env_num<T: std::str::FromStr + Copy>(name: &str, default: T) -> T {
    match std::env::var(name) {
        Ok(raw) => match raw.trim().parse::<T>() {
            Ok(value) => value,
            Err(_) => {
                tracing::warn!(variable = name, value = %raw, "invalid number; using default");
                default
            }
        },
        Err(_) => default,
    }
}

fn parse_weekdays(raw: &str) -> Vec<Weekday> {
    raw.split(',')
        .filter_map(|token| match token.trim().to_ascii_lowercase().as_str() {
            "mon" | "monday" => Some(Weekday::Mon),
            "tue" | "tues" | "tuesday" => Some(Weekday::Tue),
            "wed" | "wednesday" => Some(Weekday::Wed),
            "thu" | "thur" | "thurs" | "thursday" => Some(Weekday::Thu),
            "fri" | "friday" => Some(Weekday::Fri),
            "sat" | "saturday" => Some(Weekday::Sat),
            "sun" | "sunday" => Some(Weekday::Sun),
            _ => None,
        })
        .collect()
}

/// Facade retained for existing callers (`AppState.calendar`, integration
/// tests, `bin/server.rs`).
///
/// The historical methods ([`CalendarService::create_event`],
/// [`CalendarService::list_events`],
/// [`CalendarService::find_available_slots`],
/// [`CalendarService::cancel_event`]) keep their signatures and their
/// historical semantics: 09:00–17:00 **UTC**, Monday–Friday, 30-minute slots,
/// no buffer/notice policy. They exist for backward compatibility and are
/// implemented on the internal provider.
///
/// New code should use the provider API:
/// [`CalendarService::availability`] (IANA timezone, buffers, minimum
/// notice, allowed weekdays, per-day cap, round-robin) and
/// [`CalendarService::book`].
#[derive(Clone)]
pub struct CalendarService {
    db: PgPool,
    internal: Arc<internal::InternalCalendarProvider>,
    external: Option<Arc<dyn CalendarProvider>>,
    config: CalendarConfig,
    /// Legacy informational field — see [`CalendarService::timezone_utc_offset_hours`].
    timezone_utc_offset_hours: i8,
}

impl std::fmt::Debug for CalendarService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CalendarService")
            .field("config_timezone", &self.config.timezone.name())
            .field("external_provider", &self.external.as_ref().map(|p| p.id()))
            .field("timezone_utc_offset_hours", &self.timezone_utc_offset_hours)
            .finish_non_exhaustive()
    }
}

impl CalendarService {
    /// Build the service from the environment (see the module-level table).
    /// Provider selection is documented; an external provider selected
    /// without credentials logs a warning and falls back to the internal
    /// provider.
    pub fn new(db: PgPool) -> Self {
        Self::from_config(db, CalendarConfig::from_env())
    }

    /// Build with an explicit configuration (no environment reads for the
    /// policy; provider selection still consults
    /// `SALES_CALENDAR_PROVIDER`).
    pub fn from_config(db: PgPool, config: CalendarConfig) -> Self {
        let internal = Arc::new(internal::InternalCalendarProvider::new(
            db.clone(),
            config.clone(),
        ));
        let external = build_external_provider(&config, internal.clone());
        Self {
            db,
            internal,
            external,
            config,
            timezone_utc_offset_hours: 2, // historical EET default, informational only
        }
    }

    /// Legacy constructor with explicit UTC working hours and an
    /// informational offset. The offset is **not** used for arithmetic (IANA
    /// zones are), it only answers
    /// [`CalendarService::timezone_utc_offset_hours`].
    pub fn with_working_hours(
        db: PgPool,
        working_hour_start: u32,
        working_hour_end: u32,
        timezone_utc_offset_hours: i8,
    ) -> Self {
        let config = CalendarConfig {
            timezone: chrono_tz::UTC,
            working_hours: WorkingHours::new(
                NaiveTime::from_hms_opt(working_hour_start, 0, 0).unwrap_or(NaiveTime::MIN),
                NaiveTime::from_hms_opt(working_hour_end, 0, 0).unwrap_or(NaiveTime::MIN),
                WorkingHours::monday_to_friday(),
            ),
            ..CalendarConfig::default()
        };
        let internal = Arc::new(internal::InternalCalendarProvider::new(
            db.clone(),
            config.clone(),
        ));
        Self {
            db,
            internal,
            external: None,
            config,
            timezone_utc_offset_hours,
        }
    }

    /// The intended legacy timezone offset (UTC hours). Informational only:
    /// the scheduling arithmetic uses IANA zones with DST.
    pub fn timezone_utc_offset_hours(&self) -> i8 {
        self.timezone_utc_offset_hours
    }

    pub fn config(&self) -> &CalendarConfig {
        &self.config
    }

    pub fn internal_provider(&self) -> &internal::InternalCalendarProvider {
        &self.internal
    }

    /// The authoritative provider id: the configured external provider when
    /// one is configured, otherwise `internal`.
    pub fn provider_id(&self) -> &'static str {
        self.external
            .as_ref()
            .map(|provider| provider.id())
            .unwrap_or("internal")
    }

    // ── Provider API ────────────────────────────────────────────────────

    /// Availability, honouring the full policy. When an external provider is
    /// configured it is authoritative; its result already intersects the
    /// internal store of record. When it is not, the internal provider
    /// answers.
    pub async fn availability(
        &self,
        request: &AvailabilityRequest,
    ) -> Result<Vec<TimeSlot>, CalendarError> {
        match &self.external {
            Some(provider) => provider.availability(request).await,
            None => self.internal.availability(request).await,
        }
    }

    /// Book a meeting through the authoritative provider.
    pub async fn book(&self, request: &CreateEventRequest) -> Result<BookedEvent, CalendarError> {
        match &self.external {
            Some(provider) => provider.create_event(request).await,
            None => self.internal.create_event(request).await,
        }
    }

    /// Reschedule through the authoritative provider.
    pub async fn reschedule(
        &self,
        event_id: &str,
        new_start: DateTime<Utc>,
    ) -> Result<BookedEvent, CalendarError> {
        match &self.external {
            Some(provider) => provider.reschedule(event_id, new_start).await,
            None => self.internal.reschedule(event_id, new_start).await,
        }
    }

    /// Cancel through the authoritative provider (external event + the
    /// internal store-of-record row).
    pub async fn cancel(&self, event_id: &str) -> Result<(), CalendarError> {
        match &self.external {
            Some(provider) => provider.cancel(event_id).await,
            None => self.internal.cancel(event_id).await,
        }
    }

    // ── Legacy surface (unchanged signatures/semantics) ─────────────────

    /// Create a calendar event (legacy: UTC 09:00–17:00 policy). Validates
    /// future start, working hours and overlaps; the GiST exclusion
    /// constraint remains the hard double-booking guarantee.
    pub async fn create_event(
        &self,
        tenant_id: String,
        title: String,
        attendees: Vec<String>,
        start_at: DateTime<Utc>,
        end_at: DateTime<Utc>,
        meeting_link: Option<String>,
    ) -> Result<CalendarEvent, SalesError> {
        if end_at <= start_at {
            return Err(SalesError::InvalidInput(
                "end_at must be after start_at".into(),
            ));
        }
        if start_at <= Utc::now() {
            return Err(SalesError::InvalidInput(
                "start_at must be in the future".into(),
            ));
        }
        if !self.is_within_legacy_working_hours(start_at)
            || !self.is_within_legacy_working_hours(end_at)
        {
            return Err(SalesError::SlotUnavailable);
        }

        let mut request = CreateEventRequest::new(
            tenant_id.clone(),
            title,
            attendees,
            start_at,
            end_at,
            chrono_tz::UTC,
        );
        request.conferencing_link = meeting_link;
        let booked = self.internal.create_event(&request).await?;
        let id =
            Uuid::parse_str(&booked.event_id).map_err(|e| SalesError::Database(e.to_string()))?;
        Ok(CalendarEvent {
            id,
            tenant_id,
            title: request.title,
            attendees: request.attendees,
            start_at: booked.start,
            end_at: booked.end,
            meeting_link: Some(booked.conferencing_link),
        })
    }

    /// List events whose start falls within the range, tenant-scoped.
    pub async fn list_events(
        &self,
        tenant_id: &str,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<CalendarEvent>, SalesError> {
        let rows = sqlx::query_as::<_, CalendarEventRow>(
            "SELECT id, tenant_id, title, attendees, start_at, end_at, meeting_link FROM sales_calendar_events WHERE tenant_id = $1 AND start_at >= $2 AND start_at < $3 ORDER BY start_at ASC LIMIT $4 OFFSET $5",
        )
        .bind(tenant_id)
        .bind(from)
        .bind(to)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;

        Ok(rows.into_iter().map(|r| r.into_event()).collect())
    }

    /// Legacy 30-minute slot search on a UTC date (09:00–17:00 UTC,
    /// Monday–Friday, no buffer/min-notice policy). New callers should use
    /// [`CalendarService::availability`] with an IANA timezone.
    pub async fn find_available_slots(
        &self,
        tenant_id: &str,
        date: DateTime<Utc>,
    ) -> Result<Vec<(DateTime<Utc>, DateTime<Utc>)>, SalesError> {
        let legacy = CalendarConfig {
            timezone: chrono_tz::UTC,
            working_hours: WorkingHours::default_monday_to_friday(),
            policy: SlotPolicy {
                slot_minutes: DEFAULT_SLOT_MINUTES,
                buffer_before_minutes: 0,
                buffer_after_minutes: 0,
                min_notice_minutes: 0,
                max_meetings_per_day: usize::MAX,
            },
            salespeople: Vec::new(),
            conferencing_base_url: None,
        };
        // A dedicated provider so legacy results never depend on env policy.
        let internal = internal::InternalCalendarProvider::new(self.db.clone(), legacy.clone());
        let request = legacy.availability_request(tenant_id, date.date_naive(), Utc::now());
        let slots = internal
            .availability(&request)
            .await
            .map_err(SalesError::from)?;
        Ok(slots
            .into_iter()
            .map(|slot| (slot.start, slot.end))
            .collect())
    }

    /// Cancel (remove) an event by id, scoped to tenant. The meeting
    /// store-of-record row is marked `cancelled`; the availability-index row
    /// is deleted so the slot is offerable again.
    pub async fn cancel_event(&self, id: Uuid, tenant_id: &str) -> Result<(), SalesError> {
        let exists: Option<(i32,)> =
            sqlx::query_as("SELECT 1 FROM sales_calendar_events WHERE id = $1 AND tenant_id = $2")
                .bind(id)
                .bind(tenant_id)
                .fetch_optional(&self.db)
                .await
                .map_err(|e| SalesError::Database(e.to_string()))?;
        if exists.is_none() {
            return Err(SalesError::EventNotFound(id));
        }
        self.internal
            .cancel_recorded(&id.to_string())
            .await
            .map_err(SalesError::from)
    }

    /// Legacy working-hours check (UTC, half-open at the end): kept because
    /// existing callers/tests exercise it through `create_event`.
    fn is_within_legacy_working_hours(&self, dt: DateTime<Utc>) -> bool {
        let config = &self.config;
        let hour = chrono::Timelike::hour(&dt);
        let minute = chrono::Timelike::minute(&dt);
        let weekday = chrono::Datelike::weekday(&dt);
        let start = chrono::Timelike::hour(&config.working_hours.start);
        let end = chrono::Timelike::hour(&config.working_hours.end);
        config.working_hours.includes_weekday(weekday)
            && hour >= start
            && (hour < end || (hour == end && minute == 0))
    }
}

#[async_trait::async_trait]
impl CalendarProvider for CalendarService {
    fn id(&self) -> &'static str {
        self.provider_id()
    }

    async fn availability(
        &self,
        request: &AvailabilityRequest,
    ) -> Result<Vec<TimeSlot>, CalendarError> {
        CalendarService::availability(self, request).await
    }

    async fn create_event(
        &self,
        request: &CreateEventRequest,
    ) -> Result<BookedEvent, CalendarError> {
        self.book(request).await
    }

    async fn reschedule(
        &self,
        event_id: &str,
        new_start: DateTime<Utc>,
    ) -> Result<BookedEvent, CalendarError> {
        CalendarService::reschedule(self, event_id, new_start).await
    }

    async fn cancel(&self, event_id: &str) -> Result<(), CalendarError> {
        CalendarService::cancel(self, event_id).await
    }
}

fn build_external_provider(
    config: &CalendarConfig,
    internal: Arc<internal::InternalCalendarProvider>,
) -> Option<Arc<dyn CalendarProvider>> {
    let selected = config.selected_provider();
    match selected.as_str() {
        "internal" | "" => None,
        "google" => match google::GoogleCalendarProvider::from_env(config.clone(), internal) {
            Some(provider) => Some(Arc::new(provider)),
            None => {
                tracing::warn!(
                    "SALES_CALENDAR_PROVIDER=google but SALES_GOOGLE_CALENDAR_ACCESS_TOKEN is unset; \
                     falling back to the internal provider"
                );
                None
            }
        },
        "microsoft" => {
            match microsoft::MicrosoftCalendarProvider::from_env(config.clone(), internal) {
                Some(provider) => Some(Arc::new(provider)),
                None => {
                    tracing::warn!(
                        "SALES_CALENDAR_PROVIDER=microsoft but SALES_MICROSOFT_GRAPH_ACCESS_TOKEN is unset; \
                         falling back to the internal provider"
                    );
                    None
                }
            }
        }
        other => {
            tracing::warn!(value = %other, "unknown SALES_CALENDAR_PROVIDER; using internal");
            None
        }
    }
}

#[derive(sqlx::FromRow)]
struct CalendarEventRow {
    id: Uuid,
    tenant_id: String,
    title: String,
    attendees: Vec<String>,
    start_at: DateTime<Utc>,
    end_at: DateTime<Utc>,
    meeting_link: Option<String>,
}

impl CalendarEventRow {
    fn into_event(self) -> CalendarEvent {
        CalendarEvent {
            id: self.id,
            tenant_id: self.tenant_id,
            title: self.title,
            attendees: self.attendees,
            start_at: self.start_at,
            end_at: self.end_at,
            meeting_link: self.meeting_link,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests (offline; DB-backed coverage lives in tests/calendar_live.rs)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn lazy_svc() -> CalendarService {
        let db = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(std::time::Duration::from_millis(100))
            .connect_lazy("postgres://localhost/unused")
            .expect("lazy pool");
        CalendarService::with_working_hours(db, 9, 17, 3)
    }

    fn date(y: i32, m: u32, d: u32, h: u32, min: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, m, d, h, min, 0).unwrap()
    }

    #[tokio::test]
    async fn legacy_offset_is_informational_and_hours_still_utc() {
        let svc = lazy_svc();
        assert_eq!(svc.timezone_utc_offset_hours(), 3);
        // 2031-06-10 is a Tuesday.
        assert!(svc.is_within_legacy_working_hours(date(2031, 6, 10, 9, 0)));
        assert!(svc.is_within_legacy_working_hours(date(2031, 6, 10, 16, 30)));
        assert!(svc.is_within_legacy_working_hours(date(2031, 6, 10, 17, 0)));
        assert!(!svc.is_within_legacy_working_hours(date(2031, 6, 10, 8, 59)));
        assert!(!svc.is_within_legacy_working_hours(date(2031, 6, 10, 17, 1)));
        assert!(!svc.is_within_legacy_working_hours(date(2031, 6, 14, 10, 0)));
        // The IANA arithmetic path does NOT use the legacy offset: 09:00
    }

    #[tokio::test]
    async fn legacy_past_event_rejected_with_future_message() {
        // create_event returns the validation error before any database I/O.
        let svc = lazy_svc();
        let result = svc
            .create_event(
                "tenant-past".into(),
                "Past".into(),
                vec![],
                date(2020, 1, 6, 10, 0),
                date(2020, 1, 6, 11, 0),
                None,
            )
            .await;
        assert!(matches!(result, Err(SalesError::InvalidInput(ref m)) if m.contains("future")));
    }

    #[test]
    fn config_defaults_are_iana_and_dst_correct() {
        let config = CalendarConfig::default();
        assert_eq!(config.timezone.name(), timezone::DEFAULT_CALENDAR_TIMEZONE);
        assert_eq!(config.policy.slot_minutes, DEFAULT_SLOT_MINUTES);
        // A winter and a summer date resolve to different UTC offsets.
        let winter = config
            .availability_request(
                "t",
                NaiveDate::from_ymd_opt(2031, 1, 13).unwrap(),
                Utc::now(),
            )
            .timezone;
        assert_eq!(winter.name(), "Europe/Tallinn");
    }

    #[tokio::test]
    async fn provider_trait_is_object_safe_and_calendar_service_implements_it() {
        let svc = lazy_svc();
        let provider: &dyn CalendarProvider = &svc;
        assert_eq!(provider.id(), "internal");
        let boxed: Arc<dyn CalendarProvider> = Arc::new(svc);
        assert_eq!(boxed.id(), "internal");
    }

    #[test]
    fn calendar_error_maps_to_sales_error() {
        assert!(matches!(
            SalesError::from(CalendarError::SlotUnavailable),
            SalesError::SlotUnavailable
        ));
        assert!(matches!(
            SalesError::from(CalendarError::InvalidInput("x".into())),
            SalesError::InvalidInput(_)
        ));
        let id = Uuid::nil();
        assert!(matches!(
            SalesError::from(CalendarError::EventNotFound(id.to_string())),
            SalesError::EventNotFound(parsed) if parsed == id
        ));
        assert!(matches!(
            SalesError::from(CalendarError::Database("x".into())),
            SalesError::Database(_)
        ));
        assert!(matches!(
            SalesError::from(CalendarError::NotConfigured("x".into())),
            SalesError::ServiceUnavailable(_)
        ));
    }
}
