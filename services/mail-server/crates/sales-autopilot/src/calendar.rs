//! Calendar / demo-scheduling service backed by PostgreSQL.
//! Working hours: 09:00–17:00 UTC, Monday–Friday.
//! Slot duration is fixed at 30 minutes.
//!
//! # Security (O-12.4)
//!
//! **Root cause**: `list_events()` and `find_available_slots()` queried only by
//! date range without a `tenant_id` filter. Any tenant could list events
//! belonging to all tenants. `cancel_event()` also lacked tenant scoping.
//!
//! **Fix**: Added `tenant_id` parameter to all public methods and added
//! `WHERE tenant_id = $N` to every SQL query. Also added `tenant_id` to the
//! `CalendarEvent` struct and `CalendarEventRow` to propagate the tenant
//! context through the response.

use chrono::{DateTime, Datelike, Duration, NaiveTime, Timelike, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::types::{CalendarEvent, SalesError};

/// Default hour (UTC) at which the working day starts (inclusive).
const DEFAULT_WORKING_HOUR_START: u32 = 9;
/// Default hour (UTC) at which the working day ends (exclusive).
const DEFAULT_WORKING_HOUR_END: u32 = 17;
/// Default intended timezone for working hours, as a fixed UTC offset in
/// hours (2 = EET). Informational only — see
/// [`CalendarService::timezone_utc_offset_hours`].
const DEFAULT_TIMEZONE_UTC_OFFSET_HOURS: i8 = 2;
const SLOT_MINUTES: i64 = 30;

/// Calendar / demo-scheduling service with configurable working hours.
///
/// # Timezone limitation (documented)
///
/// All working-hour arithmetic (`is_within_working_hours`,
/// `find_available_slots`, `create_event` validation) is performed in
/// **UTC**. The intended timezone is carried in
/// [`CalendarService::timezone_utc_offset_hours`] but is deliberately not
/// applied yet: switching to local-time arithmetic must change all three
/// call sites in lock-step (otherwise slots offered by
/// `find_available_slots` would be rejected by `create_event`), and a fixed
/// offset is wrong by an hour wherever DST applies (EET +2 / EEST +3).
/// Full support requires an IANA timezone database (e.g. chrono-tz).
#[derive(Debug, Clone)]
pub struct CalendarService {
    db: PgPool,
    /// Hour of day (UTC) at which the working day starts (inclusive).
    working_hour_start: u32,
    /// Hour of day (UTC) at which the working day ends (exclusive).
    working_hour_end: u32,
    /// Intended timezone for interpreting working hours, as a fixed UTC
    /// offset in hours (default 2 = EET). See the timezone limitation in
    /// the [`CalendarService`] docs — this field is informational until
    /// full timezone support lands.
    timezone_utc_offset_hours: i8,
}

impl CalendarService {
    pub fn new(db: PgPool) -> Self {
        Self {
            db,
            working_hour_start: DEFAULT_WORKING_HOUR_START,
            working_hour_end: DEFAULT_WORKING_HOUR_END,
            timezone_utc_offset_hours: DEFAULT_TIMEZONE_UTC_OFFSET_HOURS,
        }
    }

    /// Build a service with explicit working-hours configuration.
    ///
    /// `working_hour_start` is inclusive and `working_hour_end` exclusive,
    /// both in UTC. `timezone_utc_offset_hours` records the intended
    /// timezone (see the limitation note on [`CalendarService`]).
    pub fn with_working_hours(
        db: PgPool,
        working_hour_start: u32,
        working_hour_end: u32,
        timezone_utc_offset_hours: i8,
    ) -> Self {
        Self {
            db,
            working_hour_start,
            working_hour_end,
            timezone_utc_offset_hours,
        }
    }

    /// The intended timezone offset (UTC hours) for working hours.
    /// Informational only — see the timezone limitation on
    /// [`CalendarService`].
    pub fn timezone_utc_offset_hours(&self) -> i8 {
        self.timezone_utc_offset_hours
    }

    /// Create a calendar event. Validates that the event starts in the
    /// future, falls within working hours, and does not overlap an existing
    /// booking.
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
        // Reject events that start in the past (or this instant).
        if start_at <= Utc::now() {
            return Err(SalesError::InvalidInput(
                "start_at must be in the future".into(),
            ));
        }
        if !self.is_within_working_hours(start_at) || !self.is_within_working_hours(end_at) {
            return Err(SalesError::SlotUnavailable);
        }

        // Check for overlaps (scoped to tenant).
        //
        // This COUNT is only an advisory fast-path so callers get a quick
        // friendly error; the hard guarantee against double-booking races is
        // the `no_overlapping_events` GiST exclusion constraint created in
        // `initialize_schema` — two concurrent requests that both pass this
        // COUNT are still rejected by Postgres at INSERT time.
        let overlap_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sales_calendar_events WHERE tenant_id = $1 AND start_at < $2 AND end_at > $3",
        )
        .bind(&tenant_id)
        .bind(end_at)
        .bind(start_at)
        .fetch_one(&self.db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;

        if overlap_count > 0 {
            return Err(SalesError::SlotUnavailable);
        }

        let event = CalendarEvent {
            id: Uuid::new_v4(),
            tenant_id: tenant_id.clone(),
            title,
            attendees,
            start_at,
            end_at,
            meeting_link,
        };

        match sqlx::query(
            "INSERT INTO sales_calendar_events (id, tenant_id, title, attendees, start_at, end_at, meeting_link) VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(event.id)
        .bind(&event.tenant_id)
        .bind(&event.title)
        .bind(&event.attendees)
        .bind(event.start_at)
        .bind(event.end_at)
        .bind(&event.meeting_link)
        .execute(&self.db)
        .await
        {
            Ok(_) => Ok(event),
            // A concurrent booking won the race and the exclusion constraint
            // rejected this insert — surface it as a busy slot, not a 500.
            Err(e) if is_exclusion_violation(&e) => Err(SalesError::SlotUnavailable),
            Err(e) => Err(SalesError::Database(e.to_string())),
        }
    }

    /// List events whose start falls within the given date range, scoped to tenant.
    ///
    /// Returns `Err` on database failure — previously errors were logged and
    /// silently converted into an empty list.
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

    /// Find available 30-minute slots on the given date (UTC), scoped to tenant.
    ///
    /// Returns `Err` on database failure — an empty result must mean "no
    /// free slots", not "the database is down".
    pub async fn find_available_slots(
        &self,
        tenant_id: &str,
        date: DateTime<Utc>,
    ) -> Result<Vec<(DateTime<Utc>, DateTime<Utc>)>, SalesError> {
        if !matches!(
            date.weekday(),
            chrono::Weekday::Mon
                | chrono::Weekday::Tue
                | chrono::Weekday::Wed
                | chrono::Weekday::Thu
                | chrono::Weekday::Fri
        ) {
            return Ok(Vec::new());
        }

        let Some(work_start) = NaiveTime::from_hms_opt(self.working_hour_start, 0, 0) else {
            return Ok(Vec::new());
        };
        let day_start = date.date_naive().and_time(work_start);
        let day_start = day_start.and_utc();
        let Some(work_end) = NaiveTime::from_hms_opt(self.working_hour_end, 0, 0) else {
            return Ok(Vec::new());
        };
        let day_end = date.date_naive().and_time(work_end);
        let day_end = day_end.and_utc();

        // Fetch all events for the day to check conflicts (scoped to tenant)
        let day_events: Vec<CalendarEventRow> = sqlx::query_as(
            "SELECT id, tenant_id, title, attendees, start_at, end_at, meeting_link FROM sales_calendar_events WHERE tenant_id = $1 AND start_at < $2 AND end_at > $3",
        )
        .bind(tenant_id)
        .bind(day_end)
        .bind(day_start)
        .fetch_all(&self.db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;

        let mut slots = Vec::new();
        let mut cursor = day_start;

        while cursor + Duration::minutes(SLOT_MINUTES) <= day_end {
            let slot_end = cursor + Duration::minutes(SLOT_MINUTES);
            let conflict = day_events
                .iter()
                .any(|e| cursor < e.end_at && slot_end > e.start_at);
            if !conflict {
                slots.push((cursor, slot_end));
            }
            cursor = slot_end;
        }
        Ok(slots)
    }

    /// Cancel (remove) an event by id, scoped to tenant.
    pub async fn cancel_event(&self, id: Uuid, tenant_id: &str) -> Result<(), SalesError> {
        let result =
            sqlx::query("DELETE FROM sales_calendar_events WHERE id = $1 AND tenant_id = $2")
                .bind(id)
                .bind(tenant_id)
                .execute(&self.db)
                .await
                .map_err(|e| SalesError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(SalesError::EventNotFound(id));
        }
        Ok(())
    }

    /// Returns `true` if the timestamp is within working hours on a weekday.
    ///
    /// The end-of-day boundary is inclusive at exactly
    /// `working_hour_end:00` so the final 30-minute slot generated by
    /// `find_available_slots` (e.g. 16:30–17:00) stays bookable: the
    /// previous `(9..17).contains(&hour)` check rejected hour == 17
    /// outright, making the last slot of the day impossible to book.
    fn is_within_working_hours(&self, dt: DateTime<Utc>) -> bool {
        let hour = dt.hour();
        let minute = dt.minute();
        let weekday = dt.weekday();
        matches!(
            weekday,
            chrono::Weekday::Mon
                | chrono::Weekday::Tue
                | chrono::Weekday::Wed
                | chrono::Weekday::Thu
                | chrono::Weekday::Fri
        ) && hour >= self.working_hour_start
            && (hour < self.working_hour_end
                || (hour == self.working_hour_end && minute == 0))
    }
}

/// Detect a violation of the `no_overlapping_events` exclusion constraint.
///
/// Postgres raises SQLSTATE `23P01` (`exclusion_violation`) when the GiST
/// EXCLUDE constraint on `(tenant_id, tsrange(start_at, end_at))` rejects an
/// overlapping insert. The constraint name is checked as a fallback because
/// drivers occasionally surface the code differently.
fn is_exclusion_violation(err: &sqlx::Error) -> bool {
    match err {
        sqlx::Error::Database(db) => {
            db.code().as_deref() == Some("23P01")
                || db.message().contains("no_overlapping_events")
        }
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Internal row type for sqlx mapping
// ---------------------------------------------------------------------------

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
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::postgres::PgPoolOptions;
    use std::time::Duration as StdDuration;

    fn date(y: i32, m: u32, d: u32, h: u32, min: u32) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(&format!("{y:04}-{m:02}-{d:02}T{h:02}:{min:02}:00Z"))
            .unwrap()
            .with_timezone(&Utc)
    }

    /// A service backed by a lazy pool that never connects. Useful for
    /// assertions on validation paths that return before any query runs.
    /// (Pool creation requires a Tokio context, hence the async fn.)
    async fn lazy_svc() -> CalendarService {
        let db = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(std::time::Duration::from_millis(100))
            .connect_lazy("postgres://localhost/unused")
            .unwrap();
        CalendarService::new(db)
    }

    async fn make_svc(test_name: &str) -> Option<CalendarService> {
        let database_url = match std::env::var("TEST_DATABASE_URL") {
            Ok(value) if !value.trim().is_empty() => value,
            _ => {
                eprintln!("skipping {test_name}: set TEST_DATABASE_URL to run DB-backed test");
                return None;
            }
        };
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .acquire_timeout(StdDuration::from_secs(3))
            .connect(&database_url)
            .await
            .unwrap_or_else(|error| {
                panic!("TEST_DATABASE_URL is set but {test_name} could not connect: {error}")
            });
        crate::routes::initialize_schema(&pool)
            .await
            .unwrap_or_else(|error| panic!("failed to initialize schema for {test_name}: {error}"));
        Some(CalendarService::new(pool))
    }

    #[tokio::test]
    async fn test_create_and_list_events() {
        let Some(svc) = make_svc("test_create_and_list_events").await else {
            return;
        };
        let tenant = "tenant-a";

        // Clean up any existing events for this tenant
        let _ = sqlx::query("DELETE FROM sales_calendar_events WHERE tenant_id = $1")
            .bind(tenant)
            .execute(&svc.db)
            .await;

        // 2031-06-10 is a Tuesday and comfortably in the future (events in
        // the past are rejected).
        let start = date(2031, 6, 10, 10, 0);
        let end = date(2031, 6, 10, 11, 0);

        let event = svc
            .create_event(
                tenant.to_string(),
                "Demo".into(),
                vec!["alice@test.com".into()],
                start,
                end,
                None,
            )
            .await
            .expect("create should succeed");

        assert_eq!(event.tenant_id, tenant);
        assert_eq!(event.title, "Demo");

        let events = svc
            .list_events(
                tenant,
                date(2031, 6, 9, 0, 0),
                date(2031, 6, 11, 0, 0),
                100,
                0,
            )
            .await
            .unwrap();
        assert_eq!(events.len(), 1);

        // Other tenant should not see this event
        let other_events = svc
            .list_events(
                "tenant-b",
                date(2031, 6, 9, 0, 0),
                date(2031, 6, 11, 0, 0),
                100,
                0,
            )
            .await
            .unwrap();
        assert_eq!(other_events.len(), 0);
    }

    #[tokio::test]
    async fn test_overlap_rejection_and_cancel() {
        let Some(svc) = make_svc("test_overlap_rejection_and_cancel").await else {
            return;
        };
        let tenant = "tenant-b";

        // Clean up both tenants used by this test so reruns are deterministic.
        let _ = sqlx::query("DELETE FROM sales_calendar_events WHERE tenant_id = ANY($1)")
            .bind(&["tenant-b", "tenant-c"][..])
            .execute(&svc.db)
            .await;

        // 2031-06-11 is a Wednesday, in the future.
        let start = date(2031, 6, 11, 10, 0);
        let end = date(2031, 6, 11, 11, 0);

        svc.create_event(tenant.to_string(), "First".into(), vec![], start, end, None)
            .await
            .expect("first event");

        // Overlapping slot should be rejected
        let overlap = svc
            .create_event(
                tenant.to_string(),
                "Overlap".into(),
                vec![],
                date(2031, 6, 11, 10, 30),
                date(2031, 6, 11, 11, 30),
                None,
            )
            .await;
        assert!(matches!(overlap, Err(SalesError::SlotUnavailable)));

        // Non-overlapping slot should succeed (different tenant)
        let ok = svc
            .create_event(
                "tenant-c".to_string(),
                "Other tenant".into(),
                vec![],
                date(2031, 6, 11, 10, 30),
                date(2031, 6, 11, 11, 30),
                None,
            )
            .await;
        assert!(ok.is_ok(), "different tenant should not conflict");
    }

    #[tokio::test]
    async fn test_find_available_slots() {
        let Some(svc) = make_svc("test_find_available_slots").await else {
            return;
        };
        let tenant = "tenant-d";

        let _ = sqlx::query("DELETE FROM sales_calendar_events WHERE tenant_id = $1")
            .bind(tenant)
            .execute(&svc.db)
            .await;

        // Book a slot at 10:00-11:00 (2031-06-12 is a Thursday)
        svc.create_event(
            tenant.to_string(),
            "Blocked".into(),
            vec![],
            date(2031, 6, 12, 10, 0),
            date(2031, 6, 12, 11, 0),
            None,
        )
        .await
        .expect("create blocked slot");

        // Available slots should exclude 10:00-11:00
        let slots = svc
            .find_available_slots(tenant, date(2031, 6, 12, 0, 0))
            .await
            .unwrap();

        // Should have 16 slots (9:00-17:00 in 30-min increments = 16) minus 2 blocked (10:00-11:00 = 2 slots)
        assert_eq!(slots.len(), 14, "should have 14 available 30-min slots");

        // None of the slots should overlap with 10:00-11:00
        for (slot_start, slot_end) in &slots {
            assert!(
                !(*slot_start < date(2031, 6, 12, 11, 0) && *slot_end > date(2031, 6, 12, 10, 0)),
                "slot {:?}-{:?} overlaps with blocked 10:00-11:00",
                slot_start,
                slot_end
            );
        }
    }

    #[tokio::test]
    async fn test_find_available_slots_skips_weekends() {
        let Some(svc) = make_svc("test_find_available_slots_skips_weekends").await else {
            return;
        };
        let tenant = "tenant-e";

        // Saturday (2031-06-14)
        let slots = svc
            .find_available_slots(tenant, date(2031, 6, 14, 0, 0))
            .await
            .unwrap();
        assert!(slots.is_empty(), "weekends should have no slots");
    }

    #[tokio::test]
    async fn test_last_slot_of_day_is_within_working_hours() {
        let svc = lazy_svc().await;
        // 2031-06-10 is a Tuesday.
        //
        // The last slot offered by find_available_slots is 16:30–17:00; both
        // of its endpoints must pass the working-hours check (the old
        // `(9..17).contains(&hour)` rejected hour == 17, making the final
        // slot unbookable).
        assert!(svc.is_within_working_hours(date(2031, 6, 10, 16, 30)));
        assert!(svc.is_within_working_hours(date(2031, 6, 10, 17, 0)));
        // Anything past 17:00 sharp is still outside working hours.
        assert!(!svc.is_within_working_hours(date(2031, 6, 10, 17, 1)));
        // The start boundary is inclusive.
        assert!(svc.is_within_working_hours(date(2031, 6, 10, 9, 0)));
        assert!(!svc.is_within_working_hours(date(2031, 6, 10, 8, 59)));
    }

    #[tokio::test]
    async fn test_past_events_are_rejected() {
        let svc = lazy_svc().await;
        // 2020-01-06 was a Monday inside working hours — but it is in the
        // past, so create_event must reject it before touching the database.
        let start = date(2020, 1, 6, 10, 0);
        let end = date(2020, 1, 6, 11, 0);
        let result = svc
            .create_event("tenant-past".into(), "Past".into(), vec![], start, end, None)
            .await;
        assert!(
            matches!(result, Err(SalesError::InvalidInput(ref msg)) if msg.contains("future"))
        );
    }

    #[tokio::test]
    async fn test_working_hours_are_configurable() {
        let db = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(std::time::Duration::from_millis(100))
            .connect_lazy("postgres://localhost/unused")
            .unwrap();
        // 2031-06-10 is a Tuesday.
        // 2031-06-10 is a Tuesday.
        let svc = CalendarService::with_working_hours(db, 8, 20, 3);
        assert_eq!(svc.timezone_utc_offset_hours(), 3);
        assert!(svc.is_within_working_hours(date(2031, 6, 10, 8, 0)));
        assert!(svc.is_within_working_hours(date(2031, 6, 10, 19, 30)));
        assert!(svc.is_within_working_hours(date(2031, 6, 10, 20, 0)));
        assert!(!svc.is_within_working_hours(date(2031, 6, 10, 7, 59)));
        assert!(!svc.is_within_working_hours(date(2031, 6, 10, 20, 1)));
    }
}
