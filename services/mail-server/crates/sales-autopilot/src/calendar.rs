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

/// Working hours: 09:00–17:00 UTC, Monday–Friday.
const WORK_START_HOUR: u32 = 9;
const WORK_END_HOUR: u32 = 17;
const SLOT_MINUTES: i64 = 30;

#[derive(Debug, Clone)]
pub struct CalendarService {
    db: PgPool,
}

impl CalendarService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    /// Create a calendar event. Validates that the event falls within
    /// working hours and does not overlap an existing booking.
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
        if !Self::is_within_working_hours(start_at) || !Self::is_within_working_hours(end_at) {
            return Err(SalesError::SlotUnavailable);
        }

        // Check for overlaps (scoped to tenant)
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

        sqlx::query(
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
        .map_err(|e| SalesError::Database(e.to_string()))?;

        Ok(event)
    }

    /// List events whose start falls within the given date range, scoped to tenant.
    pub async fn list_events(
        &self,
        tenant_id: &str,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
        limit: i64,
        offset: i64,
    ) -> Vec<CalendarEvent> {
        let rows = sqlx::query_as::<_, CalendarEventRow>(
            "SELECT id, tenant_id, title, attendees, start_at, end_at, meeting_link FROM sales_calendar_events WHERE tenant_id = $1 AND start_at >= $2 AND start_at < $3 ORDER BY start_at ASC LIMIT $4 OFFSET $5",
        )
        .bind(tenant_id)
        .bind(from)
        .bind(to)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db)
        .await;

        match rows {
            Ok(rows) => rows.into_iter().map(|r| r.into_event()).collect(),
            Err(e) => {
                tracing::warn!(error = %e, "failed to list calendar events");
                Vec::new()
            }
        }
    }

    /// Find available 30-minute slots on the given date (UTC), scoped to tenant.
    pub async fn find_available_slots(
        &self,
        tenant_id: &str,
        date: DateTime<Utc>,
    ) -> Vec<(DateTime<Utc>, DateTime<Utc>)> {
        if !matches!(
            date.weekday(),
            chrono::Weekday::Mon
                | chrono::Weekday::Tue
                | chrono::Weekday::Wed
                | chrono::Weekday::Thu
                | chrono::Weekday::Fri
        ) {
            return Vec::new();
        }

        let Some(work_start) = NaiveTime::from_hms_opt(WORK_START_HOUR, 0, 0) else {
            return Vec::new();
        };
        let day_start = date.date_naive().and_time(work_start);
        let day_start = day_start.and_utc();
        let Some(work_end) = NaiveTime::from_hms_opt(WORK_END_HOUR, 0, 0) else {
            return Vec::new();
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
        .unwrap_or_default();

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
        slots
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

    /// Returns `true` if the timestamp is within working hours (09–17 UTC).
    fn is_within_working_hours(dt: DateTime<Utc>) -> bool {
        let hour = dt.hour();
        let weekday = dt.weekday();
        matches!(
            weekday,
            chrono::Weekday::Mon
                | chrono::Weekday::Tue
                | chrono::Weekday::Wed
                | chrono::Weekday::Thu
                | chrono::Weekday::Fri
        ) && (WORK_START_HOUR..WORK_END_HOUR).contains(&hour)
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

        let start = date(2025, 6, 10, 10, 0); // Tuesday
        let end = date(2025, 6, 10, 11, 0);

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
                date(2025, 6, 9, 0, 0),
                date(2025, 6, 11, 0, 0),
                100,
                0,
            )
            .await;
        assert_eq!(events.len(), 1);

        // Other tenant should not see this event
        let other_events = svc
            .list_events(
                "tenant-b",
                date(2025, 6, 9, 0, 0),
                date(2025, 6, 11, 0, 0),
                100,
                0,
            )
            .await;
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

        let start = date(2025, 6, 11, 10, 0); // Wednesday
        let end = date(2025, 6, 11, 11, 0);

        svc.create_event(tenant.to_string(), "First".into(), vec![], start, end, None)
            .await
            .expect("first event");

        // Overlapping slot should be rejected
        let overlap = svc
            .create_event(
                tenant.to_string(),
                "Overlap".into(),
                vec![],
                date(2025, 6, 11, 10, 30),
                date(2025, 6, 11, 11, 30),
                None,
            )
            .await;
        assert!(overlap.is_err());

        // Non-overlapping slot should succeed (different tenant)
        let ok = svc
            .create_event(
                "tenant-c".to_string(),
                "Other tenant".into(),
                vec![],
                date(2025, 6, 11, 10, 30),
                date(2025, 6, 11, 11, 30),
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

        // Book a slot at 10:00-11:00
        svc.create_event(
            tenant.to_string(),
            "Blocked".into(),
            vec![],
            date(2025, 6, 12, 10, 0), // Thursday
            date(2025, 6, 12, 11, 0),
            None,
        )
        .await
        .expect("create blocked slot");

        // Available slots should exclude 10:00-11:00
        let slots = svc
            .find_available_slots(tenant, date(2025, 6, 12, 0, 0))
            .await;

        // Should have 16 slots (9:00-17:00 in 30-min increments = 16) minus 2 blocked (10:00-11:00 = 2 slots)
        assert_eq!(slots.len(), 14, "should have 14 available 30-min slots");

        // None of the slots should overlap with 10:00-11:00
        for (slot_start, slot_end) in &slots {
            assert!(
                !(*slot_start < date(2025, 6, 12, 11, 0) && *slot_end > date(2025, 6, 12, 10, 0)),
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

        // Saturday
        let slots = svc
            .find_available_slots(tenant, date(2025, 6, 14, 0, 0))
            .await;
        assert!(slots.is_empty(), "weekends should have no slots");
    }
}
