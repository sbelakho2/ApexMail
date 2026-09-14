//! Internal calendar provider — the **store of record** and the fallback
//! when no external provider (Google/Microsoft) is configured.
//!
//! A booking writes two rows (in one transaction):
//!
//! * `sales_calendar_events` — the availability index. Its GiST exclusion
//!   constraint `no_overlapping_events` on
//!   `(tenant_id, tstzrange(start_at, end_at))`
//!   (`migrations/200_sales_autopilot_v2_unification.sql:144-173`) is the
//!   hard double-booking guarantee: two concurrent bookings for the same
//!   slot cannot both commit, regardless of any advisory pre-check.
//! * `sales_meetings` — the canonical meeting store of record
//!   (`migrations/200_sales_autopilot_v2_unification.sql:716-735`), which
//!   carries `provider`, `provider_event_id`, `timezone`, `conferencing_link`
//!   and `status`.
//!
//! # Conferencing links
//!
//! When `SALES_CALENDAR_CONFERENCING_BASE_URL` is configured the link is
//! `{base}/{meeting_id}`. Otherwise the provider emits a deterministic
//! internal join handle `apexmail-meeting://{tenant}/{meeting_id}`. That is
//! deliberately **not** an https:// URL and must not be presented as an
//! external conferencing service; it is a stable identifier the product can
//! resolve to a real room later. No fake external URL is ever emitted.
//!
//! # Salesperson assignment
//!
//! There is no salesperson table, so candidate salespeople come from
//! `SALES_CALENDAR_SALESPEOPLE` (documented in [`super::CalendarConfig`]).
//! The assigned salesperson is recorded in
//! `sales_calendar_events.attendees TEXT[]`
//! (`migrations/200_sales_autopilot_v2_unification.sql:148`); `sales_meetings`
//! has no owner column, so round-robin load counts `sales_meetings` in the
//! window joined to the calendar row and attributed through its `attendees`.

use std::collections::BTreeMap;

use chrono::{DateTime, Duration, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use super::availability::{generate_slots, AvailabilityRequest, BusyInterval, TimeSlot};
use super::timezone::local_day_bounds;
use super::{BookedEvent, CalendarConfig, CalendarError, CalendarProvider, CreateEventRequest};

/// `proposal` guard: a single booking may not exceed this duration.
const MAX_BOOKING_MINUTES: i64 = 12 * 60;

/// `sales_meetings` columns read when rescheduling an existing event.
#[derive(sqlx::FromRow)]
struct MeetingRecordRow {
    tenant_id: String,
    start_at: DateTime<Utc>,
    end_at: DateTime<Utc>,
    conferencing_link: Option<String>,
    provider: String,
    provider_event_id: Option<String>,
}

pub struct InternalCalendarProvider {
    db: PgPool,
    config: CalendarConfig,
}

impl std::fmt::Debug for InternalCalendarProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InternalCalendarProvider")
            .field("timezone", &self.config.timezone.name())
            .finish_non_exhaustive()
    }
}

impl InternalCalendarProvider {
    pub fn new(db: PgPool, config: CalendarConfig) -> Self {
        Self { db, config }
    }

    pub fn db(&self) -> &PgPool {
        &self.db
    }

    pub fn config(&self) -> &CalendarConfig {
        &self.config
    }

    /// Occupied intervals overlapping the requested local day, tenant-scoped
    /// (`sales_calendar_events` columns:
    /// `migrations/200_sales_autopilot_v2_unification.sql:145-151`).
    pub async fn busy_intervals(
        &self,
        request: &AvailabilityRequest,
    ) -> Result<Vec<BusyInterval>, CalendarError> {
        let (day_start, day_end) =
            local_day_bounds(request.timezone, request.date).ok_or_else(|| {
                CalendarError::InvalidInput("the local day cannot be resolved".into())
            })?;
        let rows: Vec<(DateTime<Utc>, DateTime<Utc>)> = sqlx::query_as(
            "SELECT start_at, end_at FROM sales_calendar_events \
             WHERE tenant_id = $1 AND start_at < $2 AND end_at > $3",
        )
        .bind(&request.tenant_id)
        .bind(day_end)
        .bind(day_start)
        .fetch_all(&self.db)
        .await
        .map_err(|e| CalendarError::Database(e.to_string()))?;
        Ok(rows
            .into_iter()
            .map(|(start, end)| BusyInterval::new(start, end))
            .collect())
    }

    /// Per-salesperson booking counts in the requested local day: the number
    /// of `sales_meetings` rows in the window, attributed to a salesperson
    /// through the matching `sales_calendar_events.attendees` entry (see the
    /// module docs for why the attribution lives there).
    ///
    /// Column evidence: `sales_meetings.tenant_id/start_at/end_at/status`
    /// (`migrations/200_sales_autopilot_v2_unification.sql:718,725,726,729`),
    /// `sales_calendar_events.attendees` (`:148`).
    pub async fn salesperson_loads(
        &self,
        request: &AvailabilityRequest,
    ) -> Result<BTreeMap<String, usize>, CalendarError> {
        let mut loads: BTreeMap<String, usize> = request
            .salespeople
            .iter()
            .cloned()
            .map(|who| (who, 0))
            .collect();
        if request.salespeople.is_empty() {
            return Ok(loads);
        }
        let (day_start, day_end) =
            local_day_bounds(request.timezone, request.date).ok_or_else(|| {
                CalendarError::InvalidInput("the local day cannot be resolved".into())
            })?;
        let rows: Vec<(String, i64)> = sqlx::query_as(
            "SELECT attendee, COUNT(*) \
             FROM sales_meetings m \
             JOIN sales_calendar_events e ON e.id = m.id \
             CROSS JOIN LATERAL unnest(e.attendees) AS attendee \
             WHERE m.tenant_id = $1 AND m.start_at < $2 AND m.end_at > $3 \
               AND m.status <> 'cancelled' AND attendee = ANY($4) \
             GROUP BY attendee",
        )
        .bind(&request.tenant_id)
        .bind(day_end)
        .bind(day_start)
        .bind(&request.salespeople)
        .fetch_all(&self.db)
        .await
        .map_err(|e| CalendarError::Database(e.to_string()))?;
        for (attendee, count) in rows {
            loads.insert(
                attendee,
                usize::try_from(count.max(0)).unwrap_or(usize::MAX),
            );
        }
        Ok(loads)
    }

    /// Book a meeting: insert the availability-index row and the meeting
    /// store-of-record row atomically. `provider`/`provider_event_id` are
    /// supplied by external providers mirroring an event here.
    ///
    /// An empty `conferencing_link` means "no provider link was returned":
    /// the deterministic internal handle is generated from the real meeting
    /// id (never from a throwaway id).
    pub async fn record_event(
        &self,
        request: &CreateEventRequest,
        provider: &str,
        provider_event_id: Option<&str>,
        conferencing_link: String,
    ) -> Result<BookedEvent, CalendarError> {
        validate_create_request(request)?;
        let event_id = Uuid::new_v4();
        let conferencing_link = if conferencing_link.trim().is_empty() {
            self.conferencing_link_for(request, event_id)
        } else {
            conferencing_link
        };

        let mut tx = self
            .db
            .begin()
            .await
            .map_err(|e| CalendarError::Database(e.to_string()))?;

        // Advisory fast-path for deployments without btree_gist; the
        // exclusion constraint below is the real guarantee.
        let overlap: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sales_calendar_events \
             WHERE tenant_id = $1 AND start_at < $2 AND end_at > $3",
        )
        .bind(&request.tenant_id)
        .bind(request.end)
        .bind(request.start)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| CalendarError::Database(e.to_string()))?;
        if overlap > 0 {
            return Err(CalendarError::SlotUnavailable);
        }

        let insert = sqlx::query(
            "INSERT INTO sales_calendar_events \
             (id, tenant_id, title, attendees, start_at, end_at, meeting_link) \
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(event_id)
        .bind(&request.tenant_id)
        .bind(&request.title)
        .bind(request.attendees_all())
        .bind(request.start)
        .bind(request.end)
        .bind(&conferencing_link)
        .execute(&mut *tx)
        .await;
        if let Err(error) = insert {
            if is_exclusion_violation(&error) {
                // A concurrent booking won the race: the exclusion constraint
                // rejected this insert. Never surfaced as a 500.
                return Err(CalendarError::SlotUnavailable);
            }
            return Err(CalendarError::Database(error.to_string()));
        }

        sqlx::query(
            "INSERT INTO sales_meetings \
             (id, tenant_id, enrollment_id, account_id, contact_id, provider, \
              provider_event_id, start_at, end_at, timezone, conferencing_link, status) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, 'booked')",
        )
        .bind(event_id)
        .bind(&request.tenant_id)
        .bind(request.enrollment_id)
        .bind(request.account_id)
        .bind(request.contact_id)
        .bind(provider)
        .bind(provider_event_id)
        .bind(request.start)
        .bind(request.end)
        .bind(request.timezone.name())
        .bind(&conferencing_link)
        .execute(&mut *tx)
        .await
        .map_err(|e| CalendarError::Database(e.to_string()))?;

        tx.commit()
            .await
            .map_err(|e| CalendarError::Database(e.to_string()))?;

        Ok(BookedEvent {
            event_id: event_id.to_string(),
            provider: provider.to_string(),
            provider_event_id: provider_event_id.map(str::to_string),
            start: request.start,
            end: request.end,
            timezone: request.timezone,
            conferencing_link,
            status: "booked".into(),
        })
    }

    /// Move an existing recorded meeting, keeping its duration. Enforces the
    /// exclusion constraint against the new interval.
    pub async fn reschedule_recorded(
        &self,
        event_id: &str,
        new_start: DateTime<Utc>,
    ) -> Result<BookedEvent, CalendarError> {
        let id = Uuid::parse_str(event_id)
            .map_err(|_| CalendarError::InvalidInput("event id must be a UUID".into()))?;
        let row: Option<MeetingRecordRow> = sqlx::query_as(
            "SELECT tenant_id, start_at, end_at, conferencing_link, provider, provider_event_id \
                 FROM sales_meetings WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| CalendarError::Database(e.to_string()))?;
        let MeetingRecordRow {
            tenant_id,
            start_at: old_start,
            end_at: old_end,
            conferencing_link: link,
            provider,
            provider_event_id,
        } = row.ok_or_else(|| CalendarError::EventNotFound(event_id.to_string()))?;
        let duration = old_end - old_start;
        if duration <= Duration::zero() || duration > Duration::minutes(MAX_BOOKING_MINUTES) {
            return Err(CalendarError::InvalidInput(
                "existing event duration is not reschedulable".into(),
            ));
        }
        let new_end = new_start + duration;

        let mut tx = self
            .db
            .begin()
            .await
            .map_err(|e| CalendarError::Database(e.to_string()))?;
        let updated = sqlx::query(
            "UPDATE sales_calendar_events SET start_at = $2, end_at = $3 \
             WHERE id = $1 AND tenant_id = $4",
        )
        .bind(id)
        .bind(new_start)
        .bind(new_end)
        .bind(&tenant_id)
        .execute(&mut *tx)
        .await;
        match updated {
            Ok(result) if result.rows_affected() == 0 => {
                return Err(CalendarError::EventNotFound(event_id.to_string()))
            }
            Ok(_) => {}
            // Hitting the exclusion constraint here means another meeting
            // owns the target interval.
            Err(error) if is_exclusion_violation(&error) => {
                return Err(CalendarError::SlotUnavailable)
            }
            Err(error) => return Err(CalendarError::Database(error.to_string())),
        }
        sqlx::query(
            "UPDATE sales_meetings SET start_at = $2, end_at = $3, \
             status = 'rescheduled', updated_at = NOW() WHERE id = $1 AND tenant_id = $4",
        )
        .bind(id)
        .bind(new_start)
        .bind(new_end)
        .bind(&tenant_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| CalendarError::Database(e.to_string()))?;
        tx.commit()
            .await
            .map_err(|e| CalendarError::Database(e.to_string()))?;

        Ok(BookedEvent {
            event_id: event_id.to_string(),
            provider,
            provider_event_id,
            start: new_start,
            end: new_end,
            timezone: self.config.timezone,
            conferencing_link: link.unwrap_or_else(|| self.deterministic_link(&tenant_id, id)),
            status: "rescheduled".into(),
        })
    }

    /// Cancel a meeting: remove the availability-index row (freeing the slot
    /// for future bookings) and mark the store-of-record row `cancelled`.
    pub async fn cancel_recorded(&self, event_id: &str) -> Result<(), CalendarError> {
        let id = Uuid::parse_str(event_id)
            .map_err(|_| CalendarError::InvalidInput("event id must be a UUID".into()))?;
        let mut tx = self
            .db
            .begin()
            .await
            .map_err(|e| CalendarError::Database(e.to_string()))?;
        let deleted = sqlx::query("DELETE FROM sales_calendar_events WHERE id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(|e| CalendarError::Database(e.to_string()))?;
        if deleted.rows_affected() == 0 {
            return Err(CalendarError::EventNotFound(event_id.to_string()));
        }
        sqlx::query(
            "UPDATE sales_meetings SET status = 'cancelled', updated_at = NOW() \
             WHERE id = $1",
        )
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(|e| CalendarError::Database(e.to_string()))?;
        tx.commit()
            .await
            .map_err(|e| CalendarError::Database(e.to_string()))?;
        Ok(())
    }

    /// Deterministic internal join handle — see the module docs. Never an
    /// external https:// URL.
    pub fn deterministic_link(&self, tenant_id: &str, event_id: Uuid) -> String {
        match &self.config.conferencing_base_url {
            Some(base) => format!("{}/{}", base.trim_end_matches('/'), event_id),
            None => format!("apexmail-meeting://{tenant_id}/{event_id}"),
        }
    }

    /// The link a booking will carry: an explicit request link wins, then the
    /// configured base URL, then the deterministic internal handle.
    pub fn conferencing_link_for(&self, request: &CreateEventRequest, event_id: Uuid) -> String {
        request
            .conferencing_link
            .clone()
            .filter(|link| !link.trim().is_empty())
            .unwrap_or_else(|| self.deterministic_link(&request.tenant_id, event_id))
    }
}

#[async_trait::async_trait]
impl CalendarProvider for InternalCalendarProvider {
    fn id(&self) -> &'static str {
        "internal"
    }

    async fn availability(
        &self,
        request: &AvailabilityRequest,
    ) -> Result<Vec<TimeSlot>, CalendarError> {
        let busy = self.busy_intervals(request).await?;
        let loads = self.salesperson_loads(request).await?;
        Ok(generate_slots(request, &busy, busy.len(), &loads))
    }

    async fn create_event(
        &self,
        request: &CreateEventRequest,
    ) -> Result<BookedEvent, CalendarError> {
        // Empty link ⇒ `record_event` generates the deterministic handle from
        // the real meeting id (or the configured base URL).
        self.record_event(request, "internal", None, String::new())
            .await
    }

    async fn reschedule(
        &self,
        event_id: &str,
        new_start: DateTime<Utc>,
    ) -> Result<BookedEvent, CalendarError> {
        self.reschedule_recorded(event_id, new_start).await
    }

    async fn cancel(&self, event_id: &str) -> Result<(), CalendarError> {
        self.cancel_recorded(event_id).await
    }
}

fn validate_create_request(request: &CreateEventRequest) -> Result<(), CalendarError> {
    if request.tenant_id.trim().is_empty() {
        return Err(CalendarError::InvalidInput(
            "tenant_id must not be empty".into(),
        ));
    }
    if request.title.trim().is_empty() {
        return Err(CalendarError::InvalidInput(
            "title must not be empty".into(),
        ));
    }
    if request.end <= request.start {
        return Err(CalendarError::InvalidInput(
            "end_at must be after start_at".into(),
        ));
    }
    if request.end - request.start > Duration::minutes(MAX_BOOKING_MINUTES) {
        return Err(CalendarError::InvalidInput(format!(
            "meeting duration must not exceed {MAX_BOOKING_MINUTES} minutes"
        )));
    }
    if request.start <= Utc::now() {
        return Err(CalendarError::InvalidInput(
            "start_at must be in the future".into(),
        ));
    }
    Ok(())
}

/// Detect a violation of the `no_overlapping_events` GiST exclusion
/// constraint (SQLSTATE `23P01`, or the constraint name when the driver
/// surfaces it as a message).
pub(crate) fn is_exclusion_violation(err: &sqlx::Error) -> bool {
    match err {
        sqlx::Error::Database(db) => {
            db.code().as_deref() == Some("23P01") || db.message().contains("no_overlapping_events")
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::calendar::timezone::DEFAULT_CALENDAR_TIMEZONE;

    fn lazy_db() -> PgPool {
        // Lazy pool: never connects, so validation-only paths can be tested
        // without infrastructure. Pool creation needs a Tokio context.
        sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(std::time::Duration::from_millis(100))
            .connect_lazy("postgres://localhost/unused")
            .expect("lazy pool construction is infallible without I/O")
    }

    fn provider() -> InternalCalendarProvider {
        let tz: chrono_tz::Tz = DEFAULT_CALENDAR_TIMEZONE
            .parse()
            .expect("default zone must parse");
        InternalCalendarProvider::new(lazy_db(), CalendarConfig::new(tz))
    }

    fn request_at(start_utc: DateTime<Utc>, minutes: i64) -> CreateEventRequest {
        CreateEventRequest::new(
            "tenant-x",
            "Demo",
            vec!["prospect@example.com".into()],
            start_utc,
            start_utc + Duration::minutes(minutes),
            chrono_tz::UTC,
        )
    }

    #[tokio::test]
    async fn past_events_are_rejected_before_any_query() {
        let err = provider()
            .create_event(&request_at(Utc::now() - Duration::days(1), 30))
            .await
            .expect_err("past meetings must be rejected");
        assert!(matches!(err, CalendarError::InvalidInput(ref m) if m.contains("future")));
    }

    #[tokio::test]
    async fn inverted_and_empty_inputs_are_rejected() {
        let now = Utc::now() + Duration::days(2);
        let mut req = request_at(now, 30);
        req.end = req.start;
        assert!(matches!(
            provider().create_event(&req).await,
            Err(CalendarError::InvalidInput(_))
        ));

        let mut req = request_at(now, 30);
        req.tenant_id = "  ".into();
        assert!(matches!(
            provider().create_event(&req).await,
            Err(CalendarError::InvalidInput(_))
        ));

        let mut req = request_at(now, 30);
        req.title = "".into();
        assert!(matches!(
            provider().create_event(&req).await,
            Err(CalendarError::InvalidInput(_))
        ));

        let mut req = request_at(now, 30);
        req.end = req.start + Duration::hours(13);
        assert!(matches!(
            provider().create_event(&req).await,
            Err(CalendarError::InvalidInput(_))
        ));
    }

    #[tokio::test]
    async fn deterministic_link_is_not_a_fake_external_url() {
        let provider = provider();
        let id = Uuid::nil();
        let link = provider.deterministic_link("tenant-x", id);
        assert!(!link.starts_with("http://"));
        assert!(!link.starts_with("https://"));
        assert!(link.starts_with("apexmail-meeting://tenant-x/"));
    }

    #[tokio::test]
    async fn explicit_link_wins_and_configured_base_produces_https() {
        let mut config = CalendarConfig::new(chrono_tz::UTC);
        config.conferencing_base_url = Some("https://meet.apexmail.ee/room".into());
        let provider = InternalCalendarProvider::new(lazy_db(), config);
        let id = Uuid::nil();
        assert_eq!(
            provider.deterministic_link("t", id),
            format!("https://meet.apexmail.ee/room/{id}")
        );
        let mut req = request_at(Utc::now() + Duration::days(1), 30);
        req.conferencing_link = Some("https://meet.google.com/abc-defg-hij".into());
        assert_eq!(
            provider.conferencing_link_for(&req, id),
            "https://meet.google.com/abc-defg-hij"
        );
    }

    // -----------------------------------------------------------------------
    // Live-database proofs
    // -----------------------------------------------------------------------

    use chrono::NaiveDate;

    /// A fixed future Tuesday, 2031-06-10, so local-day arithmetic and
    /// working-hour windows are deterministic.
    fn fixture_day() -> NaiveDate {
        NaiveDate::from_ymd_opt(2031, 6, 10).expect("valid date")
    }

    fn utc_at(hour: u32, minute: u32) -> DateTime<Utc> {
        use chrono::TimeZone;
        Utc.with_ymd_and_hms(2031, 6, 10, hour, minute, 0).unwrap()
    }

    async fn live_provider(test_name: &str) -> Option<(PgPool, InternalCalendarProvider, String)> {
        let pool = crate::test_db::canonical_test_pool(test_name).await?;
        let tenant = crate::test_db::unique_test_tenant("cal");
        let provider =
            InternalCalendarProvider::new(pool.clone(), CalendarConfig::new(chrono_tz::UTC));
        Some((pool, provider, tenant))
    }

    async fn cleanup_calendar_tenant(pool: &PgPool, tenant_id: &str) {
        for statement in [
            "DELETE FROM sales_meetings WHERE tenant_id = $1",
            "DELETE FROM sales_calendar_events WHERE tenant_id = $1",
        ] {
            sqlx::query(statement)
                .bind(tenant_id)
                .execute(pool)
                .await
                .unwrap_or_else(|error| panic!("cleanup `{statement}`: {error}"));
        }
    }

    fn booking_request(tenant_id: &str, start: DateTime<Utc>, minutes: i64) -> CreateEventRequest {
        CreateEventRequest::new(
            tenant_id,
            "Discovery Demo",
            vec!["prospect@example.com".into()],
            start,
            start + Duration::minutes(minutes),
            chrono_tz::UTC,
        )
    }

    async fn insert_meeting_with_event(
        pool: &PgPool,
        tenant_id: &str,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        attendees: &[&str],
        status: &str,
    ) -> Uuid {
        let id = Uuid::new_v4();
        let attendees: Vec<String> = attendees.iter().map(|a| a.to_string()).collect();
        sqlx::query(
            "INSERT INTO sales_calendar_events \
                 (id, tenant_id, title, attendees, start_at, end_at, meeting_link) \
             VALUES ($1, $2, 'Booked', $3, $4, $5, 'apexmail-meeting://fixture')",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(&attendees)
        .bind(start)
        .bind(end)
        .execute(pool)
        .await
        .expect("insert calendar event fixture");
        sqlx::query(
            "INSERT INTO sales_meetings \
                 (id, tenant_id, provider, start_at, end_at, timezone, status) \
             VALUES ($1, $2, 'internal', $3, $4, 'UTC', $5)",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(start)
        .bind(end)
        .bind(status)
        .execute(pool)
        .await
        .expect("insert meeting fixture");
        id
    }

    /// Busy-interval lookup is tenant-scoped and bounded to the requested
    /// local day (overlap predicate, not containment).
    #[tokio::test]
    async fn busy_intervals_are_tenant_scoped_and_day_bounded() {
        let Some((pool, provider, tenant)) = live_provider("calendar_busy").await else {
            return;
        };
        let other = crate::test_db::unique_test_tenant("cal-other");
        for (who, start, minutes) in [
            (tenant.as_str(), utc_at(10, 0), 30),
            (tenant.as_str(), utc_at(0, 0) - Duration::minutes(30), 60),
            (tenant.as_str(), utc_at(8, 0) - Duration::hours(12), 60),
            (other.as_str(), utc_at(11, 0), 30),
        ] {
            insert_meeting_with_event(
                &pool,
                who,
                start,
                start + Duration::minutes(minutes),
                &[],
                "booked",
            )
            .await;
        }

        let mut request =
            AvailabilityRequest::new(tenant.clone(), fixture_day(), chrono_tz::UTC, Utc::now());
        request.salespeople = Vec::new();
        let busy = provider
            .busy_intervals(&request)
            .await
            .expect("busy intervals");
        assert_eq!(
            busy.len(),
            2,
            "the out-of-day and other-tenant intervals must be excluded: {busy:?}"
        );
        assert!(busy.iter().any(|interval| interval.start == utc_at(10, 0)));
        assert!(busy
            .iter()
            .any(|interval| interval.start == utc_at(0, 0) - Duration::minutes(30)));

        cleanup_calendar_tenant(&pool, &tenant).await;
        cleanup_calendar_tenant(&pool, &other).await;
    }

    /// Round-robin loads count only non-cancelled meetings of the requested
    /// tenant and day, attributed through the calendar event's attendees.
    #[tokio::test]
    async fn salesperson_loads_count_only_live_meetings_of_the_tenant() {
        let Some((pool, provider, tenant)) = live_provider("calendar_loads").await else {
            return;
        };
        let other = crate::test_db::unique_test_tenant("cal-loads-other");
        insert_meeting_with_event(
            &pool,
            &tenant,
            utc_at(10, 0),
            utc_at(10, 30),
            &["rep-a@example.com", "rep-b@example.com"],
            "booked",
        )
        .await;
        insert_meeting_with_event(
            &pool,
            &tenant,
            utc_at(11, 0),
            utc_at(11, 30),
            &["rep-a@example.com"],
            "cancelled",
        )
        .await;
        // Another day and another tenant must not contribute.
        insert_meeting_with_event(
            &pool,
            &tenant,
            utc_at(10, 0) + Duration::days(1),
            utc_at(10, 30) + Duration::days(1),
            &["rep-a@example.com"],
            "booked",
        )
        .await;
        insert_meeting_with_event(
            &pool,
            &other,
            utc_at(12, 0),
            utc_at(12, 30),
            &["rep-a@example.com"],
            "booked",
        )
        .await;

        let mut request =
            AvailabilityRequest::new(tenant.clone(), fixture_day(), chrono_tz::UTC, Utc::now());
        request.salespeople = vec![
            "rep-a@example.com".into(),
            "rep-b@example.com".into(),
            "rep-c@example.com".into(),
        ];
        let loads = provider.salesperson_loads(&request).await.expect("loads");
        assert_eq!(loads.get("rep-a@example.com"), Some(&1));
        assert_eq!(loads.get("rep-b@example.com"), Some(&1));
        assert_eq!(loads.get("rep-c@example.com"), Some(&0));

        // No candidates: no query, an empty map.
        request.salespeople = Vec::new();
        let empty = provider
            .salesperson_loads(&request)
            .await
            .expect("empty loads");
        assert!(empty.is_empty());

        cleanup_calendar_tenant(&pool, &tenant).await;
        cleanup_calendar_tenant(&pool, &other).await;
    }

    /// Booking writes both rows atomically: the availability index carries the
    /// attendees (including the round-robin salesperson) and the meeting is
    /// the store of record with the deterministic internal link.
    #[tokio::test]
    async fn record_event_writes_both_rows_with_a_deterministic_link() {
        let Some((pool, provider, tenant)) = live_provider("calendar_record").await else {
            return;
        };
        let mut request = booking_request(&tenant, utc_at(10, 0), 30);
        request.salesperson = Some("rep-a@example.com".into());
        let booked = provider
            .record_event(&request, "internal", Some("provider-evt-1"), String::new())
            .await
            .expect("a free slot books");
        assert_eq!(booked.status, "booked");
        assert_eq!(booked.provider, "internal");
        assert_eq!(booked.provider_event_id.as_deref(), Some("provider-evt-1"));
        assert_eq!(
            booked.conferencing_link,
            format!("apexmail-meeting://{tenant}/{}", booked.event_id)
        );

        let booked_id = Uuid::parse_str(&booked.event_id).expect("uuid");
        let (title, attendees, meeting_link): (String, Vec<String>, Option<String>) =
            sqlx::query_as(
                "SELECT title, attendees, meeting_link FROM sales_calendar_events WHERE id = $1",
            )
            .bind(booked_id)
            .fetch_one(&pool)
            .await
            .expect("availability row");
        assert_eq!(title, "Discovery Demo");
        assert_eq!(
            attendees,
            vec![
                "prospect@example.com".to_string(),
                "rep-a@example.com".to_string()
            ],
            "the salesperson joins the attendees once"
        );
        assert_eq!(
            meeting_link.as_deref(),
            Some(booked.conferencing_link.as_str())
        );

        let (provider_name, status, timezone, link): (String, String, String, Option<String>) =
            sqlx::query_as(
                "SELECT provider, status, timezone, conferencing_link FROM sales_meetings WHERE id = $1",
            )
            .bind(booked_id)
            .fetch_one(&pool)
            .await
            .expect("meeting row");
        assert_eq!(provider_name, "internal");
        assert_eq!(status, "booked");
        assert_eq!(timezone, "UTC");
        assert_eq!(link.as_deref(), Some(booked.conferencing_link.as_str()));

        // An explicit link wins over the deterministic handle.
        let mut second = booking_request(&tenant, utc_at(11, 0), 30);
        second.conferencing_link = Some("https://meet.example.com/room-1".into());
        let booked = provider
            .create_event(&second)
            .await
            .expect("second booking");
        assert_eq!(booked.conferencing_link, "https://meet.example.com/room-1");

        // Double-booking the exact slot is refused and adds no second row.
        let overlap = booking_request(&tenant, utc_at(10, 10), 30);
        let error = provider
            .create_event(&overlap)
            .await
            .expect_err("an overlapping slot must be refused");
        assert!(matches!(error, CalendarError::SlotUnavailable));
        let meetings: i64 =
            sqlx::query_scalar("SELECT COUNT(*)::bigint FROM sales_meetings WHERE tenant_id = $1")
                .bind(&tenant)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(meetings, 2, "the refused booking must not leave a row");

        // Back-to-back is allowed (half-open intervals must not be treated as
        // overlapping).
        let adjacent = booking_request(&tenant, utc_at(10, 30), 30);
        provider
            .create_event(&adjacent)
            .await
            .expect("adjacent bookings do not overlap");

        // A booking for another tenant on the same instant is isolated.
        let stranger = crate::test_db::unique_test_tenant("cal-iso");
        provider
            .create_event(&booking_request(&stranger, utc_at(10, 0), 30))
            .await
            .expect("another tenant may book the same wall-clock slot");
        cleanup_calendar_tenant(&pool, &stranger).await;

        cleanup_calendar_tenant(&pool, &tenant).await;
    }

    /// Rescheduling keeps the duration, updates both rows, refuses an
    /// occupied target (the exclusion constraint, not the pre-check) and
    /// refuses an un-reschedulable stored duration.
    #[tokio::test]
    async fn reschedule_moves_both_rows_and_refuses_conflicts() {
        let Some((pool, provider, tenant)) = live_provider("calendar_reschedule").await else {
            return;
        };

        let first = provider
            .create_event(&booking_request(&tenant, utc_at(10, 0), 30))
            .await
            .expect("book first");
        provider
            .create_event(&booking_request(&tenant, utc_at(11, 0), 30))
            .await
            .expect("book second");

        // Occupied target: the UPDATE hits the GiST exclusion constraint.
        let error = provider
            .reschedule(&first.event_id, utc_at(11, 5))
            .await
            .expect_err("an occupied target must be refused");
        assert!(
            matches!(error, CalendarError::SlotUnavailable),
            "got {error:?}"
        );

        // Missing and malformed ids.
        assert!(matches!(
            provider
                .reschedule(&Uuid::new_v4().to_string(), utc_at(15, 0))
                .await,
            Err(CalendarError::EventNotFound(_))
        ));
        assert!(matches!(
            provider.reschedule("not-a-uuid", utc_at(15, 0)).await,
            Err(CalendarError::InvalidInput(_))
        ));

        // A stored event longer than the 12h booking bound is not
        // reschedulable (defensive against hand-edited rows).
        let next_day = utc_at(0, 0) + Duration::days(1);
        let long_id = insert_meeting_with_event(
            &pool,
            &tenant,
            next_day,
            next_day + Duration::hours(13),
            &[],
            "booked",
        )
        .await;
        assert!(matches!(
            provider
                .reschedule(&long_id.to_string(), utc_at(16, 0))
                .await,
            Err(CalendarError::InvalidInput(_))
        ));

        // A legal move keeps the duration and marks the meeting rescheduled.
        let moved = provider
            .reschedule(&first.event_id, utc_at(14, 0))
            .await
            .expect("a free target reschedules");
        assert_eq!(moved.status, "rescheduled");
        assert_eq!(moved.end, utc_at(14, 30));
        assert_eq!(moved.start, utc_at(14, 0));
        let first_id = Uuid::parse_str(&first.event_id).expect("uuid");
        let (start, end, status): (DateTime<Utc>, DateTime<Utc>, String) =
            sqlx::query_as("SELECT start_at, end_at, status FROM sales_meetings WHERE id = $1")
                .bind(first_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(start, utc_at(14, 0));
        assert_eq!(end, utc_at(14, 30));
        assert_eq!(status, "rescheduled");
        let event_start: DateTime<Utc> =
            sqlx::query_scalar("SELECT start_at FROM sales_calendar_events WHERE id = $1")
                .bind(first_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(event_start, utc_at(14, 0), "the availability index moved");

        cleanup_calendar_tenant(&pool, &tenant).await;
    }

    /// Cancel frees the slot (the availability row is deleted) and marks the
    /// store-of-record row cancelled; a second cancel is a not-found.
    #[tokio::test]
    async fn cancel_frees_the_slot_and_is_not_idempotent_by_design() {
        let Some((pool, provider, tenant)) = live_provider("calendar_cancel").await else {
            return;
        };
        let booked = provider
            .create_event(&booking_request(&tenant, utc_at(9, 0), 30))
            .await
            .expect("book");

        provider
            .cancel_recorded(&booked.event_id)
            .await
            .expect("cancel");
        let booked_id = Uuid::parse_str(&booked.event_id).expect("uuid");
        let remaining: i64 =
            sqlx::query_scalar("SELECT COUNT(*)::bigint FROM sales_calendar_events WHERE id = $1")
                .bind(booked_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(remaining, 0, "the availability index row must be deleted");
        let status: String = sqlx::query_scalar("SELECT status FROM sales_meetings WHERE id = $1")
            .bind(booked_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(status, "cancelled");
        // The freed slot is bookable again.
        provider
            .create_event(&booking_request(&tenant, utc_at(9, 0), 30))
            .await
            .expect("a cancelled meeting frees the slot");

        assert!(matches!(
            provider.cancel_recorded(&booked.event_id).await,
            Err(CalendarError::EventNotFound(_))
        ));
        assert!(matches!(
            provider.cancel("not-a-uuid").await,
            Err(CalendarError::InvalidInput(_))
        ));

        cleanup_calendar_tenant(&pool, &tenant).await;
    }

    /// Availability delegates to the shared policy: busy slots are excluded
    /// with buffers, the per-day cap stops the day, and the least-loaded
    /// salesperson is attached.
    #[tokio::test]
    async fn availability_applies_busy_windows_the_cap_and_round_robin() {
        let Some((pool, provider, tenant)) = live_provider("calendar_availability").await else {
            return;
        };
        insert_meeting_with_event(
            &pool,
            &tenant,
            utc_at(10, 0),
            utc_at(10, 30),
            &["rep-a@example.com"],
            "booked",
        )
        .await;

        let mut request =
            AvailabilityRequest::new(tenant.clone(), fixture_day(), chrono_tz::UTC, utc_at(8, 0));
        request.policy.min_notice_minutes = 0;
        request.salespeople = vec!["rep-a@example.com".into()];
        let slots = provider.availability(&request).await.expect("availability");
        assert!(!slots.is_empty());
        // 10:00 is busy and 09:50–10:40 is inside the 10-minute buffers.
        let buffered_start = utc_at(9, 50);
        let buffered_end = utc_at(10, 40);
        assert!(
            slots
                .iter()
                .all(|slot| slot.end <= buffered_start || slot.start >= buffered_end),
            "a buffered slot was offered: {:?}",
            slots.iter().map(|s| (s.start, s.end)).collect::<Vec<_>>()
        );
        assert!(
            slots
                .iter()
                .all(|slot| slot.salesperson.as_deref() == Some("rep-a@example.com")),
            "the configured salesperson must be attached"
        );

        // The day cap counts the booked meeting: one meeting + cap 1 ⇒ no
        // slots.
        request.policy.max_meetings_per_day = 1;
        let capped = provider
            .availability(&request)
            .await
            .expect("capped availability");
        assert!(
            capped.is_empty(),
            "the per-day cap must stop a day that already has a meeting"
        );

        // An invalid policy is refused as an empty result, never a panic.
        request.policy.slot_minutes = 0;
        let invalid = provider
            .availability(&request)
            .await
            .expect("invalid policy");
        assert!(invalid.is_empty());

        cleanup_calendar_tenant(&pool, &tenant).await;
    }

    /// Workday bounds are evaluated in the requested IANA zone, not UTC: a
    /// UTC-Tuesday 22:00 instant is already Wednesday in Tallinn.
    #[tokio::test]
    async fn local_day_bounds_are_iana_not_fixed_offsets() {
        let Some((pool, provider, tenant)) = live_provider("calendar_day_bounds").await else {
            return;
        };
        let tallinn: chrono_tz::Tz = "Europe/Tallinn".parse().unwrap();
        // 2031-06-10 21:30 UTC == 2031-06-11 00:30 Tallinn (EEST, UTC+3).
        let start = utc_at(21, 30);
        insert_meeting_with_event(
            &pool,
            &tenant,
            start,
            start + Duration::minutes(30),
            &[],
            "booked",
        )
        .await;

        let mut request =
            AvailabilityRequest::new(tenant.clone(), fixture_day(), tallinn, Utc::now());
        let on_tuesday = provider.busy_intervals(&request).await.unwrap();
        assert!(
            on_tuesday.is_empty(),
            "a 21:30 UTC meeting is Wednesday in Tallinn, not Tuesday"
        );
        let wednesday = NaiveDate::from_ymd_opt(2031, 6, 11).unwrap();
        request.date = wednesday;
        let on_wednesday = provider.busy_intervals(&request).await.unwrap();
        assert_eq!(on_wednesday.len(), 1);

        cleanup_calendar_tenant(&pool, &tenant).await;
    }

    #[test]
    fn exclusion_violation_detection_is_narrow() {
        assert!(!is_exclusion_violation(&sqlx::Error::RowNotFound));
    }
}
