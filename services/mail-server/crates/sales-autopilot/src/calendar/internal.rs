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
        .bind(&request.attendees_all())
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
        let row: Option<(
            String,
            DateTime<Utc>,
            DateTime<Utc>,
            Option<String>,
            String,
            Option<String>,
        )> = sqlx::query_as(
            "SELECT tenant_id, start_at, end_at, conferencing_link, provider, provider_event_id \
                 FROM sales_meetings WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| CalendarError::Database(e.to_string()))?;
        let (tenant_id, old_start, old_end, link, provider, provider_event_id) =
            row.ok_or_else(|| CalendarError::EventNotFound(event_id.to_string()))?;
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
}
