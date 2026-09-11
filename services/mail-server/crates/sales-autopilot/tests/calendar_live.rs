//! Live-database adversarial calendar tests (audit §29).
//!
//! These tests need a **canonical, migrated Postgres** (the same migration
//! chain `routes::initialize_schema` verifies) because the guarantees under
//! test are database-level:
//!
//! * the `no_overlapping_events` GiST exclusion constraint must reject a
//!   concurrent double-booking even when both requests pass the service
//!   pre-check (the race the pre-check alone cannot close);
//! * cancelling a meeting must delete the availability-index row so the slot
//!   becomes offerable again, while the `sales_meetings` store-of-record row
//!   is retained as `cancelled`;
//! * round-robin must rotate to the least-loaded salesperson across bookings.
//!
//! All tests are `#[ignore]`d so `cargo test -p sales-autopilot` stays green
//! without infrastructure. Run them with:
//!
//! ```text
//! TEST_DATABASE_URL=postgresql://user:pass@host:5432/db \
//!   cargo test -p sales-autopilot --test calendar_live -- --ignored
//! ```

use chrono::{DateTime, Duration, NaiveDate, NaiveTime, TimeZone, Utc, Weekday};
use sqlx::PgPool;
use uuid::Uuid;

use sales_autopilot::calendar::{
    AvailabilityRequest, CalendarConfig, CalendarService, CreateEventRequest, SlotPolicy,
    WorkingHours,
};

const IGNORE_REASON: &str =
    "live database required: run with TEST_DATABASE_URL set and -- --ignored";

/// A dedicated database carrying the complete pinned canonical chain,
/// provisioned through the REAL production migrator (audit F01) exactly like
/// every other live suite in this workspace. Using a dedicated database keeps
/// these destructive fixtures away from whatever else shares
/// `TEST_DATABASE_URL`.
const LIVE_DB: &str = "apexmail_calendar_live";

async fn live_pool(test_name: &str) -> Option<PgPool> {
    let base_url = std::env::var("TEST_DATABASE_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())?;
    let pool = match migrator::test_support::shared_canonical_db(&base_url, LIVE_DB).await {
        Ok(Some(pool)) => pool,
        Ok(None) => return None,
        // The URL is configured, so provisioning failure is infrastructure
        // breakage — never a silent skip.
        Err(error) => panic!("{test_name}: {}", error.panic_message()),
    };
    sales_autopilot::routes::initialize_schema(&pool)
        .await
        .unwrap_or_else(|error| {
            panic!("canonical schema verification failed for {test_name}: {error}")
        });
    Some(pool)
}

fn live_config(salespeople: Vec<String>) -> CalendarConfig {
    CalendarConfig {
        timezone: chrono_tz::UTC,
        working_hours: WorkingHours::new(
            NaiveTime::from_hms_opt(9, 0, 0).expect("09:00"),
            NaiveTime::from_hms_opt(17, 0, 0).expect("17:00"),
            WorkingHours::monday_to_friday(),
        ),
        policy: SlotPolicy {
            slot_minutes: 30,
            buffer_before_minutes: 0,
            buffer_after_minutes: 0,
            min_notice_minutes: 0,
            max_meetings_per_day: 100,
        },
        salespeople,
        conferencing_base_url: None,
    }
}

fn tenant_id(label: &str) -> String {
    format!("cal-live-{label}-{}", Uuid::new_v4().simple())
}

/// A future Monday 10:00 UTC (2031-06-09 is a Monday) so legacy working-hour
/// checks are satisfied regardless of when the suite runs.
fn future_slot() -> (DateTime<Utc>, DateTime<Utc>) {
    let day = NaiveDate::from_ymd_opt(2031, 6, 9).expect("date");
    let start = Utc
        .from_local_datetime(&day.and_hms_opt(10, 0, 0).expect("time"))
        .single()
        .expect("unambiguous");
    (start, start + Duration::minutes(30))
}

async fn cleanup(pool: &PgPool, tenant: &str) {
    let _ = sqlx::query("DELETE FROM sales_calendar_events WHERE tenant_id = $1")
        .bind(tenant)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM sales_meetings WHERE tenant_id = $1")
        .bind(tenant)
        .execute(pool)
        .await;
}

fn request_for(
    tenant: &str,
    day: NaiveDate,
    salesperson: Option<String>,
    conference: &CalendarConfig,
) -> CreateEventRequest {
    let start = Utc
        .from_local_datetime(&day.and_hms_opt(10, 0, 0).expect("time"))
        .single()
        .expect("unambiguous");
    let mut request = CreateEventRequest::new(
        tenant,
        "Live demo",
        vec!["prospect@example.com".into()],
        start,
        start + Duration::minutes(30),
        conference.timezone,
    );
    request.salesperson = salesperson;
    request
}

// ---------------------------------------------------------------------------
// 6. Double-booking race — the DB exclusion constraint must decide
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "live database required"]
async fn live_db_exclusion_constraint_rejects_overlap() {
    let Some(pool) = live_pool("live_db_exclusion_constraint_rejects_overlap").await else {
        eprintln!("skipping: TEST_DATABASE_URL unset ({IGNORE_REASON})");
        return;
    };
    let tenant = tenant_id("constraint");
    cleanup(&pool, &tenant).await;
    let (start, end) = future_slot();

    sqlx::query(
        "INSERT INTO sales_calendar_events (id, tenant_id, title, attendees, start_at, end_at, meeting_link) \
         VALUES ($1, $2, 'first', '{}', $3, $4, NULL)",
    )
    .bind(Uuid::new_v4())
    .bind(&tenant)
    .bind(start)
    .bind(end)
    .execute(&pool)
    .await
    .expect("first insert must succeed");

    // Overlapping direct insert: must be rejected by the GiST exclusion
    // constraint (SQLSTATE 23P01), independent of any service-level check.
    let error = sqlx::query(
        "INSERT INTO sales_calendar_events (id, tenant_id, title, attendees, start_at, end_at, meeting_link) \
         VALUES ($1, $2, 'second', '{}', $3, $4, NULL)",
    )
    .bind(Uuid::new_v4())
    .bind(&tenant)
    .bind(start + Duration::minutes(15))
    .bind(end + Duration::minutes(15))
    .execute(&pool)
    .await
    .expect_err("overlapping insert must be rejected by the exclusion constraint");
    match &error {
        sqlx::Error::Database(db) => {
            assert!(
                db.code().as_deref() == Some("23P01")
                    || db.message().contains("no_overlapping_events"),
                "expected exclusion violation 23P01, got code={:?} message={}",
                db.code(),
                db.message()
            );
        }
        other => panic!("expected a database error, got {other:?}"),
    }
    cleanup(&pool, &tenant).await;
}

#[tokio::test]
#[ignore = "live database required"]
async fn live_db_double_booking_race_has_exactly_one_winner() {
    let Some(pool) = live_pool("live_db_double_booking_race_has_exactly_one_winner").await else {
        eprintln!("skipping: TEST_DATABASE_URL unset ({IGNORE_REASON})");
        return;
    };
    let tenant = tenant_id("race");
    cleanup(&pool, &tenant).await;
    let config = live_config(vec![]);
    let svc = CalendarService::from_config(pool.clone(), config.clone());
    let day = NaiveDate::from_ymd_opt(2031, 6, 9).expect("date");

    let request_one = request_for(&tenant, day, None, &config);
    let request_two = request_for(&tenant, day, None, &config);
    let (r1, r2) = tokio::join!(svc.book(&request_one), svc.book(&request_two));

    let successes = [&r1, &r2].iter().filter(|result| result.is_ok()).count();
    let unavailable = [&r1, &r2]
        .iter()
        .filter(|result| {
            matches!(
                result,
                Err(sales_autopilot::calendar::CalendarError::SlotUnavailable)
            )
        })
        .count();
    assert_eq!(
        successes, 1,
        "exactly one concurrent booking must win: {r1:?} / {r2:?}"
    );
    assert_eq!(
        unavailable, 1,
        "the loser must see SlotUnavailable: {r1:?} / {r2:?}"
    );

    // Store of record: exactly one booked meeting.
    let booked: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sales_meetings WHERE tenant_id = $1 AND status = 'booked'",
    )
    .bind(&tenant)
    .fetch_one(&pool)
    .await
    .expect("count meetings");
    assert_eq!(booked, 1);
    cleanup(&pool, &tenant).await;
}

// ---------------------------------------------------------------------------
// 7. Cancelling frees the slot
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "live database required"]
async fn live_db_cancelled_meeting_frees_the_slot() {
    let Some(pool) = live_pool("live_db_cancelled_meeting_frees_the_slot").await else {
        eprintln!("skipping: TEST_DATABASE_URL unset ({IGNORE_REASON})");
        return;
    };
    let tenant = tenant_id("cancel");
    cleanup(&pool, &tenant).await;
    let config = live_config(vec![]);
    let svc = CalendarService::from_config(pool.clone(), config.clone());
    let day = NaiveDate::from_ymd_opt(2031, 6, 9).expect("date");

    let booked = svc
        .book(&request_for(&tenant, day, None, &config))
        .await
        .expect("booking must succeed");

    let availability_request = AvailabilityRequest::new(&tenant, day, chrono_tz::UTC, Utc::now());
    let before = svc
        .availability(&availability_request)
        .await
        .expect("availability");
    assert!(
        !before.iter().any(|slot| slot.start == booked.start),
        "the booked 10:00 slot must not be offered"
    );

    svc.cancel(&booked.event_id)
        .await
        .expect("cancel must succeed");

    let after = svc
        .availability(&availability_request)
        .await
        .expect("availability after cancel");
    assert!(
        after.iter().any(|slot| slot.start == booked.start),
        "after cancellation the 10:00 slot must be offerable again"
    );

    // Store of record keeps the meeting, marked cancelled.
    let status: String = sqlx::query_scalar("SELECT status FROM sales_meetings WHERE id = $1")
        .bind(Uuid::parse_str(&booked.event_id).expect("uuid"))
        .fetch_one(&pool)
        .await
        .expect("meeting row must be retained");
    assert_eq!(status, "cancelled");
    cleanup(&pool, &tenant).await;
}

// ---------------------------------------------------------------------------
// 8. Round-robin across consecutive bookings
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "live database required"]
async fn live_db_round_robin_rotates_salespeople() {
    let Some(pool) = live_pool("live_db_round_robin_rotates_salespeople").await else {
        eprintln!("skipping: TEST_DATABASE_URL unset ({IGNORE_REASON})");
        return;
    };
    let tenant = tenant_id("roundrobin");
    cleanup(&pool, &tenant).await;
    let alice = "alice@apexmail.ee".to_string();
    let bob = "bob@apexmail.ee".to_string();
    let config = live_config(vec![alice.clone(), bob.clone()]);
    let svc = CalendarService::from_config(pool.clone(), config.clone());
    let day = NaiveDate::from_ymd_opt(2031, 6, 9).expect("date");
    // Built from the config so the configured salespeople are candidates.
    let availability_request = config.availability_request(&tenant, day, Utc::now());

    // First availability: tie → configured order (alice).
    let slots = svc
        .availability(&availability_request)
        .await
        .expect("availability");
    let first_assignee = slots
        .first()
        .and_then(|slot| slot.salesperson.clone())
        .expect("slots must be tagged with a salesperson");
    assert_eq!(
        first_assignee, alice,
        "tie must resolve to the configured order"
    );

    // Book with alice.
    let booked = svc
        .book(&request_for(&tenant, day, Some(alice.clone()), &config))
        .await
        .expect("first booking");
    assert_eq!(booked.provider, "internal");

    // Next availability: bob is now least-loaded and must be selected.
    let slots = svc
        .availability(&availability_request)
        .await
        .expect("availability after first booking");
    let next_assignee = slots
        .first()
        .and_then(|slot| slot.salesperson.clone())
        .expect("salesperson tag");
    assert_eq!(
        next_assignee, bob,
        "the second booking must rotate to the least-loaded salesperson"
    );

    // The salesperson is recorded in attendees (the load-counting column).
    let attendees: Vec<String> =
        sqlx::query_scalar("SELECT attendees FROM sales_calendar_events WHERE tenant_id = $1")
            .bind(&tenant)
            .fetch_one(&pool)
            .await
            .expect("calendar row");
    assert!(attendees.iter().any(|attendee| attendee == &alice));
    cleanup(&pool, &tenant).await;
}

// ---------------------------------------------------------------------------
// Legacy compatibility through the live schema
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "live database required"]
async fn live_db_legacy_calendar_surface_still_works() {
    let Some(pool) = live_pool("live_db_legacy_calendar_surface_still_works").await else {
        eprintln!("skipping: TEST_DATABASE_URL unset ({IGNORE_REASON})");
        return;
    };
    let tenant = tenant_id("legacy");
    cleanup(&pool, &tenant).await;
    let svc = CalendarService::new(pool.clone());
    // 2031-06-10 is a Tuesday, inside the legacy UTC 09:00–17:00 window.
    let start = Utc.with_ymd_and_hms(2031, 6, 10, 10, 0, 0).unwrap();
    let end = Utc.with_ymd_and_hms(2031, 6, 10, 10, 30, 0).unwrap();

    let event = svc
        .create_event(tenant.clone(), "Demo".into(), vec![], start, end, None)
        .await
        .expect("legacy create_event must succeed");
    let link = event
        .meeting_link
        .as_deref()
        .expect("every booked meeting carries a link");
    assert!(
        link.contains(&event.id.to_string()),
        "the deterministic internal handle must be derived from the real meeting id, got {link}"
    );
    let slots = svc
        .find_available_slots(&tenant, start)
        .await
        .expect("legacy availability");
    assert!(!slots.iter().any(|(slot_start, _)| *slot_start == start));

    svc.cancel_event(event.id, &tenant)
        .await
        .expect("legacy cancel");
    let slots = svc
        .find_available_slots(&tenant, start)
        .await
        .expect("legacy availability after cancel");
    assert!(slots.iter().any(|(slot_start, _)| *slot_start == start));
    cleanup(&pool, &tenant).await;
}

/// Keep the weekday import meaningful for future fixtures.
#[allow(dead_code)]
fn _weekdays() -> Vec<Weekday> {
    WorkingHours::monday_to_friday()
}
