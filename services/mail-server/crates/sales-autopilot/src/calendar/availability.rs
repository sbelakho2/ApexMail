//! Provider-independent availability arithmetic (audit §29).
//!
//! This module contains the *policy* — working hours, buffers, minimum
//! notice, allowed weekdays, per-day meeting caps, and round-robin
//! salesperson selection — as pure functions over injected clock/busy data.
//! Providers ([`super::internal`], [`super::google`], [`super::microsoft`])
//! only gather busy intervals and delegate slot generation here, so the
//! policy is identical whichever calendar is authoritative and is testable
//! without a database or network.
//!
//! All wall-clock arithmetic goes through
//! [`super::timezone::resolve_local_datetime`]: the UTC offset is the one in
//! force **on the requested date**, never a fixed offset and never "the
//! offset that applies today".

use std::collections::BTreeMap;

use chrono::{
    DateTime, Datelike, Duration, NaiveDate, NaiveDateTime, NaiveTime, Timelike, Utc, Weekday,
};
use chrono_tz::Tz;

use super::timezone::resolve_local_datetime;

/// Default slot length in minutes (the historical 30-minute demo).
pub const DEFAULT_SLOT_MINUTES: i64 = 30;
/// Default local working-day start (inclusive), 09:00.
pub const DEFAULT_WORKDAY_START_HOUR: u32 = 9;
/// Default local working-day end (exclusive), 17:00.
pub const DEFAULT_WORKDAY_END_HOUR: u32 = 17;
/// Default minimum notice: a slot must start more than this after `now`.
pub const DEFAULT_MIN_NOTICE_MINUTES: i64 = 120;
/// Default buffer required between the new meeting and any existing one.
pub const DEFAULT_BUFFER_MINUTES: i64 = 10;
/// Default cap on meetings per local day.
pub const DEFAULT_MAX_MEETINGS_PER_DAY: usize = 4;
/// Hard cap on slots returned for one request (hostile/oversized config
/// cannot make the endpoint emit unbounded output).
pub const MAX_SLOTS_PER_REQUEST: usize = 200;

fn hms(hour: u32, minute: u32) -> NaiveTime {
    NaiveTime::from_hms_opt(hour, minute, 0).unwrap_or(NaiveTime::MIN)
}

/// Local working hours and allowed weekdays.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkingHours {
    /// Inclusive local start of the working day.
    pub start: NaiveTime,
    /// Exclusive local end of the working day.
    pub end: NaiveTime,
    /// Weekdays on which meetings may be booked.
    pub weekdays: Vec<Weekday>,
}

impl WorkingHours {
    pub fn new(start: NaiveTime, end: NaiveTime, weekdays: Vec<Weekday>) -> Self {
        Self {
            start,
            end,
            weekdays,
        }
    }

    /// Historically the calendar was Monday–Friday;
    /// `SALES_CALENDAR_ALLOWED_WEEKDAYS` overrides this.
    pub fn monday_to_friday() -> Vec<Weekday> {
        vec![
            Weekday::Mon,
            Weekday::Tue,
            Weekday::Wed,
            Weekday::Thu,
            Weekday::Fri,
        ]
    }

    pub fn default_monday_to_friday() -> Self {
        Self::new(
            hms(DEFAULT_WORKDAY_START_HOUR, 0),
            hms(DEFAULT_WORKDAY_END_HOUR, 0),
            Self::monday_to_friday(),
        )
    }

    /// True when `weekday` is an allowed working day.
    pub fn includes_weekday(&self, weekday: Weekday) -> bool {
        self.weekdays.contains(&weekday)
    }

    /// True when a local wall-clock time falls inside the working day. The
    /// end boundary is inclusive for the *start of a slot* so the final slot
    /// (e.g. 16:30–17:00 for a 17:00 end) stays bookable.
    pub fn contains_start(&self, local: NaiveTime) -> bool {
        local >= self.start && local < self.end
    }
}

/// Slot-generation policy. All durations are minutes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlotPolicy {
    /// Slot length in minutes.
    pub slot_minutes: i64,
    /// Required gap between the end of an existing meeting and the start of
    /// the candidate (when the candidate follows it).
    pub buffer_before_minutes: i64,
    /// Required gap between the end of the candidate and the start of the
    /// next existing meeting.
    pub buffer_after_minutes: i64,
    /// Minimum notice: a candidate must start STRICTLY AFTER
    /// `now + min_notice_minutes` (a slot exactly at the boundary is not
    /// offered — see the unit tests).
    pub min_notice_minutes: i64,
    /// Maximum number of meetings already booked on the local day. Once
    /// reached, no further slots are offered for that day.
    pub max_meetings_per_day: usize,
}

impl Default for SlotPolicy {
    fn default() -> Self {
        Self {
            slot_minutes: DEFAULT_SLOT_MINUTES,
            buffer_before_minutes: DEFAULT_BUFFER_MINUTES,
            buffer_after_minutes: DEFAULT_BUFFER_MINUTES,
            min_notice_minutes: DEFAULT_MIN_NOTICE_MINUTES,
            max_meetings_per_day: DEFAULT_MAX_MEETINGS_PER_DAY,
        }
    }
}

impl SlotPolicy {
    /// Validate the policy. Returns a human-readable reason when the
    /// configuration is unusable (callers fall back to defaults rather than
    /// panicking).
    pub fn validate(&self) -> Result<(), String> {
        if self.slot_minutes <= 0 || self.slot_minutes > 8 * 60 {
            return Err("slot_minutes must be in 1..=480".into());
        }
        if self.buffer_before_minutes < 0 || self.buffer_after_minutes < 0 {
            return Err("buffers must not be negative".into());
        }
        if self.min_notice_minutes < 0 {
            return Err("min_notice_minutes must not be negative".into());
        }
        Ok(())
    }
}

/// Everything a provider needs to answer an availability query.
#[derive(Debug, Clone)]
pub struct AvailabilityRequest {
    /// Tenant scope. `sales_calendar_events` is tenant-scoped
    /// (`migrations/200_sales_autopilot_v2_unification.sql:146`).
    pub tenant_id: String,
    /// Local calendar date to generate slots for.
    pub date: NaiveDate,
    /// IANA zone used for all wall-clock arithmetic.
    pub timezone: Tz,
    /// Local working hours.
    pub working_hours: WorkingHours,
    /// Slot/buffer/notice/cap policy.
    pub policy: SlotPolicy,
    /// Candidate salespeople, least-loaded first-class (see
    /// [`pick_least_loaded`]). Empty ⇒ unassigned slots.
    pub salespeople: Vec<String>,
    /// Injected clock, so tests are deterministic.
    pub now: DateTime<Utc>,
}

impl AvailabilityRequest {
    pub fn new(
        tenant_id: impl Into<String>,
        date: NaiveDate,
        timezone: Tz,
        now: DateTime<Utc>,
    ) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            date,
            timezone,
            working_hours: WorkingHours::default_monday_to_friday(),
            policy: SlotPolicy::default(),
            salespeople: Vec::new(),
            now,
        }
    }
}

/// A bookable slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeSlot {
    /// UTC instant used for storage/comparison.
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
    /// The same instant as local wall-clock time in `timezone`.
    pub local_start: NaiveDateTime,
    /// The IANA zone the slot was generated for.
    pub timezone: Tz,
    /// Least-loaded candidate salesperson for this slot, when configured.
    pub salesperson: Option<String>,
}

impl TimeSlot {
    pub fn duration_minutes(&self) -> i64 {
        (self.end - self.start).num_minutes()
    }
}

/// An existing occupied interval, in UTC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BusyInterval {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

impl BusyInterval {
    pub fn new(start: DateTime<Utc>, end: DateTime<Utc>) -> Self {
        Self { start, end }
    }
}

/// Round-robin: the candidate with the fewest meetings in the window. Ties
/// break on the configured order (deterministic). `None` when there are no
/// candidates.
pub fn pick_least_loaded<'a>(
    candidates: &'a [String],
    loads: &BTreeMap<String, usize>,
) -> Option<&'a String> {
    candidates
        .iter()
        .enumerate()
        .min_by_key(|(index, candidate)| {
            (loads.get(candidate.as_str()).copied().unwrap_or(0), *index)
        })
        .map(|(_, candidate)| candidate)
}

/// Generate bookable slots for a request.
///
/// * `busy` — occupied intervals inside the local day (any provider).
/// * `meetings_already_in_day` — meetings already booked on the local day,
///   compared against `policy.max_meetings_per_day`.
/// * `loads` — per-salesperson meeting counts in the window, used for
///   round-robin assignment.
///
/// Nonexistent local times (DST spring-forward gap) are skipped; ambiguous
/// times (fall-back overlap) resolve to their earliest UTC instant. The
/// returned slots are unique by UTC start and capped at
/// [`MAX_SLOTS_PER_REQUEST`].
pub fn generate_slots(
    request: &AvailabilityRequest,
    busy: &[BusyInterval],
    meetings_already_in_day: usize,
    loads: &BTreeMap<String, usize>,
) -> Vec<TimeSlot> {
    let policy = request.policy;
    if policy.validate().is_err() {
        return Vec::new();
    }
    if !request
        .working_hours
        .includes_weekday(request.date.weekday())
    {
        return Vec::new();
    }
    if policy.max_meetings_per_day > 0 && meetings_already_in_day >= policy.max_meetings_per_day {
        return Vec::new();
    }
    let start_minutes = minute_of_day(request.working_hours.start);
    let end_minutes = minute_of_day(request.working_hours.end);
    if end_minutes <= start_minutes {
        return Vec::new();
    }
    let slot_minutes = policy.slot_minutes;
    let notice_cutoff = request.now + Duration::minutes(policy.min_notice_minutes);
    let salesperson = pick_least_loaded(&request.salespeople, loads).cloned();

    let mut slots: Vec<TimeSlot> = Vec::new();
    let mut candidate = start_minutes;
    while candidate + slot_minutes <= end_minutes {
        if slots.len() >= MAX_SLOTS_PER_REQUEST {
            break;
        }
        let hour = (candidate / 60) as u32;
        let minute = (candidate % 60) as u32;
        if let Some(local) = request.date.and_hms_opt(hour, minute, 0) {
            // Nonexistent wall-clock times are skipped; ambiguous times use
            // the earliest occurrence (documented in `timezone`).
            let resolved = resolve_local_datetime(request.timezone, local);
            if let Some(local_dt) = resolved.pick() {
                let start = local_dt.with_timezone(&Utc);
                let end = start + Duration::minutes(slot_minutes);
                let unique = !slots.iter().any(|s| s.start == start);
                let after_notice = start > notice_cutoff;
                let conflict = busy.iter().any(|b| {
                    start < b.end + Duration::minutes(policy.buffer_before_minutes)
                        && end + Duration::minutes(policy.buffer_after_minutes) > b.start
                });
                if unique && after_notice && !conflict {
                    slots.push(TimeSlot {
                        start,
                        end,
                        local_start: local,
                        timezone: request.timezone,
                        salesperson: salesperson.clone(),
                    });
                }
            }
        }
        candidate += slot_minutes;
    }
    slots
}

fn minute_of_day(time: NaiveTime) -> i64 {
    i64::from(time.hour()) * 60 + i64::from(time.minute())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn utc(y: i32, m: u32, d: u32, h: u32, min: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, m, d, h, min, 0).unwrap()
    }

    fn date(y: i32, m: u32, d: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(y, m, d).unwrap()
    }

    fn request(tz: Tz, day: NaiveDate, now: DateTime<Utc>) -> AvailabilityRequest {
        // 2031-03-31 is a Monday; 2031-01-13 and 2031-07-14 are Mondays too.
        AvailabilityRequest::new("tenant-test", day, tz, now)
    }

    fn starts(slots: &[TimeSlot]) -> Vec<DateTime<Utc>> {
        slots.iter().map(|s| s.start).collect()
    }

    // ── DST correctness through the slot generator ──────────────────────

    #[test]
    fn slots_use_post_transition_offset_for_requested_date() {
        // Spring forward in Berlin: Sunday 2031-03-30 02:00 CET → 03:00 CEST.
        // Generate a Monday-after slot (2031-03-31) at 09:00 local: +02:00.
        let berlin = chrono_tz::Europe::Berlin;
        let req = request(berlin, date(2031, 3, 31), utc(2031, 3, 1, 0, 0));
        let slots = generate_slots(&req, &[], 0, &BTreeMap::new());
        let first = slots.first().expect("a Monday must offer slots");
        assert_eq!(first.start, utc(2031, 3, 31, 7, 0));
        // A fixed +01:00 (winter) computation would give 08:00 UTC — the
        // test fails if anyone reintroduces a fixed offset.
        assert_ne!(first.start, utc(2031, 3, 31, 8, 0));

        // Winter Monday 2031-01-13 at 09:00 local is +01:00 → 08:00 UTC;
        // a fixed +02:00 would give 07:00 UTC.
        let req = request(berlin, date(2031, 1, 13), utc(2031, 1, 1, 0, 0));
        let slots = generate_slots(&req, &[], 0, &BTreeMap::new());
        let first = slots.first().expect("a Monday must offer slots");
        assert_eq!(first.start, utc(2031, 1, 13, 8, 0));
        assert_ne!(first.start, utc(2031, 1, 13, 7, 0));
    }

    #[test]
    fn new_york_slots_track_dst() {
        let ny = chrono_tz::America::New_York;
        let winter = generate_slots(
            &request(ny, date(2031, 1, 13), utc(2031, 1, 1, 0, 0)),
            &[],
            0,
            &BTreeMap::new(),
        );
        assert_eq!(winter[0].start, utc(2031, 1, 13, 14, 0));
        let summer = generate_slots(
            &request(ny, date(2031, 7, 14), utc(2031, 7, 1, 0, 0)),
            &[],
            0,
            &BTreeMap::new(),
        );
        assert_eq!(summer[0].start, utc(2031, 7, 14, 13, 0));
    }

    #[test]
    fn tokyo_and_kolkata_slots() {
        let tokyo = generate_slots(
            &request(
                chrono_tz::Asia::Tokyo,
                date(2031, 1, 13),
                utc(2031, 1, 1, 0, 0),
            ),
            &[],
            0,
            &BTreeMap::new(),
        );
        assert_eq!(tokyo[0].start, utc(2031, 1, 13, 0, 0));

        let kolkata = generate_slots(
            &request(
                chrono_tz::Asia::Kolkata,
                date(2031, 1, 13),
                utc(2031, 1, 1, 0, 0),
            ),
            &[],
            0,
            &BTreeMap::new(),
        );
        assert_eq!(kolkata[0].start, utc(2031, 1, 13, 3, 30));
        assert_eq!(kolkata[0].local_start.format("%H:%M").to_string(), "09:00");
    }

    #[test]
    fn spring_forward_gap_slots_are_skipped_not_fabricated() {
        // Berlin 2031-03-30 is a Sunday; allow Sunday and open 01:00–04:00.
        let berlin = chrono_tz::Europe::Berlin;
        let mut req = request(berlin, date(2031, 3, 30), utc(2031, 3, 1, 0, 0));
        req.working_hours = WorkingHours::new(
            NaiveTime::from_hms_opt(1, 0, 0).unwrap(),
            NaiveTime::from_hms_opt(4, 0, 0).unwrap(),
            vec![Weekday::Sun],
        );
        req.policy.min_notice_minutes = 0;
        let slots = generate_slots(&req, &[], 0, &BTreeMap::new());
        let got = starts(&slots);
        // 01:00 and 01:30 exist (CET +01:00): 00:00Z / 00:30Z.
        assert!(got.contains(&utc(2031, 3, 30, 0, 0)));
        assert!(got.contains(&utc(2031, 3, 30, 0, 30)));
        // 03:00 and 03:30 exist (CEST +02:00): 01:00Z / 01:30Z.
        assert!(got.contains(&utc(2031, 3, 30, 1, 0)));
        assert!(got.contains(&utc(2031, 3, 30, 1, 30)));
        // 6 wall-clock candidates (01:00 … 03:30 in 30-min steps); the two in
        // the gap do not exist, so exactly 4 slots are produced. Crucially no
        // slot carries a wall clock in the nonexistent 02:xx hour, and every
        // local time is inside the requested window.
        assert_eq!(
            slots.len(),
            4,
            "spring-forward gap must not fabricate slots"
        );
        for slot in &slots {
            assert_ne!(slot.local_start.hour(), 2);
            assert!(slot.local_start.hour() >= 1 && slot.local_start.hour() < 4);
        }
    }

    #[test]
    fn fall_back_overlap_is_deduplicated_and_earliest_is_used() {
        // Berlin 2031-10-26 is a Sunday; open 01:00–04:00.
        let berlin = chrono_tz::Europe::Berlin;
        let mut req = request(berlin, date(2031, 10, 26), utc(2031, 10, 1, 0, 0));
        req.working_hours = WorkingHours::new(
            NaiveTime::from_hms_opt(1, 0, 0).unwrap(),
            NaiveTime::from_hms_opt(4, 0, 0).unwrap(),
            vec![Weekday::Sun],
        );
        req.policy.min_notice_minutes = 0;
        let slots = generate_slots(&req, &[], 0, &BTreeMap::new());
        let got = starts(&slots);
        // 02:00 and 02:30 occur twice; the documented policy picks the first
        // occurrence (CEST +02:00 → 00:00Z / 00:30Z for the ambiguous hour).
        assert!(got.contains(&utc(2031, 10, 26, 0, 0)));
        assert!(got.contains(&utc(2031, 10, 26, 0, 30)));
        // No duplicate UTC instants.
        let mut sorted = got.clone();
        sorted.dedup();
        assert_eq!(sorted.len(), got.len(), "slots must be unique by UTC start");
    }

    // ── Policy ──────────────────────────────────────────────────────────

    #[test]
    fn minimum_notice_boundary_is_strict() {
        // Monday 2031-06-10? 2031-06-10 is a Tuesday. Use 2031-06-10 anyway.
        let req = AvailabilityRequest::new(
            "t",
            date(2031, 6, 10),
            chrono_tz::UTC,
            utc(2031, 6, 10, 8, 0),
        );
        let mut req = req;
        req.policy.min_notice_minutes = 60; // boundary = 09:00Z
        let slots = generate_slots(&req, &[], 0, &BTreeMap::new());
        let got = starts(&slots);
        // 09:00 is EXACTLY the boundary (`start > now + notice` fails) and
        // must not be offered.
        assert!(!got.contains(&utc(2031, 6, 10, 9, 0)));
        assert!(got.contains(&utc(2031, 6, 10, 9, 30)));

        // With 59 minutes of notice the 09:00 slot is legitimately outside
        // the window (09:00 > 08:59) and is offered.
        req.policy.min_notice_minutes = 59;
        let slots = generate_slots(&req, &[], 0, &BTreeMap::new());
        assert!(starts(&slots).contains(&utc(2031, 6, 10, 9, 0)));
    }

    #[test]
    fn max_meetings_per_day_blocks_the_next_slot() {
        let mut req = AvailabilityRequest::new(
            "t",
            date(2031, 6, 10),
            chrono_tz::UTC,
            utc(2031, 1, 1, 0, 0),
        );
        req.policy.max_meetings_per_day = 2;
        // N meetings already booked on the day, N < max ⇒ slots exist.
        assert!(!generate_slots(&req, &[], 1, &BTreeMap::new()).is_empty());
        // The day is full at max ⇒ the (N+1)th slot is not offered.
        assert!(generate_slots(&req, &[], 2, &BTreeMap::new()).is_empty());
        assert!(generate_slots(&req, &[], 3, &BTreeMap::new()).is_empty());
    }

    #[test]
    fn buffers_are_enforced_on_both_sides() {
        let mut req = AvailabilityRequest::new(
            "t",
            date(2031, 6, 10),
            chrono_tz::UTC,
            utc(2031, 1, 1, 0, 0),
        );
        req.policy.buffer_before_minutes = 15;
        req.policy.buffer_after_minutes = 15;
        req.policy.min_notice_minutes = 0;
        // Existing meeting 10:00–11:00 UTC.
        let busy = [BusyInterval::new(
            utc(2031, 6, 10, 10, 0),
            utc(2031, 6, 10, 11, 0),
        )];
        let got = starts(&generate_slots(&req, &busy, 1, &BTreeMap::new()));
        // Abutting slots are rejected: 09:30–10:00 and 11:00–11:30.
        assert!(!got.contains(&utc(2031, 6, 10, 9, 30)));
        assert!(!got.contains(&utc(2031, 6, 10, 11, 0)));
        // 09:00–09:30 ends 15 minutes before the meeting (09:45 ≤ 10:00) and
        // satisfies the buffer.
        assert!(got.contains(&utc(2031, 6, 10, 9, 0)));
        // Next free candidate after the buffer is 11:30 (11:30 ≥ 11:00+15m).
        assert!(got.contains(&utc(2031, 6, 10, 11, 30)));
        // The 10:30 slot (inside the meeting) is obviously gone.
        assert!(!got.contains(&utc(2031, 6, 10, 10, 30)));
    }

    #[test]
    fn weekend_days_have_no_slots_and_weekday_override_works() {
        let saturday = date(2031, 6, 14);
        let req = AvailabilityRequest::new("t", saturday, chrono_tz::UTC, utc(2031, 1, 1, 0, 0));
        assert!(generate_slots(&req, &[], 0, &BTreeMap::new()).is_empty());

        let mut sunday_req = req.clone();
        sunday_req.date = date(2031, 6, 15);
        sunday_req.working_hours.weekdays = vec![Weekday::Sun];
        assert!(!generate_slots(&sunday_req, &[], 0, &BTreeMap::new()).is_empty());
    }

    #[test]
    fn round_robin_picks_least_loaded_with_deterministic_ties() {
        let candidates = vec!["alice@x.com".to_string(), "bob@x.com".to_string()];
        let mut loads = BTreeMap::new();
        assert_eq!(
            pick_least_loaded(&candidates, &loads),
            Some(&candidates[0]),
            "ties resolve to the configured order"
        );
        loads.insert("alice@x.com".to_string(), 1);
        assert_eq!(pick_least_loaded(&candidates, &loads), Some(&candidates[1]));
        loads.insert("bob@x.com".to_string(), 2);
        assert_eq!(pick_least_loaded(&candidates, &loads), Some(&candidates[0]));
        assert_eq!(pick_least_loaded(&[], &loads), None);
    }

    #[test]
    fn slots_are_tagged_with_the_least_loaded_salesperson() {
        let mut req = AvailabilityRequest::new(
            "t",
            date(2031, 6, 10),
            chrono_tz::UTC,
            utc(2031, 1, 1, 0, 0),
        );
        req.salespeople = vec!["alice@x.com".into(), "bob@x.com".into()];
        let mut loads = BTreeMap::new();
        loads.insert("alice@x.com".to_string(), 3);
        let slots = generate_slots(&req, &[], 3, &loads);
        assert_eq!(slots[0].salesperson.as_deref(), Some("bob@x.com"));
    }

    #[test]
    fn minute_of_day_and_invalid_policy_guards() {
        assert_eq!(
            minute_of_day(NaiveTime::from_hms_opt(9, 30, 0).unwrap()),
            570
        );
        let mut req = AvailabilityRequest::new(
            "t",
            date(2031, 6, 10),
            chrono_tz::UTC,
            utc(2031, 1, 1, 0, 0),
        );
        req.policy.slot_minutes = 0;
        assert!(generate_slots(&req, &[], 0, &BTreeMap::new()).is_empty());
        req.policy.slot_minutes = 30;
        req.policy.max_meetings_per_day = 0; // 0 means "no cap"
        assert!(!generate_slots(&req, &[], 100, &BTreeMap::new()).is_empty());
    }

    #[test]
    fn working_hours_contain_start_is_half_open() {
        let wh = WorkingHours::default_monday_to_friday();
        assert!(wh.contains_start(NaiveTime::from_hms_opt(9, 0, 0).unwrap()));
        assert!(wh.contains_start(NaiveTime::from_hms_opt(16, 30, 0).unwrap()));
        assert!(!wh.contains_start(NaiveTime::from_hms_opt(17, 0, 0).unwrap()));
        assert!(!wh.contains_start(NaiveTime::from_hms_opt(8, 59, 0).unwrap()));
    }
}
