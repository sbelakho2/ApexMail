use chrono::{DateTime, Datelike, Duration, NaiveTime, Timelike, Utc};
use parking_lot::RwLock;
use std::sync::Arc;
use uuid::Uuid;

use crate::types::{CalendarEvent, SalesError};

/// Calendar / demo-scheduling service.
///
/// Working hours: 09:00–17:00 UTC, Monday–Friday equivalent.
/// Slot duration is fixed at 30 minutes.
const WORK_START_HOUR: u32 = 9;
const WORK_END_HOUR: u32 = 17;
const SLOT_MINUTES: i64 = 30;

#[derive(Debug, Clone)]
pub struct CalendarService {
    events: Arc<RwLock<Vec<CalendarEvent>>>,
}

impl Default for CalendarService {
    fn default() -> Self {
        Self::new()
    }
}

impl CalendarService {
    pub fn new() -> Self {
        Self {
            events: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Create a calendar event. Validates that the event falls within
    /// working hours and does not overlap an existing booking.
    pub fn create_event(
        &self,
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

        // Check for overlaps
        let store = self.events.read();
        let overlaps = store.iter().any(|e| start_at < e.end_at && end_at > e.start_at);
        if overlaps {
            return Err(SalesError::SlotUnavailable);
        }
        drop(store);

        let event = CalendarEvent {
            id: Uuid::new_v4(),
            title,
            attendees,
            start_at,
            end_at,
            meeting_link,
        };
        self.events.write().push(event.clone());
        Ok(event)
    }

    /// List events whose start falls within the given date range.
    pub fn list_events(
        &self,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Vec<CalendarEvent> {
        self.events
            .read()
            .iter()
            .filter(|e| e.start_at >= from && e.start_at < to)
            .cloned()
            .collect()
    }

    /// Find available 30-minute slots on the given date (UTC).
    pub fn find_available_slots(&self, date: DateTime<Utc>) -> Vec<(DateTime<Utc>, DateTime<Utc>)> {
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

        let store = self.events.read();
        let mut slots = Vec::new();
        let mut cursor = day_start;

        while cursor + Duration::minutes(SLOT_MINUTES) <= day_end {
            let slot_end = cursor + Duration::minutes(SLOT_MINUTES);
            let conflict = store
                .iter()
                .any(|e| cursor < e.end_at && slot_end > e.start_at);
            if !conflict {
                slots.push((cursor, slot_end));
            }
            cursor = slot_end;
        }
        slots
    }

    /// Cancel (remove) an event by id.
    pub fn cancel_event(&self, id: Uuid) -> Result<(), SalesError> {
        let mut store = self.events.write();
        let idx = store
            .iter()
            .position(|e| e.id == id)
            .ok_or(SalesError::EventNotFound(id))?;
        store.remove(idx);
        Ok(())
    }

    /// Returns `true` if the timestamp is within working hours (09–17 UTC).
    fn is_within_working_hours(dt: DateTime<Utc>) -> bool {
        let hour = dt.hour();
        let weekday = dt.weekday();
        matches!(weekday, chrono::Weekday::Mon | chrono::Weekday::Tue | chrono::Weekday::Wed | chrono::Weekday::Thu | chrono::Weekday::Fri)
            && hour >= WORK_START_HOUR
            && hour < WORK_END_HOUR
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDate;

    fn date(y: i32, m: u32, d: u32, h: u32, min: u32) -> DateTime<Utc> {
        NaiveDate::from_ymd_opt(y, m, d)
            .unwrap()
            .and_hms_opt(h, min, 0)
            .unwrap()
            .and_utc()
    }

    #[test]
    fn test_create_and_list_events() {
        let svc = CalendarService::new();
        let start = date(2026, 3, 2, 10, 0);
        let end = date(2026, 3, 2, 10, 30);
        let evt = svc
            .create_event("Demo".into(), vec!["alice@x.com".into()], start, end, None)
            .unwrap();
        assert_eq!(evt.title, "Demo");

        let events = svc.list_events(date(2026, 3, 2, 0, 0), date(2026, 3, 3, 0, 0));
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn test_overlap_rejection_and_cancel() {
        let svc = CalendarService::new();
        let s1 = date(2026, 3, 2, 10, 0);
        let e1 = date(2026, 3, 2, 10, 30);
        let evt = svc
            .create_event("A".into(), vec![], s1, e1, None)
            .unwrap();

        // overlapping slot should fail
        let res = svc.create_event("B".into(), vec![], s1, e1, None);
        assert!(res.is_err());

        // cancel, then same slot should succeed
        svc.cancel_event(evt.id).unwrap();
        let res2 = svc.create_event("C".into(), vec![], s1, e1, None);
        assert!(res2.is_ok());
    }

    #[test]
    fn test_find_available_slots() {
        let svc = CalendarService::new();
        let day = date(2026, 3, 2, 12, 0);

        // empty day → 16 half-hour slots (09:00–17:00)
        let slots = svc.find_available_slots(day);
        assert_eq!(slots.len(), 16);

        // book one slot → 15 available
        let (s, e) = slots[0];
        svc.create_event("X".into(), vec![], s, e, None).unwrap();
        let slots2 = svc.find_available_slots(day);
        assert_eq!(slots2.len(), 15);
    }
}
