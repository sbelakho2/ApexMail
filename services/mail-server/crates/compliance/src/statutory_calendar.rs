//! One versioned Estonian statutory/business calendar, shared by every
//! filing obligation (KMD, TSD, VD, OSS and the annual report).
//!
//! # Why this exists
//!
//! Before this module `estonia_ou::ComplianceCalendar::calculate_due_date`
//! returned raw calendar dates (the 20th, the 10th, June 30, …) with no
//! concept of a public holiday. A deadline that fell on a public holiday or a
//! weekend was therefore reported as due on a day on which the authority is
//! closed. Estonian law moves such a deadline to the next working day.
//!
//! # Calendar versioning
//!
//! The rule set is versioned, not the individual dates:
//!
//! * [`ESTONIA_CALENDAR_VERSION`] = `EE-2025.1`, mirrored (with the rule
//!   payload) in the `statutory_calendars` table (migration 221). Derived
//!   obligations record the version that produced their due date, so a later
//!   rule revision never silently rewrites dated history.
//! * Holidays are computed for any year from the fixed-date list plus the
//!   Gregorian Easter computus, so no per-year table has to be maintained.
//!
//! # The one shared function
//!
//! [`statutory_due_date`] is the single entry point: given the date the law
//! states, it returns that date when it is a working day, otherwise the next
//! working day (skipping weekends and public holidays, including chains such
//! as 24–26 December).
//!
//! Public holidays covered (`riigipühad`): 1 January (New Year), 24 February
//! (Independence Day), Good Friday, Easter Sunday, 1 May (Spring Day), 23
//! June (Victory Day), 24 June (Midsummer Day), 20 August (Day of
//! Restoration of Independence), 24–26 December (Christmas), plus Pentecost
//! (Whit Sunday), which is a public holiday in Estonia.

#![deny(unsafe_code)]

use chrono::{Datelike, Duration, NaiveDate, Weekday};

/// Version of the Estonian holiday/working-day rule set implemented here.
///
/// Must match a row in `statutory_calendars` (migration 221); obligations
/// store this string as their `calendar_version`.
pub const ESTONIA_CALENDAR_VERSION: &str = "EE-2025.1";

/// Jurisdiction code for the calendar.
pub const ESTONIA_JURISDICTION: &str = "EE";

/// One public holiday in the calendar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicHoliday {
    pub date: NaiveDate,
    pub name: &'static str,
}

/// The Estonian statutory calendar (rule version [`ESTONIA_CALENDAR_VERSION`]).
#[derive(Debug, Clone, Copy, Default)]
pub struct EstoniaHolidayCalendar;

impl EstoniaHolidayCalendar {
    pub const fn new() -> Self {
        Self
    }

    /// The rule-set version this calendar implements.
    pub const fn version(&self) -> &'static str {
        ESTONIA_CALENDAR_VERSION
    }

    /// Every public holiday in `year`, ordered by date.
    pub fn holidays(&self, year: i32) -> Vec<PublicHoliday> {
        let mut holidays: Vec<PublicHoliday> = Vec::with_capacity(12);

        let mut push = |month: u32, day: u32, name: &'static str| {
            if let Some(date) = NaiveDate::from_ymd_opt(year, month, day) {
                holidays.push(PublicHoliday { date, name });
            }
        };

        // Fixed-date public holidays (riigipühad).
        push(1, 1, "uusaasta");
        push(2, 24, "iseseisvuspäev");
        push(5, 1, "kevadpüha");
        push(6, 23, "võidupüha");
        push(6, 24, "jaanipäev");
        push(8, 20, "taasiseseisvumispäev");
        push(12, 24, "jõululaupäev");
        push(12, 25, "esimene jõulupüha");
        push(12, 26, "teine jõulupüha");

        // Easter-derived holidays.
        if let Some(easter) = easter_sunday(year) {
            let good_friday = easter - Duration::days(2);
            let pentecost = easter + Duration::days(49);
            holidays.push(PublicHoliday {
                date: good_friday,
                name: "suur reede",
            });
            holidays.push(PublicHoliday {
                date: easter,
                name: "ülestõusmispühade 1. püha",
            });
            holidays.push(PublicHoliday {
                date: pentecost,
                name: "nelipühade 1. püha",
            });
        }

        holidays.sort_by_key(|holiday| holiday.date);
        holidays
    }

    /// Is `date` a public holiday?
    pub fn is_public_holiday(&self, date: NaiveDate) -> bool {
        self.holidays(date.year())
            .iter()
            .any(|holiday| holiday.date == date)
    }

    /// Is `date` a weekend (Saturday or Sunday)?
    pub fn is_weekend(&self, date: NaiveDate) -> bool {
        matches!(date.weekday(), Weekday::Sat | Weekday::Sun)
    }

    /// Is `date` a working day (not a weekend, not a public holiday)?
    pub fn is_working_day(&self, date: NaiveDate) -> bool {
        !self.is_weekend(date) && !self.is_public_holiday(date)
    }

    /// The next working day on or after `date` (identity when `date` is a
    /// working day). Saturates rather than looping forever at the representable
    /// date boundary.
    pub fn next_working_day(&self, date: NaiveDate) -> NaiveDate {
        let mut candidate = date;
        for _ in 0..=366 {
            if self.is_working_day(candidate) {
                return candidate;
            }
            match candidate.checked_add_signed(Duration::days(1)) {
                Some(next) => candidate = next,
                None => return candidate,
            }
        }
        candidate
    }
}

/// The single shared deadline function: a statutory due date that falls on a
/// public holiday or weekend moves to the next working day.
///
/// KMD, TSD, VD, OSS and annual-report obligations all route their legal due
/// date through this function.
pub fn statutory_due_date(legal_due_date: NaiveDate) -> NaiveDate {
    EstoniaHolidayCalendar::new().next_working_day(legal_due_date)
}

/// `statutory_due_date` with an explicit calendar (useful for tests pinning a
/// specific rule version).
pub fn statutory_due_date_with(
    calendar: &EstoniaHolidayCalendar,
    legal_due_date: NaiveDate,
) -> NaiveDate {
    calendar.next_working_day(legal_due_date)
}

/// Anonymous Gregorian computus: the date of Easter Sunday for `year`
/// (Western/Gregorian Easter, as observed in Estonia).
pub fn easter_sunday(year: i32) -> Option<NaiveDate> {
    // Meeus/Jones/Butcher algorithm.
    let a = year % 19;
    let b = year / 100;
    let c = year % 100;
    let d = b / 4;
    let e = b % 4;
    let f = (b + 8) / 25;
    let g = (b - f + 1) / 3;
    let h = (19 * a + b - d - g + 15) % 30;
    let i = c / 4;
    let k = c % 4;
    let l = (32 + 2 * e + 2 * i - h - k) % 7;
    let m = (a + 11 * h + 22 * l) / 451;
    let month = (h + l - 7 * m + 114) / 31;
    let day = ((h + l - 7 * m + 114) % 31) + 1;
    NaiveDate::from_ymd_opt(year, month as u32, day as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(year: i32, month: u32, day: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(year, month, day).expect("test date")
    }

    // ── Easter computus (known Gregorian Easter Sundays) ───────────────

    #[test]
    fn easter_sunday_matches_known_years() {
        let known = [
            (2024, 3, 31),
            (2025, 4, 20),
            (2026, 4, 5),
            (2027, 3, 28),
            (2028, 4, 16),
            (2030, 4, 21),
        ];
        for (year, month, day) in known {
            assert_eq!(
                easter_sunday(year),
                Some(d(year, month, day)),
                "Easter {year}"
            );
        }
    }

    #[test]
    fn fixed_holidays_are_present() {
        let calendar = EstoniaHolidayCalendar::new();
        for (month, day) in [
            (1, 1),
            (2, 24),
            (5, 1),
            (6, 23),
            (6, 24),
            (8, 20),
            (12, 24),
            (12, 25),
            (12, 26),
        ] {
            assert!(
                calendar.is_public_holiday(d(2026, month, day)),
                "expected public holiday 2026-{month:02}-{day:02}"
            );
        }
        assert_eq!(
            calendar.holidays(2026).len(),
            12,
            "nine fixed + three Easter-derived holidays"
        );
    }

    // ── Working-day rule, table-driven over real Estonian holidays ─────

    #[test]
    fn statutory_due_date_moves_holidays_to_next_working_day() {
        // (legal due date, expected effective date, why)
        let cases: &[(NaiveDate, NaiveDate, &str)] = &[
            // A normal Friday stays put.
            (d(2026, 2, 20), d(2026, 2, 20), "ordinary Friday"),
            // Saturday moves to Monday.
            (d(2026, 6, 20), d(2026, 6, 22), "Saturday"),
            // Sunday moves to Monday.
            (d(2026, 6, 21), d(2026, 6, 22), "Sunday"),
            // Independence Day (Tuesday) -> Wednesday.
            (d(2026, 2, 24), d(2026, 2, 25), "iseseisvuspäev"),
            // Victory Day + Midsummer (Tue/Wed 23–24 June 2026).
            (
                d(2026, 6, 23),
                d(2026, 6, 25),
                "võidupüha -> jaanipäev chain",
            ),
            (d(2026, 6, 24), d(2026, 6, 25), "jaanipäev"),
            // Christmas chain 24–26 Dec 2026: Thu/Fri/Sat, plus Sunday ->
            // Monday 28 December.
            (d(2026, 12, 24), d(2026, 12, 28), "Christmas Eve chain"),
            (d(2026, 12, 25), d(2026, 12, 28), "Christmas Day chain"),
            (d(2026, 12, 26), d(2026, 12, 28), "Boxing Day chain"),
            // New Year 2026 (Thursday) -> Friday 2 January.
            (d(2026, 1, 1), d(2026, 1, 2), "uusaasta"),
            // Spring Day 2026 (Friday) -> Monday 4 May.
            (d(2026, 5, 1), d(2026, 5, 4), "kevadpüha"),
            // Restoration of Independence 2026 (Thursday) -> Friday.
            (d(2026, 8, 20), d(2026, 8, 21), "taasiseseisvumispäev"),
            // Good Friday 2026-04-03 -> Monday 6 April (Easter Monday is NOT
            // an Estonian public holiday).
            (d(2026, 4, 3), d(2026, 4, 6), "suur reede"),
            // Pentecost 2026-05-24 is a Sunday -> Monday 25 May.
            (d(2026, 5, 24), d(2026, 5, 25), "nelipühad on Sunday"),
            // Easter Sunday itself -> Monday.
            (d(2026, 4, 5), d(2026, 4, 6), "ülestõusmispüha"),
        ];
        for (legal, expected, why) in cases {
            assert_eq!(statutory_due_date(*legal), *expected, "{why}");
        }
    }

    #[test]
    fn every_public_holiday_in_three_years_is_a_non_working_day() {
        let calendar = EstoniaHolidayCalendar::new();
        for year in [2025, 2026, 2027] {
            for holiday in calendar.holidays(year) {
                assert!(!calendar.is_working_day(holiday.date), "{}", holiday.name);
                assert!(
                    statutory_due_date(holiday.date) > holiday.date,
                    "a holiday deadline must move forward ({})",
                    holiday.name
                );
                assert!(
                    calendar.is_working_day(statutory_due_date(holiday.date)),
                    "moved deadline must land on a working day ({})",
                    holiday.name
                );
            }
        }
    }

    #[test]
    fn version_is_the_migrated_calendar_version() {
        assert_eq!(
            EstoniaHolidayCalendar::new().version(),
            ESTONIA_CALENDAR_VERSION
        );
        assert_eq!(ESTONIA_CALENDAR_VERSION, "EE-2025.1");
        // The migration seeds exactly this version (deploy-time contract).
        let migration = include_str!("../../../migrations/221_statutory_filing_completion.sql");
        assert!(migration.contains("'EE-2025.1'"));
    }

    #[test]
    fn weekend_detection() {
        let calendar = EstoniaHolidayCalendar::new();
        assert!(calendar.is_weekend(d(2026, 1, 3))); // Saturday
        assert!(calendar.is_weekend(d(2026, 1, 4))); // Sunday
        assert!(!calendar.is_weekend(d(2026, 1, 5))); // Monday
    }
}
