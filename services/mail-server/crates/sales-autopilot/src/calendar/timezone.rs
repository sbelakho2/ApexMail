//! IANA timezone resolution for calendar scheduling (audit §29).
//!
//! # Why this module exists
//!
//! The previous calendar implementation did all working-hour arithmetic in
//! UTC and carried a *fixed* UTC offset (`DEFAULT_TIMEZONE_UTC_OFFSET_HOURS:
//! i8 = 2`) that was documented as informational and never applied. A fixed
//! offset is wrong by one hour wherever DST applies (EET +2 / EEST +3), so a
//! "09:00 local" slot on the day after a transition pointed at the wrong UTC
//! instant. This module resolves wall-clock times through the **IANA
//! timezone database** (`chrono-tz`) so the offset used is the one in force
//! for the requested date.
//!
//! # Policy for impossible wall-clock times (documented, asserted by tests)
//!
//! * **Nonexistent** local time (spring-forward gap, e.g. `Europe/Berlin`
//!   2031-03-30 02:30): the candidate slot is **skipped**. The scheduler must
//!   never fabricate a UTC instant for a wall-clock time that does not exist.
//! * **Ambiguous** local time (fall-back overlap, e.g. `Europe/Berlin`
//!   2031-10-26 02:30 occurs twice): the **earliest** UTC instant is chosen
//!   (the first pass, on the pre-transition offset). This is deterministic and
//!   matches how calendars typically display the first occurrence; callers
//!   that need the second occurrence must construct a UTC instant explicitly.

use chrono::{DateTime, Duration, NaiveDate, NaiveDateTime, TimeZone, Utc};
use chrono_tz::Tz;

/// The calendar default zone for ApexMail sales scheduling. The repo's
/// primary deployment is Estonian (`apexmail.ee`), so this is a defensible
/// non-UTC default; it is overridable with `SALES_CALENDAR_TIMEZONE`.
pub const DEFAULT_CALENDAR_TIMEZONE: &str = "Europe/Tallinn";

/// Resolution of a local wall-clock time in a given IANA zone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalResolution {
    /// Exactly one UTC instant corresponds to this wall-clock time.
    Unique(DateTime<Tz>),
    /// The wall-clock time occurs twice (fall-back). Both instants are
    /// returned in chronological order.
    Ambiguous {
        earliest: DateTime<Tz>,
        latest: DateTime<Tz>,
    },
    /// The wall-clock time does not exist (spring-forward gap).
    Nonexistent,
}

impl LocalResolution {
    /// The resolved instant, applying the documented policy: ambiguous →
    /// earliest occurrence; nonexistent → `None`.
    pub fn pick(self) -> Option<DateTime<Tz>> {
        match self {
            Self::Unique(dt) => Some(dt),
            Self::Ambiguous { earliest, .. } => Some(earliest),
            Self::Nonexistent => None,
        }
    }
}

/// Resolve a naive local wall-clock time in `tz` using the IANA database.
pub fn resolve_local_datetime(tz: Tz, local: NaiveDateTime) -> LocalResolution {
    use chrono::LocalResult;
    match tz.from_local_datetime(&local) {
        LocalResult::Single(dt) => LocalResolution::Unique(dt),
        LocalResult::Ambiguous(a, b) => {
            if a <= b {
                LocalResolution::Ambiguous {
                    earliest: a,
                    latest: b,
                }
            } else {
                LocalResolution::Ambiguous {
                    earliest: b,
                    latest: a,
                }
            }
        }
        LocalResult::None => LocalResolution::Nonexistent,
    }
}

/// Resolve a local wall-clock time to a UTC instant under the documented
/// policy (earliest for ambiguous, `None` for nonexistent).
pub fn resolve_local_to_utc(tz: Tz, local: NaiveDateTime) -> Option<DateTime<Utc>> {
    resolve_local_datetime(tz, local)
        .pick()
        .map(|dt| dt.with_timezone(&Utc))
}

/// The UTC interval `[start, end)` covering the local calendar day `date`.
///
/// Some zones transition at midnight (e.g. `America/Santiago`), which makes
/// 00:00 nonexistent on the transition date; in that case the day start is
/// normalised forward to the first existing local minute (documented
/// behaviour — no invalid instant is ever produced).
pub fn local_day_bounds(tz: Tz, date: NaiveDate) -> Option<(DateTime<Utc>, DateTime<Utc>)> {
    let start = resolve_day_boundary(tz, date)?;
    let end = resolve_day_boundary(tz, date.succ_opt()?)?;
    Some((start, end))
}

fn resolve_day_boundary(tz: Tz, date: NaiveDate) -> Option<DateTime<Utc>> {
    // Normalise forward up to 3 hours: the largest real-world DST shift is
    // 1 hour, so this covers every tzdb transition while remaining bounded.
    for add_minutes in 0..=180 {
        let naive = date.and_hms_opt(0, 0, 0)? + Duration::minutes(add_minutes);
        if let Some(dt) = resolve_local_to_utc(tz, naive) {
            return Some(dt);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Recipient timezone inference (audit §29: "infer from context")
// ---------------------------------------------------------------------------

/// Country (ISO 3166-1 alpha-2) → IANA zone, restricted to countries that
/// have a single zone. Countries with multiple zones are deliberately absent:
/// see [`infer_recipient_timezone`].
const COUNTRY_ZONES: &[(&str, &str)] = &[
    ("EE", "Europe/Tallinn"),
    ("FI", "Europe/Helsinki"),
    ("LV", "Europe/Riga"),
    ("LT", "Europe/Vilnius"),
    ("SE", "Europe/Stockholm"),
    ("NO", "Europe/Oslo"),
    ("DK", "Europe/Copenhagen"),
    ("DE", "Europe/Berlin"),
    ("FR", "Europe/Paris"),
    ("NL", "Europe/Amsterdam"),
    ("BE", "Europe/Brussels"),
    ("AT", "Europe/Vienna"),
    ("CH", "Europe/Zurich"),
    ("IE", "Europe/Dublin"),
    ("GB", "Europe/London"),
    ("PT", "Europe/Lisbon"),
    ("PL", "Europe/Warsaw"),
    ("CZ", "Europe/Prague"),
    ("SK", "Europe/Bratislava"),
    ("HU", "Europe/Budapest"),
    ("RO", "Europe/Bucharest"),
    ("BG", "Europe/Sofia"),
    ("GR", "Europe/Athens"),
    ("HR", "Europe/Zagreb"),
    ("SI", "Europe/Ljubljana"),
    ("IT", "Europe/Rome"),
    ("ES", "Europe/Madrid"),
    ("JP", "Asia/Tokyo"),
    ("KR", "Asia/Seoul"),
    ("SG", "Asia/Singapore"),
    ("HK", "Asia/Hong_Kong"),
    ("IN", "Asia/Kolkata"),
    ("IL", "Asia/Jerusalem"),
    ("TR", "Europe/Istanbul"),
    ("AE", "Asia/Dubai"),
    ("TH", "Asia/Bangkok"),
    ("VN", "Asia/Ho_Chi_Minh"),
    ("PH", "Asia/Manila"),
    ("NZ", "Pacific/Auckland"),
    ("EG", "Africa/Cairo"),
    ("ZA", "Africa/Johannesburg"),
    ("NG", "Africa/Lagos"),
    ("KE", "Africa/Nairobi"),
];

/// Language (ISO 639-1, region stripped) → IANA zone for languages whose
/// speakers are overwhelmingly in a single zone. `en`, `es`, `pt`, `ar`, etc.
/// are intentionally absent: they span many zones and guessing would produce
/// wrong local times.
const LANGUAGE_ZONES: &[(&str, &str)] = &[
    ("et", "Europe/Tallinn"),
    ("fi", "Europe/Helsinki"),
    ("lv", "Europe/Riga"),
    ("lt", "Europe/Vilnius"),
    ("sv", "Europe/Stockholm"),
    ("nb", "Europe/Oslo"),
    ("nn", "Europe/Oslo"),
    ("da", "Europe/Copenhagen"),
    ("de", "Europe/Berlin"),
    ("fr", "Europe/Paris"),
    ("nl", "Europe/Amsterdam"),
    ("ja", "Asia/Tokyo"),
    ("ko", "Asia/Seoul"),
    ("th", "Asia/Bangkok"),
    ("vi", "Asia/Ho_Chi_Minh"),
];

/// Infer the recipient's timezone from whatever context the reply engine has.
///
/// Precedence (first hit wins):
/// 1. `existing` — an explicit IANA zone already on the contact
///    (`sales_contacts.timezone`, migration
///    `200_sales_autopilot_v2_unification.sql:260`). Fixed-offset
///    expressions (`+02:00`, `UTC+2`) and free text are **rejected**, not
///    coerced: a fixed offset cannot represent DST. (tzdb zone names such as
///    `UTC` and `EET` do parse — they are zones, not offsets.)
/// 2. `country` — ISO 3166-1 alpha-2 mapping, but **only for single-zone
///    countries**. Multi-zone countries (US, CA, AU, BR, RU, CN, …) return
///    `None`: with no further evidence, picking e.g. `America/New_York` for
///    "US" would be wrong for a large share of recipients, and a wrong local
///    meeting time is worse than asking. `None` is the defensible default.
/// 3. `language` — ISO 639-1 mapping, only for languages concentrated in a
///    single zone; `en`/`es`/`pt`/`ar` return `None`.
///
/// Returns `None` when there is no usable evidence — never a guess.
pub fn infer_recipient_timezone(
    country: Option<&str>,
    language: Option<&str>,
    existing: Option<&str>,
) -> Option<Tz> {
    if let Some(explicit) = existing.and_then(parse_iana_zone) {
        return Some(explicit);
    }
    if let Some(tz) = country
        .map(str::trim)
        .filter(|c| !c.is_empty())
        .and_then(|c| lookup_zone(COUNTRY_ZONES, &c.to_ascii_uppercase()))
    {
        return Some(tz);
    }
    if let Some(tz) = language
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(|l| {
            // Strip the region subtag: "en-US" → "en", "pt_BR" → "pt".
            l.split(['-', '_']).next().unwrap_or(l).to_ascii_lowercase()
        })
        .filter(|l| !l.is_empty())
        .and_then(|l| lookup_zone(LANGUAGE_ZONES, &l))
    {
        return Some(tz);
    }
    None
}

fn lookup_zone(table: &[(&str, &str)], key: &str) -> Option<Tz> {
    table
        .iter()
        .find(|(k, _)| *k == key)
        .and_then(|(_, name)| parse_iana_zone(name))
}

/// Parse an IANA tzdb zone name. Fixed-offset expressions are rejected by
/// `chrono_tz`'s parser (`"+02:00"`, `"UTC+2"` → `None`); `"UTC"` is a valid
/// tzdb zone.
pub fn parse_iana_zone(name: &str) -> Option<Tz> {
    name.trim().parse::<Tz>().ok()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn naive(y: i32, m: u32, d: u32, h: u32, min: u32) -> NaiveDateTime {
        NaiveDate::from_ymd_opt(y, m, d)
            .and_then(|date| date.and_hms_opt(h, min, 0))
            .expect("valid test date")
    }

    fn utc(dt: DateTime<Tz>) -> DateTime<Utc> {
        dt.with_timezone(&Utc)
    }

    // ── DST proofs ──────────────────────────────────────────────────────

    #[test]
    fn berlin_spring_forward_uses_post_transition_offset() {
        let tz = chrono_tz::Europe::Berlin;
        // 2031-03-30 is the last Sunday of March: 02:00 CET jumps to 03:00 CEST.
        // 01:30 exists at +01:00 → 00:30 UTC.
        let before = utc(resolve_local_datetime(tz, naive(2031, 3, 30, 1, 30))
            .pick()
            .unwrap());
        assert_eq!(before, Utc.with_ymd_and_hms(2031, 3, 30, 0, 30, 0).unwrap());
        // 03:30 exists at +02:00 → 01:30 UTC.
        let after = utc(resolve_local_datetime(tz, naive(2031, 3, 30, 3, 30))
            .pick()
            .unwrap());
        assert_eq!(after, Utc.with_ymd_and_hms(2031, 3, 30, 1, 30, 0).unwrap());
        // A fixed +02:00 offset (the "today is CEST" trap) computes 23:30
        // UTC for the 01:30 wall time — one hour wrong.
        let fixed = Utc.with_ymd_and_hms(2031, 3, 30, 0, 30, 0).unwrap() - Duration::hours(1);
        assert_ne!(
            before, fixed,
            "the pre-transition instant must not match a fixed +02:00 computation"
        );
    }

    #[test]
    fn berlin_fall_back_uses_post_transition_offset() {
        let tz = chrono_tz::Europe::Berlin;
        // 2031-10-26 is the last Sunday of October: 03:00 CEST falls back to
        // 02:00 CET. 01:30 still exists once (CEST, +02:00) → 23:30 UTC on
        // 2031-10-25; 03:30 exists at +01:00 → 02:30 UTC.
        let before = utc(resolve_local_datetime(tz, naive(2031, 10, 26, 1, 30))
            .pick()
            .unwrap());
        assert_eq!(
            before,
            Utc.with_ymd_and_hms(2031, 10, 25, 23, 30, 0).unwrap()
        );
        let after = utc(resolve_local_datetime(tz, naive(2031, 10, 26, 3, 30))
            .pick()
            .unwrap());
        assert_eq!(after, Utc.with_ymd_and_hms(2031, 10, 26, 2, 30, 0).unwrap());
    }

    #[test]
    fn berlin_winter_and_summer_offsets_differ() {
        let tz = chrono_tz::Europe::Berlin;
        // 2031-01-13 (Monday) 09:00 CET (+01:00) → 08:00 UTC.
        let winter = resolve_local_to_utc(tz, naive(2031, 1, 13, 9, 0)).unwrap();
        assert_eq!(winter, Utc.with_ymd_and_hms(2031, 1, 13, 8, 0, 0).unwrap());
        // 2031-07-14 (Monday) 09:00 CEST (+02:00) → 07:00 UTC.
        let summer = resolve_local_to_utc(tz, naive(2031, 7, 14, 9, 0)).unwrap();
        assert_eq!(summer, Utc.with_ymd_and_hms(2031, 7, 14, 7, 0, 0).unwrap());
        // A naive fixed +02:00 (summer offset) applied to the winter date is
        // 07:00 UTC — the bug this module exists to prevent.
        let fixed_summer = Utc.with_ymd_and_hms(2031, 1, 13, 7, 0, 0).unwrap();
        assert_ne!(
            winter, fixed_summer,
            "winter slot must not use the summer offset"
        );
        // ...and vice versa.
        let fixed_winter = Utc.with_ymd_and_hms(2031, 7, 14, 8, 0, 0).unwrap();
        assert_ne!(
            summer, fixed_winter,
            "summer slot must not use the winter offset"
        );
    }

    #[test]
    fn new_york_dst_transitions() {
        let tz = chrono_tz::America::New_York;
        // 2031-01-13 09:00 EST (-05:00) → 14:00 UTC.
        assert_eq!(
            resolve_local_to_utc(tz, naive(2031, 1, 13, 9, 0)).unwrap(),
            Utc.with_ymd_and_hms(2031, 1, 13, 14, 0, 0).unwrap()
        );
        // 2031-07-14 09:00 EDT (-04:00) → 13:00 UTC.
        assert_eq!(
            resolve_local_to_utc(tz, naive(2031, 7, 14, 9, 0)).unwrap(),
            Utc.with_ymd_and_hms(2031, 7, 14, 13, 0, 0).unwrap()
        );
        // Spring forward 2031-03-09: 02:30 does not exist (02:00 EST → 03:00 EDT).
        assert_eq!(
            resolve_local_datetime(tz, naive(2031, 3, 9, 2, 30)),
            LocalResolution::Nonexistent
        );
        // Fall back 2031-11-02: 01:30 occurs twice (EDT -04:00, then EST -05:00).
        match resolve_local_datetime(tz, naive(2031, 11, 2, 1, 30)) {
            LocalResolution::Ambiguous { earliest, latest } => {
                assert_eq!(
                    utc(earliest),
                    Utc.with_ymd_and_hms(2031, 11, 2, 5, 30, 0).unwrap()
                );
                assert_eq!(
                    utc(latest),
                    Utc.with_ymd_and_hms(2031, 11, 2, 6, 30, 0).unwrap()
                );
            }
            other => panic!("expected an ambiguous local time, got {other:?}"),
        }
    }

    #[test]
    fn tokyo_has_no_dst() {
        use chrono::Datelike;
        let tz = chrono_tz::Asia::Tokyo;
        for date in [naive(2031, 1, 13, 9, 0), naive(2031, 7, 14, 9, 0)] {
            assert_eq!(
                resolve_local_to_utc(tz, date).unwrap(),
                Utc.with_ymd_and_hms(date.year(), date.month(), date.day(), 0, 0, 0)
                    .unwrap(),
                "Asia/Tokyo is UTC+09:00 year-round"
            );
        }
    }

    #[test]
    fn kolkata_half_hour_offset() {
        use chrono::{Datelike, Timelike};
        let tz = chrono_tz::Asia::Kolkata;
        for date in [naive(2031, 1, 13, 9, 0), naive(2031, 7, 14, 9, 0)] {
            let instant = resolve_local_to_utc(tz, date).unwrap();
            assert_eq!(instant.hour(), 3, "09:00 IST is 03:30 UTC");
            assert_eq!(instant.minute(), 30);
            assert_eq!(instant.day(), date.day());
        }
    }

    #[test]
    fn nonexistent_and_ambiguous_local_times_are_not_invalid_instants() {
        let berlin = chrono_tz::Europe::Berlin;
        // 2031-03-30 02:30 does not exist.
        assert_eq!(
            resolve_local_datetime(berlin, naive(2031, 3, 30, 2, 30)),
            LocalResolution::Nonexistent
        );
        assert_eq!(
            resolve_local_to_utc(berlin, naive(2031, 3, 30, 2, 30)),
            None
        );
        // 2031-10-26 02:30 occurs twice; the documented policy picks the
        // earliest occurrence (CEST +02:00 → 00:30 UTC).
        match resolve_local_datetime(berlin, naive(2031, 10, 26, 2, 30)) {
            LocalResolution::Ambiguous { earliest, latest } => {
                assert_eq!(
                    utc(earliest),
                    Utc.with_ymd_and_hms(2031, 10, 26, 0, 30, 0).unwrap()
                );
                assert_eq!(
                    utc(latest),
                    Utc.with_ymd_and_hms(2031, 10, 26, 1, 30, 0).unwrap()
                );
                assert_eq!(
                    resolve_local_to_utc(berlin, naive(2031, 10, 26, 2, 30)).unwrap(),
                    utc(earliest)
                );
            }
            other => panic!("expected an ambiguous local time, got {other:?}"),
        }
    }

    #[test]
    fn local_day_bounds_across_transitions() {
        // Spring forward: 2031-03-30 in Berlin is 23 hours long.
        let (start, end) = local_day_bounds(
            chrono_tz::Europe::Berlin,
            NaiveDate::from_ymd_opt(2031, 3, 30).unwrap(),
        )
        .unwrap();
        assert_eq!(start, Utc.with_ymd_and_hms(2031, 3, 29, 23, 0, 0).unwrap());
        assert_eq!(end, Utc.with_ymd_and_hms(2031, 3, 30, 22, 0, 0).unwrap());
        assert_eq!(end - start, Duration::hours(23));
        // Fall back: 2031-10-26 in Berlin is 25 hours long.
        let (start, end) = local_day_bounds(
            chrono_tz::Europe::Berlin,
            NaiveDate::from_ymd_opt(2031, 10, 26).unwrap(),
        )
        .unwrap();
        assert_eq!(end - start, Duration::hours(25));
    }

    // ── Zone inference ──────────────────────────────────────────────────

    #[test]
    fn inference_prefers_explicit_iana_zone() {
        assert_eq!(
            infer_recipient_timezone(Some("DE"), Some("de"), Some("America/New_York")),
            Some(chrono_tz::America::New_York)
        );
    }

    #[test]
    fn inference_rejects_non_iana_existing_values() {
        // `UTC` and `EET` are real tzdb zone names and parse; fixed offset
        // expressions and free text must not.
        for bogus in ["+02:00", "UTC+2", "GMT+3", "not a zone", ""] {
            let inferred = infer_recipient_timezone(Some("EE"), None, Some(bogus));
            assert_eq!(
                inferred,
                Some(chrono_tz::Europe::Tallinn),
                "{bogus:?} must be rejected and inference must fall through to the country"
            );
        }
    }

    #[test]
    fn inference_country_then_language_then_none() {
        assert_eq!(
            infer_recipient_timezone(Some("jp"), None, None),
            Some(chrono_tz::Asia::Tokyo)
        );
        assert_eq!(
            infer_recipient_timezone(None, Some("ja-JP"), None),
            Some(chrono_tz::Asia::Tokyo)
        );
        assert_eq!(infer_recipient_timezone(None, None, None), None);
        assert_eq!(infer_recipient_timezone(Some("ZZ"), None, None), None);
    }

    #[test]
    fn multi_zone_country_returns_none() {
        // Documented decision: for countries spanning multiple zones (US, CA,
        // AU, BR, RU, …) there is no defensible single default — a wrong
        // local time is worse than returning None and asking.
        for country in ["US", "CA", "AU", "BR", "RU", "CN", "MX", "ID"] {
            assert_eq!(
                infer_recipient_timezone(Some(country), None, None),
                None,
                "{country} spans multiple zones and must not be guessed"
            );
        }
    }

    #[test]
    fn broad_languages_return_none() {
        for language in ["en", "es", "pt", "ar", "zh"] {
            assert_eq!(
                infer_recipient_timezone(None, Some(language), None),
                None,
                "{language} spans multiple zones and must not be guessed"
            );
        }
    }

    #[test]
    fn parse_iana_zone_rejects_fixed_offsets() {
        assert!(parse_iana_zone("Europe/Tallinn").is_some());
        assert!(parse_iana_zone("Asia/Kolkata").is_some());
        assert!(parse_iana_zone("+02:00").is_none());
        assert!(parse_iana_zone("UTC").is_some()); // UTC is a valid tzdb zone
        assert!(parse_iana_zone("").is_none());
    }

    #[test]
    fn hostile_inputs_do_not_panic() {
        // Very long strings, control characters, unicode.
        let long = "x".repeat(100_000);
        assert_eq!(
            infer_recipient_timezone(Some(&long), Some(&long), Some(&long)),
            None
        );
        assert_eq!(
            infer_recipient_timezone(Some("EE\x00"), Some("et\n"), Some("Europe/Tallinn\n")),
            Some(chrono_tz::Europe::Tallinn)
        );
        assert_eq!(infer_recipient_timezone(None, Some("--"), None), None);
        assert_eq!(infer_recipient_timezone(None, Some("-"), None), None);
        // A non-IANA timezone string is rejected at every level, never
        // coerced and never panicked on.
        assert_eq!(
            infer_recipient_timezone(Some("Not/AZone"), Some("Not/AZone"), Some("Not/AZone")),
            None
        );
        assert!(parse_iana_zone("Not/AZone").is_none());
        assert!(parse_iana_zone("Europe/Tallinn/Extra").is_none());
        assert!(parse_iana_zone("../etc/passwd").is_none());
        assert!(parse_iana_zone("Europe\\Tallinn").is_none());
    }
}
