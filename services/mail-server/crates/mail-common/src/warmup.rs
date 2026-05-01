//! Canonical dedicated-IP warmup schedule shared across services.

pub const FULL_WARMUP_DAYS: u32 = 60;

/// Get the daily send limit for a given warmup day.
pub fn limit_for_day(day: u32) -> u64 {
    match day {
        0..=1 => 50,
        2..=3 => 100,
        4..=5 => 250,
        6..=7 => 500,
        8..=10 => 1_000,
        11..=14 => 2_500,
        15..=20 => 5_000,
        21..=28 => 10_000,
        29..=35 => 25_000,
        36..=44 => 50_000,
        45..=49 => 75_000,
        50..=54 => 100_000,
        55..=59 => 250_000,
        _ => u64::MAX,
    }
}

/// Compatibility wrapper for crates that use an associated-constant API.
pub struct WarmupSchedule;

impl WarmupSchedule {
    pub const FULL_WARMUP_DAYS: u32 = FULL_WARMUP_DAYS;

    pub fn limit_for_day(day: u32) -> u64 {
        limit_for_day(day)
    }
}

#[cfg(test)]
mod tests {
    use super::{limit_for_day, WarmupSchedule, FULL_WARMUP_DAYS};

    #[test]
    fn schedule_has_expected_boundary_values() {
        assert_eq!(limit_for_day(0), 50);
        assert_eq!(limit_for_day(2), 100);
        assert_eq!(limit_for_day(4), 250);
        assert_eq!(limit_for_day(6), 500);
        assert_eq!(limit_for_day(8), 1_000);
        assert_eq!(limit_for_day(11), 2_500);
        assert_eq!(limit_for_day(15), 5_000);
        assert_eq!(limit_for_day(21), 10_000);
        assert_eq!(limit_for_day(29), 25_000);
        assert_eq!(limit_for_day(36), 50_000);
        assert_eq!(limit_for_day(45), 75_000);
        assert_eq!(limit_for_day(50), 100_000);
        assert_eq!(limit_for_day(55), 250_000);
        assert_eq!(limit_for_day(FULL_WARMUP_DAYS), u64::MAX);
        assert_eq!(WarmupSchedule::limit_for_day(FULL_WARMUP_DAYS), u64::MAX);
    }

    #[test]
    fn schedule_is_monotonic_until_graduation() {
        let mut previous = 0;

        for day in 0..=FULL_WARMUP_DAYS {
            let current = limit_for_day(day);
            assert!(
                current >= previous,
                "warmup schedule regressed at day {day}: {current} < {previous}"
            );
            previous = current;
        }
    }

    #[test]
    fn schedule_graduates_on_day_60() {
        assert_eq!(FULL_WARMUP_DAYS, 60);
        assert_eq!(WarmupSchedule::FULL_WARMUP_DAYS, 60);
        assert_eq!(limit_for_day(FULL_WARMUP_DAYS - 1), 250_000);
        assert_eq!(limit_for_day(FULL_WARMUP_DAYS), u64::MAX);
    }
}
