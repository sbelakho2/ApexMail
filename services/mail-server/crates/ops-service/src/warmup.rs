//! IP warmup schedule management.
//!
//! Uses an exponential ramp-up curve so that sending volume roughly doubles
//! each day until the target volume is reached.

use dashmap::DashMap;
use std::sync::Arc;

use crate::types::WarmupSchedule;

/// Manages IP warmup schedules with an exponential volume ramp-up.
#[derive(Debug, Clone)]
pub struct IpWarmupManager {
    schedules: Arc<DashMap<String, WarmupSchedule>>,
}

impl IpWarmupManager {
    pub fn new() -> Self {
        Self {
            schedules: Arc::new(DashMap::new()),
        }
    }

    /// Create a warmup schedule for `ip` targeting `target_volume` over `total_days`.
    ///
    /// The schedule starts at day 0 with a small volume and exponentially ramps up.
    pub fn create_schedule(&self, ip: impl Into<String>, target_volume: u64, total_days: u32) -> WarmupSchedule {
        let ip = ip.into();
        let current_volume = self.compute_volume(target_volume, 0, total_days);
        let schedule = WarmupSchedule {
            ip: ip.clone(),
            current_volume,
            target_volume,
            day: 0,
            total_days,
        };
        self.schedules.insert(ip, schedule.clone());
        schedule
    }

    /// Get the daily volume allowance for `ip` on a given `day`.
    ///
    /// Returns `None` if no schedule exists for that IP.
    pub fn get_daily_volume(&self, ip: &str, day: u32) -> Option<u64> {
        self.schedules.get(ip).map(|s| {
            self.compute_volume(s.target_volume, day.min(s.total_days), s.total_days)
        })
    }

    /// List all registered warmup schedules.
    pub fn list_schedules(&self) -> Vec<WarmupSchedule> {
        self.schedules.iter().map(|e| e.value().clone()).collect()
    }

    /// Returns `true` if the warmup for `ip` is complete (current day >= total days).
    pub fn is_warmup_complete(&self, ip: &str) -> bool {
        self.schedules
            .get(ip)
            .map(|s| s.day >= s.total_days)
            .unwrap_or(false)
    }

    /// Advance the schedule for `ip` by one day, updating `current_volume`.
    pub fn advance_day(&self, ip: &str) -> bool {
        if let Some(mut entry) = self.schedules.get_mut(ip) {
            let s = entry.value_mut();
            if s.day < s.total_days {
                s.day += 1;
                s.current_volume = self.compute_volume(s.target_volume, s.day, s.total_days);
            }
            true
        } else {
            false
        }
    }

    /// Exponential ramp-up: `volume = target * (2^day - 1) / (2^total_days - 1)`.
    /// Guarantees at least 1 at day 0 and exactly `target` at `total_days`.
    fn compute_volume(&self, target: u64, day: u32, total_days: u32) -> u64 {
        if total_days == 0 || day >= total_days {
            return target;
        }
        // 2^day and 2^total_days may overflow for large values; use f64.
        let numerator = (2.0_f64).powi(day as i32) - 1.0;
        let denominator = (2.0_f64).powi(total_days as i32) - 1.0;
        let vol = (target as f64 * numerator / denominator).round() as u64;
        vol.max(1) // never send 0
    }
}

impl Default for IpWarmupManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_schedule() {
        let mgr = IpWarmupManager::new();
        let s = mgr.create_schedule("1.2.3.4", 100_000, 14);
        assert_eq!(s.day, 0);
        assert_eq!(s.target_volume, 100_000);
        assert!(s.current_volume >= 1);
        assert!(s.current_volume < 100_000);
    }

    #[test]
    fn test_exponential_ramp() {
        let mgr = IpWarmupManager::new();
        mgr.create_schedule("10.0.0.1", 50_000, 10);

        let v0 = mgr.get_daily_volume("10.0.0.1", 0).unwrap();
        let v5 = mgr.get_daily_volume("10.0.0.1", 5).unwrap();
        let v10 = mgr.get_daily_volume("10.0.0.1", 10).unwrap();

        assert!(v0 < v5, "day-0 volume should be less than day-5");
        assert!(v5 < v10, "day-5 volume should be less than day-10");
        assert_eq!(v10, 50_000, "final day should reach target");
    }

    #[test]
    fn test_warmup_complete() {
        let mgr = IpWarmupManager::new();
        mgr.create_schedule("10.0.0.2", 10_000, 3);

        assert!(!mgr.is_warmup_complete("10.0.0.2"));

        mgr.advance_day("10.0.0.2"); // day 1
        mgr.advance_day("10.0.0.2"); // day 2
        mgr.advance_day("10.0.0.2"); // day 3

        assert!(mgr.is_warmup_complete("10.0.0.2"));
    }
}
