//! IP warmup schedule management.
//!
//! Uses an exponential ramp-up curve so that sending volume roughly doubles
//! each day until the target volume is reached.
//!
//! State is persisted to PostgreSQL via the ip_pool_addresses table.

use dashmap::DashMap;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::sync::Arc;

use crate::types::WarmupSchedule;

/// Manages IP warmup schedules with an exponential volume ramp-up.
/// Persists state to database for crash recovery.
#[derive(Debug, Clone)]
pub struct IpWarmupManager {
    db: PgPool,
    /// In-memory cache for fast lookups (write-through to DB).
    schedules: Arc<DashMap<String, WarmupSchedule>>,
}

impl IpWarmupManager {
    pub fn new(db: PgPool) -> Self {
        Self {
            db,
            schedules: Arc::new(DashMap::new()),
        }
    }

    /// Create a manager that keeps schedules in memory without database persistence.
    /// Create an ephemeral instance for testing.
    /// Uses lazy connection so it will not block on startup (O-23.2).
    /// If the connection string is invalid, falls back to a warning log
    /// instead of panicking.
    pub fn new_ephemeral() -> Self {
        let db = PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://localhost:5432/unused")
            .unwrap_or_else(|e| {
                tracing::warn!(
                    error = %e,
                    "Ephemeral pool creation failed; creating fallback pool"
                );
                // Fallback: a syntactically valid URL that will fail at
                // connection time rather than panicking at construction.
                PgPoolOptions::new()
                    .max_connections(1)
                    .connect_lazy("postgres://localhost:5432/postgres")
                    .expect("hardcoded fallback URL is syntactically valid")
            });
        Self {
            db,
            schedules: Arc::new(DashMap::new()),
        }
    }

    /// Create an in-memory-only manager for testing.
    pub fn new_in_memory() -> Self {
        Self::new_ephemeral()
    }

    /// Create a warmup schedule for `ip` targeting `target_volume` over `total_days`.
    /// Persists to database for crash recovery.
    pub async fn create_schedule(
        &self,
        ip: impl Into<String>,
        target_volume: u64,
        total_days: u32,
    ) -> Result<WarmupSchedule, sqlx::Error> {
        let ip = ip.into();
        let current_volume = self.compute_volume(target_volume, 0, total_days);
        let schedule = WarmupSchedule {
            ip: ip.clone(),
            current_volume,
            target_volume,
            day: 0,
            total_days,
        };

        // Persist to database - update existing or insert new
        sqlx::query(
            "INSERT INTO ip_pool_addresses (id, pool_id, ip_address, warmup_enabled, warmup_day, daily_limit, created_at, updated_at)
             VALUES ($1, 'default', $2::inet, true, $3, $4, NOW(), NOW())
             ON CONFLICT (ip_address) DO UPDATE SET
                warmup_day = EXCLUDED.warmup_day,
                daily_limit = EXCLUDED.daily_limit,
                warmup_enabled = true,
                updated_at = NOW()",
        )
        .bind(format!("warmup_{}", ip.replace('.', "_")))
        .bind(&ip)
        .bind(schedule.day as i32)
        .bind(i32::try_from(current_volume).unwrap_or(i32::MAX))
        .execute(&self.db)
        .await?;

        // Update cache
        self.schedules.insert(ip, schedule.clone());
        Ok(schedule)
    }

    /// Create a warmup schedule synchronously.
    ///
    /// ⚠ O-23.3: This is a synchronous shim that performs only in-memory cache
    /// operations — it does NOT block on DB I/O. However, calling it from an
    /// async context may still block the tokio runtime thread. Use
    /// [`create_schedule`](Self::create_schedule) in async code.
    #[cfg(not(loom))]
    pub fn create_schedule_sync(
        &self,
        ip: impl Into<String>,
        target_volume: u64,
        total_days: u32,
    ) -> WarmupSchedule {
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
    /// Returns `None` if no schedule exists for that IP.
    pub fn get_daily_volume(&self, ip: &str, day: u32) -> Option<u64> {
        self.schedules
            .get(ip)
            .map(|s| self.compute_volume(s.target_volume, day.min(s.total_days), s.total_days))
    }

    /// List all registered warmup schedules from cache.
    pub fn list_schedules(&self) -> Vec<WarmupSchedule> {
        self.schedules.iter().map(|e| e.value().clone()).collect()
    }

    /// Load schedules from database into cache.
    pub async fn load_from_db(&self) -> Result<(), sqlx::Error> {
        let rows = sqlx::query_as::<_, (String, i32, Option<i32>)>(
            "SELECT ip_address::text, warmup_day, daily_limit
             FROM ip_pool_addresses WHERE warmup_enabled = true",
        )
        .fetch_all(&self.db)
        .await?;

        for (ip, day, limit) in rows {
            // Estimate total_days and target_volume from current state
            let total_days = 14u32; // default warmup period
            let current_volume = limit.unwrap_or(1) as u64;
            let target_volume =
                Self::estimate_target_volume(current_volume, day as u32, total_days);
            let schedule = WarmupSchedule {
                ip: ip.clone(),
                current_volume,
                target_volume,
                day: day as u32,
                total_days,
            };
            self.schedules.insert(ip, schedule);
        }
        Ok(())
    }

    /// Returns `true` if the warmup for `ip` is complete (current day >= total days).
    pub fn is_warmup_complete(&self, ip: &str) -> bool {
        self.schedules
            .get(ip)
            .map(|s| s.day >= s.total_days)
            .unwrap_or(false)
    }

    /// Advance the schedule for `ip` by one day, updating `current_volume`.
    pub async fn advance_day(&self, ip: &str) -> Result<bool, sqlx::Error> {
        let (new_day, new_volume) = if let Some(entry) = self.schedules.get(ip) {
            let s = entry.value();
            if s.day >= s.total_days {
                return Ok(true);
            }
            let next_day = s.day + 1;
            let next_volume = self.compute_volume(s.target_volume, next_day, s.total_days);
            (next_day, next_volume)
        } else {
            return Ok(false);
        };

        sqlx::query(
            "UPDATE ip_pool_addresses
             SET warmup_day = $2, daily_limit = $3, updated_at = NOW()
             WHERE ip_address = $1::inet",
        )
        .bind(ip)
        .bind(new_day as i32)
        .bind(i32::try_from(new_volume).unwrap_or(i32::MAX))
        .execute(&self.db)
        .await?;

        if let Some(mut entry) = self.schedules.get_mut(ip) {
            let s = entry.value_mut();
            s.day = new_day;
            s.current_volume = new_volume;
        }

        Ok(true)
    }

    /// Advance day synchronously.
    ///
    /// ⚠ O-23.3: Same caveat as [`create_schedule_sync`](Self::create_schedule_sync)
    /// — only performs in-memory cache operations, but may block the tokio
    /// runtime if called from an async context.
    #[cfg(not(loom))]
    pub fn advance_day_sync(&self, ip: &str) -> bool {
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

    /// Exponential ramp-up:`volume = target * (2^day - 1) / (2^total_days - 1)`.
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

    fn estimate_target_volume(current_volume: u64, day: u32, total_days: u32) -> u64 {
        if total_days == 0 || day == 0 {
            return current_volume.max(1);
        }
        let numerator = (2.0_f64).powi(total_days as i32) - 1.0;
        let denominator = (2.0_f64).powi(day as i32) - 1.0;
        if denominator <= 0.0 {
            return current_volume.max(1);
        }
        let target = (current_volume as f64 * numerator / denominator).round() as u64;
        target.max(current_volume.max(1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_schedule() {
        let mgr = IpWarmupManager::new_in_memory();
        let s = mgr.create_schedule_sync("1.2.3.4", 100_000, 14);
        assert_eq!(s.day, 0);
        assert_eq!(s.target_volume, 100_000);
        assert!(s.current_volume >= 1);
        assert!(s.current_volume < 100_000);
    }

    #[tokio::test]
    async fn test_exponential_ramp() {
        let mgr = IpWarmupManager::new_in_memory();
        mgr.create_schedule_sync("10.0.0.1", 50_000, 10);

        let v0 = mgr.get_daily_volume("10.0.0.1", 0).unwrap();
        let v5 = mgr.get_daily_volume("10.0.0.1", 5).unwrap();
        let v10 = mgr.get_daily_volume("10.0.0.1", 10).unwrap();

        assert!(v0 < v5, "day-0 volume should be less than day-5");
        assert!(v5 < v10, "day-5 volume should be less than day-10");
        assert_eq!(v10, 50_000, "final day should reach target");
    }

    #[tokio::test]
    async fn test_warmup_complete() {
        let mgr = IpWarmupManager::new_in_memory();
        mgr.create_schedule_sync("10.0.0.2", 10_000, 3);

        assert!(!mgr.is_warmup_complete("10.0.0.2"));

        mgr.advance_day_sync("10.0.0.2"); // day 1
        mgr.advance_day_sync("10.0.0.2"); // day 2
        mgr.advance_day_sync("10.0.0.2"); // day 3

        assert!(mgr.is_warmup_complete("10.0.0.2"));
    }
}
