//! ISP warmup repositories — TWO explicit models (F87):
//!
//! * [`WarmupProfileRepo`] — the ISP warmup PROFILE/catalog relation
//!   (`isp_warmup_templates`, migration 042): one row per ISP with MX
//!   patterns and the ordered daily-volume schedule a pool warmup is
//!   instantiated FROM.
//! * [`WarmupExecutionRepo`] — the per-pool/day EXECUTION relation
//!   (`isp_warmup_schedules`, migration 042): one row per (pool_id, day)
//!   with target/actual volume and status, written by the warmup runner.
//!
//! The profile columns are deliberately NOT appended to the execution table
//! (and vice versa): an ISP profile is not a day of a pool's warmup, and a
//! pool day is not an ISP definition.

use sqlx::PgPool;

use crate::types::{IspWarmupExecution, IspWarmupProfile};

/// Repository for the ISP warmup profile catalog (isp_warmup_templates).
pub struct WarmupProfileRepo;

impl WarmupProfileRepo {
    /// Create a new ISP warmup profile.
    pub async fn create(
        pool: &PgPool,
        id: &str,
        isp_name: &str,
        mx_patterns: serde_json::Value,
        warmup_schedule: serde_json::Value,
        notes: Option<&str>,
    ) -> Result<IspWarmupProfile, sqlx::Error> {
        sqlx::query_as::<_, IspWarmupProfile>(
            "INSERT INTO isp_warmup_templates (id, isp_name, mx_patterns, warmup_schedule, notes, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, NOW(), NOW()) \
             RETURNING id, isp_name, mx_patterns, warmup_schedule, notes, created_at, updated_at",
        )
        .bind(id)
        .bind(isp_name)
        .bind(mx_patterns)
        .bind(warmup_schedule)
        .bind(notes)
        .fetch_one(pool)
        .await
    }

    /// Get a warmup profile by ISP name.
    pub async fn get_by_isp(
        pool: &PgPool,
        isp_name: &str,
    ) -> Result<Option<IspWarmupProfile>, sqlx::Error> {
        sqlx::query_as::<_, IspWarmupProfile>(
            "SELECT id, isp_name, mx_patterns, warmup_schedule, notes, created_at, updated_at \
             FROM isp_warmup_templates WHERE isp_name = $1",
        )
        .bind(isp_name)
        .fetch_optional(pool)
        .await
    }

    /// Get a warmup profile by ID.
    pub async fn get_by_id(
        pool: &PgPool,
        id: &str,
    ) -> Result<Option<IspWarmupProfile>, sqlx::Error> {
        sqlx::query_as::<_, IspWarmupProfile>(
            "SELECT id, isp_name, mx_patterns, warmup_schedule, notes, created_at, updated_at \
             FROM isp_warmup_templates WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(pool)
        .await
    }

    /// List all warmup profiles.
    pub async fn list(pool: &PgPool) -> Result<Vec<IspWarmupProfile>, sqlx::Error> {
        sqlx::query_as::<_, IspWarmupProfile>(
            "SELECT id, isp_name, mx_patterns, warmup_schedule, notes, created_at, updated_at \
             FROM isp_warmup_templates ORDER BY isp_name",
        )
        .fetch_all(pool)
        .await
    }

    /// Update a warmup profile's schedule/notes.
    pub async fn update(
        pool: &PgPool,
        id: &str,
        warmup_schedule: serde_json::Value,
        notes: Option<&str>,
    ) -> Result<Option<IspWarmupProfile>, sqlx::Error> {
        sqlx::query_as::<_, IspWarmupProfile>(
            "UPDATE isp_warmup_templates \
             SET warmup_schedule = $2, notes = $3, updated_at = NOW() \
             WHERE id = $1 \
             RETURNING id, isp_name, mx_patterns, warmup_schedule, notes, created_at, updated_at",
        )
        .bind(id)
        .bind(warmup_schedule)
        .bind(notes)
        .fetch_optional(pool)
        .await
    }

    /// Delete a warmup profile.
    pub async fn delete(pool: &PgPool, id: &str) -> Result<bool, sqlx::Error> {
        let result = sqlx::query("DELETE FROM isp_warmup_templates WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Get daily limit for a given day from a profile's schedule.
    /// Returns the limit at the specified day index, or the final limit if
    /// day exceeds schedule length.
    pub fn get_daily_limit(schedule: &serde_json::Value, day: usize) -> Option<u64> {
        schedule.as_array().and_then(|arr| {
            let idx = day.min(arr.len().saturating_sub(1));
            arr.get(idx).and_then(|v| v.as_u64())
        })
    }

    /// Match an MX host against a profile's patterns to find the ISP.
    /// Note:This loads all profiles into memory. For production scale,
    /// consider caching profiles in-memory or adding a database-side pattern match.
    pub async fn find_by_mx_pattern(
        pool: &PgPool,
        mx_host: &str,
    ) -> Result<Option<IspWarmupProfile>, sqlx::Error> {
        // Get all profiles and match patterns
        let profiles = Self::list(pool).await?;
        for profile in profiles {
            if let Some(patterns) = profile.mx_patterns.as_array() {
                for pattern in patterns {
                    if let Some(pat) = pattern.as_str() {
                        if Self::matches_pattern(mx_host, pat) {
                            return Ok(Some(profile));
                        }
                    }
                }
            }
        }
        // Return default profile if no match
        Self::get_by_isp(pool, "Default").await
    }

    /// Simple glob-style pattern matching for MX hosts.
    fn matches_pattern(host: &str, pattern: &str) -> bool {
        if pattern == "*" {
            return true;
        }
        if pattern.starts_with("*.") {
            let suffix = &pattern[1..]; // ".domain.com"
            return host.ends_with(suffix) || host == &pattern[2..];
        }
        host == pattern
    }
}

/// Repository for the per-pool/day warmup EXECUTION rows
/// (isp_warmup_schedules).
pub struct WarmupExecutionRepo;

impl WarmupExecutionRepo {
    /// Instantiate a pool's warmup FROM a profile: one execution row per
    /// day of the profile's schedule, each carrying that day's target
    /// volume. Idempotent per (pool_id, day) — existing days are kept, so
    /// re-instantiating after a restart never resets recorded actuals.
    pub async fn instantiate_from_profile(
        pool: &PgPool,
        profile: &IspWarmupProfile,
        pool_id: &str,
    ) -> Result<Vec<IspWarmupExecution>, sqlx::Error> {
        let days = profile
            .warmup_schedule
            .as_array()
            .map(|a| a.to_vec())
            .unwrap_or_default();
        for (day, target) in days.iter().enumerate() {
            let Some(target_volume) = target.as_i64() else {
                continue;
            };
            sqlx::query(
                "INSERT INTO isp_warmup_schedules \
                     (id, pool_id, day, target_volume, status) \
                 VALUES ($1, $2, $3, $4, 'pending') \
                 ON CONFLICT (pool_id, day) DO NOTHING",
            )
            .bind(format!("ws_{pool_id}_{day}"))
            .bind(pool_id)
            .bind(day as i32)
            .bind(target_volume)
            .execute(pool)
            .await?;
        }
        Self::list_by_pool(pool, pool_id).await
    }

    /// List a pool's execution rows in day order.
    pub async fn list_by_pool(
        pool: &PgPool,
        pool_id: &str,
    ) -> Result<Vec<IspWarmupExecution>, sqlx::Error> {
        sqlx::query_as::<_, IspWarmupExecution>(
            "SELECT id, pool_id, day, target_volume, actual_volume, status, \
                    started_at, completed_at, notes, created_at, updated_at \
             FROM isp_warmup_schedules WHERE pool_id = $1 ORDER BY day",
        )
        .bind(pool_id)
        .fetch_all(pool)
        .await
    }

    /// Record one day's actual volume and derive its status from the
    /// target: completed when the target is reached, active otherwise.
    pub async fn record_daily_actual(
        pool: &PgPool,
        pool_id: &str,
        day: i32,
        actual_volume: i64,
    ) -> Result<Option<IspWarmupExecution>, sqlx::Error> {
        sqlx::query_as::<_, IspWarmupExecution>(
            "UPDATE isp_warmup_schedules \
             SET actual_volume = $3, \
                 status = CASE WHEN $3 >= target_volume THEN 'completed' ELSE 'active' END, \
                 started_at = COALESCE(started_at, NOW()), \
                 completed_at = CASE WHEN $3 >= target_volume THEN NOW() END, \
                 updated_at = NOW() \
             WHERE pool_id = $1 AND day = $2 \
             RETURNING id, pool_id, day, target_volume, actual_volume, status, \
                       started_at, completed_at, notes, created_at, updated_at",
        )
        .bind(pool_id)
        .bind(day)
        .bind(actual_volume)
        .fetch_optional(pool)
        .await
    }
}

/// Backwards-compatible alias: historical callers meant the ISP PROFILE
/// catalog. New code should name the two models explicitly.
pub type WarmupRepo = WarmupProfileRepo;

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn test_warmup_repos_are_stateless() {
        let _profiles = WarmupProfileRepo;
        let _execution = WarmupExecutionRepo;
    }

    #[test]
    fn test_get_daily_limit() {
        let schedule = serde_json::json!([50, 100, 200, 400]);
        assert_eq!(WarmupProfileRepo::get_daily_limit(&schedule, 0), Some(50));
        assert_eq!(WarmupProfileRepo::get_daily_limit(&schedule, 1), Some(100));
        assert_eq!(WarmupProfileRepo::get_daily_limit(&schedule, 3), Some(400));
        // Day 10 should clamp to last value
        assert_eq!(WarmupProfileRepo::get_daily_limit(&schedule, 10), Some(400));
    }

    #[test]
    fn test_matches_pattern() {
        assert!(WarmupProfileRepo::matches_pattern(
            "mx.google.com",
            "*.google.com"
        ));
        assert!(WarmupProfileRepo::matches_pattern(
            "google.com",
            "*.google.com"
        ));
        assert!(!WarmupProfileRepo::matches_pattern(
            "mx.yahoo.com",
            "*.google.com"
        ));
        assert!(WarmupProfileRepo::matches_pattern("anything", "*"));
    }

    #[test]
    fn test_warmup_profile_mock() {
        let profile = IspWarmupProfile {
            id: "isp_gmail".into(),
            isp_name: "Gmail".into(),
            mx_patterns: serde_json::json!(["*.google.com", "*.googlemail.com"]),
            warmup_schedule: serde_json::json!([50, 100, 200, 400, 800]),
            notes: Some("Gmail warmup".into()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        assert_eq!(profile.isp_name, "Gmail");
        assert_eq!(
            WarmupProfileRepo::get_daily_limit(&profile.warmup_schedule, 2),
            Some(200)
        );
    }

    #[test]
    fn test_warmup_execution_mock() {
        let execution = IspWarmupExecution {
            id: "ws_pool1_0".into(),
            pool_id: "pool1".into(),
            day: 0,
            target_volume: 50,
            actual_volume: Some(50),
            status: "completed".into(),
            started_at: Some(Utc::now()),
            completed_at: Some(Utc::now()),
            notes: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        assert_eq!(execution.pool_id, "pool1");
        assert_eq!(execution.target_volume, 50);
    }
}
