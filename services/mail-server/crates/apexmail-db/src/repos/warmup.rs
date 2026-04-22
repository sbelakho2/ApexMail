//! ISP warmup schedules repository.

use sqlx::PgPool;

use crate::types::IspWarmupSchedule;

/// Repository for ISP warmup schedule operations.
pub struct WarmupRepo;

impl WarmupRepo {
/// Create a new warmup schedule.
    pub async fn create(
        pool: &PgPool,
        id: &str,
        isp_name: &str,
        mx_patterns: serde_json::Value,
        warmup_schedule: serde_json::Value,
        notes: Option<&str>,
    ) -> Result<IspWarmupSchedule, sqlx::Error> {
        sqlx::query_as::<_, IspWarmupSchedule>(
            "INSERT INTO isp_warmup_schedules (id, isp_name, mx_patterns, warmup_schedule, notes, created_at, updated_at) \
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

/// Get a warmup schedule by ISP name.
    pub async fn get_by_isp(pool: &PgPool, isp_name: &str) -> Result<Option<IspWarmupSchedule>, sqlx::Error> {
        sqlx::query_as::<_, IspWarmupSchedule>(
            "SELECT id, isp_name, mx_patterns, warmup_schedule, notes, created_at, updated_at \
             FROM isp_warmup_schedules WHERE isp_name = $1",
        )
        .bind(isp_name)
        .fetch_optional(pool)
        .await
    }

/// Get a warmup schedule by ID.
    pub async fn get_by_id(pool: &PgPool, id: &str) -> Result<Option<IspWarmupSchedule>, sqlx::Error> {
        sqlx::query_as::<_, IspWarmupSchedule>(
            "SELECT id, isp_name, mx_patterns, warmup_schedule, notes, created_at, updated_at \
             FROM isp_warmup_schedules WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(pool)
        .await
    }

/// List all warmup schedules.
    pub async fn list(pool: &PgPool) -> Result<Vec<IspWarmupSchedule>, sqlx::Error> {
        sqlx::query_as::<_, IspWarmupSchedule>(
            "SELECT id, isp_name, mx_patterns, warmup_schedule, notes, created_at, updated_at \
             FROM isp_warmup_schedules ORDER BY isp_name",
        )
        .fetch_all(pool)
        .await
    }

/// Update a warmup schedule.
    pub async fn update(
        pool: &PgPool,
        id: &str,
        warmup_schedule: serde_json::Value,
        notes: Option<&str>,
    ) -> Result<Option<IspWarmupSchedule>, sqlx::Error> {
        sqlx::query_as::<_, IspWarmupSchedule>(
            "UPDATE isp_warmup_schedules \
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

/// Delete a warmup schedule.
    pub async fn delete(pool: &PgPool, id: &str) -> Result<bool, sqlx::Error> {
        let result = sqlx::query("DELETE FROM isp_warmup_schedules WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

/// Get daily limit for a given day from a schedule.
/// Returns the limit at the specified day index, or the final limit if day exceeds schedule length.
    pub fn get_daily_limit(schedule: &serde_json::Value, day: usize) -> Option<u64> {
        schedule.as_array().and_then(|arr| {
            let idx = day.min(arr.len().saturating_sub(1));
            arr.get(idx).and_then(|v| v.as_u64())
        })
    }

/// Match an MX host against patterns to find the ISP.
/// Note:This loads all schedules into memory. For production scale,
/// consider caching schedules in-memory or adding a database-side pattern match.
    pub async fn find_by_mx_pattern(pool: &PgPool, mx_host: &str) -> Result<Option<IspWarmupSchedule>, sqlx::Error> {
// Get all schedules and match patterns
        let schedules = Self::list(pool).await?;
        for schedule in schedules {
            if let Some(patterns) = schedule.mx_patterns.as_array() {
                for pattern in patterns {
                    if let Some(pat) = pattern.as_str() {
                        if Self::matches_pattern(mx_host, pat) {
                            return Ok(Some(schedule));
                        }
                    }
                }
            }
        }
// Return default schedule if no match
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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn test_warmup_repo_is_stateless() {
        let _repo = WarmupRepo;
    }

    #[test]
    fn test_get_daily_limit() {
        let schedule = serde_json::json!([50, 100, 200, 400]);
        assert_eq!(WarmupRepo::get_daily_limit(&schedule, 0), Some(50));
        assert_eq!(WarmupRepo::get_daily_limit(&schedule, 1), Some(100));
        assert_eq!(WarmupRepo::get_daily_limit(&schedule, 3), Some(400));
// Day 10 should clamp to last value
        assert_eq!(WarmupRepo::get_daily_limit(&schedule, 10), Some(400));
    }

    #[test]
    fn test_matches_pattern() {
        assert!(WarmupRepo::matches_pattern("mx.google.com", "*.google.com"));
        assert!(WarmupRepo::matches_pattern("google.com", "*.google.com"));
        assert!(!WarmupRepo::matches_pattern("mx.yahoo.com", "*.google.com"));
        assert!(WarmupRepo::matches_pattern("anything", "*"));
    }

    #[test]
    fn test_warmup_schedule_mock() {
        let schedule = IspWarmupSchedule {
            id: "isp_gmail".into(),
            isp_name: "Gmail".into(),
            mx_patterns: serde_json::json!(["*.google.com", "*.googlemail.com"]),
            warmup_schedule: serde_json::json!([50, 100, 200, 400, 800]),
            notes: Some("Gmail warmup".into()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        assert_eq!(schedule.isp_name, "Gmail");
        assert_eq!(WarmupRepo::get_daily_limit(&schedule.warmup_schedule, 2), Some(200));
    }
}
