//! DSAR (Data Subject Access Request) rate limiting middleware.
//!
//! DSAR endpoints require stricter rate limits than normal API routes:
//!
//! | Limit Type            | Value     | Scope         | Enforced At                |
//! |-----------------------|-----------|---------------|----------------------------|
//! | Per-user submission   | 1/24h     | Email address | DSAR submission handler    |
//! | Per-tenant submission | 100/24h   | Tenant ID     | DSAR submission handler    |
//! | Per-IP submission     | 5/1h      | IP address    | Rate limiter middleware    |
//! | Verification attempts | 5/token/1h| Token hash    | Verification handler       |
//!
//! See `docs/compliance/dsar-rate-limiting.md` for full specification.

use std::time::Duration;

use base64::Engine;
use deadpool_redis::Pool as RedisPool;
use sha2::{Digest, Sha256};
use tracing::warn;

use crate::config::DsarRateLimitConfig;

// ── Rate limit status ───────────────────────────────────────────────────────

/// Outcome of a DSAR rate limit check.
#[derive(Debug, Clone)]
pub enum DsarRateLimitStatus {
    /// Request is allowed.
    Allowed,
    /// Rate-limited at the user (email) level.
    UserRateLimited { retry_after: Duration },
    /// Rate-limited at the tenant level.
    TenantRateLimited { retry_after: Duration },
    /// Rate-limited at the verification token level.
    VerificationRateLimited { retry_after: Duration },
}

// ── DSAR Rate Limiter ──────────────────────────────────────────────────────

/// DSAR-specialised rate limiter with Redis-backed and in-memory fallback.
///
/// Uses the same Redis-backed infrastructure as the general rate limiter but
/// with stricter defaults tuned for DSAR compliance requirements.
#[derive(Clone)]
pub struct DsarRateLimiter {
    redis: Option<RedisPool>,
    in_memory: moka::sync::Cache<String, u32>,
    config: DsarRateLimitConfig,
}

impl DsarRateLimiter {
    /// Create a new `DsarRateLimiter`.
    ///
    /// * `config` - DSAR-specific rate limit configuration.
    /// * `redis`  - Optional Redis pool. If `None`, falls back to in-memory
    ///   caching via `moka`.
    pub fn new(config: DsarRateLimitConfig, redis: Option<RedisPool>) -> Self {
        Self {
            redis,
            in_memory: moka::sync::Cache::builder()
                .max_capacity(10_000)
                .time_to_live(Duration::from_secs(86400))
                .build(),
            config,
        }
    }

    /// Check submission rate limits for a DSAR request.
    ///
    /// Enforces both per-user (email) and per-tenant limits.
    /// Returns `DsarRateLimitStatus::Allowed` if neither limit is exceeded.
    pub async fn check_submission(&self, email: &str, tenant_id: &str) -> DsarRateLimitStatus {
        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();

        // ── User-level limit (1 per 24h) ───────────────────────────────
        let user_key = format!("dsar:user:{}:{}", hash_email(email), today);
        let user_rl = self
            .check_key(
                &user_key,
                self.config.per_user,
                self.config.user_window_secs,
            )
            .await;
        if let DsarRateLimitStatus::UserRateLimited { retry_after } = user_rl {
            return DsarRateLimitStatus::UserRateLimited { retry_after };
        }

        // ── Tenant-level limit (100 per 24h) ───────────────────────────
        let tenant_key = format!("dsar:tenant:{}:{}", tenant_id, today);
        let tenant_rl = self
            .check_key(
                &tenant_key,
                self.config.per_tenant,
                self.config.tenant_window_secs,
            )
            .await;
        if let DsarRateLimitStatus::TenantRateLimited { retry_after } = tenant_rl {
            return DsarRateLimitStatus::TenantRateLimited { retry_after };
        }

        DsarRateLimitStatus::Allowed
    }

    /// Check verification rate limit for a DSAR verification attempt.
    ///
    /// Enforces per-token-hash limit (5 attempts per token per hour).
    pub async fn check_verification(&self, token_hash: &str) -> DsarRateLimitStatus {
        let key = format!(
            "dsar:verify:{}:{}",
            token_hash,
            chrono::Utc::now().format("%Y-%m-%d-%H")
        );

        self.check_key(
            &key,
            self.config.verify_attempts,
            self.config.verify_window_secs,
        )
        .await
    }

    // ── Internal key check ─────────────────────────────────────────────

    /// Check a single rate limit key.
    ///
    /// Uses Redis INCR + EXPIRE (atomic) when available, otherwise falls back
    /// to the in-memory `moka` cache.
    async fn check_key(&self, key: &str, max_count: u32, window_secs: u64) -> DsarRateLimitStatus {
        if let Some(redis) = &self.redis {
            match self.check_redis(redis, key, max_count, window_secs).await {
                Ok(status) => return status,
                Err(e) => {
                    warn!(error = %e, "Redis rate limit check failed; falling back to in-memory");
                }
            }
        }

        // In-memory fallback
        self.check_in_memory(key, max_count, window_secs)
    }

    /// Check rate limit via Redis INCR + EXPIRE.
    async fn check_redis(
        &self,
        redis: &RedisPool,
        key: &str,
        max_count: u32,
        window_secs: u64,
    ) -> Result<DsarRateLimitStatus, String> {
        let mut conn = redis.get().await.map_err(|e| e.to_string())?;
        let result: Result<u32, _> = redis::cmd("INCR")
            .arg(key)
            .query_async(&mut *conn)
            .await
            .map_err(|e| e.to_string());

        match result {
            Ok(count) => {
                // Set TTL on first increment
                if count == 1 {
                    let _: Result<(), _> = redis::cmd("EXPIRE")
                        .arg(key)
                        .arg(window_secs as i64)
                        .query_async(&mut *conn)
                        .await
                        .map_err(|e| warn!("Failed to set Redis TTL for {key}: {e}"));
                }

                if count > max_count {
                    return Ok(DsarRateLimitStatus::UserRateLimited {
                        retry_after: Duration::from_secs(window_secs),
                    });
                }
                Ok(DsarRateLimitStatus::Allowed)
            }
            Err(e) => Err(e),
        }
    }

    /// Check rate limit using in-memory moka cache fallback.
    fn check_in_memory(&self, key: &str, max_count: u32, _window_secs: u64) -> DsarRateLimitStatus {
        let count = self.in_memory.get(key).unwrap_or(0);
        if count >= max_count {
            return DsarRateLimitStatus::UserRateLimited {
                retry_after: Duration::from_secs(3600),
            };
        }
        self.in_memory.insert(key.to_string(), count + 1);
        DsarRateLimitStatus::Allowed
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Hash an email address using SHA-256 for use as a rate-limit key.
fn hash_email(email: &str) -> String {
    let hash = Sha256::digest(email.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash)
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_email_produces_consistent_output() {
        let h1 = hash_email("user@example.com");
        let h2 = hash_email("user@example.com");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hash_email_different_emails_differ() {
        let h1 = hash_email("alice@example.com");
        let h2 = hash_email("bob@example.com");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_in_memory_rate_limiting() {
        let config = DsarRateLimitConfig {
            per_user: 1,
            user_window_secs: 86400,
            per_tenant: 100,
            tenant_window_secs: 86400,
            verify_attempts: 5,
            verify_window_secs: 3600,
        };
        let limiter = DsarRateLimiter::new(config, None);

        // First check should be allowed
        let status = limiter.check_in_memory("dsar:user:test:2026-05-14", 1, 86400);
        assert!(matches!(status, DsarRateLimitStatus::Allowed));

        // Second check should be rate-limited
        let status = limiter.check_in_memory("dsar:user:test:2026-05-14", 1, 86400);
        assert!(matches!(
            status,
            DsarRateLimitStatus::UserRateLimited { .. }
        ));
    }

    #[test]
    fn test_dsar_rate_limit_config_default() {
        let config = DsarRateLimitConfig::default();
        assert_eq!(config.per_user, 1);
        assert_eq!(config.per_tenant, 100);
        assert_eq!(config.verify_attempts, 5);
        assert_eq!(config.user_window_secs, 86400);
        assert_eq!(config.tenant_window_secs, 86400);
        assert_eq!(config.verify_window_secs, 3600);
    }
}
