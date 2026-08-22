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

    /// Check submission rate limits for a DSAR request (read-only — the
    /// quota is only consumed on success via
    /// [`DsarRateLimiter::record_submission_success`]).
    ///
    /// Enforces both per-user (email) and per-tenant limits.
    /// Returns `DsarRateLimitStatus::Allowed` if neither limit is exceeded.
    pub async fn check_submission(&self, email: &str, tenant_id: &str) -> DsarRateLimitStatus {
        // ── User-level limit (1 per 24h) ───────────────────────────────
        let user_rl = self
            .peek_key(
                &self.user_key(email),
                self.config.per_user,
                RateLimitKind::User,
                self.config.user_window_secs,
            )
            .await;
        if !matches!(user_rl, DsarRateLimitStatus::Allowed) {
            return user_rl;
        }

        // ── Tenant-level limit (100 per 24h) ───────────────────────────
        let tenant_rl = self
            .peek_key(
                &self.tenant_key(tenant_id),
                self.config.per_tenant,
                RateLimitKind::Tenant,
                self.config.tenant_window_secs,
            )
            .await;
        if !matches!(tenant_rl, DsarRateLimitStatus::Allowed) {
            return tenant_rl;
        }

        DsarRateLimitStatus::Allowed
    }

    /// L1: consume one submission slot — call only AFTER the submission has
    /// been durably accepted, so failed/invalid submissions do not burn the
    /// subject's daily quota.
    pub async fn record_submission_success(&self, email: &str, tenant_id: &str) {
        if let Err(e) = self
            .consume_key(&self.user_key(email), self.config.user_window_secs)
            .await
        {
            warn!(error = %e, "Failed to record DSAR user submission quota");
        }
        if let Err(e) = self
            .consume_key(&self.tenant_key(tenant_id), self.config.tenant_window_secs)
            .await
        {
            warn!(error = %e, "Failed to record DSAR tenant submission quota");
        }
    }

    /// Check verification rate limit for a DSAR verification attempt.
    ///
    /// Enforces per-token-hash limit (5 attempts per token per hour).
    /// D: the attempt is CONSUMED here (even failed attempts count — this is
    /// the brute-force guard), and an exceeded limit is reported as
    /// `VerificationRateLimited` so the verify handler cannot swallow it.
    pub async fn check_verification(&self, token_hash: &str) -> DsarRateLimitStatus {
        let key = format!(
            "dsar:verify:{}:{}",
            token_hash,
            chrono::Utc::now().format("%Y-%m-%d-%H")
        );

        self.check_and_consume_key(
            &key,
            self.config.verify_attempts,
            RateLimitKind::Verification,
            self.config.verify_window_secs,
        )
        .await
    }

    // ── Internal key operations ─────────────────────────────────────

    fn user_key(&self, email: &str) -> String {
        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        format!("dsar:user:{}:{}", hash_email(email), today)
    }

    fn tenant_key(&self, tenant_id: &str) -> String {
        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        format!("dsar:tenant:{}:{}", tenant_id, today)
    }

    /// Read-only check: does the key exceed `max_count`? Never mutates.
    async fn peek_key(
        &self,
        key: &str,
        max_count: u32,
        kind: RateLimitKind,
        window_secs: u64,
    ) -> DsarRateLimitStatus {
        if let Some(redis) = &self.redis {
            let conn = redis.get().await;
            match conn {
                Ok(mut conn) => {
                    match redis::cmd("GET")
                        .arg(key)
                        .query_async::<Option<u32>>(&mut *conn)
                        .await
                    {
                        Ok(Some(count)) if count >= max_count => {
                            return exceeded(kind, window_secs);
                        }
                        Ok(_) => return DsarRateLimitStatus::Allowed,
                        Err(e) => {
                            warn!(error = %e, "Redis rate limit peek failed; falling back to in-memory");
                        }
                    }
                }
                Err(e) => {
                    warn!(error = %e, "Redis rate limit peek failed; falling back to in-memory");
                }
            }
        }
        self.peek_in_memory(key, max_count, kind)
    }

    /// Increment the key's counter, establishing the window TTL if missing.
    async fn consume_key(&self, key: &str, window_secs: u64) -> Result<(), String> {
        if let Some(redis) = &self.redis {
            let mut conn = redis.get().await.map_err(|e| e.to_string())?;
            let _: u32 = redis::cmd("INCR")
                .arg(key)
                .query_async(&mut *conn)
                .await
                .map_err(|e| e.to_string())?;
            // L1: set the TTL whenever it is missing (not only when INCR
            // returns 1 — a lost EXPIRE after a crash used to leave a
            // permanent counter).
            let ttl: i64 = redis::cmd("TTL")
                .arg(key)
                .query_async(&mut *conn)
                .await
                .map_err(|e| e.to_string())?;
            if ttl < 0 {
                if let Err(e) = redis::cmd("EXPIRE")
                    .arg(key)
                    .arg(window_secs as i64)
                    .query_async::<()>(&mut *conn)
                    .await
                {
                    warn!("Failed to set Redis TTL for {key}: {e}");
                }
            }
            return Ok(());
        }
        let count = self.in_memory.get(key).unwrap_or(0);
        self.in_memory.insert(key.to_string(), count + 1);
        Ok(())
    }

    /// Check-and-consume (used for verification attempts — every attempt,
    /// successful or not, consumes quota).
    async fn check_and_consume_key(
        &self,
        key: &str,
        max_count: u32,
        kind: RateLimitKind,
        window_secs: u64,
    ) -> DsarRateLimitStatus {
        if let Some(redis) = &self.redis {
            let mut conn = match redis.get().await {
                Ok(c) => c,
                Err(e) => {
                    warn!(error = %e, "Redis rate limit check failed; falling back to in-memory");
                    return self.check_and_consume_in_memory(key, max_count, kind);
                }
            };
            let count: u32 = match redis::cmd("INCR").arg(key).query_async(&mut *conn).await {
                Ok(c) => c,
                Err(e) => {
                    warn!(error = %e, "Redis rate limit INCR failed; falling back to in-memory");
                    return self.check_and_consume_in_memory(key, max_count, kind);
                }
            };
            // L1: establish the TTL whenever missing.
            let ttl: i64 = redis::cmd("TTL")
                .arg(key)
                .query_async(&mut *conn)
                .await
                .unwrap_or(-1);
            if ttl < 0 {
                let _: Result<(), _> = redis::cmd("EXPIRE")
                    .arg(key)
                    .arg(window_secs as i64)
                    .query_async(&mut *conn)
                    .await;
            }
            if count > max_count {
                return exceeded(kind, window_secs);
            }
            return DsarRateLimitStatus::Allowed;
        }

        self.check_and_consume_in_memory(key, max_count, kind)
    }

    /// Read-only in-memory check.
    fn peek_in_memory(
        &self,
        key: &str,
        max_count: u32,
        kind: RateLimitKind,
    ) -> DsarRateLimitStatus {
        let count = self.in_memory.get(key).unwrap_or(0);
        if count >= max_count {
            return exceeded(kind, 3600);
        }
        DsarRateLimitStatus::Allowed
    }

    /// Check-and-consume in-memory (verification attempts).
    fn check_and_consume_in_memory(
        &self,
        key: &str,
        max_count: u32,
        kind: RateLimitKind,
    ) -> DsarRateLimitStatus {
        let count = self.in_memory.get(key).unwrap_or(0);
        if count >= max_count {
            return exceeded(kind, 3600);
        }
        self.in_memory.insert(key.to_string(), count + 1);
        DsarRateLimitStatus::Allowed
    }
}

/// Which limit a key belongs to — D: exceeded keys must surface as the
/// variant the handlers actually enforce (previously every exceeded key was
/// reported as `UserRateLimited`, which the verification handler swallowed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RateLimitKind {
    User,
    Tenant,
    Verification,
}

fn exceeded(kind: RateLimitKind, window_secs: u64) -> DsarRateLimitStatus {
    let retry_after = Duration::from_secs(window_secs.max(1));
    match kind {
        RateLimitKind::User => DsarRateLimitStatus::UserRateLimited { retry_after },
        RateLimitKind::Tenant => DsarRateLimitStatus::TenantRateLimited { retry_after },
        RateLimitKind::Verification => DsarRateLimitStatus::VerificationRateLimited { retry_after },
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

    // NOTE: the in-memory rate-limit test previously asserted the OLD
    // behavior where a submission check consumed quota immediately
    // (INCR-before-success). It was updated to the fixed L1 contract:
    // checks are read-only; quota is consumed only on success.

    fn test_config() -> DsarRateLimitConfig {
        DsarRateLimitConfig {
            per_user: 1,
            user_window_secs: 86400,
            per_tenant: 100,
            tenant_window_secs: 86400,
            verify_attempts: 5,
            verify_window_secs: 3600,
        }
    }

    #[test]
    fn test_in_memory_rate_limiting() {
        let limiter = DsarRateLimiter::new(test_config(), None);
        let key = "dsar:user:test:2026-05-14";

        // Peek does not consume quota.
        assert!(matches!(
            limiter.peek_in_memory(key, 1, RateLimitKind::User),
            DsarRateLimitStatus::Allowed
        ));
        assert!(matches!(
            limiter.peek_in_memory(key, 1, RateLimitKind::User),
            DsarRateLimitStatus::Allowed
        ));

        // After a successful submission consumes the slot, further checks
        // are rate-limited.
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        rt.block_on(limiter.consume_key(key, 86400)).unwrap();
        assert!(matches!(
            limiter.peek_in_memory(key, 1, RateLimitKind::User),
            DsarRateLimitStatus::UserRateLimited { .. }
        ));
    }

    /// L1: failed submissions must not burn the subject's quota.
    #[tokio::test]
    async fn test_submission_quota_only_consumed_on_success() {
        let limiter = DsarRateLimiter::new(test_config(), None);
        let email = "user@example.com";
        let tenant = "t1";

        // Several (failed) submission attempts — all still allowed.
        for _ in 0..5 {
            let status = limiter.check_submission(email, tenant).await;
            assert!(matches!(status, DsarRateLimitStatus::Allowed));
        }

        // One successful submission consumes the single per-user slot.
        limiter.record_submission_success(email, tenant).await;
        let status = limiter.check_submission(email, tenant).await;
        assert!(matches!(
            status,
            DsarRateLimitStatus::UserRateLimited { .. }
        ));
    }

    /// D: the 6th verification attempt within the window is rejected with
    /// the VerificationRateLimited variant (the one the handler enforces).
    #[tokio::test]
    async fn test_verification_attempts_rate_limited_with_correct_variant() {
        let limiter = DsarRateLimiter::new(test_config(), None);
        let token_hash = "abc123";

        for attempt in 1..=5 {
            let status = limiter.check_verification(token_hash).await;
            assert!(
                matches!(status, DsarRateLimitStatus::Allowed),
                "attempt {attempt} should be allowed"
            );
        }
        let status = limiter.check_verification(token_hash).await;
        assert!(matches!(
            status,
            DsarRateLimitStatus::VerificationRateLimited { .. }
        ));
    }

    /// D/L1: window reset — once the in-memory entry expires (evicted), the
    /// same subject can submit again.
    #[tokio::test]
    async fn test_rate_limit_resets_after_window() {
        let limiter = DsarRateLimiter::new(test_config(), None);
        let email = "reset@example.com";
        limiter.record_submission_success(email, "t1").await;
        assert!(matches!(
            limiter.check_submission(email, "t1").await,
            DsarRateLimitStatus::UserRateLimited { .. }
        ));

        // Simulate the window elapsing by evicting the counter (the Redis
        // path relies on the key TTL for the same effect).
        limiter.in_memory.invalidate(&limiter.user_key(email));
        assert!(matches!(
            limiter.check_submission(email, "t1").await,
            DsarRateLimitStatus::Allowed
        ));
    }

    /// D: exceeded limits surface as the variant matching their kind.
    #[test]
    fn test_exceeded_kind_mapping() {
        assert!(matches!(
            exceeded(RateLimitKind::User, 60),
            DsarRateLimitStatus::UserRateLimited { .. }
        ));
        assert!(matches!(
            exceeded(RateLimitKind::Tenant, 60),
            DsarRateLimitStatus::TenantRateLimited { .. }
        ));
        assert!(matches!(
            exceeded(RateLimitKind::Verification, 60),
            DsarRateLimitStatus::VerificationRateLimited { .. }
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
