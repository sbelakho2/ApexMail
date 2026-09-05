# DSAR (Data Subject Access Request) Rate Limiting

> **Last Updated:** 2026-05-11
> **Related:** historical `faults.md` audit findings §33.6 — DSAR Verification Token Uses SHA-256 Hash with No Rate Limiting (the faults.md audit document has since been removed from the repo).

## Table of Contents

- [Problem Statement](#problem-statement)
- [Architecture Context](#architecture-context)
- [Per-Tenant DSAR Rate Limits](#per-tenant-dsar-rate-limits)
- [Implementation Guidance](#implementation-guidance)
- [Redis-Backed Cooldown Tracking](#redis-backed-cooldown-tracking)
- [Rate Limit Middleware Sample Code](#rate-limit-middleware-sample-code)
- [Admin Override Capability](#admin-override-capability)
- [Verification Attempt Rate Limiting](#verification-attempt-rate-limiting)
- [Monitoring & Alerting](#monitoring--alerting)

---

## Problem Statement

**Finding (historical `faults.md` §33.6):** DSAR verification tokens use SHA-256 hashing with no rate limiting on verification attempts. Additionally, there is no rate limiting on the DSAR submission endpoint itself.

**Risk:** An attacker can:
1. Flood the DSAR submission endpoint to exhaust system resources
2. Brute-force DSAR verification tokens (no rate limiting + SHA-256 hash without sufficient entropy)
3. Submit repeated DSAR requests for the same data subject to harass or overwhelm the compliance team

**Current state:** DSAR functionality is not yet fully implemented in the codebase — `dsar.rs` in the compliance crate does not exist. This document provides the implementation plan and rate limiting strategy for when DSAR is built.

---

## Architecture Context

DSAR processing touches the following crates:

| Crate | Role | File |
|-------|------|------|
| `compliance` | DSAR submission, verification, fulfillment | [`compliance/src/routes.rs`](../../services/mail-server/crates/compliance/src/routes.rs) |
| `rate-limiter` | Distributed rate limiting (Redis-backed) | [`rate-limiter/src/redis_limiter.rs`](../../services/mail-server/crates/rate-limiter/src/redis_limiter.rs) |
| `api-server` | Admin DSAR management endpoints | [`api-server/src/routes/admin/`](../../services/mail-server/crates/api-server/src/routes/admin/) |
| `worker-processors` | Async DSAR fulfillment (data collection, redaction) | `worker-processors/src/dsar.rs` (planned — does not exist yet) |

The existing rate limiter infrastructure provides:

- Tenant-scoped rate limiting via [`check_n_for_tenant()`](../../services/mail-server/crates/rate-limiter/src/redis_limiter.rs) — scopes keys with tenant ID prefix
- Lua-based atomic operations for race-condition-free rate limit checks
- Governor in-memory fallback when Redis is unavailable
- Configurable via `RateLimitConfig` (burst, per_second, backend selection)

---

## Per-Tenant DSAR Rate Limits

### Submission Limits

| Limit Type | Value | Scope | Enforced At |
|------------|-------|-------|-------------|
| **Per-user submission** | 1 request per 24 hours | Email address | DSAR submission handler |
| **Per-tenant submission** | 100 requests per 24 hours | Tenant ID | DSAR submission handler |
| **Per-IP submission** | 5 requests per hour | IP address | Rate limiter middleware |
| **Verification attempts** | 5 attempts per token | Token hash | Verification handler |

### Rationale

- **1 per 24h per user**: GDPR Article 12(3) allows a 1-month response window. 24h prevents abuse while allowing legitimate repeat requests after the initial response.
- **100 per 24h per tenant**: Prevents resource exhaustion by a single tenant. Based on expected volume — most tenants will submit < 5 DSARs/month.
- **5 per hour per IP**: Prevents scripted attacks from a single source.
- **5 verification attempts per token**: Prevents brute-force of verification tokens. Combined with token entropy (64-bit random, see below), this makes brute-force infeasible.

### Configuration

Rate limits are configurable at deployment time via environment variables:

```bash
export DSAR_RATE_LIMIT_PER_USER="1/86400"     # 1 request per 86400 seconds (24h)
export DSAR_RATE_LIMIT_PER_TENANT="100/86400"  # 100 requests per 86400 seconds (24h)
export DSAR_RATE_LIMIT_PER_IP="5/3600"         # 5 requests per 3600 seconds (1h)
export DSAR_VERIFY_RATE_LIMIT="5/3600"         # 5 verification attempts per token per hour
```

---

## Implementation Guidance

### DSAR Verification Token Security

**Current issue:** SHA-256 hash with no rate limiting.

**Fix:**
1. Generate verification tokens using `OsRng` with at least 64 bits (8 bytes) of entropy, encoded as URL-safe base64
2. Store token hash using Argon2id (same as password hashing) instead of raw SHA-256
3. Rate-limit verification attempts using Redis-backed counters per token hash

```rust
// Verification token generation (in compliance/src/dsar.rs)
use rand::rngs::OsRng;
use rand::TryRngCore;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

fn generate_dsar_verification_token() -> String {
    let mut bytes = [0u8; 16]; // 128 bits of entropy
    OsRng.try_fill_bytes(&mut bytes)
        .expect("OsRng should not fail on first call");
    URL_SAFE_NO_PAD.encode(bytes)
}
```

### DSAR Submission Handler (Pseudocode)

```rust
async fn submit_dsar(
    State(state): State<AppState>,
    rate_limiter: RateLimiter,
    Json(req): Json<DsarSubmission>,
) -> Result<Json<DsarResponse>, AppError> {
    // 1. Rate limit by email (1 per 24h)
    let email_key = format!("dsar:email:{}", sha256(req.email.as_bytes()));
    rate_limiter.check_n_for_tenant("dsar_user", &email_key, 1, 86400).await?
        .ok_or(AppError::RateLimited("Too many DSAR requests for this email. Please wait 24 hours."))?;

    // 2. Rate limit by tenant (100 per 24h)
    rate_limiter.check_n_for_tenant("dsar_tenant", &req.tenant_id, 100, 86400).await?
        .ok_or(AppError::RateLimited("Tenant DSAR quota exceeded. Please try again later."))?;

    // 3. Create DSAR record with verification token
    let token = generate_dsar_verification_token();
    let token_hash = hash_verification_token(&token);
    let dsar = create_dsar_request(&state.db, &req, &token_hash).await?;

    // 4. Send verification email (with rate limiting per email)
    send_verification_email(&state.email_sender, &req.email, &token).await?;

    Ok(Json(DsarResponse {
        id: dsar.id,
        message: "DSAR submitted. Check your email for verification instructions.",
        verification_sent_to: mask_email(&req.email),
    }))
}
```

---

## Redis-Backed Cooldown Tracking

### Key Schema

```
dsar:user:<sha256(email)>:<date>     → count (TTL: 86400s = 24h)
dsar:tenant:<tenant_id>:<date>       → count (TTL: 86400s = 24h)
dsar:ip:<ip_address>:<date>          → count (TTL: 3600s = 1h)
dsar:verify:<token_hash>:<date>      → count (TTL: 3600s = 1h)
```

### Lua Script for Atomic Rate Limit Check

```lua
-- KEYS[1] = rate limit key (e.g., "dsar:user:abc123:2026-05-11")
-- KEYS[2] = rate limit key for tenant
-- ARGV[1] = user max count
-- ARGV[2] = user window seconds
-- ARGV[3] = tenant max count
-- ARGV[4] = tenant window seconds

local user_count = redis.call('INCR', KEYS[1])
if user_count == 1 then
    redis.call('EXPIRE', KEYS[1], ARGV[2])
end

local tenant_count = redis.call('INCR', KEYS[2])
if tenant_count == 1 then
    redis.call('EXPIRE', KEYS[2], ARGV[4])
end

if user_count > tonumber(ARGV[1]) then
    return {0, user_count, tenant_count}  -- User rate limited
end

if tenant_count > tonumber(ARGV[3]) then
    return {1, user_count, tenant_count}  -- Tenant rate limited
end

return {2, user_count, tenant_count}  -- Allowed
```

### Integration with Existing Rate Limiter

The existing [`RedisLimiter`](../../services/mail-server/crates/rate-limiter/src/redis_limiter.rs) already supports tenant-scoped keys. DSAR rate limits should use the same infrastructure:

```rust
// In compliance/src/routes.rs — DSAR handler
use rate_limiter::RedisLimiter;

async fn dsar_handler(
    limiter: Extension<RedisLimiter>,
    // ...
) -> impl Responder {
    // User-level rate limit
    let user_key = format!("dsar:user:{}:{}", email_hash, today);
    match limiter.check_n_for_tenant("dsar", &user_key, 1, 86400).await {
        Ok(Some(decision)) if decision.is_allowed() => { /* proceed */ }
        Ok(Some(decision)) if decision.is_denied() => {
            return HttpResponse::TooManyRequests().json(serde_json::json!({
                "error": "rate_limited",
                "retry_after": decision.retry_after().as_secs(),
                "message": "You have already submitted a DSAR request in the last 24 hours."
            }));
        }
        _ => { /* fallback to in-memory rate limit or proceed */ }
    }
}
```

---

## Rate Limit Middleware Sample Code

```rust
// compliance/src/middleware/dsar_rate_limit.rs

use std::sync::Arc;
use rate_limiter::{RedisLimiter, Decision};
use crate::config::DsarRateLimitConfig;

#[derive(Clone)]
pub struct DsarRateLimiter {
    redis: Option<Arc<RedisLimiter>>,
    in_memory: moka::sync::Cache<String, u32>,
    config: DsarRateLimitConfig,
}

impl DsarRateLimiter {
    pub fn new(config: DsarRateLimitConfig, redis: Option<Arc<RedisLimiter>>) -> Self {
        Self {
            redis,
            in_memory: moka::sync::Cache::builder()
                .max_capacity(10_000)
                .time_to_live(std::time::Duration::from_secs(86400))
                .build(),
            config,
        }
    }

    pub async fn check_submission(
        &self,
        email: &str,
        tenant_id: &str,
        ip: &str,
    ) -> Result<DsarRateLimitStatus, DsarError> {
        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();

        // User-level limit
        let user_key = format!("dsar:user:{}:{}", hash_email(email), today);
        if let Some(redis) = &self.redis {
            let decision = redis
                .check_n_for_tenant("dsar_user", &user_key, self.config.per_user, self.config.user_window_secs)
                .await
                .map_err(|e| DsarError::RateLimitCheckFailed(e.to_string()))?;

            if let Some(d) = decision {
                if d.is_denied() {
                    return Ok(DsarRateLimitStatus::UserRateLimited {
                        retry_after: d.retry_after(),
                    });
                }
            }
        } else {
            // In-memory fallback
            let count = self.in_memory.get(&user_key).unwrap_or(0);
            if count >= self.config.per_user {
                return Ok(DsarRateLimitStatus::UserRateLimited {
                    retry_after: std::time::Duration::from_secs(3600),
                });
            }
            self.in_memory.insert(user_key, count + 1);
        }

        // Tenant-level limit
        let tenant_key = format!("dsar:tenant:{}:{}", tenant_id, today);
        if let Some(redis) = &self.redis {
            let decision = redis
                .check_n_for_tenant("dsar_tenant", &tenant_key, self.config.per_tenant, self.config.tenant_window_secs)
                .await
                .map_err(|e| DsarError::RateLimitCheckFailed(e.to_string()))?;

            if let Some(d) = decision {
                if d.is_denied() {
                    return Ok(DsarRateLimitStatus::TenantRateLimited {
                        retry_after: d.retry_after(),
                    });
                }
            }
        }

        Ok(DsarRateLimitStatus::Allowed)
    }

    pub async fn check_verification(
        &self,
        token_hash: &str,
    ) -> Result<DsarRateLimitStatus, DsarError> {
        let key = format!("dsar:verify:{}:{}", token_hash, chrono::Utc::now().format("%Y-%m-%d"));

        if let Some(redis) = &self.redis {
            let decision = redis
                .check_n_for_tenant("dsar_verify", &key, self.config.verify_attempts, self.config.verify_window_secs)
                .await
                .map_err(|e| DsarError::RateLimitCheckFailed(e.to_string()))?;

            if let Some(d) = decision {
                if d.is_denied() {
                    return Ok(DsarRateLimitStatus::VerificationRateLimited {
                        retry_after: d.retry_after(),
                    });
                }
            }
        }

        Ok(DsarRateLimitStatus::Allowed)
    }
}

#[derive(Debug)]
pub enum DsarRateLimitStatus {
    Allowed,
    UserRateLimited { retry_after: std::time::Duration },
    TenantRateLimited { retry_after: std::time::Duration },
    VerificationRateLimited { retry_after: std::time::Duration },
}

// Config (loaded from environment)
#[derive(Clone, Debug, serde::Deserialize)]
pub struct DsarRateLimitConfig {
    pub per_user: u32,           // default: 1
    pub user_window_secs: u64,   // default: 86400 (24h)
    pub per_tenant: u32,         // default: 100
    pub tenant_window_secs: u64, // default: 86400 (24h)
    pub verify_attempts: u32,    // default: 5
    pub verify_window_secs: u64, // default: 3600 (1h)
}

impl Default for DsarRateLimitConfig {
    fn default() -> Self {
        Self {
            per_user: 1,
            user_window_secs: 86400,
            per_tenant: 100,
            tenant_window_secs: 86400,
            verify_attempts: 5,
            verify_window_secs: 3600,
        }
    }
}

fn hash_email(email: &str) -> String {
    let hash = sha2::Sha256::digest(email.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash)
}
```

---

## Admin Override Capability

### Endpoint: `POST /v1/admin/dsar/override-rate-limit`

Allows compliance administrators to bypass DSAR rate limits for legitimate purposes (e.g., legal requirement, investigation).

#### Request

```json
{
  "dsar_id": "dsar-uuid-here",
  "email": "subject@example.com",
  "reason": "Legal request from data protection authority — reference REF-2026-0511",
  "duration_minutes": 1440,
  "override_type": "user|tenant|verification"
}
```

#### Implementation

```rust
// In api-server/src/routes/admin.rs
async fn dsar_override_rate_limit(
    State(state): State<AppState>,
    Authenticated(admin): Authenticated<AdminSession>,
    Json(req): Json<DsarOverrideRequest>,
) -> Result<Json<DsarOverrideResponse>, AppError> {
    // 1. Verify admin has compliance scope
    enforce_scope(&admin, "compliance:admin")?;

    // 2. Validate reason is provided (legal requirement for override audit trail)
    if req.reason.len() < 20 {
        return Err(AppError::ValidationError("Override reason must be at least 20 characters"));
    }

    // 3. Create Redis allowlist entry
    let allowlist_key = format!("dsar:override:{}:{}", req.override_type, req.email);
    redis::cmd("SET")
        .arg(&allowlist_key)
        .arg("true")
        .arg("EX")
        .arg(req.duration_minutes * 60)
        .exec_async(&state.redis)
        .await?;

    // 4. Audit log
    audit_log(&state, "dsar.rate_limit.override", format!(
        "Admin {} overrode DSAR rate limit for {} (type: {}, reason: {})",
        admin.id, req.email, req.override_type, req.reason
    )).await?;

    Ok(Json(DsarOverrideResponse {
        status: "override_active",
        expires_at: chrono::Utc::now() + chrono::Duration::minutes(req.duration_minutes as i64),
    }))
}
```

### Rate Limit Bypass Check

In the DSAR rate limit middleware, check the allowlist before enforcing limits:

```rust
async fn is_rate_limit_overridden(redis: &RedisPool, email: &str, override_type: &str) -> bool {
    let key = format!("dsar:override:{}:{}", override_type, email);
    redis::cmd("EXISTS")
        .arg(&key)
        .query_async::<_, bool>(redis)
        .await
        .unwrap_or(false)
}
```

---

## Verification Attempt Rate Limiting

### Token Security Upgrade

Replace raw SHA-256 with Argon2id for verification token hashing:

```rust
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::password_hash::SaltString;

fn hash_verification_token(token: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(token.as_bytes(), &salt)
        .expect("Argon2id hashing should not fail")
        .to_string()
}

fn verify_verification_token(token: &str, hash: &str) -> bool {
    let parsed_hash = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(_) => return false,
    };
    Argon2::default()
        .verify_password(token.as_bytes(), &parsed_hash)
        .is_ok()
}
```

### Rate-Limited Verification Handler

```rust
async fn verify_dsar(
    State(state): State<AppState>,
    rate_limiter: Extension<DsarRateLimiter>,
    Query(params): Query<DsarVerifyParams>,
) -> Result<Json<DsarVerifyResponse>, AppError> {
    let token_hash = hash_for_rate_limit(&params.token);

    // Check verification rate limit (5 attempts per token per hour)
    match rate_limiter.check_verification(&token_hash).await? {
        DsarRateLimitStatus::VerificationRateLimited { retry_after } => {
            return Err(AppError::RateLimited(format!(
                "Too many verification attempts. Try again in {} seconds.",
                retry_after.as_secs()
            )));
        }
        DsarRateLimitStatus::Allowed => { /* proceed */ }
        _ => unreachable!(),
    }

    // Verify the token
    let dsar = get_dsar_by_token_hash(&state.db, &token_hash).await?
        .ok_or(AppError::NotFound("Invalid or expired verification token"))?;

    if verify_verification_token(&params.token, &dsar.verification_token_hash) {
        // Mark DSAR as verified and queue fulfillment
        mark_dsar_verified(&state.db, dsar.id).await?;
        queue_dsar_fulfillment(&state.queue, dsar.id).await?;

        Ok(Json(DsarVerifyResponse {
            status: "verified",
            message: "Your DSAR request has been verified. We will process your request within 30 days.",
        }))
    } else {
        Err(AppError::Unauthorized("Invalid verification token"))
    }
}
```

---

## Monitoring & Alerting

### Prometheus Metrics

```
# Counter: Total DSAR submissions
dsar_submissions_total{tenant_id="...",status="submitted|verified|fulfilled|rejected"}

# Counter: Rate-limited requests
dsar_rate_limited_total{tenant_id="...",limit_type="user|tenant|ip|verify"}

# Gauge: Pending DSAR requests
dsar_pending_total{tenant_id="..."}

# Histogram: DSAR processing time
dsar_processing_duration_seconds{stage="submission|verification|fulfillment"}
```

### Alert Rules

```yaml
# Prometheus alert rule
groups:
  - name: dsar
    rules:
      - alert: DSARRateLimitHighRejection
        expr: rate(dsar_rate_limited_total[5m]) > 10
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High DSAR rate limit rejection rate (>10 req/5m)"

      - alert: DSARVerificationBruteForce
        expr: rate(dsar_rate_limited_total{limit_type="verify"}[5m]) > 20
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "Possible brute-force attack on DSAR verification tokens"
```

---

## References

- [GDPR Article 12](https://gdpr-info.eu/art-12-gdpr/) — Transparent information, communication and modalities
- [GDPR Article 15](https://gdpr-info.eu/art-15-gdpr/) — Right of access by the data subject
- [Rate Limiter Crate](../../services/mail-server/crates/rate-limiter/src/redis_limiter.rs) — Redis-backed distributed rate limiter
- [Compliance Crate Routes](../../services/mail-server/crates/compliance/src/routes.rs) — Compliance API endpoints
- [Emergency Key Revocation](../operations/emergency-key-revocation.md) — Related: key revocation procedures
