# Per-Tenant Rate Limit Budget Enforcement

> **Document Owner:** Backend Team
> **Last Updated:** 2026-05-11
> **Related:** [`rate-limit-budgets.md`](rate-limit-budgets.md), [`rate-limiter-metrics.md`](rate-limiter-metrics.md), [`rate-limiter/src/redis_limiter.rs`](../../services/mail-server/crates/rate-limiter/src/redis_limiter.rs), [`rate-limiter/src/types.rs`](../../services/mail-server/crates/rate-limiter/src/types.rs)

## 1. Overview

This document defines the code structure and implementation plan for per-tenant rate limit budget enforcement. The enforcement system integrates with the existing [`rate-limiter`](../../services/mail-server/crates/rate-limiter/) crate and adds budget-aware rate limiting on top of the current token bucket implementation.

## 2. Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     API Gateway/Middleware                    │
│                                                              │
│  Request → RateLimitMiddleware → BudgetChecker → Backend    │
│                │                        │                    │
│                ▼                        ▼                    │
│        ┌──────────────┐       ┌──────────────┐              │
│        │ Global Limiter│       │Budget Checker│              │
│        │(in-memory)   │       │ (Redis Lua)  │              │
│        └──────┬───────┘       └──────┬────────┘              │
│               │                      │                       │
│               ▼                      ▼                       │
│        ┌──────────────┐       ┌──────────────┐              │
│        │  Local Moka  │       │ Redis Cluster│              │
│        │   (fallback) │       │  (primary)   │              │
│        └──────────────┘       └──────────────┘              │
└─────────────────────────────────────────────────────────────┘
```

## 3. Code Structure

### 3.1 New Module: `budget.rs`

```rust
// services/mail-server/crates/rate-limiter/src/budget.rs
//
// Per-tenant budget enforcement module.
// Implements token-bucket budget checking with Redis Lua scripts.

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use deadpool_redis::redis::AsyncCommands;
use serde::{Deserialize, Serialize};

use crate::metrics::RateLimiterMetrics;

// ── Types ───────────────────────────────────────────────────────────────────

/// Budget configuration for a tenant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantBudgetConfig {
    pub tenant_id: String,
    pub monthly_quota: u64,
    pub hourly_budget: u64,
    pub burst_capacity: u64,
    pub refill_rate: f64, // tokens per second
    pub tier: BudgetTier,
    pub overrides: std::collections::HashMap<String, BudgetOverride>,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum BudgetTier {
    Critical,
    Standard,
    Bulk,
    Internal,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetOverride {
    pub monthly_quota: Option<u64>,
    pub burst_capacity: Option<u64>,
    pub tier: Option<BudgetTier>,
}

/// Decision returned by the budget checker.
#[derive(Debug, Clone)]
pub struct BudgetDecision {
    pub allowed: bool,
    pub remaining_tokens: f64,
    pub max_tokens: f64,
    pub retry_after: Option<Duration>,
    pub budget_usage_ratio: f64,
}

// ── Lua Script ──────────────────────────────────────────────────────────────

/// Redis Lua script for atomic budget check and token consumption.
/// Returns [allowed: bool, remaining: float, max_tokens: float, retry_after: float]
const BUDGET_CHECK_LUA: &str = r#"
-- KEYS[1] = {rate_limit}:budget:{tenant}:{endpoint}
-- KEYS[2] = {rate_limit}:budget:{tenant}:{endpoint}:usage
-- ARGV[1] = cost (1 per request, N for bulk)
-- ARGV[2] = current timestamp (seconds)
-- ARGV[3] = refill rate (tokens/second)
-- ARGV[4] = max tokens (burst capacity)
-- ARGV[5] = monthly_quota (for usage tracking)

local budget_key = KEYS[1]
local usage_key = KEYS[2]
local cost = tonumber(ARGV[1])
local now = tonumber(ARGV[2])
local refill_rate = tonumber(ARGV[3])
local max_tokens = tonumber(ARGV[4])
local monthly_quota = tonumber(ARGV[5])

-- Get or initialize bucket
local bucket = redis.call('HMGET', budget_key, 'tokens', 'last_refill', 'total_consumed')
local tokens = tonumber(bucket[1] or max_tokens)
local last_refill = tonumber(bucket[2] or now)
local total_consumed = tonumber(bucket[3] or 0)

-- Refill tokens based on elapsed time
local elapsed = math.max(0, now - last_refill)
local refill = elapsed * refill_rate
tokens = math.min(max_tokens, tokens + refill)

-- Check monthly quota
local budget_usage_ratio = 0
if monthly_quota > 0 then
    budget_usage_ratio = total_consumed / monthly_quota
    if budget_usage_ratio >= 1.0 then
        -- Budget exhausted, deny
        return {0, tokens, max_tokens, math.ceil(1 / refill_rate), budget_usage_ratio}
    end
end

-- Check if we have enough tokens
if tokens >= cost then
    tokens = tokens - cost
    total_consumed = total_consumed + cost

    redis.call('HMSET', budget_key,
        'tokens', tokens,
        'last_refill', now,
        'max_tokens', max_tokens,
        'refill_rate', refill_rate,
        'total_consumed', total_consumed,
        'monthly_quota', monthly_quota
    )
    -- Track hourly usage window
    local hour_key = math.floor(now / 3600)
    redis.call('HINCRBY', usage_key, 'total_used', cost)
    redis.call('HINCRBY', usage_key, 'window_' .. hour_key, cost)
    redis.call('HINCRBY', usage_key, 'burst_used_' .. hour_key, math.max(0, cost - refill))
    redis.call('EXPIRE', usage_key, 86400)

    return {1, tokens, max_tokens, 0, budget_usage_ratio}
else
    -- Calculate retry-after (seconds until enough tokens accumulated)
    local wait_time = math.ceil((cost - tokens) / refill_rate)
    -- Record throttled request
    redis.call('HINCRBY', usage_key, 'throttled_count', 1)
    return {0, tokens, max_tokens, wait_time, budget_usage_ratio}
end
"#;

// ── Budget Checker ──────────────────────────────────────────────────────────

/// Core budget checker that enforces per-tenant rate limit budgets.
pub struct BudgetChecker {
    redis_pool: deadpool_redis::Pool,
    config_cache: Arc<moka::sync::Cache<String, TenantBudgetConfig>>,
    lua_script: redis::Script,
    metrics: Option<Arc<RateLimiterMetrics>>,
    fallback_limits: FallbackLimits,
}

/// Fallback limits when Redis/budget configs are unavailable.
#[derive(Debug, Clone)]
pub struct FallbackLimits {
    pub max_requests_per_second: u64,
    pub max_burst: u64,
    pub enabled: bool,
}

impl Default for FallbackLimits {
    fn default() -> Self {
        Self {
            max_requests_per_second: 100,
            max_burst: 200,
            enabled: true,
        }
    }
}

impl BudgetChecker {
    /// Create a new BudgetChecker.
    pub fn new(
        redis_pool: deadpool_redis::Pool,
        config_cache_capacity: u64,
        metrics: Option<Arc<RateLimiterMetrics>>,
        fallback_limits: FallbackLimits,
    ) -> Self {
        Self {
            redis_pool,
            config_cache: Arc::new(
                moka::sync::Cache::builder()
                    .max_capacity(config_cache_capacity)
                    .time_to_live(Duration::from_secs(300)) // 5 min TTL
                    .build()
            ),
            lua_script: redis::Script::new(BUDGET_CHECK_LUA),
            metrics,
            fallback_limits,
        }
    }

    /// Load a tenant's budget configuration.
    /// First checks local cache, then Redis, then falls back to DB.
    async fn load_budget_config(
        &self,
        tenant_id: &str,
    ) -> Result<TenantBudgetConfig, BudgetError> {
        // Check local cache
        if let Some(config) = self.config_cache.get(tenant_id) {
            return Ok(config);
        }

        // Try Redis
        let mut conn = self.redis_pool.get().await.map_err(|e| {
            BudgetError::RedisUnavailable(e.to_string())
        })?;

        let config_key = format!("{{rate_limit}}:budget_config:{}", tenant_id);
        let config_json: Option<String> = conn.get(&config_key).await.unwrap_or(None);

        if let Some(json) = config_json {
            let config: TenantBudgetConfig = serde_json::from_str(&json)
                .map_err(|e| BudgetError::ConfigParseError(e.to_string()))?;
            self.config_cache.insert(tenant_id.to_string(), config.clone());
            return Ok(config);
        }

        Err(BudgetError::ConfigNotFound(tenant_id.to_string()))
    }

    /// Check if a request is within budget.
    pub async fn check_budget(
        &self,
        tenant_id: &str,
        endpoint: &str,
        cost: u64,
    ) -> BudgetDecision {
        let start = std::time::Instant::now();

        // Load budget config
        let config = match self.load_budget_config(tenant_id).await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(tenant = %tenant_id, error = %e, "Budget config unavailable, using fallback");
                // Fallback to global limits
                return self.fallback_decision(cost);
            }
        };

        if !config.enabled {
            return BudgetDecision {
                allowed: true,
                remaining_tokens: config.burst_capacity as f64,
                max_tokens: config.burst_capacity as f64,
                retry_after: None,
                budget_usage_ratio: 0.0,
            };
        }

        // Apply per-endpoint override if exists
        let (hourly_budget, burst_capacity, refill_rate, monthly_quota) = if let Some(override_cfg) = config.overrides.get(endpoint) {
            let hb = override_cfg.monthly_quota.map(|q| q / 720).unwrap_or(config.hourly_budget);
            let bc = override_cfg.burst_capacity.unwrap_or(config.burst_capacity);
            let rr = hb as f64 / 3600.0;
            let mq = override_cfg.monthly_quota.unwrap_or(config.monthly_quota);
            (hb, bc, rr, mq)
        } else {
            (config.hourly_budget, config.burst_capacity, config.refill_rate, config.monthly_quota)
        };

        // Execute Redis Lua script
        let result = match self.execute_budget_check(
            tenant_id, endpoint, cost,
            refill_rate, burst_capacity as f64, monthly_quota,
        ).await {
            Ok(d) => d,
            Err(e) => {
                tracing::error!(tenant = %tenant_id, endpoint = %endpoint, error = %e, "Budget check failed");
                // Fail open on Redis failure (but log aggressively)
                self.metrics.as_ref().map(|m| {
                    m.errors_total.with_label_values(&["budget_check_failed"]).inc();
                });
                return self.fallback_decision(cost);
            }
        };

        // Record metrics
        let elapsed = start.elapsed();
        if let Some(ref metrics) = self.metrics {
            metrics.check_duration
                .with_label_values(&["budget", if result.allowed { "allowed" } else { "denied" }])
                .observe(elapsed.as_secs_f64());
            metrics.tokens_remaining
                .with_label_values(&[tenant_id, endpoint])
                .set(result.remaining_tokens);
            metrics.budget_usage_ratio
                .with_label_values(&[tenant_id])
                .set(result.budget_usage_ratio);
            if !result.allowed {
                metrics.budget_throttled
                    .with_label_values(&[tenant_id, endpoint])
                    .inc();
            }
        }

        result
    }

    /// Execute the atomic budget check via Redis Lua script.
    async fn execute_budget_check(
        &self,
        tenant_id: &str,
        endpoint: &str,
        cost: u64,
        refill_rate: f64,
        max_tokens: f64,
        monthly_quota: u64,
    ) -> Result<BudgetDecision, BudgetError> {
        let mut conn = self.redis_pool.get().await
            .map_err(|e| BudgetError::RedisUnavailable(e.to_string()))?;

        let budget_key = format!("{{rate_limit}}:budget:{}:{}", tenant_id, endpoint);
        let usage_key = format!("{{rate_limit}}:budget:{}:{}:usage", tenant_id, endpoint);
        let now = Utc::now().timestamp();

        let result: Vec<redis::Value> = self.lua_script
            .key(budget_key)
            .key(usage_key)
            .arg(cost as i64)
            .arg(now)
            .arg(refill_rate)
            .arg(max_tokens)
            .arg(monthly_quota as i64)
            .invoke_async(&mut *conn)
            .await
            .map_err(|e| BudgetError::ScriptError(e.to_string()))?;

        // Parse Lua return: [allowed, remaining, max, retry_after, budget_usage]
        if result.len() < 5 {
            return Err(BudgetError::ScriptError("Unexpected return values".into()));
        }

        let allowed: bool = match &result[0] {
            redis::Value::Int(i) => *i == 1,
            _ => false,
        };
        let remaining: f64 = match &result[1] {
            redis::Value::Int(i) => *i as f64,
            redis::Value::Data(d) => {
                String::from_utf8_lossy(d).parse().unwrap_or(0.0)
            }
            _ => 0.0,
        };
        let max_tok: f64 = match &result[2] {
            redis::Value::Int(i) => *i as f64,
            _ => max_tokens,
        };
        let retry_secs: u64 = match &result[3] {
            redis::Value::Int(i) => *i as u64,
            _ => 0,
        };
        let usage_ratio: f64 = match &result[4] {
            redis::Value::Data(d) => {
                String::from_utf8_lossy(d).parse().unwrap_or(0.0)
            }
            _ => 0.0,
        };

        Ok(BudgetDecision {
            allowed,
            remaining_tokens: remaining,
            max_tokens: max_tok,
            retry_after: if retry_secs > 0 {
                Some(Duration::from_secs(retry_secs))
            } else {
                None
            },
            budget_usage_ratio: usage_ratio,
        })
    }

    /// Fallback decision when Redis is unavailable.
    fn fallback_decision(&self, cost: u64) -> BudgetDecision {
        if !self.fallback_limits.enabled {
            return BudgetDecision {
                allowed: false,
                remaining_tokens: 0.0,
                max_tokens: 0.0,
                retry_after: Some(Duration::from_secs(1)),
                budget_usage_ratio: 0.0,
            };
        }

        // Simple rate limiting: allow up to fallback limits
        BudgetDecision {
            allowed: true,
            remaining_tokens: self.fallback_limits.max_burst as f64,
            max_tokens: self.fallback_limits.max_burst as f64,
            retry_after: None,
            budget_usage_ratio: 0.0,
        }
    }

    /// Explicitly warm the budget config cache for a tenant.
    pub async fn warm_tenant_config(&self, tenant_id: &str, config: TenantBudgetConfig) {
        self.config_cache.insert(tenant_id.to_string(), config.clone());

        // Also warm Redis
        if let Ok(mut conn) = self.redis_pool.get().await {
            let config_key = format!("{{rate_limit}}:budget_config:{}", tenant_id);
            let json = serde_json::to_string(&config).unwrap_or_default();
            let _: Result<(), _> = conn.set_ex(&config_key, json, 300).await;
        }
    }
}

// ── Errors ──────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum BudgetError {
    #[error("Redis unavailable: {0}")]
    RedisUnavailable(String),

    #[error("Config not found for tenant: {0}")]
    ConfigNotFound(String),

    #[error("Config parse error: {0}")]
    ConfigParseError(String),

    #[error("Lua script error: {0}")]
    ScriptError(String),
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_budget_tier_ordering() {
        assert!(BudgetTier::Critical as u8 > BudgetTier::Standard as u8);
        assert_eq!(BudgetTier::Standard as u8, 1);
    }

    #[test]
    fn test_budget_decision_defaults() {
        let decision = BudgetDecision {
            allowed: true,
            remaining_tokens: 100.0,
            max_tokens: 100.0,
            retry_after: None,
            budget_usage_ratio: 0.5,
        };
        assert!(decision.allowed);
        assert_eq!(decision.remaining_tokens, 100.0);
        assert!(decision.retry_after.is_none());
    }

    #[test]
    fn test_tenant_budget_config_serialization() {
        let config = TenantBudgetConfig {
            tenant_id: "test-tenant".into(),
            monthly_quota: 10_000_000,
            hourly_budget: 13889,
            burst_capacity: 27778,
            refill_rate: 3.858,
            tier: BudgetTier::Standard,
            overrides: std::collections::HashMap::new(),
            enabled: true,
        };
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: TenantBudgetConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.tenant_id, "test-tenant");
        assert_eq!(deserialized.monthly_quota, 10_000_000);
        assert_eq!(deserialized.tier, BudgetTier::Standard);
    }
}
```

### 3.2 Integration with Existing Rate Limiter

```rust
// services/mail-server/crates/rate-limiter/src/lib.rs

pub mod budget;
pub mod metrics;
pub mod redis_limiter;
pub mod types;

use std::sync::Arc;

use crate::budget::{BudgetChecker, BudgetDecision, BudgetError, TenantBudgetConfig};
use crate::redis_limiter::RedisRateLimiter;

/// Combined rate limiter that applies both global rate limits
/// and per-tenant budget enforcement.
pub struct CombinedRateLimiter {
    global: RedisRateLimiter,
    budget: BudgetChecker,
}

impl CombinedRateLimiter {
    /// Check a request against both global rate limits and tenant budget.
    pub async fn check_request(
        &self,
        tenant_id: &str,
        endpoint: &str,
        api_key: &str,
        cost: u64,
    ) -> CombinedDecision {
        // 1. Check global rate limit first (fast path)
        let global_decision = self.global
            .check(api_key, tenant_id, endpoint, cost as u32)
            .await;

        if !global_decision.is_allowed() {
            return CombinedDecision {
                allowed: false,
                reason: "global_rate_limit".into(),
                retry_after: global_decision.retry_after(),
                budget_usage_ratio: 0.0,
            };
        }

        // 2. Check tenant budget
        let budget_decision = self.budget
            .check_budget(tenant_id, endpoint, cost)
            .await;

        CombinedDecision {
            allowed: budget_decision.allowed,
            reason: if budget_decision.allowed {
                "ok".into()
            } else {
                "budget_exhausted".into()
            },
            retry_after: budget_decision.retry_after,
            budget_usage_ratio: budget_decision.budget_usage_ratio,
        }
    }
}

/// Combined decision from global + budget checks.
pub struct CombinedDecision {
    pub allowed: bool,
    pub reason: String,
    pub retry_after: Option<std::time::Duration>,
    pub budget_usage_ratio: f64,
}
```

### 3.3 API Middleware Integration

```rust
// services/mail-server/crates/api-server/src/middleware/rate_limit.rs

use axum::{
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::IntoResponse,
    Json,
};
use serde_json::json;
use std::sync::Arc;

use crate::rate_limiter::CombinedRateLimiter;

pub async fn rate_limit_middleware<B>(
    State(rate_limiter): State<Arc<CombinedRateLimiter>>,
    req: Request<B>,
    next: Next<B>,
) -> impl IntoResponse {
    // Extract tenant info from request
    let tenant_id = extract_tenant_id(&req).unwrap_or("unknown");
    let endpoint = req.uri().path().to_string();
    let api_key = extract_api_key(&req);

    // Determine cost based on endpoint
    let cost = match endpoint.as_str() {
        "/v1/email/send" => 1,
        "/v1/email/batch" => 10,
        _ => 1,
    };

    // Check rate limits with budget enforcement
    let decision = rate_limiter
        .check_request(&tenant_id, &endpoint, &api_key, cost)
        .await;

    if !decision.allowed {
        let mut response = (StatusCode::TOO_MANY_REQUESTS, Json(json!({
            "error": "rate_limit_exceeded",
            "message": format!("Rate limit exceeded: {}", decision.reason),
            "retry_after": decision.retry_after.map(|d| d.as_secs()).unwrap_or(60),
            "budget_usage_ratio": decision.budget_usage_ratio,
        }))).into_response();

        if let Some(retry_after) = decision.retry_after {
            response.headers_mut().insert(
                "Retry-After",
                retry_after.as_secs().to_string().parse().unwrap(),
            );
        }
        response.headers_mut().insert(
            "X-Budget-Usage-Ratio",
            decision.budget_usage_ratio.to_string().parse().unwrap(),
        );

        return response;
    }

    // Proceed with request
    let response = next.run(req).await;

    // Add rate limit headers to response
    // (extracted from global decision)
    response
}
```

## 4. Graceful Degradation

### 4.1 Failure Modes

| Failure | Behavior | Fallback |
|---------|----------|----------|
| Redis unavailable | Budget check fails | Fall back to global in-memory limits |
| Budget config missing | Config not found | Use fallback limits (100 req/s, 200 burst) |
| Lua script error | Script execution fails | Fail open (allow) but log error |
| Config parse error | Invalid JSON config | Skip tenant, use global limits |
| Cache miss | Config not cached | Load from Redis on next request |

### 4.2 Implementation

```rust
impl BudgetChecker {
    /// Determine if we should fail open or closed.
    fn should_fail_open(&self) -> bool {
        // Fail open in production to avoid blocking legitimate traffic
        // when the budget system is degraded.
        std::env::var("BUDGET_FAIL_OPEN")
            .ok()
            .and_then(|v| v.parse::<bool>().ok())
            .unwrap_or(true) // Default: fail open
    }
}
```

## 5. Database Schema

```sql
-- See also: rate-limit-budgets.md for full schema
-- This section contains production deployment migrations

-- Migration: XXX_add_budget_enforcement.sql

-- Add budget fields to existing rate limit config
ALTER TABLE tenant_rate_limit_configs
    ADD COLUMN IF NOT EXISTS monthly_quota BIGINT NOT NULL DEFAULT 1000000,
    ADD COLUMN IF NOT EXISTS burst_capacity INT NOT NULL DEFAULT 2000,
    ADD COLUMN IF NOT EXISTS refill_rate NUMERIC(10,4) NOT NULL DEFAULT 0.2778,
    ADD COLUMN IF NOT EXISTS tier VARCHAR(20) NOT NULL DEFAULT 'standard',
    ADD COLUMN IF NOT EXISTS overrides JSONB DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS fail_open BOOLEAN NOT NULL DEFAULT true;

-- Budget usage tracking
CREATE TABLE IF NOT EXISTS tenant_budget_usage (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    date DATE NOT NULL,
    total_sent BIGINT NOT NULL DEFAULT 0,
    total_cost BIGINT NOT NULL DEFAULT 0,
    burst_used BIGINT NOT NULL DEFAULT 0,
    throttled_count BIGINT NOT NULL DEFAULT 0,
    peak_rate INT NOT NULL DEFAULT 0,
    peak_rate_time TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, date)
);

CREATE INDEX IF NOT EXISTS idx_budget_usage_tenant_date
    ON tenant_budget_usage(tenant_id, date);

-- Budget override audit log
CREATE TABLE IF NOT EXISTS tenant_budget_overrides (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    admin_user_id UUID NOT NULL,
    previous_monthly_quota BIGINT,
    new_monthly_quota BIGINT NOT NULL,
    previous_burst_capacity INT,
    new_burst_capacity INT,
    previous_tier VARCHAR(20),
    new_tier VARCHAR(20) NOT NULL,
    reason TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

## 6. Admin API Endpoints

```rust
// services/mail-server/crates/api-server/src/routes/admin/budget.rs

use axum::{
    extract::{Path, State},
    routing::{get, put, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct UpdateBudgetRequest {
    pub monthly_quota: Option<u64>,
    pub burst_capacity: Option<u64>,
    pub tier: Option<String>,
    pub reason: String,
    pub overrides: Option<std::collections::HashMap<String, BudgetEndpointOverride>>,
}

#[derive(Deserialize)]
pub struct BudgetEndpointOverride {
    pub monthly_quota: Option<u64>,
    pub burst_capacity: Option<u64>,
}

pub fn budget_admin_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/v1/admin/rate-limits/budgets", get(list_budgets))
        .route("/v1/admin/rate-limits/budgets/{tenant_id}", get(get_budget))
        .route("/v1/admin/rate-limits/budgets/{tenant_id}", put(update_budget))
        .route("/v1/admin/rate-limits/budgets/{tenant_id}/reset", post(reset_budget))
        .route("/v1/admin/rate-limits/budgets/{tenant_id}/usage", get(get_usage))
        .route("/v1/admin/rate-limits/budgets/{tenant_id}/overrides", get(get_overrides))
}
```

## 7. Audit Logging

Every budget enforcement decision is logged with the following structure:

```rust
#[derive(Debug, Serialize)]
pub struct BudgetAuditEvent {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub tenant_id: String,
    pub endpoint: String,
    pub cost: u64,
    pub allowed: bool,
    pub remaining_tokens: f64,
    pub budget_usage_ratio: f64,
    pub retry_after: Option<u64>,
    pub decision_time_ms: f64,
    pub redis_available: bool,
}

impl BudgetAuditEvent {
    pub fn log(&self) {
        if !self.allowed {
            tracing::warn!(
                tenant = %self.tenant_id,
                endpoint = %self.endpoint,
                cost = self.cost,
                remaining = self.remaining_tokens,
                usage = self.budget_usage_ratio,
                "Budget enforcement: request denied"
            );
        } else if self.budget_usage_ratio > 0.8 {
            tracing::info!(
                tenant = %self.tenant_id,
                usage = self.budget_usage_ratio,
                "Budget enforcement: near limit"
            );
        }
    }
}
```

## 8. Implementation Plan

### Phase 1: Core (Week 1)
1. Create [`budget.rs`](#31-new-module-budgetrs) module with Lua script
2. Implement `BudgetChecker` struct
3. Add `CombinedRateLimiter` to `lib.rs`
4. Write unit tests for budget logic
5. Write integration tests for Lua script

### Phase 2: Integration (Week 2)
1. Integrate budget checker into API server middleware
2. Add budget config loading from database
3. Implement graceful degradation paths
4. Add budget metrics (see [`rate-limiter-metrics.md`](rate-limiter-metrics.md))
5. Deploy to staging for validation

### Phase 3: Admin API (Week 3)
1. Implement budget admin endpoints
2. Add budget override audit logging
3. Create budget management UI (optional)
4. Deploy to production with feature flag

### Phase 4: Monitoring (Week 4)
1. Create budget Grafana dashboard panels
2. Configure budget alerting rules
3. Run load tests with budget enforcement
4. Tune budget parameters based on real traffic
