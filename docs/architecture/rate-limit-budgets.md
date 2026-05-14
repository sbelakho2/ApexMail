# Per-Tenant Rate Limit Budgets

> **Document Owner:** Backend Team
> **Last Updated:** 2026-05-11
> **Related:** [`rate-limit-budget-enforcement.md`](rate-limit-budget-enforcement.md), [`rate-limiter-metrics.md`](rate-limiter-metrics.md), [`rate-limiter/src/redis_limiter.rs`](../../services/mail-server/crates/rate-limiter/src/redis_limiter.rs)

## 1. Overview

Rate limits are currently enforced globally across all tenants. This document defines a per-tenant rate limit budget system that provides:

- **Fair resource allocation** — Each tenant receives a guaranteed share of system capacity
- **Burst handling** — Tenants can accumulate unused capacity for short bursts
- **Budget overrides** — Administrative API for adjusting tenant budgets
- **Monitoring** — Visibility into budget consumption and exhaustion

## 2. Budget Model

### 2.1 Budget Definition

Each tenant is assigned a **monthly email quota** (e.g., 10 million emails/month). This is converted to an **hourly budget**:

```
hourly_budget = monthly_quota / (30 * 24)
burst_capacity = hourly_budget * 2  (accumulated up to 2x hourly rate)
```

| Plan | Monthly Quota | Hourly Budget | Burst Capacity | Enforcement |
|------|---------------|---------------|----------------|-------------|
| Free | 10,000 | ~14 | 28 | Strict |
| Starter | 50,000 | ~69 | 138 | Strict |
| Growth | 500,000 | ~694 | 1,388 | Standard |
| Scale | 5,000,000 | ~6,944 | 13,888 | Standard |
| Enterprise | Custom | Custom | Custom | Custom |

### 2.2 Token Bucket Algorithm

The budget is implemented as a **token bucket** per tenant, stored in Redis:

```
Key: rate_limit:budget:{tenant_id}:{endpoint}
Fields:
  - tokens: current available tokens (float)
  - max_tokens: maximum token capacity (float)
  - refill_rate: tokens per second (float)
  - last_refill: unix timestamp of last refill (int)
  - window_start: start of current window (int)
```

```lua
-- Redis Lua script: budget_check.lua
-- KEYS[1] = rate_limit:budget:{tenant}:{endpoint}
-- KEYS[2] = rate_limit:budget:{tenant}:{endpoint}:usage
-- ARGV[1] = cost (1 per request, N for bulk)
-- ARGV[2] = current timestamp
-- ARGV[3] = refill rate (tokens/second)
-- ARGV[4] = max tokens (burst capacity)

local budget_key = KEYS[1]
local usage_key = KEYS[2]
local cost = tonumber(ARGV[1])
local now = tonumber(ARGV[2])
local refill_rate = tonumber(ARGV[3])
local max_tokens = tonumber(ARGV[4])

-- Get or initialize bucket
local bucket = redis.call('HMGET', budget_key, 'tokens', 'last_refill')
local tokens = tonumber(bucket[1] or max_tokens)
local last_refill = tonumber(bucket[2] or now)

-- Refill tokens based on elapsed time
local elapsed = math.max(0, now - last_refill)
local refill = elapsed * refill_rate
tokens = math.min(max_tokens, tokens + refill)

-- Check if we have enough tokens
if tokens >= cost then
    tokens = tokens - cost
    redis.call('HMSET', budget_key,
        'tokens', tokens,
        'last_refill', now,
        'max_tokens', max_tokens,
        'refill_rate', refill_rate
    )
    -- Track usage
    redis.call('HINCRBY', usage_key, 'total_used', cost)
    redis.call('HINCRBY', usage_key, 'window_used_' .. math.floor(now / 3600), cost)
    redis.call('EXPIRE', usage_key, 86400)
    return {1, tokens, max_tokens}  -- allowed, remaining, limit
else
    -- Calculate retry-after
    local wait_time = math.ceil((cost - tokens) / refill_rate)
    return {0, tokens, max_tokens, wait_time}  -- denied, remaining, limit, retry_after
end
```

### 2.3 Burst Handling

- **Token accumulation:** Unused tokens accumulate up to `burst_capacity` (2x hourly rate)
- **Burst window:** Tokens accumulated over the last 30 minutes can be consumed instantly
- **Exhaustion:** When tokens are exhausted, requests are queued for `retry_after` seconds
- **Overdraft protection:** Tenants cannot go below 0 tokens (no negative balance)

### 2.4 Budget Tiers

| Tier | Description | Refill Rate | Burst Ratio | Priority |
|------|-------------|-------------|-------------|----------|
| `critical` | Real-time email (transactional) | 2x hourly rate | 3x | Highest |
| `standard` | Marketing campaigns | 1x hourly rate | 2x | Normal |
| `bulk` | Batch processing | 0.5x hourly rate | 1.5x | Low |
| `internal` | System/internal traffic | 10x hourly rate | 10x | Highest |

## 3. Database Schema

```sql
-- Tenant rate limit budget configuration
CREATE TABLE tenant_rate_limit_budgets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    monthly_quota BIGINT NOT NULL,           -- Monthly email quota
    hourly_budget INTEGER NOT NULL,           -- Computed hourly budget
    burst_capacity INTEGER NOT NULL,          -- Max tokens in bucket
    refill_rate NUMERIC(10, 4) NOT NULL,      -- Tokens per second
    tier VARCHAR(20) NOT NULL DEFAULT 'standard',  -- Budget tier
    overrides JSONB DEFAULT '{}',             -- Per-endpoint overrides
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id)
);

-- Budget usage tracking (aggregated)
CREATE TABLE tenant_budget_usage (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    date DATE NOT NULL,                       -- Date of usage
    total_sent BIGINT NOT NULL DEFAULT 0,     -- Total emails sent
    total_cost BIGINT NOT NULL DEFAULT 0,     -- Total budget consumed
    burst_used BIGINT NOT NULL DEFAULT 0,     -- Emails sent during burst
    throttled_count BIGINT NOT NULL DEFAULT 0,-- Requests throttled
    peak_rate INTEGER NOT NULL DEFAULT 0,     -- Peak requests per second
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, date)
);

CREATE INDEX idx_tenant_budget_usage_tenant_date
    ON tenant_budget_usage(tenant_id, date);

-- Budget override audit log
CREATE TABLE tenant_budget_overrides (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    admin_user_id UUID NOT NULL,
    previous_monthly_quota BIGINT,
    new_monthly_quota BIGINT NOT NULL,
    reason TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

## 4. Budget Allocation Algorithm

### 4.1 Initial Allocation

On tenant creation:

1. Look up the tenant's plan in the billing system
2. Map the plan to a monthly quota
3. Compute `hourly_budget = monthly_quota / 720` (720 hours in 30 days)
4. Compute `burst_capacity = hourly_budget * 2`
5. Compute `refill_rate = hourly_budget / 3600` (tokens per second)
6. Store the budget configuration in `tenant_rate_limit_budgets`
7. Initialize the Redis token bucket

### 4.2 Dynamic Adjustment

When a tenant upgrades/downgrades plans:

1. The billing system webhook triggers a budget update
2. New quota values are computed
3. The Redis bucket is updated with new max tokens and refill rate
4. Current token count is preserved (capped at new max_tokens)
5. The override is logged in `tenant_budget_overrides`

### 4.3 Budget Exhaustion Handling

When a tenant exhausts their budget:

1. **Soft limit (80%):** Warning log, rate limit headers indicate approaching limit
2. **Hard limit (100%):** Requests are denied with HTTP 429
3. **Critical:** Admin notified via alert
4. **Overdraft:** If `overdraft_enabled=true` and system has capacity, allow limited excess at lower priority

## 5. Integration with Rate Limiter

### 5.1 Request Flow

```
Request → API Gateway
  → Check rate_limit:budget:{tenant}:{endpoint} (Redis Lua script)
    → Sufficient budget? → Forward request → Deduct tokens
    → Insufficient budget? → Return 429 with Retry-After header
  → Log usage metrics
```

### 5.2 Rate Limiter Types

| Type | Budget Scope | Redis Key Pattern | Description |
|------|-------------|-------------------|-------------|
| Global | System-wide | `rate_limit:global` | Prevents system overload |
| Per-Tenant | Tenant-level | `rate_limit:budget:{tenant}` | Enforces tenant budgets |
| Per-Endpoint | Endpoint-level | `rate_limit:budget:{tenant}:{endpoint}` | Fine-grained control |
| Per-IP | Client-level | `rate_limit:ip:{client_ip}` | Prevents abuse |

### 5.3 Code Integration

```rust
use redis::AsyncCommands;

pub struct BudgetChecker {
    redis: deadpool_redis::Pool,
    lua_script: redis::Script,
}

impl BudgetChecker {
    pub async fn check_budget(
        &self,
        tenant_id: &str,
        endpoint: &str,
        cost: u32,
    ) -> Result<BudgetDecision, BudgetError> {
        let mut conn = self.redis.get().await?;
        let budget_key = format!("rate_limit:budget:{}:{}", tenant_id, endpoint);
        let usage_key = format!("rate_limit:budget:{}:{}:usage", tenant_id, endpoint);

        let result: (bool, f64, f64, Option<u64>) = self.lua_script
            .key(budget_key)
            .key(usage_key)
            .arg(cost)
            .arg(chrono::Utc::now().timestamp())
            .arg(REFILL_RATE)
            .arg(MAX_TOKENS)
            .invoke_async(&mut *conn)
            .await?;

        Ok(BudgetDecision {
            allowed: result.0,
            remaining: result.1 as u64,
            limit: result.2 as u64,
            retry_after: result.3,
        })
    }
}
```

## 6. Admin API

### 6.1 Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/v1/admin/rate-limits/budgets` | List all tenant budgets |
| `GET` | `/v1/admin/rate-limits/budgets/{tenant_id}` | Get tenant budget |
| `PUT` | `/v1/admin/rate-limits/budgets/{tenant_id}` | Update tenant budget |
| `POST` | `/v1/admin/rate-limits/budgets/{tenant_id}/reset` | Reset budget counter |
| `GET` | `/v1/admin/rate-limits/budgets/{tenant_id}/usage` | Get usage history |
| `GET` | `/v1/admin/rate-limits/budgets/{tenant_id}/overrides` | Get override history |

### 6.2 Update Payload

```json
{
  "monthly_quota": 20000000,
  "burst_capacity": 50000,
  "tier": "critical",
  "reason": "Customer upgraded to Enterprise plan",
  "overrides": {
    "/v1/email/send": { "monthly_quota": 10000000 },
    "/v1/analytics": { "monthly_quota": 5000000 }
  }
}
```

## 7. Monitoring & Alerting

### 7.1 Prometheus Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `rate_limiter_budget_tokens_total` | Gauge | `tenant`, `endpoint` | Current token count |
| `rate_limiter_budget_max_tokens` | Gauge | `tenant`, `endpoint` | Max token capacity |
| `rate_limiter_budget_used_total` | Counter | `tenant`, `endpoint` | Total tokens consumed |
| `rate_limiter_budget_throttled_total` | Counter | `tenant`, `endpoint` | Requests denied due to budget |
| `rate_limiter_budget_exhaustion_timestamp` | Gauge | `tenant` | Last budget exhaustion time |

### 7.2 Grafana Dashboard Panels

- **Budget Utilization by Tenant:** Heatmap showing which tenants are approaching their limits
- **Budget Exhaustion Events:** Time series of throttled requests
- **Top Tenants by Usage:** Sorted table of highest-consuming tenants
- **Burst Usage:** Visualization of burst vs steady-state traffic

### 7.3 Alerting Rules

```yaml
- alert: TenantBudget80Percent
  expr: (rate_limiter_budget_used_total[1h]) / (rate_limiter_budget_max_tokens * 3600) > 0.8
  for: 30m
  labels:
    severity: warning
  annotations:
    summary: "Tenant {{ $labels.tenant }} has used 80% of budget"

- alert: TenantBudgetExhausted
  expr: rate_limiter_budget_throttled_total > 0
  for: 5m
  labels:
    severity: warning
  annotations:
    summary: "Tenant {{ $labels.tenant }} budget exhausted"
```

## 8. Graceful Degradation

When the budget enforcement system fails:

1. **Redis unavailable:** Fall back to global rate limits (in-memory governor)
2. **Database unavailable:** Use cached budget config from local moka cache
3. **Script error:** Allow request but log error; increment error counter
4. **All systems down:** Emergency fallback to hardcoded maximum limits

## 9. Migration Plan

### Phase 1: Database (Week 1)
- Create `tenant_rate_limit_budgets` table
- Create `tenant_budget_usage` table
- Create migration script to populate budgets for existing tenants
- Backfill usage data from delivery logs

### Phase 2: Redis + Lua (Week 2)
- Deploy Redis Lua scripts
- Implement BudgetChecker in rate-limiter crate
- Add budget check to request pipeline
- Deploy to staging and validate

### Phase 3: Admin API (Week 3)
- Implement admin API endpoints
- Add UI for budget management
- Deploy budget override audit logging

### Phase 4: Monitoring (Week 4)
- Deploy Prometheus metrics
- Create Grafana dashboards
- Configure alerting rules
- Validate with load testing
