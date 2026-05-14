# Rate Limiter Prometheus Metrics

> **Document Owner:** Backend Team
> **Last Updated:** 2026-05-11
> **Related:** [`rate-limiter/src/redis_limiter.rs`](../../services/mail-server/crates/rate-limiter/src/redis_limiter.rs), [`rate-limiter/src/types.rs`](../../services/mail-server/crates/rate-limiter/src/types.rs), [`rate-limit-budgets.md`](rate-limit-budgets.md), [`rate-limit-budget-enforcement.md`](rate-limit-budget-enforcement.md)

## 1. Overview

The rate limiter currently lacks Prometheus metrics exposure. This document defines a comprehensive metrics plan covering:

- Requests allowed/denied counts
- Current token counts per tenant
- Wait times for throttled requests
- Budget consumption and exhaustion
- Performance histograms

## 2. Metric Definitions

### 2.1 Core Rate Limiter Metrics

| Metric Name | Type | Description |
|-------------|------|-------------|
| `rate_limiter_requests_total` | Counter | Total requests processed by rate limiter |
| `rate_limiter_requests_allowed_total` | Counter | Requests that passed rate limit check |
| `rate_limiter_requests_denied_total` | Counter | Requests denied by rate limiter |
| `rate_limiter_requests_inflight` | Gauge | Currently in-flight requests being checked |
| `rate_limiter_check_duration_seconds` | Histogram | Time to evaluate a rate limit decision |
| `rate_limiter_cache_hits_total` | Counter | Rate limit cache hits |
| `rate_limiter_cache_misses_total` | Counter | Rate limit cache misses |
| `rate_limiter_errors_total` | Counter | Rate limiter internal errors (Redis failures, etc.) |

### 2.2 Token Bucket Metrics

| Metric Name | Type | Description |
|-------------|------|-------------|
| `rate_limiter_tokens_remaining` | Gauge | Current available tokens per (tenant, endpoint) |
| `rate_limiter_tokens_max` | Gauge | Maximum token capacity per (tenant, endpoint) |
| `rate_limiter_bucket_refill_rate` | Gauge | Tokens per second refill rate |
| `rate_limiter_bucket_wait_time_seconds` | Gauge | Current wait time for next available token |

### 2.3 Budget Metrics

| Metric Name | Type | Description |
|-------------|------|-------------|
| `rate_limiter_budget_usage_ratio` | Gauge | Fraction of budget consumed (0.0 to 1.0) |
| `rate_limiter_budget_exhausted` | Gauge | 1 if budget exhausted, 0 otherwise |
| `rate_limiter_budget_used_total` | Counter | Total tokens consumed towards budget |
| `rate_limiter_budget_throttled_total` | Counter | Requests throttled due to budget exhaustion |
| `rate_limiter_budget_errors_total` | Counter | Budget enforcement errors |

### 2.4 Concurrency Metrics

| Metric Name | Type | Description |
|-------------|------|-------------|
| `rate_limiter_concurrent_limit` | Gauge | Maximum concurrent requests allowed |
| `rate_limiter_concurrent_inflight` | Gauge | Current inflight request count |
| `rate_limiter_concurrent_queued` | Gauge | Requests waiting for concurrency slot |

## 3. Metric Implementation

### 3.1 Rust Implementation

```rust
use prometheus::{
    register_counter_vec, register_gauge_vec, register_histogram_vec,
    CounterVec, GaugeVec, HistogramVec, IntCounterVec, IntGaugeVec,
};

#[derive(Clone)]
pub struct RateLimiterMetrics {
    // Core counters
    pub requests_total: IntCounterVec,
    pub requests_allowed: IntCounterVec,
    pub requests_denied: IntCounterVec,
    pub requests_inflight: IntGaugeVec,

    // Latency histograms
    pub check_duration: HistogramVec,

    // Cache metrics
    pub cache_hits: IntCounterVec,
    pub cache_misses: IntCounterVec,

    // Error tracking
    pub errors_total: IntCounterVec,

    // Token bucket gauges
    pub tokens_remaining: GaugeVec,
    pub tokens_max: GaugeVec,

    // Budget metrics
    pub budget_usage_ratio: GaugeVec,
    pub budget_exhausted: GaugeVec,
    pub budget_throttled: IntCounterVec,
}

impl RateLimiterMetrics {
    pub fn new(registry: &prometheus::Registry) -> Result<Self, prometheus::Error> {
        let metrics = Self {
            requests_total: register_counter_vec!(
                "rate_limiter_requests_total",
                "Total requests processed by rate limiter",
                &["tenant", "endpoint", "limiter_type"],
                registry,
            )?,
            requests_allowed: register_counter_vec!(
                "rate_limiter_requests_allowed_total",
                "Requests that passed rate limit check",
                &["tenant", "endpoint", "limiter_type"],
                registry,
            )?,
            requests_denied: register_counter_vec!(
                "rate_limiter_requests_denied_total",
                "Requests denied by rate limiter",
                &["tenant", "endpoint", "reason", "limiter_type"],
                registry,
            )?,
            requests_inflight: register_int_gauge_vec!(
                "rate_limiter_requests_inflight",
                "Currently in-flight requests being checked",
                &["limiter_type"],
                registry,
            )?,
            check_duration: register_histogram_vec!(
                "rate_limiter_check_duration_seconds",
                "Time to evaluate a rate limit decision",
                &["limiter_type", "result"],
                vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0],
                registry,
            )?,
            cache_hits: register_int_counter_vec!(
                "rate_limiter_cache_hits_total",
                "Rate limit cache hits",
                &["cache_type"],
                registry,
            )?,
            cache_misses: register_int_counter_vec!(
                "rate_limiter_cache_misses_total",
                "Rate limit cache misses",
                &["cache_type"],
                registry,
            )?,
            errors_total: register_int_counter_vec!(
                "rate_limiter_errors_total",
                "Rate limiter internal errors",
                &["error_type"],
                registry,
            )?,
            tokens_remaining: register_gauge_vec!(
                "rate_limiter_tokens_remaining",
                "Current available tokens per tenant/endpoint",
                &["tenant", "endpoint"],
                registry,
            )?,
            tokens_max: register_gauge_vec!(
                "rate_limiter_tokens_max",
                "Maximum token capacity per tenant/endpoint",
                &["tenant", "endpoint"],
                registry,
            )?,
            budget_usage_ratio: register_gauge_vec!(
                "rate_limiter_budget_usage_ratio",
                "Fraction of budget consumed (0.0 to 1.0)",
                &["tenant"],
                registry,
            )?,
            budget_exhausted: register_gauge_vec!(
                "rate_limiter_budget_exhausted",
                "1 if budget exhausted, 0 otherwise",
                &["tenant"],
                registry,
            )?,
            budget_throttled: register_int_counter_vec!(
                "rate_limiter_budget_throttled_total",
                "Requests throttled due to budget exhaustion",
                &["tenant", "endpoint"],
                registry,
            )?,
        };

        Ok(metrics)
    }
}
```

### 3.2 Integration with Rate Limiter

```rust
use prometheus::Registry;
use std::sync::Arc;

pub struct InstrumentedRateLimiter {
    inner: RedisRateLimiter,
    metrics: RateLimiterMetrics,
}

impl InstrumentedRateLimiter {
    pub fn new(
        redis_pool: deadpool_redis::Pool,
        registry: &Registry,
    ) -> Result<Self, prometheus::Error> {
        Ok(Self {
            inner: RedisRateLimiter::new(redis_pool),
            metrics: RateLimiterMetrics::new(registry)?,
        })
    }

    pub async fn check(
        &self,
        key: &str,
        tenant_id: &str,
        endpoint: &str,
        cost: u32,
        limiter_type: &str,
    ) -> Decision {
        let _inflight = self.metrics.requests_inflight
            .with_label_values(&[limiter_type])
            .inc();

        let start = std::time::Instant::now();
        let decision = self.inner.check(key, tenant_id, endpoint, cost).await;

        let duration = start.elapsed();
        let result = if decision.is_allowed() { "allowed" } else { "denied" };

        self.metrics.check_duration
            .with_label_values(&[limiter_type, result])
            .observe(duration.as_secs_f64());

        self.metrics.requests_total
            .with_label_values(&[tenant_id, endpoint, limiter_type])
            .inc();

        match &decision {
            Decision::Allowed { .. } => {
                self.metrics.requests_allowed
                    .with_label_values(&[tenant_id, endpoint, limiter_type])
                    .inc();
            }
            Decision::Denied { reason, .. } => {
                self.metrics.requests_denied
                    .with_label_values(&[tenant_id, endpoint, reason, limiter_type])
                    .inc();
            }
        }

        self.metrics.requests_inflight
            .with_label_values(&[limiter_type])
            .dec();

        decision
    }
}
```

## 4. Prometheus Metric Naming Convention

All rate limiter metrics follow the convention:

```
rate_limiter_<metric_name>_<unit>
```

| Prefix | Component | Example |
|--------|-----------|---------|
| `rate_limiter_` | Root namespace | `rate_limiter_requests_total` |
| `rate_limiter_cache_` | Cache subsystem | `rate_limiter_cache_hits_total` |
| `rate_limiter_budget_` | Budget subsystem | `rate_limiter_budget_usage_ratio` |
| `rate_limiter_bucket_` | Token bucket subsystem | `rate_limiter_bucket_refill_rate` |
| `rate_limiter_concurrent_` | Concurrency limiter | `rate_limiter_concurrent_inflight` |

## 5. Label Dimensions

| Label | Description | Cardinality | Example Values |
|-------|-------------|-------------|----------------|
| `tenant` | Tenant identifier | Medium (100-1000) | `tenant-abc123`, `acme-corp` |
| `endpoint` | API endpoint path | Low (10-50) | `/v1/email/send`, `/v1/analytics` |
| `limiter_type` | Type of rate limiter | Low (5-10) | `global`, `tenant`, `endpoint`, `ip`, `concurrent` |
| `reason` | Denial reason | Low (5-10) | `rate_exceeded`, `budget_exhausted`, `concurrent_limit` |
| `result` | Check result | Low (2) | `allowed`, `denied` |
| `error_type` | Error category | Low (5) | `redis_unavailable`, `script_error`, `config_missing` |
| `cache_type` | Cache layer | Low (2) | `local_moka`, `redis` |

## 6. Histogram Buckets

### 6.1 Check Duration

```rust
vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]
//   1ms    5ms    10ms   25ms   50ms   100ms  250ms  500ms  1s
```

Typical values:
- **Local rate limiter (moka):** 10-50µs → all in the smallest bucket
- **Redis rate limiter:** 1-5ms → p50 in 1ms bucket, p99 in 5ms bucket
- **Budget check (Redis Lua):** 2-10ms

### 6.2 Token Wait Time

```rust
vec![0.001, 0.01, 0.1, 0.5, 1.0, 5.0, 10.0, 30.0, 60.0]
//   1ms   10ms  100ms 500ms 1s    5s    10s   30s   60s
```

## 7. Metric Registration

### 7.1 Application Setup

```rust
use prometheus::Registry;
use std::sync::OnceLock;

static RATE_LIMITER_METRICS: OnceLock<RateLimiterMetrics> = OnceLock::new();

pub fn init_rate_limiter_metrics(registry: &Registry) -> &RateLimiterMetrics {
    RATE_LIMITER_METRICS.get_or_init(|| {
        RateLimiterMetrics::new(registry)
            .expect("Failed to register rate limiter metrics")
    })
}

pub fn rate_limiter_metrics() -> &'static RateLimiterMetrics {
    RATE_LIMITER_METRICS.get()
        .expect("Rate limiter metrics not initialized")
}
```

### 7.2 Prometheus Endpoint

```rust
use axum::{Router, routing::get};
use prometheus::Registry;

async fn metrics_handler(registry: &Registry) -> String {
    use prometheus::Encoder;
    let encoder = prometheus::TextEncoder::new();
    let mut buffer = String::new();
    encoder.encode(&registry.gather(), &mut buffer).unwrap();
    buffer
}

pub fn metrics_router(registry: Registry) -> Router {
    Router::new()
        .route("/metrics", get(move || {
            let registry = registry.clone();
            async move { metrics_handler(&registry).await }
        }))
}
```

## 8. Grafana Dashboard Panel Queries

### 8.1 Request Rate

```promql
# Rate of requests allowed vs denied
sum(rate(rate_limiter_requests_allowed_total[5m])) by (tenant)
sum(rate(rate_limiter_requests_denied_total[5m])) by (tenant, reason)
```

### 8.2 Denial Rate

```promql
# Denial ratio per tenant
sum(rate(rate_limiter_requests_denied_total[5m])) by (tenant)
/ (sum(rate(rate_limiter_requests_allowed_total[5m])) by (tenant)
   + sum(rate(rate_limiter_requests_denied_total[5m])) by (tenant))
```

### 8.3 Check Duration

```promql
# p95 check duration
histogram_quantile(0.95,
  sum(rate(rate_limiter_check_duration_seconds_bucket[5m])) by (le, limiter_type)
)
```

### 8.4 Token Remaining

```promql
# Token remaining by tenant
rate_limiter_tokens_remaining{tenant="$tenant"}
```

### 8.5 Budget Usage

```promql
# Budget usage ratio by tenant
rate_limiter_budget_usage_ratio{tenant="$tenant"}
```

### 8.6 Error Rate

```promql
# Rate limiter errors
sum(rate(rate_limiter_errors_total[5m])) by (error_type)
```

## 9. Dashboard Panel Layout

### Row 1: Overview (Stat Panels)
- **Requests/sec** — `sum(rate(rate_limiter_requests_total[5m]))`
- **Allow Rate** — `sum(rate(rate_limiter_requests_allowed_total[5m]))`
- **Deny Rate** — `sum(rate(rate_limiter_requests_denied_total[5m]))`
- **Error Rate** — `sum(rate(rate_limiter_errors_total[5m]))`

### Row 2: Latency (Time Series)
- **p50/p95/p99 Check Duration** — histogram_quantile queries
- **Cached vs Redis latency** — split by limiter_type

### Row 3: Tenants (Table)
- **Top 10 Tenants by Request Rate**
- **Top 10 Tenants by Denial Rate**
- **Budget Exhaustion Events**

### Row 4: Budget (Time Series)
- **Budget Usage by Tenant** — stacked area chart
- **Tokens Remaining by Tenant** — line chart
- **Budget Exhausted Flag** — threshold visualization

## 10. Alerting Rules

```yaml
- alert: RateLimiterHighDenialRate
  expr: sum(rate(rate_limiter_requests_denied_total[5m])) / sum(rate(rate_limiter_requests_total[5m])) > 0.10
  for: 5m
  labels:
    severity: warning
  annotations:
    summary: "Rate limiter denial rate above 10%"

- alert: RateLimiterHighErrorRate
  expr: sum(rate(rate_limiter_errors_total[5m])) > 0
  for: 5m
  labels:
    severity: warning
  annotations:
    summary: "Rate limiter errors detected"

- alert: RateLimiterHighLatency
  expr: histogram_quantile(0.95, sum(rate(rate_limiter_check_duration_seconds_bucket[5m])) by (le)) > 0.1
  for: 5m
  labels:
    severity: warning
  annotations:
    summary: "Rate limiter p95 latency above 100ms"
```

## 11. Implementation Priority

| Priority | Metric | Effort | Impact |
|----------|--------|--------|--------|
| P0 | `requests_total`, `requests_allowed`, `requests_denied` | 1 day | Critical for operations |
| P0 | `check_duration_seconds` histogram | 1 day | Critical for SLO tracking |
| P1 | `tokens_remaining`, `tokens_max` | 2 days | Important for capacity planning |
| P1 | `errors_total` | 0.5 day | Important for reliability |
| P2 | `budget_*` metrics | 2 days | Needed after budget enforcement |
| P2 | `cache_hits`, `cache_misses` | 0.5 day | Cache tuning |
| P3 | `concurrent_*` metrics | 1 day | Advanced monitoring |
