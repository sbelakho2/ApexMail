//! Cost-based rate limiting - weight requests by resource consumption

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use once_cell::sync::Lazy;
use parking_lot::RwLock;

/// Request cost dimensions
#[derive(Debug, Clone, Default)]
pub struct RequestCost {
    /// CPU cycles estimate (microseconds)
    pub cpu_us: u32,
    /// Memory allocation estimate (bytes)
    pub memory_bytes: u32,
    /// I/O operations count
    pub io_ops: u32,
    /// External API calls
    pub external_calls: u32,
}

impl RequestCost {
    /// Create a new request cost
    pub fn new(cpu_us: u32, memory_bytes: u32, io_ops: u32, external_calls: u32) -> Self {
        Self {
            cpu_us,
            memory_bytes,
            io_ops,
            external_calls,
        }
    }

    /// Convert to unified cost units
    /// 1 cost unit = 1μs CPU = 1KB memory = 10 IO ops = 100 external calls
    pub fn total_cost(&self) -> u64 {
        (self.cpu_us as u64)
            + (self.memory_bytes as u64 / 1024)
            + (self.io_ops as u64 * 10)
            + (self.external_calls as u64 * 100)
    }
}

/// Endpoint cost registry
pub static ENDPOINT_COSTS: Lazy<HashMap<&'static str, RequestCost>> = Lazy::new(|| {
    let mut m = HashMap::new();

    // High-cost endpoints
    m.insert(
        "/v1/messages/send",
        RequestCost::new(5000, 1024 * 1024, 5, 1),
    );
    m.insert(
        "/v1/messages/send/batch",
        RequestCost::new(50000, 10 * 1024 * 1024, 50, 10),
    );
    m.insert(
        "/v1/templates/render",
        RequestCost::new(10000, 512 * 1024, 2, 0),
    );
    m.insert("/v1/domains/verify", RequestCost::new(5000, 4096, 10, 2));

    // Medium-cost endpoints
    m.insert("/v1/messages", RequestCost::new(1000, 65536, 2, 0));
    m.insert("/v1/analytics/events", RequestCost::new(2000, 32768, 3, 0));

    // Low-cost endpoints
    m.insert("/v1/messages/:id", RequestCost::new(100, 4096, 1, 0));
    m.insert("/v1/health", RequestCost::new(10, 256, 0, 0));
    m.insert("/v1/ping", RequestCost::new(5, 128, 0, 0));

    m
});

/// Configuration for cost-based limiter
#[derive(Debug, Clone)]
pub struct CostLimiterConfig {
    /// Default budget per tenant per minute
    pub default_tenant_budget: u64,
    /// System-wide capacity
    pub system_capacity: u64,
}

impl Default for CostLimiterConfig {
    fn default() -> Self {
        Self {
            default_tenant_budget: 100_000,
            system_capacity: 10_000_000,
        }
    }
}

/// Per-tenant budget state
struct TenantBudget {
    remaining: u64,
    capacity: u64,
    last_refill: Instant,
    refill_rate: u64, // Cost units per second
}

/// Cost-based rate limiter
pub struct CostBasedLimiter {
    /// Per-tenant cost budgets
    tenant_budgets: Arc<DashMap<String, RwLock<TenantBudget>>>,
    /// Default budget for new tenants
    default_budget: u64,
    /// Global system budget
    system_budget: Arc<AtomicU64>,
    /// System capacity
    system_capacity: u64,
}

impl CostBasedLimiter {
    /// Create a new cost-based limiter
    pub fn new(config: CostLimiterConfig) -> Self {
        Self {
            tenant_budgets: Arc::new(DashMap::new()),
            default_budget: config.default_tenant_budget,
            system_budget: Arc::new(AtomicU64::new(config.system_capacity)),
            system_capacity: config.system_capacity,
        }
    }

    /// Check if request is allowed based on its cost
    pub fn check(
        &self,
        tenant_id: &str,
        endpoint: &str,
        override_cost: Option<RequestCost>,
    ) -> CostDecision {
        let cost = override_cost
            .or_else(|| ENDPOINT_COSTS.get(endpoint).cloned())
            .unwrap_or(RequestCost::new(1000, 10240, 1, 0));

        let total_cost = cost.total_cost();

        // Reserve system-wide budget first using CAS to avoid TOCTOU race
        if !self.reserve_system_budget(total_cost) {
            return CostDecision::SystemOverloaded {
                retry_after: Duration::from_secs(5),
            };
        }

        // Check tenant budget
        let budget_entry = self
            .tenant_budgets
            .entry(tenant_id.to_string())
            .or_insert_with(|| {
                RwLock::new(TenantBudget {
                    remaining: self.default_budget,
                    capacity: self.default_budget,
                    last_refill: Instant::now(),
                    refill_rate: self.default_budget / 60, // Per second
                })
            });

        let mut budget = budget_entry.write();

        // Refill based on time elapsed
        let elapsed = budget.last_refill.elapsed();
        let refill_amount = elapsed.as_secs() * budget.refill_rate;
        budget.remaining = (budget.remaining + refill_amount).min(budget.capacity);
        budget.last_refill = Instant::now();

        if total_cost > budget.remaining {
            let wait_secs = (total_cost - budget.remaining) / budget.refill_rate.max(1) + 1;
            // Tenant exceeded quota after system reservation; refund reservation.
            self.refund_system_budget(total_cost);
            return CostDecision::QuotaExceeded {
                remaining: budget.remaining,
                retry_after: Duration::from_secs(wait_secs),
            };
        }

        // Deduct cost
        budget.remaining -= total_cost;

        CostDecision::Allowed {
            cost: total_cost,
            remaining: budget.remaining,
        }
    }

    /// Record a request cost after the fact (for async operations)
    pub fn record_cost(&self, tenant_id: &str, cost: u64) {
        if let Some(entry) = self.tenant_budgets.get(tenant_id) {
            let mut budget = entry.write();
            budget.remaining = budget.remaining.saturating_sub(cost);
        }
        // Use a CAS loop to prevent underflow past zero (wrapping to u64::MAX)
        loop {
            let current = self.system_budget.load(Ordering::SeqCst);
            let new_val = current.saturating_sub(cost);
            match self.system_budget.compare_exchange(
                current,
                new_val,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => break,
                Err(_) => continue,
            }
        }
    }

    /// Get remaining budget for a tenant
    pub fn get_remaining(&self, tenant_id: &str) -> u64 {
        self.tenant_budgets
            .get(tenant_id)
            .map(|e| e.read().remaining)
            .unwrap_or(self.default_budget)
    }

    /// Get system remaining capacity
    pub fn system_remaining(&self) -> u64 {
        self.system_budget.load(Ordering::SeqCst)
    }

    /// Background task to refill system budget.
    /// Uses CAS loop to prevent TOCTOU race (load + fetch_add can overshoot capacity).
    pub async fn run_refill_loop(&self) {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        loop {
            interval.tick().await;

            // CAS loop to atomically clamp refill to available headroom
            let refill_rate = self.system_capacity / 60;
            loop {
                let current = self.system_budget.load(Ordering::SeqCst);
                if current >= self.system_capacity {
                    break; // Already at capacity
                }
                let refill = refill_rate.min(self.system_capacity - current);
                let new_val = current + refill;
                match self.system_budget.compare_exchange(
                    current,
                    new_val,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                ) {
                    Ok(_) => break,
                    Err(_) => continue, // Value changed, retry
                }
            }
        }
    }

    /// Set custom budget for a tenant
    pub fn set_tenant_budget(&self, tenant_id: &str, capacity: u64, refill_rate: u64) {
        let entry = self
            .tenant_budgets
            .entry(tenant_id.to_string())
            .or_insert_with(|| {
                RwLock::new(TenantBudget {
                    remaining: capacity,
                    capacity,
                    last_refill: Instant::now(),
                    refill_rate,
                })
            });

        let mut budget = entry.write();
        budget.capacity = capacity;
        budget.refill_rate = refill_rate;
        budget.remaining = budget.remaining.min(capacity);
    }

    /// Cleanup stale tenant budget entries to prevent unbounded memory growth.
    /// Bug E-105 fix:Evicts entries that have been inactive (budget at capacity
    /// and last_refill > 1 hour ago) to reclaim memory from ephemeral tenants.
    pub fn cleanup(&self) {
        let eviction_threshold = Duration::from_secs(3600); // 1 hour

        self.tenant_budgets.retain(|_tenant_id, entry| {
            let budget = entry.read();
            // Keep entries that have recent activity or are not at full capacity
            let is_at_capacity = budget.remaining >= budget.capacity;
            let is_stale = budget.last_refill.elapsed() > eviction_threshold;

            // Evict if at full capacity AND stale (no recent consumption)
            !(is_at_capacity && is_stale)
        });
    }

    /// Get number of tracked tenants (for monitoring)
    pub fn tracked_tenants(&self) -> usize {
        self.tenant_budgets.len()
    }

    fn reserve_system_budget(&self, amount: u64) -> bool {
        loop {
            let current = self.system_budget.load(Ordering::SeqCst);
            if current < amount {
                return false;
            }
            let new_val = current - amount;
            if self
                .system_budget
                .compare_exchange(current, new_val, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                return true;
            }
        }
    }

    fn refund_system_budget(&self, amount: u64) {
        loop {
            let current = self.system_budget.load(Ordering::SeqCst);
            let new_val = current.saturating_add(amount).min(self.system_capacity);
            if self
                .system_budget
                .compare_exchange(current, new_val, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                break;
            }
        }
    }
}

/// Cost-based rate limit decision
#[derive(Debug, Clone)]
pub enum CostDecision {
    /// Request is allowed
    Allowed {
        /// Cost deducted
        cost: u64,
        /// Remaining budget
        remaining: u64,
    },
    /// Tenant quota exceeded
    QuotaExceeded {
        /// Remaining budget
        remaining: u64,
        /// When to retry
        retry_after: Duration,
    },
    /// System is overloaded
    SystemOverloaded {
        /// When to retry
        retry_after: Duration,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_cost() {
        let cost = RequestCost::new(1000, 1024, 5, 1);
        // 1000 + 1 + 50 + 100 = 1151
        assert_eq!(cost.total_cost(), 1151);
    }

    #[test]
    fn test_cost_limiter() {
        let config = CostLimiterConfig {
            default_tenant_budget: 10000,
            system_capacity: 100000,
        };
        let limiter = CostBasedLimiter::new(config);

        // First request should be allowed
        let first = limiter.check("tenant1", "/v1/health", None);
        assert!(
            matches!(first, CostDecision::Allowed { .. }),
            "Expected Allowed"
        );

        // Exhaust budget
        for _ in 0..100 {
            let _ = limiter.check("tenant1", "/v1/messages/:id", None);
        }

        // Should be rate limited now
        let limited = limiter.check("tenant1", "/v1/messages/:id", None);
        assert!(
            matches!(limited, CostDecision::QuotaExceeded { .. }),
            "Expected QuotaExceeded, got {:?}",
            limited
        );

        // Different tenant should still work
        let other_tenant = limiter.check("tenant2", "/v1/health", None);
        assert!(
            matches!(other_tenant, CostDecision::Allowed { .. }),
            "Expected Allowed for different tenant"
        );
    }
}
