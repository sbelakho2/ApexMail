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
    /// Hard cap on tracked budget entries (audit SM5 F3). Anonymous
    /// buckets are keyed by client IP, so IPv6-/64 rotation mints one
    /// entry per address; without a cap the map grew without bound.
    /// 0 disables the cap (not recommended).
    pub max_tracked_budgets: usize,
}

impl Default for CostLimiterConfig {
    fn default() -> Self {
        Self {
            default_tenant_budget: 100_000,
            system_capacity: 10_000_000,
            max_tracked_budgets: 100_000,
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
    /// Hard cap on tracked budget entries (audit SM5 F3)
    max_tracked_budgets: usize,
}

impl CostBasedLimiter {
    /// Create a new cost-based limiter
    pub fn new(config: CostLimiterConfig) -> Self {
        Self {
            tenant_budgets: Arc::new(DashMap::new()),
            default_budget: config.default_tenant_budget,
            system_budget: Arc::new(AtomicU64::new(config.system_capacity)),
            system_capacity: config.system_capacity,
            max_tracked_budgets: config.max_tracked_budgets,
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

        // Check tenant budget. Audit SM5 F3: enforce the entry cap BEFORE
        // inserting a new key so a flood of fresh client-IP keys cannot
        // grow the map past the cap between cleanup ticks.
        if !self.tenant_budgets.contains_key(tenant_id) {
            self.enforce_budget_capacity();
        }
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
        if !self.tenant_budgets.contains_key(tenant_id) {
            self.enforce_budget_capacity();
        }
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
    /// Bug E-105 fix: evicts entries that have been inactive (last_refill
    /// > 1 hour ago) to reclaim memory from ephemeral tenants.
    ///
    /// Audit SM5 F3: the old rule only evicted entries that were BOTH
    /// stale AND at full capacity, so a PARTIALLY-drained bucket (the
    /// common case after a handful of requests) was immortal — an
    /// attacker rotating IPv6 /64s minted one permanent entry per
    /// address. Staleness alone now evicts, regardless of remaining
    /// budget; the hard cap is re-enforced as well.
    pub fn cleanup(&self) {
        let eviction_threshold = Duration::from_secs(3600); // 1 hour

        self.tenant_budgets.retain(|_tenant_id, entry| {
            let budget = entry.read();
            // Keep only entries with recent activity.
            budget.last_refill.elapsed() <= eviction_threshold
        });

        // Periodic enforcement of the hard capacity cap between
        // insert-time checks.
        self.enforce_budget_capacity();
    }

    /// Enforce the hard cap on tracked budget entries (audit SM5 F3),
    /// mirroring `SessionTracker::enforce_capacity`: when the map is at
    /// capacity, a 10% batch of the entries with the OLDEST `last_refill`
    /// (least-recently-used) is evicted before a new key is inserted, so
    /// the cap holds even between cleanup ticks.
    fn enforce_budget_capacity(&self) {
        if self.max_tracked_budgets == 0 || self.tenant_budgets.len() < self.max_tracked_budgets {
            return;
        }
        let target = self
            .max_tracked_budgets
            .saturating_sub(self.max_tracked_budgets / 10)
            .max(1);
        let mut candidates: Vec<(String, Instant)> = self
            .tenant_budgets
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().read().last_refill))
            .collect();
        candidates.sort_by_key(|(_, last_refill)| *last_refill);
        let excess = self.tenant_budgets.len().saturating_sub(target);
        for (tenant_id, _) in candidates.into_iter().take(excess) {
            self.tenant_budgets.remove(&tenant_id);
        }
    }

    /// Test-only: force a tenant entry into the stale-and-full state so
    /// the cleanup path can be exercised without waiting an hour.
    #[cfg(test)]
    pub(crate) fn force_stale_for_test(&self, tenant_id: &str) {
        let entry = self
            .tenant_budgets
            .entry(tenant_id.to_string())
            .or_insert_with(|| {
                RwLock::new(TenantBudget {
                    remaining: self.default_budget,
                    capacity: self.default_budget,
                    last_refill: Instant::now(),
                    refill_rate: self.default_budget / 60,
                })
            });
        let mut budget = entry.write();
        budget.remaining = budget.capacity;
        budget.last_refill = stale_instant_for_test(Instant::now());
    }

    /// Test-only: age a tenant entry's `last_refill` without touching its
    /// remaining budget, so the partially-drained eviction case (audit
    /// SM5 F3) can be exercised without waiting an hour.
    #[cfg(test)]
    pub(crate) fn age_last_refill_for_test(&self, tenant_id: &str) {
        if let Some(entry) = self.tenant_budgets.get(tenant_id) {
            entry.write().last_refill = stale_instant_for_test(Instant::now());
        }
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

/// Monotonic-safe back-dating for tests (audit SM5 F4: plain
/// `Instant::now() - 2h` panics on a low-uptime CI host).
#[cfg(test)]
fn stale_instant_for_test(now: Instant) -> Instant {
    now.checked_sub(Duration::from_secs(7200)).unwrap_or(now)
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
            ..Default::default()
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

    /// Fix #7b (fail-first): `cleanup` must evict stale, full-budget
    /// entries (Bug E-105) so the tenant-budget map stays bounded, and
    /// must keep active entries.
    #[test]
    fn test_cleanup_evicts_stale_tenants_and_keeps_active() {
        let limiter = CostBasedLimiter::new(CostLimiterConfig {
            default_tenant_budget: 10_000,
            system_capacity: 1_000_000,
            ..Default::default()
        });

        // An active tenant (recent consumption, below capacity).
        let _ = limiter.check("active", "/v1/health", None);
        // A stale tenant: at capacity, untouched for 2 hours.
        limiter.force_stale_for_test("stale");

        assert_eq!(limiter.tracked_tenants(), 2);
        limiter.cleanup();
        assert_eq!(
            limiter.tracked_tenants(),
            1,
            "stale full-budget tenant must be evicted"
        );
        // The survivor is the active one.
        let _ = limiter.check("active", "/v1/health", None);
        assert_eq!(limiter.tracked_tenants(), 1);
    }

    // ── Audit SM5 F3: the budget map is hard-capped and stale entries
    //    are evicted regardless of remaining budget ─────────────────────

    /// Fail-first for the finding: a PARTIALLY-drained bucket (remaining
    /// < capacity) used to be immortal — `cleanup` evicted only
    /// at-capacity entries, so client-IP rotation grew the map forever.
    #[test]
    fn test_cleanup_evicts_partially_drained_stale_bucket() {
        let limiter = CostBasedLimiter::new(CostLimiterConfig {
            default_tenant_budget: 10_000,
            system_capacity: 1_000_000,
            max_tracked_budgets: 0, // cap disabled for this scenario
        });

        // One request leaves the bucket partially drained.
        let _ = limiter.check("rotating-client", "/v1/health", None);
        assert!(
            limiter.get_remaining("rotating-client") < 10_000,
            "bucket must be partially drained for this scenario"
        );
        assert_eq!(limiter.tracked_tenants(), 1);

        limiter.age_last_refill_for_test("rotating-client");
        limiter.cleanup();

        assert_eq!(
            limiter.tracked_tenants(),
            0,
            "a stale PARTIALLY-drained bucket must be evicted too"
        );
    }

    #[test]
    fn test_cleanup_keeps_recent_partially_drained_bucket() {
        let limiter = CostBasedLimiter::new(CostLimiterConfig::default());

        let _ = limiter.check("active-client", "/v1/health", None);
        limiter.cleanup();
        assert_eq!(
            limiter.tracked_tenants(),
            1,
            "recent activity must survive cleanup regardless of remaining"
        );
    }

    /// 2× cap distinct client keys must never grow the map past the cap.
    #[test]
    fn test_budget_map_hard_capped_under_key_flood() {
        let cap = 100;
        let limiter = CostBasedLimiter::new(CostLimiterConfig {
            default_tenant_budget: 10_000,
            system_capacity: 100_000_000,
            max_tracked_budgets: cap,
        });

        for i in 0..(cap * 2) {
            let decision = limiter.check(&format!("anon:10.{i}.0.1"), "/v1/ping", None);
            assert!(
                matches!(decision, CostDecision::Allowed { .. }),
                "flood requests must be allowed (cap bounds memory, not throughput), got {decision:?} at {i}"
            );
            assert!(
                limiter.tracked_tenants() <= cap,
                "budget map exceeded cap at iteration {i}: {}",
                limiter.tracked_tenants()
            );
        }
        assert!(limiter.tracked_tenants() <= cap);
    }
}
