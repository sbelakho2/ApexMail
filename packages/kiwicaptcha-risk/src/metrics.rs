//! Aggregate, low-cardinality risk metrics. No identity labels are
//! recorded.
//!
//! Decision counters use the tuple key `decisions:<scope>:<action>:<band>`.
//! Latencies accumulate count + total microseconds for average computation.
//!
//! Hot-path keys avoid per-decision formatting and mutex traffic: the
//! engine's fixed keys ([`FixedMetric`]) are pre-interned static strings
//! backed by lock-free atomics, and the decision counters are keyed by the
//! fixed-size `(scope, action, band)` tuple — the display string is
//! materialized only in [`Metrics::snapshot`].

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

/// The engine's fixed metric keys (pre-interned `'static` strings, so the
/// per-decision path never formats or allocates them).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FixedMetric {
    /// Emergency-cap hard denies (`denied:limiter`).
    DeniedLimiter,
    /// Degraded decisions while the breaker is open (`degraded:breaker`).
    DegradedBreaker,
    /// Degraded decisions after a store failure (`degraded:store`).
    DegradedStore,
    /// `store:observe` latency accumulator, total microseconds.
    StoreObserveTotalUs,
    /// `store:observe` latency accumulator, sample count.
    StoreObserveCount,
}

impl FixedMetric {
    /// Every fixed key, in snapshot order.
    pub const ALL: [FixedMetric; 5] = [
        FixedMetric::DeniedLimiter,
        FixedMetric::DegradedBreaker,
        FixedMetric::DegradedStore,
        FixedMetric::StoreObserveTotalUs,
        FixedMetric::StoreObserveCount,
    ];

    /// The pre-interned snapshot key.
    pub fn as_str(self) -> &'static str {
        match self {
            FixedMetric::DeniedLimiter => "denied:limiter",
            FixedMetric::DegradedBreaker => "degraded:breaker",
            FixedMetric::DegradedStore => "degraded:store",
            FixedMetric::StoreObserveTotalUs => "store:observe:total_us",
            FixedMetric::StoreObserveCount => "store:observe:count",
        }
    }
}

/// Thread-safe aggregate metrics.
///
/// `snapshot()` returns counters as `(key, count)` and latency accumulators
/// as `(key:total_us, total)` / `(key:count, samples)`.
#[derive(Default)]
pub struct Metrics {
    /// Lock-free counters for the fixed engine keys (indexed by
    /// [`FixedMetric::ALL`] position).
    fixed: [AtomicU64; 5],
    /// Decision counters keyed by the fixed-size `(scope, action, band)`
    /// tuple (the `decisions:*` display strings are built only in
    /// `snapshot`).
    decisions: Mutex<HashMap<(u32, &'static str, u8), u64>>,
    counters: Mutex<HashMap<String, u64>>,
    latencies: Mutex<HashMap<String, AtomicU64>>,
    latency_counts: Mutex<HashMap<String, AtomicU64>>,
}

impl Metrics {
    pub fn new() -> Metrics {
        Metrics::default()
    }

    /// Increments a counter by `n` (default 1).
    pub fn incr(&self, key: &str) {
        self.incr_n(key, 1);
    }

    /// Increments a counter by an explicit amount.
    pub fn incr_n(&self, key: &str, n: u64) {
        let mut counters = self.counters.lock().unwrap_or_else(|p| p.into_inner());
        *counters.entry(key.to_string()).or_insert(0) += n;
    }

    /// Increments a fixed engine key (pre-interned, lock-free).
    pub fn incr_fixed(&self, key: FixedMetric) {
        self.fixed[key as usize].fetch_add(1, Ordering::Relaxed);
    }

    /// Increments a fixed engine key by an explicit amount (lock-free).
    pub fn incr_fixed_n(&self, key: FixedMetric, n: u64) {
        self.fixed[key as usize].fetch_add(n, Ordering::Relaxed);
    }

    /// Increments the `decisions:<scope>:<action>:<band>` counter — the
    /// tuple key avoids the per-decision `format!`; the display string is
    /// materialized only in [`Metrics::snapshot`].
    pub fn incr_decision(&self, scope: u32, action: &'static str, band: u8) {
        let mut decisions = self.decisions.lock().unwrap_or_else(|p| p.into_inner());
        *decisions.entry((scope, action, band)).or_insert(0) += 1;
    }

    /// Records one `store:observe` latency sample (microseconds) into the
    /// pre-interned fixed accumulators (lock-free).
    pub fn add_store_latency_us(&self, us: u64) {
        self.fixed[FixedMetric::StoreObserveTotalUs as usize].fetch_add(us, Ordering::Relaxed);
        self.fixed[FixedMetric::StoreObserveCount as usize].fetch_add(1, Ordering::Relaxed);
    }

    /// Accumulates a latency sample for `key` (microseconds).
    pub fn add_latency_us(&self, key: &str, us: u64) {
        let mut latencies = self.latencies.lock().unwrap_or_else(|p| p.into_inner());
        let entry = latencies
            .entry(key.to_string())
            .or_insert_with(|| AtomicU64::new(0));
        entry.fetch_add(us, Ordering::Relaxed);
        let mut counts = self
            .latency_counts
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let count = counts
            .entry(key.to_string())
            .or_insert_with(|| AtomicU64::new(0));
        count.fetch_add(1, Ordering::Relaxed);
    }

    /// All counters and latency accumulators.
    pub fn snapshot(&self) -> Vec<(String, u64)> {
        let mut out: Vec<(String, u64)> = FixedMetric::ALL
            .iter()
            .filter_map(|k| {
                let n = self.fixed[*k as usize].load(Ordering::Relaxed);
                (n > 0).then(|| (k.as_str().to_string(), n))
            })
            .collect();
        {
            let decisions = self.decisions.lock().unwrap_or_else(|p| p.into_inner());
            out.extend(decisions.iter().map(|((scope, action, band), n)| {
                (format!("decisions:{scope}:{action}:{band}"), *n)
            }));
        }
        {
            let counters = self.counters.lock().unwrap_or_else(|p| p.into_inner());
            out.extend(counters.iter().map(|(k, v)| (k.clone(), *v)));
        }
        {
            let latencies = self.latencies.lock().unwrap_or_else(|p| p.into_inner());
            let counts = self
                .latency_counts
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            let mut latency_entries: Vec<(String, u64)> = latencies
                .iter()
                .map(|(k, total)| (format!("{k}:total_us"), total.load(Ordering::Relaxed)))
                .collect();
            latency_entries.extend(
                counts
                    .iter()
                    .map(|(k, n)| (format!("{k}:count"), n.load(Ordering::Relaxed))),
            );
            out.extend(latency_entries);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_and_latencies() {
        let metrics = Metrics::new();
        metrics.incr("decisions:1:allow:0");
        metrics.incr("decisions:1:allow:0");
        metrics.add_latency_us("calibration:bias", 150);
        metrics.add_latency_us("calibration:bias", 350);

        let snapshot = metrics.snapshot();
        let get = |key: &str| snapshot.iter().find(|(k, _)| k == key).map(|(_, v)| *v);
        assert_eq!(get("decisions:1:allow:0"), Some(2));
        assert_eq!(get("calibration:bias:total_us"), Some(500));
        assert_eq!(get("calibration:bias:count"), Some(2));
        assert_eq!(
            get("store:observe:total_us"),
            None,
            "an untouched fixed key stays out of the snapshot"
        );
    }

    #[test]
    fn fixed_keys_and_decision_counters_are_snapshot_identical() {
        let metrics = Metrics::new();
        metrics.incr_fixed(FixedMetric::DeniedLimiter);
        metrics.incr_fixed(FixedMetric::DeniedLimiter);
        metrics.incr_fixed(FixedMetric::DegradedStore);
        metrics.add_store_latency_us(100);
        metrics.add_store_latency_us(50);
        metrics.incr_decision(7, "argon16", 5);
        metrics.incr_decision(7, "argon16", 5);

        let snapshot = metrics.snapshot();
        let get = |key: &str| snapshot.iter().find(|(k, _)| k == key).map(|(_, v)| *v);
        assert_eq!(get("denied:limiter"), Some(2));
        assert_eq!(get("degraded:store"), Some(1));
        assert_eq!(get("degraded:breaker"), None);
        assert_eq!(get("store:observe:total_us"), Some(150));
        assert_eq!(get("store:observe:count"), Some(2));
        assert_eq!(get("decisions:7:argon16:5"), Some(2));
    }
}
