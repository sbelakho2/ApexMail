//! Aggregate, low-cardinality risk metrics. No identity labels are
//! recorded.
//!
//! Decision counters use the tuple key `decisions:<scope>:<action>:<band>`.
//! Latencies accumulate count + total microseconds for average computation.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

/// Thread-safe aggregate metrics.
///
/// `snapshot()` returns counters as `(key, count)` and latency accumulators
/// as `(key:total_us, total)` / `(key:count, samples)`.
#[derive(Default)]
pub struct Metrics {
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
        let mut out: Vec<(String, u64)> = {
            let counters = self.counters.lock().unwrap_or_else(|p| p.into_inner());
            counters.iter().map(|(k, v)| (k.clone(), *v)).collect()
        };
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
        metrics.add_latency_us("store:observe", 150);
        metrics.add_latency_us("store:observe", 350);

        let snapshot = metrics.snapshot();
        let get = |key: &str| snapshot.iter().find(|(k, _)| k == key).map(|(_, v)| *v);
        assert_eq!(get("decisions:1:allow:0"), Some(2));
        assert_eq!(get("store:observe:total_us"), Some(500));
        assert_eq!(get("store:observe:count"), Some(2));
    }
}
