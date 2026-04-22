//! Prometheus-compatible metrics collection.
//!
//! Provides in-memory counters, histograms, and gauges with thread-safe
//! access via `DashMap` and `parking_lot`. The `export_prometheus` method
//! renders all recorded metrics in the Prometheus text exposition format.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::types::MetricType;

// ---------------------------------------------------------------------------
// Internal storage types
// ---------------------------------------------------------------------------

/// Atomic counter that only increments.
#[derive(Debug)]
struct CounterInner {
/// Stored as u64 bits representing an f64 to allow atomic ops.
    bits: AtomicU64,
}

impl CounterInner {
    fn new() -> Self {
        Self {
            bits: AtomicU64::new(0f64.to_bits()),
        }
    }

    fn inc(&self, v: f64) {
        loop {
            let old_bits = self.bits.load(Ordering::Relaxed);
            let old = f64::from_bits(old_bits);
            let new = old + v;
            if self
                .bits
                .compare_exchange_weak(old_bits, new.to_bits(), Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                break;
            }
        }
    }

    fn get(&self) -> f64 {
        f64::from_bits(self.bits.load(Ordering::Relaxed))
    }
}

/// Gauge that can go up and down.
#[derive(Debug)]
struct GaugeInner {
    bits: AtomicU64,
}

impl GaugeInner {
    fn new() -> Self {
        Self {
            bits: AtomicU64::new(0f64.to_bits()),
        }
    }

    fn set(&self, v: f64) {
        self.bits.store(v.to_bits(), Ordering::Release);
    }

    fn add(&self, v: f64) {
        loop {
            let old_bits = self.bits.load(Ordering::Relaxed);
            let old = f64::from_bits(old_bits);
            let new = old + v;
            if self
                .bits
                .compare_exchange_weak(old_bits, new.to_bits(), Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                break;
            }
        }
    }

    fn get(&self) -> f64 {
        f64::from_bits(self.bits.load(Ordering::Relaxed))
    }
}

/// A histogram backed by configurable bucket boundaries.
#[derive(Debug)]
struct HistogramInner {
    buckets: Vec<f64>,
    counts: Vec<AtomicU64>,
    sum: AtomicU64,
    count: AtomicU64,
}

impl HistogramInner {
    fn new(buckets: &[f64]) -> Self {
        let counts = buckets.iter().map(|_| AtomicU64::new(0)).collect();
        Self {
            buckets: buckets.to_vec(),
            counts,
            sum: AtomicU64::new(0f64.to_bits()),
            count: AtomicU64::new(0),
        }
    }

    fn observe(&self, v: f64) {
        for (i, &bound) in self.buckets.iter().enumerate() {
            if v <= bound {
                self.counts[i].fetch_add(1, Ordering::Relaxed);
            }
        }
// Add to sum (CAS loop for f64)
        loop {
            let old_bits = self.sum.load(Ordering::Relaxed);
            let old = f64::from_bits(old_bits);
            let new = old + v;
            if self
                .sum
                .compare_exchange_weak(old_bits, new.to_bits(), Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                break;
            }
        }
        self.count.fetch_add(1, Ordering::Relaxed);
    }

    fn sum(&self) -> f64 {
        f64::from_bits(self.sum.load(Ordering::Relaxed))
    }

    fn count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }
}

// ---------------------------------------------------------------------------
// Registered metric descriptor
// ---------------------------------------------------------------------------

#[derive(Debug)]
enum MetricStorage {
    Counter(Arc<CounterInner>),
    Gauge(Arc<GaugeInner>),
    Histogram(Arc<HistogramInner>),
}

#[derive(Debug)]
struct RegisteredMetric {
    name: String,
    help: String,
    metric_type: MetricType,
    storage: MetricStorage,
}

// ---------------------------------------------------------------------------
// MetricsSummary (returned by `get_summary`)
// ---------------------------------------------------------------------------

/// Overview of a single metric's current state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricSummary {
    pub name: String,
    pub metric_type: MetricType,
    pub help: String,
    pub value: f64,
}

// ---------------------------------------------------------------------------
// MetricsCollector
// ---------------------------------------------------------------------------

/// Thread-safe in-memory metrics collector compatible with Prometheus
/// text exposition format.
#[derive(Debug)]
pub struct MetricsCollector {
    metrics: DashMap<String, RegisteredMetric>,
    default_buckets: RwLock<Vec<f64>>,
    created_at: DateTime<Utc>,
}

impl MetricsCollector {
/// Create a new collector with the given default histogram buckets.
    pub fn new(default_buckets: Vec<f64>) -> Self {
        Self {
            metrics: DashMap::new(),
            default_buckets: RwLock::new(default_buckets),
            created_at: Utc::now(),
        }
    }

// -----------------------------------------------------------------------
// Registration helpers
// -----------------------------------------------------------------------

    fn ensure_counter(&self, name: &str, help: &str) {
        self.metrics
            .entry(name.to_string())
            .or_insert_with(|| RegisteredMetric {
                name: name.to_string(),
                help: help.to_string(),
                metric_type: MetricType::Counter,
                storage: MetricStorage::Counter(Arc::new(CounterInner::new())),
            });
    }

    fn ensure_gauge(&self, name: &str, help: &str) {
        self.metrics
            .entry(name.to_string())
            .or_insert_with(|| RegisteredMetric {
                name: name.to_string(),
                help: help.to_string(),
                metric_type: MetricType::Gauge,
                storage: MetricStorage::Gauge(Arc::new(GaugeInner::new())),
            });
    }

    fn ensure_histogram(&self, name: &str, help: &str) {
        self.metrics
            .entry(name.to_string())
            .or_insert_with(|| {
                let buckets = self.default_buckets.read().clone();
                RegisteredMetric {
                    name: name.to_string(),
                    help: help.to_string(),
                    metric_type: MetricType::Histogram,
                    storage: MetricStorage::Histogram(Arc::new(HistogramInner::new(&buckets))),
                }
            });
    }

// -----------------------------------------------------------------------
// Public API
// -----------------------------------------------------------------------

/// Increment a counter metric by `value` (auto-registers if needed).
    pub fn record_counter(&self, name: &str, value: f64, help: &str) {
        self.ensure_counter(name, help);
        if let Some(entry) = self.metrics.get(name) {
            if let MetricStorage::Counter(c) = &entry.storage {
                c.inc(value);
            }
        }
    }

/// Observe a value on a histogram metric (auto-registers if needed).
    pub fn record_histogram(&self, name: &str, value: f64, help: &str) {
        self.ensure_histogram(name, help);
        if let Some(entry) = self.metrics.get(name) {
            if let MetricStorage::Histogram(h) = &entry.storage {
                h.observe(value);
            }
        }
    }

/// Set a gauge metric to `value` (auto-registers if needed).
    pub fn record_gauge(&self, name: &str, value: f64, help: &str) {
        self.ensure_gauge(name, help);
        if let Some(entry) = self.metrics.get(name) {
            if let MetricStorage::Gauge(g) = &entry.storage {
                g.set(value);
            }
        }
    }

/// Increment (or decrement if negative) a gauge by `delta`.
    pub fn adjust_gauge(&self, name: &str, delta: f64, help: &str) {
        self.ensure_gauge(name, help);
        if let Some(entry) = self.metrics.get(name) {
            if let MetricStorage::Gauge(g) = &entry.storage {
                g.add(delta);
            }
        }
    }

/// Return a summary of all registered metrics.
    pub fn get_summary(&self) -> Vec<MetricSummary> {
        self.metrics
            .iter()
            .map(|entry| {
                let rm = entry.value();
                let value = match &rm.storage {
                    MetricStorage::Counter(c) => c.get(),
                    MetricStorage::Gauge(g) => g.get(),
                    MetricStorage::Histogram(h) => h.sum(),
                };
                MetricSummary {
                    name: rm.name.clone(),
                    metric_type: rm.metric_type,
                    help: rm.help.clone(),
                    value,
                }
            })
            .collect()
    }

/// Render all metrics in Prometheus text exposition format.
    pub fn export_prometheus(&self) -> String {
        let mut out = String::new();

        for entry in self.metrics.iter() {
            let rm = entry.value();
            match &rm.storage {
                MetricStorage::Counter(c) => {
                    out.push_str(&format!("# HELP {} {}\n", rm.name, rm.help));
                    out.push_str(&format!("# TYPE {} counter\n", rm.name));
                    out.push_str(&format!("{} {}\n", rm.name, c.get()));
                }
                MetricStorage::Gauge(g) => {
                    out.push_str(&format!("# HELP {} {}\n", rm.name, rm.help));
                    out.push_str(&format!("# TYPE {} gauge\n", rm.name));
                    out.push_str(&format!("{} {}\n", rm.name, g.get()));
                }
                MetricStorage::Histogram(h) => {
                    out.push_str(&format!("# HELP {} {}\n", rm.name, rm.help));
                    out.push_str(&format!("# TYPE {} histogram\n", rm.name));
                    for (i, &bound) in h.buckets.iter().enumerate() {
                        let count = h.counts[i].load(Ordering::Relaxed);
                        out.push_str(&format!(
                            "{}_bucket{{le=\"{}\"}} {}\n",
                            rm.name, bound, count
                        ));
                    }
                    out.push_str(&format!(
                        "{}_bucket{{le=\"+Inf\"}} {}\n",
                        rm.name,
                        h.count()
                    ));
                    out.push_str(&format!("{}_sum {}\n", rm.name, h.sum()));
                    out.push_str(&format!("{}_count {}\n", rm.name, h.count()));
                }
            }
            out.push('\n');
        }
        out
    }

/// How long the collector has been alive.
    pub fn uptime_secs(&self) -> u64 {
        (Utc::now() - self.created_at).num_seconds().max(0) as u64
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn default_buckets() -> Vec<f64> {
        vec![0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
    }

    #[test]
    fn test_record_counter_increments() {
        let mc = MetricsCollector::new(default_buckets());
        mc.record_counter("requests_total", 1.0, "Total requests");
        mc.record_counter("requests_total", 4.0, "Total requests");
        let summaries = mc.get_summary();
        let req = summaries.iter().find(|s| s.name == "requests_total").unwrap();
        assert!((req.value - 5.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_record_gauge_set_and_adjust() {
        let mc = MetricsCollector::new(default_buckets());
        mc.record_gauge("temperature", 36.6, "Current temp");
        mc.adjust_gauge("temperature", 1.0, "Current temp");
        let summaries = mc.get_summary();
        let temp = summaries.iter().find(|s| s.name == "temperature").unwrap();
// set(36.6) then add(1.0) => only add runs because set already created
        assert!((temp.value - 37.6).abs() < f64::EPSILON);
    }

    #[test]
    fn test_record_histogram_observation() {
        let mc = MetricsCollector::new(vec![0.1, 0.5, 1.0]);
        mc.record_histogram("latency", 0.05, "Request latency");
        mc.record_histogram("latency", 0.3, "Request latency");
        mc.record_histogram("latency", 0.8, "Request latency");
        let prom = mc.export_prometheus();
        assert!(prom.contains("latency_sum"));
        assert!(prom.contains("latency_count 3"));
// The 0.05 observation should appear in all buckets, 0.3 in ≥0.5 and ≥1.0
        assert!(prom.contains("latency_bucket{le=\"0.1\"} 1"));
        assert!(prom.contains("latency_bucket{le=\"0.5\"} 2"));
        assert!(prom.contains("latency_bucket{le=\"1\"} 3"));
    }

    #[test]
    fn test_export_prometheus_format() {
        let mc = MetricsCollector::new(default_buckets());
        mc.record_counter("http_total", 10.0, "HTTP total");
        mc.record_gauge("active_conns", 5.0, "Active connections");
        let prom = mc.export_prometheus();
        assert!(prom.contains("# HELP http_total HTTP total"));
        assert!(prom.contains("# TYPE http_total counter"));
        assert!(prom.contains("http_total 10"));
        assert!(prom.contains("# TYPE active_conns gauge"));
        assert!(prom.contains("active_conns 5"));
    }
}
