//! Prometheus metrics for DDoS protection

use once_cell::sync::Lazy;
use prometheus::{
    register_histogram_vec, register_int_counter_vec, register_gauge_vec,
    HistogramOpts, HistogramVec, IntCounterVec, Opts, GaugeVec
};

fn safe_int_counter_vec(name: &str, help: &str, labels: &[&str]) -> Option<IntCounterVec> {
    match register_int_counter_vec!(name, help, labels) {
        Ok(metric) => Some(metric),
        Err(err) => {
            tracing::warn!(metric = name, error = %err, "Falling back to unregistered IntCounterVec");
            match IntCounterVec::new(Opts::new(name, help), labels) {
                Ok(metric) => Some(metric),
                Err(build_err) => {
                    tracing::error!(metric = name, error = %build_err, "Failed to construct fallback IntCounterVec");
                    None
                }
            }
        }
    }
}

fn safe_gauge_vec(name: &str, help: &str, labels: &[&str]) -> Option<GaugeVec> {
    match register_gauge_vec!(name, help, labels) {
        Ok(metric) => Some(metric),
        Err(err) => {
            tracing::warn!(metric = name, error = %err, "Falling back to unregistered GaugeVec");
            match GaugeVec::new(Opts::new(name, help), labels) {
                Ok(metric) => Some(metric),
                Err(build_err) => {
                    tracing::error!(metric = name, error = %build_err, "Failed to construct fallback GaugeVec");
                    None
                }
            }
        }
    }
}

fn safe_histogram_vec(name: &str, help: &str, labels: &[&str], buckets: Vec<f64>) -> Option<HistogramVec> {
    match register_histogram_vec!(name, help, labels, buckets.clone()) {
        Ok(metric) => Some(metric),
        Err(err) => {
            tracing::warn!(metric = name, error = %err, "Falling back to unregistered HistogramVec");
            match HistogramVec::new(HistogramOpts::new(name, help).buckets(buckets), labels) {
                Ok(metric) => Some(metric),
                Err(build_err) => {
                    tracing::error!(metric = name, error = %build_err, "Failed to construct fallback HistogramVec");
                    None
                }
            }
        }
    }
}

/// Total requests processed
pub static REQUESTS_TOTAL: Lazy<Option<IntCounterVec>> = Lazy::new(|| {
    safe_int_counter_vec(
        "ddos_requests_total",
        "Total requests processed by DDoS protection",
        &["decision", "layer"]
    )
});

/// Currently blocked IPs
pub static BLOCKED_IPS: Lazy<Option<GaugeVec>> = Lazy::new(|| {
    safe_gauge_vec(
        "ddos_blocked_ips",
        "Number of currently blocked IP addresses",
        &["reason"]
    )
});

/// Anomaly score distribution
pub static ANOMALY_SCORE: Lazy<Option<HistogramVec>> = Lazy::new(|| {
    safe_histogram_vec(
        "ddos_anomaly_score",
        "Anomaly scores from ML model",
        &["endpoint"],
        vec![0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]
    )
});

/// Challenge latency (time for client to solve)
pub static CHALLENGE_LATENCY: Lazy<Option<HistogramVec>> = Lazy::new(|| {
    safe_histogram_vec(
        "ddos_challenge_latency_seconds",
        "Time for clients to solve challenges",
        &["type"],
        vec![0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0]
    )
});

/// Challenges issued
pub static CHALLENGES_ISSUED: Lazy<Option<IntCounterVec>> = Lazy::new(|| {
    safe_int_counter_vec(
        "ddos_challenges_issued_total",
        "Total challenges issued",
        &["type"]
    )
});

/// Challenges passed
pub static CHALLENGES_PASSED: Lazy<Option<IntCounterVec>> = Lazy::new(|| {
    safe_int_counter_vec(
        "ddos_challenges_passed_total",
        "Total challenges passed",
        &["type"]
    )
});

/// Challenges failed
pub static CHALLENGES_FAILED: Lazy<Option<IntCounterVec>> = Lazy::new(|| {
    safe_int_counter_vec(
        "ddos_challenges_failed_total",
        "Total challenges failed",
        &["type"]
    )
});

/// Reputation score distribution
pub static REPUTATION_SCORE: Lazy<Option<HistogramVec>> = Lazy::new(|| {
    safe_histogram_vec(
        "ddos_reputation_score",
        "Distribution of IP reputation scores",
        &[],
        vec![0.0, 10.0, 20.0, 30.0, 40.0, 50.0, 60.0, 70.0, 80.0, 90.0, 100.0]
    )
});

/// Threat events shared across regions
pub static THREAT_EVENTS: Lazy<Option<IntCounterVec>> = Lazy::new(|| {
    safe_int_counter_vec(
        "ddos_threat_events_total",
        "Threat events shared across regions",
        &["type", "severity", "source_region"]
    )
});

/// Cost budget usage
pub static COST_BUDGET_USAGE: Lazy<Option<GaugeVec>> = Lazy::new(|| {
    safe_gauge_vec(
        "ddos_cost_budget_usage_ratio",
        "Cost budget usage ratio (0-1)",
        &["tenant_id"]
    )
});

/// Attack detection state
pub static UNDER_ATTACK: Lazy<Option<GaugeVec>> = Lazy::new(|| {
    safe_gauge_vec(
        "ddos_under_attack",
        "Whether the system is under attack (0 or 1)",
        &["region"]
    )
});

/// XDP statistics (if available)
pub static XDP_PACKETS: Lazy<Option<IntCounterVec>> = Lazy::new(|| {
    safe_int_counter_vec(
        "ddos_xdp_packets_total",
        "Packets processed by XDP filter",
        &["action"]
    )
});

/// Session tracking stats
pub static ACTIVE_SESSIONS: Lazy<Option<GaugeVec>> = Lazy::new(|| {
    safe_gauge_vec(
        "ddos_active_sessions",
        "Number of active sessions being tracked",
        &[]
    )
});
