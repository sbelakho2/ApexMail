//! Prometheus metrics for DDoS protection

use once_cell::sync::Lazy;
use prometheus::{
    register_gauge_vec, register_histogram_vec, register_int_counter_vec, GaugeVec, HistogramOpts,
    HistogramVec, IntCounterVec, Opts,
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

fn safe_histogram_vec(
    name: &str,
    help: &str,
    labels: &[&str],
    buckets: Vec<f64>,
) -> Option<HistogramVec> {
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
        &["decision", "layer"],
    )
});

/// Currently blocked IPs
pub static BLOCKED_IPS: Lazy<Option<GaugeVec>> = Lazy::new(|| {
    safe_gauge_vec(
        "ddos_blocked_ips",
        "Number of currently blocked IP addresses",
        &["reason"],
    )
});

/// Anomaly score distribution
pub static ANOMALY_SCORE: Lazy<Option<HistogramVec>> = Lazy::new(|| {
    safe_histogram_vec(
        "ddos_anomaly_score",
        "Anomaly scores from ML model",
        &["endpoint"],
        vec![0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0],
    )
});

/// Challenge latency (time for client to solve)
pub static CHALLENGE_LATENCY: Lazy<Option<HistogramVec>> = Lazy::new(|| {
    safe_histogram_vec(
        "ddos_challenge_latency_seconds",
        "Time for clients to solve challenges",
        &["type"],
        vec![0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0],
    )
});

/// Challenges issued
pub static CHALLENGES_ISSUED: Lazy<Option<IntCounterVec>> = Lazy::new(|| {
    safe_int_counter_vec(
        "ddos_challenges_issued_total",
        "Total challenges issued",
        &["type"],
    )
});

/// Challenges passed
pub static CHALLENGES_PASSED: Lazy<Option<IntCounterVec>> = Lazy::new(|| {
    safe_int_counter_vec(
        "ddos_challenges_passed_total",
        "Total challenges passed",
        &["type"],
    )
});

/// Challenges failed
pub static CHALLENGES_FAILED: Lazy<Option<IntCounterVec>> = Lazy::new(|| {
    safe_int_counter_vec(
        "ddos_challenges_failed_total",
        "Total challenges failed",
        &["type"],
    )
});

/// Reputation score distribution
pub static REPUTATION_SCORE: Lazy<Option<HistogramVec>> = Lazy::new(|| {
    safe_histogram_vec(
        "ddos_reputation_score",
        "Distribution of IP reputation scores",
        &[],
        vec![
            0.0, 10.0, 20.0, 30.0, 40.0, 50.0, 60.0, 70.0, 80.0, 90.0, 100.0,
        ],
    )
});

/// Threat events shared across regions
pub static THREAT_EVENTS: Lazy<Option<IntCounterVec>> = Lazy::new(|| {
    safe_int_counter_vec(
        "ddos_threat_events_total",
        "Threat events shared across regions",
        &["type", "severity", "source_region"],
    )
});

/// Cost budget usage
pub static COST_BUDGET_USAGE: Lazy<Option<GaugeVec>> = Lazy::new(|| {
    safe_gauge_vec(
        "ddos_cost_budget_usage_ratio",
        "Cost budget usage ratio (0-1)",
        &["tenant_id"],
    )
});

/// Attack detection state
pub static UNDER_ATTACK: Lazy<Option<GaugeVec>> = Lazy::new(|| {
    safe_gauge_vec(
        "ddos_under_attack",
        "Whether the system is under attack (0 or 1)",
        &["region"],
    )
});

/// XDP statistics (if available)
pub static XDP_PACKETS: Lazy<Option<IntCounterVec>> = Lazy::new(|| {
    safe_int_counter_vec(
        "ddos_xdp_packets_total",
        "Packets processed by XDP filter",
        &["action"],
    )
});

/// Session tracking stats
pub static ACTIVE_SESSIONS: Lazy<Option<GaugeVec>> = Lazy::new(|| {
    safe_gauge_vec(
        "ddos_active_sessions",
        "Number of active sessions being tracked",
        &[],
    )
});

// ─── Endpoint label normalization (cardinality bound) ──────────────────

/// Maximum number of distinct endpoint labels retained for the
/// `ddos_anomaly_score` histogram. Every additional label multiplies the
/// stored time-series count by the bucket count, so raw paths (which can
/// contain attacker-controlled UUIDs/IDs) must never become labels.
pub const MAX_ENDPOINT_LABELS: usize = 500;

/// Maximum length of an endpoint label.
const MAX_LABEL_LEN: usize = 64;

/// Fallback label once the distinct-label budget is exhausted.
pub const OTHER_ENDPOINT_LABEL: &str = "other";

static KNOWN_ENDPOINT_LABELS: Lazy<parking_lot::Mutex<std::collections::HashSet<String>>> =
    Lazy::new(|| parking_lot::Mutex::new(std::collections::HashSet::new()));

/// Normalize a raw request path into a bounded-cardinality route class.
///
/// * Query strings are dropped.
/// * UUID-like segments → `{uuid}`
/// * Purely numeric segments → `{id}`
/// * Long hex segments (≥8 chars) → `{hex}`
/// * Any other segment longer than 24 chars → `{long}`
/// * Label truncated to [`MAX_LABEL_LEN`] chars on a char boundary.
pub fn normalize_endpoint_label(path: &str) -> String {
    let path_only = path.split('?').next().unwrap_or(path);
    let mut out = String::with_capacity(path_only.len().min(MAX_LABEL_LEN + 8));
    for (idx, seg) in path_only.split('/').enumerate() {
        if idx > 0 {
            out.push('/');
        }
        out.push_str(&normalize_segment(seg));
    }
    truncate_label(&out)
}

/// Convert a normalized label into a Prometheus label value, bounding the
/// number of DISTINCT labels: once [`MAX_ENDPOINT_LABELS`] distinct route
/// classes have been seen, everything else collapses to `other`.
///
/// Without this bound an attacker probing random paths creates unbounded
/// time-series (one per label × histogram buckets), exhausting Prometheus
/// memory — a metrics-cardinality DoS.
pub fn endpoint_label(path: &str) -> String {
    let normalized = normalize_endpoint_label(path);
    let mut known = KNOWN_ENDPOINT_LABELS.lock();
    if known.contains(&normalized) {
        return normalized;
    }
    if known.len() >= MAX_ENDPOINT_LABELS {
        return OTHER_ENDPOINT_LABEL.to_string();
    }
    known.insert(normalized.clone());
    normalized
}

fn normalize_segment(seg: &str) -> &str {
    if seg.is_empty() {
        return seg;
    }
    if is_uuid_like(seg) {
        return "{uuid}";
    }
    if seg.len() >= 8 && seg.chars().all(|c| c.is_ascii_hexdigit()) {
        return "{hex}";
    }
    if seg.chars().all(|c| c.is_ascii_digit()) {
        return "{id}";
    }
    if seg.len() > 24 {
        return "{long}";
    }
    seg
}

fn is_uuid_like(seg: &str) -> bool {
    // 8-4-4-4-12 hex pattern with dashes or a bare 32-hex-char UUID.
    let compact: String = seg.chars().filter(|c| *c != '-').collect();
    seg.len() == 36
        && seg.as_bytes()[8] == b'-'
        && compact.len() == 32
        && compact.chars().all(|c| c.is_ascii_hexdigit())
}

fn truncate_label(label: &str) -> String {
    if label.len() <= MAX_LABEL_LEN {
        return label.to_string();
    }
    let mut end = MAX_LABEL_LEN;
    while end > 0 && !label.is_char_boundary(end) {
        end -= 1;
    }
    label[..end].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_strips_ids_uuids_and_params() {
        assert_eq!(
            normalize_endpoint_label("/users/123e4567-e89b-12d3-a456-426614174000"),
            "/users/{uuid}"
        );
        assert_eq!(normalize_endpoint_label("/api/v1/users/42"), "/api/v1/users/{id}");
        assert_eq!(normalize_endpoint_label("/files/deadbeef12345678"), "/files/{hex}");
        assert_eq!(
            normalize_endpoint_label("/search?query=attacker-controlled"),
            "/search"
        );
        assert_eq!(normalize_endpoint_label("/health"), "/health");
    }

    #[test]
    fn normalize_caps_label_length() {
        let long = format!("/very-long-route/{}", "a".repeat(200));
        let label = normalize_endpoint_label(&long);
        // long segment → {long}; overall label bounded at 64 chars
        assert!(label.len() <= MAX_LABEL_LEN, "got {} ({})", label.len(), label);
    }

    #[test]
    fn random_paths_produce_bounded_distinct_labels() {
        // Fix H: a cardinality bomb (thousands of distinct random paths)
        // must collapse into at most MAX_ENDPOINT_LABELS distinct labels
        // plus the `other` fallback.
        let mut seen = std::collections::HashSet::new();
        for i in 0..(MAX_ENDPOINT_LABELS * 3) as u32 {
            // Literal (non-hex, non-numeric) segments stay distinct after
            // normalization, so this mimics an attacker probing unlimited
            // unique routes.
            let path = format!("/attack/route-{i:06}-zz");
            seen.insert(endpoint_label(&path));
        }
        // The bound is MAX_ENDPOINT_LABELS *retained* route classes plus the
        // single `other` overflow value the retained set collapses into —
        // 501 distinct observed labels, never more regardless of input count.
        assert!(
            seen.len() <= MAX_ENDPOINT_LABELS + 1,
            "distinct labels must stay bounded, got {}",
            seen.len()
        );
        assert!(
            seen.contains(OTHER_ENDPOINT_LABEL),
            "overflow must collapse to `other`"
        );
    }

    #[test]
    fn same_path_yields_same_label() {
        assert_eq!(endpoint_label("/api/v1/x/1"), endpoint_label("/api/v1/x/1"));
    }
}
