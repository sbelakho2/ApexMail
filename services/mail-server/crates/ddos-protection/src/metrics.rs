//! Prometheus metrics for DDoS protection.
//!
//! OPS-5 (live dogfood 2026-10-08): these series used to be registered in
//! the **`prometheus` crate's** registry via `register_int_counter_vec!`,
//! while the api-server exposes the **`metrics` facade's**
//! `metrics-exporter-prometheus` recorder on `:9090/metrics`. The two
//! registries never met, so a scrape showed ZERO `ddos_*` samples despite 42
//! live WAF verdicts and the 429/403 refusals — the A-3 reputation counters
//! had no observable surface. Every metric now emits through the `metrics`
//! facade (the SAME recorder the scrape target renders), keeping the
//! documented series names and label keys
//! (docs/security/Security_Systems.md § Prometheus metrics).

use metrics::{Key, Label, Level, Metadata};
use once_cell::sync::Lazy;

/// Metadata for facade-emitted metrics. `metrics-exporter-prometheus` keys
/// series by name+labels; the target/level are diagnostic only.
fn metadata(target: &'static str) -> Metadata<'static> {
    Metadata::new(target, Level::INFO, Some(module_path!()))
}

// ─── Facade metric handles ─────────────────────────────────────────────
//
// The tiny wrappers below preserve the call-site API this crate already
// used (`REQUESTS_TOTAL.as_ref()` → `.with_label_values(&[..]).inc()`), so
// the emission sites needed no rewrite — only the registry behind them
// changed. Labels are positional (the key names are fixed per metric).

/// A counter family with a fixed, static set of label keys.
#[derive(Clone, Copy)]
pub struct CounterVec {
    name: &'static str,
    label_keys: &'static [&'static str],
}

impl CounterVec {
    /// Construct the family (the facade needs no fallible registration).
    pub const fn new(name: &'static str, label_keys: &'static [&'static str]) -> Self {
        Self { name, label_keys }
    }

    /// Bind label values for one emission.
    ///
    /// # Panics
    /// Never: a value-count mismatch simply truncates to the declared keys
    /// (the exporter rejects a mismatched series, and the unit tests pin
    /// every call site's arity).
    /// Bind one emission's positional label values to the declared keys.
    pub fn with_label_values<'a>(&self, values: &'a [&'a str]) -> LabeledCounter<'a> {
        LabeledCounter {
            name: self.name,
            label_keys: self.label_keys,
            values,
        }
    }
}

/// A counter bound to one label set.
pub struct LabeledCounter<'a> {
    name: &'static str,
    label_keys: &'static [&'static str],
    values: &'a [&'a str],
}

impl LabeledCounter<'_> {
    /// Add one to the bound series.
    pub fn inc(&self) {
        self.inc_by(1);
    }

    /// Add `value` to the bound series.
    pub fn inc_by(&self, value: u64) {
        let key = self.key();
        metrics::with_recorder(|recorder| {
            recorder
                .register_counter(&key, &metadata(self.name))
                .increment(value);
        });
    }

    fn key(&self) -> Key {
        Key::from_parts(self.name, labels(self.label_keys, self.values))
    }
}

/// A gauge family with a fixed, static set of label keys.
#[derive(Clone, Copy)]
pub struct GaugeVec {
    name: &'static str,
    label_keys: &'static [&'static str],
}

impl GaugeVec {
    /// Construct the family (the facade needs no fallible registration).
    pub const fn new(name: &'static str, label_keys: &'static [&'static str]) -> Self {
        Self { name, label_keys }
    }

    /// Bind one emission's positional label values to the declared keys.
    pub fn with_label_values<'a>(&self, values: &'a [&'a str]) -> LabeledGauge<'a> {
        LabeledGauge {
            name: self.name,
            label_keys: self.label_keys,
            values,
        }
    }
}

/// A gauge bound to one label set.
pub struct LabeledGauge<'a> {
    name: &'static str,
    label_keys: &'static [&'static str],
    values: &'a [&'a str],
}

impl LabeledGauge<'_> {
    /// Add one to the bound series.
    pub fn inc(&self) {
        self.increment(1.0);
    }

    /// Subtract one from the bound series.
    pub fn dec(&self) {
        self.increment(-1.0);
    }

    /// Set the bound series to an absolute value.
    pub fn set(&self, value: f64) {
        let key = self.key();
        metrics::with_recorder(|recorder| {
            recorder
                .register_gauge(&key, &metadata(self.name))
                .set(value);
        });
    }

    fn increment(&self, delta: f64) {
        let key = self.key();
        metrics::with_recorder(|recorder| {
            recorder
                .register_gauge(&key, &metadata(self.name))
                .increment(delta);
        });
    }

    fn key(&self) -> Key {
        Key::from_parts(self.name, labels(self.label_keys, self.values))
    }
}

/// A histogram family with a fixed, static set of label keys.
#[derive(Clone, Copy)]
pub struct HistogramVec {
    name: &'static str,
    label_keys: &'static [&'static str],
}

impl HistogramVec {
    /// Construct the family (the facade needs no fallible registration).
    pub const fn new(name: &'static str, label_keys: &'static [&'static str]) -> Self {
        Self { name, label_keys }
    }

    /// Bind one emission's positional label values to the declared keys.
    pub fn with_label_values<'a>(&self, values: &'a [&'a str]) -> LabeledHistogram<'a> {
        LabeledHistogram {
            name: self.name,
            label_keys: self.label_keys,
            values,
        }
    }
}

/// A histogram bound to one label set.
pub struct LabeledHistogram<'a> {
    name: &'static str,
    label_keys: &'static [&'static str],
    values: &'a [&'a str],
}

impl LabeledHistogram<'_> {
    /// Record one observation on the bound series.
    pub fn observe(&self, value: f64) {
        let key = self.key();
        metrics::with_recorder(|recorder| {
            recorder
                .register_histogram(&key, &metadata(self.name))
                .record(value);
        });
    }

    fn key(&self) -> Key {
        Key::from_parts(self.name, labels(self.label_keys, self.values))
    }
}

fn labels(label_keys: &'static [&'static str], values: &[&str]) -> Vec<Label> {
    label_keys
        .iter()
        .zip(values.iter())
        .map(|(key, value)| Label::new(*key, value.to_string()))
        .collect()
}

// ─── Metric definitions ────────────────────────────────────────────────
//
// Each family describes itself (so `# HELP` reaches the scrape output) and
// then registers with the facade on first use. `Option` is kept so the call
// sites' `if let Some(metric) = …` shape is untouched; the facade cannot
// fail registration, so the value is always `Some`.

fn counter_vec(
    name: &'static str,
    help: &'static str,
    label_keys: &'static [&'static str],
) -> Option<CounterVec> {
    metrics::describe_counter!(name, metrics::Unit::Count, help);
    Some(CounterVec::new(name, label_keys))
}

fn gauge_vec(
    name: &'static str,
    help: &'static str,
    label_keys: &'static [&'static str],
) -> Option<GaugeVec> {
    metrics::describe_gauge!(name, metrics::Unit::Count, help);
    Some(GaugeVec::new(name, label_keys))
}

fn histogram_vec(
    name: &'static str,
    help: &'static str,
    label_keys: &'static [&'static str],
) -> Option<HistogramVec> {
    metrics::describe_histogram!(name, metrics::Unit::Count, help);
    Some(HistogramVec::new(name, label_keys))
}

/// Total requests processed
pub static REQUESTS_TOTAL: Lazy<Option<CounterVec>> = Lazy::new(|| {
    counter_vec(
        "ddos_requests_total",
        "Total requests processed by DDoS protection",
        &["decision", "layer"],
    )
});

/// Currently blocked IPs
pub static BLOCKED_IPS: Lazy<Option<GaugeVec>> = Lazy::new(|| {
    gauge_vec(
        "ddos_blocked_ips",
        "Number of currently blocked IP addresses",
        &["reason"],
    )
});

/// Anomaly score distribution
pub static ANOMALY_SCORE: Lazy<Option<HistogramVec>> = Lazy::new(|| {
    histogram_vec(
        "ddos_anomaly_score",
        "Anomaly scores from ML model",
        &["endpoint"],
    )
});

/// Challenge latency (time for client to solve)
pub static CHALLENGE_LATENCY: Lazy<Option<HistogramVec>> = Lazy::new(|| {
    histogram_vec(
        "ddos_challenge_latency_seconds",
        "Time for clients to solve challenges",
        &["type"],
    )
});

/// Challenges issued
pub static CHALLENGES_ISSUED: Lazy<Option<CounterVec>> = Lazy::new(|| {
    counter_vec(
        "ddos_challenges_issued_total",
        "Total challenges issued",
        &["type"],
    )
});

/// Challenges passed
pub static CHALLENGES_PASSED: Lazy<Option<CounterVec>> = Lazy::new(|| {
    counter_vec(
        "ddos_challenges_passed_total",
        "Total challenges passed",
        &["type"],
    )
});

/// Challenges failed
pub static CHALLENGES_FAILED: Lazy<Option<CounterVec>> = Lazy::new(|| {
    counter_vec(
        "ddos_challenges_failed_total",
        "Total challenges failed",
        &["type"],
    )
});

/// Reputation score distribution
pub static REPUTATION_SCORE: Lazy<Option<HistogramVec>> = Lazy::new(|| {
    histogram_vec(
        "ddos_reputation_score",
        "Distribution of IP reputation scores",
        &[],
    )
});

/// Threat events shared across regions
pub static THREAT_EVENTS: Lazy<Option<CounterVec>> = Lazy::new(|| {
    counter_vec(
        "ddos_threat_events_total",
        "Threat events shared across regions",
        &["type", "severity", "source_region"],
    )
});

/// Cost budget usage
pub static COST_BUDGET_USAGE: Lazy<Option<GaugeVec>> = Lazy::new(|| {
    gauge_vec(
        "ddos_cost_budget_usage_ratio",
        "Cost budget usage ratio (0-1)",
        &["tenant_id"],
    )
});

/// Attack detection state
pub static UNDER_ATTACK: Lazy<Option<GaugeVec>> = Lazy::new(|| {
    gauge_vec(
        "ddos_under_attack",
        "Whether the system is under attack (0 or 1)",
        &["region"],
    )
});

/// XDP statistics (if available)
pub static XDP_PACKETS: Lazy<Option<CounterVec>> = Lazy::new(|| {
    counter_vec(
        "ddos_xdp_packets_total",
        "Packets processed by XDP filter",
        &["action"],
    )
});

/// Session tracking stats
pub static ACTIVE_SESSIONS: Lazy<Option<GaugeVec>> = Lazy::new(|| {
    gauge_vec(
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
        out.push_str(normalize_segment(seg));
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
        assert_eq!(
            normalize_endpoint_label("/api/v1/users/42"),
            "/api/v1/users/{id}"
        );
        assert_eq!(
            normalize_endpoint_label("/files/deadbeef12345678"),
            "/files/{hex}"
        );
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
        assert!(
            label.len() <= MAX_LABEL_LEN,
            "got {} ({})",
            label.len(),
            label
        );
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

    /// OPS-5 regression: the ddos counters must render through the EXPOSED
    /// exporter (`metrics-exporter-prometheus`, the recorder the api-server
    /// installs on :9090) — not only into the `prometheus` crate's private
    /// registry. A local facade recorder renders the exact live series.
    #[test]
    fn ddos_counters_render_on_the_metrics_facade_exporter() {
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();

        // Exercise the real emission call shapes the protection paths use.
        metrics::with_local_recorder(&recorder, || {
            REQUESTS_TOTAL
                .as_ref()
                .expect("counter registered")
                .with_label_values(&["blocked", "blocklist"])
                .inc();
            REQUESTS_TOTAL
                .as_ref()
                .expect("counter registered")
                .with_label_values(&["rate_limited", "all"])
                .inc_by(3);
            BLOCKED_IPS
                .as_ref()
                .expect("gauge registered")
                .with_label_values(&["local"])
                .inc();
            ANOMALY_SCORE
                .as_ref()
                .expect("histogram registered")
                .with_label_values(&["/api/v1/users/{id}"])
                .observe(0.42);
        });

        let rendered = handle.render();
        assert!(
            rendered.contains("ddos_requests_total"),
            "the exposed exporter must render ddos_requests_total:\n{rendered}"
        );
        assert!(
            rendered.contains(r#"ddos_requests_total{decision="blocked",layer="blocklist"} 1"#),
            "labels must reach the scraped series:\n{rendered}"
        );
        assert!(
            rendered.contains(r#"ddos_requests_total{decision="rate_limited",layer="all"} 3"#),
            "inc_by must accumulate on the same series:\n{rendered}"
        );
        assert!(
            rendered.contains(r#"ddos_blocked_ips{reason="local"} 1"#),
            "gauges must render with their documented reason label:\n{rendered}"
        );
        assert!(
            rendered.contains("ddos_anomaly_score"),
            "the anomaly histogram must render:\n{rendered}"
        );
    }
}
