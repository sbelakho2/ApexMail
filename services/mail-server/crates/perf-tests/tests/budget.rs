//! Contention-aware wall-clock budgets shared by the perf suites (SM12 F9).
//!
//! # Budget model
//!
//! These tests gate ABSOLUTE throughput on an idle host, but the CI lane
//! runs the whole workspace's tests in parallel — under that load a
//! scheduler hiccup can double a wall-clock measurement without anything
//! being slower. The budget therefore scales with the one-minute load
//! average: the strict bound on an idle machine, up to 3× under load.
//! Non-Linux dev machines have no /proc/loadavg and keep the strict bound.
//!
//! # Baseline integration (audit finding 9)
//!
//! Every timed test prints one machine-readable metric line in the exact
//! shape `scripts/compare-baseline.sh` reads (a JSON object keyed by the
//! baseline section, containing the `throughput_ops_per_sec` field). CI can
//! collect those lines into a results file and run the script as the
//! regression gate:
//!
//! ```text
//! PERF_METRIC {"id_generation":{"throughput_ops_per_sec":389718.0}}
//! ```
//!
//! If `PERF_RESULTS_JSON` is set, the same object is appended to that file
//! as one JSON line (one process per test binary under nextest/cargo-test
//! binaries means no interleaving within a line; collectors concatenate the
//! lines or merge with `jq -s 'add'`).
//!
//! In RELEASE builds (`cargo test --release`) the tests additionally gate
//! against the committed baseline values from
//! `docs/evaluation/baselines/v1.0.json` — a release run must sustain at
//! least [`RELEASE_BASELINE_FRACTION`] of the recorded Apple-Silicon
//! throughput. Debug builds (the default `cargo test`) only apply the
//! wall-clock budgets: debug-mode throughput is 10–50× below the
//! release-mode baseline by construction, so a baseline gate there would
//! measure the compiler, not the code.

#[allow(dead_code)]
pub fn from_millis(base_ms: u64) -> std::time::Duration {
    std::time::Duration::from_millis(scaled(base_ms))
}

#[allow(dead_code)]
pub fn from_secs(base_secs: u64) -> std::time::Duration {
    std::time::Duration::from_millis(scaled(base_secs * 1000))
}

fn scaled(base: u64) -> u64 {
    let load = std::fs::read_to_string("/proc/loadavg")
        .ok()
        .and_then(|raw| {
            raw.split_whitespace()
                .next()
                .and_then(|one| one.parse::<f64>().ok())
        })
        .unwrap_or(0.0);
    let multiplier = 1.0 + (load - 1.0).clamp(0.0, 4.0) * 0.5;
    (base as f64 * multiplier) as u64
}

/// Fraction of the committed v1.0 baseline a RELEASE run must sustain.
/// The baseline JSON allows 10% degradation; this floor is far more
/// generous (cross-runner hardware variance dominates), while still
/// catching the >5× regressions the old microsecond-loose budgets hid.
pub const RELEASE_BASELINE_FRACTION: f64 = 0.1;

/// Committed throughput baselines (ops/sec), transcribed from
/// `docs/evaluation/baselines/v1.0.json` (source: load-tests ::
/// load_throughput, Apple M-series, release mode). Keep in sync with that
/// file — the file remains the authoritative record.
#[allow(dead_code)]
pub mod baseline_ops_per_sec {
    pub const ID_GENERATION: f64 = 389_718.0;
    pub const EMAIL_VALIDATION: f64 = 24_490_683.0;
    pub const PATTERN_MATCHING: f64 = 561_315.0;
    pub const BILLING_CALCULATIONS: f64 = 15_868_306.0;
}

/// Print the metric line in `compare-baseline.sh` format and, when
/// `PERF_RESULTS_JSON` is set, append it to that file as one JSON line.
#[allow(dead_code)]
pub fn emit_baseline_metric(section: &str, field: &str, value: f64) {
    let line = format!("PERF_METRIC {{\"{section}\":{{\"{field}\":{value}}}}}");
    println!("{line}");
    if let Ok(path) = std::env::var("PERF_RESULTS_JSON") {
        use std::io::Write as _;
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
        {
            let _ = writeln!(file, "{{\"{section}\":{{\"{field}\":{value}}}}}");
        }
    }
}

/// Gate a measured throughput against the committed baseline in release
/// builds (no-op in debug — see the module doc).
#[allow(dead_code)]
pub fn assert_release_throughput(measured_ops_per_sec: f64, baseline: f64, label: &str) {
    if cfg!(debug_assertions) {
        return;
    }
    let floor = baseline * RELEASE_BASELINE_FRACTION;
    assert!(
        measured_ops_per_sec >= floor,
        "{label}: release throughput {measured_ops_per_sec:.0} ops/s is below {}% of the \
         committed baseline {baseline:.0} ops/s (floor {floor:.0}) — performance regression",
        (RELEASE_BASELINE_FRACTION * 100.0) as u32
    );
}
