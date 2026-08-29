//! Contention-aware wall-clock budgets shared by the perf suites.
//!
//! These tests gate ABSOLUTE throughput on an idle host, but the CI lane
//! runs the whole workspace's tests in parallel — under that load a
//! scheduler hiccup can double a wall-clock measurement without anything
//! being slower. The budget therefore scales with the one-minute load
//! average: the strict bound on an idle machine, up to 3× under load.
//! Non-Linux dev machines have no /proc/loadavg and keep the strict bound.

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
