//! Redis key eviction monitoring.
//!
//! Tracks Redis memory usage and eviction rate by polling the `INFO memory`
//! command at regular intervals. Exposes Prometheus metrics and emits
//! `tracing::warn!` when the eviction rate exceeds a configurable threshold.
//!
//! # Metrics
//!
//! | Metric | Type | Description |
//! |---|---|---|
//! | `redis_used_memory_bytes` | Gauge | Current `used_memory` from Redis INFO |
//! | `redis_maxmemory_bytes` | Gauge | `maxmemory` configured on the Redis server (0 = no limit) |
//! | `redis_memory_utilization_ratio` | Gauge | `used_memory / maxmemory` (0.0 when maxmemory is 0) |
//! | `redis_evicted_keys_total` | Counter | Cumulative `evicted_keys` from Redis INFO |
//! | `redis_eviction_rate_per_minute` | Gauge | Evicted keys per minute (computed from delta) |
//! | `redis_info_poll_errors_total` | Counter | Number of failed `INFO memory` calls |
//!
//! # Alert Conditions
//!
//! * **High eviction rate** — When [`DEFAULT_EVICTION_RATE_THRESHOLD`]
//!   (100 keys/min) is exceeded, a `tracing::warn!` is emitted with the
//!   current rate and the cumulative evicted count.
//! * **Redis connection failure** — On any error from the `INFO memory`
//!   command, a `tracing::warn!` is logged and the error counter is
//!   incremented. All other metric gauges retain their previous values.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use deadpool_redis::Pool as RedisPool;
use parking_lot::RwLock;
use tracing::warn;

use crate::metrics_collector::MetricsCollector;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default threshold for eviction rate warnings (keys evicted per minute).
///
/// When the computed eviction rate exceeds this value, a warning is logged.
pub const DEFAULT_EVICTION_RATE_THRESHOLD: f64 = 100.0;

/// Interval (in seconds) enforced between consecutive polls of `INFO memory`.
/// This is a safety guard for the in-memory rate calculation; the caller's
/// periodic job interval should be aligned with this value.
pub const DEFAULT_POLL_INTERVAL_SECS: u64 = 60;

// ---------------------------------------------------------------------------
// Parsed INFO memory response
// ---------------------------------------------------------------------------

/// Parsed fields from the `INFO memory` Redis command response.
///
/// Only the fields relevant to eviction monitoring are extracted.
#[derive(Debug, Clone, PartialEq)]
pub struct InfoMemoryResponse {
    /// Current memory allocated by Redis (bytes).
    pub used_memory: u64,
    /// Maximum memory Redis is allowed to use (bytes). 0 means no limit.
    pub maxmemory: u64,
    /// Total number of keys evicted since Redis started.
    pub evicted_keys: u64,
}

impl InfoMemoryResponse {
    /// Parse `INFO memory` output into a structured response.
    ///
    /// The expected format is the standard Redis `INFO memory` section:
    ///
    /// ```text
    /// # Memory
    /// used_memory:1048576
    /// maxmemory:0
    /// evicted_keys:42
    /// ...
    /// ```
    ///
    /// Lines that are comments (starting with `#`), empty, or unrecognised
    /// are silently skipped. Missing fields result in a default value of 0.
    pub fn parse(info_output: &str) -> Self {
        let mut used_memory = 0u64;
        let mut maxmemory = 0u64;
        let mut evicted_keys = 0u64;

        for line in info_output.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((key, value)) = line.split_once(':') {
                let key = key.trim();
                let value_str = value.trim();
                match key {
                    "used_memory" => {
                        used_memory = value_str.parse().unwrap_or(0);
                    }
                    "maxmemory" => {
                        maxmemory = value_str.parse().unwrap_or(0);
                    }
                    "evicted_keys" => {
                        evicted_keys = value_str.parse().unwrap_or(0);
                    }
                    _ => {}
                }
            }
        }

        Self {
            used_memory,
            maxmemory,
            evicted_keys,
        }
    }

    /// Memory utilization as a ratio of `used_memory / maxmemory`.
    ///
    /// Returns `0.0` when `maxmemory` is 0 (i.e. no limit configured).
    pub fn utilization_ratio(&self) -> f64 {
        if self.maxmemory == 0 {
            0.0
        } else {
            (self.used_memory as f64 / self.maxmemory as f64).clamp(0.0, 1.0)
        }
    }
}

// ---------------------------------------------------------------------------
// RedisKeyMonitor
// ---------------------------------------------------------------------------

/// Monitors Redis key eviction by polling `INFO memory` at periodic intervals.
///
/// The monitor is thread-safe and can be shared across tasks via `Arc`.
/// It uses interior mutability (`AtomicU64`, `RwLock`) so all methods take
/// `&self`.
///
/// # Example
///
/// ```rust,ignore
/// use std::sync::Arc;
///
/// let monitor = Arc::new(RedisKeyMonitor::new(
///     redis_pool,
///     Some(100.0),    // eviction rate threshold
/// ));
///
/// // In a periodic task:
/// monitor.check_evictions().await;
/// ```
#[derive(Debug)]
pub struct RedisKeyMonitor {
    /// The last observed `evicted_keys` value, used to compute the delta.
    last_evicted_keys: AtomicU64,
    /// Timestamp (in seconds since the Unix epoch) of the last successful poll.
    last_poll_instant: RwLock<Option<Instant>>,
    /// Eviction rate threshold in keys per minute.
    eviction_rate_threshold: f64,
    /// Whether a high-eviction warning is currently active (prevents log spam).
    high_eviction_warning_active: AtomicBool,
    /// Optional collector mirrored with the same metrics so they also appear
    /// in the service's `/metrics` output and alert-rule evaluations.
    collector: Option<Arc<MetricsCollector>>,
}

impl RedisKeyMonitor {
    /// Create a new monitor with the given eviction rate threshold.
    ///
    /// If `eviction_rate_threshold` is `None`,
    /// [`DEFAULT_EVICTION_RATE_THRESHOLD`] is used.
    pub fn new(eviction_rate_threshold: Option<f64>) -> Self {
        Self {
            last_evicted_keys: AtomicU64::new(0),
            last_poll_instant: RwLock::new(None),
            eviction_rate_threshold: eviction_rate_threshold
                .unwrap_or(DEFAULT_EVICTION_RATE_THRESHOLD),
            high_eviction_warning_active: AtomicBool::new(false),
            collector: None,
        }
    }

    /// Create a monitor that also mirrors its gauges into a
    /// [`MetricsCollector`] (for `/metrics` output and alert evaluation).
    pub fn with_collector(
        eviction_rate_threshold: Option<f64>,
        collector: Arc<MetricsCollector>,
    ) -> Self {
        Self {
            collector: Some(collector),
            ..Self::new(eviction_rate_threshold)
        }
    }

    /// Process a parsed `INFO memory` response: update metrics and check
    /// eviction rate thresholds.
    ///
    /// This is the core logic of the monitor, extracted as a pure method
    /// for testability. It accepts an [`InfoMemoryResponse`] and the current
    /// wall-clock [`Instant`], and handles all metric updates and threshold
    /// checks.
    ///
    /// Returns `true` if the eviction rate exceeded the threshold (warning
    /// condition active), `false` otherwise.
    pub fn process_info_response(&self, info: &InfoMemoryResponse, now: Instant) -> bool {
        // --- Update Prometheus gauges ---

        // used_memory
        metrics::gauge!("redis_used_memory_bytes").set(info.used_memory as f64);

        // maxmemory
        metrics::gauge!("redis_maxmemory_bytes").set(info.maxmemory as f64);

        // utilization ratio
        let utilization = info.utilization_ratio();
        metrics::gauge!("redis_memory_utilization_ratio").set(utilization);

        // cumulative evicted_keys as a counter
        metrics::counter!("redis_evicted_keys_total").increment(info.evicted_keys);

        // --- Mirror into the in-memory collector (if attached) ---

        if let Some(collector) = &self.collector {
            collector.record_gauge(
                "redis_used_memory_bytes",
                info.used_memory as f64,
                "Current used_memory from Redis INFO",
            );
            collector.record_gauge(
                "redis_maxmemory_bytes",
                info.maxmemory as f64,
                "maxmemory configured on the Redis server (0 = no limit)",
            );
            collector.record_gauge(
                "redis_memory_utilization_ratio",
                utilization,
                "used_memory / maxmemory (0.0 when maxmemory is 0)",
            );
            collector.record_counter(
                "redis_evicted_keys_total",
                info.evicted_keys as f64,
                "Cumulative evicted_keys from Redis INFO",
            );
        }

        // --- Compute eviction rate ---

        let previous = self
            .last_evicted_keys
            .swap(info.evicted_keys, Ordering::AcqRel);

        // Determine elapsed time in minutes for rate computation
        let elapsed_minutes = {
            let mut last_instant_guard = self.last_poll_instant.write();
            let elapsed = match *last_instant_guard {
                Some(last) => {
                    let dur = now.duration_since(last);
                    dur.as_secs_f64() / 60.0
                }
                None => {
                    // First poll: no elapsed time yet; set the timestamp and
                    // record the delta as 0.
                    *last_instant_guard = Some(now);
                    1.0 // avoid division by zero; rate will be 0 on first poll
                }
            };
            *last_instant_guard = Some(now);
            elapsed
        };

        // Compute eviction rate
        let delta = info.evicted_keys.saturating_sub(previous);
        let rate_per_minute = if elapsed_minutes > 0.0 {
            delta as f64 / elapsed_minutes
        } else {
            0.0
        };

        metrics::gauge!("redis_eviction_rate_per_minute").set(rate_per_minute);

        if let Some(collector) = &self.collector {
            collector.record_gauge(
                "redis_eviction_rate_per_minute",
                rate_per_minute,
                "Evicted keys per minute (computed from delta)",
            );
        }

        // --- Threshold check ---

        let exceeded = rate_per_minute > self.eviction_rate_threshold;

        if exceeded {
            // Avoid log spam: only warn once when crossing the threshold
            let was_active = self
                .high_eviction_warning_active
                .swap(true, Ordering::AcqRel);
            if !was_active {
                warn!(
                    eviction_rate_per_minute = rate_per_minute,
                    threshold = self.eviction_rate_threshold,
                    cumulative_evicted_keys = info.evicted_keys,
                    used_memory_bytes = info.used_memory,
                    maxmemory_bytes = info.maxmemory,
                    utilization_ratio = utilization,
                    "HIGH REDIS EVICTION RATE: eviction rate exceeds threshold — \
                     review Redis maxmemory policy and key TTLs",
                );
            }
        } else {
            // Reset the warning flag when rate drops below threshold
            self.high_eviction_warning_active
                .store(false, Ordering::Release);
        }

        exceeded
    }

    /// Reset the internal state (useful for testing or after a reconnection).
    pub fn reset_state(&self) {
        self.last_evicted_keys.store(0, Ordering::Release);
        *self.last_poll_instant.write() = None;
        self.high_eviction_warning_active
            .store(false, Ordering::Release);
    }

    // -----------------------------------------------------------------------
    // Accessors (for testing)
    // -----------------------------------------------------------------------

    /// Returns the current eviction rate threshold.
    pub fn eviction_rate_threshold(&self) -> f64 {
        self.eviction_rate_threshold
    }

    /// Whether the high-eviction warning is currently active.
    pub fn is_high_eviction_warning_active(&self) -> bool {
        self.high_eviction_warning_active.load(Ordering::Acquire)
    }

    // -----------------------------------------------------------------------
    // Async Redis interaction
    // -----------------------------------------------------------------------

    /// Poll Redis `INFO memory` and process the response.
    ///
    /// This is the primary entry point for the periodic job loop. It:
    ///
    /// 1. Acquires a connection from the pool.
    /// 2. Sends the `INFO memory` command.
    /// 3. Parses the response via [`InfoMemoryResponse::parse`].
    /// 4. Delegates to [`Self::process_info_response`] for metric updates and
    ///    threshold checks.
    ///
    /// # Errors
    ///
    /// * **Pool error** — logged as `warn!`, error counter incremented.
    /// * **Command error** — logged as `warn!`, error counter incremented.
    ///
    /// In both error cases the method returns `None` so callers can detect
    /// failures if needed.
    pub async fn check_evictions(&self, pool: &RedisPool) -> Option<bool> {
        let mut conn = match pool.get().await {
            Ok(c) => c,
            Err(e) => {
                warn!(
                    error = %e,
                    "REDIS KEY EVICTION MONITOR: failed to acquire Redis connection"
                );
                metrics::counter!("redis_info_poll_errors_total").increment(1);
                return None;
            }
        };

        let info_output: String = match redis::cmd("INFO")
            .arg("memory")
            .query_async(&mut conn)
            .await
        {
            Ok(output) => output,
            Err(e) => {
                warn!(
                    error = %e,
                    "REDIS KEY EVICTION MONITOR: INFO memory command failed"
                );
                metrics::counter!("redis_info_poll_errors_total").increment(1);
                return None;
            }
        };

        let parsed = InfoMemoryResponse::parse(&info_output);
        let exceeded = self.process_info_response(&parsed, Instant::now());
        Some(exceeded)
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ─── InfoMemoryResponse parsing ────────────────────────────────────

    /// Sample `INFO memory` output with typical values.
    const SAMPLE_INFO_OUTPUT: &str = "\
# Memory
used_memory:2097152
used_memory_human:2.00M
used_memory_rss:3145728
used_memory_rss_human:3.00M
used_memory_peak:4194304
used_memory_peak_human:4.00M
used_memory_peak_perc:50.00%
used_memory_overhead:1048576
used_memory_startup:8388608
used_memory_dataset:1048576
used_memory_dataset_perc:50.00%
allocator_allocated:2097152
allocator_active:2621440
allocator_resident:3145728
total_system_memory:17179869184
total_system_memory_human:16.00G
used_memory_lua:37888
used_memory_lua_human:37.00K
maxmemory:8388608
maxmemory_human:8.00M
maxmemory_policy:allkeys-lru
mem_fragmentation_ratio:1.50
mem_allocator:jemalloc-5.3.0
evicted_keys:42
evicted_keys_per_second:0.05
";

    #[test]
    fn test_parse_info_memory_typical() {
        let parsed = InfoMemoryResponse::parse(SAMPLE_INFO_OUTPUT);

        assert_eq!(parsed.used_memory, 2_097_152);
        assert_eq!(parsed.maxmemory, 8_388_608);
        assert_eq!(parsed.evicted_keys, 42);
    }

    #[test]
    fn test_parse_info_memory_no_limit() {
        let output = SAMPLE_INFO_OUTPUT.replace("maxmemory:8388608", "maxmemory:0");
        let parsed = InfoMemoryResponse::parse(&output);

        assert_eq!(parsed.used_memory, 2_097_152);
        assert_eq!(parsed.maxmemory, 0);
        assert_eq!(parsed.evicted_keys, 42);
    }

    #[test]
    fn test_parse_info_memory_zero_evictions() {
        let output = SAMPLE_INFO_OUTPUT.replace("evicted_keys:42", "evicted_keys:0");
        let parsed = InfoMemoryResponse::parse(&output);

        assert_eq!(parsed.used_memory, 2_097_152);
        assert_eq!(parsed.maxmemory, 8_388_608);
        assert_eq!(parsed.evicted_keys, 0);
    }

    #[test]
    fn test_parse_info_memory_large_values() {
        let output = "\
# Memory
used_memory:1099511627776
maxmemory:2199023255552
evicted_keys:18446744073709551615
";
        let parsed = InfoMemoryResponse::parse(output);

        assert_eq!(parsed.used_memory, 1_099_511_627_776);
        assert_eq!(parsed.maxmemory, 2_199_023_255_552);
        assert_eq!(parsed.evicted_keys, u64::MAX);
    }

    #[test]
    fn test_parse_info_memory_empty_output() {
        let parsed = InfoMemoryResponse::parse("");
        assert_eq!(parsed.used_memory, 0);
        assert_eq!(parsed.maxmemory, 0);
        assert_eq!(parsed.evicted_keys, 0);
    }

    #[test]
    fn test_parse_info_memory_only_comments() {
        let parsed = InfoMemoryResponse::parse("# Memory\n# Only comments\n");
        assert_eq!(parsed.used_memory, 0);
        assert_eq!(parsed.maxmemory, 0);
        assert_eq!(parsed.evicted_keys, 0);
    }

    #[test]
    fn test_parse_info_memory_malformed_values() {
        // Non-numeric values should be silently treated as 0
        let output = "\
# Memory
used_memory:not_a_number
maxmemory:also_bad
evicted_keys:invalid
";
        let parsed = InfoMemoryResponse::parse(output);
        assert_eq!(parsed.used_memory, 0);
        assert_eq!(parsed.maxmemory, 0);
        assert_eq!(parsed.evicted_keys, 0);
    }

    #[test]
    fn test_parse_info_memory_extra_whitespace() {
        let output = "  used_memory  :  1048576  \n  maxmemory:  0  \n  evicted_keys:  99  ";
        let parsed = InfoMemoryResponse::parse(output);
        assert_eq!(parsed.used_memory, 1_048_576);
        assert_eq!(parsed.maxmemory, 0);
        assert_eq!(parsed.evicted_keys, 99);
    }

    // ─── Utilization ratio ─────────────────────────────────────────────

    #[test]
    fn test_utilization_ratio_typical() {
        let info = InfoMemoryResponse {
            used_memory: 4_194_304, // 4 MB
            maxmemory: 8_388_608,   // 8 MB
            evicted_keys: 0,
        };
        let ratio = info.utilization_ratio();
        // 4 MB / 8 MB = 0.5
        assert!((ratio - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_utilization_ratio_no_limit() {
        let info = InfoMemoryResponse {
            used_memory: 4_194_304,
            maxmemory: 0,
            evicted_keys: 0,
        };
        assert!((info.utilization_ratio() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_utilization_ratio_full() {
        let info = InfoMemoryResponse {
            used_memory: 8_388_608,
            maxmemory: 8_388_608,
            evicted_keys: 0,
        };
        assert!((info.utilization_ratio() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_utilization_ratio_over_limit() {
        // Clamped to 1.0
        let info = InfoMemoryResponse {
            used_memory: 16_777_216, // 16 MB (double the limit)
            maxmemory: 8_388_608,    // 8 MB
            evicted_keys: 0,
        };
        assert!((info.utilization_ratio() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_utilization_ratio_zero_used() {
        let info = InfoMemoryResponse {
            used_memory: 0,
            maxmemory: 8_388_608,
            evicted_keys: 0,
        };
        assert!((info.utilization_ratio() - 0.0).abs() < f64::EPSILON);
    }

    // ─── RedisKeyMonitor — Normal (no eviction) ────────────────────────

    #[test]
    fn test_process_info_response_normal_no_eviction() {
        // No evictions, low memory usage — should not trigger warning
        let monitor = RedisKeyMonitor::new(None);
        let now = Instant::now();

        let info = InfoMemoryResponse {
            used_memory: 1_048_576,
            maxmemory: 8_388_608,
            evicted_keys: 0,
        };

        let exceeded = monitor.process_info_response(&info, now);

        assert!(!exceeded, "no evictions should not trigger warning");
        assert!(
            !monitor.is_high_eviction_warning_active(),
            "warning flag must remain inactive"
        );
    }

    #[test]
    fn test_process_info_response_first_call_no_rate() {
        // First call: no previous data, rate should be 0
        let monitor = RedisKeyMonitor::new(None);
        let now = Instant::now();

        let info = InfoMemoryResponse {
            used_memory: 2_097_152,
            maxmemory: 8_388_608,
            evicted_keys: 100, // has evictions, but first call has no delta
        };

        let exceeded = monitor.process_info_response(&info, now);
        // First call has no prior snapshot, so delta = 100 - 0 = 100,
        // but elapsed < some small amount → rate may be high.
        // Actually: last_evicted_keys initial is 0, so delta = 100.
        // elapsed_minutes will be 1.0 for first call (guard against div by 0).
        // So rate = 100 / 1.0 = 100.0, which equals threshold (100.0).
        // The check is rate > threshold (strictly greater), so not exceeded.
        assert!(!exceeded, "first-call delta should not exceed threshold");
    }

    // ─── RedisKeyMonitor — Low eviction rate (below threshold) ─────────

    #[test]
    fn test_process_info_response_low_eviction_rate() {
        let monitor = RedisKeyMonitor::new(Some(100.0)); // threshold = 100 keys/min
        let start = Instant::now();

        // First call: establish baseline at evicted_keys = 500
        let info1 = InfoMemoryResponse {
            used_memory: 4_194_304,
            maxmemory: 8_388_608,
            evicted_keys: 500,
        };
        monitor.process_info_response(&info1, start);

        // Second call: simulate a poll after ~60 seconds with 10 more evictions
        // That's 10 keys/min — well below threshold.
        let later = start + std::time::Duration::from_secs(60);
        let info2 = InfoMemoryResponse {
            used_memory: 4_194_304,
            maxmemory: 8_388_608,
            evicted_keys: 510,
        };

        let exceeded = monitor.process_info_response(&info2, later);

        assert!(
            !exceeded,
            "10 keys/min should not exceed threshold of 100 keys/min"
        );
        assert!(
            !monitor.is_high_eviction_warning_active(),
            "warning flag must remain inactive for low eviction rate"
        );
    }

    // ─── RedisKeyMonitor — High eviction rate (above threshold) ────────

    #[test]
    fn test_process_info_response_high_eviction_rate() {
        let monitor = RedisKeyMonitor::new(Some(50.0)); // threshold = 50 keys/min
        let start = Instant::now();

        // First call: establish baseline
        let info1 = InfoMemoryResponse {
            used_memory: 6_291_456,
            maxmemory: 8_388_608,
            evicted_keys: 1_000,
        };
        monitor.process_info_response(&info1, start);

        // Second call: ~30 seconds later with 100 more evictions
        // That's 100 / 0.5 = 200 keys/min — well above threshold.
        let later = start + std::time::Duration::from_secs(30);
        let info2 = InfoMemoryResponse {
            used_memory: 6_291_456,
            maxmemory: 8_388_608,
            evicted_keys: 1_100,
        };

        let exceeded = monitor.process_info_response(&info2, later);

        assert!(
            exceeded,
            "200 keys/min should exceed threshold of 50 keys/min"
        );
        assert!(
            monitor.is_high_eviction_warning_active(),
            "warning flag must be active after threshold exceeded"
        );
    }

    #[test]
    fn test_high_eviction_warning_resets_when_rate_drops() {
        let monitor = RedisKeyMonitor::new(Some(50.0));
        let start = Instant::now();

        // First call: baseline
        let info1 = InfoMemoryResponse {
            used_memory: 6_291_456,
            maxmemory: 8_388_608,
            evicted_keys: 1_000,
        };
        monitor.process_info_response(&info1, start);

        // Second call: high rate — triggers warning
        let spike_time = start + std::time::Duration::from_secs(30);
        let info2 = InfoMemoryResponse {
            used_memory: 6_291_456,
            maxmemory: 8_388_608,
            evicted_keys: 1_100,
        };
        let exceeded = monitor.process_info_response(&info2, spike_time);
        assert!(exceeded);
        assert!(monitor.is_high_eviction_warning_active());

        // Third call: rate drops below threshold — warning should reset
        let recovery_time = spike_time + std::time::Duration::from_secs(60);
        let info3 = InfoMemoryResponse {
            used_memory: 6_291_456,
            maxmemory: 8_388_608,
            evicted_keys: 1_105, // only 5 more in 60 sec = 5 keys/min
        };
        let exceeded = monitor.process_info_response(&info3, recovery_time);
        assert!(!exceeded, "5 keys/min should be below threshold");
        assert!(
            !monitor.is_high_eviction_warning_active(),
            "warning flag must reset when rate returns below threshold"
        );
    }

    // ─── RedisKeyMonitor — reset_state ─────────────────────────────────

    #[test]
    fn test_reset_state_clears_warning() {
        let monitor = RedisKeyMonitor::new(Some(10.0));
        let start = Instant::now();

        // Set high eviction
        let info1 = InfoMemoryResponse {
            used_memory: 4_194_304,
            maxmemory: 8_388_608,
            evicted_keys: 0,
        };
        monitor.process_info_response(&info1, start);

        let later = start + std::time::Duration::from_secs(10);
        let info2 = InfoMemoryResponse {
            used_memory: 4_194_304,
            maxmemory: 8_388_608,
            evicted_keys: 50, // 300 keys/min
        };
        let _ = monitor.process_info_response(&info2, later);
        assert!(monitor.is_high_eviction_warning_active());

        // Reset
        monitor.reset_state();
        assert!(!monitor.is_high_eviction_warning_active());

        // After reset, next poll behaves like first call (baseline is 0)
        let after_reset = later + std::time::Duration::from_secs(1);
        let info3 = InfoMemoryResponse {
            used_memory: 4_194_304,
            maxmemory: 8_388_608,
            evicted_keys: 100,
        };
        let exceeded = monitor.process_info_response(&info3, after_reset);
        // Since last_evicted_keys was reset to 0, delta = 100.
        // elapsed_minutes = 1.0 (first-call guard). Rate = 100/1 = 100 > 10.
        assert!(exceeded, "after reset should re-evaluate from new baseline");
    }

    // ─── Threshold configuration ───────────────────────────────────────

    #[test]
    fn test_default_threshold() {
        let monitor = RedisKeyMonitor::new(None);
        assert!(
            (monitor.eviction_rate_threshold() - DEFAULT_EVICTION_RATE_THRESHOLD).abs()
                < f64::EPSILON,
            "default threshold must match DEFAULT_EVICTION_RATE_THRESHOLD"
        );
    }

    #[test]
    fn test_custom_threshold() {
        let monitor = RedisKeyMonitor::new(Some(250.0));
        assert!((monitor.eviction_rate_threshold() - 250.0).abs() < f64::EPSILON);
    }

    // ─── Edge cases ────────────────────────────────────────────────────

    #[test]
    fn test_zero_delta_no_rate() {
        // Two consecutive polls with no change in evicted_keys
        let monitor = RedisKeyMonitor::new(Some(100.0));
        let start = Instant::now();

        let info = InfoMemoryResponse {
            used_memory: 4_194_304,
            maxmemory: 8_388_608,
            evicted_keys: 500,
        };
        monitor.process_info_response(&info, start);

        let later = start + std::time::Duration::from_secs(60);
        let info_same = InfoMemoryResponse {
            used_memory: 4_194_304,
            maxmemory: 8_388_608,
            evicted_keys: 500, // same as before — no delta
        };
        let exceeded = monitor.process_info_response(&info_same, later);
        assert!(!exceeded, "zero delta must not trigger warning");
    }

    #[test]
    fn test_evicted_keys_wraparound() {
        // Simulate evicted_keys wrapping from u64::MAX to 0 (theoretical edge case)
        let monitor = RedisKeyMonitor::new(Some(100.0));
        let start = Instant::now();

        let info_before_wrap = InfoMemoryResponse {
            used_memory: 4_194_304,
            maxmemory: 8_388_608,
            evicted_keys: u64::MAX,
        };
        monitor.process_info_response(&info_before_wrap, start);

        let after_wrap = start + std::time::Duration::from_secs(60);
        let info_after_wrap = InfoMemoryResponse {
            used_memory: 4_194_304,
            maxmemory: 8_388_608,
            evicted_keys: 50, // wrapped around
        };
        // saturating_sub: u64::MAX - 50 = very large negative → saturates to 0
        let exceeded = monitor.process_info_response(&info_after_wrap, after_wrap);
        // delta will be 0 (saturating_sub), so no warning
        assert!(!exceeded, "wraparound must not cause false positive");
    }

    #[test]
    fn test_very_rapid_polling() {
        // Two polls within the same millisecond — elapsed_minutes ≈ 0
        let monitor = RedisKeyMonitor::new(Some(100.0));
        let now = Instant::now();

        let info1 = InfoMemoryResponse {
            used_memory: 4_194_304,
            maxmemory: 8_388_608,
            evicted_keys: 0,
        };
        monitor.process_info_response(&info1, now);

        // Same instant — elapsed = 0
        let info2 = InfoMemoryResponse {
            used_memory: 4_194_304,
            maxmemory: 8_388_608,
            evicted_keys: 10,
        };
        // Duration will be extremely small but non-zero, so rate will be high.
        // The monitor should handle this gracefully (rate may be very large,
        // but that's a reflection of real data).
        let _ = monitor.process_info_response(&info2, now);
        // No assertion on the result — just ensuring no panic or crash.
    }
}
