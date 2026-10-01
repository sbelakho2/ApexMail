//! Structured log aggregation.
//!
//! In-memory log store with level/service filtering, per-level counts, and
//! error-rate calculation over a sliding window.
//!
//! When a [`PersistenceConfig`] is provided, the aggregator can periodically
//! flush log entries to the database to survive process restarts.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, VecDeque};

use chrono::{Duration, Utc};
use parking_lot::RwLock;

use crate::config::PersistenceConfig;
use crate::types::{LogEntry, LogLevel};

// ---------------------------------------------------------------------------
// LogAggregator
// ---------------------------------------------------------------------------

/// Serialized-size budget for ONE ingested entry's `context`/`metadata` map
/// (SM10 F15). The ingest route truncates only `message`, so a single entry
/// could previously carry megabytes of untruncated maps (a 2 MB body can be
/// one entry) and the default 500 000-entry store could hold gigabytes.
/// Maps over budget are shed key-by-key until they fit; a map that cannot
/// fit at all is dropped (`None`) rather than stored oversized.
const MAX_INGEST_MAP_BYTES: usize = 1024;

/// Approximate serialized size of a JSON value in bytes.
fn value_bytes(value: &serde_json::Value) -> usize {
    serde_json::to_vec(value)
        .map(|bytes| bytes.len())
        .unwrap_or(0)
}

/// Approximate serialized size of a context/metadata map (key + value +
/// per-entry overhead estimate).
fn map_bytes(map: &HashMap<String, serde_json::Value>) -> usize {
    map.iter().map(|(k, v)| k.len() + value_bytes(v) + 1).sum()
}

/// Bound one ingested map to [`MAX_INGEST_MAP_BYTES`] (SM10 F15).
///
/// Maps within budget pass through unchanged (the hot path — one size
/// computation, no copy). Over-budget maps are shed whole-key in
/// lexicographic key order (deterministic, so logs shed the same way on
/// every node) until the remainder fits; entries that do not fit are
/// dropped. A map with nothing left is `None`, not an empty husk.
fn cap_ingest_map(
    map: Option<HashMap<String, serde_json::Value>>,
) -> Option<HashMap<String, serde_json::Value>> {
    let map = map?;
    if map.is_empty() {
        return None;
    }
    if map_bytes(&map) <= MAX_INGEST_MAP_BYTES {
        return Some(map);
    }

    let mut keys: Vec<&String> = map.keys().collect();
    keys.sort();

    let mut kept: HashMap<String, serde_json::Value> = HashMap::new();
    let mut used = 0usize;
    for key in keys {
        let value = &map[key];
        let cost = key.len() + value_bytes(value) + 1;
        if used + cost <= MAX_INGEST_MAP_BYTES {
            used += cost;
            kept.insert(key.clone(), value.clone());
        }
    }
    if kept.is_empty() {
        None
    } else {
        Some(kept)
    }
}

/// Thread-safe in-memory structured log store.
/// Caps total stored entries at `max_entries`; when full, the oldest entries
/// are evicted on each insert to prevent unbounded memory growth.
///
/// The store is a ring (`VecDeque`): eviction pops from the front instead of
/// shifting the surviving half of a `Vec::drain`, and the allocation is
/// shrunk when the ring's slack grows past half the cap again, so evicted
/// capacity is actually returned (SM10 F15 — `Vec::drain` never shrank the
/// allocation).
///
/// Per-entry payloads are bounded at the single point every producer passes
/// through ([`LogAggregator::ingest`]): `context`/`metadata` maps are capped
/// by [`cap_ingest_map`].
///
/// Optionally persists log entries to the database when `persistence_config`
/// is `Some` and `enabled` is `true`.
#[derive(Debug)]
pub struct LogAggregator {
    entries: RwLock<VecDeque<LogEntry>>,
    max_entries: usize,
    persistence_config: Option<PersistenceConfig>,
}

impl LogAggregator {
    /// Create a new, empty aggregator with a default 500 000 entry cap.
    pub fn new() -> Self {
        Self::with_capacity(500_000)
    }

    /// Create an aggregator that retains at most `max_entries` entries.
    pub fn with_capacity(max_entries: usize) -> Self {
        Self {
            entries: RwLock::new(VecDeque::new()),
            max_entries,
            persistence_config: None,
        }
    }

    /// Create an aggregator with persistence configuration, enabling periodic
    /// flush of log entries to the database.
    pub fn with_persistence(max_entries: usize, config: PersistenceConfig) -> Self {
        Self {
            entries: RwLock::new(VecDeque::new()),
            max_entries,
            persistence_config: if config.enabled { Some(config) } else { None },
        }
    }

    /// Return the persistence configuration, if any.
    pub fn persistence(&self) -> Option<&PersistenceConfig> {
        self.persistence_config.as_ref()
    }

    /// Ingest a single log entry.
    /// If the store is at capacity, the oldest 10% of entries are evicted.
    /// The entry's `context`/`metadata` maps are size-capped before storage
    /// (SM10 F15).
    pub fn ingest(&self, mut entry: LogEntry) {
        entry.context = cap_ingest_map(entry.context);
        entry.metadata = cap_ingest_map(entry.metadata);

        let mut guard = self.entries.write();
        if guard.len() >= self.max_entries {
            let prune_count = guard.len() / 10;
            for _ in 0..prune_count {
                guard.pop_front();
            }
            // Return evicted capacity once the ring's slack passes half the
            // cap — bounding memory at ~1.5x max entries without paying a
            // realloc on every insert-at-capacity.
            if guard.capacity() > self.max_entries + self.max_entries / 2 {
                guard.shrink_to_fit();
            }
        }
        guard.push_back(entry);
    }

    /// Query logs with optional level and service filters, returning at most
    /// `limit` entries ordered newest-first.
    pub fn query(
        &self,
        level_filter: Option<LogLevel>,
        service_filter: Option<&str>,
        limit: usize,
    ) -> Vec<LogEntry> {
        if limit == 0 {
            return Vec::new();
        }

        let guard = self.entries.read();
        let mut heap: BinaryHeap<(Reverse<chrono::DateTime<Utc>>, usize)> = BinaryHeap::new();

        for (idx, entry) in guard.iter().enumerate() {
            let level_ok = level_filter.map(|l| entry.level >= l).unwrap_or(true);
            let svc_ok = service_filter.map(|s| entry.service == s).unwrap_or(true);
            if !level_ok || !svc_ok {
                continue;
            }

            heap.push((Reverse(entry.timestamp), idx));
            if heap.len() > limit {
                heap.pop();
            }
        }

        let mut results: Vec<LogEntry> = heap
            .into_iter()
            .map(|(_, idx)| guard[idx].clone())
            .collect();
        results.sort_by_key(|entry| Reverse(entry.timestamp));
        results
    }

    /// Return the count of log entries grouped by [`LogLevel`].
    pub fn count_by_level(&self) -> HashMap<LogLevel, usize> {
        let guard = self.entries.read();
        let mut counts = HashMap::new();
        for entry in guard.iter() {
            *counts.entry(entry.level).or_insert(0) += 1;
        }
        counts
    }

    /// Calculate the error rate (errors / total) within the last
    /// `window_secs` seconds. Returns 0.0 when there are no entries in the
    /// window.
    pub fn get_error_rate(&self, window_secs: i64) -> f64 {
        let guard = self.entries.read();
        let cutoff = Utc::now() - Duration::seconds(window_secs);

        let (mut total, mut errors) = (0u64, 0u64);
        for entry in guard.iter() {
            if entry.timestamp >= cutoff {
                total += 1;
                if entry.level >= LogLevel::Error {
                    errors += 1;
                }
            }
        }

        if total == 0 {
            0.0
        } else {
            errors as f64 / total as f64
        }
    }

    /// Total number of stored entries.
    pub fn len(&self) -> usize {
        self.entries.read().len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.read().is_empty()
    }
}

impl Default for LogAggregator {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn make_log(level: LogLevel, service: &str, message: &str) -> LogEntry {
        LogEntry {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            level,
            message: message.to_string(),
            service: service.to_string(),
            trace_id: None,
            span_id: None,
            context: None,
            error_info: None,
            duration_ms: None,
            metadata: None,
        }
    }

    #[test]
    fn test_ingest_and_query() {
        let agg = LogAggregator::new();
        agg.ingest(make_log(LogLevel::Info, "api", "request received"));
        agg.ingest(make_log(LogLevel::Error, "api", "db timeout"));
        agg.ingest(make_log(LogLevel::Warn, "worker", "slow job"));

        // No filters
        let all = agg.query(None, None, 100);
        assert_eq!(all.len(), 3);

        // Level filter:Error and above
        let errors = agg.query(Some(LogLevel::Error), None, 100);
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].message, "db timeout");

        // Service filter
        let worker_logs = agg.query(None, Some("worker"), 100);
        assert_eq!(worker_logs.len(), 1);
    }

    #[test]
    fn test_count_by_level() {
        let agg = LogAggregator::new();
        agg.ingest(make_log(LogLevel::Info, "api", "ok"));
        agg.ingest(make_log(LogLevel::Info, "api", "ok2"));
        agg.ingest(make_log(LogLevel::Error, "api", "fail"));

        let counts = agg.count_by_level();
        assert_eq!(counts.get(&LogLevel::Info), Some(&2));
        assert_eq!(counts.get(&LogLevel::Error), Some(&1));
        assert_eq!(counts.get(&LogLevel::Warn), None);
    }

    #[test]
    fn test_error_rate() {
        let agg = LogAggregator::new();
        // 2 info + 1 error = 1/3 ≈ 0.333
        agg.ingest(make_log(LogLevel::Info, "api", "ok"));
        agg.ingest(make_log(LogLevel::Info, "api", "ok2"));
        agg.ingest(make_log(LogLevel::Error, "api", "fail"));

        let rate = agg.get_error_rate(60);
        assert!((rate - 1.0 / 3.0).abs() < 0.01);

        // Empty window (impossibly old) → 0
        let empty = LogAggregator::new();
        assert!((empty.get_error_rate(60)).abs() < f64::EPSILON);
    }

    // ── SM10 F15: bounded per-entry payloads + ring eviction ───────────────

    fn oversized_map(keys: usize, value_bytes: usize) -> HashMap<String, serde_json::Value> {
        (0..keys)
            .map(|i| {
                (
                    format!("key-{i:04}"),
                    serde_json::Value::String("x".repeat(value_bytes)),
                )
            })
            .collect()
    }

    /// An oversized `metadata` map must be stored capped: the stored entry's
    /// map stays within the ingest budget instead of the full ~10 KB the
    /// producer sent (the old code stored the map verbatim).
    #[test]
    fn ingest_caps_oversized_metadata_maps() {
        let agg = LogAggregator::new();
        let mut entry = make_log(LogLevel::Info, "api", "big context");
        entry.metadata = Some(oversized_map(100, 100)); // ~10 KB serialized

        agg.ingest(entry);

        let stored = agg.query(None, Some("api"), 1);
        assert_eq!(stored.len(), 1);
        let metadata = stored[0].metadata.as_ref().expect("some keys must survive");
        assert!(
            map_bytes(metadata) <= MAX_INGEST_MAP_BYTES,
            "stored map must be capped to {MAX_INGEST_MAP_BYTES} bytes, got {}",
            map_bytes(metadata)
        );
        assert!(
            metadata.len() < 100,
            "shedding must have dropped keys, got {}",
            metadata.len()
        );
    }

    /// Maps within budget pass through byte-for-byte — the cap must not
    /// degrade healthy payloads.
    #[test]
    fn ingest_passes_reasonably_sized_maps_through_unchanged() {
        let agg = LogAggregator::new();
        let mut entry = make_log(LogLevel::Info, "api", "normal");
        let small = oversized_map(4, 16);
        entry.context = Some(small.clone());

        agg.ingest(entry);

        let stored = agg.query(None, Some("api"), 1);
        assert_eq!(stored[0].context.as_ref(), Some(&small));
    }

    /// A single value that alone exceeds the budget cannot fit even after
    /// shedding — the map is dropped (`None`), never stored oversized.
    #[test]
    fn ingest_drops_a_map_that_cannot_fit_at_all() {
        let oversized = oversized_map(1, MAX_INGEST_MAP_BYTES * 4);
        assert_eq!(cap_ingest_map(Some(oversized)), None);

        // And the same holds through the ingest path.
        let mut entry = make_log(LogLevel::Info, "api", "one giant value");
        entry.metadata = Some(oversized_map(1, MAX_INGEST_MAP_BYTES * 4));
        let agg = LogAggregator::new();
        agg.ingest(entry);
        let stored = agg.query(None, Some("api"), 1);
        assert_eq!(stored[0].metadata, None);
        assert_eq!(
            cap_ingest_map(Some(HashMap::new())),
            None,
            "an empty map must not be stored as a husk"
        );
    }

    /// Both map fields are capped independently on the same entry.
    #[test]
    fn ingest_caps_context_and_metadata_independently() {
        let mut entry = make_log(LogLevel::Info, "api", "both maps");
        entry.context = Some(oversized_map(50, 100));
        entry.metadata = Some(oversized_map(50, 100));
        let capped = LogAggregator::with_capacity(8);
        capped.ingest(entry);
        let stored = capped.query(None, Some("api"), 1);
        for field in [&stored[0].context, &stored[0].metadata] {
            let map = field.as_ref().expect("each field keeps some keys");
            assert!(map_bytes(map) <= MAX_INGEST_MAP_BYTES);
        }
    }

    /// The ring keeps the store at its cap and evicts the OLDEST entries;
    /// the allocation is shrunk when the slack passes half the cap.
    #[test]
    fn eviction_keeps_len_capped_and_drops_oldest() {
        let agg = LogAggregator::with_capacity(10);
        for i in 0..25 {
            let mut entry = make_log(LogLevel::Info, "svc", &format!("m{i}"));
            entry.timestamp = Utc::now() + Duration::milliseconds(i);
            agg.ingest(entry);
        }
        assert!(
            agg.len() <= 10,
            "the ring must stay at the cap, got {}",
            agg.len()
        );
        // The 15 oldest entries are gone; the newest survive.
        let newest = agg.query(None, Some("svc"), 100);
        assert_eq!(newest.len(), 10);
        assert_eq!(newest[0].message, "m24");
        assert_eq!(newest[9].message, "m15");
        let guard = agg.entries.read();
        // The shrink triggers when slack passes 1.5x the cap; the ring then
        // grows back by doubling (0.9x → 1.8x), so the observed steady-state
        // bound is 2x the cap — far below the old unbounded Vec slack.
        assert!(
            guard.capacity() <= 20,
            "ring slack must stay within ~2x the cap, got {}",
            guard.capacity()
        );
    }
}
