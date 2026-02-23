//! Structured log aggregation.
//!
//! In-memory log store with level/service filtering, per-level counts, and
//! error-rate calculation over a sliding window.

use std::collections::HashMap;

use chrono::{Duration, Utc};
use parking_lot::RwLock;

use crate::types::{LogEntry, LogLevel};

// ---------------------------------------------------------------------------
// LogAggregator
// ---------------------------------------------------------------------------

/// Thread-safe in-memory structured log store.
#[derive(Debug)]
pub struct LogAggregator {
    entries: RwLock<Vec<LogEntry>>,
}

impl LogAggregator {
    /// Create a new, empty aggregator.
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(Vec::new()),
        }
    }

    /// Ingest a single log entry.
    pub fn ingest(&self, entry: LogEntry) {
        self.entries.write().push(entry);
    }

    /// Query logs with optional level and service filters, returning at most
    /// `limit` entries ordered newest-first.
    pub fn query(
        &self,
        level_filter: Option<LogLevel>,
        service_filter: Option<&str>,
        limit: usize,
    ) -> Vec<LogEntry> {
        let guard = self.entries.read();
        let mut filtered: Vec<&LogEntry> = guard
            .iter()
            .filter(|e| {
                let level_ok = level_filter.map(|l| e.level >= l).unwrap_or(true);
                let svc_ok = service_filter
                    .map(|s| e.service == s)
                    .unwrap_or(true);
                level_ok && svc_ok
            })
            .collect();
        filtered.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        filtered.into_iter().take(limit).cloned().collect()
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

        // Level filter: Error and above
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
}
