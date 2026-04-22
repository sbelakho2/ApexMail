//! Distributed tracing span collector.
//!
//! In-memory store of [`TraceSpan`]s with search, filtering, and
//! average-duration computation. Thread-safe via `parking_lot::RwLock`.

use parking_lot::RwLock;

use crate::types::TraceSpan;

// ---------------------------------------------------------------------------
// TraceCollector
// ---------------------------------------------------------------------------

/// Thread-safe in-memory trace span store.
/// Caps total stored spans at `max_spans`; when full, the oldest spans are
/// evicted on each insert to prevent unbounded memory growth.
#[derive(Debug)]
pub struct TraceCollector {
    spans: RwLock<Vec<TraceSpan>>,
    max_spans: usize,
}

impl TraceCollector {
/// Create a new, empty collector with the given capacity limit.
    pub fn new() -> Self {
        Self::with_capacity(500_000)
    }

/// Create a collector that retains at most `max_spans` spans.
    pub fn with_capacity(max_spans: usize) -> Self {
        Self {
            spans: RwLock::new(Vec::new()),
            max_spans,
        }
    }

/// Record a span into the store.
/// If the store is at capacity, the oldest span is dropped first.
    pub fn record_span(&self, span: TraceSpan) {
        let mut guard = self.spans.write();
        if guard.len() >= self.max_spans {
            let prune_count = guard.len() / 10;
            guard.drain(..prune_count); // evict oldest 10%
        }
        guard.push(span);
    }

/// Return all spans belonging to the given `trace_id`.
    pub fn get_trace(&self, trace_id: &str) -> Vec<TraceSpan> {
        self.spans
            .read()
            .iter()
            .filter(|s| s.trace_id == trace_id)
            .cloned()
            .collect()
    }

/// Return the most recent `limit` spans ordered by `start_time` descending.
    pub fn list_recent(&self, limit: usize) -> Vec<TraceSpan> {
        let guard = self.spans.read();
        let mut sorted: Vec<&TraceSpan> = guard.iter().collect();
        sorted.sort_by(|a, b| b.start_time.cmp(&a.start_time));
        sorted.into_iter().take(limit).cloned().collect()
    }

/// Search spans matching an optional operation name filter and/or
/// minimum duration in milliseconds.
    pub fn search(
        &self,
        operation_filter: Option<&str>,
        min_duration_ms: Option<i64>,
    ) -> Vec<TraceSpan> {
        self.spans
            .read()
            .iter()
            .filter(|s| {
                let op_ok = operation_filter
                    .map(|f| s.operation_name.contains(f))
                    .unwrap_or(true);
                let dur_ok = min_duration_ms
                    .map(|min| s.duration_ms.unwrap_or(0) >= min)
                    .unwrap_or(true);
                op_ok && dur_ok
            })
            .cloned()
            .collect()
    }

/// Compute the average duration (in ms) for all spans matching `operation`.
/// Returns `None` if there are no matching spans with a recorded duration.
    pub fn avg_duration(&self, operation: &str) -> Option<f64> {
        let guard = self.spans.read();
        let durations: Vec<f64> = guard
            .iter()
            .filter(|s| s.operation_name == operation)
            .filter_map(|s| s.duration_ms.map(|d| d as f64))
            .collect();

        if durations.is_empty() {
            None
        } else {
            let sum: f64 = durations.iter().sum();
            Some(sum / durations.len() as f64)
        }
    }

/// Total number of stored spans.
    pub fn len(&self) -> usize {
        self.spans.read().len()
    }

/// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.spans.read().is_empty()
    }
}

impl Default for TraceCollector {
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
    use crate::types::{SpanKind, SpanStatus};
    use chrono::Utc;
    use std::collections::HashMap;

    fn make_span(trace_id: &str, operation: &str, duration_ms: i64) -> TraceSpan {
        let now = Utc::now();
        TraceSpan {
            span_id: uuid::Uuid::new_v4().to_string(),
            trace_id: trace_id.to_string(),
            parent_span_id: None,
            operation_name: operation.to_string(),
            service_name: "test-svc".to_string(),
            kind: SpanKind::Server,
            status: SpanStatus::Ok,
            status_message: None,
            start_time: now,
            end_time: Some(now + chrono::Duration::milliseconds(duration_ms)),
            duration_ms: Some(duration_ms),
            attributes: HashMap::new(),
            events: Vec::new(),
        }
    }

    #[test]
    fn test_record_and_get_trace() {
        let tc = TraceCollector::new();
        tc.record_span(make_span("trace-1", "GET /api", 100));
        tc.record_span(make_span("trace-1", "db.query", 30));
        tc.record_span(make_span("trace-2", "GET /health", 5));

        let trace1 = tc.get_trace("trace-1");
        assert_eq!(trace1.len(), 2);
        assert!(trace1.iter().all(|s| s.trace_id == "trace-1"));

        let trace2 = tc.get_trace("trace-2");
        assert_eq!(trace2.len(), 1);
    }

    #[test]
    fn test_search_by_operation_and_duration() {
        let tc = TraceCollector::new();
        tc.record_span(make_span("t1", "GET /api", 10));
        tc.record_span(make_span("t2", "GET /api", 500));
        tc.record_span(make_span("t3", "POST /api", 200));

// Operation filter only
        let results = tc.search(Some("GET"), None);
        assert_eq!(results.len(), 2);

// Duration filter only
        let results = tc.search(None, Some(100));
        assert_eq!(results.len(), 2); // 500 and 200

// Both filters
        let results = tc.search(Some("GET"), Some(100));
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].duration_ms, Some(500));
    }

    #[test]
    fn test_avg_duration() {
        let tc = TraceCollector::new();
        tc.record_span(make_span("t1", "GET /api", 100));
        tc.record_span(make_span("t2", "GET /api", 200));
        tc.record_span(make_span("t3", "GET /api", 300));

        let avg = tc.avg_duration("GET /api").unwrap();
        assert!((avg - 200.0).abs() < f64::EPSILON);

// Non-existent operation
        assert!(tc.avg_duration("PUT /nope").is_none());
    }
}
