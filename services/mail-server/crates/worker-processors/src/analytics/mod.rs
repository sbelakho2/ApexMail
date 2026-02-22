//! Analytics processor — event aggregation and real-time stats.
//!
//! Consumes events from `analytics_queue`, aggregates them into hourly buckets,
//! and writes to `analytics_hourly` while maintaining real-time Redis counters.

mod processor;
mod types;

pub use processor::AnalyticsProcessor;
pub use types::{AggregatedStats, AnalyticsEvent};
