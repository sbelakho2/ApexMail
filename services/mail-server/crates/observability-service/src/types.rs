//! Core domain types for the observability service.
//!
//! Maps 1-to-1 with the TypeScript interfaces in the original codebase://! `MetricPoint`, `TraceSpan`, `LogEntry`, `Alert`, `SloTarget`,
//! `HealthStatus`, and `AlertSeverity`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// MetricPoint
// ---------------------------------------------------------------------------

/// The kind of metric being recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetricType {
    Counter,
    Gauge,
    Histogram,
    Summary,
}

/// A single recorded metric data-point.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricPoint {
    pub name: String,
    pub metric_type: MetricType,
    pub value: f64,
    pub labels: HashMap<String, String>,
    pub timestamp: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// TraceSpan
// ---------------------------------------------------------------------------

/// Status of a trace span.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpanStatus {
    Ok,
    Error,
    Unset,
}

/// The role of a span inside the trace graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpanKind {
    Internal,
    Server,
    Client,
    Producer,
    Consumer,
}

/// A single span within a distributed trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceSpan {
    pub span_id: String,
    pub trace_id: String,
    pub parent_span_id: Option<String>,
    pub operation_name: String,
    pub service_name: String,
    pub kind: SpanKind,
    pub status: SpanStatus,
    pub status_message: Option<String>,
    pub start_time: DateTime<Utc>,
    pub end_time: Option<DateTime<Utc>>,
    pub duration_ms: Option<i64>,
    pub attributes: HashMap<String, serde_json::Value>,
    pub events: Vec<SpanEvent>,
}

/// An event attached to a span.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpanEvent {
    pub name: String,
    pub timestamp: DateTime<Utc>,
    pub attributes: HashMap<String, serde_json::Value>,
}

// ---------------------------------------------------------------------------
// LogEntry
// ---------------------------------------------------------------------------

/// Severity level for a log entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogLevel {
    Trace = 0,
    Debug = 1,
    Info = 2,
    Warn = 3,
    Error = 4,
    Fatal = 5,
}

impl LogLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Trace => "trace",
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
            Self::Fatal => "fatal",
        }
    }
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A structured log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub level: LogLevel,
    pub message: String,
    pub service: String,
    pub trace_id: Option<String>,
    pub span_id: Option<String>,
    pub context: Option<HashMap<String, serde_json::Value>>,
    pub error_info: Option<ErrorInfo>,
    pub duration_ms: Option<i64>,
    pub metadata: Option<HashMap<String, serde_json::Value>>,
}

/// Structured error details within a log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorInfo {
    pub name: String,
    pub message: String,
    pub stack: Option<String>,
}

// ---------------------------------------------------------------------------
// Alert & AlertSeverity
// ---------------------------------------------------------------------------

/// Severity of an alert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertSeverity {
    Info,
    Warning,
    Critical,
    Emergency,
}

impl AlertSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Critical => "critical",
            Self::Emergency => "emergency",
        }
    }
}

impl std::fmt::Display for AlertSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Current state of an alert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertStatus {
    Pending,
    Firing,
    Resolved,
    Acknowledged,
    Silenced,
}

/// A concrete alert instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: String,
    pub rule_id: String,
    pub rule_name: String,
    pub status: AlertStatus,
    pub severity: AlertSeverity,
    pub summary: String,
    pub description: String,
    pub labels: HashMap<String, String>,
    pub annotations: HashMap<String, String>,
    pub value: f64,
    pub threshold: f64,
    pub fired_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub acknowledged_at: Option<DateTime<Utc>>,
    pub acknowledged_by: Option<String>,
    pub silenced_until: Option<DateTime<Utc>>,
    pub notifications_sent: u32,
    pub last_notification_at: Option<DateTime<Utc>>,
}

/// An alert rule definition (template that produces `Alert`s when triggered).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub enabled: bool,
    pub expression: String,
/// Duration in seconds that condition must hold before firing.
    pub duration_secs: u64,
    pub severity: AlertSeverity,
    pub labels: HashMap<String, String>,
    pub annotations: HashMap<String, String>,
    pub notification_channels: Vec<String>,
    pub runbook: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// SloTarget
// ---------------------------------------------------------------------------

/// A Service Level Objective definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SloTarget {
    pub id: String,
    pub name: String,
    pub description: String,
    pub service: String,
/// Target ratio (0.0 – 1.0), e.g. 0.999 = 99.9 %.
    pub target: f64,
/// Rolling window in seconds.
    pub window_secs: u64,
/// Metric expression used for numerator (good events).
    pub good_event_expr: String,
/// Metric expression used for denominator (total events).
    pub total_event_expr: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Result of checking an SLO's current compliance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SloCompliance {
    pub slo_id: String,
    pub name: String,
    pub target: f64,
    pub current: f64,
    pub compliant: bool,
    pub error_budget_remaining: f64,
    pub window_secs: u64,
    pub evaluated_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// HealthStatus
// ---------------------------------------------------------------------------

/// Status of a single health-check component.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComponentHealth {
    Healthy,
    Degraded,
    Unhealthy,
}

/// Overall service health report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    pub status: ComponentHealth,
    pub version: String,
    pub uptime_secs: u64,
    pub checks: HashMap<String, ComponentCheck>,
}

/// Individual component health probe result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentCheck {
    pub status: ComponentHealth,
    pub message: Option<String>,
    pub latency_ms: Option<u64>,
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metric_point_serialization() {
        let mp = MetricPoint {
            name: "http_requests_total".into(),
            metric_type: MetricType::Counter,
            value: 42.0,
            labels: HashMap::from([("method".into(), "GET".into())]),
            timestamp: Utc::now(),
        };
        let json = serde_json::to_string(&mp).unwrap();
        let deser: MetricPoint = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.name, "http_requests_total");
        assert_eq!(deser.metric_type, MetricType::Counter);
        assert!((deser.value - 42.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_alert_severity_display() {
        assert_eq!(AlertSeverity::Info.as_str(), "info");
        assert_eq!(AlertSeverity::Warning.as_str(), "warning");
        assert_eq!(AlertSeverity::Critical.as_str(), "critical");
        assert_eq!(AlertSeverity::Emergency.as_str(), "emergency");
        assert_eq!(format!("{}", AlertSeverity::Critical), "critical");
    }

    #[test]
    fn test_log_level_ordering() {
        assert!(LogLevel::Trace < LogLevel::Debug);
        assert!(LogLevel::Debug < LogLevel::Info);
        assert!(LogLevel::Info < LogLevel::Warn);
        assert!(LogLevel::Warn < LogLevel::Error);
        assert!(LogLevel::Error < LogLevel::Fatal);
    }

    #[test]
    fn test_health_status_roundtrip() {
        let hs = HealthStatus {
            status: ComponentHealth::Healthy,
            version: "1.0.0".into(),
            uptime_secs: 3600,
            checks: HashMap::from([(
                "database".into(),
                ComponentCheck {
                    status: ComponentHealth::Healthy,
                    message: Some("connected".into()),
                    latency_ms: Some(2),
                },
            )]),
        };
        let json = serde_json::to_string(&hs).unwrap();
        let deser: HealthStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.status, ComponentHealth::Healthy);
        assert_eq!(deser.uptime_secs, 3600);
        assert!(deser.checks.contains_key("database"));
    }
}
