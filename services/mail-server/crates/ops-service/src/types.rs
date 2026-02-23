//! Core domain types for the operations service.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

/// Incident severity levels (P1 = most critical).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IncidentSeverity {
    P1,
    P2,
    P3,
    P4,
}

impl std::fmt::Display for IncidentSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::P1 => write!(f, "P1"),
            Self::P2 => write!(f, "P2"),
            Self::P3 => write!(f, "P3"),
            Self::P4 => write!(f, "P4"),
        }
    }
}

/// Lifecycle status of an incident.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IncidentStatus {
    Open,
    Investigating,
    Identified,
    Monitoring,
    Resolved,
}

impl std::fmt::Display for IncidentStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Open => "Open",
            Self::Investigating => "Investigating",
            Self::Identified => "Identified",
            Self::Monitoring => "Monitoring",
            Self::Resolved => "Resolved",
        };
        write!(f, "{s}")
    }
}

/// Operational status of an individual service shown on the status page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ServiceStatus {
    Operational,
    Degraded,
    PartialOutage,
    MajorOutage,
}

impl std::fmt::Display for ServiceStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Operational => "Operational",
            Self::Degraded => "Degraded",
            Self::PartialOutage => "Partial Outage",
            Self::MajorOutage => "Major Outage",
        };
        write!(f, "{s}")
    }
}

// ---------------------------------------------------------------------------
// Structs
// ---------------------------------------------------------------------------

/// Result of a single health check against a service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheck {
    pub service: String,
    pub status: ServiceStatus,
    pub latency_ms: u64,
    pub timestamp: DateTime<Utc>,
}

/// An operational incident.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Incident {
    pub id: Uuid,
    pub title: String,
    pub severity: IncidentSeverity,
    pub status: IncidentStatus,
    pub started_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub affected_services: Vec<String>,
}

/// A Service Level Objective definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SloDefinition {
    pub name: String,
    /// Target expressed as a percentage (e.g. 99.9).
    pub target: f64,
    /// Rolling window in days.
    pub window_days: u32,
}

/// Aggregated status page view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusPage {
    pub overall_status: ServiceStatus,
    pub services: Vec<HealthCheck>,
    pub updated_at: DateTime<Utc>,
}

/// An IP warmup schedule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WarmupSchedule {
    pub ip: String,
    pub current_volume: u64,
    pub target_volume: u64,
    pub day: u32,
    pub total_days: u32,
}

/// Trust score computed for a tenant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustScore {
    pub tenant_id: Uuid,
    pub score: f64,
    pub factors: TrustFactors,
    pub computed_at: DateTime<Utc>,
}

/// Individual factors that feed into a trust score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustFactors {
    pub bounce_rate: f64,
    pub complaint_rate: f64,
    pub engagement_rate: f64,
    pub age_days: u64,
    pub volume: u64,
}

// ---------------------------------------------------------------------------
// Timeline event type used by incident management
// ---------------------------------------------------------------------------

/// A single entry on an incident timeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEntry {
    pub timestamp: DateTime<Utc>,
    pub status: IncidentStatus,
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_incident_severity_display() {
        assert_eq!(IncidentSeverity::P1.to_string(), "P1");
        assert_eq!(IncidentSeverity::P4.to_string(), "P4");
    }

    #[test]
    fn test_service_status_ordering() {
        // Operational < MajorOutage so we can pick the worst via max.
        assert!(ServiceStatus::Operational < ServiceStatus::MajorOutage);
        assert!(ServiceStatus::Degraded < ServiceStatus::PartialOutage);
    }

    #[test]
    fn test_health_check_serialization() {
        let hc = HealthCheck {
            service: "api".into(),
            status: ServiceStatus::Operational,
            latency_ms: 12,
            timestamp: Utc::now(),
        };
        let json = serde_json::to_string(&hc).unwrap();
        assert!(json.contains("\"service\":\"api\""));
    }

    #[test]
    fn test_incident_roundtrip() {
        let inc = Incident {
            id: Uuid::new_v4(),
            title: "DB down".into(),
            severity: IncidentSeverity::P1,
            status: IncidentStatus::Open,
            started_at: Utc::now(),
            resolved_at: None,
            affected_services: vec!["database".into()],
        };
        let json = serde_json::to_string(&inc).unwrap();
        let decoded: Incident = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.id, inc.id);
        assert_eq!(decoded.severity, IncidentSeverity::P1);
    }
}
