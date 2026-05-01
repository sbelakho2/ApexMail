//! Alert rule evaluation and management.
//!
//! Provides [`AlertManager`] for defining rules, evaluating them against
//! metric summaries, listing active alerts, and acknowledging firings.

use chrono::Utc;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::metrics_collector::MetricSummary;
use crate::types::{Alert, AlertSeverity, AlertStatus};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// AlertRule (lightweight, evaluable)
// ---------------------------------------------------------------------------

/// A rule that produces an [`Alert`] when its condition is met.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRule {
    pub name: String,
    /// Human-readable description of the condition (e.g. "error_rate > 0.05").
    pub condition_description: String,
    /// The metric name this rule monitors.
    pub metric_name: String,
    /// Threshold above which the rule fires.
    pub threshold: f64,
    pub severity: AlertSeverity,
    /// Minimum seconds between consecutive firings for the same rule.
    pub cooldown_secs: u64,
}

// ---------------------------------------------------------------------------
// AlertManager
// ---------------------------------------------------------------------------

/// Manages alert rules, evaluates them against metric summaries, and stores
/// fired alerts.
/// Caps stored alerts at `max_alerts`; when full, resolved/acknowledged alerts
/// are evicted first, then the oldest firing alerts.
#[derive(Debug)]
pub struct AlertManager {
    rules: RwLock<Vec<AlertRule>>,
    alerts: RwLock<Vec<Alert>>,
    max_alerts: usize,
}

impl AlertManager {
    /// Create a new, empty manager with a default 10 000 alert cap.
    pub fn new() -> Self {
        Self::with_capacity(10_000)
    }

    /// Create a manager that retains at most `max_alerts` alerts.
    pub fn with_capacity(max_alerts: usize) -> Self {
        Self {
            rules: RwLock::new(Vec::new()),
            alerts: RwLock::new(Vec::new()),
            max_alerts,
        }
    }

    /// Register a new alert rule.
    pub fn add_rule(&self, rule: AlertRule) {
        self.rules.write().push(rule);
    }

    /// Evaluate all rules against the provided metric summaries.
    /// Returns the list of newly-fired alerts.
    pub fn evaluate_all(&self, summaries: &[MetricSummary]) -> Vec<Alert> {
        let rules = self.rules.read();
        let mut alerts_guard = self.alerts.write();
        let now = Utc::now();
        let mut new_alerts = Vec::new();

        for rule in rules.iter() {
            // Find matching metric
            let metric_value = summaries
                .iter()
                .find(|m| m.name == rule.metric_name)
                .map(|m| m.value);

            let value = match metric_value {
                Some(v) => v,
                None => continue,
            };

            // Check threshold
            if value <= rule.threshold {
                continue;
            }

            // Cooldown:skip if there's a recent firing for this rule name
            let recently_fired = alerts_guard.iter().any(|a| {
                a.rule_name == rule.name
                    && (now - a.fired_at).num_seconds() < rule.cooldown_secs as i64
            });
            if recently_fired {
                continue;
            }

            let alert = Alert {
                id: Uuid::new_v4().to_string(),
                rule_id: Uuid::new_v4().to_string(),
                rule_name: rule.name.clone(),
                status: AlertStatus::Firing,
                severity: rule.severity,
                summary: rule.condition_description.clone(),
                description: format!(
                    "{}: current value {:.4} exceeds threshold {:.4}",
                    rule.name, value, rule.threshold
                ),
                labels: HashMap::new(),
                annotations: HashMap::new(),
                value,
                threshold: rule.threshold,
                fired_at: now,
                resolved_at: None,
                acknowledged_at: None,
                acknowledged_by: None,
                silenced_until: None,
                notifications_sent: 0,
                last_notification_at: None,
            };

            new_alerts.push(alert.clone());
            alerts_guard.push(alert);
        }

        self.trim_alerts(&mut alerts_guard);

        new_alerts
    }

    /// Upsert alerts received from an external alert source such as Alertmanager.
    pub fn ingest_external_alerts(&self, alerts: Vec<Alert>) {
        let mut alerts_guard = self.alerts.write();

        for alert in alerts {
            if let Some(existing) = alerts_guard
                .iter_mut()
                .find(|existing| existing.id == alert.id)
            {
                *existing = alert;
            } else {
                alerts_guard.push(alert);
            }
        }

        self.trim_alerts(&mut alerts_guard);
    }

    /// List all alerts that are currently firing (not acknowledged / resolved).
    pub fn list_active_alerts(&self) -> Vec<Alert> {
        self.alerts
            .read()
            .iter()
            .filter(|a| a.status == AlertStatus::Firing)
            .cloned()
            .collect()
    }

    /// Acknowledge an alert by ID. Returns `true` if the alert was found.
    pub fn acknowledge(&self, alert_id: &str) -> bool {
        let mut guard = self.alerts.write();
        if let Some(alert) = guard.iter_mut().find(|a| a.id == alert_id) {
            alert.status = AlertStatus::Acknowledged;
            alert.acknowledged_at = Some(Utc::now());
            true
        } else {
            false
        }
    }

    /// Return a snapshot of all registered rules.
    pub fn list_rules(&self) -> Vec<AlertRule> {
        self.rules.read().clone()
    }

    /// Return all alerts (any status).
    pub fn list_all_alerts(&self) -> Vec<Alert> {
        self.alerts.read().clone()
    }

    fn trim_alerts(&self, alerts: &mut Vec<Alert>) {
        // Evict if over capacity:remove resolved/acknowledged first, then oldest
        if alerts.len() > self.max_alerts {
            // Partition:keep firing alerts, evict resolved/acknowledged
            alerts.retain(|a| a.status == AlertStatus::Firing);
        }
        if alerts.len() > self.max_alerts {
            let excess = alerts.len() - self.max_alerts;
            alerts.drain(..excess);
        }
    }
}

impl Default for AlertManager {
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
    use crate::types::MetricType;

    fn summary(name: &str, value: f64) -> MetricSummary {
        MetricSummary {
            name: name.to_string(),
            metric_type: MetricType::Gauge,
            help: String::new(),
            value,
        }
    }

    fn error_rate_rule(threshold: f64) -> AlertRule {
        AlertRule {
            name: "high_error_rate".to_string(),
            condition_description: "error_rate > threshold".to_string(),
            metric_name: "error_rate".to_string(),
            threshold,
            severity: AlertSeverity::Critical,
            cooldown_secs: 0,
        }
    }

    #[test]
    fn test_add_and_list_rules() {
        let mgr = AlertManager::new();
        mgr.add_rule(error_rate_rule(0.05));
        mgr.add_rule(AlertRule {
            name: "high_latency".to_string(),
            condition_description: "p99_latency > 2000".to_string(),
            metric_name: "p99_latency".to_string(),
            threshold: 2000.0,
            severity: AlertSeverity::Warning,
            cooldown_secs: 60,
        });
        assert_eq!(mgr.list_rules().len(), 2);
    }

    #[test]
    fn test_evaluate_fires_alert() {
        let mgr = AlertManager::new();
        mgr.add_rule(error_rate_rule(0.05));

        let summaries = vec![summary("error_rate", 0.10)];
        let fired = mgr.evaluate_all(&summaries);

        assert_eq!(fired.len(), 1);
        assert_eq!(fired[0].rule_name, "high_error_rate");
        assert_eq!(fired[0].status, AlertStatus::Firing);
        assert!((fired[0].value - 0.10).abs() < f64::EPSILON);
    }

    #[test]
    fn test_evaluate_no_fire_below_threshold() {
        let mgr = AlertManager::new();
        mgr.add_rule(error_rate_rule(0.05));

        let summaries = vec![summary("error_rate", 0.01)];
        let fired = mgr.evaluate_all(&summaries);

        assert!(fired.is_empty());
        assert!(mgr.list_active_alerts().is_empty());
    }

    #[test]
    fn test_acknowledge_alert() {
        let mgr = AlertManager::new();
        mgr.add_rule(error_rate_rule(0.05));

        let summaries = vec![summary("error_rate", 0.10)];
        let fired = mgr.evaluate_all(&summaries);
        assert_eq!(fired.len(), 1);

        let alert_id = fired[0].id.clone();
        assert!(mgr.acknowledge(&alert_id));
        assert!(mgr.list_active_alerts().is_empty()); // acknowledged → no longer active

        // Acknowledging again is fine (already found)
        assert!(mgr.acknowledge(&alert_id));

        // Non-existent ID
        assert!(!mgr.acknowledge("nonexistent"));
    }

    #[test]
    fn test_ingest_external_alert_updates_existing_alert() {
        let mgr = AlertManager::new();
        let alert = Alert {
            id: "fingerprint-1".to_string(),
            rule_id: "fingerprint-1".to_string(),
            rule_name: "TrackingServiceDown".to_string(),
            status: AlertStatus::Firing,
            severity: AlertSeverity::Critical,
            summary: "Tracking down".to_string(),
            description: "Tracking is unavailable".to_string(),
            labels: HashMap::new(),
            annotations: HashMap::new(),
            value: 0.0,
            threshold: 0.0,
            fired_at: Utc::now(),
            resolved_at: None,
            acknowledged_at: None,
            acknowledged_by: None,
            silenced_until: None,
            notifications_sent: 1,
            last_notification_at: Some(Utc::now()),
        };

        mgr.ingest_external_alerts(vec![alert.clone()]);
        assert_eq!(mgr.list_active_alerts().len(), 1);

        let mut resolved = alert;
        resolved.status = AlertStatus::Resolved;
        resolved.resolved_at = Some(Utc::now());

        mgr.ingest_external_alerts(vec![resolved]);
        assert!(mgr.list_active_alerts().is_empty());
        assert_eq!(mgr.list_all_alerts().len(), 1);
        assert_eq!(mgr.list_all_alerts()[0].status, AlertStatus::Resolved);
    }
}
