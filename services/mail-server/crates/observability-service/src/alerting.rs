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
// ComparisonOperator
// ---------------------------------------------------------------------------

/// Comparison operator used when evaluating an [`AlertRule`] expression.
///
/// This replaces the hardcoded "greater-than" logic so rules can specify
/// `gt`, `lt`, `gte`, `lte`, or `eq` comparisons against a threshold.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum ComparisonOperator {
    /// Greater than (`>`)
    Gt,
    /// Less than (`<`)
    Lt,
    /// Greater than or equal (`>=`)
    Gte,
    /// Less than or equal (`<=`)
    Lte,
    /// Equal (`==`)
    Eq,
}

impl ComparisonOperator {
    /// Evaluate `value` against `threshold` using this operator.
    pub fn evaluate(&self, value: f64, threshold: f64) -> bool {
        match self {
            Self::Gt => value > threshold,
            Self::Lt => value < threshold,
            Self::Gte => value >= threshold,
            Self::Lte => value <= threshold,
            Self::Eq => (value - threshold).abs() < f64::EPSILON,
        }
    }
}

impl std::fmt::Display for ComparisonOperator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Gt => write!(f, ">"),
            Self::Lt => write!(f, "<"),
            Self::Gte => write!(f, ">="),
            Self::Lte => write!(f, "<="),
            Self::Eq => write!(f, "=="),
        }
    }
}

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
    /// Comparison operator used against `threshold`.
    pub operator: ComparisonOperator,
    /// Threshold value compared against the metric using `operator`.
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
    /// Webhook endpoints (from `AlertConfig.webhook_urls`) that fired alerts
    /// are POSTed to. Empty means dispatch is disabled.
    webhook_urls: RwLock<Vec<String>>,
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
            webhook_urls: RwLock::new(Vec::new()),
        }
    }

    /// Configure webhook dispatch targets (see `AlertConfig::webhook_urls`).
    pub fn set_webhook_urls(&self, urls: Vec<String>) {
        *self.webhook_urls.write() = urls;
    }

    /// POST the given alerts as JSON to every configured webhook URL.
    ///
    /// Minimal, fail-safe dispatch: network and endpoint errors are logged
    /// and never propagated to the caller — alerting must not take down the
    /// evaluation loop.
    pub async fn dispatch_alerts(&self, alerts: &[Alert]) {
        let urls = self.webhook_urls.read().clone();
        if urls.is_empty() || alerts.is_empty() {
            return;
        }

        let client = match reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
        {
            Ok(client) => client,
            Err(err) => {
                tracing::warn!(error = %err, "alert dispatch: failed to build HTTP client");
                return;
            }
        };

        for alert in alerts {
            for url in &urls {
                match client.post(url).json(alert).send().await {
                    Ok(response) if response.status().is_success() => {}
                    Ok(response) => {
                        tracing::warn!(
                            rule = %alert.rule_name,
                            webhook_url = %url,
                            status = %response.status(),
                            "alert webhook dispatch returned an error status"
                        );
                    }
                    Err(err) => {
                        tracing::warn!(
                            rule = %alert.rule_name,
                            webhook_url = %url,
                            error = %err,
                            "alert webhook dispatch failed"
                        );
                    }
                }
            }
        }
    }

    /// Register a new alert rule.
    pub fn add_rule(&self, rule: AlertRule) {
        self.rules.write().push(rule);
    }

    /// Evaluate all rules against the provided metric summaries.
    ///
    /// When a rule's condition no longer holds, its Firing alerts are
    /// auto-resolved (status → `Resolved`, `resolved_at` set). Returns the
    /// list of newly-fired alerts.
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

            // Check condition using the rule's comparison operator
            if !rule.operator.evaluate(value, rule.threshold) {
                // Condition is false — auto-resolve any Firing alerts for
                // this rule so recovered rules do not stay firing forever.
                let mut resolved_count = 0_usize;
                for alert in alerts_guard.iter_mut() {
                    if alert.rule_name == rule.name && alert.status == AlertStatus::Firing {
                        alert.status = AlertStatus::Resolved;
                        alert.resolved_at = Some(now);
                        resolved_count += 1;
                    }
                }
                if resolved_count > 0 {
                    tracing::info!(
                        rule = %rule.name,
                        resolved_count,
                        value,
                        threshold = rule.threshold,
                        "alert condition cleared — auto-resolved firing alerts"
                    );
                }
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
                    "{}: current value {:.4} {} threshold {:.4}",
                    rule.name, value, rule.operator, rule.threshold
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
            operator: ComparisonOperator::Gt,
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
            operator: ComparisonOperator::Gt,
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
    fn test_condition_recovery_auto_resolves_firing_alerts() {
        let mgr = AlertManager::new();
        mgr.add_rule(error_rate_rule(0.05));

        // Fire on a high error rate.
        let fired = mgr.evaluate_all(&[summary("error_rate", 0.10)]);
        assert_eq!(fired.len(), 1);
        assert_eq!(mgr.list_active_alerts().len(), 1);

        // Error rate recovers below the threshold — the firing alert must be
        // auto-resolved even though no new alert fires.
        let fired = mgr.evaluate_all(&[summary("error_rate", 0.01)]);
        assert!(fired.is_empty());
        assert!(mgr.list_active_alerts().is_empty(), "recovered rule must auto-resolve");
        assert_eq!(mgr.list_all_alerts().len(), 1);
        assert_eq!(mgr.list_all_alerts()[0].status, AlertStatus::Resolved);
        assert!(mgr.list_all_alerts()[0].resolved_at.is_some());
    }

    #[test]
    fn test_missing_metric_leaves_alerts_untouched() {
        let mgr = AlertManager::new();
        mgr.add_rule(error_rate_rule(0.05));

        let fired = mgr.evaluate_all(&[summary("error_rate", 0.10)]);
        assert_eq!(fired.len(), 1);

        // Metric absent (no data) must NOT resolve the alert — no data is
        // not the same as a healthy value.
        let fired = mgr.evaluate_all(&[]);
        assert!(fired.is_empty());
        assert_eq!(mgr.list_active_alerts().len(), 1, "no data must not auto-resolve");
    }

    #[tokio::test]
    async fn test_dispatch_alerts_no_webhooks_is_noop() {
        let mgr = AlertManager::new();
        mgr.add_rule(error_rate_rule(0.05));
        let fired = mgr.evaluate_all(&[summary("error_rate", 0.10)]);

        // No webhook URLs configured — dispatch must return without error.
        mgr.dispatch_alerts(&fired).await;
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
