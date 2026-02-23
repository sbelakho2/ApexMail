//! Service Level Objective (SLO) monitoring.
//!
//! Define objectives, check compliance against request counts, and track
//! remaining error budget.

use chrono::Utc;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::types::SloTarget;

// ---------------------------------------------------------------------------
// SloComplianceResult
// ---------------------------------------------------------------------------

/// Result of evaluating an SLO against actual request data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SloComplianceResult {
    pub name: String,
    pub compliant: bool,
    /// Current success percentage (0.0–100.0).
    pub current_pct: f64,
    /// Target percentage (0.0–100.0).
    pub target_pct: f64,
    /// Fraction of the error budget still remaining (0.0–1.0).
    /// Negative values indicate the budget has been exceeded.
    pub error_budget_remaining: f64,
}

// ---------------------------------------------------------------------------
// SloMonitor
// ---------------------------------------------------------------------------

/// In-memory SLO definition store with compliance checking.
#[derive(Debug)]
pub struct SloMonitor {
    targets: RwLock<Vec<SloTarget>>,
}

impl SloMonitor {
    /// Create a new, empty monitor.
    pub fn new() -> Self {
        Self {
            targets: RwLock::new(Vec::new()),
        }
    }

    /// Define (or overwrite) an SLO by name.
    ///
    /// * `target_pct` – target success percentage, e.g. `99.9` for 99.9 %.
    /// * `window_days` – rolling window expressed in days.
    pub fn define_slo(&self, name: &str, target_pct: f64, window_days: u32) {
        let mut guard = self.targets.write();
        // Overwrite if same name already exists
        guard.retain(|t| t.name != name);

        let now = Utc::now();
        guard.push(SloTarget {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.to_string(),
            description: format!("{:.2}% over {} days", target_pct, window_days),
            service: String::new(),
            target: target_pct / 100.0, // store as ratio
            window_secs: window_days as u64 * 86_400,
            good_event_expr: String::new(),
            total_event_expr: String::new(),
            created_at: now,
            updated_at: now,
        });
    }

    /// Check compliance for the named SLO given observed request counts.
    ///
    /// Returns `None` if no SLO with that name has been defined.
    pub fn check_compliance(
        &self,
        name: &str,
        total_requests: u64,
        error_requests: u64,
    ) -> Option<SloComplianceResult> {
        let guard = self.targets.read();
        let target = guard.iter().find(|t| t.name == name)?;

        let current_ratio = if total_requests == 0 {
            1.0
        } else {
            1.0 - (error_requests as f64 / total_requests as f64)
        };
        let current_pct = current_ratio * 100.0;
        let target_pct = target.target * 100.0;

        let allowed_errors = (1.0 - target.target) * total_requests as f64;
        let error_budget_remaining = if allowed_errors == 0.0 {
            if error_requests == 0 {
                1.0
            } else {
                -1.0
            }
        } else {
            1.0 - (error_requests as f64 / allowed_errors)
        };

        Some(SloComplianceResult {
            name: name.to_string(),
            compliant: current_ratio >= target.target,
            current_pct,
            target_pct,
            error_budget_remaining,
        })
    }

    /// Snapshot of all defined SLOs.
    pub fn list_slos(&self) -> Vec<SloTarget> {
        self.targets.read().clone()
    }
}

impl Default for SloMonitor {
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

    #[test]
    fn test_define_and_list() {
        let mon = SloMonitor::new();
        mon.define_slo("availability", 99.9, 30);
        mon.define_slo("latency_p99", 99.0, 7);

        let slos = mon.list_slos();
        assert_eq!(slos.len(), 2);
        assert!(slos.iter().any(|s| s.name == "availability"));
        assert!(slos.iter().any(|s| s.name == "latency_p99"));
    }

    #[test]
    fn test_compliance_within_budget() {
        let mon = SloMonitor::new();
        mon.define_slo("availability", 99.9, 30);

        // 10 000 requests, 5 errors → 99.95% (above 99.9% target)
        let result = mon.check_compliance("availability", 10_000, 5).unwrap();
        assert!(result.compliant);
        assert!(result.current_pct > 99.9);
        assert!(result.error_budget_remaining > 0.0);
    }

    #[test]
    fn test_compliance_budget_exhausted() {
        let mon = SloMonitor::new();
        mon.define_slo("availability", 99.9, 30);

        // 10 000 requests, 20 errors → 99.8% (below 99.9% target)
        // Allowed errors = 10, actual = 20 → budget = 1 - 20/10 = -1.0
        let result = mon.check_compliance("availability", 10_000, 20).unwrap();
        assert!(!result.compliant);
        assert!(result.current_pct < 99.9);
        assert!(result.error_budget_remaining < 0.0);

        // Non-existent SLO
        assert!(mon.check_compliance("nonexistent", 100, 1).is_none());
    }
}
