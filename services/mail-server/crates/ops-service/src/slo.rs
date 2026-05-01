//! Service Level Objective (SLO) tracking & error-budget evaluation.

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::types::SloDefinition;

/// Result of evaluating an SLO over observed data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SloEvaluation {
    pub name: String,
    pub target: f64,
    pub actual: f64,
    pub within_budget: bool,
}

/// Tracks SLO definitions and evaluates them against observed metrics.
#[derive(Debug, Clone)]
pub struct SloTracker {
    definitions: Arc<DashMap<String, SloDefinition>>,
}

impl SloTracker {
    pub fn new() -> Self {
        Self {
            definitions: Arc::new(DashMap::new()),
        }
    }

    /// Register (or overwrite) an SLO definition.
    pub fn define(&self, slo: SloDefinition) {
        self.definitions.insert(slo.name.clone(), slo);
    }

    /// Evaluate an SLO given total requests and error count.
    /// Returns `None` if the SLO name is not registered.
    pub fn evaluate(&self, name: &str, total: u64, errors: u64) -> Option<SloEvaluation> {
        self.definitions.get(name).map(|slo| {
            let actual = if total == 0 {
                0.0
            } else {
                (1.0 - errors as f64 / total as f64) * 100.0
            };
            SloEvaluation {
                name: slo.name.clone(),
                target: slo.target,
                actual,
                within_budget: actual >= slo.target,
            }
        })
    }

    /// Compute the remaining error budget as a percentage of total budget.
    /// Error budget = 100 - target. Remaining = budget - consumed.
    /// Returns `None` if the SLO is not registered.
    pub fn get_error_budget(&self, name: &str, total: u64, errors: u64) -> Option<f64> {
        self.definitions.get(name).map(|slo| {
            let budget = 100.0 - slo.target; // e.g. 0.1 for 99.9 SLO
            let consumed = if total == 0 {
                0.0
            } else {
                (errors as f64 / total as f64) * 100.0
            };
            (budget - consumed).max(0.0)
        })
    }

    /// List all registered SLO definitions.
    pub fn list_all(&self) -> Vec<SloDefinition> {
        self.definitions.iter().map(|e| e.value().clone()).collect()
    }
}

impl Default for SloTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::SloDefinition;

    fn api_slo() -> SloDefinition {
        SloDefinition {
            name: "api-availability".into(),
            target: 99.9,
            window_days: 30,
        }
    }

    #[test]
    fn test_define_and_list() {
        let tracker = SloTracker::new();
        tracker.define(api_slo());
        let all = tracker.list_all();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].name, "api-availability");
    }

    #[test]
    fn test_evaluate_within_budget() {
        let tracker = SloTracker::new();
        tracker.define(api_slo());

        // 100_000 total, 50 errors → 99.95% → within 99.9 target
        let eval = tracker.evaluate("api-availability", 100_000, 50).unwrap();
        assert!(eval.within_budget);
        assert!(eval.actual > 99.9);
    }

    #[test]
    fn test_evaluate_exceeds_budget() {
        let tracker = SloTracker::new();
        tracker.define(api_slo());

        // 1000 total, 5 errors → 99.5% → below 99.9 target
        let eval = tracker.evaluate("api-availability", 1000, 5).unwrap();
        assert!(!eval.within_budget);
        assert!(eval.actual < 99.9);
    }
}
