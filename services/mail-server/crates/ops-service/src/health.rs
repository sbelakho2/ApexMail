//! Health checking subsystem.
//!
//! Uses a [`DashMap`] for lock-free concurrent storage of check results.

use chrono::Utc;
use dashmap::DashMap;
use std::sync::Arc;
use std::time::Duration;

use crate::types::{HealthCheck, ServiceStatus};

/// In-memory health checker that probes services and records history.
#[derive(Debug, Clone)]
pub struct HealthChecker {
/// Map from service name → ring buffer of recent health checks.
    history: Arc<DashMap<String, Vec<HealthCheck>>>,
/// Maximum history entries kept per service.
    max_history: usize,
    http_client: reqwest::Client,
}

impl HealthChecker {
    pub fn new(max_history: usize) -> Self {
        Self {
            history: Arc::new(DashMap::new()),
            max_history,
            http_client: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("failed to build HTTP client"),
        }
    }

/// Perform a health check against a single service by hitting its URL.
/// In production this issues an HTTP GET; the result is stored in memory.
/// For unit tests, use [`record_check`] to inject synthetic results.
    pub async fn check_service(&self, name: &str, url: &str) -> HealthCheck {
        let start = std::time::Instant::now();
        let (status, latency_ms) = match self.http_client.get(url).send().await {
            Ok(resp) if resp.status().is_success() => {
                (ServiceStatus::Operational, start.elapsed().as_millis() as u64)
            }
            Ok(_) => (ServiceStatus::Degraded, start.elapsed().as_millis() as u64),
            Err(_) => (ServiceStatus::MajorOutage, start.elapsed().as_millis() as u64),
        };

        let check = HealthCheck {
            service: name.to_string(),
            status,
            latency_ms,
            timestamp: Utc::now(),
        };
        self.record_check(check.clone());
        check
    }

/// Check all previously-seen services (re-check using stored names).
/// Returns the latest result for every service.
    pub fn latest_checks(&self) -> Vec<HealthCheck> {
        self.history
            .iter()
            .filter_map(|entry| entry.value().last().cloned())
            .collect()
    }

/// Return the last `limit` health-check entries for the given service.
    pub fn get_history(&self, service: &str, limit: usize) -> Vec<HealthCheck> {
        self.history
            .get(service)
            .map(|v| {
                let data = v.value();
                let start = data.len().saturating_sub(limit);
                data[start..].to_vec()
            })
            .unwrap_or_default()
    }

/// Manually record a [`HealthCheck`] (useful for testing and synthetic checks).
    pub fn record_check(&self, check: HealthCheck) {
        let mut entry = self.history.entry(check.service.clone()).or_default();
        entry.push(check);
        if entry.len() > self.max_history {
            let excess = entry.len() - self.max_history;
            entry.drain(..excess);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_check(service: &str, status: ServiceStatus, latency_ms: u64) -> HealthCheck {
        HealthCheck {
            service: service.to_string(),
            status,
            latency_ms,
            timestamp: Utc::now(),
        }
    }

    #[test]
    fn test_record_and_latest() {
        let checker = HealthChecker::new(100);
        checker.record_check(make_check("api", ServiceStatus::Operational, 5));
        checker.record_check(make_check("db", ServiceStatus::Degraded, 50));

        let latest = checker.latest_checks();
        assert_eq!(latest.len(), 2);
    }

    #[test]
    fn test_history_limit() {
        let checker = HealthChecker::new(3);
        for i in 0..5 {
            checker.record_check(make_check("api", ServiceStatus::Operational, i));
        }
        let hist = checker.get_history("api", 10);
        assert_eq!(hist.len(), 3); // max_history caps at 3
    }

    #[test]
    fn test_get_history_subset() {
        let checker = HealthChecker::new(100);
        for i in 0..10 {
            checker.record_check(make_check("worker", ServiceStatus::Operational, i));
        }
        let hist = checker.get_history("worker", 3);
        assert_eq!(hist.len(), 3);
// Should be the *last* 3 entries
        assert_eq!(hist[0].latency_ms, 7);
        assert_eq!(hist[2].latency_ms, 9);
    }
}
