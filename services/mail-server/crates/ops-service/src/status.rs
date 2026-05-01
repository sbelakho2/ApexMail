//! Status page generation.
//!
//! Derives an overall status from individual service health checks.

use chrono::Utc;

use crate::types::{HealthCheck, ServiceStatus, StatusPage};

/// Generates an aggregate [`StatusPage`] from a set of health checks.
pub struct StatusPageGenerator;

impl StatusPageGenerator {
    /// Build a status page from the provided checks.
    /// The `overall_status` is the *worst* status observed across all services.
    /// If the input slice is empty the overall status is [`ServiceStatus::Operational`].
    pub fn generate_page(checks: &[HealthCheck]) -> StatusPage {
        let overall_status = checks
            .iter()
            .map(|c| c.status)
            .max()
            .unwrap_or(ServiceStatus::Operational);

        StatusPage {
            overall_status,
            services: checks.to_vec(),
            updated_at: Utc::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::HealthCheck;

    fn check(service: &str, status: ServiceStatus) -> HealthCheck {
        HealthCheck {
            service: service.into(),
            status,
            latency_ms: 10,
            timestamp: Utc::now(),
        }
    }

    #[test]
    fn test_all_operational() {
        let checks = vec![
            check("api", ServiceStatus::Operational),
            check("db", ServiceStatus::Operational),
        ];
        let page = StatusPageGenerator::generate_page(&checks);
        assert_eq!(page.overall_status, ServiceStatus::Operational);
        assert_eq!(page.services.len(), 2);
    }

    #[test]
    fn test_worst_status_wins() {
        let checks = vec![
            check("api", ServiceStatus::Operational),
            check("db", ServiceStatus::MajorOutage),
            check("cache", ServiceStatus::Degraded),
        ];
        let page = StatusPageGenerator::generate_page(&checks);
        assert_eq!(page.overall_status, ServiceStatus::MajorOutage);
    }

    #[test]
    fn test_empty_checks() {
        let page = StatusPageGenerator::generate_page(&[]);
        assert_eq!(page.overall_status, ServiceStatus::Operational);
        assert!(page.services.is_empty());
    }
}
