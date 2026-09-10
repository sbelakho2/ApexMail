//! Status page incidents repository.

use sqlx::PgPool;

use crate::types::{StatusPageIncident, StatusPageIncidentUpdate};

/// Typed incident lifecycle state. ONE transition function
/// ([`IncidentRepo::transition`]) derives both the stored `status` label and
/// `resolved_at` from this value, so callers can never supply contradictory
/// (status, resolved) pairs, and reopening always clears the resolution
/// timestamp (F86).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IncidentStatus {
    Investigating,
    Identified,
    Monitoring,
    Resolved,
}

impl IncidentStatus {
    /// Canonical status label stored in status_page_incidents.status.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Investigating => "investigating",
            Self::Identified => "identified",
            Self::Monitoring => "monitoring",
            Self::Resolved => "resolved",
        }
    }

    /// Whether this state represents a resolved incident. Only
    /// [`Self::Resolved`] stamps resolved_at; every other state clears it.
    pub fn is_resolved(&self) -> bool {
        matches!(self, Self::Resolved)
    }
}

/// Repository for status page incident operations.
pub struct IncidentRepo;

impl IncidentRepo {
    /// Create a new incident.
    pub async fn create(
        pool: &PgPool,
        id: &str,
        title: &str,
        status: &str,
        impact: &str,
        affected_components: &[String],
    ) -> Result<StatusPageIncident, sqlx::Error> {
        sqlx::query_as::<_, StatusPageIncident>(
            "INSERT INTO status_page_incidents (id, title, status, impact, affected_components, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, NOW(), NOW()) \
             RETURNING id, title, status, impact, affected_components, created_at, updated_at, resolved_at",
        )
        .bind(id)
        .bind(title)
        .bind(status)
        .bind(impact)
        .bind(affected_components)
        .fetch_one(pool)
        .await
    }

    /// Get an incident by ID.
    pub async fn get_by_id(
        pool: &PgPool,
        id: &str,
    ) -> Result<Option<StatusPageIncident>, sqlx::Error> {
        sqlx::query_as::<_, StatusPageIncident>(
            "SELECT id, title, status, impact, affected_components, created_at, updated_at, resolved_at \
             FROM status_page_incidents WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(pool)
        .await
    }

    /// List all active (non-resolved) incidents. A reopened incident has its
    /// resolved_at cleared by the typed transition, so it reappears here
    /// (F86: the unresolved update branch used to keep the stale timestamp
    /// and hide reopened incidents).
    pub async fn list_active(
        pool: &PgPool,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<StatusPageIncident>, sqlx::Error> {
        sqlx::query_as::<_, StatusPageIncident>(
            "SELECT id, title, status, impact, affected_components, created_at, updated_at, resolved_at \
             FROM status_page_incidents WHERE resolved_at IS NULL ORDER BY created_at DESC LIMIT $1 OFFSET $2",
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
    }

    /// List all incidents with pagination.
    pub async fn list(
        pool: &PgPool,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<StatusPageIncident>, sqlx::Error> {
        sqlx::query_as::<_, StatusPageIncident>(
            "SELECT id, title, status, impact, affected_components, created_at, updated_at, resolved_at \
             FROM status_page_incidents ORDER BY created_at DESC LIMIT $1 OFFSET $2",
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
    }

    /// F86: the ONE typed state transition. `next` alone determines both the
    /// stored status and resolved_at — resolving stamps NOW(), any other
    /// state clears the timestamp (reopening included). There is no separate
    /// (status, resolved) parameter pair to get out of sync.
    pub async fn transition(
        pool: &PgPool,
        id: &str,
        next: IncidentStatus,
    ) -> Result<Option<StatusPageIncident>, sqlx::Error> {
        sqlx::query_as::<_, StatusPageIncident>(
            "UPDATE status_page_incidents \
             SET status = $2, \
                 resolved_at = CASE WHEN $3 THEN NOW() ELSE NULL END, \
                 updated_at = NOW() \
             WHERE id = $1 \
             RETURNING id, title, status, impact, affected_components, created_at, updated_at, resolved_at",
        )
        .bind(id)
        .bind(next.as_str())
        .bind(next.is_resolved())
        .fetch_optional(pool)
        .await
    }

    /// Add a timeline update to an incident.
    pub async fn add_update(
        pool: &PgPool,
        id: &str,
        incident_id: &str,
        status: &str,
        body: &str,
        author: &str,
    ) -> Result<StatusPageIncidentUpdate, sqlx::Error> {
        sqlx::query_as::<_, StatusPageIncidentUpdate>(
            "INSERT INTO status_page_incident_updates (id, incident_id, status, body, author, created_at) \
             VALUES ($1, $2, $3, $4, $5, NOW()) \
             RETURNING id, incident_id, status, body, author, created_at",
        )
        .bind(id)
        .bind(incident_id)
        .bind(status)
        .bind(body)
        .bind(author)
        .fetch_one(pool)
        .await
    }

    /// Get timeline updates for an incident.
    pub async fn get_updates(
        pool: &PgPool,
        incident_id: &str,
    ) -> Result<Vec<StatusPageIncidentUpdate>, sqlx::Error> {
        sqlx::query_as::<_, StatusPageIncidentUpdate>(
            "SELECT id, incident_id, status, body, author, created_at \
             FROM status_page_incident_updates WHERE incident_id = $1 ORDER BY created_at ASC",
        )
        .bind(incident_id)
        .fetch_all(pool)
        .await
    }

    /// Delete an incident and its updates (CASCADE handles updates).
    pub async fn delete(pool: &PgPool, id: &str) -> Result<bool, sqlx::Error> {
        let result = sqlx::query("DELETE FROM status_page_incidents WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn test_incident_repo_is_stateless() {
        let _repo = IncidentRepo;
    }

    #[test]
    fn test_typed_status_labels() {
        assert_eq!(IncidentStatus::Investigating.as_str(), "investigating");
        assert_eq!(IncidentStatus::Identified.as_str(), "identified");
        assert_eq!(IncidentStatus::Monitoring.as_str(), "monitoring");
        assert_eq!(IncidentStatus::Resolved.as_str(), "resolved");
    }

    /// F86: only Resolved stamps the timestamp; every other state clears it
    /// (reopening included) — one typed value, no contradictory pairs.
    #[test]
    fn test_only_resolved_state_carries_resolution() {
        assert!(IncidentStatus::Resolved.is_resolved());
        assert!(!IncidentStatus::Investigating.is_resolved());
        assert!(!IncidentStatus::Identified.is_resolved());
        assert!(!IncidentStatus::Monitoring.is_resolved());
    }

    #[test]
    fn test_incident_mock() {
        let inc = StatusPageIncident {
            id: "inc_123".into(),
            title: "Database outage".into(),
            status: "investigating".into(),
            impact: "major".into(),
            affected_components: vec!["database".into(), "api".into()],
            created_at: Utc::now(),
            updated_at: Utc::now(),
            resolved_at: None,
        };
        assert_eq!(inc.status, "investigating");
        assert_eq!(inc.affected_components.len(), 2);
    }

    #[test]
    fn test_incident_update_mock() {
        let update = StatusPageIncidentUpdate {
            id: "upd_123".into(),
            incident_id: "inc_123".into(),
            status: "identified".into(),
            body: "Root cause found: disk full".into(),
            author: "ops-team".into(),
            created_at: Utc::now(),
        };
        assert_eq!(update.status, "identified");
        assert!(update.body.contains("disk full"));
    }
}
