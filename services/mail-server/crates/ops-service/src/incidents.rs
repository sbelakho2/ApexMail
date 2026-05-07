//! Incident management with lifecycle tracking.
//!
//! State is persisted to PostgreSQL via the status_page_incidents table.
//! An in-memory cache is maintained for fast reads.

use chrono::Utc;
use parking_lot::RwLock;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

use crate::types::{Incident, IncidentSeverity, IncidentStatus, TimelineEntry};
use apexmail_db::repos::incidents::IncidentRepo;

/// Thread-safe incident manager with database persistence.
#[derive(Debug, Clone)]
pub struct IncidentManager {
    db: PgPool,
    persist_to_db: bool,
    /// In-memory cache for fast reads (write-through).
    cache: Arc<RwLock<Vec<Incident>>>,
    timelines: Arc<RwLock<Vec<(Uuid, TimelineEntry)>>>,
}

impl IncidentManager {
    pub fn new(db: PgPool) -> Self {
        Self {
            db,
            persist_to_db: true,
            cache: Arc::new(RwLock::new(Vec::new())),
            timelines: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Create a manager that keeps state in memory without database persistence.
    /// Create an ephemeral instance for testing.
    /// Uses lazy connection so it will not block on startup (O-23.2).
    /// If the connection string is invalid, falls back to a warning log
    /// instead of panicking.
    pub fn new_ephemeral() -> Self {
        let db = PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://localhost:5432/unused")
            .unwrap_or_else(|e| {
                tracing::warn!(
                    error = %e,
                    "Ephemeral pool creation failed; creating fallback pool"
                );
                // Fallback: a syntactically valid URL that will fail at
                // connection time rather than panicking at construction.
                PgPoolOptions::new()
                    .max_connections(1)
                    .connect_lazy("postgres://localhost:5432/postgres")
                    .expect("hardcoded fallback URL is syntactically valid")
            });
        Self {
            db,
            persist_to_db: false,
            cache: Arc::new(RwLock::new(Vec::new())),
            timelines: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Create a new in-memory-only manager for testing without database.
    #[cfg(test)]
    pub fn new_in_memory() -> Self {
        Self::new_ephemeral()
    }

    /// Create a new incident and return its id.
    /// Persists to database and updates cache.
    pub async fn create_incident(
        &self,
        title: impl Into<String>,
        severity: IncidentSeverity,
        affected_services: Vec<String>,
    ) -> Result<Uuid, sqlx::Error> {
        let id = Uuid::new_v4();
        let now = Utc::now();
        let title = title.into();

        // Map severity to impact string for database
        let impact = match severity {
            IncidentSeverity::P1 => "critical",
            IncidentSeverity::P2 => "major",
            IncidentSeverity::P3 => "minor",
            IncidentSeverity::P4 => "none",
        };

        if self.persist_to_db {
            IncidentRepo::create(
                &self.db,
                &id.to_string(),
                &title,
                "investigating", // IncidentStatus::Open maps to "investigating"
                impact,
                &affected_services,
            )
            .await?;

            let update_id = Uuid::new_v4();
            IncidentRepo::add_update(
                &self.db,
                &update_id.to_string(),
                &id.to_string(),
                "investigating",
                "Incident created",
                "system",
            )
            .await?;
        }

        let incident = Incident {
            id,
            title,
            severity,
            status: IncidentStatus::Open,
            started_at: now,
            resolved_at: None,
            affected_services,
        };

        // Update cache
        self.cache.write().push(incident);
        self.timelines.write().push((
            id,
            TimelineEntry {
                timestamp: now,
                status: IncidentStatus::Open,
                message: "Incident created".into(),
            },
        ));

        Ok(id)
    }

    /// Create a new incident synchronously (for backwards compatibility in tests).
    #[cfg(test)]
    pub fn create_incident_sync(
        &self,
        title: impl Into<String>,
        severity: IncidentSeverity,
        affected_services: Vec<String>,
    ) -> Uuid {
        let id = Uuid::new_v4();
        let now = Utc::now();
        let incident = Incident {
            id,
            title: title.into(),
            severity,
            status: IncidentStatus::Open,
            started_at: now,
            resolved_at: None,
            affected_services,
        };
        self.cache.write().push(incident);
        self.timelines.write().push((
            id,
            TimelineEntry {
                timestamp: now,
                status: IncidentStatus::Open,
                message: "Incident created".into(),
            },
        ));
        id
    }

    /// Update the status of an existing incident.
    pub async fn update_status(
        &self,
        id: Uuid,
        new_status: IncidentStatus,
        message: impl Into<String>,
    ) -> Result<bool, sqlx::Error> {
        let message = message.into();
        let status_str = match new_status {
            IncidentStatus::Open => "investigating",
            IncidentStatus::Investigating => "investigating",
            IncidentStatus::Identified => "identified",
            IncidentStatus::Monitoring => "monitoring",
            IncidentStatus::Resolved => "resolved",
        };
        let resolved = new_status == IncidentStatus::Resolved;

        if self.persist_to_db {
            let result =
                IncidentRepo::update_status(&self.db, &id.to_string(), status_str, resolved)
                    .await?;
            if result.is_none() {
                return Ok(false);
            }

            let update_id = Uuid::new_v4();
            IncidentRepo::add_update(
                &self.db,
                &update_id.to_string(),
                &id.to_string(),
                status_str,
                &message,
                "system",
            )
            .await?;
        } else if !self.cache.read().iter().any(|inc| inc.id == id) {
            return Ok(false);
        }

        let mut cache = self.cache.write();
        if let Some(inc) = cache.iter_mut().find(|i| i.id == id) {
            inc.status = new_status;
            if resolved {
                inc.resolved_at = Some(Utc::now());
            }
        }

        self.timelines.write().push((
            id,
            TimelineEntry {
                timestamp: Utc::now(),
                status: new_status,
                message,
            },
        ));

        Ok(true)
    }

    /// Update status synchronously (for backwards compatibility in tests).
    #[cfg(test)]
    pub fn update_status_sync(
        &self,
        id: Uuid,
        new_status: IncidentStatus,
        message: impl Into<String>,
    ) -> bool {
        let mut cache = self.cache.write();
        if let Some(inc) = cache.iter_mut().find(|i| i.id == id) {
            inc.status = new_status;
            if new_status == IncidentStatus::Resolved {
                inc.resolved_at = Some(Utc::now());
            }
            self.timelines.write().push((
                id,
                TimelineEntry {
                    timestamp: Utc::now(),
                    status: new_status,
                    message: message.into(),
                },
            ));
            true
        } else {
            false
        }
    }

    /// Convenience wrapper:resolve an incident.
    pub async fn resolve(&self, id: Uuid, message: impl Into<String>) -> Result<bool, sqlx::Error> {
        self.update_status(id, IncidentStatus::Resolved, message)
            .await
    }

    /// Resolve synchronously (for backwards compatibility in tests).
    #[cfg(test)]
    pub fn resolve_sync(&self, id: Uuid, message: impl Into<String>) -> bool {
        self.update_status_sync(id, IncidentStatus::Resolved, message)
    }

    /// List all incidents that are **not** resolved.
    pub fn list_active(&self, limit: usize, offset: usize) -> Vec<Incident> {
        self.cache
            .read()
            .iter()
            .filter(|i| i.status != IncidentStatus::Resolved)
            .skip(offset)
            .take(limit)
            .cloned()
            .collect()
    }

    /// List active incidents from database (async).
    pub async fn list_active_from_db(
        &self,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Incident>, sqlx::Error> {
        if !self.persist_to_db {
            let limit = usize::try_from(limit.max(0)).unwrap_or(usize::MAX);
            let offset = usize::try_from(offset.max(0)).unwrap_or(0);
            return Ok(self.list_active(limit, offset));
        }

        let db_incidents = IncidentRepo::list_active(&self.db, limit, offset).await?;
        db_incidents
            .into_iter()
            .map(|i| {
                let id = parse_incident_id(&i.id)?;
                Ok(Incident {
                    id,
                    title: i.title,
                    severity: severity_from_impact(&i.impact),
                    status: match i.status.as_str() {
                        "investigating" => IncidentStatus::Investigating,
                        "identified" => IncidentStatus::Identified,
                        "monitoring" => IncidentStatus::Monitoring,
                        "resolved" => IncidentStatus::Resolved,
                        _ => IncidentStatus::Open,
                    },
                    started_at: i.created_at,
                    resolved_at: i.resolved_at,
                    affected_services: i.affected_components,
                })
            })
            .collect::<Result<Vec<_>, sqlx::Error>>()
    }

    /// Retrieve an incident by id from cache.
    pub fn get_by_id(&self, id: Uuid) -> Option<Incident> {
        self.cache.read().iter().find(|i| i.id == id).cloned()
    }

    /// Retrieve an incident by id from database (async).
    pub async fn get_by_id_from_db(&self, id: Uuid) -> Result<Option<Incident>, sqlx::Error> {
        if !self.persist_to_db {
            return Ok(self.get_by_id(id));
        }

        let db_incident = IncidentRepo::get_by_id(&self.db, &id.to_string()).await?;
        match db_incident {
            Some(i) => {
                let id = parse_incident_id(&i.id)?;
                Ok(Some(Incident {
                    id,
                    title: i.title,
                    severity: severity_from_impact(&i.impact),
                    status: match i.status.as_str() {
                        "investigating" => IncidentStatus::Investigating,
                        "identified" => IncidentStatus::Identified,
                        "monitoring" => IncidentStatus::Monitoring,
                        "resolved" => IncidentStatus::Resolved,
                        _ => IncidentStatus::Open,
                    },
                    started_at: i.created_at,
                    resolved_at: i.resolved_at,
                    affected_services: i.affected_components,
                }))
            }
            None => Ok(None),
        }
    }

    /// Return the timeline entries for a given incident from cache.
    pub fn get_timeline(&self, id: Uuid) -> Vec<TimelineEntry> {
        self.timelines
            .read()
            .iter()
            .filter(|(iid, _)| *iid == id)
            .map(|(_, e)| e.clone())
            .collect()
    }

    /// Load incidents from database into cache on startup.
    pub async fn load_from_db(&self) -> Result<(), sqlx::Error> {
        if !self.persist_to_db {
            return Ok(());
        }

        let db_incidents = IncidentRepo::list(&self.db, 1000, 0).await?;
        let mut cache = self.cache.write();
        cache.clear();
        for i in db_incidents {
            let id = parse_incident_id(&i.id)?;
            cache.push(Incident {
                id,
                title: i.title,
                severity: severity_from_impact(&i.impact),
                status: match i.status.as_str() {
                    "investigating" => IncidentStatus::Investigating,
                    "identified" => IncidentStatus::Identified,
                    "monitoring" => IncidentStatus::Monitoring,
                    "resolved" => IncidentStatus::Resolved,
                    _ => IncidentStatus::Open,
                },
                started_at: i.created_at,
                resolved_at: i.resolved_at,
                affected_services: i.affected_components,
            });
        }
        Ok(())
    }
}

fn severity_from_impact(impact: &str) -> IncidentSeverity {
    match impact {
        "critical" => IncidentSeverity::P1,
        "major" => IncidentSeverity::P2,
        "minor" => IncidentSeverity::P3,
        "none" => IncidentSeverity::P4,
        _ => IncidentSeverity::P2,
    }
}

fn parse_incident_id(id: &str) -> Result<Uuid, sqlx::Error> {
    Uuid::parse_str(id).map_err(|e| sqlx::Error::Decode(Box::new(e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_and_list_active() {
        let mgr = IncidentManager::new_in_memory();
        let id = mgr.create_incident_sync("DB outage", IncidentSeverity::P1, vec!["db".into()]);

        let active = mgr.list_active(50, 0);
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].id, id);
        assert_eq!(active[0].status, IncidentStatus::Open);
    }

    #[tokio::test]
    async fn test_update_status() {
        let mgr = IncidentManager::new_in_memory();
        let id = mgr.create_incident_sync("Slow API", IncidentSeverity::P3, vec!["api".into()]);

        let ok = mgr.update_status_sync(id, IncidentStatus::Investigating, "Looking into it");
        assert!(ok);

        let inc = mgr.get_by_id(id).unwrap();
        assert_eq!(inc.status, IncidentStatus::Investigating);
    }

    #[tokio::test]
    async fn test_resolve_removes_from_active() {
        let mgr = IncidentManager::new_in_memory();
        let id = mgr.create_incident_sync("High latency", IncidentSeverity::P2, vec!["api".into()]);

        mgr.resolve_sync(id, "Fixed");
        let active = mgr.list_active(50, 0);
        assert!(active.is_empty());

        let inc = mgr.get_by_id(id).unwrap();
        assert_eq!(inc.status, IncidentStatus::Resolved);
        assert!(inc.resolved_at.is_some());
    }

    #[tokio::test]
    async fn test_timeline() {
        let mgr = IncidentManager::new_in_memory();
        let id =
            mgr.create_incident_sync("Disk full", IncidentSeverity::P1, vec!["storage".into()]);
        mgr.update_status_sync(id, IncidentStatus::Identified, "Root cause found");
        mgr.resolve_sync(id, "Disk cleaned");

        let tl = mgr.get_timeline(id);
        assert_eq!(tl.len(), 3);
        assert_eq!(tl[0].status, IncidentStatus::Open);
        assert_eq!(tl[1].status, IncidentStatus::Identified);
        assert_eq!(tl[2].status, IncidentStatus::Resolved);
    }
}
