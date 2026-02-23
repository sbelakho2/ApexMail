//! Incident management with lifecycle tracking.
//!
//! All state is held in-memory behind a [`parking_lot::RwLock`].

use chrono::Utc;
use parking_lot::RwLock;
use std::sync::Arc;
use uuid::Uuid;

use crate::types::{Incident, IncidentSeverity, IncidentStatus, TimelineEntry};

/// Thread-safe incident manager.
#[derive(Debug, Clone)]
pub struct IncidentManager {
    incidents: Arc<RwLock<Vec<Incident>>>,
    timelines: Arc<RwLock<Vec<(Uuid, TimelineEntry)>>>,
}

impl IncidentManager {
    pub fn new() -> Self {
        Self {
            incidents: Arc::new(RwLock::new(Vec::new())),
            timelines: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Create a new incident and return its id.
    pub fn create_incident(
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
        self.incidents.write().push(incident);
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
    pub fn update_status(&self, id: Uuid, new_status: IncidentStatus, message: impl Into<String>) -> bool {
        let mut incidents = self.incidents.write();
        if let Some(inc) = incidents.iter_mut().find(|i| i.id == id) {
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

    /// Convenience wrapper: resolve an incident.
    pub fn resolve(&self, id: Uuid, message: impl Into<String>) -> bool {
        self.update_status(id, IncidentStatus::Resolved, message)
    }

    /// List all incidents that are **not** resolved.
    pub fn list_active(&self) -> Vec<Incident> {
        self.incidents
            .read()
            .iter()
            .filter(|i| i.status != IncidentStatus::Resolved)
            .cloned()
            .collect()
    }

    /// Retrieve an incident by id.
    pub fn get_by_id(&self, id: Uuid) -> Option<Incident> {
        self.incidents.read().iter().find(|i| i.id == id).cloned()
    }

    /// Return the timeline entries for a given incident.
    pub fn get_timeline(&self, id: Uuid) -> Vec<TimelineEntry> {
        self.timelines
            .read()
            .iter()
            .filter(|(iid, _)| *iid == id)
            .map(|(_, e)| e.clone())
            .collect()
    }
}

impl Default for IncidentManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_and_list_active() {
        let mgr = IncidentManager::new();
        let id = mgr.create_incident("DB outage", IncidentSeverity::P1, vec!["db".into()]);

        let active = mgr.list_active();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].id, id);
        assert_eq!(active[0].status, IncidentStatus::Open);
    }

    #[test]
    fn test_update_status() {
        let mgr = IncidentManager::new();
        let id = mgr.create_incident("Slow API", IncidentSeverity::P3, vec!["api".into()]);

        let ok = mgr.update_status(id, IncidentStatus::Investigating, "Looking into it");
        assert!(ok);

        let inc = mgr.get_by_id(id).unwrap();
        assert_eq!(inc.status, IncidentStatus::Investigating);
    }

    #[test]
    fn test_resolve_removes_from_active() {
        let mgr = IncidentManager::new();
        let id = mgr.create_incident("High latency", IncidentSeverity::P2, vec!["api".into()]);

        mgr.resolve(id, "Fixed");
        let active = mgr.list_active();
        assert!(active.is_empty());

        let inc = mgr.get_by_id(id).unwrap();
        assert_eq!(inc.status, IncidentStatus::Resolved);
        assert!(inc.resolved_at.is_some());
    }

    #[test]
    fn test_timeline() {
        let mgr = IncidentManager::new();
        let id = mgr.create_incident("Disk full", IncidentSeverity::P1, vec!["storage".into()]);
        mgr.update_status(id, IncidentStatus::Identified, "Root cause found");
        mgr.resolve(id, "Disk cleaned");

        let tl = mgr.get_timeline(id);
        assert_eq!(tl.len(), 3);
        assert_eq!(tl[0].status, IncidentStatus::Open);
        assert_eq!(tl[1].status, IncidentStatus::Identified);
        assert_eq!(tl[2].status, IncidentStatus::Resolved);
    }
}
