-- Migration 198: Status page incidents resolved at
--
-- =============================================================================
-- F86: status_page_incidents.resolved_at. The IncidentRepo
-- (apexmail-db/repos/incidents.rs) reads/writes resolved_at on every query,
-- but migration 115 created the table without it — every repo call failed
-- with 42703, and even with the column added naively, the unresolved update
-- branch would keep a stale resolved_at while list_active filters on
-- resolved_at IS NULL, hiding reopened incidents.
--
-- Deliberate backfill: incidents already in a resolved status get
-- resolved_at from their own history — the latest timeline update that
-- marks resolution, falling back to the row's updated_at when no timeline
-- update exists. Incidents in any other status stay NULL (they were never
-- resolved; the typed transition in the repo now owns this invariant).
--
-- This is the STATUS PAGE incident relation (tenant-facing outage page),
-- not the separate trust-portal incident relation (migration 039).
-- =============================================================================

ALTER TABLE status_page_incidents
    ADD COLUMN IF NOT EXISTS resolved_at TIMESTAMPTZ;

-- One-time reconciliation of legacy resolved rows.
UPDATE status_page_incidents i
SET resolved_at = COALESCE(
        (SELECT MAX(u.created_at)
           FROM status_page_incident_updates u
          WHERE u.incident_id = i.id
            AND lower(u.status) IN ('resolved', 'fixed', 'completed')),
        i.updated_at)
WHERE i.resolved_at IS NULL
  AND lower(i.status) IN ('resolved', 'fixed', 'completed');

-- list_active: unresolved incidents, newest first.
CREATE INDEX IF NOT EXISTS idx_status_page_incidents_unresolved
    ON status_page_incidents (created_at DESC)
    WHERE resolved_at IS NULL;
