-- Migration 165: Isolation audit
--
-- =============================================================================
-- F63: canonical schema for the isolation crate's tamper-evident audit log.
-- audit.rs buffers events and flushes them in batches (flush_events INSERT),
-- queries with pagination + filters (query: organization_id + optional
-- workspace_id/severity/actor_id/resource/created_at range), computes
-- statistics grouped by event_type/severity/day/actor (get_stats), walks the
-- hash chain (verify_hash_chain reads metadata->>'hash' ordered by
-- created_at) and purges old rows (DELETE WHERE created_at < $1) — but no
-- migration ever created iso_audit_logs, so none of this persisted.
--
-- Shape derived from the AuditRow struct and the exact SELECT/INSERT column
-- lists: ids and actor/resource strings are TEXT (event ids are
-- Uuid::new_v4().to_string()); workspace_id / actor_ip / actor_user_agent /
-- resource / resource_id are Option → NULLable; details / metadata are
-- non-Option JSON values → NOT NULL. organization_id / workspace_id
-- reference the iso_* hierarchy created in 164 (NOT the canonical tenants
-- table — see the ID-domain note there).
-- =============================================================================

CREATE TABLE IF NOT EXISTS iso_audit_logs (
    id                TEXT        PRIMARY KEY,
    organization_id   TEXT        NOT NULL REFERENCES iso_organizations(id),
    workspace_id      TEXT        REFERENCES iso_workspaces(id),
    event_type        TEXT        NOT NULL,
    severity          TEXT        NOT NULL,
    actor_id          TEXT        NOT NULL,
    actor_type        TEXT        NOT NULL,
        -- user | system | api_key
    actor_ip          TEXT,
    actor_user_agent  TEXT,
    resource          TEXT,
    resource_id       TEXT,
    action            TEXT        NOT NULL,
    details           JSONB       NOT NULL,
    metadata          JSONB       NOT NULL,
        -- carries the hash chain: previous_hash / hash / signature
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- query()/verify_hash_chain(): per-organization, newest first.
CREATE INDEX IF NOT EXISTS idx_iso_audit_logs_org_created
    ON iso_audit_logs (organization_id, created_at DESC);
-- get_stats() groups by event_type / severity / actor within an org window.
CREATE INDEX IF NOT EXISTS idx_iso_audit_logs_org_type
    ON iso_audit_logs (organization_id, event_type, created_at);
CREATE INDEX IF NOT EXISTS idx_iso_audit_logs_org_severity
    ON iso_audit_logs (organization_id, severity, created_at);
-- Retention purge: DELETE ... WHERE created_at < $1.
CREATE INDEX IF NOT EXISTS idx_iso_audit_logs_created_at
    ON iso_audit_logs (created_at);
