-- 195_iso_access_attempts.sql
--
-- =============================================================================
-- F63: canonical schema for the isolation crate's data-access audit trail.
-- data_isolation.rs audit_access_attempt INSERTs
--   (id, organization_id, workspace_id, actor_id, target_workspace_id,
--    resource, action, allowed, context, created_at)
-- with id bound as Uuid::new_v4().to_string() — but no migration ever
-- created iso_access_attempts, so every allow/deny decision the policy
-- engine made was lost with a 42P01 (logged as an audit-trail gap).
--
-- Shape derived from the exact INSERT column list and the IsolationContext
-- field types: all identifiers TEXT in the iso_* hierarchy's UUID-string
-- domain (see 164's ID-domain note — these FKs reference the iso_*
-- organization/workspace relations the crate actually creates, NOT the
-- canonical tenants table whose ids are VARCHAR(26) ULIDs). context is a
-- non-Option serde_json::Value → JSONB NOT NULL. allowed BOOLEAN NOT NULL.
--
-- Retention: DataIsolationService::cleanup_access_attempts purges rows
-- older than the configured window; idx_iso_access_attempts_created_at
-- serves that scan. Organization/workspace-scoped indexes serve the
-- investigative reads (which org/workspace saw which attempts).
-- =============================================================================

CREATE TABLE IF NOT EXISTS iso_access_attempts (
    id                  TEXT        PRIMARY KEY,
    organization_id     TEXT        NOT NULL REFERENCES iso_organizations(id),
    workspace_id        TEXT        REFERENCES iso_workspaces(id),
    actor_id            TEXT        NOT NULL,
    target_workspace_id TEXT        NOT NULL,
    resource            TEXT        NOT NULL,
    action              TEXT        NOT NULL,
    allowed             BOOLEAN     NOT NULL,
    context             JSONB       NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_iso_access_attempts_org_created
    ON iso_access_attempts (organization_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_iso_access_attempts_workspace_created
    ON iso_access_attempts (workspace_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_iso_access_attempts_actor_created
    ON iso_access_attempts (actor_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_iso_access_attempts_created_at
    ON iso_access_attempts (created_at);
