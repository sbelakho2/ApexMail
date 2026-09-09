-- 166_isolation_data_isolation.sql
--
-- =============================================================================
-- F63: canonical schema for the isolation crate's data-isolation layer.
-- data_isolation.rs loads row-level access policies into memory
-- (load_policies: SELECT id, name, resource, conditions, actions, effect
-- FROM iso_access_policies) and tracks per-workspace isolation level
-- (migrate_isolation_level UPDATEs iso_isolation_configs SET
-- current_level/migration_status/updated_at WHERE workspace_id = $2) — but
-- no migration ever created either table, so policy loading and isolation
-- migrations both failed at runtime.
--
-- Shapes derived from the exact SQL and the load_policies decode tuple
-- (String, String, String, JSONB, JSONB, String). iso_isolation_configs is
-- keyed by workspace_id (the UPDATE's WHERE key) and references the
-- iso_workspaces table created in 164.
-- =============================================================================

CREATE TABLE IF NOT EXISTS iso_access_policies (
    id          TEXT   PRIMARY KEY,
    name        TEXT   NOT NULL,
    resource    TEXT   NOT NULL,
    conditions  JSONB  NOT NULL,
    actions     JSONB  NOT NULL,
    effect      TEXT   NOT NULL
        -- allow | deny
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_iso_access_policies_name
    ON iso_access_policies (name);

CREATE TABLE IF NOT EXISTS iso_isolation_configs (
    workspace_id       TEXT        PRIMARY KEY REFERENCES iso_workspaces(id) ON DELETE CASCADE,
    current_level      TEXT        NOT NULL DEFAULT 'shared',
        -- shared | dedicated_schema
    migration_status   TEXT        NOT NULL DEFAULT 'completed',
        -- completed (the only status the crate writes)
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
