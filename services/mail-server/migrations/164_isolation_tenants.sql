-- Migration 164: Isolation tenants
--
-- =============================================================================
-- F63: canonical schema for the isolation crate's organization / workspace
-- hierarchy (tenant.rs). The crate creates organizations and workspaces,
-- manages workspace membership and quotas/usage — but no migration ever
-- created iso_organizations, iso_workspaces, iso_workspace_members or
-- iso_cleanup_queue, so every one of those statements failed at runtime.
--
-- ID-domain decision (deliberate): these tables do NOT foreign-key into the
-- canonical `tenants` table. tenants.id is VARCHAR(26) (ULID-style, see
-- 064_standardize_tenant_id_varchar26.sql), while the isolation crate
-- generates ids with `Uuid::new_v4().to_string()` — 36-character canonical
-- UUID strings (tenant.rs create_organization / create_workspace /
-- add_workspace_member). An FK to tenants(id) would reject every INSERT the
-- crate performs. The iso_* hierarchy therefore uses TEXT ids with FKs among
-- its own tables, exactly matching what the code binds and reads.
--
-- Shapes derived from the OrgRow / WorkspaceRow structs and the exact SQL
-- column lists in tenant.rs:
--   * iso_workspaces UNIQUE (organization_id, slug) — create_workspace
--     checks slug uniqueness per org before inserting.
--   * iso_workspace_members UNIQUE (workspace_id, user_id) —
--     add_workspace_member upserts ON CONFLICT (workspace_id, user_id).
--   * invited_by is NULLable: the creator-membership INSERT (workspace
--     creation) omits it.
--   * iso_cleanup_queue: delete_workspace enqueues a 30-day-delayed cleanup
--     (INSERT is best-effort ".ok()" — table present so the queue works).
-- =============================================================================

CREATE TABLE IF NOT EXISTS iso_organizations (
    id               TEXT        PRIMARY KEY,
    name             TEXT        NOT NULL,
    slug             TEXT        NOT NULL UNIQUE,
    billing_email    TEXT        NOT NULL,
    plan             TEXT        NOT NULL DEFAULT 'free',
    status           TEXT        NOT NULL DEFAULT 'active',
        -- active | suspended
    isolation_level  TEXT        NOT NULL DEFAULT 'shared',
        -- shared | dedicated_schema
    schema_name      TEXT,
    database_name    TEXT,
    owner_id         TEXT        NOT NULL,
    settings         JSONB       NOT NULL DEFAULT '{}'::jsonb,
    metadata         JSONB       NOT NULL DEFAULT '{}'::jsonb,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS iso_workspaces (
    id               TEXT        PRIMARY KEY,
    organization_id  TEXT        NOT NULL REFERENCES iso_organizations(id),
    name             TEXT        NOT NULL,
    slug             TEXT        NOT NULL,
    status           TEXT        NOT NULL DEFAULT 'active',
        -- active | suspended | deleted
    schema_name      TEXT,
    database_name    TEXT,
    quota            JSONB       NOT NULL,
    usage            JSONB       NOT NULL,
    settings         JSONB       NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- One live slug per organization (create_workspace enforces this in code;
-- deleted workspaces keep their slug).
CREATE UNIQUE INDEX IF NOT EXISTS idx_iso_workspaces_org_slug
    ON iso_workspaces (organization_id, slug)
    WHERE status != 'deleted';

-- list_workspaces / count queries filter by organization_id + status.
CREATE INDEX IF NOT EXISTS idx_iso_workspaces_org
    ON iso_workspaces (organization_id, status);

CREATE TABLE IF NOT EXISTS iso_workspace_members (
    id            TEXT        PRIMARY KEY,
    workspace_id  TEXT        NOT NULL REFERENCES iso_workspaces(id) ON DELETE CASCADE,
    user_id       TEXT        NOT NULL,
    role          TEXT        NOT NULL,
        -- admin | member | viewer
    permissions   JSONB       NOT NULL DEFAULT '[]'::jsonb,
    invited_by    TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- add_workspace_member upserts ON CONFLICT (workspace_id, user_id);
-- check_member_access / remove_workspace_member look up the same pair.
CREATE UNIQUE INDEX IF NOT EXISTS idx_iso_workspace_members_ws_user
    ON iso_workspace_members (workspace_id, user_id);

CREATE TABLE IF NOT EXISTS iso_cleanup_queue (
    id            TEXT        PRIMARY KEY,
    workspace_id  TEXT        NOT NULL REFERENCES iso_workspaces(id) ON DELETE CASCADE,
    scheduled_at  TIMESTAMPTZ NOT NULL,
    created_by    TEXT        NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_iso_cleanup_queue_scheduled_at
    ON iso_cleanup_queue (scheduled_at);
