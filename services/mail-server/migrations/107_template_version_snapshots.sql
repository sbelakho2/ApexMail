-- 107: Template version snapshots (audit item L-1).
--
-- POST /v1/templates/:id/rollback restores a template from
-- `template_versions`, but nothing ever created the table or wrote rows to
-- it: every rollback failed (relation does not exist) and no version
-- history existed to roll back to.
--
-- Fix: create the table and snapshot every saved state. The API's template
-- writer (routes/templates.rs) inserts a v1 snapshot on create and a new
-- snapshot on each update inside the same transaction as the templates
-- write, using ON CONFLICT (template_id, version) DO UPDATE so history
-- stays linear after a rollback (saving again after rolling back to v1
-- rewrites v2 rather than colliding with the stale v2 snapshot).

CREATE TABLE IF NOT EXISTS template_versions (
    template_id VARCHAR(26)  NOT NULL,
    tenant_id   VARCHAR(26)  NOT NULL,
    version     INTEGER      NOT NULL,
    name        VARCHAR(255) NOT NULL,
    subject     VARCHAR(255) NOT NULL,
    html_body   TEXT         NOT NULL,
    text_body   TEXT,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    PRIMARY KEY (template_id, version)
);

CREATE INDEX IF NOT EXISTS idx_template_versions_tenant
    ON template_versions(tenant_id);

-- Seed one snapshot per existing template so current content is rollback-
-- safe from the moment this migration lands (version = the template's
-- current version).
INSERT INTO template_versions (template_id, tenant_id, version, name, subject, html_body, text_body, created_at)
SELECT t.id, t.tenant_id, t.version, t.name, t.subject, t.html_body, t.text_body, t.updated_at
FROM templates t
ON CONFLICT (template_id, version) DO NOTHING;
