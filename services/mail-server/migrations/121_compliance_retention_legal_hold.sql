-- Migration 121: Compliance retention controls on the canonical tenants table.
--
-- The retention sweep (crates/compliance/src/retention_sweep.rs) and the GDPR
-- erasure workflow need two tenant-level controls that previously existed only
-- in the archived legacy schema (tools/migrations/001_initial_schema.sql
-- carried tenants.legal_hold) or nowhere at all:
--
--   * tenants.legal_hold  — tenants under legal hold must be EXCLUDED from
--     every retention purge (event stores, gdpr_exports, DSR outbox, audit
--     trim). Deleting data under a legal hold is evidence spoliation.
--   * tenants.retention_days — per-tenant retention override. NULL means
--     "use the plan-tier default" resolved from the RET-001..023 registry;
--     a value is validated by RetentionRegistry::validate_customer_selection
--     (must be >= the category minimum and <= the tenant's plan limit).
--
--   * audit_logs.tenant_id is added IF NOT EXISTS as a heal for databases
--     whose audit_logs predates migration 038 (the UUID-shaped legacy
--     runtime table had no tenant linkage, so retention could not exclude
--     held tenants). On canonical-shape databases (038) this is a no-op:
--     audit_logs.tenant_id TEXT already exists there.
--
-- All statements are idempotent (ADD COLUMN IF NOT EXISTS).

ALTER TABLE tenants ADD COLUMN IF NOT EXISTS legal_hold BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS retention_days INT;

-- Partial index: the sweep only ever asks for held tenants.
CREATE INDEX IF NOT EXISTS idx_tenants_legal_hold
    ON tenants (id) WHERE legal_hold;

-- Heal pre-038 audit_logs shapes so audit rows can be attributed to a tenant
-- (NULL = legacy rows with unknown attribution; retention keeps them when any
-- hold is active because they cannot be excluded).
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS tenant_id TEXT;
