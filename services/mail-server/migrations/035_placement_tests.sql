-- Placement tests created by customers
BEGIN;
CREATE TABLE IF NOT EXISTS placement_tests (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         UUID NOT NULL,
    name              VARCHAR(255),
    status            VARCHAR(20) NOT NULL DEFAULT 'pending',
    from_email        VARCHAR(320) NOT NULL,
    subject           VARCHAR(998) NOT NULL,
    body_text         TEXT,
    body_html         TEXT,
    total_accounts    INTEGER NOT NULL DEFAULT 0,
    completed_accounts INTEGER NOT NULL DEFAULT 0,
    seed_accounts_used UUID[] NOT NULL DEFAULT '{}',
    scheduled_for     TIMESTAMPTZ,
    completed_at      TIMESTAMPTZ,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_placement_tests_tenant ON placement_tests (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_placement_tests_status ON placement_tests (status) WHERE status = 'pending' OR status = 'running';
COMMIT;
