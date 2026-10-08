-- Migration 247: custom tracking domains — per-tenant verified host lifecycle.
--
-- Context (dogfood 2026-10-06 P0 capability wave 2): `custom_tracking_domain`
-- is sold on Pro and above (docs/pricing.md) but had NO setup/verification
-- route and the tracking service had no tenant custom-domain lifecycle, so
-- the entitlement could not be granted honestly. This migration adds the
-- state the lifecycle needs:
--
--   * one row per configured tracking host (e.g. `email.example.com`);
--   * `domain` is GLOBALLY unique: a CNAME'd request reaches the tracking
--     service with only the Host header as the tenant signal, so a tracking
--     host must resolve to exactly one workspace;
--   * `(tenant_id, parent_domain)` is unique per docs/domains/tracking-domain.md
--     ("You can only have one custom tracking domain per verified domain");
--   * `status` is one of pending|verified|failed and `status_reason` carries
--     the NAMED reason when a check fails — never a silent state;
--   * `cname_target` is stored per row so the DNS record shown to the
--     customer is byte-for-byte the one verification compares against.
--
-- Idempotent by construction (CREATE ... IF NOT EXISTS throughout), valid
-- inside the migrator's single transaction.

CREATE TABLE IF NOT EXISTS tracking_domains (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    domain          VARCHAR(253) NOT NULL,
    parent_domain   VARCHAR(253) NOT NULL,
    status          VARCHAR(16) NOT NULL DEFAULT 'pending',
    status_reason   TEXT,
    cname_target    VARCHAR(253) NOT NULL,
    verified_at     TIMESTAMPTZ,
    last_checked_at TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'tracking_domains_status_check'
    ) THEN
        ALTER TABLE tracking_domains
            ADD CONSTRAINT tracking_domains_status_check
            CHECK (status IN ('pending', 'verified', 'failed'));
    END IF;
END $$;

CREATE UNIQUE INDEX IF NOT EXISTS uq_tracking_domains_domain
    ON tracking_domains (domain);
CREATE UNIQUE INDEX IF NOT EXISTS uq_tracking_domains_tenant_parent
    ON tracking_domains (tenant_id, parent_domain);
CREATE INDEX IF NOT EXISTS idx_tracking_domains_tenant
    ON tracking_domains (tenant_id, created_at DESC);
