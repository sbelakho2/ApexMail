-- 181: independent tenant access restrictions (audit F09).
--
-- Payment recovery wrote tenants.status = 'active' whenever no open abuse
-- row existed — clearing administrator suspensions and pending
-- verification in the same stroke, because a single status column cannot
-- record WHY a tenant is restricted. This table represents each
-- restriction cause independently (billing / administrative /
-- verification / abuse) with actor, reason and timestamps; effective send
-- access is derived from ALL active rows, and a confirmed billing
-- recovery clears ONLY the billing restriction before recomputing.

CREATE TABLE IF NOT EXISTS tenant_restrictions (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     VARCHAR(26) NOT NULL,
    kind          VARCHAR(16) NOT NULL
        CHECK (kind IN ('billing', 'administrative', 'verification', 'abuse')),
    reason        TEXT NOT NULL DEFAULT '',
    actor_type    VARCHAR(16) NOT NULL DEFAULT 'system'
        CHECK (actor_type IN ('system', 'admin', 'support')),
    actor_id      VARCHAR(64),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    cleared_at    TIMESTAMPTZ,
    cleared_by    VARCHAR(64),
    cleared_reason TEXT
);

-- One ACTIVE restriction per (tenant, kind): the latest cause wins;
-- history is preserved in cleared rows.
CREATE UNIQUE INDEX IF NOT EXISTS uq_tenant_restrictions_active
    ON tenant_restrictions (tenant_id, kind)
    WHERE cleared_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_tenant_restrictions_tenant
    ON tenant_restrictions (tenant_id, created_at DESC);

-- Seed active billing restrictions for tenants currently suspended by the
-- dunning flow, so the first recovery after this migration can attribute
-- the suspension to billing. Tenants suspended for other reasons get NO
-- billing row: recovery will leave them restricted (the conservative
-- direction — an unattributable suspension is never auto-cleared).
INSERT INTO tenant_restrictions (tenant_id, kind, reason, actor_type)
SELECT t.id, 'billing',
       'backfilled from dunning suspension state (migration 181)',
       'system'
FROM tenants t
WHERE t.status = 'suspended'
  AND EXISTS (
      SELECT 1 FROM dunning_records d
      WHERE d.tenant_id = t.id
        AND d.failed_payment_count > 0
        AND d.status <> 'healthy'
  )
ON CONFLICT DO NOTHING;
