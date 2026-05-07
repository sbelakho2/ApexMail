-- Migration 041: Per-provider outbound throttle overrides.
-- Operators can override the postmaster_reputation_summary recommendation
-- for a tenant + provider pair (e.g. force 100% throttle during incident).
--
-- Throttle pct semantics: 0 = no throttling (send all), 100 = block all.
-- The outbound-queue probabilistically defers messages whose roll exceeds
-- (100 - throttle_pct).

CREATE TABLE IF NOT EXISTS outbound_provider_throttle_overrides (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       TEXT,                          -- NULL = global override
    provider        TEXT NOT NULL,                  -- 'google'|'microsoft'|'yahoo'|'apple'|'aol'|'other'
    throttle_pct    INT  NOT NULL CHECK (throttle_pct BETWEEN 0 AND 100),
    reason          TEXT NOT NULL,
    expires_at      TIMESTAMPTZ,                    -- NULL = no expiry
    created_by      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_throttle_overrides_lookup
    ON outbound_provider_throttle_overrides (provider, tenant_id)
    WHERE expires_at IS NULL OR expires_at > NOW();

CREATE INDEX IF NOT EXISTS idx_throttle_overrides_active
    ON outbound_provider_throttle_overrides (expires_at)
    WHERE expires_at IS NOT NULL;

-- Audit: every actual probabilistic defer driven by reputation/override
-- so customers can see WHY their messages were paused.
CREATE TABLE IF NOT EXISTS outbound_throttle_decisions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       TEXT,
    sender_domain   TEXT,
    recipient_domain TEXT NOT NULL,
    provider        TEXT NOT NULL,
    throttle_pct    INT  NOT NULL,
    decision        TEXT NOT NULL,        -- 'sent' | 'deferred'
    source          TEXT NOT NULL,        -- 'reputation' | 'override' | 'default'
    score           INT,
    band            TEXT,
    decided_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_throttle_decisions_recent
    ON outbound_throttle_decisions (decided_at DESC, provider, decision);

CREATE INDEX IF NOT EXISTS idx_throttle_decisions_tenant
    ON outbound_throttle_decisions (tenant_id, decided_at DESC)
    WHERE tenant_id IS NOT NULL;
