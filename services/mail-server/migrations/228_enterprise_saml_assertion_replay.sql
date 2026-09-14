-- Migration 228: SAML assertion replay protection.
--
-- A SAML assertion is a bearer credential: without a consumed-id store an
-- attacker who captures a valid response can replay it for its whole
-- validity window. `SSOService::validate_saml_assertion_claims` consumes the
-- assertion's ID here with an idempotent `ON CONFLICT DO NOTHING` insert and
-- refuses the second use. The store is scoped to the configured tenant and
-- pruned to a bounded retention horizon (24h).
CREATE TABLE IF NOT EXISTS ent_saml_assertion_replays (
    tenant_id    VARCHAR(26) NOT NULL,
    assertion_id TEXT        NOT NULL,
    consumed_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, assertion_id)
);

CREATE INDEX IF NOT EXISTS idx_ent_saml_assertion_replays_consumed_at
    ON ent_saml_assertion_replays (consumed_at);
