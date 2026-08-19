-- =============================================================================
-- Domain DKIM readiness convergence
-- Migration: 018_domain_dkim_readiness.sql
-- Purpose: Keep the lightweight tool/test schema aligned with the production
--          domain-authentication contract.
-- =============================================================================

ALTER TABLE domains ADD COLUMN IF NOT EXISTS spf_verified BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS dkim_verified BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS dmarc_verified BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS return_path_verified BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS mta_sts_verified BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS bimi_verified BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS tlsrpt_verified BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS dkim_enabled BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS dkim_private_key TEXT;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS ses_verified BOOLEAN NOT NULL DEFAULT false;

-- Older tool databases stored the domain key under this legacy column. Preserve
-- it only for explicit verification-time migration; new domain writes use the
-- fail-closed encrypted dkim_private_key column.
UPDATE domains
SET dkim_private_key = dkim_private_key_encrypted
WHERE dkim_private_key IS NULL
  AND dkim_private_key_encrypted IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_domains_sending_readiness
    ON domains (tenant_id, name)
    WHERE status = 'verified' AND dkim_enabled = true;
