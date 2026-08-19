-- Domain authentication readiness hardening.
--
-- A verified flag alone cannot authorize mail: a domain must have complete
-- per-domain DKIM material and, when SES is used, an independently observed
-- SES identity readiness state. Preserve legacy rows for explicit repair via
-- POST /v1/domains/:id/verify, but do not leave partial rows marked verified.

ALTER TABLE domains ADD COLUMN IF NOT EXISTS dkim_selector TEXT;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS dkim_public_key TEXT;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS dkim_private_key TEXT;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS dkim_enabled BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS ses_verified BOOLEAN NOT NULL DEFAULT false;

UPDATE domains
SET verified = false
WHERE status IS DISTINCT FROM 'verified';

UPDATE domains
SET status = 'pending',
    verified = false,
    ses_verified = false,
    dkim_verified = false
WHERE status = 'verified'
  AND (
      dkim_enabled = false
      OR dkim_selector IS NULL OR btrim(dkim_selector) = ''
      OR dkim_public_key IS NULL OR btrim(dkim_public_key) = ''
      OR dkim_private_key IS NULL OR btrim(dkim_private_key) = ''
        OR dkim_private_key NOT LIKE 'dkim:v1:%'
  );

CREATE INDEX IF NOT EXISTS idx_domains_sending_readiness
    ON domains (tenant_id, name)
    WHERE status = 'verified' AND dkim_enabled = true;
