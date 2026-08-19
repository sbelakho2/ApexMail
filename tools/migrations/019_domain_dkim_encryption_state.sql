-- =============================================================================
-- Domain sender-readiness state convergence
-- Migration: 019_domain_dkim_encryption_state.sql
--
-- The test/tool schema must enforce the same fail-closed readiness contract as
-- production migration 100: plaintext or incomplete DKIM material is never a
-- verified sender. POST /domains/:id/verify performs the explicit repair.
-- =============================================================================

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