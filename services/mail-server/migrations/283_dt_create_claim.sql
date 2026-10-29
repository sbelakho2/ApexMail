-- Migration 283: Dedicated Tenant atomic create claim (eighth external audit, P0-DT).
--
-- enterprise/src/dedicated_exec.rs POSTs the provider's server-create
-- endpoint for a `validated` deployment. Two defects the audit found:
--
--   1. Two concurrent operator calls both read the row (status=validated,
--      no host) and both POST — two real servers, both billed.
--   2. A provider success followed by a LOCAL persist failure leaves no
--      durable host id, so a retry POSTs again — a second machine.
--
-- The remediation claims the create ATOMICALLY before the provider call:
-- execute_host_provision_via runs
--
--   UPDATE ent_private_deployments
--   SET create_claim_token = $2, create_claimed_at = NOW()
--   WHERE id = $1 AND status = 'validated'
--     AND (provider_host_id IS NULL OR provider_host_id = '')
--     AND (create_claimed_at IS NULL
--          OR create_claimed_at < NOW() - INTERVAL '10 minutes')
--   RETURNING create_claim_token
--
-- and only the single winner may POST. Zero rows affected means another
-- execution holds a live claim: nothing is created and the caller receives
-- the typed 409 (ExecError::CreateClaimed) pointing at reconciliation.
--
-- The 10-minute window is the crashed-claimant recovery path: a claim older
-- than the window is STALE and can be stolen by a new claim, so a process
-- that died between claim and POST cannot block provisioning forever.
--
-- Deterministic recovery for an UNCERTAIN create (transport error, timeout,
-- persist failure after a 201): the create stamps the provider server with
-- the deterministic label `apexmail-dt:<deployment id>`, so the executor
-- can LIST the provider by that label before any further create and ADOPT
-- the found server instead of duplicating it (see dedicated_exec.rs). These
-- columns are the local half of that evidence: a row with
-- create_claimed_at set but no provider_host_id is exactly the
-- "create may exist unrecorded" state reconciliation resolves.
--
-- Additive only: two nullable columns, IF NOT EXISTS, no data touched,
-- idempotent by construction.

ALTER TABLE ent_private_deployments ADD COLUMN IF NOT EXISTS create_claim_token UUID;
ALTER TABLE ent_private_deployments ADD COLUMN IF NOT EXISTS create_claimed_at TIMESTAMPTZ;

COMMENT ON COLUMN ent_private_deployments.create_claim_token IS
    'Fresh per-attempt token written by the atomic pre-create claim in enterprise/src/dedicated_exec.rs; only the claim winner may POST the provider create (eighth external audit, P0-DT).';
COMMENT ON COLUMN ent_private_deployments.create_claimed_at IS
    'When the create claim was taken. A claim inside the 10-minute window blocks further creates (409); a STALE claim is stealable — the recovery path for a crashed claimant. Claim set without provider_host_id means a create may exist unrecorded: reconcile by the deterministic provider label apexmail-dt:<deployment id> before creating.';
