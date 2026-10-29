-- Migration 278: Dedicated Tenant host execution — the recorded provider host.
--
-- The Dedicated Tenant lifecycle machine (enterprise/src/dedicated_tenant.rs,
-- migrations 043 + 261) walks requested -> validated -> provisioned -> active
-- -> decommissioning -> decommissioned, and `provisioned` is gated on the
-- validated-bundle artifact. But nothing executed the PHYSICAL host creation
-- against the provider: the validated -> provisioned step was a manual
-- operator action unbacked by an API call, and the row could not record WHAT
-- the provider created (host id, addresses) or WHY an execution attempt
-- failed. enterprise/src/dedicated_exec.rs closes that gap by calling the
-- provider's server-create endpoint; this migration gives the deployment row
-- the columns that execution records.
--
-- This migration is additive and touches no data:
--
--   1. `provider_host_id` — the provider's server id for the created host.
--      A non-NULL value marks the deployment as ALREADY EXECUTED: the
--      execution path is idempotent and returns AlreadyExists instead of
--      creating a second provider resource.
--   2. `provider_host_ips` — the host's public addresses as the provider
--      reported them (IPv4 plus IPv6 when present), recorded for the
--      operator and the runbooks.
--   3. `provisioned_at` — when the provider accepted the create call.
--   4. `provision_error` — the tail of the provider's refusal when an
--      execution attempt failed; the row stays `validated` and the operator
--      can fix the cause and re-execute.
--
-- Idempotent by construction (existence-probing guards, IF NOT EXISTS, no
-- DML) so a re-run no-ops cleanly.

-- ---------------------------------------------------------------------------
-- 1. The provider host recorded on the deployment row.
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_schema = 'public' AND table_name = 'ent_private_deployments'
                     AND column_name = 'provider_host_id') THEN
        ALTER TABLE ent_private_deployments ADD COLUMN provider_host_id TEXT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_schema = 'public' AND table_name = 'ent_private_deployments'
                     AND column_name = 'provider_host_ips') THEN
        ALTER TABLE ent_private_deployments
            ADD COLUMN provider_host_ips TEXT[] NOT NULL DEFAULT '{}';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_schema = 'public' AND table_name = 'ent_private_deployments'
                     AND column_name = 'provisioned_at') THEN
        ALTER TABLE ent_private_deployments ADD COLUMN provisioned_at TIMESTAMPTZ;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_schema = 'public' AND table_name = 'ent_private_deployments'
                     AND column_name = 'provision_error') THEN
        ALTER TABLE ent_private_deployments ADD COLUMN provision_error TEXT;
    END IF;
END
$$;

-- The execution resume read: "deployments of tenant X that already carry a
-- provider host" (idempotent re-execute answers from this row alone).
CREATE INDEX IF NOT EXISTS idx_ent_private_deployments_provider_host
    ON ent_private_deployments (tenant_id, provider_host_id)
    WHERE provider_host_id IS NOT NULL;

COMMENT ON COLUMN ent_private_deployments.provider_host_id IS
    'Provider server id of the executed dedicated-tenant host (see enterprise/src/dedicated_exec.rs); non-NULL marks the deployment as already executed and makes re-execution return AlreadyExists.';
COMMENT ON COLUMN ent_private_deployments.provider_host_ips IS
    'Public addresses of the executed provider host as reported by the provider (IPv4 plus IPv6 when present).';
COMMENT ON COLUMN ent_private_deployments.provision_error IS
    'Tail of the provider refusal when a host-execution attempt failed; the deployment stays `validated` and the operator can fix the cause and re-execute.';
