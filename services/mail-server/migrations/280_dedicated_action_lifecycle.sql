-- Migration 280: dedicated-tenant host execution against the provider's
-- REAL asynchronous contract (seventh external audit, P0-DT-4).
--
-- A create-server 201 means the provider ACCEPTED the work, not that the
-- machine exists: the response carries an `action` whose completion must
-- be observed before the deployment may be called provisioned. The
-- executor therefore persists the action id and its observed state
-- alongside the server id, holding the deployment in `validated` (the
-- machine maps the legacy `provisioning` spelling to Provisioned, which
-- would make the completed transition illegal) until the action succeeds
-- AND the server verifies operational. Re-executing a
-- mid-flight deployment RESUMES the poll loop; it never re-creates the
-- server (the same idempotency rule the one-shot create already had).
--
-- Additive only: one nullable column, existence-guarded, idempotent.

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'ent_private_deployments'
          AND column_name = 'provider_action_id'
    ) THEN
        RAISE NOTICE 'provider_action_id already present; skipping';
    ELSE
        ALTER TABLE ent_private_deployments
            ADD COLUMN provider_action_id TEXT;
        ALTER TABLE ent_private_deployments
            ADD COLUMN provider_action_state TEXT;
    END IF;
END
$$;

COMMENT ON COLUMN ent_private_deployments.provider_action_id IS
    'The provider create/provision action id; the async lifecycle is polled until success before the deployment may transition to provisioned (seventh external audit, P0-DT-4).';
COMMENT ON COLUMN ent_private_deployments.provider_action_state IS
    'Last observed provider action status (running/success/error); provisioning is resumable, never re-created.';
