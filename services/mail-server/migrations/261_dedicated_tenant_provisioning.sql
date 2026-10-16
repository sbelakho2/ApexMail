-- Migration 261: Dedicated Tenant provisioning — lifecycle spellings + the
-- recorded deployment-bundle artifact.
--
-- The 2026-10 plan sells Dedicated Tenant as a code-side provisioning
-- workflow: a per-tenant deployment bundle is generated and VALIDATED
-- (release-SHA-pinned, EU/EEA default, 2 managed IPs, catalog-checked fees),
-- and the deployment record walks the audited lifecycle
-- requested -> validated -> provisioned -> active -> decommissioning ->
-- decommissioned. `ent_private_deployments` (migration 043) carried only the
-- generic status vocabulary and no place to record the validated bundle, so
-- nothing downstream could prove a deployment was ever validated.
--
-- This migration is additive and touches no data:
--
--   1. `ent_private_deployments.status` gains the dedicated-tenant
--      spellings ('requested', 'validated', 'provisioned',
--      'decommissioned') while KEEPING every existing value valid. The
--      legacy spellings are not removed: 'pending' is what the generic
--      create path (and its regression tests) writes and is the storage
--      synonym of the machine's `requested` state, and 'provisioning' /
--      'maintenance' remain reachable from the legacy provision/health
--      paths. No UPDATE runs: mapping stored rows between spellings would
--      rewrite operator-visible history, and the state machine reads both
--      spellings (see `enterprise/src/dedicated_tenant.rs`).
--   2. The bundle artifact columns: `bundle_path` and `bundle_sha256` (the
--      sha256 over the rendered bundle bytes — the identity the operator
--      and the reconciliation checks agree on), `validated_at`, and
--      `validation_report` (the full fail-closed report the transition
--      gates read).
--
-- Idempotent by construction (existence-probing guards, IF NOT EXISTS, no
-- DML) so a re-run no-ops cleanly.

-- ---------------------------------------------------------------------------
-- 1. status: extended lifecycle vocabulary.
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'ent_private_deployments_status_check'
          AND conrelid = 'ent_private_deployments'::regclass
    ) THEN
        ALTER TABLE ent_private_deployments DROP CONSTRAINT ent_private_deployments_status_check;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'ent_private_deployments_status_check'
          AND conrelid = 'ent_private_deployments'::regclass
    ) THEN
        ALTER TABLE ent_private_deployments
            ADD CONSTRAINT ent_private_deployments_status_check
            CHECK (status IN (
                -- generic/legacy vocabulary
                'pending', 'provisioning', 'maintenance', 'failed',
                -- dedicated-tenant lifecycle (the state machine's spellings)
                'requested', 'validated', 'provisioned',
                -- shared by both vocabularies
                'active',
                -- lifecycle tail
                'decommissioning', 'decommissioned'
            ));
    END IF;
END
$$;

-- ---------------------------------------------------------------------------
-- 2. The validated-bundle artifact recorded on the deployment row.
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_schema = 'public' AND table_name = 'ent_private_deployments'
                     AND column_name = 'bundle_path') THEN
        ALTER TABLE ent_private_deployments ADD COLUMN bundle_path TEXT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_schema = 'public' AND table_name = 'ent_private_deployments'
                     AND column_name = 'bundle_sha256') THEN
        ALTER TABLE ent_private_deployments ADD COLUMN bundle_sha256 VARCHAR(64);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_schema = 'public' AND table_name = 'ent_private_deployments'
                     AND column_name = 'validated_at') THEN
        ALTER TABLE ent_private_deployments ADD COLUMN validated_at TIMESTAMPTZ;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_schema = 'public' AND table_name = 'ent_private_deployments'
                     AND column_name = 'validation_report') THEN
        ALTER TABLE ent_private_deployments ADD COLUMN validation_report JSONB;
    END IF;
END
$$;

-- The lifecycle read: "the dedicated deployments of tenant X by status".
CREATE INDEX IF NOT EXISTS idx_ent_private_deployments_dedicated_lifecycle
    ON ent_private_deployments (tenant_id, status, created_at DESC)
    WHERE deployment_type = 'dedicated';

COMMENT ON COLUMN ent_private_deployments.bundle_sha256 IS
    'sha256 of the rendered dedicated-tenant deployment bundle (see enterprise/src/dedicated_tenant.rs); the validation artifact the lifecycle transitions read.';
COMMENT ON COLUMN ent_private_deployments.validation_report IS
    'The fail-closed validation report for the rendered bundle (passed flag, per-check rows, recorded operator overrides).';
