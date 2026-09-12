-- Migration 207: Dedicated-IP provisioning state machine
--
-- =============================================================================
-- P0: the dedicated-IP provisioning path could publish an unusable IP.
--
-- Before this migration the only persisted lifecycle was
--     warming -> active
-- and `allocate_ip` wrote `warming` immediately after the provider call, even
-- when attaching the floating IP to an MTA server failed (only warned) or
-- rDNS was never set / never verified. The worker admits dedicated senders
-- from `status = 'warming'`, so a half-attached IP could receive production
-- traffic. The provisioning lifecycle is now explicit:
--
--     provisioning -> created -> attached -> rdns_ready -> warming -> active
--
-- Only `warming` (with `warmup_started_at`) and `active` are selectable for
-- sending; every select path keeps filtering on exactly those statuses
-- (worker: `status = 'warming'`; routing-cache trigger:
-- `status IN ('active','warming')`), so the new intermediate states are
-- unreachable by construction.
--
-- Vocabulary: this is a strict superset of BOTH constraint variants that
-- exist in the chain — migration 003
-- (`pending, warming, active, suspended, releasing, retired`) and migration
-- 021's create branch (`warming, active, cooldown, releasing, retired`). No
-- existing allowed value is removed, so existing rows stay valid. The
-- constraint is added NOT VALID and validated best-effort so a historically
-- inconsistent row can never abort a deploy.
--
-- Additive: three nullable audit columns; no existing column or row changes.
-- =============================================================================

-- 1. Extended status vocabulary (superset of both historical definitions).
ALTER TABLE dedicated_ips DROP CONSTRAINT IF EXISTS dedicated_ips_status_check;
ALTER TABLE dedicated_ips ADD CONSTRAINT dedicated_ips_status_check
    CHECK (status IN (
        'pending',
        'provisioning',
        'created',
        'attached',
        'rdns_ready',
        'warming',
        'active',
        'suspended',
        'cooldown',
        'failed',
        'cleanup_failed',
        'releasing',
        'retired'
    )) NOT VALID;

DO $$
BEGIN
    EXECUTE 'ALTER TABLE dedicated_ips VALIDATE CONSTRAINT dedicated_ips_status_check';
EXCEPTION WHEN check_violation THEN
    RAISE NOTICE 'dedicated_ips_status_check left NOT VALID: pre-existing row outside the vocabulary';
END $$;

-- 2. Provisioning failure audit — loud and queryable.
--    `cleanup_failed` means the provider resource may still exist and must be
--    reconciled by an operator; the Hetzner id stays in
--    `hetzner_floating_ip_id` and the provider response in
--    `provisioning_error`.
ALTER TABLE dedicated_ips ADD COLUMN IF NOT EXISTS provisioning_error TEXT;
ALTER TABLE dedicated_ips ADD COLUMN IF NOT EXISTS provisioning_failed_at TIMESTAMPTZ;

-- rDNS is verified with an actual PTR lookup (not the provider's 200 OK); the
-- verification timestamp is the evidence a `warming` promotion requires.
ALTER TABLE dedicated_ips ADD COLUMN IF NOT EXISTS rdns_verified_at TIMESTAMPTZ;

-- 3. Reconciliation support for interrupted attempts. Billing's
--    auto-provision intentionally fires N concurrent allocate requests for a
--    tenant (one per purchased IP), so in-flight rows are NOT unique per
--    tenant: each attempt owns a distinct provider floating IP, and a losing
--    attempt is compensated by deleting its own resource (see
--    `run_provisioning`). This index makes the two operator queries cheap:
--      * stale in-flight rows:
--          SELECT id, tenant_id, status, created_at FROM dedicated_ips
--          WHERE status IN ('created','attached','rdns_ready')
--            AND updated_at < NOW() - INTERVAL '1 hour';
--      * rows whose provider resource may still exist (the worklist):
--          SELECT id, tenant_id, hetzner_floating_ip_id, provisioning_error
--          FROM dedicated_ips WHERE status = 'cleanup_failed';
CREATE INDEX IF NOT EXISTS idx_dedicated_ips_inflight
    ON dedicated_ips (status, created_at)
    WHERE status IN ('provisioning', 'created', 'attached', 'rdns_ready');

-- 4. A `warming` row must carry its warmup anchor. The worker keys daily
--    admission on `warmup_started_at`; a warming row without it previously
--    slipped through every guard until EXTRACT(...) yielded NULL. Added NOT
--    VALID and validated best-effort for the same reason as (1).
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'public.dedicated_ips'::regclass
          AND conname = 'dedicated_ips_warming_anchor_check'
    ) THEN
        EXECUTE 'ALTER TABLE dedicated_ips ADD CONSTRAINT dedicated_ips_warming_anchor_check
                 CHECK (status <> ''warming'' OR warmup_started_at IS NOT NULL) NOT VALID';
    END IF;
    BEGIN
        EXECUTE 'ALTER TABLE dedicated_ips VALIDATE CONSTRAINT dedicated_ips_warming_anchor_check';
    EXCEPTION WHEN check_violation THEN
        RAISE NOTICE 'dedicated_ips_warming_anchor_check left NOT VALID: pre-existing warming row without warmup_started_at';
    END;
END $$;

-- 5. Operator visibility for rows that may carry a live provider resource.
CREATE INDEX IF NOT EXISTS idx_dedicated_ips_failure_states
    ON dedicated_ips (status)
    WHERE status IN ('failed', 'cleanup_failed');
