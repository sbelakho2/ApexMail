-- Migration 201: Sales execution contract
--
-- =============================================================================
-- The v2 unification (migration 200) created the Decision Packet and the
-- durable action queue, but the two were not actually connected: the sequence
-- worker enforced its own copy of the gates inline and never called
-- `decision_engine::decide`, so no outgoing sequence email carried a
-- `sales_decisions` row. Recording a decision engine that the live path does
-- not use is worse than having none — it makes the architecture look
-- auditable while the running application is not.
--
-- This migration adds the columns that let the live path (a) persist the
-- enforcement verdict, (b) reference the sender it actually sends from,
-- (c) carry an operator approval as a state rather than as an action replay,
-- and (d) fence a worker's writes behind a per-claim lease token.
--
-- Rollout note: `sales_actions.decision_id` is deliberately NOT made NOT NULL
-- here. Queued send_step actions created before this change legitimately have
-- a null decision id; the constraint belongs in the invariants migration
-- (204) that runs after the queue has drained.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- 1. sales_decisions — enforcement, sender reference, operator review
-- ---------------------------------------------------------------------------
ALTER TABLE sales_decisions
    ADD COLUMN IF NOT EXISTS enforcement TEXT,
    ADD COLUMN IF NOT EXISTS selected_sender_id UUID,
    ADD COLUMN IF NOT EXISTS review_status TEXT,
    ADD COLUMN IF NOT EXISTS reviewed_by TEXT,
    ADD COLUMN IF NOT EXISTS reviewed_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS review_note TEXT;

-- The enforcement verdict must be one of the four the engine can return. A
-- free-text column here would let a writer invent a verdict the worker's
-- match arms do not handle.
DO $$
BEGIN
    ALTER TABLE sales_decisions DROP CONSTRAINT IF EXISTS chk_sales_decisions_enforcement;
    ALTER TABLE sales_decisions ADD CONSTRAINT chk_sales_decisions_enforcement
        CHECK (enforcement IS NULL OR enforcement IN ('execute', 'denied', 'shadowed', 'await_approval'));
EXCEPTION
    WHEN check_violation THEN
        RAISE EXCEPTION 'sales_decisions already contains an enforcement value outside the four known verdicts; reconcile before applying 201';
END
$$;

DO $$
BEGIN
    ALTER TABLE sales_decisions DROP CONSTRAINT IF EXISTS chk_sales_decisions_review_status;
    ALTER TABLE sales_decisions ADD CONSTRAINT chk_sales_decisions_review_status
        CHECK (
            review_status IS NULL
            OR review_status IN ('pending', 'approved', 'rejected', 'not_required')
        );
EXCEPTION
    WHEN check_violation THEN
        RAISE EXCEPTION 'sales_decisions already contains an unknown review_status; reconcile before applying 201';
END
$$;

DO $$
BEGIN
    ALTER TABLE sales_decisions DROP CONSTRAINT IF EXISTS fk_sales_decisions_sender;
    ALTER TABLE sales_decisions ADD CONSTRAINT fk_sales_decisions_sender
        FOREIGN KEY (selected_sender_id)
        REFERENCES sales_sender_identities(id)
        ON DELETE SET NULL;
END
$$;

CREATE INDEX IF NOT EXISTS idx_sales_decisions_review_pending
    ON sales_decisions (tenant_id, created_at DESC)
    WHERE review_status = 'pending';

-- `selected_sender` (TEXT) is the pre-201 carrier. New code writes
-- `selected_sender_id`; the text column is retained for read compatibility and
-- is dropped by a later cleanup migration once no reader depends on it.
COMMENT ON COLUMN sales_decisions.selected_sender IS
    'Deprecated: pre-201 TEXT carrier for the sender identity. Use selected_sender_id.';

-- ---------------------------------------------------------------------------
-- 2. sales_actions — lease token and the awaiting_approval state
-- ---------------------------------------------------------------------------
-- A lease identified only by an owner *string* cannot distinguish two claims
-- by the same worker (or two containers that happen to share a PID). The token
-- makes each claim individually fenced, so a worker whose lease was recovered
-- by another process cannot complete or mutate the action afterwards.
ALTER TABLE sales_actions
    ADD COLUMN IF NOT EXISTS lease_token UUID;

-- A decision that needs a human is not a failure and not a success: the work
-- must survive, unclaimed, until an operator acts. Reusing `queued` for that
-- would let the normal claim path pick it straight back up.
DO $$
BEGIN
    ALTER TABLE sales_actions DROP CONSTRAINT IF EXISTS sales_actions_state_check;
    ALTER TABLE sales_actions ADD CONSTRAINT sales_actions_state_check
        CHECK (state IN (
            'queued', 'leased', 'executing', 'succeeded', 'failed',
            'dead_letter', 'cancelled', 'awaiting_approval'
        ));
END
$$;

CREATE INDEX IF NOT EXISTS idx_sales_actions_awaiting_approval
    ON sales_actions (tenant_id, decision_id)
    WHERE state = 'awaiting_approval';

-- ---------------------------------------------------------------------------
-- 3. sales_step_executions — the sender actually used
-- ---------------------------------------------------------------------------
ALTER TABLE sales_step_executions
    ADD COLUMN IF NOT EXISTS sender_identity_id UUID
        REFERENCES sales_sender_identities(id) ON DELETE SET NULL;

-- ---------------------------------------------------------------------------
-- 4. sales_discovery_jobs — leased and fenced
-- ---------------------------------------------------------------------------
-- A discovery job that only flips `status = 'running'` has no ownership: two
-- runners can execute the same job concurrently and a crashed runner leaves
-- the job running forever.
ALTER TABLE sales_discovery_jobs
    ADD COLUMN IF NOT EXISTS lease_owner TEXT,
    ADD COLUMN IF NOT EXISTS lease_token UUID,
    ADD COLUMN IF NOT EXISTS lease_expires_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS attempt INTEGER NOT NULL DEFAULT 0;

DO $$
BEGIN
    ALTER TABLE sales_discovery_jobs DROP CONSTRAINT IF EXISTS sales_discovery_jobs_attempt_check;
    ALTER TABLE sales_discovery_jobs ADD CONSTRAINT sales_discovery_jobs_attempt_check
        CHECK (attempt >= 0);
END
$$;

CREATE INDEX IF NOT EXISTS idx_sales_discovery_jobs_claimable
    ON sales_discovery_jobs (status, lease_expires_at)
    WHERE status IN ('queued', 'running');

-- ---------------------------------------------------------------------------
-- 5. Legacy campaign → canonical sequence mapping
-- ---------------------------------------------------------------------------
-- The control plane's `sales_campaigns` model still has a start endpoint. It
-- must stop dispatching mail itself and instead materialize canonical
-- enrollments; this column is the stable mapping from a legacy campaign to the
-- compatibility sequence that represents it, so restarting a campaign adapts
-- the same sequence rather than creating a new one on every call.
ALTER TABLE sales_sequences
    ADD COLUMN IF NOT EXISTS legacy_campaign_id UUID;

CREATE UNIQUE INDEX IF NOT EXISTS idx_sales_sequences_legacy_campaign
    ON sales_sequences (tenant_id, legacy_campaign_id)
    WHERE legacy_campaign_id IS NOT NULL;
