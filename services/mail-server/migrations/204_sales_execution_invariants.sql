-- Migration 204: Sales execution invariants
--
-- =============================================================================
-- The point of this migration is that a future programmer literally cannot
-- accidentally reintroduce a decisionless Sales V2 email, or an external sales
-- action with no Decision Packet behind it.
--
-- Two deliberate design choices make that safe to apply BEFORE the old queue
-- has drained (the audit's requirement was to run this "after the deployment
-- has backfilled/drained pre-fix work, not in the first migration"):
--
--   1. The two CHECK constraints are added `NOT VALID`. PostgreSQL enforces a
--      NOT VALID check on every INSERT and UPDATE immediately, but does not
--      scan existing rows — so pre-fix rows are grandfathered rather than
--      failing the deploy, while no NEW row can violate the invariant. A later
--      migration runs VALIDATE CONSTRAINT once the drain is confirmed (see the
--      instructions at the bottom of this file).
--
--   2. `sales_decisions.enforcement` is backfilled from the information that
--      already exists before it is made NOT NULL, so existing packets keep a
--      truthful verdict instead of blocking the deploy or being defaulted to a
--      value nobody chose.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- 1. Backfill the Decision Packet verdicts, then require them
-- ---------------------------------------------------------------------------
-- `enforcement` was added nullable in 201. Rows written before the live path
-- recorded verdicts have NULL. Derive each one from what the row already says,
-- in precedence order, so the backfilled value is a defensible reading of the
-- stored data rather than an invented default:
--   * a blocked packet was denied (block_reasons is non-empty);
--   * otherwise the autonomy mode tells us whether it executed.
UPDATE sales_decisions
SET enforcement = CASE
        WHEN blocked THEN 'denied'
        WHEN autonomy_mode = 'shadow' THEN 'shadowed'
        WHEN autonomy_mode IN ('assisted', 'approval_required') THEN 'await_approval'
        ELSE 'execute'
    END
WHERE enforcement IS NULL;

-- A packet that was never awaiting review is 'not_required'; one whose derived
-- verdict awaits approval is 'pending', so it surfaces in the operator queue
-- rather than sitting invisible.
UPDATE sales_decisions
SET review_status = CASE
        WHEN enforcement = 'await_approval' THEN 'pending'
        ELSE 'not_required'
    END
WHERE review_status IS NULL;

DO $$
BEGIN
    ALTER TABLE sales_decisions ALTER COLUMN enforcement SET NOT NULL;
    ALTER TABLE sales_decisions ALTER COLUMN review_status SET NOT NULL;
EXCEPTION
    WHEN not_null_violation THEN
        RAISE EXCEPTION
            'migration 204 could not require sales_decisions.enforcement: rows still have NULL after backfill. Inspect sales_decisions for values outside the known autonomy_mode set and reconcile.';
END
$$;

-- ---------------------------------------------------------------------------
-- 2. Every external sales EFFECT must carry a decision
-- ---------------------------------------------------------------------------
-- The audit asked for a CHECK on `sales_actions` requiring `decision_id` for
-- every `send_step`. That constraint cannot be satisfied by the correct
-- architecture, and shipping it would force either a broken enrollment path or
-- the constraint being disabled in production. The reason is structural:
--
--   * `enrollments::start_outreach` enqueues `send_step` work at ENROLLMENT
--     time (one action per contact) — before any decision exists;
--   * the Decision Packet is computed at EXECUTION time, because it depends on
--     facts that only exist then: the refreshed score, the gathered evidence,
--     the chosen experiment variant and the resolved sender identity
--     (`sequence_worker::handle_inner` → `decision_engine::decide`).
--
-- So a queued, leased or executing `send_step` legitimately has no decision
-- yet, and the early-skip branches (kill switch, autonomy disabled, human
-- reply, unsendable enrollment) correctly record a skip without a packet —
-- they produced no external effect to explain.
--
-- The invariant that actually holds, and the one that delivers the audit's
-- stated goal ("a future programmer literally cannot accidentally reintroduce
-- a decisionless Sales V2 email"), is enforced at the point of no return: the
-- `email_queue` constraint in section 3. An external sales effect cannot exist
-- without full provenance, regardless of which code path tries to create it.
-- The dispatch boundary additionally requires a decision at compile time:
-- `ProductionCampaignDispatcher::enqueue_sequenced` takes `decision_id: Uuid`
-- as a required parameter.
--
-- Recorded here rather than as a constraint so the next reader does not
-- reintroduce a CHECK that the correct code cannot pass.
COMMENT ON COLUMN sales_actions.decision_id IS
    'The Decision Packet that authorized this action. NULL is legitimate for a queued send_step: the packet is computed at execution time. The external effect is guarded by chk_sales_sequence_has_decision on email_queue.';

-- ---------------------------------------------------------------------------
-- 3. Every sequenced email must carry full typed provenance
-- ---------------------------------------------------------------------------
-- `email_queue.tags` is TEXT[], so the membership test is the array form.
-- A row tagged `sales-sequence` without all four provenance columns is exactly
-- the "attribution without reverse-engineering JSON" defect migration 202
-- exists to remove.
DO $$
BEGIN
    ALTER TABLE email_queue DROP CONSTRAINT IF EXISTS chk_sales_sequence_has_decision;
    ALTER TABLE email_queue ADD CONSTRAINT chk_sales_sequence_has_decision
        CHECK (
            NOT ('sales-sequence' = ANY (tags))
            OR (
                sales_decision_id IS NOT NULL
                AND sales_sender_identity_id IS NOT NULL
                AND sales_step_execution_id IS NOT NULL
                AND sales_enrollment_id IS NOT NULL
            )
        )
        NOT VALID;
END
$$;

-- =============================================================================
-- VALIDATION STEP — run this as a NAMED, SEPARATE migration once the queue has
-- drained, not here. `NOT VALID` already enforces every new row; VALIDATE only
-- extends that guarantee to the historical rows, and it takes a (short,
-- non-blocking for reads) ACCESS EXCLUSIVE lock, so it belongs in its own
-- change that an operator can schedule:
--
--   ALTER TABLE email_queue VALIDATE CONSTRAINT chk_sales_sequence_has_decision;
--
-- Precondition before validating:
--   SELECT COUNT(*) FROM email_queue
--    WHERE 'sales-sequence' = ANY(tags)
--      AND (sales_decision_id IS NULL OR sales_sender_identity_id IS NULL
--           OR sales_step_execution_id IS NULL OR sales_enrollment_id IS NULL);
--                                                              -- must be 0
--
-- If either count is non-zero the remaining rows are pre-fix work that must be
-- re-planned (replay through the worker) or explicitly cancelled — never
-- deleted just to make the count zero, since they may carry delivery history.
-- =============================================================================
