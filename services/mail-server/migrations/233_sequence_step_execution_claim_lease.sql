-- Migration 233: lease-based claims for sales_step_executions (audit SM7 F2).
--
-- =============================================================================
-- WHY (P1 sequence dead-end): the send claim was
--
--     UPDATE sales_step_executions SET state = 'executing' ...
--     WHERE id = $1 AND state IN ('scheduled', 'queued')
--
-- and NO code path ever transitioned a step back out of 'executing'. Every
-- transient failure between the claim and the terminal write (a DB blip on
-- the dispatcher enqueue, a crash) therefore stranded the step in
-- 'executing' forever: the retried action passed the terminal-state gate,
-- its claim matched zero rows, and the handler returned SUCCEEDED without
-- sending and without advancing — a silently cancelled customer touch and an
-- enrollment frozen mid-sequence.
--
-- THE FIX (crates/sales-autopilot/src/sequence_worker.rs):
--
--   * the claim now stamps `claimed_at` — the lease;
--   * `requeue_stale_executing_steps` (wired into the action worker's tick,
--     next to the sales_actions lease reaper) requeues steps whose lease
--     expired, so a crashed or failed attempt is RECOVERED, not stranded;
--   * a claim miss on a NON-terminal state now returns Retry/dead-letter,
--     never Succeeded — only 'sent'/'skipped'/'cancelled' short-circuit.
--
-- Duplicate-send safety is unchanged and is why the reaper is sound: the
-- send identity is the step execution's idempotency key, so a requeued step
-- whose message actually went out resolves to DuplicateIdempotency on the
-- retry and is marked sent without a second email.
-- =============================================================================

ALTER TABLE sales_step_executions
    ADD COLUMN IF NOT EXISTS claimed_at TIMESTAMPTZ;

COMMENT ON COLUMN sales_step_executions.claimed_at IS
    'Lease stamp of the executing claim (audit SM7 F2). The reaper '
    '(sales_autopilot::sequence_worker::requeue_stale_executing_steps) requeues '
    'executing rows older than the lease; NULL on every non-executing row. Legacy '
    'executing rows predating this migration are reaped by their updated_at age.';

-- The reaper's scan: only executing rows, by lease age.
CREATE INDEX IF NOT EXISTS idx_sales_step_executions_executing_lease
    ON sales_step_executions (COALESCE(claimed_at, updated_at))
    WHERE state = 'executing';
