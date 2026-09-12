-- Migration 222: validate the sales-sequence provenance invariant.
--
-- Migration 204 added `chk_sales_sequence_has_decision` on `email_queue`
-- `NOT VALID`, with the explicit instruction that validation belongs in a
-- later migration once the pre-fix queue has drained. This is that migration:
-- it reconciles every grandfathered row where it can, refuses loudly where it
-- cannot, and only then runs VALIDATE CONSTRAINT.
--
-- =============================================================================
-- Reconciliation rule, per row (tagged `sales-sequence` with any of the four
-- sales_* provenance columns NULL):
--
--   1. RECOVER from the linked `messages` row (`messages.id =
--      email_queue.message_id`). The dispatcher writes both rows in the same
--      transaction with the same four typed columns
--      (dispatcher.rs: SEQUENCE_MESSAGES_INSERT_SQL / SEQUENCE_EMAIL_QUEUE_
--      INSERT_SQL), so the messages row is authoritative evidence, not a
--      guess. Missing values are then recovered from the queue row's own
--      `metadata` JSON — but ONLY when the id references a row that actually
--      exists (the ids the dispatcher/worker wrote: `sales_decision_id`,
--      `sales_sender_identity_id` / `decision_id`, `enrollment_id`,
--      `sales_step_execution_id`). A value that references nothing is not
--      provenance, so it is left NULL.
--
--   2. CANCEL what never left the building. A row that is still `pending` or
--      `deferred`, has `sent_at IS NULL`, `attempts = 0` and is not locked
--      produced no external effect. If its provenance cannot be recovered the
--      migration explicitly cancels it (status = 'cancelled') — exactly the
--      "re-planned or explicitly cancelled" resolution migration 204
--      prescribes — and retires the `sales-sequence` tag to
--      `sales-sequence-unattributed` so the constraint's subject (a governed
--      sequence send) is truthfully empty. The row is KEPT: it is evidence
--      for the operator, it costs nothing, and it must not be deleted.
--
--   3. REFUSE on delivery history. A row that was sent, attempted
--      (`attempts > 0`), carries `sent_at`, or is `processing` may have
--      reached a recipient. Nothing in the database can invent provenance for
--      a real delivery, and silently re-tagging it would rewrite the audit
--      trail; deleting it is forbidden by the task and by prudence. So the
--      migration raises a clear error naming the remaining rows and the two
--      lawful resolutions (attach true, foreign-key-valid ids; or make the
--      tag truthful with an audited `sales-sequence-unattributed` statement
--      reviewed by an operator). An operator decision is required precisely
--      because the data cannot make it.
--
-- Deleting was not the answer for any case: even an undelivered row is
-- evidence of what the pre-fix code attempted, and a delivered row is the
-- only record that the message reached a human and may be the subject of a
-- bounce/complaint/GPDR request. The invariant is restored by telling the
-- truth about each row, never by shrinking the table.
--
-- On success the migration runs VALIDATE CONSTRAINT, which extends enforcement
-- of the four-column provenance from new rows to every historical row.
--
-- Mechanical note: `NOT VALID` still enforces every UPDATE, so 204's
-- constraint would reject the reconciliation UPDATEs themselves (a row that
-- is only partially recovered still violates the predicate). The constraint
-- is therefore dropped inside this migration's transaction and re-added
-- (NOT VALID) before validation — see step 0 for why the window is invisible
-- to concurrent writers and cannot survive a failure.
--
-- =============================================================================
-- Why this migration does NOT add an action-level CHECK on
-- `sales_actions.decision_id` (follow-up to migration 204's note):
--
-- Migration 204 deliberately omitted `CHECK (decision_id IS NOT NULL)` on
-- `sales_actions`, because `send_step` work is queued at enrollment time and
-- the Decision Packet is computed at execution time. Re-checking the CURRENT
-- code confirms the reasoning and shows the narrower "terminal-success must
-- carry a decision" variant is ALSO unsatisfiable:
--
--   * `enrollments::start_outreach` still enqueues send_step actions at
--     enrollment time, before any decision exists.
--   * `sequence_worker::handle_inner` computes the packet only at execution
--     time, then enqueues the email (`decision_engine::decide` →
--     `enqueue_sequenced(.., decision.decision_id, ..)`).
--   * Every early-skip branch records a skip and RETURNS SUCCESS with no
--     packet at all: `skip()` sets `sales_step_executions.state='skipped'`
--     and returns `ActionOutcome::Succeeded` (sequence_worker.rs:1178-1193),
--     which `outcome_state` maps to `sales_actions.state='succeeded'`
--     (actions.rs:207-214). The branches are: non-email step kind, global
--     kill switch, autonomy mode that does not permit execution, human reply,
--     enrollment not sendable, next-best-action not an external send, no
--     contact point, and template unavailable.
--
-- So `state='succeeded' AND decision_id IS NULL` is a NORMAL, CORRECT row
-- (the send was skipped for a legitimate reason; there is no external effect
-- to explain). A `CHECK ... NOT VALID` with that predicate would refuse the
-- correct code, which is exactly what migration 204 warned against. The
-- enforceable invariant remains the one at the point of no return:
-- `chk_sales_sequence_has_decision` on `email_queue` (validated below).
-- =============================================================================

-- ---------------------------------------------------------------------------
-- 0. Drop the constraint for the duration of the reconciliation.
--
--    `NOT VALID` still enforces every UPDATE: with 204's constraint in place,
--    an UPDATE that fills only SOME provenance columns would be rejected
--    because the resulting row still violates the predicate (the failure this
--    migration exists to fix would abort its own repair). The constraint is
--    re-added (NOT VALID) in step 3 and validated in step 4, so the
--    unprotected window is exactly this migration's transaction. sqlx applies
--    each migration in a transaction, and the DROP takes ACCESS EXCLUSIVE on
--    `email_queue`, so no writer can observe the window; if a later step
--    raises, the transaction rolls back and 204's constraint is still there.
-- ---------------------------------------------------------------------------
ALTER TABLE email_queue DROP CONSTRAINT IF EXISTS chk_sales_sequence_has_decision;

-- ---------------------------------------------------------------------------
-- 1a. Recover provenance from the linked `messages` row.
-- ---------------------------------------------------------------------------
UPDATE email_queue q
SET sales_decision_id        = COALESCE(q.sales_decision_id, m.sales_decision_id),
    sales_sender_identity_id = COALESCE(q.sales_sender_identity_id, m.sales_sender_identity_id),
    sales_step_execution_id  = COALESCE(q.sales_step_execution_id, m.sales_step_execution_id),
    sales_enrollment_id      = COALESCE(q.sales_enrollment_id, m.sales_enrollment_id),
    updated_at               = NOW()
FROM messages m
WHERE m.id = q.message_id
  AND 'sales-sequence' = ANY (q.tags)
  AND (
        q.sales_decision_id IS NULL
     OR q.sales_sender_identity_id IS NULL
     OR q.sales_step_execution_id IS NULL
     OR q.sales_enrollment_id IS NULL
  )
  AND (
        m.sales_decision_id IS NOT NULL
     OR m.sales_sender_identity_id IS NOT NULL
     OR m.sales_step_execution_id IS NOT NULL
     OR m.sales_enrollment_id IS NOT NULL
  );

-- ---------------------------------------------------------------------------
-- 1b. Recover remaining NULLs from the row's own metadata, but only values
--     that reference an EXISTING sales row. The regex guard keeps a malformed
--     JSON value from aborting the migration; the EXISTS guard keeps a stale
--     or unrelated id from being written as provenance.
-- ---------------------------------------------------------------------------
UPDATE email_queue q
SET sales_decision_id = COALESCE(
        q.sales_decision_id,
        CASE
            WHEN q.metadata->>'sales_decision_id' ~ '^[0-9a-fA-F-]{36}$'
             AND EXISTS (SELECT 1 FROM sales_decisions d
                          WHERE d.id = (q.metadata->>'sales_decision_id')::uuid)
            THEN (q.metadata->>'sales_decision_id')::uuid
        END,
        CASE
            WHEN q.metadata->>'decision_id' ~ '^[0-9a-fA-F-]{36}$'
             AND EXISTS (SELECT 1 FROM sales_decisions d
                          WHERE d.id = (q.metadata->>'decision_id')::uuid)
            THEN (q.metadata->>'decision_id')::uuid
        END
    ),
    sales_sender_identity_id = COALESCE(
        q.sales_sender_identity_id,
        CASE
            WHEN q.metadata->>'sales_sender_identity_id' ~ '^[0-9a-fA-F-]{36}$'
             AND EXISTS (SELECT 1 FROM sales_sender_identities s
                          WHERE s.id = (q.metadata->>'sales_sender_identity_id')::uuid)
            THEN (q.metadata->>'sales_sender_identity_id')::uuid
        END
    ),
    sales_step_execution_id = COALESCE(
        q.sales_step_execution_id,
        CASE
            WHEN q.metadata->>'sales_step_execution_id' ~ '^[0-9a-fA-F-]{36}$'
             AND EXISTS (SELECT 1 FROM sales_step_executions s
                          WHERE s.id = (q.metadata->>'sales_step_execution_id')::uuid)
            THEN (q.metadata->>'sales_step_execution_id')::uuid
        END
    ),
    sales_enrollment_id = COALESCE(
        q.sales_enrollment_id,
        CASE
            WHEN q.metadata->>'enrollment_id' ~ '^[0-9a-fA-F-]{36}$'
             AND EXISTS (SELECT 1 FROM sales_enrollments e
                          WHERE e.id = (q.metadata->>'enrollment_id')::uuid)
            THEN (q.metadata->>'enrollment_id')::uuid
        END
    ),
    updated_at = NOW()
WHERE 'sales-sequence' = ANY (q.tags)
  AND (
        q.sales_decision_id IS NULL
     OR q.sales_sender_identity_id IS NULL
     OR q.sales_step_execution_id IS NULL
     OR q.sales_enrollment_id IS NULL
  );

-- ---------------------------------------------------------------------------
-- 2. Rows with no external effect and no recoverable provenance: cancel and
--    retire the tag, keeping the row. `pending`/`deferred` rows are
--    explicitly cancelled; `failed`/`cancelled` rows with zero attempts are
--    already terminal, so only their tag becomes truthful. A locked row is
--    left to the refusal check (a live worker may be mid-send).
-- ---------------------------------------------------------------------------
UPDATE email_queue q
SET status = CASE WHEN q.status IN ('pending', 'deferred') THEN 'cancelled' ELSE q.status END,
    last_error = COALESCE(
        q.last_error,
        'migration 222: pre-fix sales-sequence row had no recoverable Decision Packet provenance; cancelled without sending'
    ),
    metadata = q.metadata || jsonb_build_object(
        'migration_222',
        jsonb_build_object(
            'action', 'cancelled-unattributed',
            'reason', 'no recoverable sales provenance (messages row and metadata both lack the ids)',
            'at', NOW()
        )
    ),
    tags = CASE
        WHEN 'sales-sequence-unattributed' = ANY (array_remove(q.tags, 'sales-sequence'))
        THEN array_remove(q.tags, 'sales-sequence')
        ELSE array_append(
                 array_remove(q.tags, 'sales-sequence'),
                 'sales-sequence-unattributed'::text
             )
    END,
    updated_at = NOW()
WHERE 'sales-sequence' = ANY (q.tags)
  AND (
        q.sales_decision_id IS NULL
     OR q.sales_sender_identity_id IS NULL
     OR q.sales_step_execution_id IS NULL
     OR q.sales_enrollment_id IS NULL
  )
  AND q.sent_at IS NULL
  AND q.attempts = 0
  AND q.status IN ('pending', 'deferred', 'failed', 'cancelled')
  AND (q.locked_until IS NULL OR q.locked_until < NOW());

-- ---------------------------------------------------------------------------
-- 3. Restore the invariant (NOT VALID, exactly 204's definition) before the
--    refusal check, so no failure path can leave the table unprotected: if
--    the check below raises, the constraint is back and only the historical
--    rows remain grandfathered.
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'chk_sales_sequence_has_decision'
          AND conrelid = 'email_queue'::regclass
    ) THEN
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
    END IF;
END
$$;

-- ---------------------------------------------------------------------------
-- 4. Refuse on anything left that may carry delivery history. No deletion, no
--    silent re-tagging: the operator must choose between true provenance and
--    a truthful tag.
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    remaining BIGINT;
    per_status TEXT;
BEGIN
    SELECT COUNT(*)
      INTO remaining
      FROM email_queue
     WHERE 'sales-sequence' = ANY (tags)
       AND (
            sales_decision_id IS NULL
         OR sales_sender_identity_id IS NULL
         OR sales_step_execution_id IS NULL
         OR sales_enrollment_id IS NULL
       );

    IF remaining > 0 THEN
        SELECT string_agg(format('%s: %s', status, n), ', ' ORDER BY status)
          INTO per_status
          FROM (
                SELECT status, COUNT(*) AS n
                  FROM email_queue
                 WHERE 'sales-sequence' = ANY (tags)
                   AND (
                        sales_decision_id IS NULL
                     OR sales_sender_identity_id IS NULL
                     OR sales_step_execution_id IS NULL
                     OR sales_enrollment_id IS NULL
                   )
                 GROUP BY status
               ) counted;

        RAISE EXCEPTION USING
            MESSAGE = format(
                'migration 222: %s sales-sequence email_queue row(s) still lack full Decision Packet '
                'provenance and may carry delivery history (%s). They were NOT deleted and NOT '
                're-tagged: either would falsify or destroy the delivery audit trail.',
                remaining, per_status
            ),
            HINT = 'Resolve them, then re-run: (1) if the true provenance exists in an external audit '
                   'trail, set the four sales_* columns to those foreign-key-valid ids; (2) otherwise '
                   'make the tag truthful with an audited statement, e.g. '
                   'UPDATE email_queue SET tags = array_append(array_remove(tags, ''sales-sequence''), '
                   '''sales-sequence-unattributed''::text) WHERE id = ...; '
                   'the validated invariant then covers every genuinely governed sequence send.';
    END IF;
END
$$;

-- ---------------------------------------------------------------------------
-- 5. Validate: from here on the provenance requirement is enforced against
--    every row, historical and new.
-- ---------------------------------------------------------------------------
ALTER TABLE email_queue VALIDATE CONSTRAINT chk_sales_sequence_has_decision;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'chk_sales_sequence_has_decision'
          AND conrelid = 'email_queue'::regclass
          AND convalidated
    ) THEN
        RAISE EXCEPTION
            'migration 222: chk_sales_sequence_has_decision is still NOT VALID after VALIDATE CONSTRAINT';
    END IF;
END
$$;

-- ---------------------------------------------------------------------------
-- 6. Document on the action table why the action-level CHECK remains absent
--    (see the header; re-stated here so a reader of the column comment cannot
--    reintroduce a constraint the correct code cannot pass).
-- ---------------------------------------------------------------------------
COMMENT ON COLUMN sales_actions.decision_id IS
    'The Decision Packet that authorized this action. NULL is correct for a queued send_step '
    '(the packet is computed at execution time) and for a terminal-success skip: the '
    'execution-time gates (kill switch, autonomy mode, human reply, unsendable enrollment, '
    'next-best-action not an external send, no contact point/template) record '
    'sales_step_executions.state=''skipped'' and return ActionOutcome::Succeeded without a '
    'packet, because no external effect was produced to explain (sequence_worker.rs skip()). '
    'A CHECK requiring decision_id on state=''succeeded'' is therefore unsatisfiable by the '
    'correct code and is deliberately absent. The enforceable invariant is at the point of '
    'no return: chk_sales_sequence_has_decision on email_queue (validated by migration 222).';
