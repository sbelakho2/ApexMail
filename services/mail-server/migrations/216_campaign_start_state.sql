-- Migration 216: Resumable campaign start operation state
--
-- (Numbered 216 because concurrent work claimed 213-215 while this change was
-- in flight; sqlx requires globally unique migration versions.)
--
-- =============================================================================
-- `start_campaign` used to commit `status = 'active'` FIRST and only then
-- materialize the compatibility sequence/contacts/enrollments. A failure after
-- that commit left the campaign active with nothing enrolled, and a normal
-- retry was refused with "cannot start campaign in status active" — an active
-- campaign stranded with no way forward.
--
-- The start is now a durable, resumable operation layered over the legacy
-- `sales_campaigns.status` column (whose draft/active/paused/completed
-- vocabulary stays untouched for the control plane):
--
--   * `start_state = 'starting'` — an operation with `start_operation_id` has
--     been admitted and its enrollment materialization is in flight. The
--     campaign is NOT active. A failure or process crash leaves this state in
--     place, and the next start call RESUMES the SAME operation id
--     (sequence/contact/enrollment materialization is idempotent).
--   * `start_state = 'verification_pending'` — enrollment completed but
--     accepted zero contacts that can actually be sent to. The campaign is NOT
--     active (it would otherwise advertise an active campaign whose every
--     recipient was rejected). `last_error` carries the operator-readable
--     reason; a later retry resumes the same operation once contacts are
--     verified.
--   * `start_state IS NULL` — no operation pending. On success the campaign is
--     `status = 'active'` and `start_operation_id` is retained as the audit id
--     of the operation that activated it.
--
-- The tenant-scoped max-active check uses `pg_advisory_xact_lock(hashtext(
-- tenant_id))` in the application, and an in-flight `'starting'` row counts as
-- a reserved active slot, so two concurrent starts with one remaining slot
-- cannot both activate.
-- =============================================================================

ALTER TABLE sales_campaigns
    ADD COLUMN IF NOT EXISTS start_state TEXT;
ALTER TABLE sales_campaigns
    ADD COLUMN IF NOT EXISTS start_operation_id UUID;

-- The vocabulary is closed: anything else is a bug, not a state.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'sales_campaigns_start_state_check'
    ) THEN
        ALTER TABLE sales_campaigns
            ADD CONSTRAINT sales_campaigns_start_state_check
            CHECK (start_state IS NULL
                   OR start_state IN ('starting', 'verification_pending'));
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'sales_campaigns_start_operation_check'
    ) THEN
        ALTER TABLE sales_campaigns
            ADD CONSTRAINT sales_campaigns_start_operation_check
            CHECK (start_state IS NULL OR start_operation_id IS NOT NULL);
    END IF;
END
$$;

-- The admission query counts active + reserved (`starting`) slots for a tenant;
-- the partial index keeps that count cheap.
CREATE INDEX IF NOT EXISTS idx_sales_campaigns_start_reservation
    ON sales_campaigns (tenant_id)
    WHERE status = 'active' OR start_state = 'starting';

COMMENT ON COLUMN sales_campaigns.start_state IS
    'Durable phase of a resumable start operation: ''starting'' (admitted, materializing, resumable) or ''verification_pending'' (completed with zero accepted recipients, not active). NULL = no pending operation.';
COMMENT ON COLUMN sales_campaigns.start_operation_id IS
    'Stable id of the campaign start operation. Set once at admission, reused by every retry/resume (including from verification_pending), retained after activation as the audit id.';
