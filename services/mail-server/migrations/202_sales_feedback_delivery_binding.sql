-- Migration 202: Sales feedback and delivery binding
--
-- =============================================================================
-- The sequence dispatcher identified its outbound mail only in JSON metadata
-- (the `metadata` jsonb on `messages` and `email_queue`). That makes the
-- feedback loops that matter impossible to run reliably: to attribute a bounce
-- or a complaint to the sender identity that caused it, or a delivered reply
-- to the experiment arm that produced it, a consumer would have to
-- reverse-engineer metadata at delivery speed.
--
-- This migration adds typed provenance columns — real foreign keys with
-- partial indexes — plus the two event ledgers the feedback projectors read:
--
--   * `sales_sender_events`   — per-send delivery outcomes, so sender health
--                               aggregates are computed from one idempotent
--                               ledger instead of three separate callbacks.
--   * `sales_outcomes.reward_processed_at` — the claim marker for the
--                               experiment-reward projector.
--
-- It also persists the recipient mailbox provider at delivery time, where MX
-- resolution actually knows it, instead of inferring it later from a visible
-- domain (which misclassifies every hosted custom domain).
-- =============================================================================

-- ---------------------------------------------------------------------------
-- 1. Typed sales provenance on messages / email_queue
-- ---------------------------------------------------------------------------
ALTER TABLE messages
    ADD COLUMN IF NOT EXISTS sales_decision_id UUID,
    ADD COLUMN IF NOT EXISTS sales_sender_identity_id UUID,
    ADD COLUMN IF NOT EXISTS sales_step_execution_id UUID,
    ADD COLUMN IF NOT EXISTS sales_enrollment_id UUID;

ALTER TABLE email_queue
    ADD COLUMN IF NOT EXISTS sales_decision_id UUID,
    ADD COLUMN IF NOT EXISTS sales_sender_identity_id UUID,
    ADD COLUMN IF NOT EXISTS sales_step_execution_id UUID,
    ADD COLUMN IF NOT EXISTS sales_enrollment_id UUID;

-- Foreign keys. Guarded individually: `ON DELETE SET NULL` means deleting a
-- sales row must never cascade into deleting a delivered platform message
-- (that would destroy the delivery record the feedback loop depends on).
DO $$
BEGIN
    ALTER TABLE messages DROP CONSTRAINT IF EXISTS fk_messages_sales_decision;
    ALTER TABLE messages ADD CONSTRAINT fk_messages_sales_decision
        FOREIGN KEY (sales_decision_id) REFERENCES sales_decisions(id) ON DELETE SET NULL;

    ALTER TABLE messages DROP CONSTRAINT IF EXISTS fk_messages_sales_sender;
    ALTER TABLE messages ADD CONSTRAINT fk_messages_sales_sender
        FOREIGN KEY (sales_sender_identity_id) REFERENCES sales_sender_identities(id) ON DELETE SET NULL;

    ALTER TABLE messages DROP CONSTRAINT IF EXISTS fk_messages_sales_step;
    ALTER TABLE messages ADD CONSTRAINT fk_messages_sales_step
        FOREIGN KEY (sales_step_execution_id) REFERENCES sales_step_executions(id) ON DELETE SET NULL;

    ALTER TABLE messages DROP CONSTRAINT IF EXISTS fk_messages_sales_enrollment;
    ALTER TABLE messages ADD CONSTRAINT fk_messages_sales_enrollment
        FOREIGN KEY (sales_enrollment_id) REFERENCES sales_enrollments(id) ON DELETE SET NULL;
END
$$;

DO $$
BEGIN
    ALTER TABLE email_queue DROP CONSTRAINT IF EXISTS fk_email_queue_sales_decision;
    ALTER TABLE email_queue ADD CONSTRAINT fk_email_queue_sales_decision
        FOREIGN KEY (sales_decision_id) REFERENCES sales_decisions(id) ON DELETE SET NULL;

    ALTER TABLE email_queue DROP CONSTRAINT IF EXISTS fk_email_queue_sales_sender;
    ALTER TABLE email_queue ADD CONSTRAINT fk_email_queue_sales_sender
        FOREIGN KEY (sales_sender_identity_id) REFERENCES sales_sender_identities(id) ON DELETE SET NULL;

    ALTER TABLE email_queue DROP CONSTRAINT IF EXISTS fk_email_queue_sales_step;
    ALTER TABLE email_queue ADD CONSTRAINT fk_email_queue_sales_step
        FOREIGN KEY (sales_step_execution_id) REFERENCES sales_step_executions(id) ON DELETE SET NULL;

    ALTER TABLE email_queue DROP CONSTRAINT IF EXISTS fk_email_queue_sales_enrollment;
    ALTER TABLE email_queue ADD CONSTRAINT fk_email_queue_sales_enrollment
        FOREIGN KEY (sales_enrollment_id) REFERENCES sales_enrollments(id) ON DELETE SET NULL;
END
$$;

-- Partial indexes: the overwhelming majority of rows are not sales mail, so a
-- full index would be mostly nulls.
CREATE INDEX IF NOT EXISTS idx_email_queue_sales_decision
    ON email_queue (sales_decision_id) WHERE sales_decision_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_email_queue_sales_sender
    ON email_queue (sales_sender_identity_id) WHERE sales_sender_identity_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_email_queue_sales_step
    ON email_queue (sales_step_execution_id) WHERE sales_step_execution_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_email_queue_sales_enrollment
    ON email_queue (sales_enrollment_id) WHERE sales_enrollment_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_messages_sales_decision
    ON messages (sales_decision_id) WHERE sales_decision_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_messages_sales_step
    ON messages (sales_step_execution_id) WHERE sales_step_execution_id IS NOT NULL;

-- ---------------------------------------------------------------------------
-- 2. sales_sender_events — the sender-health event ledger
-- ---------------------------------------------------------------------------
-- Every delivery path that knows which sender identity produced a message
-- writes one row here; a single projector folds them into
-- `sales_sender_health`. The unique key makes a replayed provider callback a
-- no-op instead of double-counting a complaint against a sending domain.
CREATE TABLE IF NOT EXISTS sales_sender_events (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         TEXT NOT NULL,
    sender_identity_id UUID NOT NULL
        REFERENCES sales_sender_identities(id) ON DELETE CASCADE,
    event_type        TEXT NOT NULL
        CHECK (event_type IN (
            'delivered', 'hard_bounce', 'soft_bounce', 'complaint',
            'unsubscribe', 'deferral', 'auth_failure'
        )),
    message_id        TEXT,
    recipient         TEXT,
    occurred_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    processed_at      TIMESTAMPTZ,
    UNIQUE (sender_identity_id, event_type, message_id, recipient)
);

CREATE INDEX IF NOT EXISTS idx_sales_sender_events_unprocessed
    ON sales_sender_events (occurred_at)
    WHERE processed_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_sales_sender_events_sender
    ON sales_sender_events (sender_identity_id, occurred_at DESC);

-- ---------------------------------------------------------------------------
-- 3. sales_outcomes — reward projection claim marker
-- ---------------------------------------------------------------------------
-- The experiment reward loop is only real if normal production outcomes reach
-- it. This column lets one projector claim each outcome exactly once.
ALTER TABLE sales_outcomes
    ADD COLUMN IF NOT EXISTS reward_processed_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_sales_outcomes_reward_pending
    ON sales_outcomes (occurred_at)
    WHERE reward_processed_at IS NULL AND step_execution_id IS NOT NULL;

-- ---------------------------------------------------------------------------
-- 4. Recipient mailbox provider, persisted where it is actually known
-- ---------------------------------------------------------------------------
-- `provider_source` records how the value was obtained, so a consumer can tell
-- an MX-derived fact from a guess. Inferring "Google Workspace" from a visible
-- recipient domain is exactly the mistake this distinction prevents: a custom
-- domain hosted on Google is indistinguishable from a self-hosted one without
-- the MX record.
ALTER TABLE events
    ADD COLUMN IF NOT EXISTS recipient_provider TEXT,
    ADD COLUMN IF NOT EXISTS provider_source TEXT;

DO $$
BEGIN
    ALTER TABLE events DROP CONSTRAINT IF EXISTS chk_events_provider_source;
    ALTER TABLE events ADD CONSTRAINT chk_events_provider_source
        CHECK (
            provider_source IS NULL
            OR provider_source IN ('mx_resolved', 'provider_callback', 'inferred')
        );
END
$$;

CREATE INDEX IF NOT EXISTS idx_events_recipient_provider
    ON events (recipient_provider, timestamp DESC)
    WHERE recipient_provider IS NOT NULL;
