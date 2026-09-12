-- 210_inbound_delivery_ledger.sql
--
-- =============================================================================
-- Durable inbound recipient ledger for accept-then-deliver semantics.
-- =============================================================================
-- Finding (P0): the inbound SMTP server issued the final `250` after writing
-- only `inbound_messages`; the per-recipient mailbox delivery happened
-- afterwards as a best-effort inline step. A recipient without a mailstore
-- account was logged at DEBUG and silently skipped, and a persistent
-- mailstore failure stranded the message with nothing but an ERROR log — an
-- accept-then-drop failure with no durable DSN compensation.
--
-- This migration adds the durable recipient-level ledger the retry worker
-- (`crates/mta/src/servers/inbound_delivery.rs`) drives:
--
--   * `inbound_recipients` — one row per (message, envelope recipient).
--     Written in the SAME transaction as `inbound_messages` and BEFORE the
--     SMTP `250`, so an accepted message can never lose a recipient silently.
--   * `inbound_delivery_attempts` — append-only per-attempt history for
--     audit/observability (which stage failed, how, when).
--
-- Status vocabulary for `inbound_recipients.status`:
--   pending       — committed with the message, no delivery attempt yet
--   delivering    — claimed by a worker (lease = next_attempt_at); a crash
--                   leaves the row reclaimable when the lease expires
--   deferred      — transient failure; retry at next_attempt_at
--   delivered     — terminal success; delivered_at set
--   failed        — permanent failure; a DSN is outstanding/being dispatched
--   dsn_sent      — terminal: RFC 3464 DSN durably handed to the outbound
--                   pipeline (dsn_generated_at set)
--   undeliverable — terminal: permanent failure with a NULL return path, so
--                   no DSN may be generated (RFC 5321 §4.5.5 / RFC 3464)
--
-- `mailbox_id` is the mailstore account id (`mail_accounts.id`, the same
-- UUID the MailstoreService GetAccount/StoreMessage RPCs take), resolved at
-- RCPT time. It is NULL only for rows written by older deployments or for
-- VERP recipients (which are replies handed to the bounce/reply-handler
-- path, not mailbox deliveries) — the worker can still re-resolve by email.
--
-- Idempotent: safe to re-run.
-- =============================================================================

CREATE TABLE IF NOT EXISTS inbound_recipients (
    message_id       VARCHAR(26) NOT NULL,
    recipient        TEXT        NOT NULL,
    -- mail_accounts.id (UUID) as text: the mailstore account the recipient
    -- resolved to at RCPT time. NULL = not resolved / VERP hand-off.
    mailbox_id       TEXT,
    status           TEXT        NOT NULL DEFAULT 'pending',
    -- Attempts already performed (0 = none yet).
    attempt          INTEGER     NOT NULL DEFAULT 0,
    -- Both the retry deadline for deferred rows and the delivery lease for
    -- claimed ('delivering') rows — an expired lease makes the row due
    -- again, which is how a crashed worker's claim is recovered.
    next_attempt_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    delivered_at     TIMESTAMPTZ,
    dsn_generated_at TIMESTAMPTZ,
    last_error       TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT inbound_recipients_pkey PRIMARY KEY (message_id, recipient),
    CONSTRAINT fk_inbound_recipients_message
        FOREIGN KEY (message_id) REFERENCES inbound_messages(id) ON DELETE CASCADE,
    CONSTRAINT chk_inbound_recipients_status CHECK (status IN (
        'pending', 'delivering', 'deferred', 'delivered',
        'failed', 'dsn_sent', 'undeliverable'
    )),
    CONSTRAINT chk_inbound_recipients_attempt CHECK (attempt >= 0)
);

-- The retry sweep's claim predicate: due rows in a non-terminal state.
CREATE INDEX IF NOT EXISTS idx_inbound_recipients_due
    ON inbound_recipients (next_attempt_at)
    WHERE status IN ('pending', 'delivering', 'deferred', 'failed');

-- A failed row is a pending DSN dispatch (retried by the same sweep even
-- though mailbox delivery is over). `dsn_generated_at` may already be
-- stamped if a worker crashed mid-dispatch: the retry re-dispatches rather
-- than losing the DSN (at-least-once; terminal rows are status='dsn_sent').
CREATE INDEX IF NOT EXISTS idx_inbound_recipients_dsn_pending
    ON inbound_recipients (next_attempt_at)
    WHERE status = 'failed';

-- Per-message lookups (operations/replay: "what happened to this message?").
CREATE INDEX IF NOT EXISTS idx_inbound_recipients_message
    ON inbound_recipients (message_id);

COMMENT ON TABLE inbound_recipients IS
    'Durable per-recipient inbound delivery ledger. INSERTed in the same transaction as inbound_messages and before the SMTP 250; the delivery worker owns every state transition after that.';

-- =============================================================================
-- Per-attempt history
-- =============================================================================
-- Append-only: never updated or deleted by the worker (only tenant-wide
-- retention cleanup, which cascades from inbound_messages). `outcome` uses
-- the same vocabulary as the recipient status transitions; `stage` is
-- 'delivery' for mailbox delivery and 'dsn' for DSN dispatch.
CREATE TABLE IF NOT EXISTS inbound_delivery_attempts (
    id         BIGSERIAL   PRIMARY KEY,
    message_id VARCHAR(26) NOT NULL,
    recipient  TEXT        NOT NULL,
    -- Attempt ordinal (1 for the first delivery attempt, 2 for the second, …).
    attempt    INTEGER     NOT NULL,
    stage      TEXT        NOT NULL,
    outcome    TEXT        NOT NULL,
    error      TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT fk_inbound_delivery_attempts_recipient
        FOREIGN KEY (message_id, recipient)
        REFERENCES inbound_recipients (message_id, recipient) ON DELETE CASCADE,
    CONSTRAINT chk_inbound_delivery_attempts_stage
        CHECK (stage IN ('delivery', 'dsn')),
    CONSTRAINT chk_inbound_delivery_attempts_outcome
        CHECK (outcome IN ('delivered', 'transient', 'permanent')),
    CONSTRAINT chk_inbound_delivery_attempts_attempt CHECK (attempt >= 1)
);

CREATE INDEX IF NOT EXISTS idx_inbound_delivery_attempts_recipient
    ON inbound_delivery_attempts (message_id, recipient, created_at DESC);

COMMENT ON TABLE inbound_delivery_attempts IS
    'Append-only per-attempt history for inbound mailbox delivery and DSN dispatch; the durable audit trail behind inbound_recipients.last_error/status.';
