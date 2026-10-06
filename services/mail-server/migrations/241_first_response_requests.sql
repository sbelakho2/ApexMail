-- Migration 241: first-response requests (SalesCloser plan §5.4)
--
-- The "instant response" rail: when a lead arrives (contact form today;
-- inbound sales mail and chat leads via the same table), a first-response
-- request row is written in the SAME transaction as the lead itself, and the
-- mailbot claims it to produce a grounded, draft-only reply that reaches the
-- review queue on the priority lane.
--
-- * first_response_requests — one row per inbound lead. `kind` names the
--   source, `subject_ref` the canonical row it describes (contact id,
--   inbound message id, chat session id), `payload` the submission fields
--   the draft may use. `state` moves pending -> drafted | declined | skipped
--   (the mailbot's terminals; a human approval is the next step, not a
--   state here).
-- * `due_at` + `ai_claimed_at` mirror the inbound-messages claim contract:
--   a stale claim (15 minutes) is re-claimable, so a crashed worker cannot
--   strand a lead.
-- * The unique key on (tenant_id, kind, subject_ref) makes a double-submitted
--   form collapse onto one request instead of drafting twice.
--
-- NOTE on numbering: the gap analysis wrote this as "234"; 234-240 are taken
-- by the auth/campaign waves and the console-assistant migration.

CREATE TABLE IF NOT EXISTS first_response_requests (
    id             VARCHAR(26) PRIMARY KEY,
    tenant_id      VARCHAR(26) NOT NULL,
    kind           VARCHAR(16) NOT NULL CHECK (kind IN ('contact_form', 'inbound_email', 'chat_lead')),
    subject_ref    TEXT NOT NULL,
    payload        JSONB NOT NULL DEFAULT '{}'::jsonb,
    state          VARCHAR(16) NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'drafted', 'declined', 'skipped')),
    due_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ai_claimed_at  TIMESTAMPTZ,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, kind, subject_ref)
);

CREATE INDEX IF NOT EXISTS idx_first_response_pending
    ON first_response_requests (state, due_at);

CREATE INDEX IF NOT EXISTS idx_first_response_tenant
    ON first_response_requests (tenant_id, created_at DESC);

-- The claim lane the worker's email processor scans orders by
-- `priority DESC, created_at ASC` over pending/expired-lease rows; the
-- existing indexes key on next_retry_at, so the planner had no lane-ordered
-- access path for the first-response priority (100 over the default 5).
CREATE INDEX IF NOT EXISTS idx_email_queue_claim_lane
    ON email_queue (status, priority DESC, created_at)
    WHERE status IN ('pending', 'processing');
