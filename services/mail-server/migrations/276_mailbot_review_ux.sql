-- Migration 276: Mailbot review UX backend (sixth external audit, item 7).
--
-- The tenant-owned review surface (/v1/ai/drafts) shares the operator
-- approval core but the draft row could not represent the review lifecycle
-- the audit demands: regeneration versions (old superseded, NEVER deleted),
-- tenant escalation to the operator queue, and the Edit & Send telemetry.
-- This migration adds the missing columns to inbound_messages:
--
--   draft_version     — 1 for the mailbot's original draft, +1 for every
--                       regenerated version (POST /v1/ai/drafts/:id/regenerate
--                       creates a NEW row and supersedes the old one).
--   superseded_by     — the NEW draft's id on the superseded row; NULL on
--                       every live draft. History is preserved: a superseded
--                       row is only retired (pending_approval = false), never
--                       deleted, so the approval/audit trail stays answerable.
--   escalated_at      — when the tenant escalated the draft for operator
--                       attention (NULL = never). Escalation is a flag on a
--                       still-pending draft, not a terminal decision: the
--                       draft remains approvable/rejectable on both surfaces.
--   escalated_by      — the escalator identity (user id, or the API key id
--                       for a machine credential).
--   escalation_reason — the optional STRUCTURED reason the reviewer sent
--                       with the escalation (JSONB object).
--
-- Edit & Send telemetry (edited flag + char edit distance) rides the
-- approval audit rows (audit_logs.details), which already commit atomically
-- with the decision; no additional column is needed for it.
--
-- Idempotent: every statement is existence-guarded, safe to re-run on any
-- deployment (the repo's migration convention).
-- =============================================================================

ALTER TABLE inbound_messages
    ADD COLUMN IF NOT EXISTS draft_version INTEGER NOT NULL DEFAULT 1;
ALTER TABLE inbound_messages
    ADD COLUMN IF NOT EXISTS superseded_by VARCHAR(26);
ALTER TABLE inbound_messages
    ADD COLUMN IF NOT EXISTS escalated_at TIMESTAMPTZ;
ALTER TABLE inbound_messages
    ADD COLUMN IF NOT EXISTS escalated_by VARCHAR(255);
ALTER TABLE inbound_messages
    ADD COLUMN IF NOT EXISTS escalation_reason JSONB;

-- The operator review queue surfaces escalated drafts FIRST and supports an
-- escalated-only filter; both read this partial index.
CREATE INDEX IF NOT EXISTS idx_inbound_escalated_pending
    ON inbound_messages (escalated_at, received_at)
    WHERE escalated_at IS NOT NULL AND pending_approval = true;

-- Version lineage lookups (which draft superseded which).
CREATE INDEX IF NOT EXISTS idx_inbound_superseded_by
    ON inbound_messages (superseded_by)
    WHERE superseded_by IS NOT NULL;

COMMENT ON COLUMN inbound_messages.draft_version IS
    'Mailbot draft version: 1 for the original generated draft, +1 per regeneration. A regeneration creates a NEW row and marks the old one superseded (never deleted).';
COMMENT ON COLUMN inbound_messages.superseded_by IS
    'The id of the draft row that superseded this one (regeneration lineage). NULL on every live draft.';
COMMENT ON COLUMN inbound_messages.escalated_at IS
    'When the tenant escalated this still-pending draft to the operator queue. NULL = not escalated. Escalation does not consume the draft.';
COMMENT ON COLUMN inbound_messages.escalated_by IS
    'The escalator identity: the acting user id, or the API key id for a machine credential.';
COMMENT ON COLUMN inbound_messages.escalation_reason IS
    'The optional structured escalation reason supplied by the reviewer (JSONB object), recorded verbatim in the escalation audit entry too.';
