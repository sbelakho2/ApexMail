-- Migration 262: performance indexes for the hot claim/read paths.
--
-- The 2026-10 performance campaign removed N+1 loops and O(n²) scans in the
-- worker processors, API read paths, mailstore, tracking service and
-- compliance sweeps. The rewritten SQL is shaped against specific indexes;
-- this migration ships them. Every index below is the exact key the sibling
-- Rust code documents (and, where a plan assertion exists, EXPLAIN-verified
-- against):
--
--   1. webhook_queue (status, created_at) WHERE status = 'pending' — the
--      webhook claim orders by created_at; the pre-existing (status,
--      next_attempt_at) partial cannot serve that order and forced a Sort of
--      the whole pending queue per claim.
--   2. email_queue (priority DESC, created_at ASC) WHERE status IN
--      ('pending', 'processing') — the email claim's OR-shaped status
--      predicate plus its order; the leading-status claim lane from 241
--      cannot provide the order (Sort of every matching row).
--   3. suppressions / subscription_preferences (tenant_id, lower(email)) —
--      dispatch-time consent probes read the lowercased address for an
--      exact tenant; the existing unique keys are on the raw spelling.
--   4. events (tenant_id, timestamp DESC) — the keyset pagination lane.
--   5. events (tenant_id, campaign_id) — per-campaign stat rollups.
--   6. consent_records (granted, expires_at) WHERE granted AND expires_at
--      IS NOT NULL — the expiry sweep only ever visits live consents.
--   7. inbound_messages (received_at) WHERE classification IS NULL AND
--      from_email IS NOT NULL — the reply-ingest lane's pending rows.
--   8. mail_messages (mailbox_id) WHERE NOT is_read AND NOT is_deleted —
--      the unread counts filter on mailbox_id; the 050 index is keyed on
--      account_id and cannot serve them.
--   9. metering_events (event_type, (metadata->>'source'), tenant_id) and
--      (event_type, timestamp) — storage reconciliation reads by source and
--      the day window reads by event type; both were full partition scans.
--  10. invoices (status, paid_at) — the receivables/dunning sweep.
--  11. mail_messages GIN on text_body — the RFC 3501 SEARCH BODY scope.
--
-- Removed (dead or strict-prefix-redundant; details in section 12):
--   events: idx_events_message, idx_events_timestamp, idx_events_tenant
--   mail_messages: idx_mail_messages_search_simple,
--                  idx_mail_messages_labels_gin, idx_mail_messages_mailbox,
--                  idx_mail_messages_account_id, idx_mail_messages_mailbox_id
--   invoices: idx_invoices_tenant
--   suppressions: idx_suppressions_tenant
--   subscription_preferences: idx_sub_prefs_tenant_email
-- Prefix scans of the longer index serve every query the short one served.
--
-- Additive/idempotent (IF NOT EXISTS / IF EXISTS; no DML). Plain CREATE
-- INDEX (not CONCURRENTLY) because migrations run inside a transaction.

-- ---------------------------------------------------------------------------
-- 1. webhook_queue: the pending claim's ordering lane.
-- ---------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_webhook_queue_pending_created
    ON webhook_queue (status, created_at)
    WHERE status = 'pending';

-- ---------------------------------------------------------------------------
-- 2. email_queue: the claim's priority/age lane (partitioned parent; the
--    index recurses to every partition).
-- ---------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_email_queue_claim_order
    ON email_queue (priority DESC, created_at ASC)
    WHERE status IN ('pending', 'processing');

-- ---------------------------------------------------------------------------
-- 3. Consent probes by lowercased address.
-- ---------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_suppressions_tenant_email_lower
    ON suppressions (tenant_id, lower(email));

CREATE INDEX IF NOT EXISTS idx_sub_prefs_tenant_email_lower
    ON subscription_preferences (tenant_id, lower(email));

-- ---------------------------------------------------------------------------
-- 4/5. events: keyset read lane + per-campaign rollups.
-- ---------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_events_tenant_ts
    ON events (tenant_id, "timestamp" DESC);

CREATE INDEX IF NOT EXISTS idx_events_tenant_campaign
    ON events (tenant_id, campaign_id);

-- ---------------------------------------------------------------------------
-- 6. consent_records: live-consent expiry sweep.
-- ---------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_consent_records_expiry
    ON consent_records (granted, expires_at)
    WHERE granted = true AND expires_at IS NOT NULL;

-- ---------------------------------------------------------------------------
-- 7. inbound_messages: pending reply-ingest lane.
-- ---------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_inbound_messages_reply_pending
    ON inbound_messages (received_at)
    WHERE classification IS NULL AND from_email IS NOT NULL;

-- ---------------------------------------------------------------------------
-- 8. mail_messages: unread counts by mailbox (partitioned parent).
-- ---------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_mail_messages_mailbox_unread
    ON mail_messages (mailbox_id)
    WHERE NOT is_read AND NOT is_deleted;

-- ---------------------------------------------------------------------------
-- 9. metering_events: storage reconciliation + day windows (partitioned
--    parent; expression index follows to every partition).
-- ---------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_metering_events_source_tenant
    ON metering_events (event_type, (metadata->>'source'), tenant_id);

CREATE INDEX IF NOT EXISTS idx_metering_events_event_type_ts
    ON metering_events (event_type, "timestamp");

-- ---------------------------------------------------------------------------
-- 10. invoices: the receivables/dunning sweep.
-- ---------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_invoices_status_paid_at
    ON invoices (status, paid_at);

-- ---------------------------------------------------------------------------
-- 11. mail_messages: IMAP SEARCH BODY scope (RFC 3501 §6.4.4).
--
-- TEXT / free-form search uses the 050 combined GIN index (subject + body +
-- sender). BODY must match text_body ONLY, so it gets its own expression
-- index; the query in `mailstore-core` uses this exact expression.
-- ---------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_mail_messages_body_search
    ON mail_messages USING GIN (to_tsvector('english', COALESCE(text_body, '')));

-- ---------------------------------------------------------------------------
-- 12. Dead / strictly redundant indexes removed.
--
-- Each entry below is either never referenced by any query in the repo or a
-- strict prefix of a longer index that serves every scan the short one could:
--
--   idx_mail_messages_search_simple — no query builds `to_tsvector('simple',
--       ...)` anywhere in the repo; it was pure GIN write cost on the hottest
--       table (every stored message).
--   idx_mail_messages_labels_gin — no query uses JSONB/array containment on
--       `labels` (keyword STORE writes them; nothing searches them).
--   idx_mail_messages_mailbox — IDENTICAL to idx_mail_messages_account_mailbox
--       (account_id, mailbox_id, date DESC), created by 050 and re-created
--       under the new name by 109.
--   idx_mail_messages_account_id — strict prefix of account_mailbox.
--   idx_mail_messages_mailbox_id — strict prefix of the UNIQUE
--       idx_mail_messages_mailbox_uid (mailbox_id, uid, created_at).
--   idx_invoices_tenant — strict prefix of idx_invoices_tenant_issued.
--   idx_suppressions_tenant — strict prefix of the new
--       (tenant_id, lower(email)) index in section 3.
--   idx_sub_prefs_tenant_email — strict prefix of the UNIQUE
--       (tenant_id, email, category) constraint index.
--
-- Prefix scans of the longer index serve every query the short one served, so
-- dropping these removes write amplification without removing a read path.
-- ---------------------------------------------------------------------------
DROP INDEX IF EXISTS idx_events_message;
DROP INDEX IF EXISTS idx_events_timestamp;
DROP INDEX IF EXISTS idx_events_tenant;
DROP INDEX IF EXISTS idx_mail_messages_search_simple;
DROP INDEX IF EXISTS idx_mail_messages_labels_gin;
DROP INDEX IF EXISTS idx_mail_messages_mailbox;
DROP INDEX IF EXISTS idx_mail_messages_account_id;
DROP INDEX IF EXISTS idx_mail_messages_mailbox_id;
DROP INDEX IF EXISTS idx_invoices_tenant;
DROP INDEX IF EXISTS idx_suppressions_tenant;
DROP INDEX IF EXISTS idx_sub_prefs_tenant_email;
