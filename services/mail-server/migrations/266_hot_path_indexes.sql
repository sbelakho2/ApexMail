-- Migration 266: the remaining hot-path indexes (performance audit 2026-10-18).
--
-- Every index below backs a query that runs on a request/send/worker hot
-- path and had NO usable index (the planner fell back to a sequential scan
-- or a full sort). They are additive; the 262/263 duplicate-drop lists were
-- checked so none recreates a dropped index or duplicates a live one.
--
--   1. consent_records / double_opt_in_tokens / suppression_list — the
--      marketing consent probe lowercases the address in its predicate
--      (`lower(email) = $2`), which the existing (tenant_id, email) indexes
--      cannot serve. consent_records already has (tenant_id, email); the
--      expression form is the one the enforcer actually uses.
--   2. email_queue(message_id) — cancel, message timeline, bounce and FBL
--      lookups all filter by message_id; no index on the parent existed, so
--      every lookup scanned every monthly partition. Partial on NOT NULL
--      (rows without a message id are never looked up this way).
--   3. campaign_recipients claim — the drain query orders by
--      (campaign_id, created_at, id) with a status/phase predicate and
--      FOR UPDATE SKIP LOCKED; the existing (campaign_id, status) index
--      cannot provide the order, so each tick sorted the whole queued set.
--   4. contacts keyset + tags — the list orders by (created_at, id) and
--      filters tags with `@>`; both were unindexed (GIN default jsonb_ops
--      serves @>, ?& and ?| — jsonb_path_ops would not serve ?&/?|).
--   5. campaigns keyset — the campaigns list orders by (created_at, id).
--   6. users (tenant_id, email) — SCIM lists ORDER BY email per tenant.
--   7. events — the GDPR export filters lower(recipient); the send-time
--      optimizer groups by recipient/event_type over a tenant. Both scans
--      were unindexed.
--   8. suppressions (tenant_id, created_at DESC) — the suppression list
--      page sorts the tenant's rows newest-first.
--
-- Idempotent by construction (CREATE INDEX IF NOT EXISTS, no DML).

CREATE INDEX IF NOT EXISTS idx_consent_records_tenant_email_lower
    ON consent_records (tenant_id, lower(email), consent_type, granted_at DESC);

CREATE INDEX IF NOT EXISTS idx_doi_tenant_email_lower
    ON double_opt_in_tokens (tenant_id, lower(email));

CREATE INDEX IF NOT EXISTS idx_suppression_list_tenant_email_lower
    ON suppression_list (tenant_id, lower(email));

CREATE INDEX IF NOT EXISTS idx_email_queue_message_id
    ON email_queue (message_id)
    WHERE message_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_campaign_recipients_claim
    ON campaign_recipients (campaign_id, created_at, id)
    WHERE status IN ('queued', 'sending')
      AND (phase IS NULL OR phase IN ('test', 'winner'));

CREATE INDEX IF NOT EXISTS idx_contacts_tenant_created_id
    ON contacts (tenant_id, created_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_contacts_tags_gin
    ON contacts USING GIN (tags);

CREATE INDEX IF NOT EXISTS idx_campaigns_tenant_created_id
    ON campaigns (tenant_id, created_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_users_tenant_email
    ON users (tenant_id, email);

CREATE INDEX IF NOT EXISTS idx_events_tenant_recipient_lower_ts
    ON events (tenant_id, lower(recipient), "timestamp" DESC);

CREATE INDEX IF NOT EXISTS idx_events_tenant_recipient_type_ts
    ON events (tenant_id, recipient, event_type, "timestamp");

CREATE INDEX IF NOT EXISTS idx_suppressions_tenant_created
    ON suppressions (tenant_id, created_at DESC);
