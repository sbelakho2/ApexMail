-- Migration 088: Unify email queue inbound schema
--
-- =============================================================================
-- SPLIT-BRAIN RESOLUTION: email_queue / inbound_messages / queue consumers
-- =============================================================================
-- The mail pipeline had two conflicting schema definitions:
--
--   * services/mail-server/migrations/  (applied by docker-compose initdb at
--     services/mail-server/docker-compose.yml:216) — email_queue with
--     id UUID, from_address/to_addresses, text_body/html_body, attempts;
--     inbound_messages with from_email/to_email/body_text/body_html/...
--   * tools/migrations/                 — email_queue with id VARCHAR(26),
--     "from"/"to"/html/text/tags/attempt/locked_until; inbound_messages with
--     mail_from/rcpt_to/raw_message/spf_result/...
--
-- Production converged on the services/mail-server tree but only PARTIALLY:
-- email_queue carries BOTH column families (uuid id + from_address family +
-- tree-2 worker family), while inbound_messages has a third shape that matches
-- neither the MTA inbound writer nor the worker reply-handler.
--
-- This migration completes the convergence to ONE canonical schema that every
-- producer and consumer writes/reads:
--
--   email_queue      = partitioned table, uuid ids, BOTH column families,
--                      plus error_message / smtp_message_id and a status CHECK
--                      that admits the worker's 'bounced'/'suppressed' states.
--   inbound_messages = superset serving the MTA inbound writer (mail_from,
--                      rcpt_to, client_ip, helo_hostname, raw_message,
--                      raw_size, auth_results, spf_result, disposition,
--                      is_verp_reply), the AI email agent (processed,
--                      processing, processed_at, ai_response, ai_tokens_used,
--                      pending_approval), and the worker reply-handler
--                      (tenant_id, lead_id, classification,
--                      classification_confidence, suggested_action,
--                      action_taken).
--   analytics_queue  = worker poll columns (processed/processing/...).
--   suppressions     = created (worker hard-bounce + reply-handler + API).
--   sales_leads      = reply-handler columns (snoozed_until, last_reply_at,
--                      priority).
--   email_dlq        = created (worker dead-letter queue).
--
-- Idempotent: safe to re-run on any deployment.
-- =============================================================================


-- =============================================================================
-- 1. email_queue — worker columns missing from the deployed schema
-- =============================================================================
-- The worker EmailProcessor writes these on send/failure paths; they were
-- never added by any migration, so delivery failed at runtime with
-- "column does not exist".
ALTER TABLE email_queue ADD COLUMN IF NOT EXISTS error_message TEXT;
ALTER TABLE email_queue ADD COLUMN IF NOT EXISTS smtp_message_id TEXT;

-- The worker transitions rows to 'bounced' and 'suppressed'; the original
-- CHECK (migration 050) only allowed pending/processing/sent/failed/
-- deferred/cancelled, so those updates were rejected.
ALTER TABLE email_queue DROP CONSTRAINT IF EXISTS chk_email_queue_status;
ALTER TABLE email_queue
    ADD CONSTRAINT chk_email_queue_status
    CHECK (status IN ('pending', 'processing', 'sent', 'failed', 'deferred',
                      'cancelled', 'bounced', 'suppressed'));

-- =============================================================================
-- 2. inbound_messages — canonical superset
-- =============================================================================
-- No canonical migration before this one created inbound_messages (the only
-- CREATE lives in the tools/initdb lineage). The ALTERs below were all
-- existence-guarded, so a fresh canonical chain simply never materialized
-- the table and the MTA inbound writer failed at runtime. Create the full
-- union shape unconditionally-if-missing; on databases that already have a
-- lineage shape this is a no-op and the guarded ALTERs reconcile columns.
-- The id is the MTA's `inb_<22 hex>` (26 chars). The legacy from_email/
-- to_email mirror pair is nullable here directly (migration 114 relaxed
-- deployed shapes for the same reason: the MTA writer never populates it).
CREATE TABLE IF NOT EXISTS inbound_messages (
    id                            VARCHAR(26) PRIMARY KEY,
    tenant_id                     VARCHAR(26),
    from_email                    VARCHAR(255),
    to_email                      VARCHAR(255),
    message_id_header             VARCHAR(255),
    subject                       VARCHAR(255),
    body_text                     TEXT,
    body_html                     TEXT,
    domain_id                     VARCHAR(64),
    mail_from                     TEXT,
    rcpt_to                       TEXT[],
    client_ip                     TEXT,
    helo_hostname                 TEXT,
    raw_message                   BYTEA,
    raw_size                      BIGINT,
    auth_results                  TEXT,
    spf_result                    TEXT,
    dkim_result                   VARCHAR(20),
    dmarc_result                  VARCHAR(20),
    disposition                   TEXT,
    is_verp_reply                 BOOLEAN NOT NULL DEFAULT false,
    lead_id                       VARCHAR(26),
    classification                TEXT,
    classification_confidence     DOUBLE PRECISION,
    suggested_action              JSONB,
    action_taken                  TEXT,
    processed                     BOOLEAN NOT NULL DEFAULT false,
    processing                    BOOLEAN NOT NULL DEFAULT false,
    processed_at                  TIMESTAMPTZ,
    ai_response                   TEXT,
    ai_tokens_used                INTEGER,
    pending_approval              BOOLEAN NOT NULL DEFAULT false,
    received_at                   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    headers                       JSONB,
    attachments                   JSONB,
    spam_score                    DECIMAL(5,2),
    spam_status                   VARCHAR(20),
    virus_status                  VARCHAR(20),
    session_id                    VARCHAR(50),
    created_at                    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_inbound_tenant ON inbound_messages (tenant_id);
CREATE INDEX IF NOT EXISTS idx_inbound_received ON inbound_messages (received_at);

-- MTA inbound writer (crates/mta/src/servers/inbound.rs)
DO $$
BEGIN
    IF to_regclass('public.inbound_messages') IS NOT NULL THEN
        ALTER TABLE inbound_messages ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(26);
        ALTER TABLE inbound_messages ADD COLUMN IF NOT EXISTS mail_from TEXT;
    END IF;
END
$$;

DO $$
BEGIN
    IF to_regclass('public.inbound_messages') IS NOT NULL THEN
        ALTER TABLE inbound_messages ADD COLUMN IF NOT EXISTS rcpt_to TEXT[];
        ALTER TABLE inbound_messages ADD COLUMN IF NOT EXISTS client_ip TEXT;
    END IF;
END
$$;

DO $$
BEGIN
    IF to_regclass('public.inbound_messages') IS NOT NULL THEN
        ALTER TABLE inbound_messages ADD COLUMN IF NOT EXISTS helo_hostname TEXT;
        ALTER TABLE inbound_messages ADD COLUMN IF NOT EXISTS raw_message BYTEA;
    END IF;
END
$$;

DO $$
BEGIN
    IF to_regclass('public.inbound_messages') IS NOT NULL THEN
        ALTER TABLE inbound_messages ADD COLUMN IF NOT EXISTS raw_size BIGINT;
        ALTER TABLE inbound_messages ADD COLUMN IF NOT EXISTS auth_results TEXT;
    END IF;
END
$$;

DO $$
BEGIN
    IF to_regclass('public.inbound_messages') IS NOT NULL THEN
        ALTER TABLE inbound_messages ADD COLUMN IF NOT EXISTS spf_result TEXT;
        ALTER TABLE inbound_messages ADD COLUMN IF NOT EXISTS disposition TEXT;
    END IF;
END
$$;

DO $$
BEGIN
    IF to_regclass('public.inbound_messages') IS NOT NULL THEN
        ALTER TABLE inbound_messages ADD COLUMN IF NOT EXISTS is_verp_reply BOOLEAN NOT NULL DEFAULT false;
        
        -- Worker reply-handler (crates/worker-processors/src/reply_handler)
        ALTER TABLE inbound_messages ADD COLUMN IF NOT EXISTS lead_id VARCHAR(26);
    END IF;
END
$$;

DO $$
BEGIN
    IF to_regclass('public.inbound_messages') IS NOT NULL THEN
        ALTER TABLE inbound_messages ADD COLUMN IF NOT EXISTS classification TEXT;
        ALTER TABLE inbound_messages ADD COLUMN IF NOT EXISTS classification_confidence DOUBLE PRECISION;
    END IF;
END
$$;

DO $$
BEGIN
    IF to_regclass('public.inbound_messages') IS NOT NULL THEN
        ALTER TABLE inbound_messages ADD COLUMN IF NOT EXISTS suggested_action JSONB;
        ALTER TABLE inbound_messages ADD COLUMN IF NOT EXISTS action_taken TEXT;
    END IF;
END
$$;


-- AI email agent (crates/ai-service/src/email_agent.rs)
DO $$
BEGIN
    IF to_regclass('public.inbound_messages') IS NOT NULL THEN
        ALTER TABLE inbound_messages ADD COLUMN IF NOT EXISTS pending_approval BOOLEAN NOT NULL DEFAULT false;
        
        -- Poll index shared by the reply-handler and the AI email agent.
        CREATE INDEX IF NOT EXISTS idx_inbound_messages_pending
            ON inbound_messages (processed_at, processing, received_at);
    END IF;
END
$$;


-- =============================================================================
-- 3. analytics_queue — worker poll columns
-- =============================================================================
-- The AnalyticsProcessor claims rows via processed/processing/processing_at
-- and marks them done via processed_at; it also aggregates on message_id/
-- domain_id/campaign_id. None of these existed on the deployed table.
-- Like inbound_messages above, no canonical migration ever created the
-- table (the tools-lineage shape is a UUID-id job queue, NOT this poll
-- shape): the guarded ALTERs left fresh canonical chains without it. The
-- worker reads id as bigint (mark/reset bind ANY($1::bigint[])), so the
-- canonical fresh shape is a BIGSERIAL event log.
CREATE TABLE IF NOT EXISTS analytics_queue (
    id            BIGSERIAL PRIMARY KEY,
    tenant_id     VARCHAR(26) NOT NULL,
    event_type    TEXT NOT NULL,
    message_id    VARCHAR(26),
    domain_id     VARCHAR(26),
    campaign_id   VARCHAR(64),
    recipient     TEXT,
    metadata      JSONB,
    "timestamp"   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    processed     BOOLEAN NOT NULL DEFAULT FALSE,
    processed_at  TIMESTAMPTZ,
    processing    BOOLEAN NOT NULL DEFAULT FALSE,
    processing_at TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_analytics_queue_pending
    ON analytics_queue (processed, processing, "timestamp");

DO $$
BEGIN
    IF to_regclass('public.analytics_queue') IS NOT NULL THEN
        ALTER TABLE analytics_queue ADD COLUMN IF NOT EXISTS processed BOOLEAN NOT NULL DEFAULT false;
        ALTER TABLE analytics_queue ADD COLUMN IF NOT EXISTS processing BOOLEAN NOT NULL DEFAULT false;
    END IF;
END
$$;

DO $$
BEGIN
    IF to_regclass('public.analytics_queue') IS NOT NULL THEN
        ALTER TABLE analytics_queue ADD COLUMN IF NOT EXISTS processing_at TIMESTAMPTZ;
        ALTER TABLE analytics_queue ADD COLUMN IF NOT EXISTS processed_at TIMESTAMPTZ;
    END IF;
END
$$;

DO $$
BEGIN
    IF to_regclass('public.analytics_queue') IS NOT NULL THEN
        ALTER TABLE analytics_queue ADD COLUMN IF NOT EXISTS message_id VARCHAR(26);
        ALTER TABLE analytics_queue ADD COLUMN IF NOT EXISTS domain_id VARCHAR(26);
    END IF;
END
$$;

DO $$
BEGIN
    IF to_regclass('public.analytics_queue') IS NOT NULL THEN
        ALTER TABLE analytics_queue ADD COLUMN IF NOT EXISTS campaign_id VARCHAR(26);
    END IF;
END
$$;

-- =============================================================================
-- 4. suppressions — missing table
-- =============================================================================
-- Referenced by the worker (hard-bounce suppression), the reply-handler
-- (Suppress/Unsubscribe actions) and the API send path (suppressed_recipients).
-- Canonical definition matches tools/migrations/001_initial_schema.sql.
-- Deliberately NOT nested inside the analytics_queue existence guard: no
-- canonical migration creates analytics_queue either, so on a fresh chain
-- the guard is never true and the suppressions table (and its consumers)
-- never materialized.
CREATE TABLE IF NOT EXISTS suppressions (
    id         VARCHAR(26) PRIMARY KEY,
    tenant_id  VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email      VARCHAR(255) NOT NULL,
    reason     VARCHAR(50) NOT NULL,
    subtype    VARCHAR(100),
    source     VARCHAR(100),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ,
    UNIQUE (tenant_id, email)
);
CREATE INDEX IF NOT EXISTS idx_suppressions_tenant ON suppressions (tenant_id);
CREATE INDEX IF NOT EXISTS idx_suppressions_email ON suppressions (email);
CREATE INDEX IF NOT EXISTS idx_suppressions_reason ON suppressions (reason);



-- =============================================================================
-- 5. sales_leads — reply-handler columns
-- =============================================================================
-- The reply-handler performs lead status updates (Snooze/FlagSales actions
-- and classification-driven status transitions).
DO $$
BEGIN
    IF to_regclass('public.sales_leads') IS NOT NULL THEN
        ALTER TABLE sales_leads ADD COLUMN IF NOT EXISTS snoozed_until TIMESTAMPTZ;
        ALTER TABLE sales_leads ADD COLUMN IF NOT EXISTS last_reply_at TIMESTAMPTZ;
    END IF;
END
$$;

DO $$
BEGIN
    IF to_regclass('public.sales_leads') IS NOT NULL THEN
        ALTER TABLE sales_leads ADD COLUMN IF NOT EXISTS priority VARCHAR(50);
    END IF;
END
$$;

-- 6. email_dlq — worker dead-letter queue (unconditional create-if-missing:
-- the worker requires it regardless of which lineage created sales_leads).
DO $$
BEGIN
    CREATE TABLE IF NOT EXISTS email_dlq (
        id            TEXT PRIMARY KEY,
        job_id        TEXT NOT NULL,
        tenant_id     TEXT,
        message_id    TEXT,
        error_message TEXT,
        created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_email_dlq_created_at ON email_dlq (created_at);
END
$$;

