-- Migration 093: Deep schema convergence
--
-- =============================================================================
-- DEEP PASS: schema/contract convergence (wave 2)
-- =============================================================================
-- Prior wave (088) reconciled email_queue/inbound_messages split-brain. This
-- migration completes the audit of EVERY table the deployed code touches
-- (api-server, worker, mta, mailstore, enterprise, tracking, status-server):
--
--   A. Tables referenced by deployed code but missing on production
--      (created here with the exact shape the code writes/reads).
--   B. Existing production tables whose shape diverged from the code
--      contract (ALTER TABLE convergences, idempotent).
--   C. Missing hot-path indexes (api_keys.key_hash lookup is on every API
--      auth; tenant_deliverability_metrics upsert needs its unique key).
--   D. Partition runway: extend create_future_partitions() so email_queue /
--      email_delivery_log / bounce_analytics_daily / audit_logs partitions
--      never run out.
--
-- Idempotent: safe to re-run on any deployment.
-- =============================================================================


-- =============================================================================
-- A. MISSING TABLES
-- =============================================================================

-- ── Control-plane access log (middleware/cp_auth.rs) ────────────────────────
CREATE TABLE IF NOT EXISTS cp_access_log (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email      VARCHAR(320),
    path       VARCHAR(1024) NOT NULL,
    outcome    VARCHAR(64) NOT NULL,
    status_code INTEGER,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_cp_access_log_created_at ON cp_access_log (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_cp_access_log_outcome    ON cp_access_log (outcome);
CREATE INDEX IF NOT EXISTS idx_cp_access_log_email      ON cp_access_log (email) WHERE email IS NOT NULL;

-- ── Health-check history (routes/admin/health.rs) ───────────────────────────
CREATE TABLE IF NOT EXISTS health_check_history (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    overall_score DOUBLE PRECISION NOT NULL,
    db_score     DOUBLE PRECISION NOT NULL,
    redis_score  DOUBLE PRECISION NOT NULL,
    queue_score  DOUBLE PRECISION NOT NULL,
    mta_score    DOUBLE PRECISION NOT NULL,
    disk_score   DOUBLE PRECISION NOT NULL,
    memory_score DOUBLE PRECISION NOT NULL,
    details      JSONB NOT NULL DEFAULT '{}'::jsonb,
    checked_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_health_check_history_time   ON health_check_history (checked_at DESC);
CREATE INDEX IF NOT EXISTS idx_health_check_history_recent ON health_check_history (overall_score, checked_at DESC);

-- ── Report history (admin_report_scheduler.rs, routes/admin/reports.rs) ─────
CREATE TABLE IF NOT EXISTS report_history (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    report_type  VARCHAR(20) NOT NULL,
    format       VARCHAR(10) NOT NULL,
    period_start TIMESTAMPTZ,
    period_end   TIMESTAMPTZ,
    data         JSONB,
    generated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_report_history_type_time ON report_history (report_type, generated_at DESC);
CREATE INDEX IF NOT EXISTS idx_report_history_generated_at ON report_history (generated_at DESC);

-- ── Invoice line items (admin_report_scheduler.rs revenue calc) ─────────────
CREATE TABLE IF NOT EXISTS invoice_line_items (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    invoice_id  UUID,
    tenant_id   VARCHAR(26),
    description TEXT,
    amount_cents BIGINT NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_invoice_line_items_created ON invoice_line_items (created_at);

-- ── List subscribers (routes/lists.rs) ──────────────────────────────────────
CREATE TABLE IF NOT EXISTS list_subscribers (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    list_id    UUID NOT NULL REFERENCES lists(id) ON DELETE CASCADE,
    contact_id VARCHAR(26) NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
    status     VARCHAR(20) NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(list_id, contact_id)
);
CREATE INDEX IF NOT EXISTS idx_list_subscribers_list   ON list_subscribers (list_id);
CREATE INDEX IF NOT EXISTS idx_list_subscribers_contact ON list_subscribers (contact_id);
CREATE INDEX IF NOT EXISTS idx_list_subscribers_status ON list_subscribers (list_id, status);

-- ── SCIM (routes/scim.rs) ───────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS scim_users (
    id           VARCHAR(26) PRIMARY KEY,
    tenant_id    VARCHAR(26) NOT NULL,
    external_id  VARCHAR(255),
    email        VARCHAR(255) NOT NULL,
    display_name VARCHAR(255),
    active       BOOLEAN NOT NULL DEFAULT true,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_scim_users_tenant   ON scim_users (tenant_id);
CREATE INDEX IF NOT EXISTS idx_scim_users_external ON scim_users (tenant_id, external_id);

CREATE TABLE IF NOT EXISTS scim_groups (
    id           VARCHAR(26) PRIMARY KEY,
    tenant_id    VARCHAR(26) NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    scim_id      VARCHAR(255) NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_scim_groups_tenant ON scim_groups (tenant_id);

CREATE TABLE IF NOT EXISTS scim_group_members (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    group_id   VARCHAR(26) NOT NULL REFERENCES scim_groups(id) ON DELETE CASCADE,
    user_id    UUID NOT NULL,
    tenant_id  VARCHAR(26) NOT NULL,
    display    VARCHAR(255),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(group_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_scim_group_members_user ON scim_group_members (user_id);

-- ── Dunning records (routes/billing.rs, billing-service) ────────────────────
-- Superset of migration 087 (invoice_id/attempt_number/amount_cents) and the
-- api-server/billing-service column families (failed_payment_count, retry
-- schedule, suspension state).
CREATE TABLE IF NOT EXISTS dunning_records (
    id                   VARCHAR(26) PRIMARY KEY,
    tenant_id            VARCHAR(26) NOT NULL,
    invoice_id           VARCHAR(26),
    attempt_number       INTEGER NOT NULL DEFAULT 0,
    amount_cents         BIGINT NOT NULL DEFAULT 0,
    failed_payment_count INTEGER NOT NULL DEFAULT 0,
    first_failed_at      TIMESTAMPTZ,
    last_failed_at       TIMESTAMPTZ,
    next_retry_at        TIMESTAMPTZ,
    grace_period_ends_at TIMESTAMPTZ,
    suspended_at         TIMESTAMPTZ,
    status               VARCHAR(50) NOT NULL DEFAULT 'pending',
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_dunning_records_tenant ON dunning_records (tenant_id);
CREATE INDEX IF NOT EXISTS idx_dunning_records_status ON dunning_records (tenant_id, status);
-- One dunning record per tenant (upsert target for billing flows).
CREATE UNIQUE INDEX IF NOT EXISTS idx_dunning_records_tenant_unique ON dunning_records (tenant_id);

-- ── Dedicated IP provisioning requests (billing-service stripe_webhooks.rs) ─
CREATE TABLE IF NOT EXISTS dedicated_ip_provisioning_requests (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       VARCHAR(26) NOT NULL,
    requested_count INTEGER NOT NULL,
    status          VARCHAR(50) NOT NULL DEFAULT 'pending',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_dedicated_ip_provisioning_tenant ON dedicated_ip_provisioning_requests (tenant_id, status);
CREATE UNIQUE INDEX IF NOT EXISTS idx_dedicated_ip_provisioning_pending
    ON dedicated_ip_provisioning_requests (tenant_id) WHERE status = 'pending';

-- ── Feature flags (routes/admin/features.rs) ────────────────────────────────
CREATE TABLE IF NOT EXISTS feature_flags (
    id          UUID PRIMARY KEY,
    name        VARCHAR(128) NOT NULL,
    description TEXT,
    enabled     BOOLEAN NOT NULL DEFAULT false,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_feature_flags_name ON feature_flags (name);

CREATE TABLE IF NOT EXISTS feature_flag_overrides (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    flag_key   VARCHAR(128) NOT NULL,
    tenant_id  VARCHAR(26) NOT NULL,
    tenant_name VARCHAR(255),
    value      JSONB NOT NULL DEFAULT 'true'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_feature_flag_overrides_tenant ON feature_flag_overrides (tenant_id, flag_key);

-- ── Webhook deliveries (worker-processors/src/webhook/processor.rs) ─────────
CREATE TABLE IF NOT EXISTS webhook_deliveries (
    id               TEXT PRIMARY KEY,
    webhook_id       VARCHAR(26) NOT NULL,
    tenant_id        VARCHAR(26) NOT NULL,
    event_type       VARCHAR(128) NOT NULL,
    payload          JSONB NOT NULL DEFAULT '{}'::jsonb,
    status_code      INTEGER,
    response_time_ms BIGINT,
    response_body    TEXT,
    attempt          INTEGER NOT NULL DEFAULT 1,
    error            TEXT,
    delivered_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_webhook ON webhook_deliveries (webhook_id, delivered_at DESC);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_tenant  ON webhook_deliveries (tenant_id, delivered_at DESC);

-- ── Bounce/complaint events + sender reputation (mta) ───────────────────────
CREATE TABLE IF NOT EXISTS bounce_events (
    id                   UUID PRIMARY KEY,
    original_message_id  TEXT,
    original_recipient   TEXT,
    bounce_type          TEXT NOT NULL,
    bounce_subtype       TEXT,
    diagnostic_code      TEXT,
    status_code          TEXT,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_bounce_events_recipient ON bounce_events (original_recipient);
CREATE INDEX IF NOT EXISTS idx_bounce_events_created   ON bounce_events (created_at DESC);

CREATE TABLE IF NOT EXISTS complaint_events (
    id                   UUID PRIMARY KEY,
    original_message_id  TEXT,
    original_recipient   TEXT,
    feedback_type        TEXT,
    source_ip            TEXT,
    reporting_mta        TEXT,
    user_agent           TEXT,
    arrival_date         TIMESTAMPTZ,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_complaint_events_recipient ON complaint_events (original_recipient);
CREATE INDEX IF NOT EXISTS idx_complaint_events_created   ON complaint_events (created_at DESC);

CREATE TABLE IF NOT EXISTS sender_reputation (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain     TEXT NOT NULL,
    date       DATE NOT NULL,
    complaints BIGINT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(domain, date)
);

CREATE TABLE IF NOT EXISTS alert_webhook_deliveries (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    webhook_id    TEXT NOT NULL,
    alert_type    TEXT NOT NULL,
    payload       JSONB NOT NULL DEFAULT '{}'::jsonb,
    success       BOOLEAN NOT NULL DEFAULT false,
    status_code   INTEGER,
    error_message TEXT,
    delivered_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_alert_webhook_deliveries_webhook ON alert_webhook_deliveries (webhook_id, delivered_at DESC);

-- ── Alert webhooks (mta feedback_loop.rs) ──────────────────────────────────
CREATE TABLE IF NOT EXISTS alert_webhooks (
    id          UUID PRIMARY KEY,
    url         TEXT NOT NULL,
    secret      TEXT,
    enabled     BOOLEAN NOT NULL DEFAULT true,
    alert_types JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── Queue jobs (queue-provider/src/schema.rs, admin sse/system_health) ──────
CREATE TABLE IF NOT EXISTS queue_jobs (
    id                 UUID PRIMARY KEY,
    tenant_id          UUID NOT NULL,
    queue              TEXT NOT NULL,
    queue_name         TEXT,
    payload            JSONB NOT NULL DEFAULT '{}'::jsonb,
    status             TEXT NOT NULL DEFAULT 'pending'
                       CHECK (status IN ('pending', 'processing', 'completed', 'failed', 'dead_letter')),
    attempts           INTEGER NOT NULL DEFAULT 0,
    max_attempts       INTEGER NOT NULL DEFAULT 3,
    priority           INTEGER NOT NULL DEFAULT 0,
    scheduled_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at         TIMESTAMPTZ,
    completed_at       TIMESTAMPTZ,
    failed_at          TIMESTAMPTZ,
    error_message      TEXT,
    visibility_timeout INTEGER NOT NULL DEFAULT 300,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_queue_jobs_dequeue ON queue_jobs (queue, scheduled_at) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_queue_jobs_tenant  ON queue_jobs (tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_queue_jobs_stale   ON queue_jobs (started_at) WHERE status = 'processing';
CREATE INDEX IF NOT EXISTS idx_queue_jobs_purge   ON queue_jobs (queue, updated_at) WHERE status IN ('completed', 'dead_letter');

-- ── Support ticket messages (routes/admin/support.rs) ───────────────────────
CREATE TABLE IF NOT EXISTS support_ticket_messages (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ticket_id   VARCHAR(26) NOT NULL,
    content     TEXT NOT NULL,
    author      VARCHAR(255),
    author_type VARCHAR(20),
    attachments JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_support_ticket_messages_ticket ON support_ticket_messages (ticket_id, created_at);

-- ── Reputation alerts/stats (routes/admin/risk.rs) ──────────────────────────
CREATE TABLE IF NOT EXISTS reputation_alerts (
    id           VARCHAR(26) PRIMARY KEY,
    tenant_id    VARCHAR(26) NOT NULL,
    alert_type   VARCHAR(50) NOT NULL,
    value        DOUBLE PRECISION NOT NULL,
    threshold    DOUBLE PRECISION NOT NULL,
    acknowledged BOOLEAN NOT NULL DEFAULT false,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_reputation_alerts_tenant ON reputation_alerts (tenant_id, acknowledged);

CREATE TABLE IF NOT EXISTS reputation_stats (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  VARCHAR(26) NOT NULL,
    date       DATE NOT NULL,
    bounces    BIGINT NOT NULL DEFAULT 0,
    complaints BIGINT NOT NULL DEFAULT 0,
    sent       BIGINT NOT NULL DEFAULT 0,
    UNIQUE(tenant_id, date)
);

-- ── Autopilot inbox (routes/admin/inbox.rs) ─────────────────────────────────
CREATE TABLE IF NOT EXISTS autopilot_inbox_messages (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     VARCHAR(26),
    classification VARCHAR(50),
    subject       TEXT,
    from_address  TEXT,
    to_address    TEXT,
    summary       TEXT,
    is_read       BOOLEAN NOT NULL DEFAULT false,
    is_archived   BOOLEAN NOT NULL DEFAULT false,
    action_taken  TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_autopilot_inbox_tenant ON autopilot_inbox_messages (tenant_id, created_at DESC);

-- ── Calendar (routes/admin/calendar.rs) ─────────────────────────────────────
CREATE TABLE IF NOT EXISTS calendar_events (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   VARCHAR(26),
    title       TEXT NOT NULL,
    type        VARCHAR(50),
    start_time  TIMESTAMPTZ NOT NULL,
    end_time    TIMESTAMPTZ,
    description TEXT,
    attendees   JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_calendar_events_tenant ON calendar_events (tenant_id, start_time);

CREATE TABLE IF NOT EXISTS availability_slots (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   VARCHAR(26),
    day_of_week INTEGER NOT NULL,
    start_time  TIME NOT NULL,
    end_time    TIME NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_availability_slots_tenant ON availability_slots (tenant_id);

-- ── Content items (routes/admin/content.rs) ─────────────────────────────────
CREATE TABLE IF NOT EXISTS content_items (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    VARCHAR(26),
    title        TEXT NOT NULL,
    content_type VARCHAR(50),
    type         VARCHAR(50),
    body         TEXT,
    author       VARCHAR(255),
    tags         JSONB NOT NULL DEFAULT '[]'::jsonb,
    view_count   BIGINT NOT NULL DEFAULT 0,
    views        BIGINT NOT NULL DEFAULT 0,
    click_count  BIGINT NOT NULL DEFAULT 0,
    published_at TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_content_items_tenant ON content_items (tenant_id, created_at DESC);

-- ── IP pools (routes/admin/warmup.rs, ops-service/warmup.rs) ────────────────
CREATE TABLE IF NOT EXISTS ip_pools (
    id         VARCHAR(26) PRIMARY KEY,
    name       VARCHAR(128) NOT NULL,
    status     VARCHAR(20) NOT NULL DEFAULT 'pending',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ip_pool_addresses (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    pool_id        VARCHAR(26) NOT NULL,
    ip_address     INET NOT NULL,
    status         VARCHAR(20) NOT NULL DEFAULT 'warming',
    warmup_enabled BOOLEAN NOT NULL DEFAULT false,
    warmup_day     INTEGER NOT NULL DEFAULT 0,
    daily_limit    INTEGER NOT NULL DEFAULT 0,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_ip_pool_addresses_pool ON ip_pool_addresses (pool_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_ip_pool_addresses_ip ON ip_pool_addresses (ip_address);

-- ── Tenant settings (tracking-service routes/click.rs) ──────────────────────
CREATE TABLE IF NOT EXISTS tenant_settings (
    tenant_id              VARCHAR(26) PRIMARY KEY,
    allowed_redirect_domains JSONB NOT NULL DEFAULT '[]'::jsonb,
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── Email categories (tracking-service routes/unsubscribe.rs) ───────────────
CREATE TABLE IF NOT EXISTS email_categories (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     VARCHAR(26) NOT NULL,
    name          VARCHAR(128) NOT NULL,
    description   TEXT,
    active        BOOLEAN NOT NULL DEFAULT true,
    display_order INTEGER NOT NULL DEFAULT 0,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_email_categories_tenant ON email_categories (tenant_id, display_order);

-- ── User/tenant membership (api-server middleware/auth.rs) ──────────────────
CREATE TABLE IF NOT EXISTS user_tenant_membership (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    VARCHAR(26) NOT NULL,
    tenant_id  VARCHAR(26) NOT NULL,
    role       VARCHAR(50) NOT NULL DEFAULT 'member',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(user_id, tenant_id)
);
CREATE INDEX IF NOT EXISTS idx_user_tenant_membership_tenant ON user_tenant_membership (tenant_id);

-- =============================================================================
-- B. TABLE CONVERGENCE (ALTERs)
-- =============================================================================

-- ── suppression_list: the MTA bounce/FBL paths suppress provider-wide
-- (no tenant context on the VERP/DSN path). Allow tenant-less rows; dedup
-- those by email.
ALTER TABLE suppression_list ALTER COLUMN tenant_id DROP NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_suppression_list_email_no_tenant
    ON suppression_list (email) WHERE tenant_id IS NULL;

-- ── drip_campaigns: converge to the api-server admin contract (id TEXT
-- "cmp_..." ids, campaign_type/sequence/stats/started_at families).
ALTER TABLE drip_campaigns ALTER COLUMN id TYPE TEXT USING id::text;
ALTER TABLE drip_campaigns ALTER COLUMN tenant_id DROP NOT NULL;
ALTER TABLE drip_campaigns ADD COLUMN IF NOT EXISTS campaign_type TEXT;
ALTER TABLE drip_campaigns ADD COLUMN IF NOT EXISTS description TEXT;
ALTER TABLE drip_campaigns ADD COLUMN IF NOT EXISTS from_email TEXT;
ALTER TABLE drip_campaigns ADD COLUMN IF NOT EXISTS from_name TEXT;
ALTER TABLE drip_campaigns ADD COLUMN IF NOT EXISTS sequence JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE drip_campaigns ADD COLUMN IF NOT EXISTS stats JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE drip_campaigns ADD COLUMN IF NOT EXISTS started_at TIMESTAMPTZ;

-- ── campaign_recipients: match admin/sales.rs batch INSERT
-- (lead_id/email/opened_at/clicked_at/replied_at; campaign_id now text FK).
ALTER TABLE campaign_recipients DROP CONSTRAINT IF EXISTS campaign_recipients_campaign_id_fkey;
ALTER TABLE campaign_recipients ALTER COLUMN campaign_id TYPE TEXT USING campaign_id::text;
ALTER TABLE campaign_recipients ALTER COLUMN contact_id DROP NOT NULL;
ALTER TABLE campaign_recipients ADD COLUMN IF NOT EXISTS lead_id TEXT;
ALTER TABLE campaign_recipients ADD COLUMN IF NOT EXISTS email TEXT;
ALTER TABLE campaign_recipients ADD COLUMN IF NOT EXISTS opened_at TIMESTAMPTZ;
ALTER TABLE campaign_recipients ADD COLUMN IF NOT EXISTS clicked_at TIMESTAMPTZ;
ALTER TABLE campaign_recipients ADD COLUMN IF NOT EXISTS replied_at TIMESTAMPTZ;
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'campaign_recipients_campaign_id_fkey') THEN
        ALTER TABLE campaign_recipients
            ADD CONSTRAINT campaign_recipients_campaign_id_fkey
            FOREIGN KEY (campaign_id) REFERENCES drip_campaigns(id) ON DELETE CASCADE;
    END IF;
END $$;
CREATE INDEX IF NOT EXISTS idx_campaign_recipients_campaign_id ON campaign_recipients (campaign_id);

-- ── risk_settings: add the admin/risk.rs single-row global fields.
ALTER TABLE risk_settings ADD COLUMN IF NOT EXISTS thresholds JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE risk_settings ADD COLUMN IF NOT EXISTS last_assessed_at TIMESTAMPTZ;

-- ── sales_settings: add the admin/sales.rs global scoring config fields.
ALTER TABLE sales_settings ADD COLUMN IF NOT EXISTS scoring_weights JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE sales_settings ADD COLUMN IF NOT EXISTS schedule JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE sales_settings ADD COLUMN IF NOT EXISTS notifications JSONB NOT NULL DEFAULT '{}'::jsonb;

-- ── plan_overrides: add the admin plan-override fields + upsert key.
ALTER TABLE plan_overrides ADD COLUMN IF NOT EXISTS plan_id VARCHAR(26);
ALTER TABLE plan_overrides ADD COLUMN IF NOT EXISTS reason TEXT;
ALTER TABLE plan_overrides ADD COLUMN IF NOT EXISTS admin_id VARCHAR(26);
ALTER TABLE plan_overrides ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;
CREATE UNIQUE INDEX IF NOT EXISTS idx_plan_overrides_tenant ON plan_overrides (tenant_id);

-- ── invoices: add the number/notes families used by both invoice writers.
ALTER TABLE invoices ADD COLUMN IF NOT EXISTS invoice_number VARCHAR(64);
ALTER TABLE invoices ADD COLUMN IF NOT EXISTS purchase_order_number VARCHAR(128);
ALTER TABLE invoices ADD COLUMN IF NOT EXISTS notes TEXT;

-- ── tenant_deliverability_metrics: upsert key for the daily rollups.
CREATE UNIQUE INDEX IF NOT EXISTS idx_tdm_tenant_period ON tenant_deliverability_metrics (tenant_id, period_start);

-- ── dedicated_ips: api-server writes full UUID ids (36 chars).
ALTER TABLE dedicated_ips ALTER COLUMN id TYPE VARCHAR(64);

-- ── domains: the worker DKIM signer reads per-domain signing material
-- directly from `domains` (migration 093_add_domain_dkim_key_columns was
-- planned but never shipped). Add the code-contract columns.
ALTER TABLE domains ADD COLUMN IF NOT EXISTS dkim_selector TEXT;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS dkim_public_key TEXT;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS dkim_private_key TEXT;
-- SES identity flag written by the verify-domain flow and read by ops.
ALTER TABLE domains ADD COLUMN IF NOT EXISTS ses_verified BOOLEAN NOT NULL DEFAULT false;

-- =============================================================================
-- C. HOT-PATH INDEXES
-- =============================================================================

-- Every API-key auth does key_hash lookup (HMAC, legacy SHA-256, Argon2 scan).
CREATE INDEX IF NOT EXISTS idx_api_keys_key_hash ON api_keys (key_hash);

-- =============================================================================
-- D. PARTITION RUNWAY
-- =============================================================================

-- Extend email_queue / email_delivery_log / bounce_analytics_daily /
-- audit_logs / mail_messages partitions 18 periods ahead of today.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_proc WHERE proname = 'create_future_partitions') THEN
        PERFORM create_future_partitions();
    END IF;
END $$;

