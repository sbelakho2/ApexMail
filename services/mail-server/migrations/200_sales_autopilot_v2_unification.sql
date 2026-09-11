-- Migration 200: Sales autopilot v2 — unification and canonical schema
--
-- =============================================================================
-- Before this migration the sales system had two disconnected halves:
--
--   * api-server's control plane ran its own "autopilot" inside the API
--     process (a JoinHandle polling loop that flipped sales_leads rows from
--     new/prospect to qualified at score >= 80) and its own campaign
--     execution path writing drip_campaigns + campaign_recipients — rows no
--     production scheduler ever consumed;
--   * sales-autopilot (the real outbound engine) scheduled
--     sales_campaigns + sales_campaign_recipients and carried the actual
--     dispatcher.
--
-- Both halves also bootstrapped their own tables with CREATE TABLE
-- IF NOT EXISTS at runtime, so schema ownership was non-deterministic and
-- sales_leads had no canonical definition at all (only conditional ALTERs
-- guarded by to_regclass).
--
-- This migration makes the sales domain canonical and single-brained:
--
--   1. accounts / contacts / contact points — an email address is a
--      verified, suppressible attribute of a person, never the identity;
--   2. evidence + enrichment facts — every machine-derived claim keeps its
--      provider, confidence, observation time and source snapshot hash;
--   3. sequences / versions / steps / enrollments / step executions — the
--      unit of send is a logical step execution, so a second legitimate
--      email to one recipient inside one sequence is representable (the old
--      (campaign, recipient) key made that an inherent collision);
--   4. sales_actions — a durable, lease-based work queue (FOR UPDATE SKIP
--      LOCKED), so a process death recovers instead of losing or
--      duplicating work;
--   5. sales_decisions — the Decision Packet behind every automated
--      external action, for explainability and replay;
--   6. sender identities + health — pool classes with sales reputation
--      isolated from transactional/customer sending;
--   7. jurisdiction policies + contact policy decisions — the EU legal gate;
--   8. discovery, signals, scores, experiments, outcomes, attribution.
--
-- Retired by this migration (their code paths are deleted in the same
-- change): drip_campaigns, campaign_recipients — the CP's fake execution
-- path — and sales_autopilot_state — replaced by sales_autonomy_state,
-- whose mode column replaces the safe_mode boolean with real autonomy
-- levels.
--
-- Suppression authority stays shared: the platform `suppressions` table
-- (migration 088) is the canonical authority; sales_unsubscribes remains the
-- sales-side fast path and is created here canonically rather than by
-- runtime bootstrap.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- 0. sales_leads — canonical definition (previously runtime-created only)
-- ---------------------------------------------------------------------------
-- The reply-handling workers and the CP lead list read this table, so it must
-- exist on a freshly migrated database. Shape matches the runtime bootstrap
-- in sales-autopilot/src/{routes,crm_pg}.rs byte-for-byte so an existing
-- deployment converges instead of conflicting.
CREATE TABLE IF NOT EXISTS sales_leads (
    id            TEXT PRIMARY KEY,
    tenant_id     TEXT NOT NULL,
    company_name  TEXT NOT NULL DEFAULT '',
    domain        TEXT NOT NULL DEFAULT '',
    contact_email TEXT,
    contact_name  TEXT,
    email         TEXT,
    title         TEXT NOT NULL DEFAULT '',
    score         INTEGER NOT NULL DEFAULT 0,
    source        TEXT NOT NULL DEFAULT '',
    status        TEXT NOT NULL DEFAULT 'new',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_sales_leads_status ON sales_leads(status);
CREATE INDEX IF NOT EXISTS idx_sales_leads_tenant ON sales_leads(tenant_id);
CREATE INDEX IF NOT EXISTS idx_sales_leads_email ON sales_leads(email);

-- Columns added by later runtime guards / reply-handler convergence.
ALTER TABLE sales_leads ADD COLUMN IF NOT EXISTS notes TEXT;
ALTER TABLE sales_leads ADD COLUMN IF NOT EXISTS tags JSONB;
ALTER TABLE sales_leads ADD COLUMN IF NOT EXISTS deal_value DOUBLE PRECISION;
ALTER TABLE sales_leads ADD COLUMN IF NOT EXISTS snoozed_until TIMESTAMPTZ;
ALTER TABLE sales_leads ADD COLUMN IF NOT EXISTS last_reply_at TIMESTAMPTZ;
ALTER TABLE sales_leads ADD COLUMN IF NOT EXISTS priority VARCHAR(50);

-- Transitional bridge: each lead links to the account/contact model. The
-- columns are nullable so the mapping is incremental; new code writes them
-- and the lead rows remain readable for the CP list during the transition.
ALTER TABLE sales_leads ADD COLUMN IF NOT EXISTS account_id UUID;
ALTER TABLE sales_leads ADD COLUMN IF NOT EXISTS contact_id UUID;
CREATE INDEX IF NOT EXISTS idx_sales_leads_account ON sales_leads(account_id);
CREATE INDEX IF NOT EXISTS idx_sales_leads_contact ON sales_leads(contact_id);

-- ---------------------------------------------------------------------------
-- 1. sales_unsubscribes — sales-side suppression fast path (was runtime DDL)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sales_unsubscribes (
    tenant_id  TEXT NOT NULL,
    email      TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, email)
);
CREATE INDEX IF NOT EXISTS idx_sales_unsubscribes_tenant ON sales_unsubscribes(tenant_id);

-- ---------------------------------------------------------------------------
-- 1b. Tables that only ever existed through runtime DDL
-- ---------------------------------------------------------------------------
-- The sales service used to bootstrap these with `CREATE TABLE IF NOT EXISTS`
-- at startup. Removing that bootstrap without folding them into the canonical
-- chain would have left a freshly migrated deployment with no enrichment,
-- calendar, inbox or conversion storage at all — the code would fail on first
-- use. Shapes are byte-compatible with the former bootstrap (and its later
-- guarded ALTERs) so an existing database converges instead of conflicting.

-- Enriched company records (enrichment waterfall output of record).
CREATE TABLE IF NOT EXISTS enriched_companies (
    id                UUID PRIMARY KEY,
    tenant_id         TEXT NOT NULL,
    domain            TEXT NOT NULL,
    company_name      TEXT,
    industry          TEXT,
    employee_count    TEXT,
    annual_revenue    TEXT,
    funding_stage     TEXT,
    headquarters      TEXT,
    founded_year      INTEGER,
    description       TEXT,
    linkedin_url      TEXT,
    email_provider    TEXT,
    confidence_score  DOUBLE PRECISION NOT NULL DEFAULT 0,
    last_enriched_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, domain)
);
CREATE INDEX IF NOT EXISTS idx_enriched_companies_last_enriched_at
    ON enriched_companies (last_enriched_at DESC);
CREATE INDEX IF NOT EXISTS idx_enriched_companies_industry
    ON enriched_companies (industry);

-- Sales calendar events. The previous bootstrap also installed a GiST
-- exclusion constraint preventing double-booking; it is reinstated here so a
-- concurrent insert cannot slip past the service-level pre-check.
CREATE TABLE IF NOT EXISTS sales_calendar_events (
    id           UUID PRIMARY KEY,
    tenant_id    TEXT NOT NULL DEFAULT '',
    title        TEXT NOT NULL,
    attendees    TEXT[] NOT NULL DEFAULT '{}',
    start_at     TIMESTAMPTZ NOT NULL,
    end_at       TIMESTAMPTZ NOT NULL,
    meeting_link TEXT
);
CREATE INDEX IF NOT EXISTS idx_sales_calendar_events_tenant_id_start_at
    ON sales_calendar_events (tenant_id, start_at);
CREATE INDEX IF NOT EXISTS idx_sales_calendar_events_start_at
    ON sales_calendar_events (start_at);

DO $$
BEGIN
    -- btree_gist supplies the `=` operator for the scalar tenant_id column
    -- inside a GiST index. The range constructor must be tstzrange: the
    -- columns are TIMESTAMPTZ and tsrange(timestamptz, timestamptz) does not
    -- exist. Requires the extension to be available; a database without it
    -- keeps the service-level pre-check and the two indexes above.
    CREATE EXTENSION IF NOT EXISTS btree_gist;
    ALTER TABLE sales_calendar_events DROP CONSTRAINT IF EXISTS no_overlapping_events;
    ALTER TABLE sales_calendar_events ADD CONSTRAINT no_overlapping_events
        EXCLUDE USING gist (tenant_id WITH =, tstzrange(start_at, end_at) WITH &&);
EXCEPTION
    WHEN undefined_file OR insufficient_privilege OR feature_not_supported THEN
        RAISE NOTICE 'btree_gist unavailable — sales_calendar_events keeps the service-level double-booking pre-check only';
END
$$;

-- Monitored sales inbox messages.
CREATE TABLE IF NOT EXISTS sales_inbox_messages (
    id          UUID PRIMARY KEY,
    tenant_id   TEXT NOT NULL,
    sender      TEXT NOT NULL,
    subject     TEXT NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    category    TEXT NOT NULL DEFAULT 'other',
    replied     BOOLEAN NOT NULL DEFAULT false
);
CREATE INDEX IF NOT EXISTS idx_sales_inbox_messages_tenant_id
    ON sales_inbox_messages (tenant_id);
CREATE INDEX IF NOT EXISTS idx_sales_inbox_messages_category
    ON sales_inbox_messages (category);
CREATE INDEX IF NOT EXISTS idx_sales_inbox_messages_received_at
    ON sales_inbox_messages (received_at);

-- Conversion tracking (attribution of revenue to a campaign/lead).
CREATE TABLE IF NOT EXISTS sales_conversions (
    id           UUID PRIMARY KEY,
    tenant_id    TEXT NOT NULL,
    campaign_id  UUID NOT NULL,
    lead_id      UUID NOT NULL,
    revenue      DOUBLE PRECISION NOT NULL DEFAULT 0,
    description  TEXT NOT NULL DEFAULT '',
    converted_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_sales_conversions_tenant_id
    ON sales_conversions (tenant_id);
CREATE INDEX IF NOT EXISTS idx_sales_conversions_campaign_id
    ON sales_conversions (campaign_id);
CREATE INDEX IF NOT EXISTS idx_sales_conversions_lead_id
    ON sales_conversions (lead_id);

-- ---------------------------------------------------------------------------
-- 2. sales_accounts — one company
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sales_accounts (
    id                UUID PRIMARY KEY,
    tenant_id         TEXT NOT NULL,
    company           TEXT NOT NULL,
    domain            TEXT NOT NULL,
    country           TEXT,
    country_confidence DOUBLE PRECISION NOT NULL DEFAULT 0
        CHECK (country_confidence >= 0 AND country_confidence <= 1),
    industry          TEXT,
    employees         INTEGER CHECK (employees IS NULL OR employees >= 0),
    revenue_band      TEXT,
    funding_stage     TEXT,
    technologies      TEXT[] NOT NULL DEFAULT '{}',
    -- Current ESP hypotheses as evidence-backed propositions, never facts.
    esp_hypotheses    JSONB NOT NULL DEFAULT '[]'::jsonb,
    eea_relevance     TEXT NOT NULL DEFAULT 'unknown'
        CHECK (eea_relevance IN ('in_scope', 'out_of_scope', 'unknown')),
    icp_segment       TEXT,
    account_owner     TEXT,
    lifecycle         TEXT NOT NULL DEFAULT 'discovered'
        CHECK (lifecycle IN ('discovered', 'enriched', 'qualified', 'nurturing',
                             'customer', 'disqualified')),
    -- Account-level contact coordination budgets (audit: never let
    -- automation independently contact five people at one company).
    max_active_contacts      SMALLINT NOT NULL DEFAULT 2 CHECK (max_active_contacts >= 1),
    multi_thread_allowed     BOOLEAN NOT NULL DEFAULT FALSE,
    negative_reply_cooldown_hours INTEGER NOT NULL DEFAULT 0,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, domain)
);
CREATE INDEX IF NOT EXISTS idx_sales_accounts_tenant_lifecycle
    ON sales_accounts (tenant_id, lifecycle);
CREATE INDEX IF NOT EXISTS idx_sales_accounts_icp ON sales_accounts (tenant_id, icp_segment);

-- ---------------------------------------------------------------------------
-- 3. sales_contacts — one human
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sales_contacts (
    id         UUID PRIMARY KEY,
    tenant_id  TEXT NOT NULL,
    account_id UUID REFERENCES sales_accounts(id) ON DELETE CASCADE,
    full_name  TEXT NOT NULL DEFAULT '',
    job_title  TEXT,
    department TEXT,
    seniority  TEXT,
    persona    TEXT,
    country    TEXT,
    timezone   TEXT,
    language   TEXT,
    lifecycle  TEXT NOT NULL DEFAULT 'active'
        CHECK (lifecycle IN ('active', 'snoozed', 'replied', 'meeting_booked',
                             'customer', 'do_not_contact', 'left_company')),
    is_primary BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_sales_contacts_account ON sales_contacts (account_id);
CREATE INDEX IF NOT EXISTS idx_sales_contacts_tenant_lifecycle
    ON sales_contacts (tenant_id, lifecycle);

-- ---------------------------------------------------------------------------
-- 4. sales_contact_points — email / phone / social, each verifiable
-- ---------------------------------------------------------------------------
-- Never make an email address the fundamental identity: this table is the
-- only place a channel address lives, it carries verification provenance, and
-- suppression is a first-class column.
CREATE TABLE IF NOT EXISTS sales_contact_points (
    id                  UUID PRIMARY KEY,
    tenant_id           TEXT NOT NULL,
    contact_id          UUID NOT NULL REFERENCES sales_contacts(id) ON DELETE CASCADE,
    channel             TEXT NOT NULL
        CHECK (channel IN ('email', 'phone', 'linkedin', 'x', 'other')),
    value               TEXT NOT NULL,
    normalized_value    TEXT NOT NULL,
    verification        TEXT NOT NULL DEFAULT 'unverified'
        CHECK (verification IN ('unverified', 'valid', 'invalid', 'risky', 'unknown')),
    verification_provider TEXT,
    confidence          DOUBLE PRECISION NOT NULL DEFAULT 0
        CHECK (confidence >= 0 AND confidence <= 1),
    source              TEXT,
    last_verified_at    TIMESTAMPTZ,
    suppressed_at       TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, channel, normalized_value)
);
CREATE INDEX IF NOT EXISTS idx_sales_contact_points_contact
    ON sales_contact_points (contact_id);
CREATE INDEX IF NOT EXISTS idx_sales_contact_points_verification
    ON sales_contact_points (tenant_id, verification)
    WHERE suppressed_at IS NULL;

-- ---------------------------------------------------------------------------
-- 5. sales_evidence — every machine-derived claim, with provenance
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sales_evidence (
    id           UUID PRIMARY KEY,
    tenant_id    TEXT NOT NULL,
    account_id   UUID REFERENCES sales_accounts(id) ON DELETE CASCADE,
    contact_id   UUID REFERENCES sales_contacts(id) ON DELETE CASCADE,
    proposition  TEXT NOT NULL,
    confidence   DOUBLE PRECISION NOT NULL DEFAULT 0
        CHECK (confidence >= 0 AND confidence <= 1),
    source_kind  TEXT NOT NULL
        CHECK (source_kind IN ('dns_observation', 'http_fetch', 'provider_api',
                               'first_party', 'public_registry', 'manual')),
    source_ref   TEXT,
    source_hash  TEXT,
    observed_at  TIMESTAMPTZ NOT NULL,
    expires_at   TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_sales_evidence_account
    ON sales_evidence (account_id, proposition);
CREATE INDEX IF NOT EXISTS idx_sales_evidence_expiry
    ON sales_evidence (expires_at) WHERE expires_at IS NOT NULL;

-- ---------------------------------------------------------------------------
-- 6. sales_enrichment_facts — waterfall output, provenance preserved
-- ---------------------------------------------------------------------------
-- Enrichment never flattens straight into a company record: each field keeps
-- the provider that supplied it, its confidence, observation/expiry time and
-- the evidence row that grounds it.
CREATE TABLE IF NOT EXISTS sales_enrichment_facts (
    id           UUID PRIMARY KEY,
    tenant_id    TEXT NOT NULL,
    subject_type TEXT NOT NULL CHECK (subject_type IN ('account', 'contact', 'contact_point')),
    subject_id   UUID NOT NULL,
    field        TEXT NOT NULL,
    value        JSONB,
    provider     TEXT NOT NULL,
    confidence   DOUBLE PRECISION NOT NULL DEFAULT 0
        CHECK (confidence >= 0 AND confidence <= 1),
    observed_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at   TIMESTAMPTZ,
    evidence_id  UUID REFERENCES sales_evidence(id) ON DELETE SET NULL,
    cost_eur     NUMERIC(12, 4) NOT NULL DEFAULT 0 CHECK (cost_eur >= 0),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, subject_type, subject_id, field, provider)
);
CREATE INDEX IF NOT EXISTS idx_sales_enrichment_facts_subject
    ON sales_enrichment_facts (tenant_id, subject_type, subject_id);

-- Rolling provider statistics powering cost-aware routing
-- (expected_information_gain / marginal_cost).
CREATE TABLE IF NOT EXISTS sales_provider_stats (
    id              UUID PRIMARY KEY,
    tenant_id       TEXT NOT NULL,
    provider        TEXT NOT NULL,
    field           TEXT NOT NULL,
    attempts        BIGINT NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    fills           BIGINT NOT NULL DEFAULT 0 CHECK (fills >= 0),
    verified_correct BIGINT NOT NULL DEFAULT 0 CHECK (verified_correct >= 0),
    total_latency_ms BIGINT NOT NULL DEFAULT 0 CHECK (total_latency_ms >= 0),
    total_cost_eur  NUMERIC(14, 6) NOT NULL DEFAULT 0 CHECK (total_cost_eur >= 0),
    errors          BIGINT NOT NULL DEFAULT 0 CHECK (errors >= 0),
    last_success_at TIMESTAMPTZ,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, provider, field)
);

-- ---------------------------------------------------------------------------
-- 7. sales_signals — always-on account change detection
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sales_signals (
    id          UUID PRIMARY KEY,
    tenant_id   TEXT NOT NULL,
    account_id  UUID NOT NULL REFERENCES sales_accounts(id) ON DELETE CASCADE,
    signal_type TEXT NOT NULL,
    strength    DOUBLE PRECISION NOT NULL DEFAULT 0
        CHECK (strength >= 0 AND strength <= 1),
    observed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at  TIMESTAMPTZ,
    evidence_id UUID REFERENCES sales_evidence(id) ON DELETE SET NULL,
    payload     JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_sales_signals_account
    ON sales_signals (account_id, signal_type, observed_at DESC);
-- Recency lookup for live signals. The predicate cannot reference NOW()
-- (index predicates must be IMMUTABLE); expiry is filtered at query time.
CREATE INDEX IF NOT EXISTS idx_sales_signals_active
    ON sales_signals (tenant_id, observed_at DESC);

-- ---------------------------------------------------------------------------
-- 8. sales_scores — explainable multi-dimensional score
-- ---------------------------------------------------------------------------
-- Replaces the single weighted 0-100 lead score. The feature vector is stored
-- so a decision can be replayed and audited; reason_codes carry the
-- human-readable contributions the CP renders.
CREATE TABLE IF NOT EXISTS sales_scores (
    id                  UUID PRIMARY KEY,
    tenant_id           TEXT NOT NULL,
    account_id          UUID NOT NULL REFERENCES sales_accounts(id) ON DELETE CASCADE,
    contact_id          UUID REFERENCES sales_contacts(id) ON DELETE CASCADE,
    account_fit         DOUBLE PRECISION NOT NULL DEFAULT 0,
    persona_fit         DOUBLE PRECISION NOT NULL DEFAULT 0,
    need_fit            DOUBLE PRECISION NOT NULL DEFAULT 0,
    intent              DOUBLE PRECISION NOT NULL DEFAULT 0,
    timing              DOUBLE PRECISION NOT NULL DEFAULT 0,
    email_stack_fit     DOUBLE PRECISION NOT NULL DEFAULT 0,
    eu_residency_fit    DOUBLE PRECISION NOT NULL DEFAULT 0,
    reachability        DOUBLE PRECISION NOT NULL DEFAULT 0,
    evidence_quality    DOUBLE PRECISION NOT NULL DEFAULT 0,
    legal_contactability DOUBLE PRECISION NOT NULL DEFAULT 0,
    risk                DOUBLE PRECISION NOT NULL DEFAULT 0,
    p_qualified_reply   DOUBLE PRECISION NOT NULL DEFAULT 0,
    p_meeting           DOUBLE PRECISION NOT NULL DEFAULT 0,
    p_paid              DOUBLE PRECISION NOT NULL DEFAULT 0,
    expected_value_eur  NUMERIC(14, 4) NOT NULL DEFAULT 0,
    total               DOUBLE PRECISION NOT NULL DEFAULT 0,
    reason_codes        JSONB NOT NULL DEFAULT '[]'::jsonb,
    scoring_version     TEXT NOT NULL,
    computed_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_sales_scores_latest
    ON sales_scores (tenant_id, account_id, computed_at DESC);

-- ---------------------------------------------------------------------------
-- 9. Sequences — real adaptive workflows, not a single template id
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sales_sequences (
    id          UUID PRIMARY KEY,
    tenant_id   TEXT NOT NULL,
    name        TEXT NOT NULL,
    description TEXT,
    status      TEXT NOT NULL DEFAULT 'draft'
        CHECK (status IN ('draft', 'active', 'paused', 'retired')),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_sales_sequences_tenant ON sales_sequences (tenant_id, status);

-- Versions are immutable once active: every step execution points at the
-- exact version it ran, which makes replay and attribution exact.
CREATE TABLE IF NOT EXISTS sales_sequence_versions (
    id          UUID PRIMARY KEY,
    tenant_id   TEXT NOT NULL,
    sequence_id UUID NOT NULL REFERENCES sales_sequences(id) ON DELETE CASCADE,
    version     INTEGER NOT NULL CHECK (version >= 1),
    status      TEXT NOT NULL DEFAULT 'draft'
        CHECK (status IN ('draft', 'active', 'retired')),
    locale      TEXT NOT NULL DEFAULT 'en',
    approved_by TEXT,
    approved_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (sequence_id, version)
);
CREATE INDEX IF NOT EXISTS idx_sales_sequence_versions_active
    ON sales_sequence_versions (sequence_id, status);

CREATE TABLE IF NOT EXISTS sales_sequence_steps (
    id                UUID PRIMARY KEY,
    tenant_id         TEXT NOT NULL,
    version_id        UUID NOT NULL REFERENCES sales_sequence_versions(id) ON DELETE CASCADE,
    step_index        INTEGER NOT NULL CHECK (step_index >= 0),
    kind              TEXT NOT NULL
        CHECK (kind IN ('email', 'wait', 'enrich', 'research', 'condition',
                        'branch', 'manual_task', 'meeting_invite', 'nurture', 'stop')),
    template_id       TEXT,
    min_delay_secs    BIGINT NOT NULL DEFAULT 0 CHECK (min_delay_secs >= 0),
    max_delay_secs    BIGINT NOT NULL DEFAULT 0
        CHECK (max_delay_secs >= 0 AND max_delay_secs >= min_delay_secs),
    send_window       JSONB NOT NULL DEFAULT '{}'::jsonb,
    recipient_timezone BOOLEAN NOT NULL DEFAULT TRUE,
    allowed_weekdays  SMALLINT[] NOT NULL DEFAULT '{1,2,3,4,5}',
    experiment_key    TEXT,
    tracking_policy   TEXT NOT NULL DEFAULT 'standard'
        CHECK (tracking_policy IN ('standard', 'no_open_tracking', 'none')),
    sender_pool       TEXT NOT NULL DEFAULT 'sales_outbound'
        CHECK (sender_pool IN ('sales_outbound', 'sales_warmup')),
    exit_conditions   JSONB NOT NULL DEFAULT '[]'::jsonb,
    retry_policy      JSONB NOT NULL DEFAULT '{}'::jsonb,
    branch_rules      JSONB NOT NULL DEFAULT '[]'::jsonb,
    config            JSONB NOT NULL DEFAULT '{}'::jsonb,
    UNIQUE (version_id, step_index)
);

CREATE TABLE IF NOT EXISTS sales_enrollments (
    id                  UUID PRIMARY KEY,
    tenant_id           TEXT NOT NULL,
    sequence_version_id UUID NOT NULL REFERENCES sales_sequence_versions(id) ON DELETE RESTRICT,
    account_id          UUID REFERENCES sales_accounts(id) ON DELETE CASCADE,
    contact_id          UUID NOT NULL REFERENCES sales_contacts(id) ON DELETE CASCADE,
    contact_point_id    UUID REFERENCES sales_contact_points(id) ON DELETE SET NULL,
    state               TEXT NOT NULL DEFAULT 'pending'
        CHECK (state IN ('pending', 'active', 'waiting', 'paused', 'replied',
                         'meeting_booked', 'completed', 'suppressed', 'failed')),
    current_step_index  INTEGER NOT NULL DEFAULT 0 CHECK (current_step_index >= 0),
    experiment_id       UUID,
    experiment_variant  TEXT,
    -- Set by the reply handler; a human reply must block the next scheduled
    -- touch even if the action row was already queued.
    has_human_reply     BOOLEAN NOT NULL DEFAULT FALSE,
    autonomy_mode       TEXT,
    decision_id         UUID,
    enrolled_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at        TIMESTAMPTZ,
    UNIQUE (tenant_id, sequence_version_id, contact_id)
);
CREATE INDEX IF NOT EXISTS idx_sales_enrollments_state
    ON sales_enrollments (tenant_id, state);
CREATE INDEX IF NOT EXISTS idx_sales_enrollments_account
    ON sales_enrollments (account_id, state);

-- One row per logical step execution attempt. The idempotency_key is the send
-- identity (enrollment, version, step, attempt kind, variant) — NOT
-- (campaign, recipient), so a second legitimate email to the same recipient
-- in the same sequence is representable.
CREATE TABLE IF NOT EXISTS sales_step_executions (
    id                  UUID PRIMARY KEY,
    tenant_id           TEXT NOT NULL,
    enrollment_id       UUID NOT NULL REFERENCES sales_enrollments(id) ON DELETE CASCADE,
    sequence_version_id UUID NOT NULL,
    sequence_step_id    UUID NOT NULL REFERENCES sales_sequence_steps(id) ON DELETE RESTRICT,
    step_index          INTEGER NOT NULL,
    attempt_kind        TEXT NOT NULL DEFAULT 'primary'
        CHECK (attempt_kind IN ('primary', 'followup', 'high_intent', 'meeting_invite', 'nurture')),
    variant             TEXT NOT NULL DEFAULT 'default',
    state               TEXT NOT NULL DEFAULT 'scheduled'
        CHECK (state IN ('scheduled', 'queued', 'executing', 'sent', 'skipped',
                         'failed', 'cancelled')),
    idempotency_key     TEXT NOT NULL,
    scheduled_for       TIMESTAMPTZ,
    executed_at         TIMESTAMPTZ,
    message_id          UUID,
    decision_id         UUID,
    attempt             INTEGER NOT NULL DEFAULT 0 CHECK (attempt >= 0),
    skip_reason         TEXT,
    last_error          TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (idempotency_key)
);
CREATE INDEX IF NOT EXISTS idx_sales_step_executions_enrollment
    ON sales_step_executions (enrollment_id, step_index);
CREATE INDEX IF NOT EXISTS idx_sales_step_executions_due
    ON sales_step_executions (scheduled_for)
    WHERE state IN ('scheduled', 'queued');

-- ---------------------------------------------------------------------------
-- 10. sales_actions — the durable work queue
-- ---------------------------------------------------------------------------
-- Claims use FOR UPDATE SKIP LOCKED with a lease, so any number of workers
-- can run concurrently and a process death at any point recovers via lease
-- expiry instead of losing work or duplicating a send.
CREATE TABLE IF NOT EXISTS sales_actions (
    id              UUID PRIMARY KEY,
    tenant_id       TEXT NOT NULL,
    action_type     TEXT NOT NULL,
    entity_type     TEXT NOT NULL,
    entity_id       UUID NOT NULL,
    due_at          TIMESTAMPTZ NOT NULL,
    priority        SMALLINT NOT NULL DEFAULT 100
        CHECK (priority >= 0 AND priority <= 1000),
    state           TEXT NOT NULL DEFAULT 'queued'
        CHECK (state IN ('queued', 'leased', 'executing', 'succeeded',
                         'failed', 'dead_letter', 'cancelled')),
    attempt         INTEGER NOT NULL DEFAULT 0 CHECK (attempt >= 0),
    max_attempts    INTEGER NOT NULL DEFAULT 5 CHECK (max_attempts >= 1),
    lease_owner     TEXT,
    lease_expires_at TIMESTAMPTZ,
    idempotency_key TEXT NOT NULL,
    payload         JSONB NOT NULL DEFAULT '{}'::jsonb,
    decision_id     UUID,
    last_error      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at    TIMESTAMPTZ,
    UNIQUE (idempotency_key)
);
CREATE INDEX IF NOT EXISTS idx_sales_actions_claim
    ON sales_actions (priority DESC, due_at ASC)
    WHERE state = 'queued';
CREATE INDEX IF NOT EXISTS idx_sales_actions_lease
    ON sales_actions (lease_expires_at)
    WHERE state IN ('leased', 'executing');
CREATE INDEX IF NOT EXISTS idx_sales_actions_entity
    ON sales_actions (tenant_id, entity_type, entity_id);

-- ---------------------------------------------------------------------------
-- 11. sales_decisions — the Decision Packet
-- ---------------------------------------------------------------------------
-- Every automated external action has exactly one of these: what was decided,
-- why, on which evidence, under which policy and model version, and when it
-- was allowed to execute. This is what makes the machine explainable and
-- replayable.
CREATE TABLE IF NOT EXISTS sales_decisions (
    id                UUID PRIMARY KEY,
    tenant_id         TEXT NOT NULL,
    account_id        UUID REFERENCES sales_accounts(id) ON DELETE SET NULL,
    contact_id        UUID REFERENCES sales_contacts(id) ON DELETE SET NULL,
    action            TEXT NOT NULL,
    expected_value_eur NUMERIC(14, 4) NOT NULL DEFAULT 0,
    confidence        DOUBLE PRECISION NOT NULL DEFAULT 0
        CHECK (confidence >= 0 AND confidence <= 1),
    score_total       DOUBLE PRECISION NOT NULL DEFAULT 0,
    selected_offer    TEXT,
    selected_sequence TEXT,
    selected_variant  TEXT,
    selected_sender   TEXT,
    evidence_ids      UUID[] NOT NULL DEFAULT '{}',
    policy_id         TEXT,
    model_version     TEXT,
    autonomy_mode     TEXT NOT NULL,
    rationale         TEXT NOT NULL DEFAULT '',
    blocked           BOOLEAN NOT NULL DEFAULT FALSE,
    block_reasons     JSONB NOT NULL DEFAULT '[]'::jsonb,
    execute_after     TIMESTAMPTZ,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_sales_decisions_account
    ON sales_decisions (tenant_id, account_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_sales_decisions_blocked
    ON sales_decisions (tenant_id, created_at DESC) WHERE blocked;

-- ---------------------------------------------------------------------------
-- 12. Sender identities and health — reputation isolation
-- ---------------------------------------------------------------------------
-- The pool column is the isolation invariant: a sales action may only ever
-- select a sales pool. Transactional customer traffic is a different pool and
-- the code path that resolves a sender refuses cross-pool fallback.
CREATE TABLE IF NOT EXISTS sales_sender_identities (
    id          UUID PRIMARY KEY,
    tenant_id   TEXT NOT NULL,
    pool        TEXT NOT NULL
        CHECK (pool IN ('transactional_customer', 'internal_transactional',
                        'sales_outbound', 'sales_warmup')),
    from_email  TEXT NOT NULL,
    from_name   TEXT,
    domain      TEXT NOT NULL,
    source_ip   INET,
    provider    TEXT,
    status      TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('provisioning', 'active', 'throttled', 'paused', 'quarantined', 'retired')),
    daily_limit INTEGER CHECK (daily_limit IS NULL OR daily_limit >= 0),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, from_email)
);
CREATE INDEX IF NOT EXISTS idx_sales_sender_identities_pool
    ON sales_sender_identities (tenant_id, pool, status);

CREATE TABLE IF NOT EXISTS sales_sender_health (
    id                  UUID PRIMARY KEY,
    tenant_id           TEXT NOT NULL,
    sender_identity_id  UUID NOT NULL REFERENCES sales_sender_identities(id) ON DELETE CASCADE,
    window_start        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    window_secs         INTEGER NOT NULL DEFAULT 86400 CHECK (window_secs > 0),
    volume              BIGINT NOT NULL DEFAULT 0 CHECK (volume >= 0),
    hard_bounces        BIGINT NOT NULL DEFAULT 0 CHECK (hard_bounces >= 0),
    soft_bounces        BIGINT NOT NULL DEFAULT 0 CHECK (soft_bounces >= 0),
    complaints          BIGINT NOT NULL DEFAULT 0 CHECK (complaints >= 0),
    unsubscribes        BIGINT NOT NULL DEFAULT 0 CHECK (unsubscribes >= 0),
    deferrals           BIGINT NOT NULL DEFAULT 0 CHECK (deferrals >= 0),
    auth_failures       BIGINT NOT NULL DEFAULT 0 CHECK (auth_failures >= 0),
    inbox_placement     DOUBLE PRECISION,
    reply_quality       DOUBLE PRECISION,
    health_score        DOUBLE PRECISION NOT NULL DEFAULT 1
        CHECK (health_score >= 0 AND health_score <= 1),
    state               TEXT NOT NULL DEFAULT 'healthy'
        CHECK (state IN ('warming', 'healthy', 'throttled', 'paused', 'quarantined')),
    warmup_day          INTEGER CHECK (warmup_day IS NULL OR warmup_day >= 0),
    domain_age_days     INTEGER CHECK (domain_age_days IS NULL OR domain_age_days >= 0),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (sender_identity_id)
);

-- ---------------------------------------------------------------------------
-- 13. Reply classifications — one canonical inbound intelligence record
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sales_reply_classifications (
    id                UUID PRIMARY KEY,
    tenant_id         TEXT NOT NULL,
    enrollment_id     UUID REFERENCES sales_enrollments(id) ON DELETE SET NULL,
    contact_id        UUID REFERENCES sales_contacts(id) ON DELETE SET NULL,
    contact_point_id  UUID REFERENCES sales_contact_points(id) ON DELETE SET NULL,
    inbound_message_id TEXT,
    disposition       TEXT NOT NULL
        CHECK (disposition IN ('positive', 'meeting_request', 'question', 'referral',
                               'not_interested', 'unsubscribe', 'complaint', 'ooo',
                               'bounce_hard', 'bounce_soft', 'unknown')),
    confidence        DOUBLE PRECISION NOT NULL DEFAULT 0
        CHECK (confidence >= 0 AND confidence <= 1),
    classifier        TEXT NOT NULL CHECK (classifier IN ('deterministic', 'ai', 'operator')),
    reasoning         TEXT,
    model_version     TEXT,
    prompt_version    TEXT,
    evidence          JSONB NOT NULL DEFAULT '{}'::jsonb,
    suggested_action  TEXT,
    actual_action     TEXT,
    operator_correction TEXT,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_sales_reply_classifications_enrollment
    ON sales_reply_classifications (enrollment_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_sales_reply_classifications_training
    ON sales_reply_classifications (tenant_id, created_at DESC)
    WHERE operator_correction IS NOT NULL;

-- ---------------------------------------------------------------------------
-- 14. Meetings, opportunities, outcomes
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sales_meetings (
    id                UUID PRIMARY KEY,
    tenant_id         TEXT NOT NULL,
    enrollment_id     UUID REFERENCES sales_enrollments(id) ON DELETE SET NULL,
    account_id        UUID REFERENCES sales_accounts(id) ON DELETE SET NULL,
    contact_id        UUID REFERENCES sales_contacts(id) ON DELETE SET NULL,
    provider          TEXT NOT NULL DEFAULT 'internal'
        CHECK (provider IN ('internal', 'google', 'microsoft')),
    provider_event_id TEXT,
    start_at          TIMESTAMPTZ NOT NULL,
    end_at            TIMESTAMPTZ NOT NULL,
    timezone          TEXT NOT NULL DEFAULT 'UTC',
    conferencing_link TEXT,
    status            TEXT NOT NULL DEFAULT 'booked'
        CHECK (status IN ('booked', 'rescheduled', 'attended', 'no_show', 'cancelled')),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (end_at > start_at)
);
CREATE INDEX IF NOT EXISTS idx_sales_meetings_start
    ON sales_meetings (tenant_id, start_at DESC);

CREATE TABLE IF NOT EXISTS sales_opportunities (
    id                UUID PRIMARY KEY,
    tenant_id         TEXT NOT NULL,
    account_id        UUID NOT NULL REFERENCES sales_accounts(id) ON DELETE CASCADE,
    contact_id        UUID REFERENCES sales_contacts(id) ON DELETE SET NULL,
    stage             TEXT NOT NULL DEFAULT 'open'
        CHECK (stage IN ('open', 'qualified', 'negotiation', 'won', 'lost')),
    amount_eur        NUMERIC(14, 2) NOT NULL DEFAULT 0,
    expected_close_at TIMESTAMPTZ,
    won_at            TIMESTAMPTZ,
    lost_at           TIMESTAMPTZ,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_sales_opportunities_stage
    ON sales_opportunities (tenant_id, stage);

-- The outcome ladder the optimizer learns from. Opens and clicks are recorded
-- but are explicitly NOT the reward signal (Apple privacy features and
-- automated image fetching make them too weak to optimize against).
CREATE TABLE IF NOT EXISTS sales_outcomes (
    id                UUID PRIMARY KEY,
    tenant_id         TEXT NOT NULL,
    account_id        UUID REFERENCES sales_accounts(id) ON DELETE SET NULL,
    contact_id        UUID REFERENCES sales_contacts(id) ON DELETE SET NULL,
    enrollment_id     UUID REFERENCES sales_enrollments(id) ON DELETE SET NULL,
    step_execution_id UUID REFERENCES sales_step_executions(id) ON DELETE SET NULL,
    discovery_source  TEXT,
    offer             TEXT,
    outcome           TEXT NOT NULL
        CHECK (outcome IN ('delivered', 'open', 'click', 'reply', 'positive_reply',
                           'meeting_booked', 'meeting_attended', 'trial',
                           'paid_subscription', 'retained_mrr', 'bounce',
                           'complaint', 'unsubscribe')),
    value_eur         NUMERIC(14, 4) NOT NULL DEFAULT 0,
    message_id        UUID,
    provider          TEXT,
    occurred_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, outcome, step_execution_id)
);
CREATE INDEX IF NOT EXISTS idx_sales_outcomes_account
    ON sales_outcomes (tenant_id, account_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_sales_outcomes_revenue
    ON sales_outcomes (tenant_id, outcome, occurred_at DESC)
    WHERE outcome IN ('trial', 'paid_subscription', 'retained_mrr');

-- ---------------------------------------------------------------------------
-- 15. Experiments — contextual bandit arms with economic exploration limits
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sales_experiments (
    id          UUID PRIMARY KEY,
    tenant_id   TEXT NOT NULL,
    key         TEXT NOT NULL,
    name        TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'draft'
        CHECK (status IN ('draft', 'running', 'paused', 'promoted', 'stopped')),
    -- Context dimensions this experiment conditions on (segment, country,
    -- persona, esp, offer, language, step kind, sender type …).
    context     JSONB NOT NULL DEFAULT '{}'::jsonb,
    -- Economic exploration limits: max contacts, max sender-domain exposure,
    -- max daily exploration %, max negative-outcome budget, max enrichment
    -- spend, minimum sample before promotion, minimum posterior confidence.
    budgets     JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, key)
);

CREATE TABLE IF NOT EXISTS sales_experiment_arms (
    id          UUID PRIMARY KEY,
    tenant_id   TEXT NOT NULL,
    experiment_id UUID NOT NULL REFERENCES sales_experiments(id) ON DELETE CASCADE,
    variant     TEXT NOT NULL,
    alpha       DOUBLE PRECISION NOT NULL DEFAULT 1
        CHECK (alpha > 0 AND alpha < 'Infinity'),
    beta        DOUBLE PRECISION NOT NULL DEFAULT 1
        CHECK (beta > 0 AND beta < 'Infinity'),
    trials      BIGINT NOT NULL DEFAULT 0 CHECK (trials >= 0),
    successes   BIGINT NOT NULL DEFAULT 0 CHECK (successes >= 0 AND successes <= trials),
    contacts    BIGINT NOT NULL DEFAULT 0 CHECK (contacts >= 0),
    enrichment_cost_eur NUMERIC(14, 6) NOT NULL DEFAULT 0,
    negative_outcomes BIGINT NOT NULL DEFAULT 0,
    is_control  BOOLEAN NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (experiment_id, variant)
);

-- Idempotent outcome ledger: replaying the same logical outcome moves the
-- posterior at most once.
CREATE TABLE IF NOT EXISTS sales_experiment_outcomes (
    outcome_key TEXT PRIMARY KEY,
    experiment_id UUID NOT NULL,
    variant     TEXT NOT NULL,
    reward      DOUBLE PRECISION NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ---------------------------------------------------------------------------
-- 16. Discovery — a real provider-backed pipeline, not a read of cached rows
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sales_discovery_jobs (
    id          UUID PRIMARY KEY,
    tenant_id   TEXT NOT NULL,
    query       JSONB NOT NULL,
    sources     TEXT[] NOT NULL DEFAULT '{}',
    status      TEXT NOT NULL DEFAULT 'queued'
        CHECK (status IN ('queued', 'running', 'completed', 'failed', 'cancelled')),
    cursor      TEXT,
    discovered  BIGINT NOT NULL DEFAULT 0 CHECK (discovered >= 0),
    imported    BIGINT NOT NULL DEFAULT 0 CHECK (imported >= 0),
    cost_eur    NUMERIC(14, 6) NOT NULL DEFAULT 0 CHECK (cost_eur >= 0),
    error       TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at  TIMESTAMPTZ,
    completed_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_sales_discovery_jobs_status
    ON sales_discovery_jobs (tenant_id, status, created_at DESC);

CREATE TABLE IF NOT EXISTS sales_discovery_candidates (
    id                UUID PRIMARY KEY,
    tenant_id         TEXT NOT NULL,
    job_id            UUID REFERENCES sales_discovery_jobs(id) ON DELETE CASCADE,
    source            TEXT NOT NULL,
    source_url        TEXT,
    company_name      TEXT,
    account_domain    TEXT,
    jurisdiction      TEXT,
    jurisdiction_confidence DOUBLE PRECISION NOT NULL DEFAULT 0
        CHECK (jurisdiction_confidence >= 0 AND jurisdiction_confidence <= 1),
    raw_snapshot_hash TEXT,
    confidence        DOUBLE PRECISION NOT NULL DEFAULT 0
        CHECK (confidence >= 0 AND confidence <= 1),
    refresh_expires_at TIMESTAMPTZ,
    discovered_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    promoted_account_id UUID REFERENCES sales_accounts(id) ON DELETE SET NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_sales_discovery_candidates_pending
    ON sales_discovery_candidates (tenant_id, promoted_account_id, discovered_at DESC);
-- Same company may legitimately appear from two sources; the same source URL
-- twice is a duplicate.
CREATE UNIQUE INDEX IF NOT EXISTS idx_sales_discovery_candidates_source_url
    ON sales_discovery_candidates (tenant_id, source, source_url)
    WHERE source_url IS NOT NULL;

CREATE TABLE IF NOT EXISTS sales_source_runs (
    id           UUID PRIMARY KEY,
    tenant_id    TEXT NOT NULL,
    job_id       UUID REFERENCES sales_discovery_jobs(id) ON DELETE CASCADE,
    source       TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'running'
        CHECK (status IN ('running', 'succeeded', 'failed', 'rate_limited')),
    http_status  INTEGER,
    items        BIGINT NOT NULL DEFAULT 0,
    cost_eur     NUMERIC(14, 6) NOT NULL DEFAULT 0,
    latency_ms   BIGINT,
    error        TEXT,
    started_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_sales_source_runs_source
    ON sales_source_runs (tenant_id, source, started_at DESC);

-- ---------------------------------------------------------------------------
-- 17. Jurisdiction policy — the EU legal gate
-- ---------------------------------------------------------------------------
-- Country-by-country, versioned, counsel-approved. This is an engineering
-- control, not a claim that software resolves the law: an unknown or
-- unapproved jurisdiction defaults to approval-required in code.
CREATE TABLE IF NOT EXISTS sales_jurisdiction_policies (
    id                UUID PRIMARY KEY,
    jurisdiction      TEXT NOT NULL,
    channel           TEXT NOT NULL DEFAULT 'email'
        CHECK (channel IN ('email', 'phone', 'linkedin', 'other')),
    contact_type      TEXT NOT NULL DEFAULT 'b2b_professional'
        CHECK (contact_type IN ('b2b_professional', 'b2c', 'sole_trader', 'unknown')),
    decision          TEXT NOT NULL
        CHECK (decision IN ('allowed', 'approval_required', 'prohibited')),
    basis             TEXT NOT NULL
        CHECK (basis IN ('consent', 'soft_opt_in', 'legitimate_interest', 'not_permitted')),
    required_disclosure JSONB NOT NULL DEFAULT '{}'::jsonb,
    version           INTEGER NOT NULL DEFAULT 1 CHECK (version >= 1),
    approved_by       TEXT,
    approved_at       TIMESTAMPTZ,
    valid_from        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    valid_until       TIMESTAMPTZ,
    notes             TEXT,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (jurisdiction, channel, contact_type, version)
);
CREATE INDEX IF NOT EXISTS idx_sales_jurisdiction_policies_lookup
    ON sales_jurisdiction_policies (jurisdiction, channel, contact_type, version DESC);

CREATE TABLE IF NOT EXISTS sales_contact_policy_decisions (
    id                UUID PRIMARY KEY,
    tenant_id         TEXT NOT NULL,
    account_id        UUID REFERENCES sales_accounts(id) ON DELETE CASCADE,
    contact_id        UUID REFERENCES sales_contacts(id) ON DELETE CASCADE,
    contact_point_id  UUID REFERENCES sales_contact_points(id) ON DELETE SET NULL,
    jurisdiction      TEXT NOT NULL,
    policy_id         UUID REFERENCES sales_jurisdiction_policies(id) ON DELETE SET NULL,
    policy_version    INTEGER,
    decision          TEXT NOT NULL
        CHECK (decision IN ('allowed', 'approval_required', 'prohibited')),
    basis             TEXT NOT NULL,
    reason            TEXT NOT NULL DEFAULT '',
    required_disclosure JSONB NOT NULL DEFAULT '{}'::jsonb,
    inputs            JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_sales_contact_policy_decisions_contact
    ON sales_contact_policy_decisions (tenant_id, contact_id, created_at DESC);

-- ---------------------------------------------------------------------------
-- 18. sales_autonomy_state — real autonomy levels, kill switch
-- ---------------------------------------------------------------------------
-- Replaces sales_autopilot_state.safe_mode. Mode semantics:
--   disabled | shadow | assisted | approval_required | autonomous_guarded
-- Shadow still runs the entire brain (think + generate) and only blocks
-- execution, which is what produces a validation dataset before autonomy is
-- granted.
CREATE TABLE IF NOT EXISTS sales_autonomy_state (
    tenant_id           TEXT PRIMARY KEY,
    mode                TEXT NOT NULL DEFAULT 'disabled'
        CHECK (mode IN ('disabled', 'shadow', 'assisted', 'approval_required',
                        'autonomous_guarded')),
    kill_switch         BOOLEAN NOT NULL DEFAULT FALSE,
    experiments_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    exploration_budget  JSONB NOT NULL DEFAULT '{}'::jsonb,
    rules               JSONB NOT NULL DEFAULT '{}'::jsonb,
    last_action         TEXT,
    last_action_at      TIMESTAMPTZ,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Carry the legacy boolean forward: safe_mode = true becomes shadow (it still
-- stopped execution but the brain kept reading), false becomes disabled —
-- never autonomous, because autonomy must be granted deliberately.
DO $$
BEGIN
    IF to_regclass('public.sales_autopilot_state') IS NOT NULL THEN
        INSERT INTO sales_autonomy_state (tenant_id, mode, rules, last_action,
                                          last_action_at, updated_at)
        SELECT tenant_id,
               CASE WHEN safe_mode THEN 'shadow' ELSE 'disabled' END,
               COALESCE(rules, '{}'::jsonb),
               last_action,
               last_action_at,
               updated_at
        FROM sales_autopilot_state
        ON CONFLICT (tenant_id) DO NOTHING;
    END IF;
END
$$;

-- ---------------------------------------------------------------------------
-- 18b. sales_campaign_recipients — canonical (was runtime-created only)
-- ---------------------------------------------------------------------------
-- Migration 197 folded `sales_campaigns` into the canonical chain so the arm
-- table could carry a real FK, but its recipient table was still created by
-- the service's runtime bootstrap. It is part of the send ledger the scheduler
-- reads, so it belongs here. Shape matches the former bootstrap plus its two
-- guarded ALTERs byte-for-byte.
CREATE TABLE IF NOT EXISTS sales_campaign_recipients (
    campaign_id UUID NOT NULL REFERENCES sales_campaigns(id) ON DELETE CASCADE,
    email       TEXT NOT NULL,
    PRIMARY KEY (campaign_id, email)
);
-- `sent_at` is stamped after a successful dispatch, so pausing and restarting
-- a campaign does not re-dispatch the whole recipient list.
ALTER TABLE sales_campaign_recipients ADD COLUMN IF NOT EXISTS sent_at TIMESTAMPTZ;
-- Links a dispatched recipient to its platform `messages` row for the
-- open/click reconciliation.
ALTER TABLE sales_campaign_recipients ADD COLUMN IF NOT EXISTS message_id UUID;

CREATE INDEX IF NOT EXISTS idx_sales_campaign_recipients_unsent
    ON sales_campaign_recipients (campaign_id)
    WHERE sent_at IS NULL;

-- ---------------------------------------------------------------------------
-- 19. Retire the two-brain artifacts
-- ---------------------------------------------------------------------------
-- drip_campaigns / campaign_recipients were the CP's own campaign execution
-- path: the CP could report "outreach queued" while the rows it wrote were
-- never consumed by the production scheduler (sales_campaigns /
-- sales_campaign_recipients). Dropped here; the CP now reads the canonical
-- sequence/enrollment model.
DROP TABLE IF EXISTS campaign_recipients;
DROP TABLE IF EXISTS drip_campaigns;

-- sales_autopilot_state is superseded by sales_autonomy_state (data copied
-- above).
DROP TABLE IF EXISTS sales_autopilot_state;

-- ---------------------------------------------------------------------------
-- 20. sales_settings — converge the two column sets
-- ---------------------------------------------------------------------------
-- 069 created (autopilot_enabled, discovery_enabled, settings); the CP's
-- sales route reads/writes (scoring_weights, schedule, notifications). 093
-- added scoring_weights only, so save_settings failed with 42703 on a
-- correctly migrated database and get_settings silently fell back to
-- defaults. Both sets now exist.
ALTER TABLE sales_settings ADD COLUMN IF NOT EXISTS scoring_weights JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE sales_settings ADD COLUMN IF NOT EXISTS schedule JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE sales_settings ADD COLUMN IF NOT EXISTS notifications JSONB NOT NULL DEFAULT '{}'::jsonb;

-- ---------------------------------------------------------------------------
-- 21. Seed the safe default policy set
-- ---------------------------------------------------------------------------
-- No jurisdiction is allowed to send autonomously until an explicit policy
-- row exists. These rows make the default explicit and auditable: EU member
-- states start approval-required on the conservative reading of ePrivacy
-- Art. 13 + EDPB guidance on national implementations, and unknown
-- jurisdiction is approval-required.
INSERT INTO sales_jurisdiction_policies
    (id, jurisdiction, channel, contact_type, decision, basis, version,
     approved_by, approved_at, notes)
VALUES
    (gen_random_uuid(), 'EU', 'email', 'b2b_professional', 'approval_required',
     'legitimate_interest', 1, 'migration:200', NOW(),
     'Default EU/EEA posture: legitimate-interest basis requires operator approval per send until counsel-approved country policies are loaded.'),
    (gen_random_uuid(), 'UNKNOWN', 'email', 'unknown', 'approval_required',
     'not_permitted', 1, 'migration:200', NOW(),
     'Fail-closed default: an unresolvable or unlisted jurisdiction never sends autonomously.')
ON CONFLICT (jurisdiction, channel, contact_type, version) DO NOTHING;
