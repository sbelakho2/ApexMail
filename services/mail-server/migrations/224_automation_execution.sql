-- Migration 224: Automation execution — event inbox, runs, per-action log
--
-- =============================================================================
-- The `/v1/automations` surface was CRUD only: `automations.trigger_config`,
-- `.conditions` and `.actions` were stored and listed, but nothing in the
-- workspace ever read them back to evaluate a trigger or execute an action
-- (audit implementation-order item 3: "unify SendAdmissionService for REST +
-- SMTP submission + Sales + automations" — the automation arm had no executor
-- at all, so the admission call was a documented contract with no caller).
--
-- This migration installs the SCHEMA half of the executor. The Rust half is
-- `sales_autopilot::automations::AutomationExecutor` (crates/sales-autopilot/
-- src/automations.rs), whose tick claims due work from
-- `automation_trigger_events` with FOR UPDATE SKIP LOCKED and executes
-- matching rules through the ONE shared send admission gate
-- (`billing_service::send_admission::SendAdmissionService`).
--
-- -----------------------------------------------------------------------------
-- IDEMPOTENCY IDENTITY (exactly-once, replay-safe)
-- -----------------------------------------------------------------------------
-- Three layers, each keyed by a DERIVED, deterministic identity — never a
-- random per-attempt id:
--
-- 1. EVENT INGEST — `automation_trigger_events.event_key` is derived from the
--    source row, not from the processing attempt:
--      contact.created   -> 'contact.created:<contact uuid>'
--      contact.updated   -> 'contact.updated:<contact uuid>:<updated_at µs>'
--      contact.tag_added -> 'contact.tag_added:<contact uuid>:<updated_at µs>'
--      message.received  -> 'message.received:<inbound_messages.id>'
--    with UNIQUE (tenant_id, event_key). Replaying the same platform event
--    (at-least-once producer, crash before lease settlement) is a no-op.
--
-- 2. RUN CLAIM — `automation_runs` is unique on
--    (tenant_id, automation_id, trigger_event_key): ONE run per (rule, event)
--    for the lifetime of the rule. Re-claiming an event whose lease expired
--    resumes the existing run (only actions without a terminal record are
--    re-attempted); it can never execute a second time.
--
-- 3. SEND — the `messages` row carries the deterministic
--    idempotency key 'autoact:<run_id>:<action_index>' (unique on
--    (tenant_id, idempotency_key)), and `automation_run_actions` is written in
--    the SAME transaction as the `messages` + `email_queue` inserts. A crash
--    between enqueue and bookkeeping therefore cannot double-send: either the
--    whole action committed, or none of it did. The admission reservation uses
--    the derived usage-event identity 'auto-run:<run_id>:<action_index>' so a
--    retry of the same action re-derives the same metering event and cannot
--    double-reserve quota either.
--
-- -----------------------------------------------------------------------------
-- WHY DATABASE TRIGGERS PRODUCE THE EVENTS
-- -----------------------------------------------------------------------------
-- No platform event bus exists: nothing else in the workspace writes an
-- automation event, and the product has no event producer to call. Rather than
-- shipping an executor that never receives work (or a second write path bolted
-- onto the contact/inbound routes — those files are owned by other changes in
-- flight), the canonical schema itself emits the two event families the
-- product actually stores:
--
--   * `contacts` INSERT/UPDATE -> contact.created / contact.updated /
--     contact.tag_added (tag deltas are computed here; the application could
--     not observe them without an old/new diff). Trigger functions are
--     defensive: they never raise, so an automation problem can never abort a
--     contact write.
--   * `inbound_messages` INSERT -> message.received (the 1:1 reply trigger;
--     its sends are the only automation mail admitted as `transactional`).
--
-- The triggers only INSERT into the inbox; every decision (matching a rule,
-- evaluating conditions, admission, enqueue) stays in Rust under the
-- execution rules above.
-- =============================================================================

-- =============================================================================
-- 1. TRIGGER-EVENT INBOX (the "due work" claimed by the executor tick)
-- =============================================================================
CREATE TABLE IF NOT EXISTS automation_trigger_events (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       VARCHAR(26) NOT NULL,
    event_type      TEXT NOT NULL,
    event_key       TEXT NOT NULL,
    contact_id      UUID,
    -- For message.received: the inbound sender, i.e. the reply target.
    recipient_email TEXT,
    payload         JSONB NOT NULL DEFAULT '{}'::jsonb,
    status          TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'processing', 'processed', 'failed')),
    attempts        INTEGER NOT NULL DEFAULT 0,
    max_attempts    INTEGER NOT NULL DEFAULT 5,
    available_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    locked_until    TIMESTAMPTZ,
    locked_by       TEXT,
    last_error      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    processed_at    TIMESTAMPTZ
);

-- Layer 1 of the idempotency identity (see header).
CREATE UNIQUE INDEX IF NOT EXISTS uq_automation_trigger_events_tenant_key
    ON automation_trigger_events (tenant_id, event_key);

-- The tick's claim query: due pending work, or processing work whose lease
-- expired (crash recovery).
CREATE INDEX IF NOT EXISTS idx_automation_trigger_events_due
    ON automation_trigger_events (status, available_at)
    WHERE status IN ('pending', 'processing');

-- Bounded retention prune (the tick deletes a bounded slice of settled rows).
CREATE INDEX IF NOT EXISTS idx_automation_trigger_events_prune
    ON automation_trigger_events (status, updated_at);

CREATE INDEX IF NOT EXISTS idx_automation_trigger_events_tenant
    ON automation_trigger_events (tenant_id, created_at DESC);

-- =============================================================================
-- 2. RUN LOG (observable: "did my rule run, when, and why did nothing happen?")
-- =============================================================================
CREATE TABLE IF NOT EXISTS automation_runs (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- History outlives the rule: deleting an automation detaches its runs
    -- (SET NULL) instead of erasing the audit trail.
    automation_id     UUID REFERENCES automations(id) ON DELETE SET NULL,
    -- Snapshot so a run stays readable after the rule is gone/renamed.
    automation_name   TEXT NOT NULL,
    tenant_id         VARCHAR(26) NOT NULL,
    -- The stored trigger kind (`trigger_config->>'type'`) exactly as written;
    -- unsupported kinds are recorded here and explained in skip_reason.
    trigger_kind      TEXT NOT NULL,
    -- The normalized source event type when the trigger resolved to one
    -- (e.g. 'contact.created'), NULL otherwise.
    trigger_event_type TEXT,
    -- Layer 2 of the idempotency identity (see header).
    trigger_event_key TEXT NOT NULL,
    source_event_id   UUID REFERENCES automation_trigger_events(id) ON DELETE SET NULL,
    status            TEXT NOT NULL DEFAULT 'running'
                      CHECK (status IN ('running', 'succeeded', 'skipped', 'failed')),
    -- TRUE when the failure is a retryable deferral (quota/metering/
    -- suppression-store unavailability); FALSE for terminal outcomes.
    retryable         BOOLEAN NOT NULL DEFAULT FALSE,
    skip_reason       TEXT,
    error             TEXT,
    started_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finished_at       TIMESTAMPTZ,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_automation_runs_identity
    ON automation_runs (tenant_id, automation_id, trigger_event_key);

CREATE INDEX IF NOT EXISTS idx_automation_runs_automation
    ON automation_runs (automation_id, started_at DESC);

CREATE INDEX IF NOT EXISTS idx_automation_runs_tenant
    ON automation_runs (tenant_id, started_at DESC);

-- =============================================================================
-- 3. PER-ACTION LOG (what each action did: sent / skipped why / failed how)
-- =============================================================================
CREATE TABLE IF NOT EXISTS automation_run_actions (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    run_id         UUID NOT NULL REFERENCES automation_runs(id) ON DELETE CASCADE,
    tenant_id      VARCHAR(26) NOT NULL,
    action_index   INTEGER NOT NULL,
    action_type    TEXT NOT NULL,
    status         TEXT NOT NULL
                   CHECK (status IN ('succeeded', 'skipped', 'failed', 'unsupported')),
    -- skipped/unsupported: the product-readable reason ('suppressed',
    -- 'condition_not_met', 'unsupported action kind ...', ...).
    reason         TEXT,
    error          TEXT,
    retryable      BOOLEAN NOT NULL DEFAULT FALSE,
    attempts       INTEGER NOT NULL DEFAULT 0,
    -- The enqueued artefacts (send_email actions): messages.id + email_queue.id.
    message_id     UUID,
    queue_id       UUID,
    -- The admission usage-event id the send reserved under (observability).
    quota_event_id UUID,
    detail         JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- One row per action per run; a resumed run updates its row, never duplicates it.
CREATE UNIQUE INDEX IF NOT EXISTS uq_automation_run_actions_index
    ON automation_run_actions (run_id, action_index);

CREATE INDEX IF NOT EXISTS idx_automation_run_actions_run
    ON automation_run_actions (run_id, action_index);

CREATE INDEX IF NOT EXISTS idx_automation_run_actions_tenant
    ON automation_run_actions (tenant_id, created_at DESC);

-- =============================================================================
-- 4. EVENT PRODUCERS (canonical schema emits the events the product stores)
-- =============================================================================

-- 4a. contacts -> contact.created / contact.updated / contact.tag_added.
--
-- Defensive by construction: every statement is a single INSERT ... ON
-- CONFLICT DO NOTHING against a table with no foreign keys back to contacts,
-- and the function is wrapped so an unexpected failure logs a WARNING and lets
-- the contact write proceed. Automations must never be able to break the
-- product's contact writes.
CREATE OR REPLACE FUNCTION automation_emit_contact_event() RETURNS TRIGGER AS $$
DECLARE
    added_tags JSONB;
    stamp_us   BIGINT;
BEGIN
    -- Executor-driven contact writes (an `add_tag`/`remove_tag` action) set
    -- this transaction-local flag so a tag action can never feed itself or
    -- another rule in a cascade. Everything else leaves the flag unset.
    IF current_setting('apexmail.automation_write', true) = 'on' THEN
        RETURN NEW;
    END IF;

    IF TG_OP = 'INSERT' THEN
        INSERT INTO automation_trigger_events
            (tenant_id, event_type, event_key, contact_id, payload)
        VALUES (
            NEW.tenant_id,
            'contact.created',
            'contact.created:' || NEW.id::text,
            NEW.id,
            jsonb_build_object(
                'email', NEW.email,
                'name', NEW.name,
                'status', NEW.status,
                'tags', COALESCE(NEW.tags, '[]'::jsonb)
            )
        )
        ON CONFLICT (tenant_id, event_key) DO NOTHING;
        RETURN NEW;
    END IF;

    -- UPDATE: one stable microsecond stamp shared by both event keys.
    stamp_us := (EXTRACT(EPOCH FROM NEW.updated_at) * 1000000)::BIGINT;

    INSERT INTO automation_trigger_events
        (tenant_id, event_type, event_key, contact_id, payload)
    VALUES (
        NEW.tenant_id,
        'contact.updated',
        'contact.updated:' || NEW.id::text || ':' || stamp_us::text,
        NEW.id,
        jsonb_build_object(
            'email', NEW.email,
            'name', NEW.name,
            'status', NEW.status,
            'tags', COALESCE(NEW.tags, '[]'::jsonb)
        )
    )
    ON CONFLICT (tenant_id, event_key) DO NOTHING;

    -- Tag delta: elements present in NEW.tags and absent from OLD.tags.
    IF COALESCE(NEW.tags, '[]'::jsonb) IS DISTINCT FROM COALESCE(OLD.tags, '[]'::jsonb) THEN
        SELECT COALESCE(jsonb_agg(t.value), '[]'::jsonb)
          INTO added_tags
          FROM jsonb_array_elements_text(COALESCE(NEW.tags, '[]'::jsonb)) AS t(value)
         WHERE NOT (COALESCE(OLD.tags, '[]'::jsonb) @> jsonb_build_array(t.value));

        IF jsonb_array_length(added_tags) > 0 THEN
            INSERT INTO automation_trigger_events
                (tenant_id, event_type, event_key, contact_id, payload)
            VALUES (
                NEW.tenant_id,
                'contact.tag_added',
                'contact.tag_added:' || NEW.id::text || ':' || stamp_us::text,
                NEW.id,
                jsonb_build_object(
                    'email', NEW.email,
                    'name', NEW.name,
                    'status', NEW.status,
                    'tags', COALESCE(NEW.tags, '[]'::jsonb),
                    'tags_added', added_tags
                )
            )
            ON CONFLICT (tenant_id, event_key) DO NOTHING;
        END IF;
    END IF;

    RETURN NEW;
EXCEPTION WHEN OTHERS THEN
    RAISE WARNING 'automation_emit_contact_event failed for contact %: %', NEW.id, SQLERRM;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_automation_contact_event ON contacts;
CREATE TRIGGER trg_automation_contact_event
    AFTER INSERT OR UPDATE ON contacts
    FOR EACH ROW EXECUTE FUNCTION automation_emit_contact_event();

-- 4b. inbound_messages -> message.received (1:1 inbound mail).
--
-- Rows with no tenant (unroutable/spam) or no sender are not events.
CREATE OR REPLACE FUNCTION automation_emit_inbound_event() RETURNS TRIGGER AS $$
BEGIN
    IF NEW.tenant_id IS NULL
       OR NEW.from_email IS NULL
       OR btrim(NEW.from_email) = '' THEN
        RETURN NEW;
    END IF;

    INSERT INTO automation_trigger_events
        (tenant_id, event_type, event_key, recipient_email, payload)
    VALUES (
        NEW.tenant_id,
        'message.received',
        'message.received:' || NEW.id::text,
        lower(btrim(NEW.from_email)),
        jsonb_build_object(
            'from_email', NEW.from_email,
            'to_email', NEW.to_email,
            'subject', NEW.subject,
            'message_id_header', NEW.message_id_header,
            -- Bounded: the inbox row is an event, not a message archive.
            'body_text', left(COALESCE(NEW.body_text, ''), 4096)
        )
    )
    ON CONFLICT (tenant_id, event_key) DO NOTHING;

    RETURN NEW;
EXCEPTION WHEN OTHERS THEN
    RAISE WARNING 'automation_emit_inbound_event failed for inbound message %: %', NEW.id, SQLERRM;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_automation_inbound_event ON inbound_messages;
CREATE TRIGGER trg_automation_inbound_event
    AFTER INSERT ON inbound_messages
    FOR EACH ROW EXECUTE FUNCTION automation_emit_inbound_event();
