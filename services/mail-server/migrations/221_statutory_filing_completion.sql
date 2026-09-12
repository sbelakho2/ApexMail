-- Migration 221: statutory filing completion.
--
-- Closes the remaining statutory filing gaps left by migrations 219
-- (OSS/VD scaffold) and 220 (accounting core):
--
--   1. ANNUAL REPORT FROM THE CLOSED LEDGER. Migration 220's views are the
--      only sanctioned read surface for filing code. An annual report is a
--      legal act with three distinct states — generated (machine), management
--      approval (human, authenticated, timestamped) and submission (human,
--      with an authority receipt). Generation must never imply approval or
--      submission; the CHECK constraints below make those states
--      unrepresentable without their evidence.
--   2. STATUTORY OBLIGATION SCHEDULER. Obligations are derived from entity
--      facts (VAT/VD registration, employer status, OSS registration,
--      financial-year end) and dated through ONE Estonian business calendar;
--      the calendar version that produced each due date is recorded for
--      audit.
--   3. FILING SUBMISSION TRANSPORT EVIDENCE. VD/OSS returns may be sent by a
--      configured machine client, or — where no machine API exists — the
--      exact submission package is persisted and a mandatory authenticated
--      human task is opened. Acknowledgement is receipt-driven: a receipt
--      row is the only evidence a return may be marked acknowledged on.
--
-- Nothing here fabricates a submission or an acknowledgement. Statuses only
-- move when the corresponding evidence row exists.

-- ===========================================================================
-- 1. Versioned Estonian statutory calendar registry
-- ===========================================================================
--
-- The holiday rules themselves are computed in Rust
-- (compliance::statutory_calendar, version EE-2025.1: fixed public holidays
-- plus Easter-derived Good Friday / Easter Sunday / Pentecost). This table
-- records WHICH rule version each derived obligation was dated with, so a
-- later rule revision is auditable rather than silently rewriting history.

CREATE TABLE IF NOT EXISTS statutory_calendars (
    version         TEXT PRIMARY KEY,
    jurisdiction    CHAR(2) NOT NULL DEFAULT 'EE',
    description     TEXT NOT NULL,
    effective_from  DATE NOT NULL,
    effective_to    DATE,
    -- Machine-readable copy of the rule set the version pins (holiday list
    -- for the covered years, working-day rule, weekend definition).
    rules           JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (effective_to IS NULL OR effective_to >= effective_from)
);

INSERT INTO statutory_calendars (version, description, effective_from, rules)
VALUES (
    'EE-2025.1',
    'Estonian public holidays (riigipühad): fixed dates + Easter-derived Good Friday, Easter Sunday and Pentecost; Saturday/Sunday non-working; a due date on a non-working day moves to the next working day.',
    '2025-01-01',
    '{
       "weekend": [6, 7],
       "fixed_holidays": [
         {"month": 1,  "day": 1,  "name": "uusaasta"},
         {"month": 2,  "day": 24, "name": "iseseisvuspäev"},
         {"month": 5,  "day": 1,  "name": "kevadpüha"},
         {"month": 6,  "day": 23, "name": "võidupüha"},
         {"month": 6,  "day": 24, "name": "jaanipäev"},
         {"month": 8,  "day": 20, "name": "taasiseseisvumispäev"},
         {"month": 12, "day": 24, "name": "jõululaupäev"},
         {"month": 12, "day": 25, "name": "esimene jõulupüha"},
         {"month": 12, "day": 26, "name": "teine jõulupüha"}
       ],
       "easter_derived": ["good_friday", "easter_sunday", "pentecost"],
       "due_date_rule": "legal_due_date if working day, else next working day"
     }'::jsonb
)
ON CONFLICT (version) DO NOTHING;

COMMENT ON TABLE statutory_calendars IS
    'Versioned statutory calendars. Obligations record the version used for their due date; revisions never rewrite dated history.';

-- ===========================================================================
-- 2. Entity filing facts (obligations derive from these, never from a
--    hard-coded "annual report = June 30")
-- ===========================================================================

CREATE TABLE IF NOT EXISTS legal_entity_filing_facts (
    legal_entity_id        UUID PRIMARY KEY
        REFERENCES legal_entities(id) ON DELETE RESTRICT,
    -- Date the entity entered the Estonian VAT register (KMD + VD duties).
    vat_registered_from    DATE,
    -- Optional override when VD reporting starts later than VAT registration.
    vd_reporting_from      DATE,
    -- Date the entity first had employees (TSD duty).
    employer_since         DATE,
    -- Date the entity registered for the OSS Union scheme (quarterly OSS).
    oss_registered_from    DATE,
    -- Financial year end month (1..12); drives the annual-report deadline
    -- (six months after the financial year end, per ÄS §179).
    fiscal_year_end_month  SMALLINT NOT NULL DEFAULT 12
        CHECK (fiscal_year_end_month BETWEEN 1 AND 12),
    -- Authority the annual report is submitted to.
    annual_report_authority TEXT NOT NULL DEFAULT 'ariregister',
    created_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (vd_reporting_from IS NULL OR vat_registered_from IS NULL
           OR vd_reporting_from >= vat_registered_from)
);

COMMENT ON TABLE legal_entity_filing_facts IS
    'Facts that create statutory filing obligations. The scheduler derives obligations from these; no deadline constant is hard-coded in code.';

-- ===========================================================================
-- 3. Derived statutory obligations
-- ===========================================================================

CREATE TABLE IF NOT EXISTS statutory_obligations (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    legal_entity_id  UUID NOT NULL REFERENCES legal_entities(id) ON DELETE RESTRICT,
    obligation_type  TEXT NOT NULL CHECK (obligation_type IN (
        'kmd',            -- VAT return, monthly (KMS §27)
        'tsd',            -- payroll/social tax return, monthly (TuMS §54)
        'vd',             -- intra-Community supply report, monthly
        'oss_union',      -- OSS Union scheme return, quarterly
        'annual_report'   -- annual report (ÄS §179)
    )),
    period_start     DATE NOT NULL,
    period_end       DATE NOT NULL,
    period_label     TEXT NOT NULL,
    -- The date the law states, before the working-day adjustment.
    legal_due_date   DATE NOT NULL,
    -- The date filing is actually due after the calendar adjustment.
    due_date         DATE NOT NULL,
    calendar_version TEXT NOT NULL REFERENCES statutory_calendars(version),
    status           TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'filed', 'waived', 'overdue')),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (period_end >= period_start),
    -- The adjustment only ever moves a deadline FORWARD to the next working
    -- day; it can never pull a deadline earlier.
    CHECK (due_date >= legal_due_date),
    -- Idempotent horizon sync: re-deriving the same period updates the row.
    UNIQUE (legal_entity_id, obligation_type, period_start)
);

CREATE INDEX IF NOT EXISTS idx_statutory_obligations_due
    ON statutory_obligations (legal_entity_id, due_date)
    WHERE status = 'pending';

COMMENT ON TABLE statutory_obligations IS
    'Statutory obligations derived from legal_entity_filing_facts, dated through the versioned Estonian calendar. KMD/TSD/VD/OSS/annual-report deadlines all share statutory_calendar::statutory_due_date.';

-- ===========================================================================
-- 4. Annual reports (bilanss + kasumiaruanne) from CLOSED ledger periods
-- ===========================================================================
--
-- Values are derived from migration 220's views (v_accounting_trial_balance,
-- v_accounting_period_movement, v_accounting_posted_entries) — posted journal
-- lines only. The state machine is draft -> management_approved -> submitted:
--
--   * draft               generation only; no approval fields may be set.
--   * management_approved requires an authenticated approver + timestamp.
--   * submitted           requires the approval AND an authority receipt
--                         reference plus the submitting actor.
--
-- Regeneration is only possible while the report is a draft; an approved or
-- submitted report is a human legal act and is frozen.

CREATE TABLE IF NOT EXISTS annual_reports (
    id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    legal_entity_id          UUID NOT NULL REFERENCES legal_entities(id) ON DELETE RESTRICT,
    fiscal_period_id         UUID NOT NULL REFERENCES fiscal_periods(id) ON DELETE RESTRICT,
    fiscal_year              INTEGER NOT NULL,
    period_start             DATE NOT NULL,
    period_end               DATE NOT NULL,
    status                   TEXT NOT NULL DEFAULT 'draft'
        CHECK (status IN ('draft', 'management_approved', 'submitted')),
    generated_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    generated_by             TEXT NOT NULL,
    -- Snapshot provenance of the derivation.
    ledger_entry_count       BIGINT NOT NULL DEFAULT 0 CHECK (ledger_entry_count >= 0),
    ledger_hash              TEXT NOT NULL CHECK (ledger_hash ~ '^[0-9a-f]{64}$'),
    -- Bilanss / kasumiaruanne aggregates and the full structured document.
    balance_sheet            JSONB NOT NULL DEFAULT '{}'::jsonb,
    income_statement         JSONB NOT NULL DEFAULT '{}'::jsonb,
    structured_document      JSONB NOT NULL DEFAULT '{}'::jsonb,
    -- Well-formed XBRL instance container (see compliance::annual_report for
    -- the documented namespace/taxonomy caveat).
    xbrl_instance            TEXT NOT NULL,
    balance_check_ok         BOOLEAN NOT NULL DEFAULT FALSE,
    balance_difference_cents BIGINT NOT NULL DEFAULT 0,
    -- Human legal acts (nullable until performed).
    approved_by              TEXT,
    approved_at              TIMESTAMPTZ,
    submitted_by             TEXT,
    submitted_at             TIMESTAMPTZ,
    authority_receipt_reference TEXT,
    authority_receipt_payload   JSONB,
    retention_class          TEXT NOT NULL DEFAULT 'legal_7y'
        REFERENCES accounting_retention_classes(code),
    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (legal_entity_id, fiscal_period_id),
    CHECK (period_end >= period_start),
    CONSTRAINT annual_reports_draft_has_no_human_act CHECK (
        status <> 'draft' OR (
            approved_by IS NULL AND approved_at IS NULL
            AND submitted_by IS NULL AND submitted_at IS NULL
            AND authority_receipt_reference IS NULL
        )
    ),
    CONSTRAINT annual_reports_approval_requires_actor CHECK (
        status <> 'management_approved' OR (
            approved_by IS NOT NULL AND approved_at IS NOT NULL
            AND submitted_by IS NULL AND submitted_at IS NULL
            AND authority_receipt_reference IS NULL
        )
    ),
    CONSTRAINT annual_reports_submission_requires_receipt CHECK (
        status <> 'submitted' OR (
            approved_by IS NOT NULL AND approved_at IS NOT NULL
            AND submitted_by IS NOT NULL AND submitted_at IS NOT NULL
            AND authority_receipt_reference IS NOT NULL
        )
    )
);

CREATE INDEX IF NOT EXISTS idx_annual_reports_status
    ON annual_reports (legal_entity_id, status, period_end DESC);

-- Per-account derivation snapshot (every value traces to one posted ledger
-- account balance in the closed period).
CREATE TABLE IF NOT EXISTS annual_report_lines (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    report_id       UUID NOT NULL REFERENCES annual_reports(id) ON DELETE CASCADE,
    statement       TEXT NOT NULL CHECK (statement IN ('balance_sheet', 'income_statement')),
    section         TEXT NOT NULL CHECK (section IN (
        'assets', 'liabilities', 'equity', 'revenue', 'expenses'
    )),
    account_id      UUID NOT NULL REFERENCES chart_of_accounts(id) ON DELETE RESTRICT,
    account_code    TEXT NOT NULL,
    account_name    TEXT NOT NULL,
    account_type    TEXT NOT NULL,
    account_role    TEXT,
    debit_cents     BIGINT NOT NULL DEFAULT 0,
    credit_cents    BIGINT NOT NULL DEFAULT 0,
    balance_cents   BIGINT NOT NULL DEFAULT 0,
    retention_class TEXT NOT NULL DEFAULT 'legal_7y'
        REFERENCES accounting_retention_classes(code),
    UNIQUE (report_id, account_id)
);

CREATE INDEX IF NOT EXISTS idx_annual_report_lines_report
    ON annual_report_lines (report_id, statement, account_code);

-- Append-only audit of the state machine (generation / approval / submission).
CREATE TABLE IF NOT EXISTS annual_report_events (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    report_id   UUID NOT NULL REFERENCES annual_reports(id) ON DELETE RESTRICT,
    event       TEXT NOT NULL CHECK (event IN (
        'generated', 'management_approved', 'submitted'
    )),
    actor       TEXT NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    detail      JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_annual_report_events_report
    ON annual_report_events (report_id, occurred_at);

COMMENT ON TABLE annual_reports IS
    'Estonian annual report (majandusaasta aruanne) derived from CLOSED fiscal periods'' posted journal lines via the accounting-core views. draft -> management_approved (authenticated approver) -> submitted (authority receipt).';

-- ===========================================================================
-- 5. VD/OSS submission transport evidence
-- ===========================================================================

-- The exact package handed to the machine transport or the human operator.
-- A package row is created before any submission attempt; the payload hash is
-- the identity against which receipts are matched.
CREATE TABLE IF NOT EXISTS filing_submission_packages (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    return_kind       TEXT NOT NULL CHECK (return_kind IN ('oss', 'vd')),
    return_id         UUID NOT NULL,
    period            TEXT NOT NULL,
    payload           JSONB NOT NULL,
    payload_sha256    TEXT NOT NULL CHECK (payload_sha256 ~ '^[0-9a-f]{64}$'),
    transport         TEXT NOT NULL DEFAULT 'human_task'
        CHECK (transport IN ('machine', 'human_task')),
    status            TEXT NOT NULL DEFAULT 'queued' CHECK (status IN (
        'queued', 'sent', 'failed', 'awaiting_human'
    )),
    endpoint          TEXT,
    external_reference TEXT,
    attempts          INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    error             TEXT,
    retention_class   TEXT NOT NULL DEFAULT 'legal_7y'
        REFERENCES accounting_retention_classes(code),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    sent_at           TIMESTAMPTZ,
    -- Exact-package idempotency: the same payload for the same return can
    -- only produce one package row.
    UNIQUE (return_kind, return_id, payload_sha256)
);

CREATE INDEX IF NOT EXISTS idx_filing_submission_packages_return
    ON filing_submission_packages (return_kind, return_id, created_at DESC);

-- Mandatory authenticated human task where no machine API exists (the same
-- pattern as breach_authority_tasks, migration 213). Completion requires an
-- authenticated actor and a completion timestamp.
CREATE TABLE IF NOT EXISTS filing_human_tasks (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    package_id          UUID NOT NULL REFERENCES filing_submission_packages(id) ON DELETE RESTRICT,
    return_kind         TEXT NOT NULL CHECK (return_kind IN ('oss', 'vd')),
    return_id           UUID NOT NULL,
    status              TEXT NOT NULL DEFAULT 'open'
        CHECK (status IN ('open', 'completed', 'cancelled')),
    required_role       TEXT NOT NULL DEFAULT 'tax_filer',
    task                TEXT NOT NULL,
    due_at              TIMESTAMPTZ NOT NULL,
    authenticated_actor TEXT,
    completed_at        TIMESTAMPTZ,
    evidence            JSONB,
    retention_class     TEXT NOT NULL DEFAULT 'legal_7y'
        REFERENCES accounting_retention_classes(code),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT filing_human_tasks_completion_requires_actor CHECK (
        status <> 'completed' OR (authenticated_actor IS NOT NULL AND completed_at IS NOT NULL)
    )
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_filing_human_tasks_open
    ON filing_human_tasks (return_kind, return_id) WHERE status = 'open';

-- Receipts as received from the portal/authority (or recorded from a human
-- operator's evidence). An acknowledgement can only be recorded by inserting
-- this row and then moving the return; no receipt means no acknowledgement.
CREATE TABLE IF NOT EXISTS filing_receipts (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    package_id       UUID NOT NULL REFERENCES filing_submission_packages(id) ON DELETE RESTRICT,
    return_kind      TEXT NOT NULL CHECK (return_kind IN ('oss', 'vd')),
    return_id        UUID NOT NULL,
    receipt_type     TEXT NOT NULL CHECK (receipt_type IN (
        'submission', 'acknowledgement', 'rejection'
    )),
    receipt_reference TEXT NOT NULL,
    receipt_payload  JSONB NOT NULL DEFAULT '{}'::jsonb,
    -- sha256 of the exact receipt payload as received (tamper evidence).
    payload_sha256   TEXT NOT NULL CHECK (payload_sha256 ~ '^[0-9a-f]{64}$'),
    received_at      TIMESTAMPTZ NOT NULL,
    recorded_by      TEXT NOT NULL,
    retention_class  TEXT NOT NULL DEFAULT 'legal_7y'
        REFERENCES accounting_retention_classes(code),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (return_kind, return_id, receipt_reference)
);

CREATE INDEX IF NOT EXISTS idx_filing_receipts_return
    ON filing_receipts (return_kind, return_id, receipt_type, received_at DESC);

COMMENT ON TABLE filing_submission_packages IS
    'Exact VD/OSS submission packages. Machine transport requires an explicit endpoint+credential configuration; otherwise the package is persisted and a mandatory authenticated human task is opened.';
COMMENT ON TABLE filing_receipts IS
    'Receipt evidence for VD/OSS filings. A return may only become acknowledged through a recorded acknowledgement receipt matched to its package hash.';

-- ===========================================================================
-- 6. Retention and immutability guards on the new statutory records
-- ===========================================================================

-- 6a. Derivation-snapshot lines: they belong to the report's DRAFT phase
-- (regeneration replaces them) and are frozen together with the human legal
-- acts. Deleting the generic legal_7y retention guard's protection for them
-- is deliberate: the retention duty attaches to the approved report, and a
-- draft's snapshot is mutable derivation state, not a filed record.
CREATE OR REPLACE FUNCTION annual_report_lines_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    parent_id     UUID;
    parent_status TEXT;
BEGIN
    parent_id := CASE WHEN TG_OP = 'DELETE' THEN OLD.report_id ELSE NEW.report_id END;

    SELECT status INTO parent_status FROM annual_reports WHERE id = parent_id;

    IF parent_status IS NULL OR parent_status <> 'draft' THEN
        RAISE EXCEPTION USING
            ERRCODE = 'object_not_in_prerequisite_state',
            MESSAGE = format(
                'annual report %s is %s; its derivation snapshot is immutable',
                parent_id, COALESCE(parent_status, 'missing')
            ),
            HINT = 'Only a draft report may be regenerated; approved/submitted reports are human legal acts.';
    END IF;

    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END;
$$;

DROP TRIGGER IF EXISTS trg_annual_report_lines_guard ON annual_report_lines;
CREATE TRIGGER trg_annual_report_lines_guard
    BEFORE INSERT OR UPDATE OR DELETE ON annual_report_lines
    FOR EACH ROW
    EXECUTE FUNCTION annual_report_lines_guard();

-- 6b. Retention guard on the statutory records themselves.
DO $$
DECLARE
    tbl TEXT;
BEGIN
    FOREACH tbl IN ARRAY ARRAY[
        'annual_reports',
        'filing_submission_packages', 'filing_human_tasks', 'filing_receipts'
    ]
    LOOP
        EXECUTE format('DROP TRIGGER IF EXISTS trg_%s_retention ON %I', tbl, tbl);
        EXECUTE format(
            'CREATE TRIGGER trg_%s_retention BEFORE DELETE ON %I '
            'FOR EACH ROW EXECUTE FUNCTION accounting_retention_delete_guard()',
            tbl, tbl
        );
    END LOOP;
END;
$$;

-- Deploy-time sanity: the calendar version the Rust module pins must exist.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM statutory_calendars WHERE version = 'EE-2025.1') THEN
        RAISE EXCEPTION 'migration 221: statutory_calendars missing EE-2025.1';
    END IF;
END;
$$;
