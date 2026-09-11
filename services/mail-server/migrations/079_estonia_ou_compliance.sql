-- 079: Estonia OÜ legal compliance — submission + deadline tracking.
--
-- Tracks all mandatory Estonian OÜ filings and their deadlines:
--   1. Annual Report (Majandusaasta aruanne) — due June 30
--   2. VAT Declaration (Käibedeklaratsioon) — due 20th
--   3. Income Tax Declaration (Tulumaks) — due 10th
--   4. Social Tax Declaration (TSD) — due 10th
--   5. Annual Statistical Reports — Statistics Estonia
--
-- Company: BEL CONSULTING OÜ (Registry Code 16588745), Tallinn.

-- ─── Compliance submissions ─────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS compliance_submissions (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    submission_type TEXT        NOT NULL,
        -- annual_report | vat_declaration | income_tax | social_tax | statistical_report
    period_start    DATE        NOT NULL,
    period_end      DATE        NOT NULL,
    tax_year        INT         NOT NULL,
    tax_month       INT,                        -- only for monthly submissions
    status          TEXT        NOT NULL DEFAULT 'draft'
        CHECK (status IN ('draft', 'generated', 'submitted', 'acknowledged', 'overdue', 'error')),
    submitted_at    TIMESTAMPTZ,
    document_json   JSONB       NOT NULL DEFAULT '{}'::jsonb,
    document_url    TEXT,
    filing_reference TEXT,
    notes           TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- One submission per type + period combination
CREATE UNIQUE INDEX IF NOT EXISTS idx_compliance_submissions_unique
    ON compliance_submissions (submission_type, tax_year, COALESCE(tax_month, 0));

CREATE INDEX IF NOT EXISTS idx_compliance_submissions_status
    ON compliance_submissions (submission_type, status);

CREATE INDEX IF NOT EXISTS idx_compliance_submissions_due
    ON compliance_submissions (status)
    WHERE status IN ('draft', 'overdue');

CREATE INDEX IF NOT EXISTS idx_compliance_submissions_period
    ON compliance_submissions (tax_year, tax_month);

-- ─── Compliance deadlines ───────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS compliance_deadlines (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    deadline_type   TEXT        NOT NULL,
        -- annual_report | vat_declaration | income_tax | social_tax | statistical_report
    label           TEXT        NOT NULL,
    period_start    DATE        NOT NULL,
    period_end      DATE        NOT NULL,
    due_date        DATE        NOT NULL,
    status          TEXT        NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'filed', 'overdue', 'exempt')),
    submission_id   UUID        REFERENCES compliance_submissions(id),
    reminded_7d_at  TIMESTAMPTZ,
    reminded_1d_at  TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_compliance_deadlines_unique
    ON compliance_deadlines (deadline_type, due_date);

CREATE INDEX IF NOT EXISTS idx_compliance_deadlines_due
    ON compliance_deadlines (due_date, status)
    WHERE status = 'pending';

CREATE INDEX IF NOT EXISTS idx_compliance_deadlines_reminder
    ON compliance_deadlines (status, due_date)
    WHERE (reminded_7d_at IS NULL OR reminded_1d_at IS NULL);
