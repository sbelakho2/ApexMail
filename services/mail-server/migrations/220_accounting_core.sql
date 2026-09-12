-- Migration 220: statutory accounting core.
--
-- Finding: `compliance/src/estonia_ou.rs` generated annual reports/VAT
-- declarations straight from operational tables (`invoices`, `payroll_records`,
-- `operating_costs`) with a hard-coded company identity and no accounting
-- foundation. Estonian accounting law (Raamatupidamise seadus / RPS §12,
-- Maksukorralduse seadus / MKS §25) requires source documents and accounting
-- registers (journals, ledgers) to be retained for seven years.
--
-- This migration creates the first-class accounting domain the generators
-- must derive from. Structural invariants:
--
--   1. SUM(debit) == SUM(credit) for every posted journal.
--      Enforced by a DEFERRABLE INITIALLY DEFERRED constraint trigger
--      (trg_journal_entries_balanced). A deferred constraint trigger is
--      chosen over "the posting function asserts it" because it protects
--      EVERY writer — psql, migration backfills, future services — not only
--      callers of the Rust API. The posting function ALSO asserts the sum
--      before writing (fail fast, typed error), but the database is the
--      backstop: a transaction that commits an unbalanced posted entry
--      cannot exist.
--   2. Posted entries are immutable. BEFORE UPDATE/DELETE triggers raise
--      (accounting_journal_entry_guard / accounting_journal_line_guard);
--      corrections are reversal/adjusting entries only.
--   3. Every entry carries a `source_hash` (sha256 hex of the evidence).
--   4. Periods become locked after close; posting into a closed/locked
--      period raises (accounting_journal_entry_guard validates the period
--      status and that entry_date lies inside the period).
--   5. Idempotent posting: `journal_entries.idempotency_key` is UNIQUE and
--      `accounting_source_documents (source_type, source_table, source_id)`
--      is UNIQUE, so replaying a Stripe webhook / invoice finalization /
--      credit note posts exactly once (INSERT .. ON CONFLICT DO NOTHING).
--   6. Seven-year retention: every record table carries a `retention_class`
--      referencing `accounting_retention_classes`; a BEFORE DELETE guard
--      refuses deletion of legal_7y/legal_10y rows unless an explicit purge
--      session sets `apexmail.accounting.retention_override = 'on'`, so an
--      ordinary customer-deletion path cannot remove them by accident.
--
-- No runtime DDL is required by the application: everything below is
-- deploy-time schema. The `operating_costs` expense table referenced by
-- estonia_ou.rs is deployment-optional and deliberately NOT created here.

-- ===========================================================================
-- 0. Retention classes
-- ===========================================================================

CREATE TABLE IF NOT EXISTS accounting_retention_classes (
    code            TEXT PRIMARY KEY,
    description     TEXT NOT NULL,
    retention_years INTEGER NOT NULL CHECK (retention_years >= 0),
    legal_basis     TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO accounting_retention_classes (code, description, retention_years, legal_basis)
VALUES
    ('legal_7y', 'Statutory accounting records (source documents, journals, ledgers) — 7 years minimum',
     7, 'Estonian RPS §12; MKS §25'),
    ('legal_10y', 'Statutory records under a 10-year retention duty',
     10, 'Deployment-specific statutory duty'),
    ('operational', 'Operational records without a statutory retention floor',
     0, NULL)
ON CONFLICT (code) DO NOTHING;

-- ===========================================================================
-- 1. Legal entities (the DB-backed replacement for the hard-coded identity)
-- ===========================================================================

CREATE TABLE IF NOT EXISTS legal_entities (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    legal_name              TEXT NOT NULL,
    trading_name            TEXT,
    registry_code           TEXT NOT NULL UNIQUE,
    vat_number              TEXT,
    address_line1           TEXT,
    city                    TEXT,
    postal_code             TEXT,
    country_code            CHAR(2) NOT NULL DEFAULT 'EE',
    default_currency        CHAR(3) NOT NULL DEFAULT 'EUR',
    fiscal_year_start_month SMALLINT NOT NULL DEFAULT 1
        CHECK (fiscal_year_start_month BETWEEN 1 AND 12),
    is_default              BOOLEAN NOT NULL DEFAULT FALSE,
    retention_class         TEXT NOT NULL DEFAULT 'legal_7y'
        REFERENCES accounting_retention_classes(code),
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Exactly one default entity; adapters resolve it when no explicit entity
-- is configured.
CREATE UNIQUE INDEX IF NOT EXISTS uq_legal_entities_default
    ON legal_entities (is_default) WHERE is_default;

-- ===========================================================================
-- 2. Fiscal periods
-- ===========================================================================

CREATE TABLE IF NOT EXISTS fiscal_periods (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    legal_entity_id UUID NOT NULL REFERENCES legal_entities(id) ON DELETE RESTRICT,
    period_type     TEXT NOT NULL DEFAULT 'month'
        CHECK (period_type IN ('month', 'quarter', 'year', 'custom')),
    label           TEXT NOT NULL,
    start_date      DATE NOT NULL,
    end_date        DATE NOT NULL,
    status          TEXT NOT NULL DEFAULT 'open'
        CHECK (status IN ('open', 'closed', 'locked')),
    opened_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    closed_at       TIMESTAMPTZ,
    locked_at       TIMESTAMPTZ,
    closed_by       TEXT,
    locked_by       TEXT,
    retention_class TEXT NOT NULL DEFAULT 'legal_7y'
        REFERENCES accounting_retention_classes(code),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Derived flags so "is this period closed/locked?" is a plain column
    -- read for reporting code.
    closed          BOOLEAN GENERATED ALWAYS AS (status IN ('closed', 'locked')) STORED,
    locked          BOOLEAN GENERATED ALWAYS AS (status = 'locked') STORED,
    CHECK (end_date >= start_date),
    UNIQUE (legal_entity_id, start_date, end_date)
);

CREATE INDEX IF NOT EXISTS idx_fiscal_periods_entity_dates
    ON fiscal_periods (legal_entity_id, start_date DESC);
CREATE INDEX IF NOT EXISTS idx_fiscal_periods_open
    ON fiscal_periods (legal_entity_id, start_date, end_date) WHERE status = 'open';

-- ===========================================================================
-- 3. Chart of accounts
-- ===========================================================================

CREATE TABLE IF NOT EXISTS chart_of_accounts (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    legal_entity_id UUID NOT NULL REFERENCES legal_entities(id) ON DELETE RESTRICT,
    code            TEXT NOT NULL,
    name            TEXT NOT NULL,
    account_type    TEXT NOT NULL
        CHECK (account_type IN ('asset', 'liability', 'equity', 'revenue', 'expense')),
    normal_balance  TEXT NOT NULL CHECK (normal_balance IN ('debit', 'credit')),
    -- Semantic role adapters resolve accounts by (never by hard-coded
    -- numeric codes, which differ per entity).
    account_role    TEXT
        CHECK (account_role IS NULL OR account_role IN (
            'ar', 'ap', 'revenue', 'refunds', 'vat_output', 'vat_input',
            'bank', 'bank_clearing', 'stripe_clearing', 'stripe_fees',
            'wallet_liability', 'expense_default', 'payroll_expense',
            'net_wages_payable', 'income_tax_payable', 'social_tax_payable',
            'unemployment_payable', 'pension_payable', 'fx_gain', 'fx_loss',
            'depreciation_expense', 'accumulated_depreciation',
            'retained_earnings', 'suspense', 'other_income'
        )),
    vat_code        TEXT,
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (legal_entity_id, code)
);

-- One account per role per entity (roles drive automatic postings).
CREATE UNIQUE INDEX IF NOT EXISTS uq_chart_of_accounts_role
    ON chart_of_accounts (legal_entity_id, account_role)
    WHERE account_role IS NOT NULL AND is_active;

-- ===========================================================================
-- 4. Master data: customers / suppliers
-- ===========================================================================

CREATE TABLE IF NOT EXISTS customers (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    legal_entity_id  UUID NOT NULL REFERENCES legal_entities(id) ON DELETE RESTRICT,
    -- Platform tenant (VARCHAR(26), migration 064 shape) this customer
    -- corresponds to. NULL for walk-in/manual customers.
    tenant_id        VARCHAR(26),
    name             TEXT NOT NULL,
    registry_code    TEXT,
    vat_number       TEXT,
    -- PII: subject to GDPR erasure/anonymisation, but the row itself is a
    -- statutory counterparty record and must not be deleted.
    email            TEXT,
    country_code     CHAR(2),
    default_currency CHAR(3) NOT NULL DEFAULT 'EUR',
    retention_class  TEXT NOT NULL DEFAULT 'legal_7y'
        REFERENCES accounting_retention_classes(code),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (legal_entity_id, tenant_id)
);

CREATE TABLE IF NOT EXISTS suppliers (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    legal_entity_id  UUID NOT NULL REFERENCES legal_entities(id) ON DELETE RESTRICT,
    name             TEXT NOT NULL,
    registry_code    TEXT,
    vat_number       TEXT,
    email            TEXT,
    country_code     CHAR(2),
    default_currency CHAR(3) NOT NULL DEFAULT 'EUR',
    retention_class  TEXT NOT NULL DEFAULT 'legal_7y'
        REFERENCES accounting_retention_classes(code),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (legal_entity_id, registry_code)
);

-- ===========================================================================
-- 5. Source documents (idempotency anchor + evidence hash)
-- ===========================================================================

CREATE TABLE IF NOT EXISTS accounting_source_documents (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    legal_entity_id UUID NOT NULL REFERENCES legal_entities(id) ON DELETE RESTRICT,
    source_type     TEXT NOT NULL CHECK (source_type IN (
        'invoice', 'credit_note', 'credit_note_refund', 'stripe_settlement',
        'wallet_settlement', 'manual_settlement', 'expense',
        'bank_statement_line', 'payroll', 'tax', 'manual',
        'opening_balance', 'depreciation', 'fx_revaluation', 'reversal',
        'closing'
    )),
    -- Operational origin: (source_table, source_id) must name a REAL row,
    -- so every journal entry can be traced back to its evidence.
    source_table    TEXT NOT NULL,
    source_id       TEXT NOT NULL,
    -- sha256 hex of the canonical evidence payload. Replaying the same
    -- (source_type, source_table, source_id) with a different hash is
    -- refused by the posting API (divergent replay).
    source_hash     TEXT NOT NULL CHECK (source_hash ~ '^[0-9a-f]{64}$'),
    document_date   DATE NOT NULL,
    currency        CHAR(3) NOT NULL DEFAULT 'EUR',
    total_cents     BIGINT NOT NULL DEFAULT 0,
    payload         JSONB NOT NULL DEFAULT '{}'::jsonb,
    retention_class TEXT NOT NULL DEFAULT 'legal_7y'
        REFERENCES accounting_retention_classes(code),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- IDEMPOTENCY ANCHOR: the same source row can only ever be registered
    -- once, so a replayed webhook or re-finalized invoice cannot create a
    -- second document (and therefore cannot create a second posting).
    UNIQUE (source_type, source_table, source_id)
);

-- ===========================================================================
-- 6. Journals
-- ===========================================================================

CREATE SEQUENCE IF NOT EXISTS accounting_journal_entry_no_seq;

CREATE TABLE IF NOT EXISTS journal_entries (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    legal_entity_id     UUID NOT NULL REFERENCES legal_entities(id) ON DELETE RESTRICT,
    fiscal_period_id    UUID NOT NULL REFERENCES fiscal_periods(id) ON DELETE RESTRICT,
    entry_no            BIGINT NOT NULL DEFAULT nextval('accounting_journal_entry_no_seq'),
    entry_date          DATE NOT NULL,
    entry_type          TEXT NOT NULL DEFAULT 'standard' CHECK (entry_type IN (
        'standard', 'reversal', 'adjusting', 'opening', 'closing',
        'depreciation', 'payroll', 'tax'
    )),
    memo                TEXT NOT NULL DEFAULT '',
    source_document_id  UUID REFERENCES accounting_source_documents(id) ON DELETE RESTRICT,
    -- Every entry — including manual/adjusting ones — carries an evidence
    -- hash (sha256 hex over the source payload, or over the entry's own
    -- canonical content for manual entries).
    source_hash         TEXT NOT NULL CHECK (source_hash ~ '^[0-9a-f]{64}$'),
    -- Replay key: UNIQUE, so an adapter retry never double-posts.
    idempotency_key     TEXT NOT NULL,
    reversal_of_entry_id UUID REFERENCES journal_entries(id) ON DELETE RESTRICT,
    posted_at           TIMESTAMPTZ,
    posted_by           TEXT,
    retention_class     TEXT NOT NULL DEFAULT 'legal_7y'
        REFERENCES accounting_retention_classes(code),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (idempotency_key),
    CHECK (entry_type <> 'reversal' OR reversal_of_entry_id IS NOT NULL),
    CHECK (reversal_of_entry_id IS NULL OR entry_type IN ('reversal', 'adjusting'))
);

CREATE INDEX IF NOT EXISTS idx_journal_entries_entity_period
    ON journal_entries (legal_entity_id, fiscal_period_id, entry_date);
CREATE INDEX IF NOT EXISTS idx_journal_entries_posted
    ON journal_entries (posted_at) WHERE posted_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_journal_entries_source_document
    ON journal_entries (source_document_id) WHERE source_document_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_journal_entries_reversal
    ON journal_entries (reversal_of_entry_id) WHERE reversal_of_entry_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS journal_lines (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    entry_id        UUID NOT NULL REFERENCES journal_entries(id) ON DELETE CASCADE,
    line_no         INTEGER NOT NULL,
    account_id      UUID NOT NULL REFERENCES chart_of_accounts(id) ON DELETE RESTRICT,
    debit_cents     BIGINT NOT NULL DEFAULT 0 CHECK (debit_cents >= 0),
    credit_cents    BIGINT NOT NULL DEFAULT 0 CHECK (credit_cents >= 0),
    currency        CHAR(3) NOT NULL DEFAULT 'EUR',
    -- Tax evidence for VAT derivation (KMD): on VAT lines net_cents is the
    -- taxable base and vat_cents the tax amount; rate in basis points.
    net_cents       BIGINT CHECK (net_cents IS NULL OR net_cents >= 0),
    vat_cents       BIGINT CHECK (vat_cents IS NULL OR vat_cents >= 0),
    vat_rate_bp     INTEGER CHECK (vat_rate_bp IS NULL OR vat_rate_bp >= 0),
    vat_code        TEXT,
    description     TEXT NOT NULL DEFAULT '',
    retention_class TEXT NOT NULL DEFAULT 'legal_7y'
        REFERENCES accounting_retention_classes(code),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK ((debit_cents > 0) <> (credit_cents > 0)),
    UNIQUE (entry_id, line_no)
);

CREATE INDEX IF NOT EXISTS idx_journal_lines_account
    ON journal_lines (account_id);
CREATE INDEX IF NOT EXISTS idx_journal_lines_entry
    ON journal_lines (entry_id);
CREATE INDEX IF NOT EXISTS idx_journal_lines_vat
    ON journal_lines (vat_code) WHERE vat_code IS NOT NULL;

-- ===========================================================================
-- 7. Subledgers: AR / AP / bank
-- ===========================================================================

CREATE TABLE IF NOT EXISTS accounts_receivable (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    legal_entity_id    UUID NOT NULL REFERENCES legal_entities(id) ON DELETE RESTRICT,
    customer_id        UUID REFERENCES customers(id) ON DELETE RESTRICT,
    invoice_id         UUID NOT NULL UNIQUE,
    source_document_id UUID REFERENCES accounting_source_documents(id) ON DELETE RESTRICT,
    amount_cents       BIGINT NOT NULL CHECK (amount_cents >= 0),
    settled_cents      BIGINT NOT NULL DEFAULT 0 CHECK (settled_cents >= 0),
    currency           CHAR(3) NOT NULL DEFAULT 'EUR',
    due_date           DATE,
    status             TEXT NOT NULL DEFAULT 'open'
        CHECK (status IN ('open', 'partially_settled', 'settled', 'written_off')),
    retention_class    TEXT NOT NULL DEFAULT 'legal_7y'
        REFERENCES accounting_retention_classes(code),
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (settled_cents <= amount_cents)
);

CREATE INDEX IF NOT EXISTS idx_accounts_receivable_open
    ON accounts_receivable (legal_entity_id, status, due_date);

CREATE TABLE IF NOT EXISTS accounts_payable (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    legal_entity_id    UUID NOT NULL REFERENCES legal_entities(id) ON DELETE RESTRICT,
    supplier_id        UUID REFERENCES suppliers(id) ON DELETE RESTRICT,
    source_document_id UUID REFERENCES accounting_source_documents(id) ON DELETE RESTRICT,
    supplier_reference TEXT,
    amount_cents       BIGINT NOT NULL CHECK (amount_cents > 0),
    paid_cents         BIGINT NOT NULL DEFAULT 0 CHECK (paid_cents >= 0),
    currency           CHAR(3) NOT NULL DEFAULT 'EUR',
    due_date           DATE,
    status             TEXT NOT NULL DEFAULT 'open'
        CHECK (status IN ('open', 'partially_paid', 'paid', 'written_off')),
    retention_class    TEXT NOT NULL DEFAULT 'legal_7y'
        REFERENCES accounting_retention_classes(code),
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (paid_cents <= amount_cents),
    UNIQUE (source_document_id)
);

CREATE TABLE IF NOT EXISTS bank_accounts (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    legal_entity_id UUID NOT NULL REFERENCES legal_entities(id) ON DELETE RESTRICT,
    name            TEXT NOT NULL,
    iban            TEXT,
    bic             TEXT,
    currency        CHAR(3) NOT NULL DEFAULT 'EUR',
    account_id      UUID NOT NULL REFERENCES chart_of_accounts(id) ON DELETE RESTRICT,
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (legal_entity_id, iban)
);

CREATE TABLE IF NOT EXISTS bank_statement_lines (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    bank_account_id       UUID NOT NULL REFERENCES bank_accounts(id) ON DELETE RESTRICT,
    -- Bank-provided identity: (account, external_id) is the replay anchor
    -- for statement ingestion.
    external_id           TEXT NOT NULL,
    statement_date        DATE NOT NULL,
    value_date            DATE,
    -- Signed: positive = money in (receipt), negative = money out.
    amount_cents          BIGINT NOT NULL,
    currency              CHAR(3) NOT NULL DEFAULT 'EUR',
    reference             TEXT,
    counterparty_name     TEXT,
    counterparty_account  TEXT,
    source_document_id    UUID REFERENCES accounting_source_documents(id) ON DELETE RESTRICT,
    journal_entry_id      UUID REFERENCES journal_entries(id) ON DELETE RESTRICT,
    reconciled_at         TIMESTAMPTZ,
    retention_class       TEXT NOT NULL DEFAULT 'legal_7y'
        REFERENCES accounting_retention_classes(code),
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (bank_account_id, external_id)
);

CREATE INDEX IF NOT EXISTS idx_bank_statement_lines_unreconciled
    ON bank_statement_lines (bank_account_id, statement_date)
    WHERE journal_entry_id IS NULL;

CREATE TABLE IF NOT EXISTS bank_reconciliations (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    bank_statement_line_id UUID NOT NULL UNIQUE
        REFERENCES bank_statement_lines(id) ON DELETE RESTRICT,
    journal_entry_id      UUID REFERENCES journal_entries(id) ON DELETE RESTRICT,
    matched_amount_cents  BIGINT NOT NULL,
    method                TEXT NOT NULL DEFAULT 'manual'
        CHECK (method IN ('auto', 'manual', 'write_off')),
    reconciled_by         TEXT,
    reconciled_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    notes                 TEXT,
    retention_class       TEXT NOT NULL DEFAULT 'legal_7y'
        REFERENCES accounting_retention_classes(code)
);

-- ===========================================================================
-- 8. Fixed assets / depreciation
-- ===========================================================================

CREATE TABLE IF NOT EXISTS fixed_assets (
    id                                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    legal_entity_id                    UUID NOT NULL REFERENCES legal_entities(id) ON DELETE RESTRICT,
    name                               TEXT NOT NULL,
    asset_account_id                   UUID REFERENCES chart_of_accounts(id) ON DELETE RESTRICT,
    depreciation_account_id            UUID REFERENCES chart_of_accounts(id) ON DELETE RESTRICT,
    accumulated_depreciation_account_id UUID REFERENCES chart_of_accounts(id) ON DELETE RESTRICT,
    acquisition_date                   DATE NOT NULL,
    acquisition_cost_cents             BIGINT NOT NULL CHECK (acquisition_cost_cents > 0),
    residual_value_cents               BIGINT NOT NULL DEFAULT 0 CHECK (residual_value_cents >= 0),
    useful_life_months                 INTEGER NOT NULL CHECK (useful_life_months > 0),
    method                             TEXT NOT NULL DEFAULT 'straight_line'
        CHECK (method IN ('straight_line', 'declining_balance')),
    accumulated_depreciation_cents     BIGINT NOT NULL DEFAULT 0 CHECK (accumulated_depreciation_cents >= 0),
    status                             TEXT NOT NULL DEFAULT 'in_service'
        CHECK (status IN ('draft', 'in_service', 'disposed', 'fully_depreciated')),
    disposed_at                        DATE,
    source_document_id                 UUID REFERENCES accounting_source_documents(id) ON DELETE RESTRICT,
    retention_class                    TEXT NOT NULL DEFAULT 'legal_7y'
        REFERENCES accounting_retention_classes(code),
    created_at                         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at                         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (residual_value_cents <= acquisition_cost_cents)
);

CREATE TABLE IF NOT EXISTS depreciation_entries (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    fixed_asset_id   UUID NOT NULL REFERENCES fixed_assets(id) ON DELETE RESTRICT,
    fiscal_period_id UUID NOT NULL REFERENCES fiscal_periods(id) ON DELETE RESTRICT,
    amount_cents     BIGINT NOT NULL CHECK (amount_cents > 0),
    journal_entry_id UUID REFERENCES journal_entries(id) ON DELETE RESTRICT,
    retention_class  TEXT NOT NULL DEFAULT 'legal_7y'
        REFERENCES accounting_retention_classes(code),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- One depreciation posting per asset per period.
    UNIQUE (fixed_asset_id, fiscal_period_id)
);

-- ===========================================================================
-- 9. Payroll postings / tax accounts
-- ===========================================================================

CREATE TABLE IF NOT EXISTS payroll_postings (
    id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    legal_entity_id             UUID NOT NULL REFERENCES legal_entities(id) ON DELETE RESTRICT,
    fiscal_period_id            UUID NOT NULL REFERENCES fiscal_periods(id) ON DELETE RESTRICT,
    -- Canonical payroll input (migration 199, payroll_records).
    payroll_record_id           UUID NOT NULL UNIQUE,
    employee_name               TEXT,
    gross_cents                 BIGINT NOT NULL CHECK (gross_cents >= 0),
    income_tax_cents            BIGINT NOT NULL DEFAULT 0 CHECK (income_tax_cents >= 0),
    social_tax_cents            BIGINT NOT NULL DEFAULT 0 CHECK (social_tax_cents >= 0),
    unemployment_employee_cents BIGINT NOT NULL DEFAULT 0 CHECK (unemployment_employee_cents >= 0),
    unemployment_employer_cents BIGINT NOT NULL DEFAULT 0 CHECK (unemployment_employer_cents >= 0),
    pension_cents               BIGINT NOT NULL DEFAULT 0 CHECK (pension_cents >= 0),
    net_cents                   BIGINT NOT NULL CHECK (net_cents >= 0),
    journal_entry_id            UUID REFERENCES journal_entries(id) ON DELETE RESTRICT,
    source_document_id          UUID REFERENCES accounting_source_documents(id) ON DELETE RESTRICT,
    currency                    CHAR(3) NOT NULL DEFAULT 'EUR',
    retention_class             TEXT NOT NULL DEFAULT 'legal_7y'
        REFERENCES accounting_retention_classes(code),
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (gross_cents >= net_cents)
);

CREATE INDEX IF NOT EXISTS idx_payroll_postings_period
    ON payroll_postings (legal_entity_id, fiscal_period_id);

CREATE TABLE IF NOT EXISTS tax_accounts (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    legal_entity_id UUID NOT NULL REFERENCES legal_entities(id) ON DELETE RESTRICT,
    tax_type        TEXT NOT NULL CHECK (tax_type IN (
        'vat_output', 'vat_input', 'vat_payable', 'income_tax', 'social_tax',
        'unemployment_employee', 'unemployment_employer', 'pension_ii_pillar',
        'corporate'
    )),
    account_id      UUID NOT NULL REFERENCES chart_of_accounts(id) ON DELETE RESTRICT,
    -- Date-effective rate in basis points (2400 = 24.00%).
    rate_bp         INTEGER CHECK (rate_bp IS NULL OR rate_bp >= 0),
    effective_from  DATE NOT NULL,
    effective_to    DATE,
    jurisdiction    CHAR(2) NOT NULL DEFAULT 'EE',
    retention_class TEXT NOT NULL DEFAULT 'legal_7y'
        REFERENCES accounting_retention_classes(code),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (legal_entity_id, tax_type, effective_from),
    CHECK (effective_to IS NULL OR effective_to >= effective_from)
);

-- ===========================================================================
-- 10. Payment-processor clearing / FX
-- ===========================================================================

CREATE TABLE IF NOT EXISTS processor_clearing_accounts (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    legal_entity_id     UUID NOT NULL REFERENCES legal_entities(id) ON DELETE RESTRICT,
    processor           TEXT NOT NULL CHECK (processor IN ('stripe', 'paypal', 'bank')),
    currency            CHAR(3) NOT NULL DEFAULT 'EUR',
    clearing_account_id UUID NOT NULL REFERENCES chart_of_accounts(id) ON DELETE RESTRICT,
    fee_account_id      UUID REFERENCES chart_of_accounts(id) ON DELETE RESTRICT,
    is_active           BOOLEAN NOT NULL DEFAULT TRUE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (legal_entity_id, processor, currency)
);

CREATE TABLE IF NOT EXISTS fx_rates (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    base_currency   CHAR(3) NOT NULL,
    quote_currency  CHAR(3) NOT NULL,
    rate            NUMERIC(20, 10) NOT NULL CHECK (rate > 0),
    rate_date       DATE NOT NULL,
    source          TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (base_currency, quote_currency, rate_date),
    CHECK (base_currency <> quote_currency)
);

CREATE TABLE IF NOT EXISTS fx_revaluations (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    legal_entity_id      UUID NOT NULL REFERENCES legal_entities(id) ON DELETE RESTRICT,
    fiscal_period_id     UUID NOT NULL REFERENCES fiscal_periods(id) ON DELETE RESTRICT,
    currency             CHAR(3) NOT NULL,
    balance_before_cents BIGINT NOT NULL,
    balance_after_cents  BIGINT NOT NULL,
    gain_loss_cents      BIGINT NOT NULL,
    journal_entry_id     UUID REFERENCES journal_entries(id) ON DELETE RESTRICT,
    retention_class      TEXT NOT NULL DEFAULT 'legal_7y'
        REFERENCES accounting_retention_classes(code),
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (legal_entity_id, fiscal_period_id, currency)
);

-- ===========================================================================
-- 11. Period close runs
-- ===========================================================================

CREATE TABLE IF NOT EXISTS period_close_runs (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    fiscal_period_id UUID NOT NULL REFERENCES fiscal_periods(id) ON DELETE RESTRICT,
    run_type         TEXT NOT NULL CHECK (run_type IN ('close', 'lock', 'reopen_request')),
    status           TEXT NOT NULL DEFAULT 'running'
        CHECK (status IN ('running', 'completed', 'failed')),
    checks           JSONB NOT NULL DEFAULT '{}'::jsonb,
    journal_entry_id UUID REFERENCES journal_entries(id) ON DELETE RESTRICT,
    started_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at     TIMESTAMPTZ,
    performed_by     TEXT,
    error            TEXT,
    retention_class  TEXT NOT NULL DEFAULT 'legal_7y'
        REFERENCES accounting_retention_classes(code)
);

CREATE INDEX IF NOT EXISTS idx_period_close_runs_period
    ON period_close_runs (fiscal_period_id, started_at DESC);

-- ===========================================================================
-- 12. Enforcement functions
-- ===========================================================================

-- 12a. Balance assertion for POSTED entries (deferred constraint trigger).
-- Chosen over "the posting function asserts the sum" because it is the only
-- enforcement point every writer passes through: a transaction that commits
-- a posted, line-less or unbalanced entry cannot exist, even if written by
-- raw SQL. The Rust posting API additionally validates before writing so
-- callers get a typed error instead of a SQLSTATE.
CREATE OR REPLACE FUNCTION accounting_assert_journal_balanced()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    total_debit  BIGINT;
    total_credit BIGINT;
    line_count   INTEGER;
    bad_accounts INTEGER;
BEGIN
    -- Draft entries (posted_at IS NULL) are not asserted; only posting
    -- (and any later operation on a posted entry) must be balanced.
    IF NEW.posted_at IS NULL THEN
        RETURN NULL;
    END IF;

    SELECT COALESCE(SUM(debit_cents), 0),
           COALESCE(SUM(credit_cents), 0),
           COUNT(*)
      INTO total_debit, total_credit, line_count
      FROM journal_lines
     WHERE entry_id = NEW.id;

    IF line_count = 0 THEN
        RAISE EXCEPTION USING
            ERRCODE = 'check_violation',
            MESSAGE = format('journal entry %s cannot be posted without lines', NEW.id);
    END IF;

    IF total_debit <> total_credit THEN
        RAISE EXCEPTION USING
            ERRCODE = 'check_violation',
            MESSAGE = format('journal entry %s is unbalanced: SUM(debit)=%s <> SUM(credit)=%s',
                             NEW.id, total_debit, total_credit),
            HINT = 'Every posted journal must satisfy SUM(debit) = SUM(credit); post a reversal/adjusting entry instead of editing.';
    END IF;

    -- Every line account must belong to the entry's legal entity.
    SELECT COUNT(*)
      INTO bad_accounts
      FROM journal_lines l
      JOIN chart_of_accounts a ON a.id = l.account_id
     WHERE l.entry_id = NEW.id
       AND a.legal_entity_id <> NEW.legal_entity_id;

    IF bad_accounts > 0 THEN
        RAISE EXCEPTION USING
            ERRCODE = 'foreign_key_violation',
            MESSAGE = format('journal entry %s references %s account(s) of another legal entity',
                             NEW.id, bad_accounts);
    END IF;

    RETURN NULL;
END;
$$;

DROP TRIGGER IF EXISTS trg_journal_entries_balanced ON journal_entries;
CREATE CONSTRAINT TRIGGER trg_journal_entries_balanced
    AFTER INSERT OR UPDATE ON journal_entries
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW
    EXECUTE FUNCTION accounting_assert_journal_balanced();

-- 12b. Journal entry guard: immutability of posted entries, period status
-- and period/entry-date consistency on posting.
CREATE OR REPLACE FUNCTION accounting_journal_entry_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    period_status TEXT;
    period_start  DATE;
    period_end    DATE;
    period_entity UUID;
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF OLD.posted_at IS NOT NULL THEN
            RAISE EXCEPTION USING
                ERRCODE = 'object_not_in_prerequisite_state',
                MESSAGE = format('posted journal entry %s is immutable and cannot be deleted', OLD.id),
                HINT = 'Correct a posted entry with a reversal/adjusting entry.';
        END IF;
        RETURN OLD;
    END IF;

    IF TG_OP = 'UPDATE' AND OLD.posted_at IS NOT NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = 'object_not_in_prerequisite_state',
            MESSAGE = format('posted journal entry %s is immutable', OLD.id),
            HINT = 'Posted entries are immutable; correct them with a reversal/adjusting entry.';
    END IF;

    IF NEW.posted_at IS NOT NULL THEN
        SELECT status, start_date, end_date, legal_entity_id
          INTO period_status, period_start, period_end, period_entity
          FROM fiscal_periods
         WHERE id = NEW.fiscal_period_id;

        IF NOT FOUND THEN
            RAISE EXCEPTION USING
                ERRCODE = 'foreign_key_violation',
                MESSAGE = format('journal entry %s references missing fiscal period %s',
                                 NEW.id, NEW.fiscal_period_id);
        END IF;

        IF period_entity <> NEW.legal_entity_id THEN
            RAISE EXCEPTION USING
                ERRCODE = 'foreign_key_violation',
                MESSAGE = format('journal entry %s entity does not match its fiscal period entity', NEW.id);
        END IF;

        IF period_status <> 'open' THEN
            RAISE EXCEPTION USING
                ERRCODE = 'object_not_in_prerequisite_state',
                MESSAGE = format('fiscal period %s is %s; posting is refused',
                                 NEW.fiscal_period_id, period_status),
                HINT = 'Open a new period for the correction; closed periods are locked for statutory reporting.';
        END IF;

        IF NEW.entry_date < period_start OR NEW.entry_date > period_end THEN
            RAISE EXCEPTION USING
                ERRCODE = 'check_violation',
                MESSAGE = format('entry date %s is outside fiscal period %s [%s .. %s]',
                                 NEW.entry_date, NEW.fiscal_period_id, period_start, period_end);
        END IF;
    END IF;

    IF TG_OP = 'UPDATE'
       AND (to_jsonb(NEW) - 'posted_at' - 'posted_by')
           IS DISTINCT FROM (to_jsonb(OLD) - 'posted_at' - 'posted_by') THEN
        RAISE EXCEPTION USING
            ERRCODE = 'object_not_in_prerequisite_state',
            MESSAGE = format('draft journal entry %s may only be transitioned to posted (or deleted)', OLD.id),
            HINT = 'Delete and re-create the draft, or post a reversal/adjusting entry.';
    END IF;

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_journal_entries_guard ON journal_entries;
CREATE TRIGGER trg_journal_entries_guard
    BEFORE INSERT OR UPDATE OR DELETE ON journal_entries
    FOR EACH ROW
    EXECUTE FUNCTION accounting_journal_entry_guard();

-- 12c. Journal line guard: no line may be added to, changed in, or removed
-- from a posted entry.
CREATE OR REPLACE FUNCTION accounting_journal_line_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    parent_entry UUID;
    parent_posted TIMESTAMPTZ;
BEGIN
    parent_entry := COALESCE(NEW.entry_id, OLD.entry_id);

    SELECT posted_at INTO parent_posted FROM journal_entries WHERE id = parent_entry;

    -- NULL parent_posted also covers the cascade-delete case (parent row
    -- already gone). Posted parent rows always exist (ON DELETE RESTRICT
    -- semantics are enforced by the entry guard).
    IF parent_posted IS NOT NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = 'object_not_in_prerequisite_state',
            MESSAGE = format('journal entry %s is posted; its lines are immutable', parent_entry),
            HINT = 'Correct with a reversal/adjusting entry.';
    END IF;

    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_journal_lines_guard ON journal_lines;
CREATE TRIGGER trg_journal_lines_guard
    BEFORE INSERT OR UPDATE OR DELETE ON journal_lines
    FOR EACH ROW
    EXECUTE FUNCTION accounting_journal_line_guard();

-- 12d. Fiscal period state machine: open -> closed -> locked; no way back.
CREATE OR REPLACE FUNCTION accounting_fiscal_period_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.status = 'locked' AND NEW.status <> 'locked' THEN
        RAISE EXCEPTION USING
            ERRCODE = 'object_not_in_prerequisite_state',
            MESSAGE = format('locked fiscal period %s cannot change status', OLD.id);
    END IF;

    IF OLD.status = 'closed' AND NEW.status NOT IN ('closed', 'locked') THEN
        RAISE EXCEPTION USING
            ERRCODE = 'object_not_in_prerequisite_state',
            MESSAGE = format('closed fiscal period %s can only be locked, never reopened', OLD.id);
    END IF;

    IF NEW.status = 'closed' AND OLD.status <> 'closed' AND NEW.closed_at IS NULL THEN
        NEW.closed_at := NOW();
    END IF;

    IF NEW.status = 'locked' THEN
        NEW.closed_at := COALESCE(NEW.closed_at, NOW());
        NEW.locked_at := COALESCE(NEW.locked_at, NOW());
    END IF;

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_fiscal_periods_guard ON fiscal_periods;
CREATE TRIGGER trg_fiscal_periods_guard
    BEFORE UPDATE ON fiscal_periods
    FOR EACH ROW
    EXECUTE FUNCTION accounting_fiscal_period_guard();

-- 12e. Retention guard: a legal_7y/legal_10y row cannot be deleted by an
-- ordinary deletion path. Authorized retention-expiry purges set
-- `SET LOCAL apexmail.accounting.retention_override = 'on'` in their
-- session/transaction.
CREATE OR REPLACE FUNCTION accounting_retention_delete_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    cls      TEXT;
    override TEXT;
BEGIN
    cls := to_jsonb(OLD) ->> 'retention_class';
    override := COALESCE(current_setting('apexmail.accounting.retention_override', true), '');

    IF cls IN ('legal_7y', 'legal_10y') AND override <> 'on' THEN
        RAISE EXCEPTION USING
            ERRCODE = 'restrict_violation',
            MESSAGE = format('retention-protected %s row (class %s) cannot be deleted',
                             TG_TABLE_NAME, cls),
            HINT = 'Statutory accounting records are retained for 7+ years. Set apexmail.accounting.retention_override = on only for an authorized, audited retention-expiry purge.';
    END IF;

    RETURN OLD;
END;
$$;

-- Attach the retention guard to every record table that carries a
-- retention_class. journal_entries/journal_lines are deliberately excluded:
-- their delete semantics are stricter (posted entries can never be deleted;
-- drafts may be discarded before posting) and enforced by 12b/12c.
DO $$
DECLARE
    tbl TEXT;
BEGIN
    FOREACH tbl IN ARRAY ARRAY[
        'legal_entities', 'customers', 'suppliers',
        'accounting_source_documents', 'accounts_receivable', 'accounts_payable',
        'bank_statement_lines', 'bank_reconciliations', 'fixed_assets',
        'depreciation_entries', 'payroll_postings', 'fx_revaluations',
        'period_close_runs'
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

-- ===========================================================================
-- 13. Derivation read contract (views consumed by tax/annual workflows)
-- ===========================================================================
--
-- These views are the ONLY sanctioned read surface for filing code
-- (KMD/TSD/annual report). Operational tables (invoices, credit_notes,
-- payroll_records) are evidence, not the ledger: reports must derive from
-- posted journal entries through these views (or the equivalent typed
-- functions in accounting-core::derive).

DROP VIEW IF EXISTS v_accounting_posted_entries;
CREATE VIEW v_accounting_posted_entries AS
SELECT
    e.id                AS journal_entry_id,
    e.legal_entity_id,
    e.fiscal_period_id,
    e.entry_no,
    e.entry_date,
    e.entry_type,
    e.memo,
    e.source_document_id,
    e.source_hash,
    e.idempotency_key,
    e.reversal_of_entry_id,
    e.posted_at,
    e.posted_by,
    e.retention_class,
    p.label             AS period_label,
    p.start_date        AS period_start,
    p.end_date          AS period_end,
    le.registry_code    AS legal_entity_registry_code
FROM journal_entries e
JOIN fiscal_periods p  ON p.id  = e.fiscal_period_id
JOIN legal_entities le ON le.id = e.legal_entity_id
WHERE e.posted_at IS NOT NULL;

DROP VIEW IF EXISTS v_accounting_trial_balance;
CREATE VIEW v_accounting_trial_balance AS
SELECT
    e.legal_entity_id,
    e.fiscal_period_id,
    a.id                        AS account_id,
    a.code                      AS account_code,
    a.name                      AS account_name,
    a.account_type,
    a.normal_balance,
    a.account_role,
    SUM(l.debit_cents)::bigint  AS debit_cents,
    SUM(l.credit_cents)::bigint AS credit_cents,
    (SUM(l.debit_cents) - SUM(l.credit_cents))::bigint AS balance_debit_positive
FROM journal_lines l
JOIN journal_entries e   ON e.id = l.entry_id AND e.posted_at IS NOT NULL
JOIN chart_of_accounts a ON a.id = l.account_id
GROUP BY e.legal_entity_id, e.fiscal_period_id, a.id, a.code, a.name,
         a.account_type, a.normal_balance, a.account_role;

DROP VIEW IF EXISTS v_accounting_vat_entries;
CREATE VIEW v_accounting_vat_entries AS
SELECT
    e.legal_entity_id,
    e.fiscal_period_id,
    e.id                AS journal_entry_id,
    e.entry_date,
    e.entry_type,
    e.source_document_id,
    d.source_type,
    d.source_table,
    d.source_id,
    a.account_role      AS vat_role,
    COALESCE(l.vat_code, a.vat_code) AS vat_code,
    l.vat_rate_bp,
    l.net_cents,
    l.vat_cents,
    -- Direction-signed amounts: output VAT is a liability (credit side
    -- increases it), input VAT is an asset (debit side increases it).
    -- Reversals/credit notes carry the opposite side and net out.
    CASE
        WHEN a.account_role = 'vat_output' AND l.credit_cents > 0 THEN l.net_cents
        WHEN a.account_role = 'vat_output' AND l.debit_cents > 0 THEN -l.net_cents
        WHEN a.account_role = 'vat_input'  AND l.debit_cents > 0 THEN l.net_cents
        ELSE -l.net_cents
    END                 AS signed_net_cents,
    CASE
        WHEN a.account_role = 'vat_output' AND l.credit_cents > 0 THEN l.vat_cents
        WHEN a.account_role = 'vat_output' AND l.debit_cents > 0 THEN -l.vat_cents
        WHEN a.account_role = 'vat_input'  AND l.debit_cents > 0 THEN l.vat_cents
        ELSE -l.vat_cents
    END                 AS signed_vat_cents,
    l.currency,
    e.retention_class
FROM journal_lines l
JOIN journal_entries e   ON e.id = l.entry_id AND e.posted_at IS NOT NULL
JOIN chart_of_accounts a ON a.id = l.account_id
LEFT JOIN accounting_source_documents d ON d.id = e.source_document_id
WHERE a.account_role IN ('vat_output', 'vat_input')
  AND l.vat_cents IS NOT NULL;

DROP VIEW IF EXISTS v_accounting_payroll_taxes;
CREATE VIEW v_accounting_payroll_taxes AS
SELECT
    pp.id,
    pp.legal_entity_id,
    pp.fiscal_period_id,
    pp.payroll_record_id,
    pp.employee_name,
    pp.gross_cents,
    pp.income_tax_cents,
    pp.social_tax_cents,
    pp.unemployment_employee_cents,
    pp.unemployment_employer_cents,
    pp.pension_cents,
    pp.net_cents,
    pp.currency,
    pp.journal_entry_id,
    e.entry_date,
    e.posted_at
FROM payroll_postings pp
LEFT JOIN journal_entries e ON e.id = pp.journal_entry_id AND e.posted_at IS NOT NULL;

DROP VIEW IF EXISTS v_accounting_period_movement;
CREATE VIEW v_accounting_period_movement AS
SELECT
    e.legal_entity_id,
    e.fiscal_period_id,
    a.account_type,
    SUM(l.debit_cents)::bigint  AS debit_cents,
    SUM(l.credit_cents)::bigint AS credit_cents
FROM journal_lines l
JOIN journal_entries e   ON e.id = l.entry_id AND e.posted_at IS NOT NULL
JOIN chart_of_accounts a ON a.id = l.account_id
GROUP BY e.legal_entity_id, e.fiscal_period_id, a.account_type;

-- Sanity assertion for the deploy-time migration itself: the class table
-- must contain the statutory classes.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM accounting_retention_classes WHERE code = 'legal_7y') THEN
        RAISE EXCEPTION 'migration 220: accounting_retention_classes missing legal_7y';
    END IF;
END;
$$;
