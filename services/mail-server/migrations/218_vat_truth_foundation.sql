-- Migration 218: VAT truth foundation — one charging authority, authoritative
-- VIES evidence, and a taxable-event recognition ledger.
--
-- =============================================================================
-- Background (P0 tax-truth findings)
--
-- 1. Stripe and ApexMail were two independent tax deciders. Checkout
--    collected address/tax-ID data but never enabled Stripe Tax, while
--    ApexMail computed its own VAT for the statutory invoice. The result
--    could legitimately be "Stripe charged X" and "the statutory invoice says
--    X + VAT". `stripe_tax_snapshots` now records, immutably, what Stripe
--    actually charged (amounts, tax breakdown, jurisdiction, tax-ID status,
--    the Stripe invoice id and a payload hash). ApexMail validates the
--    charged total against its own computation; a mismatch blocks local
--    invoice finalization and opens a `finance_incidents` row.
--
-- 2. A structurally valid EU VAT number is not VIES evidence.
--    `vat_validation_evidence` stores dated, authoritative consultations
--    (source = VIES) including the outage state. Reverse charge is only
--    authorised against a valid, in-force, matching evidence row, and
--    `invoices.vat_evidence_id` snapshots the row that justified a zero-rated
--    invoice. Rows recording an outage have valid = FALSE and can never
--    authorise a reverse charge.
--
-- 3. "status = 'paid'" is not a VAT model. `vat_recognition_entries` records
--    the taxable event per supply under an accounting scheme resolved from
--    dated, explicitly-authorised bases (`vat_accounting_bases`). KMD
--    aggregates this ledger, not invoice status.
--
-- The recognition ledger carries a nullable `journal_entry_id` so the
-- double-entry accounting core can reconcile each entry to its journal line
-- once that crate/table exists. No FK is declared yet on purpose.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- 1. Authoritative VAT-number evidence
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS vat_validation_evidence (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Buyer identity: either the tenant (customer_id == tenant id today) or
    -- a nullable tenant link for customer records that are not tenants.
    customer_id           TEXT,
    tenant_id             TEXT,
    vat_number            TEXT NOT NULL,
    country               VARCHAR(2) NOT NULL,
    source                TEXT NOT NULL CHECK (source IN ('VIES')),
    requested_at          TIMESTAMPTZ NOT NULL,
    valid                 BOOLEAN NOT NULL,
    returned_name         TEXT,
    returned_address      TEXT,
    authority_request_id  TEXT,
    response_hash         TEXT NOT NULL,
    -- VIES `requestDate`: the date the authoritative answer applies from.
    valid_from            DATE NOT NULL,
    -- Optional operator-set refresh horizon; NULL = open-ended.
    valid_until           DATE,
    -- Outage marker (MS_UNAVAILABLE, SERVICE_UNAVAILABLE, TIMEOUT,
    -- GLOBAL_MAX_CONCURRENT_REQ, ...). An outage row is never valid.
    outage_state          TEXT,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT vat_validation_evidence_outage_never_valid
        CHECK (outage_state IS NULL OR valid = FALSE),
    CONSTRAINT vat_validation_evidence_valid_from_before_until
        CHECK (valid_until IS NULL OR valid_until >= valid_from),
    CONSTRAINT vat_validation_evidence_valid_outside_outage
        CHECK (valid = FALSE OR outage_state IS NULL)
);

-- Reverse-charge lookup: newest authoritative row for (tenant, number).
CREATE INDEX IF NOT EXISTS idx_vat_validation_evidence_lookup
    ON vat_validation_evidence (tenant_id, UPPER(REPLACE(vat_number, ' ', '')), requested_at DESC);

-- Operators auditing "which reverse-charged invoice relied on what".
CREATE INDEX IF NOT EXISTS idx_vat_validation_evidence_valid
    ON vat_validation_evidence (vat_number, valid_from DESC)
    WHERE valid = TRUE AND outage_state IS NULL;

COMMENT ON TABLE vat_validation_evidence IS
    'Dated authoritative VAT-number consultations (VIES). Only valid = TRUE with a NULL outage_state can authorise a reverse charge; an outage is never silently treated as valid.';

-- ---------------------------------------------------------------------------
-- 2. Invoice snapshots of the evidence and the Stripe tax decision
-- ---------------------------------------------------------------------------

ALTER TABLE invoices
    ADD COLUMN IF NOT EXISTS vat_evidence_id UUID
        REFERENCES vat_validation_evidence(id) ON DELETE RESTRICT,
    ADD COLUMN IF NOT EXISTS stripe_tax_snapshot_id UUID;

COMMENT ON COLUMN invoices.vat_evidence_id IS
    'The vat_validation_evidence row that justified a 0% reverse charge on this invoice. NULL when normal VAT was charged.';

-- ---------------------------------------------------------------------------
-- 3. Immutable Stripe tax snapshots
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS stripe_tax_snapshots (
    id                                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    stripe_invoice_id                 TEXT NOT NULL,
    stripe_invoice_number             TEXT,
    tenant_id                         TEXT,
    local_invoice_id                  UUID REFERENCES invoices(id) ON DELETE SET NULL,
    currency                          VARCHAR(8) NOT NULL,
    subtotal_cents                    BIGINT NOT NULL,
    tax_cents                         BIGINT NOT NULL,
    total_cents                       BIGINT NOT NULL,
    amount_paid_cents                 BIGINT,
    -- Stripe `automatic_tax.status` verbatim (complete,
    -- requires_location_inputs, failed, ...) or NULL when Stripe Tax was not
    -- enabled on the invoice.
    automatic_tax_status              TEXT,
    -- Who decided the charged tax: Stripe Tax (authoritative external
    -- authority) or ApexMail's local computation (fallback only).
    authority                         TEXT NOT NULL CHECK (authority IN ('stripe_tax', 'apexmail_local')),
    jurisdiction                      TEXT,
    tax_id_status                     TEXT,
    tax_ids                           JSONB NOT NULL DEFAULT '[]'::jsonb,
    tax_breakdown                     JSONB NOT NULL DEFAULT '[]'::jsonb,
    apexmail_expected_subtotal_cents  BIGINT,
    apexmail_expected_vat_cents       BIGINT,
    apexmail_expected_total_cents     BIGINT,
    validation_status                 TEXT NOT NULL CHECK (validation_status IN ('validated', 'discrepancy', 'fallback_unavailable', 'unverified_external')),
    discrepancy_cents                 BIGINT NOT NULL DEFAULT 0,
    raw_payload_hash                  TEXT NOT NULL,
    raw_payload                       JSONB NOT NULL,
    created_at                        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT stripe_tax_snapshots_one_per_invoice UNIQUE (stripe_invoice_id)
);

CREATE INDEX IF NOT EXISTS idx_stripe_tax_snapshots_tenant
    ON stripe_tax_snapshots (tenant_id, created_at DESC);

-- Immutable by construction: snapshots are evidence of what the charging
-- authority said; they may be superseded by a NEW row, never edited.
CREATE OR REPLACE FUNCTION prevent_stripe_tax_snapshot_mutation()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'stripe_tax_snapshots is immutable (attempted % on %)',
        TG_OP, COALESCE(OLD.stripe_invoice_id, '(unknown)');
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_stripe_tax_snapshots_immutable ON stripe_tax_snapshots;
CREATE TRIGGER trg_stripe_tax_snapshots_immutable
    BEFORE UPDATE OR DELETE ON stripe_tax_snapshots
    FOR EACH ROW EXECUTE FUNCTION prevent_stripe_tax_snapshot_mutation();

COMMENT ON TABLE stripe_tax_snapshots IS
    'Immutable record of the finalized Stripe invoice tax decision (amounts, jurisdiction, tax-ID status, hash). Immutability enforced by trigger.';

-- ---------------------------------------------------------------------------
-- 4. Finance incidents (durable operator-queryable block)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS finance_incidents (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    kind                  TEXT NOT NULL,
    severity              TEXT NOT NULL DEFAULT 'high'
                              CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    status                TEXT NOT NULL DEFAULT 'open'
                              CHECK (status IN ('open', 'acknowledged', 'resolved', 'dismissed')),
    tenant_id             TEXT,
    local_invoice_id      UUID,
    stripe_invoice_id     TEXT,
    currency              VARCHAR(8),
    expected_total_cents  BIGINT,
    observed_total_cents  BIGINT,
    delta_cents           BIGINT,
    detail                JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    acknowledged_at       TIMESTAMPTZ,
    resolved_at           TIMESTAMPTZ,
    resolution_note       TEXT
);

-- At most one OPEN incident per (kind, Stripe invoice): webhook retries and
-- dead-letter replays must not spam the queue with duplicates.
CREATE UNIQUE INDEX IF NOT EXISTS uq_finance_incidents_open_per_invoice
    ON finance_incidents (kind, stripe_invoice_id)
    WHERE status = 'open' AND stripe_invoice_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_finance_incidents_open
    ON finance_incidents (status, severity, created_at DESC);

COMMENT ON TABLE finance_incidents IS
    'Durable finance incidents. A tax-total mismatch blocks invoice finalization and lands here (kind = tax_total_mismatch) for operators.';

-- ---------------------------------------------------------------------------
-- 5. Effective-dated accounting bases (general / cash_special)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS vat_accounting_bases (
    id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- NULL = platform default basis.
    tenant_id                TEXT,
    scheme                   TEXT NOT NULL CHECK (scheme IN ('general', 'cash_special')),
    effective_from           DATE NOT NULL,
    effective_to             DATE,
    authorised_at            DATE,
    authorisation_reference  TEXT,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT vat_accounting_bases_period_valid
        CHECK (effective_to IS NULL OR effective_to >= effective_from),
    -- Cash accounting is only the special, EXPLICITLY authorised scheme.
    CONSTRAINT vat_accounting_bases_cash_special_requires_authorisation
        CHECK (scheme <> 'cash_special'
               OR (authorised_at IS NOT NULL
                   AND authorisation_reference IS NOT NULL
                   AND btrim(authorisation_reference) <> ''))
);

-- One open-ended row per (tenant, scheme); closed historical rows may repeat.
CREATE UNIQUE INDEX IF NOT EXISTS uq_vat_accounting_bases_open
    ON vat_accounting_bases (COALESCE(tenant_id, ''), scheme)
    WHERE effective_to IS NULL;

-- Platform default: general accrual from the beginning of the supported
-- period. Every tenant resolves to at least this row.
INSERT INTO vat_accounting_bases (tenant_id, scheme, effective_from, authorised_at)
SELECT NULL, 'general', DATE '2000-01-01', NULL
WHERE NOT EXISTS (
    SELECT 1 FROM vat_accounting_bases
    WHERE tenant_id IS NULL AND scheme = 'general'
);

COMMENT ON TABLE vat_accounting_bases IS
    'Effective-dated VAT accounting bases. cash_special requires an explicit authorisation reference and cannot be used without one.';

-- ---------------------------------------------------------------------------
-- 6. VAT recognition ledger
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS vat_recognition_entries (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Stable supply identity: invoice id / credit-note id / usage supply id.
    supply_id             TEXT NOT NULL,
    tenant_id             TEXT NOT NULL,
    invoice_id            UUID,
    event_type            TEXT NOT NULL
                              CHECK (event_type IN ('supply', 'payment', 'cash_special_due', 'correction')),
    -- The actual taxable event instant (Tallinn-local day converted to UTC
    -- by the writer); recognition_period is derived from it.
    taxable_event_at      TIMESTAMPTZ NOT NULL,
    recognition_period    TEXT NOT NULL
                              CHECK (recognition_period ~ '^[0-9]{4}-(0[1-9]|1[0-2])$'),
    taxable_amount_cents  BIGINT NOT NULL,
    vat_rate              DOUBLE PRECISION NOT NULL,
    vat_amount_cents      BIGINT NOT NULL,
    currency              VARCHAR(8) NOT NULL DEFAULT 'EUR',
    scheme                TEXT NOT NULL CHECK (scheme IN ('general', 'cash_special')),
    reason                TEXT,
    source_document_id    TEXT,
    -- Reconciliation hook for the double-entry accounting core
    -- (journal_entries/journal_lines). Nullable and FK-less until that
    -- crate/table exists; entries must remain reconcilable without it.
    journal_entry_id      UUID,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- One CURRENT recognition event per (supply, scheme): the materializer
-- replaces the previous supply/payment/cash_special_due row when the
-- recognition trigger changes (payment arrives before/after the fallback).
-- Corrections are separate rows and are not constrained by this index.
CREATE UNIQUE INDEX IF NOT EXISTS uq_vat_recognition_current_event
    ON vat_recognition_entries (supply_id, scheme)
    WHERE event_type IN ('supply', 'payment', 'cash_special_due');

CREATE INDEX IF NOT EXISTS idx_vat_recognition_period
    ON vat_recognition_entries (recognition_period, currency);

CREATE INDEX IF NOT EXISTS idx_vat_recognition_tenant
    ON vat_recognition_entries (tenant_id, taxable_event_at DESC);

COMMENT ON TABLE vat_recognition_entries IS
    'Taxable-event ledger. KMD aggregates this table by recognition_period; invoice status is never a VAT trigger. scheme = general recognises on supply, cash_special on payment or the first day of the third following month, whichever is earlier. journal_entry_id links to the accounting core when available.';
