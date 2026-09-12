-- Migration 219: OSS and VD filing scaffold.
--
-- =============================================================================
-- Two statutory reporting flows were entirely absent:
--
-- * OSS (One Stop Shop, Union scheme) — ApexMail charges destination VAT on
--   EU B2C digital services; that VAT is filed through OSS, not the Estonian
--   KMD alone. The operating model needs registrations, customer-location
--   evidence, per-supply entries, period returns, adjustments and payments.
--
-- * VD (intra-Community supply report) — zero-rated EU B2B supplies must be
--   reported per counterparty and can only be zero-rated against VIES
--   evidence (see migration 218's vat_validation_evidence).
--
-- This migration creates the SCHEMA and the state a filing workflow needs:
-- generation, validation, submission, acknowledgement and amendment. What is
-- NOT implemented is stated explicitly in the module docs
-- (compliance::vat_oss): nothing here pretends a return was filed or paid.
-- Status columns transition through the documented state machine only.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- OSS: registrations
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS oss_registrations (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Seller identity. NULL = the platform's own single-entity registration.
    tenant_id            TEXT,
    scheme               TEXT NOT NULL CHECK (scheme IN ('union', 'non_union', 'ioss')),
    registration_country VARCHAR(2) NOT NULL,
    registration_number  TEXT NOT NULL,
    valid_from           DATE NOT NULL,
    valid_to             DATE,
    status               TEXT NOT NULL DEFAULT 'active'
                             CHECK (status IN ('active', 'suspended', 'expired')),
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT oss_registrations_period_valid
        CHECK (valid_to IS NULL OR valid_to >= valid_from),
    CONSTRAINT oss_registrations_identity_unique
        UNIQUE (scheme, registration_country, registration_number, valid_from)
);

-- ---------------------------------------------------------------------------
-- OSS: customer location evidence
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS customer_location_evidence (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id        TEXT NOT NULL,
    customer_id      TEXT,
    invoice_id       UUID,
    country          VARCHAR(2) NOT NULL,
    evidence_type    TEXT NOT NULL
                         CHECK (evidence_type IN ('billing_address', 'payment_method', 'ip_address', 'declaration', 'other')),
    evidence_at      TIMESTAMPTZ NOT NULL,
    source_reference TEXT,
    -- Higher = stronger evidence; the place-of-supply decision must record
    -- which evidence won (OSS requires two non-contradictory pieces for
    -- digital supplies, or a consistent one).
    evidence_weight  INTEGER NOT NULL DEFAULT 0,
    raw              JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_customer_location_evidence_lookup
    ON customer_location_evidence (tenant_id, customer_id, evidence_at DESC);

-- ---------------------------------------------------------------------------
-- OSS: per-supply entries (derivation target for period returns)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS oss_supply_entries (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    registration_id      UUID NOT NULL REFERENCES oss_registrations(id) ON DELETE RESTRICT,
    period               TEXT NOT NULL CHECK (period ~ '^[0-9]{4}-(0[1-9]|1[0-2])$'),
    supply_id            TEXT NOT NULL,
    tenant_id            TEXT NOT NULL,
    invoice_id           UUID,
    recognition_entry_id UUID,
    customer_country     VARCHAR(2) NOT NULL,
    consumption_country  VARCHAR(2) NOT NULL,
    taxable_amount_cents BIGINT NOT NULL,
    vat_rate             DOUBLE PRECISION NOT NULL,
    vat_amount_cents     BIGINT NOT NULL,
    currency             VARCHAR(8) NOT NULL DEFAULT 'EUR',
    source_document_id   TEXT,
    status               TEXT NOT NULL DEFAULT 'included'
                             CHECK (status IN ('included', 'amended')),
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Idempotent generation: regenerating a period updates the same supplies.
    CONSTRAINT oss_supply_entries_period_supply_unique
        UNIQUE (registration_id, period, supply_id)
);

CREATE INDEX IF NOT EXISTS idx_oss_supply_entries_period
    ON oss_supply_entries (registration_id, period);

-- ---------------------------------------------------------------------------
-- OSS: returns (one per registration + period + scheme)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS oss_returns (
    id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    registration_id          UUID NOT NULL REFERENCES oss_registrations(id) ON DELETE RESTRICT,
    period                   TEXT NOT NULL CHECK (period ~ '^[0-9]{4}-(0[1-9]|1[0-2])$'),
    scheme                   TEXT NOT NULL CHECK (scheme IN ('union', 'non_union', 'ioss')),
    status                   TEXT NOT NULL DEFAULT 'draft'
                                 CHECK (status IN ('draft', 'generated', 'validated', 'submitted', 'acknowledged', 'amended', 'failed')),
    total_taxable_cents      BIGINT NOT NULL DEFAULT 0,
    total_vat_cents          BIGINT NOT NULL DEFAULT 0,
    supply_count             BIGINT NOT NULL DEFAULT 0,
    payload_hash             TEXT,
    generated_at             TIMESTAMPTZ,
    validated_at             TIMESTAMPTZ,
    submitted_at             TIMESTAMPTZ,
    acknowledged_at          TIMESTAMPTZ,
    acknowledgement_reference TEXT,
    filing_error             TEXT,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT oss_returns_period_unique UNIQUE (registration_id, period, scheme),
    -- A return cannot claim acknowledgement without a reference.
    CONSTRAINT oss_returns_ack_has_reference
        CHECK (status <> 'acknowledged' OR acknowledgement_reference IS NOT NULL)
);

CREATE INDEX IF NOT EXISTS idx_oss_returns_status
    ON oss_returns (status, period);

-- ---------------------------------------------------------------------------
-- OSS: return adjustments (amendments to filed periods)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS oss_return_adjustments (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    return_id            UUID NOT NULL REFERENCES oss_returns(id) ON DELETE CASCADE,
    source_period        TEXT NOT NULL CHECK (source_period ~ '^[0-9]{4}-(0[1-9]|1[0-2])$'),
    correction_type      TEXT NOT NULL CHECK (correction_type IN ('increase', 'decrease', 'replacement')),
    taxable_amount_cents BIGINT NOT NULL,
    vat_amount_cents     BIGINT NOT NULL,
    currency             VARCHAR(8) NOT NULL DEFAULT 'EUR',
    reason               TEXT NOT NULL,
    source_document_id   TEXT,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_oss_return_adjustments_return
    ON oss_return_adjustments (return_id, source_period);

-- ---------------------------------------------------------------------------
-- OSS: payments
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS oss_payments (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    return_id         UUID REFERENCES oss_returns(id) ON DELETE SET NULL,
    period            TEXT NOT NULL CHECK (period ~ '^[0-9]{4}-(0[1-9]|1[0-2])$'),
    amount_cents      BIGINT NOT NULL,
    currency          VARCHAR(8) NOT NULL DEFAULT 'EUR',
    paid_at           TIMESTAMPTZ,
    payment_reference TEXT,
    status            TEXT NOT NULL DEFAULT 'pending'
                          CHECK (status IN ('pending', 'paid', 'failed', 'refunded')),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT oss_payments_paid_has_timestamp
        CHECK (status <> 'paid' OR paid_at IS NOT NULL)
);

CREATE INDEX IF NOT EXISTS idx_oss_payments_period
    ON oss_payments (period, status);

-- ---------------------------------------------------------------------------
-- VD: intra-Community supply report
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS vd_returns (
    id                        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    period                    TEXT NOT NULL UNIQUE CHECK (period ~ '^[0-9]{4}-(0[1-9]|1[0-2])$'),
    seller_vat_number         TEXT,
    status                    TEXT NOT NULL DEFAULT 'draft'
                                  CHECK (status IN ('draft', 'generated', 'validated', 'submitted', 'acknowledged', 'amended', 'failed')),
    total_taxable_cents       BIGINT NOT NULL DEFAULT 0,
    total_vat_cents           BIGINT NOT NULL DEFAULT 0,
    line_count                BIGINT NOT NULL DEFAULT 0,
    payload_hash              TEXT,
    generated_at              TIMESTAMPTZ,
    validated_at              TIMESTAMPTZ,
    submitted_at              TIMESTAMPTZ,
    acknowledged_at           TIMESTAMPTZ,
    acknowledgement_reference TEXT,
    filing_error              TEXT,
    created_at                TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at                TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT vd_returns_ack_has_reference
        CHECK (status <> 'acknowledged' OR acknowledgement_reference IS NOT NULL)
);

CREATE TABLE IF NOT EXISTS vd_entries (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    return_id           UUID NOT NULL REFERENCES vd_returns(id) ON DELETE CASCADE,
    period              TEXT NOT NULL CHECK (period ~ '^[0-9]{4}-(0[1-9]|1[0-2])$'),
    supply_id           TEXT NOT NULL,
    invoice_id          UUID,
    customer_vat_number TEXT NOT NULL,
    customer_country    VARCHAR(2) NOT NULL,
    -- Zero-rating requires the authoritative evidence row (migration 218).
    vat_evidence_id     UUID REFERENCES vat_validation_evidence(id) ON DELETE RESTRICT,
    transaction_nature  TEXT NOT NULL DEFAULT 'services'
                            CHECK (transaction_nature IN ('goods', 'triangular', 'services')),
    taxable_amount_cents BIGINT NOT NULL,
    currency            VARCHAR(8) NOT NULL DEFAULT 'EUR',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT vd_entries_period_supply_unique UNIQUE (period, supply_id),
    -- A VD line with no VIES evidence cannot be zero-rated; it must carry
    -- the evidence that justified it.
    CONSTRAINT vd_entries_zero_rated_requires_evidence
        CHECK (vat_evidence_id IS NOT NULL)
);

CREATE INDEX IF NOT EXISTS idx_vd_entries_return
    ON vd_entries (return_id);

COMMENT ON TABLE vd_returns IS
    'Estonian VD (intra-Community supply) returns. Status follows the same generated -> validated -> submitted -> acknowledged/amended/failed machine as OSS returns; submission/acknowledgement transports are NOT implemented yet.';
COMMENT ON TABLE vd_entries IS
    'VD lines. Every line must reference the vat_validation_evidence row (VIES) that justified 0% treatment.';
COMMENT ON TABLE customer_location_evidence IS
    'Evidence justifying the customer location used for OSS place-of-supply. Weight/source are recorded; no automatic place-of-supply adjudicator is implemented yet.';
