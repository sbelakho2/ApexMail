-- Migration 214: canonical GDPR governance registry — ROPA, lawful-basis,
-- DPIA, processor contracts, international transfers (TIA/SCC/adequacy) and
-- retention classes.
--
-- =============================================================================
-- WHY
--
-- There was no canonical production registry for the platform's records of
-- processing (GDPR Art. 30), DPIAs (Art. 35), processor contracts (Art. 28)
-- or international transfers (Chapter V). The compliance service knew which
-- stores it erases and exports, but no durable, queryable record tied a data
-- store to its purpose, subjects, data categories, recipients, lawful basis,
-- controller/processor role, retention class and transfer situation.
--
-- This migration creates the registry tables; the compliance service seeds
-- the records it can SUBSTANTIATE FROM CODE (governance::seed_registry).
-- Lawful bases, DPIA outcomes, transfer mechanisms and adequacy conclusions
-- are NEVER invented in code: seeded rows carry
-- `require_legal_input` / `legal_input_required` markers until Legal records
-- the decision through the registry API.
--
-- Relationship to the RET-001..023 registry (`crates/compliance/src/retention.rs`):
-- retention classes are the legally-grounded buckets (statutory vs
-- operational); `registry_category_id` links a class to the operational
-- RET-xxx category where one exists.
-- =============================================================================

-- ─── Retention classes ──────────────────────────────────────────────────────
--
-- A retention class is a legal bucket, not a customer setting. Statutory
-- classes (Estonia: accounting evidence, seven years) cannot be shortened by
-- a customer selection or an ordinary erasure — erasure moves those records
-- to the legally-restricted archive instead.

CREATE TABLE IF NOT EXISTS retention_classes (
    id                    TEXT PRIMARY KEY,
    name                  TEXT NOT NULL,
    description           TEXT NOT NULL,
    statutory             BOOLEAN NOT NULL DEFAULT FALSE,
    -- Minimum retention the platform must honour; for statutory classes this
    -- is the legal floor (2555 days = seven years for EE accounting).
    minimum_days          INTEGER NOT NULL CHECK (minimum_days >= 0),
    maximum_days          INTEGER,
    -- Operational default when the class is not statutory.
    retention_days        INTEGER NOT NULL CHECK (retention_days >= 0),
    legal_basis_reference TEXT,
    jurisdiction          VARCHAR(10),
    customer_selectable   BOOLEAN NOT NULL DEFAULT FALSE,
    -- Links to the operational category in retention.rs (RET-001..023).
    registry_category_id  TEXT,
    review_status         VARCHAR(30) NOT NULL DEFAULT 'legal_input_required',
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT retention_classes_review_status_valid CHECK (
        review_status IN ('legal_input_required', 'reviewed', 'approved')
    ),
    CONSTRAINT retention_classes_statutory_has_reference CHECK (
        NOT statutory OR legal_basis_reference IS NOT NULL
    ),
    CONSTRAINT retention_classes_statutory_not_selectable CHECK (
        NOT statutory OR NOT customer_selectable
    )
);

CREATE INDEX IF NOT EXISTS idx_retention_classes_statutory
    ON retention_classes (statutory, minimum_days DESC);

-- ─── Records of processing (ROPA, Art. 30) ──────────────────────────────────

CREATE TABLE IF NOT EXISTS processing_activities (
    id                       TEXT PRIMARY KEY,
    name                     TEXT NOT NULL,
    description              TEXT NOT NULL,
    status                   VARCHAR(20) NOT NULL DEFAULT 'active',
    -- controller | processor | joint_controller
    controller_or_processor  VARCHAR(20) NOT NULL,
    purpose                  TEXT NOT NULL,
    data_subjects            JSONB NOT NULL DEFAULT '[]'::jsonb,
    data_categories          JSONB NOT NULL DEFAULT '[]'::jsonb,
    recipients               JSONB NOT NULL DEFAULT '[]'::jsonb,
    -- The platform stores this activity reads/writes.
    data_stores              JSONB NOT NULL DEFAULT '[]'::jsonb,
    retention_class_id       TEXT REFERENCES retention_classes(id),
    lawful_basis_record_id   TEXT,
    transfer_assessment_id   TEXT,
    dpia_assessment_id       TEXT,
    -- Where the record is substantiated from (code path / migration), so a
    -- reviewer can verify the seeded facts instead of trusting them.
    source_location          TEXT NOT NULL,
    review_status            VARCHAR(30) NOT NULL DEFAULT 'legal_input_required',
    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT processing_activities_status_valid CHECK (
        status IN ('active', 'retired')
    ),
    CONSTRAINT processing_activities_role_valid CHECK (
        controller_or_processor IN ('controller', 'processor', 'joint_controller')
    ),
    CONSTRAINT processing_activities_review_status_valid CHECK (
        review_status IN ('legal_input_required', 'reviewed', 'approved')
    )
);

CREATE INDEX IF NOT EXISTS idx_processing_activities_status
    ON processing_activities (status, review_status);

-- ─── Lawful basis records (Art. 6 / Art. 9) ─────────────────────────────────
--
-- `basis` is NULL until Legal records the decision; the CHECK makes it
-- impossible to store a review state of "asserted" without a basis, and
-- impossible to store a basis while claiming "requires legal input".

CREATE TABLE IF NOT EXISTS lawful_basis_records (
    id                     TEXT PRIMARY KEY,
    processing_activity_id TEXT NOT NULL REFERENCES processing_activities(id) ON DELETE CASCADE,
    -- Art. 6(1) letter (a..f) or Art. 9(2) condition; NULL = not decided.
    basis                  TEXT,
    basis_status           VARCHAR(30) NOT NULL DEFAULT 'requires_legal_input',
    gdpr_article           TEXT,
    jurisdiction           VARCHAR(10),
    assessment_notes       TEXT NOT NULL,
    assessed_by            TEXT,
    assessed_at            TIMESTAMPTZ,
    review_status          VARCHAR(30) NOT NULL DEFAULT 'legal_input_required',
    created_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT lawful_basis_records_basis_status_valid CHECK (
        basis_status IN ('asserted', 'requires_legal_input')
    ),
    CONSTRAINT lawful_basis_records_review_status_valid CHECK (
        review_status IN ('legal_input_required', 'reviewed', 'approved')
    ),
    CONSTRAINT lawful_basis_records_asserted_requires_basis CHECK (
        basis IS NOT NULL OR basis_status = 'requires_legal_input'
    ),
    CONSTRAINT lawful_basis_records_asserted_requires_assessor CHECK (
        basis_status <> 'asserted' OR (assessed_by IS NOT NULL AND assessed_at IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS idx_lawful_basis_records_activity
    ON lawful_basis_records (processing_activity_id);

-- ─── DPIA assessments (Art. 35) ─────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS dpia_assessments (
    id                     TEXT PRIMARY KEY,
    processing_activity_id TEXT REFERENCES processing_activities(id) ON DELETE SET NULL,
    title                  TEXT NOT NULL,
    -- required | in_progress | completed | not_required
    status                 VARCHAR(30) NOT NULL DEFAULT 'required',
    necessity_assessment   TEXT,
    risks                  JSONB NOT NULL DEFAULT '[]'::jsonb,
    mitigations            JSONB NOT NULL DEFAULT '[]'::jsonb,
    residual_risk          VARCHAR(20),
    dpo_opinion            TEXT,
    completed_at           TIMESTAMPTZ,
    review_due_at          TIMESTAMPTZ,
    source_location        TEXT NOT NULL,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT dpia_assessments_status_valid CHECK (
        status IN ('required', 'in_progress', 'completed', 'not_required')
    ),
    CONSTRAINT dpia_assessments_completed_has_opinion CHECK (
        status <> 'completed' OR (completed_at IS NOT NULL AND dpo_opinion IS NOT NULL)
    )
);

-- ─── Processor / subprocessor contracts (Art. 28) ───────────────────────────

CREATE TABLE IF NOT EXISTS subprocessor_contracts (
    id                     TEXT PRIMARY KEY,
    subprocessor_name      TEXT NOT NULL,
    service_description    TEXT NOT NULL,
    processing_activity_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
    contract_reference     TEXT,
    dpa_signed_at          TIMESTAMPTZ,
    dpa_expires_at         TIMESTAMPTZ,
    data_locations         JSONB NOT NULL DEFAULT '[]'::jsonb,
    security_measures      TEXT,
    -- pending | active | terminated
    status                 VARCHAR(20) NOT NULL DEFAULT 'pending',
    review_status          VARCHAR(30) NOT NULL DEFAULT 'legal_input_required',
    source_location        TEXT NOT NULL,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT subprocessor_contracts_status_valid CHECK (
        status IN ('pending', 'active', 'terminated')
    ),
    CONSTRAINT subprocessor_contracts_active_has_dpa CHECK (
        status <> 'active' OR (dpa_signed_at IS NOT NULL AND contract_reference IS NOT NULL)
    )
);

-- ─── International transfer assessments (Chapter V) ─────────────────────────

CREATE TABLE IF NOT EXISTS international_transfer_assessments (
    id                     TEXT PRIMARY KEY,
    processing_activity_id TEXT REFERENCES processing_activities(id) ON DELETE SET NULL,
    destination_country    VARCHAR(2) NOT NULL,
    destination_entity     TEXT NOT NULL,
    -- adequacy_decision | sccs | bcrs | derogation | undetermined
    transfer_mechanism     VARCHAR(30) NOT NULL DEFAULT 'undetermined',
    mechanism_evidence_id  TEXT,
    tia_completed_at       TIMESTAMPTZ,
    risk_assessment        TEXT,
    supplementary_measures TEXT,
    -- legal_input_required until Legal records the mechanism/decision.
    status                 VARCHAR(30) NOT NULL DEFAULT 'legal_input_required',
    source_location        TEXT NOT NULL,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT international_transfer_assessments_mechanism_valid CHECK (
        transfer_mechanism IN ('adequacy_decision', 'sccs', 'bcrs', 'derogation', 'undetermined')
    ),
    CONSTRAINT international_transfer_assessments_status_valid CHECK (
        status IN ('legal_input_required', 'in_review', 'approved', 'rejected')
    ),
    CONSTRAINT international_transfer_assessments_mechanism_requires_evidence CHECK (
        transfer_mechanism = 'undetermined'
        OR (mechanism_evidence_id IS NOT NULL AND tia_completed_at IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS idx_international_transfer_assessments_country
    ON international_transfer_assessments (destination_country, status);

-- ─── Standard contractual clauses (Art. 46(2)(c)) ───────────────────────────

CREATE TABLE IF NOT EXISTS scc_records (
    id                     TEXT PRIMARY KEY,
    transfer_assessment_id TEXT NOT NULL REFERENCES international_transfer_assessments(id) ON DELETE CASCADE,
    -- c2c | c2p | p2p | p2c (2021/914 modules)
    scc_module             VARCHAR(10) NOT NULL,
    scc_version            TEXT NOT NULL,
    signed_at              TIMESTAMPTZ,
    parties                TEXT NOT NULL,
    document_reference     TEXT,
    status                 VARCHAR(20) NOT NULL DEFAULT 'pending',
    created_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT scc_records_module_valid CHECK (
        scc_module IN ('c2c', 'c2p', 'p2p', 'p2c')
    ),
    CONSTRAINT scc_records_status_valid CHECK (
        status IN ('pending', 'signed', 'expired', 'terminated')
    ),
    CONSTRAINT scc_records_signed_requires_evidence CHECK (
        status <> 'signed' OR (signed_at IS NOT NULL AND document_reference IS NOT NULL)
    )
);

-- ─── Adequacy evidence (Art. 45) ────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS adequacy_evidence (
    id                 TEXT PRIMARY KEY,
    country_code       VARCHAR(2) NOT NULL,
    decision_reference TEXT,
    decision_date      DATE,
    evidence_url       TEXT,
    valid_until        DATE,
    notes              TEXT,
    review_status      VARCHAR(30) NOT NULL DEFAULT 'legal_input_required',
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT adequacy_evidence_review_status_valid CHECK (
        review_status IN ('legal_input_required', 'reviewed', 'approved')
    ),
    CONSTRAINT adequacy_evidence_reference_unique UNIQUE (country_code, decision_reference)
);
