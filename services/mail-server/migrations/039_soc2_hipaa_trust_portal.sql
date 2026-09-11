-- 039: SOC2 Type II + HIPAA BAA + Trust Portal.
--
-- Provides the persistence layer for ApexMail's enterprise compliance posture:
--   * SOC2 Trust Service Criteria control catalog + automated evidence collection
--   * HIPAA Business Associate Agreement (BAA) lifecycle
--   * Public Trust Portal (security posture, subprocessors, incidents,
--     downloadable documents)
--
-- These tables underpin /v1/admin/soc2, /v1/admin/hipaa, /v1/admin/trust
-- and the public /trust/* endpoints. Backed by the new `compliance::soc2`,
-- `compliance::hipaa`, and `compliance::trust_portal` modules.

-- ─── SOC2 control catalog ──────────────────────────────────────────────────

-- One row per Trust Service Criteria control we attest to (e.g. CC1.1, CC6.1,
-- A1.2). Rows are seeded by `compliance::soc2::seed_default_controls()` on
-- service startup so adding/removing controls is a code-level change.
CREATE TABLE IF NOT EXISTS soc2_controls (
    id                  TEXT        PRIMARY KEY,
    control_id          TEXT        NOT NULL UNIQUE,    -- e.g. "CC1.1", "A1.2"
    category            TEXT        NOT NULL,           -- "Common Criteria", "Availability", ...
    title               TEXT        NOT NULL,
    description         TEXT        NOT NULL,
    owner               TEXT        NOT NULL,           -- e.g. "Security", "Engineering"
    status              TEXT        NOT NULL DEFAULT 'in_scope',  -- in_scope | not_applicable | deferred
    evidence_required   JSONB       NOT NULL DEFAULT '[]'::jsonb, -- list of evidence_type tags
    automation          TEXT        NOT NULL DEFAULT 'manual',    -- manual | automated | hybrid
    last_attested_at    TIMESTAMPTZ,
    next_attestation_at TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_soc2_controls_status_next
    ON soc2_controls (status, next_attestation_at);

-- Captured evidence (point-in-time snapshots, signed and hash-locked).
CREATE TABLE IF NOT EXISTS soc2_control_evidence (
    id              TEXT        PRIMARY KEY,
    control_id      TEXT        NOT NULL REFERENCES soc2_controls (control_id) ON DELETE CASCADE,
    evidence_type   TEXT        NOT NULL,            -- "access_review", "backup_test", "vuln_scan", ...
    source          TEXT        NOT NULL,            -- "audit_logs", "dedicated_ips", "github", ...
    payload         JSONB       NOT NULL,            -- structured evidence body
    sha256_hash     TEXT        NOT NULL,            -- hex(SHA256(canonical_json(payload)))
    storage_url     TEXT,                            -- optional offsite blob URL
    period_start    TIMESTAMPTZ NOT NULL,
    period_end      TIMESTAMPTZ NOT NULL,
    collected_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    collected_by    TEXT        NOT NULL DEFAULT 'system',
    UNIQUE (control_id, evidence_type, period_start, period_end)
);
CREATE INDEX IF NOT EXISTS idx_soc2_evidence_control_collected
    ON soc2_control_evidence (control_id, collected_at DESC);
CREATE INDEX IF NOT EXISTS idx_soc2_evidence_period
    ON soc2_control_evidence (period_start, period_end);

-- Audit trail of automated evidence-collection runs (pass/fail, errors).
CREATE TABLE IF NOT EXISTS soc2_evidence_collection_runs (
    id              BIGSERIAL   PRIMARY KEY,
    control_id      TEXT        NOT NULL,
    evidence_type   TEXT        NOT NULL,
    run_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status          TEXT        NOT NULL,                 -- success | failed | partial
    items_collected INTEGER     NOT NULL DEFAULT 0,
    duration_ms     INTEGER     NOT NULL DEFAULT 0,
    error           TEXT
);
CREATE INDEX IF NOT EXISTS idx_soc2_runs_control_ts
    ON soc2_evidence_collection_runs (control_id, run_at DESC);

-- ─── HIPAA Business Associate Agreement (BAA) lifecycle ────────────────────

-- One row per tenant/BAA. The lifecycle is:
--   draft -> requested -> signed -> countersigned -> active -> terminated
--
-- The hipaa_compliance flag in plan_features.json must be enabled before a
-- BAA can advance past 'requested'. Active BAAs gate the HIPAA-restricted
-- API surface (PHI logging suppression, encrypted-at-rest mailboxes, etc.).
CREATE TABLE IF NOT EXISTS hipaa_baas (
    id                  TEXT        PRIMARY KEY,
    tenant_id           TEXT        NOT NULL,
    version             TEXT        NOT NULL DEFAULT 'v1.0',
    status              TEXT        NOT NULL DEFAULT 'draft',
        -- draft | requested | signed | countersigned | active | terminated
    signer_name         TEXT,
    signer_email        TEXT,
    signer_title        TEXT,
    signer_ip           TEXT,
    signed_at           TIMESTAMPTZ,
    signed_signature    TEXT,                       -- HMAC signature of canonical doc
    countersigner_name  TEXT,
    countersigner_email TEXT,
    countersigned_at    TIMESTAMPTZ,
    document_url        TEXT,                       -- location of the executed PDF
    document_sha256     TEXT,                       -- hex digest of executed PDF bytes
    effective_date      TIMESTAMPTZ,
    terminated_at       TIMESTAMPTZ,
    termination_reason  TEXT,
    metadata            JSONB       NOT NULL DEFAULT '{}'::jsonb,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
-- Only one active BAA per tenant.
CREATE UNIQUE INDEX IF NOT EXISTS uq_hipaa_baa_tenant_active
    ON hipaa_baas (tenant_id) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_hipaa_baa_tenant_status
    ON hipaa_baas (tenant_id, status);

-- Hash-chained immutable history of every BAA state transition.
CREATE TABLE IF NOT EXISTS hipaa_baa_events (
    id          TEXT        PRIMARY KEY,
    baa_id      TEXT        NOT NULL REFERENCES hipaa_baas (id) ON DELETE CASCADE,
    tenant_id   TEXT        NOT NULL,
    event_type  TEXT        NOT NULL,           -- created, requested, signed, countersigned, activated, terminated
    actor       TEXT        NOT NULL,           -- user_id or "system"
    payload     JSONB       NOT NULL DEFAULT '{}'::jsonb,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    hash        TEXT        NOT NULL,
    previous_hash TEXT
);
CREATE INDEX IF NOT EXISTS idx_hipaa_baa_events_baa_ts
    ON hipaa_baa_events (baa_id, occurred_at);

-- ─── Public Trust Portal ───────────────────────────────────────────────────

-- Versioned, public-or-private documents (security whitepaper, SOC2 report,
-- pen-test summary, BCP, etc.). Documents with public=true are served at
-- /trust/{slug}; private documents are gated behind /v1/admin/trust.
CREATE TABLE IF NOT EXISTS trust_portal_documents (
    id              TEXT        PRIMARY KEY,
    slug            TEXT        NOT NULL,
    title           TEXT        NOT NULL,
    document_type   TEXT        NOT NULL,           -- whitepaper | report | policy | certification
    version         TEXT        NOT NULL,
    summary         TEXT,
    content_md      TEXT        NOT NULL,
    sha256_hash     TEXT        NOT NULL,
    storage_url     TEXT,                           -- e.g. signed CDN URL
    public          BOOLEAN     NOT NULL DEFAULT FALSE,
    requires_nda    BOOLEAN     NOT NULL DEFAULT FALSE,
    published_at    TIMESTAMPTZ,
    superseded_by   TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (slug, version)
);
CREATE INDEX IF NOT EXISTS idx_trust_docs_slug_pub
    ON trust_portal_documents (slug)
    WHERE public = TRUE AND superseded_by IS NULL;

-- Subprocessor registry (GDPR Art.28 transparency requirement).
CREATE TABLE IF NOT EXISTS trust_portal_subprocessors (
    id              TEXT        PRIMARY KEY,
    name            TEXT        NOT NULL,
    purpose         TEXT        NOT NULL,
    location        TEXT        NOT NULL,           -- e.g. "EU/Germany", "US/Virginia"
    data_categories JSONB       NOT NULL DEFAULT '[]'::jsonb,
    dpa_url         TEXT,
    certifications  JSONB       NOT NULL DEFAULT '[]'::jsonb,  -- ["SOC2", "ISO27001", ...]
    added_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    removed_at      TIMESTAMPTZ,
    public          BOOLEAN     NOT NULL DEFAULT TRUE,
    UNIQUE (name)
);
CREATE INDEX IF NOT EXISTS idx_trust_subproc_active
    ON trust_portal_subprocessors (added_at DESC) WHERE removed_at IS NULL;

-- Public security-incident log (status-page style).
CREATE TABLE IF NOT EXISTS trust_portal_incidents (
    id            TEXT        PRIMARY KEY,
    slug          TEXT        NOT NULL UNIQUE,
    title         TEXT        NOT NULL,
    severity      TEXT        NOT NULL,          -- low | medium | high | critical
    status        TEXT        NOT NULL,          -- investigating | identified | monitoring | resolved
    started_at    TIMESTAMPTZ NOT NULL,
    detected_at   TIMESTAMPTZ,
    resolved_at   TIMESTAMPTZ,
    summary_md    TEXT        NOT NULL DEFAULT '',
    impact        TEXT,
    root_cause    TEXT,
    customer_data_affected BOOLEAN NOT NULL DEFAULT FALSE,
    public        BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_trust_incidents_status_started
    ON trust_portal_incidents (status, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_trust_incidents_public_started
    ON trust_portal_incidents (started_at DESC) WHERE public = TRUE;

CREATE TABLE IF NOT EXISTS trust_portal_incident_updates (
    id          TEXT        PRIMARY KEY,
    incident_id TEXT        NOT NULL REFERENCES trust_portal_incidents (id) ON DELETE CASCADE,
    status      TEXT        NOT NULL,
    body_md     TEXT        NOT NULL,
    posted_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    posted_by   TEXT        NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_trust_incident_updates_incident
    ON trust_portal_incident_updates (incident_id, posted_at);

-- Customer requests for compliance artifacts (gated behind NDA capture).
CREATE TABLE IF NOT EXISTS trust_portal_access_requests (
    id              TEXT        PRIMARY KEY,
    document_slug   TEXT        NOT NULL,
    requester_name  TEXT        NOT NULL,
    requester_email TEXT        NOT NULL,
    company         TEXT,
    purpose         TEXT,
    nda_accepted    BOOLEAN     NOT NULL DEFAULT FALSE,
    nda_accepted_at TIMESTAMPTZ,
    granted         BOOLEAN     NOT NULL DEFAULT FALSE,
    granted_at      TIMESTAMPTZ,
    granted_by      TEXT,
    revoked_at      TIMESTAMPTZ,
    requested_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_trust_access_requests_pending
    ON trust_portal_access_requests (requested_at DESC) WHERE granted = FALSE;
