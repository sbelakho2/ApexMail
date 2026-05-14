-- 038: Compliance core tables.
--
-- Persists state for the `compliance` crate (audit_logger, secret_manager,
-- risk_scoring, content_scanner, gdpr_automation). Prior migrations did not
-- create these tables; they were assumed to exist at runtime. This migration
-- materialises the canonical schema referenced by the compliance crate's
-- INSERT/UPDATE/SELECT statements verbatim.
--
-- All tables use IF NOT EXISTS so this migration is safe to re-run.

-- ─── Audit log (tamper-evident hash chain) ──────────────────────────────────

CREATE TABLE IF NOT EXISTS audit_logs (
    id              TEXT        PRIMARY KEY,
    tenant_id       TEXT,
    user_id         TEXT,
    session_id      TEXT,
    action          TEXT        NOT NULL,
    resource        TEXT        NOT NULL,
    resource_id     TEXT,
    details         JSONB       NOT NULL DEFAULT '{}'::jsonb,
    ip_address      TEXT,
    user_agent      TEXT,
    outcome         TEXT        NOT NULL,
    error_message   TEXT,
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    hash            TEXT        NOT NULL,
    previous_hash   TEXT,
    signature       TEXT        NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant_ts
    ON audit_logs (tenant_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_ts
    ON audit_logs (user_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action_ts
    ON audit_logs (action, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_resource
    ON audit_logs (resource, resource_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_outcome
    ON audit_logs (outcome) WHERE outcome <> 'success';

CREATE TABLE IF NOT EXISTS audit_logs_archive (LIKE audit_logs INCLUDING ALL);

-- C-15: Remove PK constraint inherited from audit_logs to avoid duplicate PK
-- violations when archiving rows with the same id.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_class c
        JOIN pg_constraint pk ON pk.conrelid = c.oid
        WHERE c.relname = 'audit_logs_archive'
          AND pk.contype = 'p'
          AND pk.conname LIKE '%pk%'
    ) THEN
        EXECUTE format('ALTER TABLE audit_logs_archive DROP CONSTRAINT %I',
            (SELECT pk.conname FROM pg_class c
             JOIN pg_constraint pk ON pk.conrelid = c.oid
             WHERE c.relname = 'audit_logs_archive' AND pk.contype = 'p' LIMIT 1)
        );
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS audit_webhooks (
    id          TEXT        PRIMARY KEY,
    tenant_id   TEXT        NOT NULL,
    url         TEXT        NOT NULL,
    events      JSONB       NOT NULL DEFAULT '[]'::jsonb,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_audit_webhooks_tenant ON audit_webhooks (tenant_id);

-- ─── Secret manager ─────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS secrets (
    id                  TEXT        PRIMARY KEY,
    tenant_id           TEXT        NOT NULL,
    name                TEXT        NOT NULL,
    type                TEXT        NOT NULL,
    encrypted_value     TEXT        NOT NULL,
    version             INTEGER     NOT NULL DEFAULT 1,
    rotation_schedule   JSONB,
    last_rotated_at     TIMESTAMPTZ,
    next_rotation_at    TIMESTAMPTZ,
    created_by          TEXT        NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at          TIMESTAMPTZ,
    UNIQUE (tenant_id, name)
);
CREATE INDEX IF NOT EXISTS idx_secrets_tenant_type ON secrets (tenant_id, type);
CREATE INDEX IF NOT EXISTS idx_secrets_next_rotation
    ON secrets (next_rotation_at) WHERE next_rotation_at IS NOT NULL;

CREATE TABLE IF NOT EXISTS secrets_archive (LIKE secrets INCLUDING ALL);

-- C-16: Remove UNIQUE constraint inherited from secrets to allow archiving
-- multiple historical versions of the same secret (same tenant_id, name).
DO $$
DECLARE
    v_conname TEXT;
BEGIN
    FOR v_conname IN
        SELECT conname FROM pg_constraint
        WHERE conrelid = 'public.secrets_archive'::regclass
          AND contype = 'u'
    LOOP
        EXECUTE format('ALTER TABLE secrets_archive DROP CONSTRAINT %I', v_conname);
    END LOOP;
END $$;

CREATE TABLE IF NOT EXISTS secret_versions (
    secret_id       TEXT        NOT NULL,
    version         INTEGER     NOT NULL,
    encrypted_value TEXT        NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (secret_id, version)
);

CREATE TABLE IF NOT EXISTS secret_access (
    id          TEXT        PRIMARY KEY,
    secret_id   TEXT        NOT NULL,
    user_id     TEXT        NOT NULL,
    access_type TEXT        NOT NULL,
    granted_by  TEXT        NOT NULL,
    granted_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at  TIMESTAMPTZ,
    revoked_at  TIMESTAMPTZ,
    UNIQUE (secret_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_secret_access_user ON secret_access (user_id);

CREATE TABLE IF NOT EXISTS secret_access_log (
    id          BIGSERIAL   PRIMARY KEY,
    secret_id   TEXT        NOT NULL,
    user_id     TEXT        NOT NULL,
    action      TEXT        NOT NULL,
    accessed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_secret_access_log_secret_ts
    ON secret_access_log (secret_id, accessed_at DESC);

-- ─── Risk scoring ───────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS risk_profiles (
    tenant_id            TEXT        PRIMARY KEY,
    risk_score           REAL        NOT NULL DEFAULT 0,
    risk_level           TEXT        NOT NULL DEFAULT 'low',
    factors              JSONB       NOT NULL DEFAULT '{}'::jsonb,
    limits               JSONB       NOT NULL DEFAULT '{}'::jsonb,
    flags                JSONB       NOT NULL DEFAULT '[]'::jsonb,
    last_assessed_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    next_assessment_at   TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '1 day',
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_risk_profiles_level
    ON risk_profiles (risk_level)
    WHERE risk_level IN ('high', 'critical');
CREATE INDEX IF NOT EXISTS idx_risk_profiles_next_assessment
    ON risk_profiles (next_assessment_at);

CREATE TABLE IF NOT EXISTS flag_resolutions (
    id            BIGSERIAL    PRIMARY KEY,
    tenant_id     TEXT         NOT NULL,
    flag_type     TEXT         NOT NULL,
    resolution    TEXT         NOT NULL,
    resolved_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_flag_resolutions_tenant_ts
    ON flag_resolutions (tenant_id, resolved_at DESC);

-- ─── Content scanning ──────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS scan_results (
    id                 TEXT        PRIMARY KEY,
    tenant_id          TEXT        NOT NULL,
    message_id         TEXT,
    scanned_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    results            JSONB       NOT NULL,
    overall_verdict    TEXT        NOT NULL,
    spam_detected      BOOLEAN     NOT NULL DEFAULT FALSE,
    phishing_detected  BOOLEAN     NOT NULL DEFAULT FALSE
);
CREATE INDEX IF NOT EXISTS idx_scan_results_tenant_ts
    ON scan_results (tenant_id, scanned_at DESC);
CREATE INDEX IF NOT EXISTS idx_scan_results_verdict
    ON scan_results (overall_verdict)
    WHERE overall_verdict IN ('block', 'quarantine');

CREATE TABLE IF NOT EXISTS content_policies (
    id          TEXT        PRIMARY KEY,
    tenant_id   TEXT        NOT NULL,
    name        TEXT        NOT NULL,
    rules       JSONB       NOT NULL DEFAULT '[]'::jsonb,
    enabled     BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, name)
);
CREATE INDEX IF NOT EXISTS idx_content_policies_tenant_enabled
    ON content_policies (tenant_id) WHERE enabled = TRUE;

-- ─── GDPR / data-subject requests ───────────────────────────────────────────

CREATE TABLE IF NOT EXISTS data_subject_requests (
    id                          TEXT        PRIMARY KEY,
    tenant_id                   TEXT        NOT NULL,
    request_type                TEXT        NOT NULL,
    email                       TEXT        NOT NULL,
    verification_token_hash     TEXT        NOT NULL,
    verified                    BOOLEAN     NOT NULL DEFAULT FALSE,
    verified_at                 TIMESTAMPTZ,
    status                      TEXT        NOT NULL DEFAULT 'pending_verification',
    requested_at                TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    processed_at                TIMESTAMPTZ,
    completed_at                TIMESTAMPTZ,
    expires_at                  TIMESTAMPTZ NOT NULL,
    result                      JSONB
);
CREATE INDEX IF NOT EXISTS idx_dsr_tenant_status
    ON data_subject_requests (tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_dsr_email
    ON data_subject_requests (email);
CREATE INDEX IF NOT EXISTS idx_dsr_expires_pending
    ON data_subject_requests (expires_at)
    WHERE status = 'pending_verification';

CREATE TABLE IF NOT EXISTS gdpr_exports (
    id           TEXT        PRIMARY KEY,
    request_id   TEXT        NOT NULL,
    tenant_id    TEXT        NOT NULL,
    email        TEXT        NOT NULL,
    data         JSONB       NOT NULL,
    export_url   TEXT,
    expires_at   TIMESTAMPTZ NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_gdpr_exports_request ON gdpr_exports (request_id);
CREATE INDEX IF NOT EXISTS idx_gdpr_exports_expires ON gdpr_exports (expires_at);

CREATE TABLE IF NOT EXISTS consent_records (
    id                TEXT        PRIMARY KEY,
    tenant_id         TEXT        NOT NULL,
    subscriber_id     TEXT        NOT NULL,
    email             TEXT        NOT NULL,
    consent_type      TEXT        NOT NULL,
    granted           BOOLEAN     NOT NULL,
    granted_at        TIMESTAMPTZ,
    revoked_at        TIMESTAMPTZ,
    source            TEXT        NOT NULL,
    ip_address        TEXT,
    user_agent        TEXT,
    proof_document    TEXT,
    expires_at        TIMESTAMPTZ,
    metadata          JSONB       NOT NULL DEFAULT '{}'::jsonb,
    UNIQUE (tenant_id, subscriber_id, consent_type)
);
CREATE INDEX IF NOT EXISTS idx_consent_email
    ON consent_records (tenant_id, email);
CREATE INDEX IF NOT EXISTS idx_consent_type
    ON consent_records (tenant_id, consent_type, granted);

CREATE TABLE IF NOT EXISTS double_opt_in_tokens (
    tenant_id      TEXT        NOT NULL,
    subscriber_id  TEXT        NOT NULL,
    consent_type   TEXT        NOT NULL,
    email          TEXT        NOT NULL,
    token_hash     TEXT        NOT NULL,
    expires_at     TIMESTAMPTZ NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    confirmed_at   TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, subscriber_id, consent_type)
);
CREATE INDEX IF NOT EXISTS idx_doi_expires
    ON double_opt_in_tokens (expires_at) WHERE confirmed_at IS NULL;

-- ─── Suppression list (CAN-SPAM Section 5(a)(4) / GDPR Art.21) ──────────────

CREATE TABLE IF NOT EXISTS suppression_list (
    id          TEXT        PRIMARY KEY,
    tenant_id   TEXT        NOT NULL,
    email       TEXT        NOT NULL,
    reason      TEXT        NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, email)
);
CREATE INDEX IF NOT EXISTS idx_suppression_email ON suppression_list (email);
CREATE INDEX IF NOT EXISTS idx_suppression_tenant_reason
    ON suppression_list (tenant_id, reason);
