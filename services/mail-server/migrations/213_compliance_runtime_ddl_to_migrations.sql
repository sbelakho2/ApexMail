-- Migration 213: move every compliance-service runtime-DDL table into the
-- numbered platform chain, and add the DSAR statutory clock + the legally
-- restricted retention archive.
--
-- =============================================================================
-- WHY
--
-- The compliance service used to create its own schema at startup:
--
--   * `GdprAutomation::apply_outbox_migration`  → dsr_verification_outbox
--   * `BreachNotifier::apply_migration`         → breach_reports
--   * `RetentionSweeper::apply_migration`       → retention_report
--   * `AuditLogger::initialize`                 → idx_audit_logs_tenant_timestamp
--
-- Production credentials for that service are supposed to be DML-only, but a
-- DML-only role cannot boot the service while it issues CREATE TABLE / CREATE
-- INDEX at runtime. Every statement the service used to issue is reproduced
-- here byte-for-byte (column names and types match the SQL the code binds),
-- so after this migration the service boots and processes with SELECT /
-- INSERT / UPDATE / DELETE only.
--
-- Statements are idempotent (IF NOT EXISTS + guarded ALTERs) so databases
-- where the runtime DDL already created the legacy shapes are healed:
-- missing columns are added, the legacy `active`/`notified_*` states are
-- mapped onto the new breach state machine, and the default status changes
-- to `detected`.
-- =============================================================================

-- ─── DSR verification outbox (was GdprAutomation::apply_outbox_migration) ────

CREATE TABLE IF NOT EXISTS dsr_verification_outbox (
    id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    email TEXT NOT NULL,
    -- Raw token is required for delivery; data_subject_requests stores only
    -- the SHA-256 hash. Rows are purged by the retention sweep once the
    -- request window (request_expiration_days) has passed.
    verification_token TEXT NOT NULL,
    verify_url TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    attempts INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    sent_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_dsr_outbox_pending
    ON dsr_verification_outbox (status, created_at)
    WHERE status = 'pending';

-- ─── Retention report (was RetentionSweeper::apply_migration) ────────────────

CREATE TABLE IF NOT EXISTS retention_report (
    id TEXT PRIMARY KEY,
    ran_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    plan_tier TEXT NOT NULL DEFAULT 'default',
    report JSONB NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_retention_report_ran_at
    ON retention_report (ran_at DESC);

-- ─── Audit index (was AuditLogger::initialize) ──────────────────────────────

CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant_timestamp
    ON audit_logs (tenant_id, timestamp DESC);

-- ─── DSAR statutory clock (GDPR Art. 12(3)) ─────────────────────────────────
--
-- A GDPR response period is NOT "N configurable days". The clock starts when
-- the request is RECEIVED, the identity-verification event is recorded
-- separately, and the statutory due date (one calendar month after receipt)
-- is persisted so it cannot drift with configuration changes. An extension
-- (up to two further months, Art. 12(3)) is its own recorded, justified,
-- notified act — the DB refuses an extension without both a reason and the
-- timestamp at which the subject was informed.

ALTER TABLE data_subject_requests ADD COLUMN IF NOT EXISTS received_at TIMESTAMPTZ;
ALTER TABLE data_subject_requests ADD COLUMN IF NOT EXISTS identity_verified_at TIMESTAMPTZ;
ALTER TABLE data_subject_requests ADD COLUMN IF NOT EXISTS statutory_due_at TIMESTAMPTZ;
ALTER TABLE data_subject_requests ADD COLUMN IF NOT EXISTS extension_due_at TIMESTAMPTZ;
ALTER TABLE data_subject_requests ADD COLUMN IF NOT EXISTS extension_reason TEXT;
ALTER TABLE data_subject_requests ADD COLUMN IF NOT EXISTS extension_notified_at TIMESTAMPTZ;

-- Backfill existing requests from the legacy timestamps; the canonical
-- receipt event is `requested_at`, identity verification is `verified_at`.
UPDATE data_subject_requests
   SET received_at = requested_at
 WHERE received_at IS NULL;

UPDATE data_subject_requests
   SET identity_verified_at = verified_at
 WHERE identity_verified_at IS NULL AND verified = TRUE AND verified_at IS NOT NULL;

-- One calendar month, evaluated in the database so every row agrees with the
-- application's `statutory_due_at(received_at)` helper across month lengths.
UPDATE data_subject_requests
   SET statutory_due_at = received_at + INTERVAL '1 month'
 WHERE statutory_due_at IS NULL AND received_at IS NOT NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'public.data_subject_requests'::regclass
          AND conname = 'dsr_extension_requires_justification'
    ) THEN
        ALTER TABLE data_subject_requests
            ADD CONSTRAINT dsr_extension_requires_justification CHECK (
                extension_due_at IS NULL
                OR (extension_reason IS NOT NULL AND length(btrim(extension_reason)) > 0
                    AND extension_notified_at IS NOT NULL)
            );
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'public.data_subject_requests'::regclass
          AND conname = 'dsr_statutory_clock_present'
    ) THEN
        -- New rows are written by the service with the full clock; the CHECK
        -- is written so legacy rows backfilled above satisfy it.
        ALTER TABLE data_subject_requests
            ADD CONSTRAINT dsr_statutory_clock_present CHECK (
                statutory_due_at IS NULL OR received_at IS NOT NULL
            );
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_dsr_statutory_due_open
    ON data_subject_requests (statutory_due_at)
    WHERE status NOT IN ('completed', 'rejected', 'expired', 'failed');

-- ─── Legally restricted retention archive ────────────────────────────────────
--
-- Storage limitation (Art. 5(1)(e)) does not authorise deleting records that
-- carry an independent statutory retention obligation (Estonia: accounting
-- evidence, seven years). An ordinary erasure therefore moves those records
-- into a legally-restricted archive instead of deleting them, and the DSAR
-- result discloses what was retained, why, and until when. The lifecycle is
-- monotonic and enforced by a trigger:
--
--     legally_restricted → statutory_expired → deleted
--
-- (no transition backwards; timestamps are write-once).

CREATE TABLE IF NOT EXISTS legal_retention_archive (
    id                  TEXT PRIMARY KEY,
    -- TEXT (not VARCHAR(26)): the archive must accept every tenant id shape
    -- the DSR/erasure tables accept, including legacy long ids.
    tenant_id           TEXT NOT NULL,
    -- sha256(subject email): the archived rows must remain attributable to the
    -- erasure that disclosed them without keeping a second plaintext copy.
    subject_email_hash  TEXT NOT NULL,
    source_table        TEXT NOT NULL,
    source_record_id    TEXT NOT NULL,
    retention_class_id  TEXT NOT NULL,
    reason              TEXT NOT NULL,
    state               VARCHAR(30) NOT NULL DEFAULT 'legally_restricted',
    archived_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    statutory_expiry_at TIMESTAMPTZ NOT NULL,
    statutory_expired_at TIMESTAMPTZ,
    deleted_at          TIMESTAMPTZ,
    -- The disclosure shown to the data subject (what/why/until when).
    disclosure          JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT legal_retention_archive_state_valid CHECK (
        state IN ('legally_restricted', 'statutory_expired', 'deleted')
    ),
    CONSTRAINT legal_retention_archive_expired_requires_timestamp CHECK (
        state <> 'statutory_expired' OR statutory_expired_at IS NOT NULL
    ),
    CONSTRAINT legal_retention_archive_deleted_requires_timestamp CHECK (
        state <> 'deleted' OR deleted_at IS NOT NULL
    ),
    CONSTRAINT legal_retention_archive_unique_record UNIQUE (source_table, source_record_id)
);

CREATE INDEX IF NOT EXISTS idx_legal_retention_archive_subject
    ON legal_retention_archive (tenant_id, subject_email_hash);
CREATE INDEX IF NOT EXISTS idx_legal_retention_archive_due
    ON legal_retention_archive (statutory_expiry_at)
    WHERE state = 'legally_restricted';

CREATE OR REPLACE FUNCTION legal_retention_archive_state_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.state IS DISTINCT FROM OLD.state THEN
        IF NOT (
            (OLD.state = 'legally_restricted' AND NEW.state = 'statutory_expired')
            OR (OLD.state = 'statutory_expired' AND NEW.state = 'deleted')
        ) THEN
            RAISE EXCEPTION
                'illegal legal_retention_archive transition % -> % (monotonic order is legally_restricted -> statutory_expired -> deleted)',
                OLD.state, NEW.state;
        END IF;
    END IF;

    -- Write-once timestamps: once set they may never change or clear.
    IF OLD.archived_at IS NOT NULL AND NEW.archived_at IS DISTINCT FROM OLD.archived_at THEN
        RAISE EXCEPTION 'legal_retention_archive.archived_at is immutable';
    END IF;
    IF OLD.statutory_expired_at IS NOT NULL
       AND NEW.statutory_expired_at IS DISTINCT FROM OLD.statutory_expired_at THEN
        RAISE EXCEPTION 'legal_retention_archive.statutory_expired_at is immutable';
    END IF;
    IF OLD.deleted_at IS NOT NULL AND NEW.deleted_at IS DISTINCT FROM OLD.deleted_at THEN
        RAISE EXCEPTION 'legal_retention_archive.deleted_at is immutable';
    END IF;

    RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS trg_legal_retention_archive_guard ON legal_retention_archive;
CREATE TRIGGER trg_legal_retention_archive_guard
    BEFORE UPDATE ON legal_retention_archive
    FOR EACH ROW
    EXECUTE FUNCTION legal_retention_archive_state_guard();

-- ─── Breach reports: state machine + submission/receipt evidence ────────────
--
--   detected → triage → notifiable | not_notifiable
--   notifiable → authority_queued → authority_submitted → authority_acknowledged
--
-- The old shape (runtime-created) only flipped a status; it stored neither
-- the submitted notification, its hash, the submission timestamp nor the
-- authority reference/receipt. The DB now requires all of them before
-- `authority_submitted` / `authority_acknowledged` can be reached.

CREATE TABLE IF NOT EXISTS breach_reports (
    id TEXT PRIMARY KEY,
    tenant_id VARCHAR(26) NOT NULL,
    discovered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    affected_records INTEGER NOT NULL,
    data_types JSONB NOT NULL DEFAULT '[]',
    description TEXT NOT NULL,
    severity VARCHAR(20) NOT NULL DEFAULT 'medium',
    gdpr_deadline TIMESTAMPTZ,
    hipaa_deadline TIMESTAMPTZ,
    status VARCHAR(30) NOT NULL DEFAULT 'detected',
    -- Triage (notifiable / not_notifiable decision, GDPR Art. 33(1)).
    triage_rationale TEXT,
    triaged_at TIMESTAMPTZ,
    triaged_by TEXT,
    risk_to_subjects BOOLEAN NOT NULL DEFAULT FALSE,
    subject_notification_required BOOLEAN NOT NULL DEFAULT FALSE,
    -- Art. 33(3) assessment fields the submission package is built from.
    dpo_contact TEXT,
    likely_consequences TEXT,
    measures_taken TEXT,
    -- Authority notification evidence.
    authority_submitted_at TIMESTAMPTZ,
    authority_reference TEXT,
    authority_receipt TEXT,
    authority_receipt_received_at TIMESTAMPTZ,
    -- Legacy column kept so pre-213 rows heal without losing the recorded
    -- notification moment; new code writes authority_submitted_at.
    dpa_notified_at TIMESTAMPTZ,
    -- Subject notification (Art. 34) summary; delivery evidence lives in
    -- breach_subject_notification_outbox.
    subjects_notified_at TIMESTAMPTZ,
    resolved_at TIMESTAMPTZ,
    notification_document JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT breach_reports_submitted_requires_timestamp CHECK (
        status <> 'authority_submitted' OR authority_submitted_at IS NOT NULL
    ),
    CONSTRAINT breach_reports_ack_requires_receipt CHECK (
        status <> 'authority_acknowledged'
        OR (authority_reference IS NOT NULL AND authority_receipt IS NOT NULL
            AND authority_receipt_received_at IS NOT NULL)
    )
);

-- Heal the legacy runtime shape: add every column the new model expects, and
-- the constraints above, on databases where breach_reports already exists.
ALTER TABLE breach_reports ADD COLUMN IF NOT EXISTS triage_rationale TEXT;
ALTER TABLE breach_reports ADD COLUMN IF NOT EXISTS triaged_at TIMESTAMPTZ;
ALTER TABLE breach_reports ADD COLUMN IF NOT EXISTS triaged_by TEXT;
ALTER TABLE breach_reports ADD COLUMN IF NOT EXISTS risk_to_subjects BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE breach_reports ADD COLUMN IF NOT EXISTS subject_notification_required BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE breach_reports ADD COLUMN IF NOT EXISTS dpo_contact TEXT;
ALTER TABLE breach_reports ADD COLUMN IF NOT EXISTS likely_consequences TEXT;
ALTER TABLE breach_reports ADD COLUMN IF NOT EXISTS measures_taken TEXT;
ALTER TABLE breach_reports ADD COLUMN IF NOT EXISTS authority_submitted_at TIMESTAMPTZ;
ALTER TABLE breach_reports ADD COLUMN IF NOT EXISTS authority_reference TEXT;
ALTER TABLE breach_reports ADD COLUMN IF NOT EXISTS authority_receipt TEXT;
ALTER TABLE breach_reports ADD COLUMN IF NOT EXISTS authority_receipt_received_at TIMESTAMPTZ;
ALTER TABLE breach_reports ALTER COLUMN status SET DEFAULT 'detected';

-- Map the legacy lifecycle onto the state machine. Legacy rows keep their
-- recorded facts (timestamps) but must still earn `authority_acknowledged`
-- with a real receipt — none exists in the legacy shape, so a `resolved`
-- legacy row lands on `authority_submitted` at best.
UPDATE breach_reports
   SET status = CASE
       WHEN status = 'active' THEN 'detected'
       WHEN status = 'notified_dpa' THEN 'authority_submitted'
       WHEN status = 'notified_subjects' THEN
           CASE WHEN dpa_notified_at IS NOT NULL THEN 'authority_submitted' ELSE 'notifiable' END
       WHEN status = 'resolved' THEN
           CASE
               WHEN authority_receipt_received_at IS NOT NULL THEN 'authority_acknowledged'
               WHEN authority_submitted_at IS NOT NULL OR dpa_notified_at IS NOT NULL THEN 'authority_submitted'
               ELSE 'detected'
           END
       ELSE status
   END
 WHERE status IN ('active', 'notified_dpa', 'notified_subjects', 'resolved');

UPDATE breach_reports
   SET authority_submitted_at = COALESCE(authority_submitted_at, dpa_notified_at)
 WHERE authority_submitted_at IS NULL AND dpa_notified_at IS NOT NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'public.breach_reports'::regclass
          AND conname = 'breach_reports_submitted_requires_timestamp'
    ) THEN
        ALTER TABLE breach_reports
            ADD CONSTRAINT breach_reports_submitted_requires_timestamp CHECK (
                status <> 'authority_submitted' OR authority_submitted_at IS NOT NULL
            );
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'public.breach_reports'::regclass
          AND conname = 'breach_reports_ack_requires_receipt'
    ) THEN
        ALTER TABLE breach_reports
            ADD CONSTRAINT breach_reports_ack_requires_receipt CHECK (
                status <> 'authority_acknowledged'
                OR (authority_reference IS NOT NULL AND authority_receipt IS NOT NULL
                    AND authority_receipt_received_at IS NOT NULL)
            );
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_breach_reports_tenant_id
    ON breach_reports (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_breach_reports_status
    ON breach_reports (status);

-- Status transitions are monotonic; `authority_acknowledged` is unreachable
-- without a recorded receipt (the CHECK above is the hard gate, this trigger
-- keeps the graph honest — no skipping triage, no backwards moves). Legacy
-- source states are accepted as starting points so a rolling deploy of old
-- binaries cannot wedge writes.
CREATE OR REPLACE FUNCTION breach_reports_status_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.status IS DISTINCT FROM OLD.status AND NEW.status <> OLD.status THEN
        IF NOT (
            (OLD.status = 'detected' AND NEW.status = 'triage')
            OR (OLD.status = 'triage' AND NEW.status IN ('notifiable', 'not_notifiable'))
            OR (OLD.status = 'notifiable' AND NEW.status IN ('authority_queued', 'not_notifiable'))
            OR (OLD.status = 'authority_queued' AND NEW.status = 'authority_submitted')
            OR (OLD.status = 'authority_submitted' AND NEW.status = 'authority_acknowledged')
            OR (OLD.status = 'not_notifiable' AND NEW.status = 'authority_acknowledged')
            -- legacy pre-state-machine values
            OR (OLD.status = 'active' AND NEW.status = 'triage')
            OR (OLD.status IN ('notified_dpa', 'notified_subjects') AND NEW.status = 'authority_submitted')
            OR (OLD.status = 'resolved' AND NEW.status IN ('authority_acknowledged', 'authority_submitted', 'detected'))
        ) THEN
            RAISE EXCEPTION
                'illegal breach_reports status transition % -> %',
                OLD.status, NEW.status;
        END IF;
    END IF;
    RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS trg_breach_reports_status_guard ON breach_reports;
CREATE TRIGGER trg_breach_reports_status_guard
    BEFORE UPDATE ON breach_reports
    FOR EACH ROW
    EXECUTE FUNCTION breach_reports_status_guard();

-- ─── Authority submissions (the exact thing that was submitted) ─────────────

CREATE TABLE IF NOT EXISTS breach_authority_submissions (
    id                    TEXT PRIMARY KEY,
    breach_id             TEXT NOT NULL REFERENCES breach_reports(id) ON DELETE CASCADE,
    -- queued (package generated, human task open) | submitted (authority
    -- notification actually made) | receipt_recorded (acknowledged)
    status                VARCHAR(20) NOT NULL DEFAULT 'queued',
    -- human_task when no machine API exists (the platform has none); the
    -- exact package is generated and an authenticated operator submits it.
    channel               VARCHAR(20) NOT NULL DEFAULT 'human_task',
    package               JSONB NOT NULL,
    package_sha256        TEXT NOT NULL,
    -- The exact notification text that was submitted, and its hash.
    submitted_notification TEXT,
    submitted_sha256      TEXT,
    -- Rendered attachment (the submission package as a document) and hash.
    attachment            TEXT,
    attachment_sha256     TEXT,
    authority_reference   TEXT,
    receipt               TEXT,
    submission_timestamp  TIMESTAMPTZ,
    receipt_received_at   TIMESTAMPTZ,
    submitted_by          TEXT,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT breach_authority_submissions_status_valid CHECK (
        status IN ('queued', 'submitted', 'receipt_recorded')
    ),
    CONSTRAINT breach_authority_submissions_channel_valid CHECK (
        channel IN ('human_task', 'machine_api')
    ),
    CONSTRAINT breach_authority_submissions_submitted_evidence CHECK (
        status <> 'submitted'
        OR (submitted_notification IS NOT NULL AND submitted_sha256 IS NOT NULL
            AND submission_timestamp IS NOT NULL AND authority_reference IS NOT NULL)
    ),
    CONSTRAINT breach_authority_submissions_receipt_evidence CHECK (
        status <> 'receipt_recorded'
        OR (receipt IS NOT NULL AND receipt_received_at IS NOT NULL
            AND authority_reference IS NOT NULL AND submission_timestamp IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS idx_breach_authority_submissions_breach
    ON breach_authority_submissions (breach_id, created_at DESC);

-- ─── Mandatory authenticated human task (no machine API) ────────────────────
--
-- Where no supervisory-authority machine API exists, the notification cannot
-- be completed by flipping a status: the exact submission package must be
-- generated AND a mandatory task handed to an authenticated human operator.
-- Completion requires the authenticated actor and a completion timestamp.

CREATE TABLE IF NOT EXISTS breach_authority_tasks (
    id                   TEXT PRIMARY KEY,
    breach_id            TEXT NOT NULL REFERENCES breach_reports(id) ON DELETE CASCADE,
    submission_id        TEXT NOT NULL REFERENCES breach_authority_submissions(id) ON DELETE CASCADE,
    status               VARCHAR(20) NOT NULL DEFAULT 'open',
    required_role        VARCHAR(50) NOT NULL DEFAULT 'dpo',
    task                 TEXT NOT NULL,
    due_at               TIMESTAMPTZ NOT NULL,
    authenticated_actor  TEXT,
    completed_at         TIMESTAMPTZ,
    evidence             JSONB,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT breach_authority_tasks_status_valid CHECK (
        status IN ('open', 'completed', 'cancelled')
    ),
    CONSTRAINT breach_authority_tasks_completion_requires_actor CHECK (
        status <> 'completed' OR (authenticated_actor IS NOT NULL AND completed_at IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS idx_breach_authority_tasks_open
    ON breach_authority_tasks (breach_id) WHERE status = 'open';

-- ─── High-risk data-subject notification outbox ─────────────────────────────
--
-- Art. 34 notification is a real delivery, not a state flip: each recipient
-- gets a durable outbox row carrying the exact notification text and hash,
-- and the row only becomes `sent` with delivery evidence (timestamp plus a
-- provider message id or recorded evidence).

CREATE TABLE IF NOT EXISTS breach_subject_notification_outbox (
    id                  TEXT PRIMARY KEY,
    breach_id           TEXT NOT NULL REFERENCES breach_reports(id) ON DELETE CASCADE,
    tenant_id           VARCHAR(26) NOT NULL,
    recipient_email     TEXT NOT NULL,
    subject             TEXT NOT NULL,
    body_text           TEXT NOT NULL,
    body_sha256         TEXT NOT NULL,
    status              VARCHAR(20) NOT NULL DEFAULT 'pending',
    attempts            INTEGER NOT NULL DEFAULT 0,
    provider_message_id TEXT,
    delivery_evidence   JSONB,
    queued_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    delivered_at        TIMESTAMPTZ,
    failed_reason       TEXT,
    CONSTRAINT breach_subject_outbox_status_valid CHECK (
        status IN ('pending', 'sent', 'failed')
    ),
    CONSTRAINT breach_subject_outbox_delivery_evidence CHECK (
        status <> 'sent'
        OR (delivered_at IS NOT NULL
            AND (provider_message_id IS NOT NULL OR delivery_evidence IS NOT NULL))
    )
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_breach_subject_outbox_recipient
    ON breach_subject_notification_outbox (breach_id, lower(recipient_email));
CREATE INDEX IF NOT EXISTS idx_breach_subject_outbox_pending
    ON breach_subject_notification_outbox (status, queued_at)
    WHERE status = 'pending';
