-- 160_edge_case_services.sql
--
-- =============================================================================
-- F63: canonical schema for the edge-cases crate's persistence contracts.
-- The crate records attachment scan results (attachment.rs
-- record_scan_result), stores parsed calendar invites (calendar.rs
-- store_event), keeps a per-message delivery-attempt history (delivery.rs
-- record_delivery_attempt / get_delivery_history / is_known_greylister) and
-- caches per-domain SMTPUTF8 capability probes (eai.rs update_domain_capability
-- / check_eai_support) — but no migration ever created any of these tables,
-- so every one of those statements failed at runtime. Column names, types
-- and NULLability below are derived exactly from the crate's SQL strings and
-- row structs (notably: delivery.rs decodes mx_priority/response_code as
-- i16 → SMALLINT, attempt_number as i32 → INTEGER, duration_ms as i64 →
-- BIGINT).
-- =============================================================================

-- ── Attachment anti-virus / validation scan results ─────────────────────────
-- Writer: attachment.rs record_scan_result (INSERT, id via gen_random_uuid()).
CREATE TABLE IF NOT EXISTS edge_attachment_scans (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    message_id    TEXT        NOT NULL,
    filename      TEXT        NOT NULL,
    is_valid      BOOLEAN     NOT NULL,
    virus_scanned BOOLEAN     NOT NULL,
    virus_detected BOOLEAN    NOT NULL,
    virus_name    TEXT,
    errors        JSONB       NOT NULL,
    warnings      JSONB       NOT NULL,
    scanned_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_edge_attachment_scans_message
    ON edge_attachment_scans (message_id);
CREATE INDEX IF NOT EXISTS idx_edge_attachment_scans_detected
    ON edge_attachment_scans (virus_detected)
    WHERE virus_detected;

-- ── Calendar (iCalendar) events extracted from messages ─────────────────────
-- Writer: calendar.rs store_event (INSERT; location is Option → NULLable).
CREATE TABLE IF NOT EXISTS edge_calendar_events (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    message_id      TEXT        NOT NULL,
    uid             TEXT        NOT NULL,
    summary         TEXT        NOT NULL,
    organizer_email TEXT        NOT NULL,
    start_time      TIMESTAMPTZ NOT NULL,
    end_time        TIMESTAMPTZ NOT NULL,
    location        TEXT,
    method          TEXT        NOT NULL,
    status          TEXT        NOT NULL,
    attendee_count  INTEGER     NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_edge_calendar_events_message
    ON edge_calendar_events (message_id);
CREATE INDEX IF NOT EXISTS idx_edge_calendar_events_time
    ON edge_calendar_events (start_time);

-- ── Outbound delivery attempt history ───────────────────────────────────────
-- Writers: delivery.rs record_delivery_attempt (INSERT) and
-- get_delivery_history (SELECT ... WHERE message_id = $1 ORDER BY
-- attempt_number ASC). mx_priority / response_code decode as i16, so they
-- are SMALLINT, not INTEGER.
CREATE TABLE IF NOT EXISTS edge_delivery_attempts (
    id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    message_id       TEXT        NOT NULL,
    attempt_number   INTEGER     NOT NULL,
    mx_host          TEXT        NOT NULL,
    mx_priority      SMALLINT    NOT NULL,
    response_code    SMALLINT    NOT NULL,
    response_message TEXT        NOT NULL,
    response_type    TEXT        NOT NULL,
    attempt_time     TIMESTAMPTZ NOT NULL,
    duration_ms      BIGINT      NOT NULL
);
-- History lookup: one numbered attempt per message.
CREATE UNIQUE INDEX IF NOT EXISTS idx_edge_delivery_attempts_message_attempt
    ON edge_delivery_attempts (message_id, attempt_number);
-- is_known_greylister: mx_host LIKE '%.<domain>' AND response_type =
-- 'greylist' AND attempt_time > NOW() - INTERVAL '30 days'. The LIKE
-- pattern is a suffix match (unindexable), so index the discriminators.
CREATE INDEX IF NOT EXISTS idx_edge_delivery_attempts_greylist
    ON edge_delivery_attempts (response_type, attempt_time)
    WHERE response_type = 'greylist';

-- ── Per-domain EAI (SMTPUTF8) capability cache ──────────────────────────────
-- Writer: eai.rs update_domain_capability (UPSERT on domain) and
-- check_eai_support (fresh within 7 days).
CREATE TABLE IF NOT EXISTS edge_domain_capabilities (
    domain              TEXT        PRIMARY KEY,
    supports_smtputf8   BOOLEAN     NOT NULL,
    checked_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_edge_domain_capabilities_checked_at
    ON edge_domain_capabilities (checked_at);
