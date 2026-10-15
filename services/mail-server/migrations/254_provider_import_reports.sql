-- Migration 254: Durable provider-import reports (the switching importer).
--
-- A committed provider import (routes/provider_import, POST
-- /v1/import/:provider/:kind?mode=commit) stores its full report here —
-- counts, conflicts, unconvertible-template notes and the templates' ORIGINAL
-- provider bodies — so the receipt (and the review material) survives the
-- request: GET /v1/import/reports/:id. Dry runs write nothing anywhere,
-- this table included.
--
-- Idempotent by construction: CREATE TABLE / INDEX IF NOT EXISTS, no DML.
-- Import replays are idempotent at the artifact level (suppressions and
-- contacts dedupe on (tenant_id, email), templates on (tenant_id, name)), so
-- a replay appends one more report row describing an all-duplicates run.

CREATE TABLE IF NOT EXISTS import_reports (
    id          VARCHAR(26)  PRIMARY KEY,
    tenant_id   VARCHAR(26)  NOT NULL,
    provider    VARCHAR(20)  NOT NULL,
    kind        VARCHAR(20)  NOT NULL,
    mode        VARCHAR(10)  NOT NULL,
    file_sha256 VARCHAR(64)  NOT NULL,
    report      JSONB        NOT NULL,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_import_reports_tenant
    ON import_reports(tenant_id, created_at DESC);

