-- Email Grader: tenant-scoped grader_results plus retention helper.
--
-- Schema notes:
--   * tenant_id is TEXT (not UUID) because the api-server uses ULID-style
--     VARCHAR(26) tenant identifiers (see migrations 022/023/024).
--   * `from_address`, `subject`, and the optional encrypted-content blob are
--     stored as TEXT so that AES-GCM `v1:<nonce>:<ct>` envelopes (handled by
--     the email-grader crypto module) fit alongside cleartext rows.
--   * `idempotency_key` is unique per tenant inside a configurable window;
--     enforced by the partial index below.
--   * `expires_at` is populated from per-tenant retention settings on insert
--     and the `purge_expired_grader_results()` function is intended to be
--     called periodically by the workers crate.
BEGIN;

CREATE TABLE IF NOT EXISTS grader_results (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       TEXT NOT NULL,
    domain          VARCHAR(255) NOT NULL,
    score           SMALLINT NOT NULL CHECK (score >= 0 AND score <= 100),
    grade           VARCHAR(2) NOT NULL,
    breakdown       JSONB NOT NULL DEFAULT '{}',
    findings        JSONB NOT NULL DEFAULT '[]',
    recommendations TEXT[] NOT NULL DEFAULT '{}',
    from_address    TEXT,
    subject         TEXT,
    body_hash       VARCHAR(64),
    sender_ip       INET,
    idempotency_key TEXT,
    encrypted       BOOLEAN NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ
);

-- Tenant-isolated lookup paths.
CREATE INDEX IF NOT EXISTS idx_grader_results_tenant_created
    ON grader_results (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_grader_results_tenant_id
    ON grader_results (tenant_id, id);
CREATE INDEX IF NOT EXISTS idx_grader_results_tenant_domain
    ON grader_results (tenant_id, domain);

-- Idempotency: within (tenant_id, idempotency_key), only one non-null pair
-- may exist. The window is enforced at the application layer (the row's
-- created_at is compared to GraderConfig::idempotency_window_seconds).
CREATE UNIQUE INDEX IF NOT EXISTS uq_grader_results_idempotency
    ON grader_results (tenant_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL;

-- Retention sweep: deletes rows whose explicit expires_at has passed.
-- Returns the number of rows deleted so callers can emit metrics/logs.
CREATE OR REPLACE FUNCTION purge_expired_grader_results()
RETURNS INTEGER
LANGUAGE plpgsql
AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    WITH del AS (
        DELETE FROM grader_results
        WHERE expires_at IS NOT NULL AND expires_at < NOW()
        RETURNING 1
    )
    SELECT COUNT(*) INTO deleted_count FROM del;
    RETURN deleted_count;
END;
$$;

COMMIT;
