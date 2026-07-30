-- 085: Control-plane access logging for admin isolation compliance.
-- Logs every access attempt (success and failure) to /cp/* and /v1/admin/* routes.
-- This table is separate from the general audit_logs to keep CP access
-- records immutable and auditable independently from user-facing activity.

CREATE TABLE IF NOT EXISTS cp_access_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(320),
    path VARCHAR(1024) NOT NULL,
    status_code INTEGER NOT NULL,
    outcome VARCHAR(64) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cp_access_log_created_at ON cp_access_log (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_cp_access_log_outcome ON cp_access_log (outcome);
CREATE INDEX IF NOT EXISTS idx_cp_access_log_email ON cp_access_log (email) WHERE email IS NOT NULL;
