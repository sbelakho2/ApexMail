-- 133: abuse_reports status lifecycle (audit F09).
--
-- Payment-recovery paths (billing-service maintenance.rs mark_payment_recovered
-- and the api-server admin dunning reset) gate tenant reactivation on
-- `abuse_reports.status IN ('open', 'investigating', 'confirmed')` — a column
-- that never existed, so the whole statement failed with 42703. Implement the
-- abuse lifecycle at the schema level:
--
--   * constrained statuses: open -> investigating -> confirmed | dismissed |
--     resolved (a confirmed report can still be resolved after remediation;
--     dismissed/resolved are terminal);
--   * conservative historical backfill: rows written before this migration
--     carry no review state. They are marked 'resolved' so an unreviewable
--     legacy report can never hold a paying tenant's reactivation hostage
--     forever; NEW reports default to 'open' (the cautious state for abuse).
--   * review/resolution timestamps for the audit trail.

ALTER TABLE abuse_reports ADD COLUMN IF NOT EXISTS status VARCHAR(20);

ALTER TABLE abuse_reports
    ADD COLUMN IF NOT EXISTS reviewed_at TIMESTAMPTZ;
ALTER TABLE abuse_reports
    ADD COLUMN IF NOT EXISTS resolved_at TIMESTAMPTZ;
ALTER TABLE abuse_reports
    ADD COLUMN IF NOT EXISTS reviewed_by VARCHAR(26);

-- Backfill first (column was added nullable), then constrain + default.
UPDATE abuse_reports SET status = 'resolved' WHERE status IS NULL;

ALTER TABLE abuse_reports
    ALTER COLUMN status SET NOT NULL,
    ALTER COLUMN status SET DEFAULT 'open';

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'chk_abuse_reports_status'
    ) THEN
        ALTER TABLE abuse_reports
            ADD CONSTRAINT chk_abuse_reports_status
            CHECK (status IN ('open', 'investigating', 'confirmed', 'dismissed', 'resolved'));
    END IF;
END
$$;

CREATE INDEX IF NOT EXISTS idx_abuse_reports_tenant_open
    ON abuse_reports (tenant_id, created_at DESC)
    WHERE status IN ('open', 'investigating', 'confirmed');
