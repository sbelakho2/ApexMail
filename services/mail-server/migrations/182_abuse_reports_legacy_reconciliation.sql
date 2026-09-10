-- Migration 182: reconcile legacy abuse reports into the review queue (audit F09).
--
-- Migration 133 labelled every pre-existing abuse report 'resolved' with
-- no review evidence, so recovery logic could never see a legacy abuse
-- hold. Reconciliation is conservative: only evidence-backed reviewed
-- cases stay resolved (reviewed_at present). Reports that were
-- blanket-resolved without any reviewer action are re-opened into the
-- abuse review queue (status 'open') — unresolved unless evidence.
-- Tenants are NOT auto-suspended by this migration; the review queue
-- itself drives any enforcement decision.

UPDATE abuse_reports
SET status = 'open',
    resolved_at = NULL,
    reviewed_at = NULL,
    reviewed_by = NULL
WHERE status = 'resolved'
  AND reviewed_at IS NULL
  AND resolved_at IS NULL;

-- Review-queue visibility: every unreviewed active report, oldest first.
CREATE INDEX IF NOT EXISTS idx_abuse_reports_review_queue
    ON abuse_reports (status, created_at)
    WHERE status IN ('open', 'investigating');
