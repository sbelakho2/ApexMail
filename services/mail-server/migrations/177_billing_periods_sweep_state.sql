-- 177: per-period sweep attempt state (audit F31).
--
-- One failing period aborted the whole overage sweep (`...await?` on the
-- first unresolved period), and the sweep's 40-day lookback silently aged
-- unresolved financial work out of the query. This migration adds the
-- per-period attempt ledger so failures are ISOLATED (each period carries
-- its own attempt counter, last error and backoff-decorrelated
-- next-attempt time) and the sweep can expose oldest-unresolved age and
-- failed-period counts. The 40-day cutoff itself is removed from the
-- sweep query in code — unbilled periods are retained until explicitly
-- reconciled (terminal state or 'needs_review' pricing reconciliation,
-- migration 178).

ALTER TABLE billing_periods
    ADD COLUMN IF NOT EXISTS sweep_attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE billing_periods
    ADD COLUMN IF NOT EXISTS last_sweep_error TEXT;
ALTER TABLE billing_periods
    ADD COLUMN IF NOT EXISTS next_sweep_attempt_at TIMESTAMPTZ;

-- Retryable-work scan: unbilled periods whose backoff window has elapsed.
CREATE INDEX IF NOT EXISTS idx_billing_periods_sweep_retry
    ON billing_periods (next_sweep_attempt_at, period_end)
    WHERE invoice_state = 'unbilled';

-- Unresolved-aging observability: every unbilled period, oldest first.
CREATE INDEX IF NOT EXISTS idx_billing_periods_unresolved_age
    ON billing_periods (period_end)
    WHERE invoice_state = 'unbilled';
