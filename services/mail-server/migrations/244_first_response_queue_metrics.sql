-- Migration 244: persist the first-response enqueue instant (plan §5.4 SLO)
--
-- The SLO metric is the Prometheus histogram emitted at enqueue; the /sales
-- panel additionally needs queryable percentiles without a metrics backend.
-- `queued_at` records WHEN the approved reply was durably enqueued, so the
-- panel computes accept -> enqueue percentiles from the same rows the metric
-- counts (and labels them as automated-path latency, human review excluded).

ALTER TABLE first_response_requests
    ADD COLUMN IF NOT EXISTS queued_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_first_response_queued
    ON first_response_requests (queued_at)
    WHERE queued_at IS NOT NULL;
