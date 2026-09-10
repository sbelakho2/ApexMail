-- 180: exclusive collection ownership lease (audit F33).
--
-- Collection claiming accepted pending/in_progress rows with no owner: a
-- claim failure was logged and collection proceeded anyway, and two
-- collectors could drive the same invoice concurrently. This adds an
-- owner/lease fence plus a backoff-decorrelated next-attempt time:
--
--   * owner_token identifies the collector that holds the operation;
--   * lease_expires_at bounds the hold — a crashed owner's lease goes
--     stale and can be reclaimed safely;
--   * next_attempt_at is when a retryable failure becomes claimable again.

ALTER TABLE invoice_collection_outbox
    ADD COLUMN IF NOT EXISTS owner_token VARCHAR(64);
ALTER TABLE invoice_collection_outbox
    ADD COLUMN IF NOT EXISTS lease_expires_at TIMESTAMPTZ;
ALTER TABLE invoice_collection_outbox
    ADD COLUMN IF NOT EXISTS next_attempt_at TIMESTAMPTZ;

-- Claimable work: due operations not held under a live lease.
CREATE INDEX IF NOT EXISTS idx_invoice_collection_outbox_claimable
    ON invoice_collection_outbox (next_attempt_at, created_at)
    WHERE status IN ('pending', 'in_progress');
