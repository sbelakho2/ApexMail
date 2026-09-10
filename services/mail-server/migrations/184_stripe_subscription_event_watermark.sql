-- Migration 184: subscription event ordering watermark (audit F36).
--
-- handle_subscription_change read and validated the current subscription
-- BEFORE acquiring the tenant entitlement lock, then applied the event
-- unconditionally: a delayed event could pass validation against an
-- earlier snapshot, wait while a replacement committed, then restore the
-- old subscription and cancel the new one. The code now re-reads and
-- re-validates inside the lock; this column persists the ordering
-- watermark (the billing-cycle start of the last APPLIED event) so a
-- same-status older event can never rewind the cycle, and replays are
-- recognized as no-ops.

ALTER TABLE stripe_subscriptions
    ADD COLUMN IF NOT EXISTS event_watermark TIMESTAMPTZ;

-- Backfill: the stored billing_cycle_start of every row IS the cycle the
-- last applied event carried.
UPDATE stripe_subscriptions
SET event_watermark = billing_cycle_start
WHERE event_watermark IS NULL
  AND billing_cycle_start IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_stripe_subscriptions_watermark
    ON stripe_subscriptions (tenant_id, event_watermark DESC)
    WHERE event_watermark IS NOT NULL;
