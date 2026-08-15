-- 094_admin_override_columns.sql
--
-- Follow-up to 093: the admin subscription-status override path
-- (routes/billing.rs) writes admin_override_* columns on stripe_subscriptions
-- that were never created.

BEGIN;

ALTER TABLE stripe_subscriptions ADD COLUMN IF NOT EXISTS admin_override_at TIMESTAMPTZ;
ALTER TABLE stripe_subscriptions ADD COLUMN IF NOT EXISTS admin_override_by VARCHAR(64);
ALTER TABLE stripe_subscriptions ADD COLUMN IF NOT EXISTS admin_override_reason TEXT;

COMMIT;
