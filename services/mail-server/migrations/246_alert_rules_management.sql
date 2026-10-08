-- Migration 246: alert-rule identity and severity on the evaluated store
--
-- The control-plane `/alerts/rules` surface manages the EXISTING evaluated
-- store (`usage_alert_configs`, migration 024): the billing-service
-- maintenance sweep resolves every enabled row against live usage and fires
-- when the threshold holds. A rules page needs two fields the store does not
-- carry yet:
--
--   * `name` — a human label for the rule. The tenant-facing
--     POST /v1/billing/alerts upsert stays valid without one (legacy rows
--     keep NULL and the console falls back to the metric), while the
--     operator surface requires a name for new rules;
--   * `severity` — how a fired rule reads on /alerts. Fired incidents land
--     in `system_alerts`, whose CHECK constraint (migration 020) admits
--     exactly info|warning|critical, so the rule severity uses that set and
--     every legacy row defaults to 'warning'.
--
-- Additive and idempotent: IF NOT EXISTS columns plus a catalog-guarded
-- constraint, safe inside the migrator's single transaction and on re-run.

ALTER TABLE usage_alert_configs
    ADD COLUMN IF NOT EXISTS name TEXT,
    ADD COLUMN IF NOT EXISTS severity TEXT NOT NULL DEFAULT 'warning';

DO $$
BEGIN
    IF to_regclass('public.usage_alert_configs') IS NOT NULL
       AND NOT EXISTS (
           SELECT 1 FROM pg_constraint
           WHERE conname = 'usage_alert_configs_severity_check'
             AND conrelid = to_regclass('public.usage_alert_configs')
       ) THEN
        ALTER TABLE usage_alert_configs
            ADD CONSTRAINT usage_alert_configs_severity_check
            CHECK (severity IN ('info', 'warning', 'critical'));
    END IF;
END $$;
