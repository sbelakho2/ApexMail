BEGIN;

ALTER TABLE usage_alert_configs
  DROP COLUMN IF EXISTS last_triggered_at;

DROP TABLE IF EXISTS viral_attributions CASCADE;
DROP TABLE IF EXISTS credit_memos CASCADE;
DROP TABLE IF EXISTS slo_breaches CASCADE;
DROP TABLE IF EXISTS billing_addresses CASCADE;
DROP TABLE IF EXISTS proration_records CASCADE;
DROP TABLE IF EXISTS audit_logs CASCADE;
DROP TABLE IF EXISTS webhook_deliveries CASCADE;
DROP TABLE IF EXISTS notification_queue CASCADE;

COMMIT;
