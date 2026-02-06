-- Rollback migration 008: Remove queue NOTIFY triggers

DROP TRIGGER IF EXISTS email_queue_notify ON email_queue;
DROP TRIGGER IF EXISTS webhook_queue_notify ON webhook_queue;
DROP TRIGGER IF EXISTS analytics_queue_notify ON analytics_queue;
DROP FUNCTION IF EXISTS queue_notify();
