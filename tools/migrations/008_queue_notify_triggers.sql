-- Migration 008: Add PostgreSQL NOTIFY triggers for queue tables
-- Replaces constant polling with event-driven wakeup (latency: ~1s → <5ms)

-- Trigger function that sends a NOTIFY on the appropriate channel
CREATE OR REPLACE FUNCTION queue_notify() RETURNS trigger AS $$
BEGIN
  PERFORM pg_notify('queue_' || TG_TABLE_NAME, NEW.id::text);
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Notify on new email queue inserts
CREATE TRIGGER email_queue_notify
  AFTER INSERT ON email_queue
  FOR EACH ROW
  EXECUTE FUNCTION queue_notify();

-- Notify on new webhook queue inserts
CREATE TRIGGER webhook_queue_notify
  AFTER INSERT ON webhook_queue
  FOR EACH ROW
  EXECUTE FUNCTION queue_notify();

-- Notify on new analytics queue inserts
CREATE TRIGGER analytics_queue_notify
  AFTER INSERT ON analytics_queue
  FOR EACH ROW
  EXECUTE FUNCTION queue_notify();
