-- Migration 008:Add PostgreSQL NOTIFY triggers for queue tables
-- Replaces constant polling with event-driven wakeup (latency:~1s → <5ms)

-- Analytics queue table (was missing from initial schema)
CREATE TABLE IF NOT EXISTS analytics_queue (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    event_type      TEXT NOT NULL,
    priority        INT NOT NULL DEFAULT 0,
    status          TEXT NOT NULL DEFAULT 'pending',
    payload         JSONB NOT NULL,
    worker_id       TEXT,
    attempts        INT NOT NULL DEFAULT 0,
    max_attempts    INT NOT NULL DEFAULT 3,
    scheduled_for   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_analytics_queue_processing
    ON analytics_queue(status, priority DESC, scheduled_for);
CREATE INDEX IF NOT EXISTS idx_analytics_queue_tenant
    ON analytics_queue(tenant_id);

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
