-- ApexMail Database Schema - Queue Jobs
-- Version:1.0.2
-- Adds queue_jobs table used by @apexmail/lib queue implementation

SET lock_timeout = '5s';
SET statement_timeout = '30s';

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'queue_status') THEN
    CREATE TYPE queue_status AS ENUM ('pending', 'processing', 'completed', 'dead_letter');
  END IF;
END $$;

CREATE TABLE IF NOT EXISTS queue_jobs (
  id UUID PRIMARY KEY,
  queue VARCHAR(255) NOT NULL,
  payload JSONB NOT NULL,
  priority INTEGER NOT NULL DEFAULT 0,
  attempts INTEGER NOT NULL DEFAULT 0,
  max_attempts INTEGER NOT NULL DEFAULT 3,
  visibility_timeout INTEGER NOT NULL DEFAULT 300,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  scheduled_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  locked_until TIMESTAMPTZ,
  completed_at TIMESTAMPTZ,
  failed_at TIMESTAMPTZ,
  error_message TEXT,
  tenant_id VARCHAR(255),
  metadata JSONB NOT NULL DEFAULT '{}',
  status queue_status NOT NULL DEFAULT 'pending'
);

CREATE INDEX IF NOT EXISTS idx_queue_jobs_dequeue ON queue_jobs (queue, scheduled_at, priority DESC)
  WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_queue_jobs_dequeue_stable ON queue_jobs (queue, scheduled_at, priority DESC, id)
  WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_queue_jobs_tenant ON queue_jobs (tenant_id, queue)
  WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_queue_jobs_locked ON queue_jobs (locked_until)
  WHERE locked_until IS NOT NULL;
