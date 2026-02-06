-- ApexMail Database Schema - Queue Jobs (Rollback)

DROP INDEX IF EXISTS idx_queue_jobs_locked;
DROP INDEX IF EXISTS idx_queue_jobs_tenant;
DROP INDEX IF EXISTS idx_queue_jobs_dequeue;
DROP TABLE IF EXISTS queue_jobs;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_type WHERE typname = 'queue_status') THEN
    DROP TYPE queue_status;
  END IF;
END $$;
