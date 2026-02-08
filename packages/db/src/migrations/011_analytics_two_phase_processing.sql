-- FIX-500-002: Add two-phase processing columns to analytics_queue.
-- Phase 1: processing=true + processing_at=NOW() when claimed by a worker.
-- Phase 2: processed=true after successful flush.
-- A stale-processing sweep can reclaim events stuck in processing=true if
-- the worker crashes between phases.

ALTER TABLE analytics_queue
  ADD COLUMN IF NOT EXISTS processing BOOLEAN NOT NULL DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS processing_at TIMESTAMPTZ;

-- Index for the new two-phase fetch query (WHERE processed=false AND processing=false)
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_analytics_queue_two_phase
  ON analytics_queue (timestamp ASC)
  WHERE processed = false AND processing = false;
