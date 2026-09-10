-- Migration 103: Lease tokens for queue_jobs (exact lease fencing).
--
-- Problem (audit item K / migrations_needed proposal
-- 20260821_queue_lease_token.sql): complete()/fail()/dead_letter() could
-- only fence on `status = 'processing'`. That closes most of the
-- re-claimed-job window, but a stale worker whose job was recovered and
-- immediately re-dequeued could still race the new owner between the
-- recovery UPDATE and the new dequeue's status flip: both believed they
-- held the lease.
--
-- A per-dequeue lease token makes the fence exact: dequeue mints
-- gen_random_uuid() into lease_token, and every completion-path UPDATE
-- requires (status = 'processing' AND lease_token = $token).
-- recover_stale/replay NULL the token when they flip status so no stale
-- token can ever match again.
--
-- All statements are idempotent and safe to re-run.

DO $$
BEGIN
    IF to_regclass('public.queue_jobs') IS NOT NULL THEN
        ALTER TABLE queue_jobs
            ADD COLUMN IF NOT EXISTS lease_token UUID;

        -- Serves monitoring/recovery lookups by lease owner; the fencing
        -- UPDATE itself is a primary-key lookup.
        CREATE INDEX IF NOT EXISTS idx_queue_jobs_lease
            ON queue_jobs (lease_token)
            WHERE status = 'processing' AND lease_token IS NOT NULL;
    END IF;
END
$$;
