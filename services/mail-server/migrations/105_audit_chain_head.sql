-- 105: Audit hash-chain head table (audit item M-10).
--
-- Every audited event (login, MFA, recovery, billing, admin actions) used to
-- link into the hash chain with:
--     SELECT hash FROM audit_logs ORDER BY timestamp DESC, id DESC LIMIT 1
--     FOR UPDATE
-- in the same transaction as its INSERT. That statement serialises ALL
-- audit writers platform-wide on the newest row of a large partitioned
-- table: every auth event queues behind every other audit event, and the
-- lock is held for the remainder of each writer's transaction (billing
-- writers hold it across their whole business write).
--
-- Fix: keep the chain head in a dedicated single-row-per-chain table.
-- Appends advance it with one INSERT ... ON CONFLICT ... RETURNING statement
-- executed in the SAME transaction as the log insert:
--   * the ON CONFLICT row lock on the head row is the (much narrower)
--     serialization point — it touches no audit_logs rows, so chain
--     verification readers and retention jobs are never blocked;
--   * it is held only for the short append, never across the event's other
--     work;
--   * chain integrity is unchanged: each row's previous_hash is still the
--     hash of the previously appended row, in append order.
--
-- `prev_hash` records the hash the head replaced, which is what the
-- advance statement RETURNs to link the next entry.
--
-- Backfill: seed the head from the newest existing row so post-migration
-- appends chain onto the pre-migration history instead of starting a fresh
-- NULL-rooted chain. Deploy this migration BEFORE the new writer code
-- rolls out; a mixed-version window where old and new writers interleave
-- can fork the chain (same risk class as the old code under a rolling
-- deploy).

CREATE TABLE IF NOT EXISTS audit_chain_head (
    chain_id    TEXT        PRIMARY KEY,
    head_hash   TEXT        NOT NULL,
    prev_hash   TEXT,
    head_seq    BIGINT      NOT NULL DEFAULT 1,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO audit_chain_head (chain_id, head_hash, prev_hash, head_seq)
SELECT 'global', latest.hash, latest.previous_hash, 1
FROM (
    SELECT hash, previous_hash
    FROM audit_logs
    ORDER BY timestamp DESC, id DESC
    LIMIT 1
) AS latest
ON CONFLICT (chain_id) DO NOTHING;
