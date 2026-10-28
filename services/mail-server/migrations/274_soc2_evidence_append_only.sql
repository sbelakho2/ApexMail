-- Migration 274: SOC 2 evidence is append-only; readers use the latest row.
--
-- External audit 2026-10-28 (evidence integrity, finding 8): the table's
-- unique identity on (control_id, evidence_type, period_start, period_end)
-- combined with record_evidence()'s ON CONFLICT DO UPDATE let a re-collection
-- overwrite the prior payload/hash. Evidence history must never be mutable:
-- every collection writes a NEW row and a correction SUPERSEDES the older row
-- for readers without destroying it.
--
-- This migration:
--   1. drops the old upsert-friendly unique constraint (located by its
--      definition, so a truncated deployment-side constraint name is handled);
--   2. installs an append identity that includes collected_at + id;
--   3. indexes the latest-row lookup used by every reader;
--   4. refuses any UPDATE of an existing evidence row at the DB level, so an
--      application regression cannot silently rewrite evidence;
--   5. clears attestations granted by the old one-item rule; the next
--      recompute re-derives them from the full required evidence set.
--
-- Readers select the latest row per (control, type, period) with
-- ORDER BY collected_at DESC, id DESC.

DO $$
DECLARE
    conname text;
BEGIN
    SELECT c.conname INTO conname
      FROM pg_constraint c
      JOIN pg_class t ON t.oid = c.conrelid
     WHERE t.relname = 'soc2_control_evidence'
       AND c.contype = 'u'
       AND pg_get_constraintdef(c.oid)
           LIKE '%UNIQUE (control_id, evidence_type, period_start, period_end)%'
     LIMIT 1;
    IF conname IS NOT NULL THEN
        EXECUTE format('ALTER TABLE soc2_control_evidence DROP CONSTRAINT %I', conname);
    END IF;
END
$$;

-- Append identity: the old (control, type, period) tuple is no longer unique;
-- a new row is identified by when it was collected and its row id.
CREATE UNIQUE INDEX IF NOT EXISTS uq_soc2_control_evidence_append_identity
    ON soc2_control_evidence
       (control_id, evidence_type, period_start, period_end, collected_at, id);

CREATE INDEX IF NOT EXISTS idx_soc2_evidence_latest
    ON soc2_control_evidence (control_id, evidence_type, collected_at DESC, id DESC);

-- Attestations granted by the previous one-item rule are not trustworthy:
-- any single evidence write set them. Clear them so the next recompute (after
-- a collection) re-derives attestation from the FULL required evidence set.
-- Scoped to rows that actually claim an attestation.
UPDATE soc2_controls
   SET last_attested_at = NULL,
       next_attestation_at = NULL,
       updated_at = NOW()
 WHERE last_attested_at IS NOT NULL
    OR next_attestation_at IS NOT NULL;

CREATE OR REPLACE FUNCTION soc2_control_evidence_append_only()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION
        'soc2_control_evidence is append-only: row % cannot be updated; insert a superseding evidence row instead',
        OLD.id;
END
$$;

DROP TRIGGER IF EXISTS trg_soc2_control_evidence_append_only
    ON soc2_control_evidence;

CREATE TRIGGER trg_soc2_control_evidence_append_only
    BEFORE UPDATE ON soc2_control_evidence
    FOR EACH ROW
    EXECUTE FUNCTION soc2_control_evidence_append_only();
