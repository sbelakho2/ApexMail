-- Migration 231: analytics cold-storage compaction ledger (durable commit
-- protocol for hot→cold migration).
--
-- =============================================================================
-- WHY (P0 data-loss finding A): cold-storage compaction used to name its
-- objects `events_{unix_millis}.jsonl` — wall-clock identity. Two batches
-- written in the same millisecond collided, and `std::fs::write` TRUNCATES,
-- so the second batch silently destroyed the first. Objects now carry a
-- random UUIDv4 identity (`events_<uuid>.jsonl`), they are written through a
-- temp file + fsync + atomic rename, and the DELETE of the hot rows happens
-- ONLY after a durable database row exists.
--
-- THE COMMIT PROTOCOL (crates/analytics/src/compaction.rs):
--
--   1. write the JSONL object + its manifest to unique temp files in the
--      target directory, fsync each file, then rename into the final
--      UUID-named path (atomic within the same filesystem);
--   2. INSERT one row here + one row per covered event id into
--      `analytics_compaction_batch_event_ids` inside ONE transaction —
--      this row IS the commit point;
--   3. ONLY THEN delete the migrated rows from `events`.
--
-- Crash windows, honestly:
--   * after step 1 / before step 2 → an ORPHAN object: harmless (it is a
--     complete copy of rows whose hot rows still exist and will be re-written
--     and committed by the rerun; at worst the cold tier briefly holds a
--     duplicate for that one crashed batch — it ages out with the month
--     directory under cold retention). Never data loss.
--   * after step 2 / before step 3 → the rerun consults THIS ledger (finding
--     B's indexed membership lookup, never a filesystem rescan), sees the ids
--     covered, skips the re-write and completes the delete.
--
-- THE LEDGER IS THE SOURCE OF TRUTH (finding C): the filesystem is a
-- materialization. Recovery/verification reads committed rows — never
-- "whatever files exist".
--
-- WHY EXACT PER-ID ROWS (finding B's honest id-coverage tradeoff):
-- `events.id` carries random UUIDv4 text (VARCHAR(64)); producers write
-- `Uuid::new_v4().to_string()`. The ids are NOT time-ordered, so
-- lower/upper id-range columns cannot describe a batch's coverage. A digest
-- cannot answer membership, and a bounded Bloom/count-min sketch has FALSE
-- POSITIVES by design — a false positive here means "skip the cold write,
-- delete the hot row" = silent event loss, which is exactly the P0 class
-- this migration fixes. The honest design the data supports is exact
-- membership: one child row per covered event id, so the rerun's dedup
-- lookup is `WHERE tenant_id = $1 AND event_id = ANY($batch_ids)` — an
-- indexed probe over THE BATCH, i.e. compaction work ∝ batch and recovery
-- ∝ ledger rows (indexed), NEVER ∝ history.
-- =============================================================================

CREATE TABLE IF NOT EXISTS analytics_compaction_batches (
    batch_id     UUID PRIMARY KEY,             -- the UUIDv4 object identity
    tenant_id    VARCHAR(26) NOT NULL,
    year         INTEGER NOT NULL,             -- cold tier {YYYY} of the batch
    month        INTEGER NOT NULL,             -- cold tier {MM} (1..=12); retention parity with the files
    object_key   TEXT NOT NULL,                -- storage-root-relative JSONL path (materialization)
    manifest_key TEXT NOT NULL,                -- storage-root-relative manifest path (materialization)
    event_count  BIGINT NOT NULL,
    checksum     TEXT NOT NULL,                -- SHA-256 hex of the exact JSONL bytes
    committed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()  -- THE COMMIT POINT (precedes the hot DELETE)
);

-- Recovery/verification listing per tenant, newest first.
CREATE INDEX IF NOT EXISTS idx_compaction_batches_tenant_committed
    ON analytics_compaction_batches (tenant_id, committed_at DESC);

-- Retention prune (same {YYYY/MM} cutoff rule as the on-disk month dirs).
CREATE INDEX IF NOT EXISTS idx_compaction_batches_year_month
    ON analytics_compaction_batches (year, month);

-- Exact covered-id ledger: one row per event id a committed batch wrote to
-- cold storage. (batch_id, event_id) is the PK; CASCADE keeps id rows
-- tethered to their batch so the retention prune is one DELETE.
CREATE TABLE IF NOT EXISTS analytics_compaction_batch_event_ids (
    batch_id  UUID NOT NULL REFERENCES analytics_compaction_batches (batch_id) ON DELETE CASCADE,
    tenant_id VARCHAR(26) NOT NULL,
    event_id  TEXT NOT NULL,                   -- matches events.id (VARCHAR(64), free-form text)
    PRIMARY KEY (batch_id, event_id)
);

-- THE recovery-lookup index: per-tenant membership probe
-- `WHERE tenant_id = $1 AND event_id = ANY($2)` — work ∝ batch, never ∝ history.
CREATE INDEX IF NOT EXISTS idx_compaction_event_ids_tenant_event
    ON analytics_compaction_batch_event_ids (tenant_id, event_id);

COMMENT ON TABLE analytics_compaction_batches IS
    'Durable commit ledger for analytics hot→cold compaction (migration 231). One row per '
    'committed cold batch; the INSERT is the commit point that precedes deleting the migrated '
    'rows from events. The ledger row — not the filesystem — is the source of truth for what '
    'cold storage must contain; the object at object_key is a materialization.';

COMMENT ON COLUMN analytics_compaction_batches.checksum IS
    'SHA-256 hex of the exact JSONL bytes written to object_key; lets verification detect a '
    'truncated or corrupted materialization without rescanning history.';

COMMENT ON COLUMN analytics_compaction_batches.committed_at IS
    'The commit point of the compaction protocol: hot rows are deleted only after this '
    'timestamp exists. A crash before it leaves an orphan object (harmless); a crash after it '
    'leaves duplicate coverage that the ledger-driven rerun resolves without re-writing.';

COMMENT ON TABLE analytics_compaction_batch_event_ids IS
    'Exact per-event-id coverage of committed compaction batches (migration 231). Chosen over '
    'id ranges (events.id is random UUIDv4 text, not time-ordered) and over Bloom/digest '
    'sketches (false positives would silently delete an event with no cold copy). The '
    '(tenant_id, event_id) index makes the rerun dedup probe O(batch), never O(history).';
