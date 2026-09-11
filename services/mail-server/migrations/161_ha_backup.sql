-- 161_ha_backup.sql
--
-- =============================================================================
-- F63: canonical schema for the ha crate's backup catalog. backup.rs writes
-- and reads ha_backups (create_backup INSERT, mark-in-progress UPDATE,
-- completion UPDATE, pitr/get_backup/list_backups SELECTs, delete_backup /
-- enforce_retention DELETEs) — but no migration ever created the table, so
-- the entire backup catalog was broken at runtime. Shape derived from the
-- BackupRow struct (ha/src/types.rs) and the exact SELECT column list:
-- tables_included/location/checksum/compression_ratio/wal_lsns/completed_at/
-- duration_ms/parent_backup_id/metadata are Option → NULLable.
-- =============================================================================

CREATE TABLE IF NOT EXISTS ha_backups (
    id                UUID            PRIMARY KEY,
    backup_type       VARCHAR(20)     NOT NULL,
        -- full | incremental
    status            VARCHAR(20)     NOT NULL,
        -- pending | in_progress | completed | failed
    size_bytes        BIGINT          NOT NULL DEFAULT 0,
    tables_included   JSONB,
    location          TEXT,
    checksum          TEXT,
    encrypted         BOOLEAN         NOT NULL,
    compressed        BOOLEAN         NOT NULL,
    compression_ratio DOUBLE PRECISION,
    wal_start_lsn     TEXT,
    wal_end_lsn       TEXT,
    started_at        TIMESTAMPTZ     NOT NULL,
    completed_at      TIMESTAMPTZ,
    duration_ms       BIGINT,
    parent_backup_id  UUID            REFERENCES ha_backups(id),
    metadata          JSONB
);

-- list_backups: optional backup_type/status filters + ORDER BY started_at DESC.
CREATE INDEX IF NOT EXISTS idx_ha_backups_started_at
    ON ha_backups (started_at DESC);
CREATE INDEX IF NOT EXISTS idx_ha_backups_type_status_started
    ON ha_backups (backup_type, status, started_at DESC);
-- pitr: latest completed full backup started before the target timestamp.
CREATE INDEX IF NOT EXISTS idx_ha_backups_pitr
    ON ha_backups (started_at DESC)
    WHERE backup_type = 'full' AND status = 'completed';
-- enforce_retention: DELETE WHERE status = 'completed' AND completed_at < cut.
CREATE INDEX IF NOT EXISTS idx_ha_backups_retention
    ON ha_backups (completed_at)
    WHERE status = 'completed';
