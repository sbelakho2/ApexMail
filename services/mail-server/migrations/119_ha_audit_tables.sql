-- Migration 119: Ha audit tables
--
-- =============================================================================
-- Canonical schema for the HA audit tables. The ha crate writes failover
-- events and replication-lag history (failover.rs record_event /
-- replication.rs) — but no migration ever created either table, so every
-- INSERT failed at runtime and the failover audit trail was silently absent
-- (failures were only warn!'d). The crate also self-bootstraps these shapes
-- at startup (ha::bootstrap_tables) as a defense for already-deployed
-- databases; this migration folds the identical DDL into the canonical
-- chain so a migrated database has them before the service starts, and the
-- shapes stay governed by the chain rather than by crate code.
-- Idempotent and byte-compatible with the crate's bootstrap (IF NOT EXISTS
-- everywhere — whichever runs first, the other no-ops).
-- =============================================================================

CREATE TABLE IF NOT EXISTS ha_failover_events (
    id            UUID PRIMARY KEY,
    from_node     VARCHAR(255) NOT NULL,
    to_node       VARCHAR(255) NOT NULL,
    failover_type VARCHAR(50)  NOT NULL,
    state         VARCHAR(50)  NOT NULL,
    reason        TEXT,
    started_at    TIMESTAMPTZ  NOT NULL,
    completed_at  TIMESTAMPTZ,
    duration_ms   BIGINT,
    data_loss     BOOLEAN      NOT NULL DEFAULT FALSE,
    metadata      JSONB
);
CREATE INDEX IF NOT EXISTS idx_ha_failover_events_started_at
    ON ha_failover_events (started_at DESC);

CREATE TABLE IF NOT EXISTS ha_replication_lag_history (
    id           BIGSERIAL PRIMARY KEY,
    replica_name VARCHAR(255)     NOT NULL,
    lag_ms       DOUBLE PRECISION NOT NULL DEFAULT 0,
    lag_bytes    BIGINT           NOT NULL DEFAULT 0,
    recorded_at  TIMESTAMPTZ      NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_ha_replication_lag_history_recorded_at
    ON ha_replication_lag_history (recorded_at DESC);
