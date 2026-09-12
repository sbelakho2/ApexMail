-- Migration 215: service heartbeats — REAL process liveness leases (audit P1).
--
-- The Control Plane's system_health previously had no true MTA/worker process
-- liveness: `queueWriters` were derived from `queue_jobs` activity and
-- `ipPoolAddresses` were sending-IP rows. A busy queue is not a live process,
-- and an idle-but-alive worker looks dead under traffic inference.
--
-- This table is the explicit lease registry written by each service binary's
-- heartbeat emitter (`apexmail_lib::heartbeat`):
--
--   * one row per PROCESS instance, keyed by
--     instance_id = {service}-{hostname}-{pid};
--   * last_seen_at is refreshed on every beat (default every 30 s);
--   * started_at is written by the first beat and never moved;
--   * capabilities is a JSON array of human-readable labels;
--   * region is optional (never guessed).
--
-- `system_health` reads freshness from this table (stale after 90 s by
-- default) and reports an explicit `no_heartbeat` state for a service with
-- no rows. Process health is NEVER inferred from queue traffic.
--
-- Rollback: DROP TABLE IF EXISTS service_heartbeats;

CREATE TABLE IF NOT EXISTS service_heartbeats (
    instance_id   VARCHAR(200) PRIMARY KEY,
    service       VARCHAR(64)  NOT NULL,
    version       VARCHAR(64)  NOT NULL,
    started_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    last_seen_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    capabilities  JSONB        NOT NULL DEFAULT '[]'::jsonb,
    region        VARCHAR(64),
    CONSTRAINT chk_service_heartbeats_capabilities_array
        CHECK (jsonb_typeof(capabilities) = 'array')
);

-- Liveness read: all instances of one service, freshest first.
CREATE INDEX IF NOT EXISTS idx_service_heartbeats_service_seen
    ON service_heartbeats (service, last_seen_at DESC);

-- Global freshness scan (and future retention cleanup).
CREATE INDEX IF NOT EXISTS idx_service_heartbeats_last_seen
    ON service_heartbeats (last_seen_at DESC);
