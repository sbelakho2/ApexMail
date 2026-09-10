-- 194_ha_health_checks.sql
--
-- =============================================================================
-- F63: canonical schema for the HA service's persisted health-check results.
-- health_check.rs record_health_check INSERTs (node_id, region, status,
-- components, checked_at) and get_cluster_status SELECTs the same five
-- columns filtered to the last five minutes — but no migration ever created
-- ha_health_checks, so every INSERT failed at runtime (warn!'d) and the
-- cluster status read failed with 42P01.
--
-- Shape derived from the exact INSERT/SELECT column lists and their bound
-- types: node_id/region/status TEXT (config strings + HealthStatus display),
-- components JSONB (serde_json::to_value(&[ComponentHealth])), checked_at
-- TIMESTAMPTZ (bound NOW() server-side).
--
-- Uniqueness: the INSERT already carries ON CONFLICT DO NOTHING, which only
-- has meaning against a unique key. (node_id, checked_at) is that key — two
-- results for one node at the same instant are the same observation. An
-- identity BIGSERIAL primary key keeps the table append-only and gives
-- retention cleanup a stable row identity.
--
-- Retention: HealthCheckService::cleanup_history deletes rows older than
-- the configured window; idx_ha_health_checks_checked_at serves that scan.
-- =============================================================================

CREATE TABLE IF NOT EXISTS ha_health_checks (
    id          BIGSERIAL   PRIMARY KEY,
    node_id     VARCHAR(255) NOT NULL,
    region      VARCHAR(255) NOT NULL,
    status      VARCHAR(20)  NOT NULL,
        -- healthy | degraded | unhealthy | unknown
    components  JSONB        NOT NULL,
    checked_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_ha_health_checks_node_checked UNIQUE (node_id, checked_at)
);

-- get_cluster_status: latest results within a time window, newest first.
CREATE INDEX IF NOT EXISTS idx_ha_health_checks_checked_at
    ON ha_health_checks (checked_at DESC);
CREATE INDEX IF NOT EXISTS idx_ha_health_checks_node_checked
    ON ha_health_checks (node_id, checked_at DESC);
