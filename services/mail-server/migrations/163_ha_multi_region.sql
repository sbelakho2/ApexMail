-- 163_ha_multi_region.sql
--
-- =============================================================================
-- F63: canonical schema for the ha crate's multi-region registry and
-- geo-routing rules. multi_region.rs registers regions (UPSERT on name),
-- tracks their health (update_health UPDATE), fences/unfences them, adjusts
-- traffic weights, and manages ordered geo-routing rules
-- (find_matching_rule: WHERE source_region = $1 AND enabled = true
-- ORDER BY priority LIMIT 1) — but no migration ever created either table.
-- Shapes derived from the RegionRow / GeoRoutingRuleRow structs
-- (ha/src/types.rs) and the exact SQL column lists. Rules reference regions
-- by name only and may be registered ahead of the region itself, so no FK
-- is imposed (the code never relies on one).
-- =============================================================================

CREATE TABLE IF NOT EXISTS ha_regions (
    id                  UUID            PRIMARY KEY,
    name                VARCHAR(255)    NOT NULL UNIQUE,
    endpoint            TEXT            NOT NULL,
    status              VARCHAR(50)     NOT NULL,
        -- active | standby | inactive | fenced
    role                VARCHAR(50)     NOT NULL,
        -- primary | secondary
    is_primary          BOOLEAN         NOT NULL DEFAULT FALSE,
    health_score        DOUBLE PRECISION NOT NULL DEFAULT 100.0,
    latency_ms          DOUBLE PRECISION,
    replication_lag_ms  DOUBLE PRECISION,
    weight              INTEGER         NOT NULL DEFAULT 1,
    last_health_check   TIMESTAMPTZ,
    availability_zone   VARCHAR(255),
    metadata            JSONB
);

-- list_regions: ORDER BY is_primary DESC, name.
CREATE INDEX IF NOT EXISTS idx_ha_regions_ordering
    ON ha_regions (is_primary DESC, name);
CREATE INDEX IF NOT EXISTS idx_ha_regions_status
    ON ha_regions (status)
    WHERE status = 'active';

CREATE TABLE IF NOT EXISTS ha_geo_routing_rules (
    id             UUID         PRIMARY KEY,
    name           VARCHAR(255) NOT NULL,
    source_region  VARCHAR(255) NOT NULL,
    target_region  VARCHAR(255) NOT NULL,
    priority       INTEGER      NOT NULL,
    enabled        BOOLEAN      NOT NULL DEFAULT TRUE,
    conditions     JSONB
);

-- find_matching_rule: enabled rules for a source, lowest priority number
-- first; list_geo_rules: ORDER BY priority.
CREATE INDEX IF NOT EXISTS idx_ha_geo_routing_rules_match
    ON ha_geo_routing_rules (source_region, priority)
    WHERE enabled;
