-- 089_analytics_hourly.sql
--
-- =============================================================================
-- SPLIT-BRAIN RESOLUTION (cont.): analytics_hourly aggregation table
-- =============================================================================
-- The worker AnalyticsProcessor (crates/worker-processors/src/analytics/
-- processor.rs) upserts hourly aggregates into `analytics_hourly`:
--
--   * write_aggregations()      — INSERT ... ON CONFLICT
--       (tenant_id, COALESCE(domain_id, ''), COALESCE(campaign_id, ''), period_start)
--       DO UPDATE SET sent/delivered/... = existing + EXCLUDED
--   * run_hourly_aggregation()  — same upsert target from the events table
--
-- Migration 088 added the analytics_queue poll columns but NO migration ever
-- created `analytics_hourly`, so every flush/hourly rollup failed with
-- "relation analytics_hourly does not exist".
--
-- This migration creates the canonical table with the exact unique expression
-- the ON CONFLICT clause targets.  Idempotent: safe to re-run.
-- =============================================================================


CREATE TABLE IF NOT EXISTS analytics_hourly (
    id           TEXT PRIMARY KEY,
    tenant_id    VARCHAR(26) NOT NULL,
    domain_id    VARCHAR(26),
    campaign_id  VARCHAR(64),
    period_start TIMESTAMPTZ NOT NULL,
    period_end   TIMESTAMPTZ NOT NULL,
    sent         BIGINT NOT NULL DEFAULT 0,
    delivered    BIGINT NOT NULL DEFAULT 0,
    opened       BIGINT NOT NULL DEFAULT 0,
    clicked      BIGINT NOT NULL DEFAULT 0,
    bounced      BIGINT NOT NULL DEFAULT 0,
    unsubscribed BIGINT NOT NULL DEFAULT 0,
    complained   BIGINT NOT NULL DEFAULT 0,
    failed       BIGINT NOT NULL DEFAULT 0,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Unique expression matching the worker's ON CONFLICT target exactly:
--   (tenant_id, COALESCE(domain_id, ''), COALESCE(campaign_id, ''), period_start)
CREATE UNIQUE INDEX IF NOT EXISTS idx_analytics_hourly_unique
    ON analytics_hourly (
        tenant_id,
        COALESCE(domain_id, ''),
        COALESCE(campaign_id, ''),
        period_start
    );

CREATE INDEX IF NOT EXISTS idx_analytics_hourly_period
    ON analytics_hourly (period_start);

