-- 162_ha_chaos.sql
--
-- =============================================================================
-- F63: canonical schema for the ha crate's chaos-engineering experiment log.
-- chaos.rs runs experiments against the live system (INSERT on start, UPDATE
-- to running/completed, get_experiment / list_experiments SELECTs,
-- delete_experiment DELETE) — but no migration ever created
-- ha_chaos_experiments, so the experiment audit trail silently failed.
-- Shape derived from the ExperimentRow struct (ha/src/types.rs) and the
-- exact SELECT/INSERT column lists: config/target/parameters/safety_checks
-- are non-Option serde values → NOT NULL; started_at/completed_at/
-- duration_ms/results/created_by are Option → NULLable. duration_ms is
-- assigned via EXTRACT(EPOCH ...) * 1000 on completion.
-- =============================================================================

CREATE TABLE IF NOT EXISTS ha_chaos_experiments (
    id              UUID        PRIMARY KEY,
    name            VARCHAR(255) NOT NULL,
    experiment_type VARCHAR(50) NOT NULL,
    status          VARCHAR(50) NOT NULL,
        -- pending | running | completed | aborted | failed
    config          JSONB       NOT NULL,
    target          JSONB       NOT NULL,
    parameters      JSONB       NOT NULL,
    safety_checks   JSONB       NOT NULL,
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    duration_ms     BIGINT,
    results         JSONB,
    created_by      VARCHAR(255),
    created_at      TIMESTAMPTZ NOT NULL
);

-- list_experiments: optional status filter + ORDER BY created_at DESC.
CREATE INDEX IF NOT EXISTS idx_ha_chaos_experiments_created_at
    ON ha_chaos_experiments (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ha_chaos_experiments_status
    ON ha_chaos_experiments (status, created_at DESC);
