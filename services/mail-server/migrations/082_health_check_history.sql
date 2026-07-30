-- 082: Health check history — stores periodic system health snapshots.
--
-- Used by the health monitoring background task to retain 7 days of hourly
-- health scores for the /v1/admin/health/history endpoint.

CREATE TABLE IF NOT EXISTS health_check_history (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    overall_score   FLOAT       NOT NULL,
    db_score        FLOAT       NOT NULL,
    redis_score     FLOAT       NOT NULL,
    queue_score     FLOAT       NOT NULL,
    mta_score       FLOAT       NOT NULL,
    disk_score      FLOAT       NOT NULL,
    memory_score    FLOAT       NOT NULL,
    details         JSONB       NOT NULL DEFAULT '{}'::jsonb,
    checked_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_health_check_history_time
    ON health_check_history (checked_at DESC);

CREATE INDEX IF NOT EXISTS idx_health_check_history_recent
    ON health_check_history (checked_at DESC)
    WHERE checked_at > NOW() - INTERVAL '7 days';
