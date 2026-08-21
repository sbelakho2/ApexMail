//! DDL schema for the queue_jobs table.

/// SQL DDL to create the queue_jobs table and indexes.
pub const QUEUE_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS queue_jobs (
    id              UUID PRIMARY KEY,
    tenant_id       UUID NOT NULL,
    queue           TEXT NOT NULL,
    payload         JSONB NOT NULL DEFAULT '{}',
    status          TEXT NOT NULL DEFAULT 'pending'
                        CHECK (status IN ('pending', 'processing', 'completed', 'failed', 'dead_letter')),
    attempts        INTEGER NOT NULL DEFAULT 0,
    max_attempts    INTEGER NOT NULL DEFAULT 3,
    priority        INTEGER NOT NULL DEFAULT 0,
    scheduled_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    failed_at       TIMESTAMPTZ,
    error_message   TEXT,
    visibility_timeout INTEGER NOT NULL DEFAULT 300,
    lease_token     UUID,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Primary dequeue index:pending jobs ordered by priority and creation time
CREATE INDEX IF NOT EXISTS idx_queue_jobs_dequeue
    ON queue_jobs (queue, scheduled_at)
    WHERE status = 'pending';

-- Tenant-level stats
CREATE INDEX IF NOT EXISTS idx_queue_jobs_tenant
    ON queue_jobs (tenant_id, status);

-- Stale job recovery
CREATE INDEX IF NOT EXISTS idx_queue_jobs_stale
    ON queue_jobs (started_at)
    WHERE status = 'processing';

-- Purge index
CREATE INDEX IF NOT EXISTS idx_queue_jobs_purge
    ON queue_jobs (queue, updated_at)
    WHERE status IN ('completed', 'dead_letter');

-- Lease ownership lookups (migration 103)
CREATE INDEX IF NOT EXISTS idx_queue_jobs_lease
    ON queue_jobs (lease_token)
    WHERE status = 'processing' AND lease_token IS NOT NULL;
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schema_contains_table() {
        assert!(QUEUE_SCHEMA.contains("CREATE TABLE"));
        assert!(QUEUE_SCHEMA.contains("queue_jobs"));
    }

    #[test]
    fn test_schema_contains_indexes() {
        assert!(QUEUE_SCHEMA.contains("idx_queue_jobs_dequeue"));
        assert!(QUEUE_SCHEMA.contains("idx_queue_jobs_tenant"));
        assert!(QUEUE_SCHEMA.contains("idx_queue_jobs_stale"));
        assert!(QUEUE_SCHEMA.contains("idx_queue_jobs_purge"));
    }

    #[test]
    fn test_schema_contains_required_columns() {
        assert!(QUEUE_SCHEMA.contains("tenant_id"));
        assert!(QUEUE_SCHEMA.contains("payload"));
        assert!(QUEUE_SCHEMA.contains("status"));
        assert!(QUEUE_SCHEMA.contains("attempts"));
        assert!(QUEUE_SCHEMA.contains("visibility_timeout"));
        assert!(!QUEUE_SCHEMA.contains("SKIP LOCKED"));
        // SKIP LOCKED is in the query, not the schema
    }

    #[test]
    fn test_schema_has_status_constraint() {
        assert!(QUEUE_SCHEMA.contains("CHECK"));
        assert!(QUEUE_SCHEMA.contains("pending"));
        assert!(QUEUE_SCHEMA.contains("dead_letter"));
    }
}
