# Database Partitioning Strategy

> **Document Owner:** Backend / Infrastructure Team
> **Last Updated:** 2026-05-11
> **Related:** [`migrations/050_partition_high_volume_tables.sql`](../../services/mail-server/migrations/050_partition_high_volume_tables.sql)

## 1. Overview

High-volume tables require partitioning to maintain query performance as data scales. This document defines the partition strategy, key recommendations, migration approach, and operational procedures.

## 2. Partition Key Recommendations

### 2.1 Primary Partition Keys

| Table | Partition Key | Partition Type | Rationale |
|-------|---------------|----------------|-----------|
| `email_queue` | `(tenant_id, created_at)` | RANGE (by month) | All queries filter by tenant; time-based for TTL |
| `email_delivery_log` | `(tenant_id, attempted_at)` | RANGE (by month) | Tenant-scoped queries; time-series reporting |
| `mail_messages` | `(tenant_id, received_at)` | RANGE (by month) | Mailbox queries filtered by tenant and time |
| `audit_logs` | `(tenant_id, created_at)` | RANGE (by quarter) | Compliance queries by tenant; retention policy |
| `bounce_analytics_daily` | `tenant_id` | LIST (by tenant hash) | Even distribution across partitions |
| `notification_queue` | `(tenant_id, created_at)` | RANGE (by month) | Tenant-scoped notification processing |
| `webhook_delivery_log` | `(tenant_id, created_at)` | RANGE (by month) | Tenant-scoped webhook tracking |

### 2.2 Partition Type Selection

**RANGE Partitioning** — Used for time-series data:
- Data naturally segregates by time period
- Old partitions can be detached/DROPped for TTL
- Query planner prunes partitions based on time range filters
- Example: `email_delivery_log` by month

**LIST Partitioning** — Used for tenant-based distribution:
- Even data distribution across partitions
- Queries filter directly to correct partition
- Supports partition-wise joins for cross-table queries
- Example: `bounce_analytics_daily` by `tenant_id % N`

**Composite Partitioning** — Used for large tables:
- Multi-level partitioning (LIST by tenant, then RANGE by date)
- Provides both tenant isolation and time-based pruning
- Example: `email_queue` partitioned by `tenant_id` hash, sub-partitioned by month

## 3. Migration Strategy (Zero-Downtime)

### 3.1 Prerequisites

- [ ] Table has a primary key that includes the partition column
- [ ] Foreign keys reference the partition column
- [ ] Application queries include the partition column in WHERE clauses
- [ ] Connection pool has sufficient connections for concurrent migration

### 3.2 Migration Steps

```sql
-- Step 1: Create partitioned table with same structure
CREATE TABLE email_queue_new (
    LIKE email_queue INCLUDING DEFAULTS INCLUDING CONSTRAINTS
) PARTITION BY RANGE (created_at);

-- Step 2: Create initial partitions
SELECT create_future_partitions('email_queue_new', '2026-05-01'::date, 6);

-- Step 3: Create indexes on parent table
CREATE INDEX idx_email_queue_new_tenant_status
    ON email_queue_new (tenant_id, status, created_at DESC);

-- Step 4: Attach existing data as default partition
ALTER TABLE email_queue_new ATTACH PARTITION email_queue_legacy
    FOR VALUES FROM (MINVALUE) TO ('2026-05-01');

-- Step 5: Use pgaudit or trigger to dual-write during migration
CREATE OR REPLACE FUNCTION migrate_email_queue_insert()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO email_queue_new VALUES (NEW.*);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_email_queue_migrate
    AFTER INSERT ON email_queue
    FOR EACH ROW EXECUTE FUNCTION migrate_email_queue_insert();

-- Step 6: Backfill historical data in batches
-- Run in application: SELECT backfill_partitioned_table('email_queue', 1000);

-- Step 7: Switch application to new table
-- (Application code update to use email_queue_new instead of email_queue)

-- Step 8: Drop legacy table and rename
DROP TABLE email_queue;
ALTER TABLE email_queue_new RENAME TO email_queue;
```

### 3.3 Batch Backfill Procedure

```rust
pub async fn backfill_partitioned_table(
    pool: &PgPool,
    source_table: &str,
    target_table: &str,
    batch_size: i64,
) -> Result<u64, sqlx::Error> {
    let mut total_migrated = 0u64;
    loop {
        let migrated = sqlx::query_scalar::<_, i64>(&format!(
            "WITH batch AS (
                SELECT id FROM {} WHERE migrated = false
                LIMIT $1 FOR UPDATE SKIP LOCKED
            )
            INSERT INTO {} SELECT * FROM {} WHERE id IN (SELECT id FROM batch)
            RETURNING 1",
            source_table, target_table, source_table
        ))
        .bind(batch_size)
        .execute(pool)
        .await?;

        if migrated == 0 {
            break;
        }
        total_migrated += migrated as u64;
        tracing::info!(migrated = total_migrated, table = %source_table, "Backfill progress");
    }
    Ok(total_migrated)
}
```

## 4. Query Impact Analysis

### 4.1 Supported Query Patterns

```sql
-- ✅ Efficient (partition-pruned):
SELECT * FROM email_delivery_log
WHERE tenant_id = 'abc123'
  AND attempted_at >= '2026-01-01'
  AND attempted_at < '2026-02-01'
ORDER BY attempted_at DESC;

-- ✅ Efficient (partition-pruned):
SELECT * FROM email_queue
WHERE tenant_id = 'abc123'
  AND status = 'pending'
  AND created_at > NOW() - INTERVAL '1 hour';

-- ❌ Inefficient (full scan across all partitions):
SELECT * FROM email_delivery_log
WHERE status = 'failed'
  AND attempted_at > NOW() - INTERVAL '1 hour';
  -- Missing tenant_id filter!

-- ❌ Potentially slow:
SELECT * FROM email_delivery_log
WHERE tenant_id = 'abc123';
  -- No time range filter — scans all partitions for this tenant
```

### 4.2 Query Rewrite Rules

1. **Always include tenant_id** in WHERE clause
2. **Always include time range** bounds (even if wide: `>= '2020-01-01'`)
3. **Avoid cross-partition ORDER BY** without partition pruning
4. **Use partition-wise JOIN** for tables partitioned on same key

## 5. Monitoring Partition Sizes

### 5.1 Partition Size Query

```sql
SELECT
    schemaname,
    tablename,
    pg_size_pretty(pg_total_relation_size(schemaname || '.' || tablename)) as size,
    pg_total_relation_size(schemaname || '.' || tablename) as size_bytes,
    (SELECT COUNT(*) FROM ONLY tablename) as row_count
FROM pg_tables
WHERE tablename LIKE 'email_queue_%'
   OR tablename LIKE 'email_delivery_log_%'
   OR tablename LIKE 'mail_messages_%'
   OR tablename LIKE 'audit_logs_%'
   OR tablename LIKE 'bounce_analytics_%'
ORDER BY size_bytes DESC;
```

### 5.2 Prometheus Metrics

```yaml
# Exposed by postgres-exporter
pg_partition_size_bytes{partition="email_queue_2026_01"} 1234567890
pg_partition_row_count{partition="email_queue_2026_01"} 500000

# Custom metric
apexmail_partition_count{status="ok"} 24
apexmail_partition_size_bytes{partition="email_queue_2026_01"} 1234567890
apexmail_partition_row_count{partition="email_queue_2026_01"} 500000
```

### 5.3 Grafana Dashboard Panels

- **Partition Size Distribution** — Bar chart of partition sizes
- **Partition Growth Rate** — Time series of size per partition
- **Upcoming Partition Creation** — Table of partitions needing creation in next 30 days
- **Oversized Partitions** — Alerts for partitions > 10GB

## 6. Re-Partitioning Procedure

### 6.1 When to Re-Partition

- A partition exceeds 10GB
- Query performance degrades on a partition
- Data distribution changes significantly
- New tenant scale requires more partitions

### 6.2 Re-Partitioning Steps

```sql
-- 1. Create new partition scheme
CREATE TABLE email_queue_v2 (
    LIKE email_queue INCLUDING DEFAULTS INCLUDING CONSTRAINTS
) PARTITION BY RANGE (created_at);

-- 2. Create finer-grained partitions (weekly instead of monthly)
SELECT create_future_partitions('email_queue_v2', '2026-06-01'::date, 12, '1 week');

-- 3. Detach oversized partition
ALTER TABLE email_queue DETACH PARTITION email_queue_2026_05;

-- 4. Split oversized partition data into new scheme
INSERT INTO email_queue_v2 SELECT * FROM email_queue_2026_05;

-- 5. Attach re-partitioned data
-- (Already in correct partitions via routing)

-- 6. Switch application
ALTER TABLE email_queue RENAME TO email_queue_old;
ALTER TABLE email_queue_v2 RENAME TO email_queue;

-- 7. Cleanup
DROP TABLE email_queue_old;
```

### 6.3 Automated Partition Management

The `create_future_partitions()` function in [`migrations/050_partition_high_volume_tables.sql`](../../services/mail-server/migrations/050_partition_high_volume_tables.sql) should be called periodically:

```sql
-- Run weekly via pg_cron or application scheduler
SELECT create_future_partitions('email_queue', NOW()::date, 3);
SELECT create_future_partitions('email_delivery_log', NOW()::date, 3);
SELECT create_future_partitions('mail_messages', NOW()::date, 3);
SELECT create_future_partitions('audit_logs', NOW()::date, 4);

-- Detach partitions older than retention period
SELECT drop_old_partitions('email_queue', INTERVAL '90 days');
SELECT drop_old_partitions('email_delivery_log', INTERVAL '90 days');
SELECT drop_old_partitions('audit_logs', INTERVAL '365 days');
```

## 7. Partition Retention Policy

| Table | Retention | Detach Action | Data Disposition |
|-------|-----------|---------------|------------------|
| `email_queue` | 90 days | DROP | Delete completed deliveries |
| `email_delivery_log` | 90 days | DROP | Delete old delivery records |
| `mail_messages` | 365 days | DETACH | Archive to cold storage |
| `audit_logs` | 365 days | DETACH | Archive to cold storage |
| `bounce_analytics_daily` | 730 days | DROP | Aggregate and delete |
| `notification_queue` | 30 days | DROP | Delete processed notifications |
| `webhook_delivery_log` | 90 days | DROP | Delete old webhook logs |

## 8. Testing Partition Pruning

```sql
-- Verify partition pruning with EXPLAIN
EXPLAIN (ANALYZE, BUFFERS)
SELECT * FROM email_delivery_log
WHERE tenant_id = 'test-tenant'
  AND attempted_at >= '2026-01-01'
  AND attempted_at < '2026-02-01';

-- Expected: Only scans the relevant monthly partition
-- Look for: "Partition Pruned: 11 of 12 partitions scanned"
-- Look for: "Seq Scan on email_delivery_log_2026_01" (single partition)
```

## 9. Operational Runbook

### Daily
- Check partition sizes (Prometheus + Grafana)
- Verify partition pruning on top queries
- Monitor partition creation cron job

### Weekly
- Review slow query log for missing partition filters
- Check partition growth rates
- Verify retention policy execution

### Monthly
- Create next month's partitions (automated)
- Review partition count and distribution
- Archive detached partitions to cold storage
- Update partition size baselines
