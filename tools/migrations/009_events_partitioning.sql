/**
 * PERF-002: Time-range partitioning on the events table.
 *
 * The events table is the highest-volume table in the system (every open,
 * click, unsubscribe, bounce, complaint, and delivery event goes here).
 * Every analytics query filters by timestamp — dashboard, volume, engagement,
 * domain breakdown, hourly aggregation, daily rollup, and unique open/click
 * calculations all scan this table.
 *
 * Without partitioning, PostgreSQL must index-scan or seq-scan the ENTIRE
 * table for every time-range query. At 1M events/day, after 6 months that's
 * ~180M rows. The daily rollup runs correlated subqueries per analytics_daily
 * row against this table — for a tenant with 50 campaigns × 5 domains, that's
 * 500 full scans of 180M rows.
 *
 * Monthly range partitioning on `timestamp` enables:
 * - Partition pruning: a 24-hour query touches 1-2 partitions, not 180M rows
 * - Per-partition VACUUM and index maintenance (faster, non-blocking)
 * - Easy archival: DROP old partitions instead of expensive DELETE
 * - ~10-100× speedup on analytics queries proportional to data age
 *
 * Strategy: Declarative partitioning (PostgreSQL 12+) with monthly granularity.
 * This migration creates the partitioned table structure and pre-creates
 * partitions for 2024-01 through 2027-12 (3 years). A cron job or the
 * application should create future partitions as needed.
 */

-- Step 1: Rename the existing table
ALTER TABLE IF EXISTS events RENAME TO events_old;

-- Step 2: Create the new partitioned table matching the existing schema exactly
CREATE TABLE events (
    id VARCHAR(26) NOT NULL,
    tenant_id VARCHAR(26) NOT NULL,
    message_id VARCHAR(26),
    type VARCHAR(50) NOT NULL,
    recipient VARCHAR(255),
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    user_agent TEXT,
    ip_address VARCHAR(45),
    link_id VARCHAR(50),
    link_url TEXT,
    bounce_type VARCHAR(20),
    bounce_subtype VARCHAR(50),
    diagnostic_code TEXT,
    complaint_type VARCHAR(50),
    complaint_user_agent TEXT,
    message_data JSONB,
    deduplication_key VARCHAR(255),
    processed_at TIMESTAMPTZ,
    metadata JSONB,
    domain VARCHAR(255),
    provider VARCHAR(100),
    provider_message_id VARCHAR(255),
    feedback_id VARCHAR(255),
    PRIMARY KEY (id, timestamp)
) PARTITION BY RANGE (timestamp);

-- Step 3: Drop old indexes from renamed table (they keep original names after RENAME)
DROP INDEX IF EXISTS idx_events_tenant;
DROP INDEX IF EXISTS idx_events_message;
DROP INDEX IF EXISTS idx_events_type;
DROP INDEX IF EXISTS idx_events_timestamp;
DROP INDEX IF EXISTS idx_events_recipient;
DROP INDEX IF EXISTS idx_events_dedup;
DROP INDEX IF EXISTS idx_events_tenant_timestamp;
DROP INDEX IF EXISTS idx_events_tenant_type_timestamp;

-- Step 4: Recreate indexes on the partitioned table
-- (These will be automatically created on each partition)
CREATE INDEX idx_events_tenant ON events(tenant_id);
CREATE INDEX idx_events_message ON events(message_id);
CREATE INDEX idx_events_type ON events(type);
CREATE INDEX idx_events_timestamp ON events(timestamp);
CREATE INDEX idx_events_recipient ON events(recipient);
CREATE INDEX idx_events_dedup ON events(deduplication_key) WHERE deduplication_key IS NOT NULL;
CREATE INDEX idx_events_tenant_timestamp ON events(tenant_id, timestamp);
CREATE INDEX idx_events_tenant_type_timestamp ON events(tenant_id, type, timestamp);

-- Step 5: Create monthly partitions (2024-01 through 2027-12)
-- Using a DO block to generate them programmatically
DO $$
DECLARE
    start_date DATE := '2024-01-01';
    end_date DATE := '2028-01-01';
    current_start DATE;
    current_end DATE;
    partition_name TEXT;
BEGIN
    current_start := start_date;
    WHILE current_start < end_date LOOP
        current_end := current_start + INTERVAL '1 month';
        partition_name := 'events_' || TO_CHAR(current_start, 'YYYY_MM');
        
        EXECUTE format(
            'CREATE TABLE %I PARTITION OF events FOR VALUES FROM (CAST(%L AS timestamptz)) TO (CAST(%L AS timestamptz))',
            partition_name,
            current_start,
            current_end
        );
        
        current_start := current_end;
    END LOOP;
END $$;

-- Step 6: Create a default partition for any data outside the defined ranges
CREATE TABLE events_default PARTITION OF events DEFAULT;

-- Step 7: Migrate existing data from the old table
-- This INSERT will route each row to the correct partition based on timestamp
INSERT INTO events SELECT * FROM events_old;

-- Step 8: Drop the old table
DROP TABLE events_old;
