-- Down migration: Revert events table partitioning
-- This converts the partitioned table back to a regular heap table

-- Step 1: Create a regular table with same schema
CREATE TABLE events_unpartitioned (
    id VARCHAR(26) PRIMARY KEY,
    tenant_id VARCHAR(26) NOT NULL,
    message_id VARCHAR(26),
    event_type VARCHAR(50) NOT NULL,
    recipient VARCHAR(255),
    recipient_email VARCHAR(255),
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
    raw_data JSONB,
    deduplication_key VARCHAR(64),
    processed_at TIMESTAMPTZ,
    domain VARCHAR(255),
    provider VARCHAR(100),
    provider_message_id VARCHAR(255),
    feedback_id VARCHAR(255),
    location JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Step 2: Copy data from partitioned table
INSERT INTO events_unpartitioned SELECT * FROM events;

DO $$
DECLARE
    partitioned_count BIGINT;
    unpartitioned_count BIGINT;
BEGIN
    SELECT COUNT(*) INTO partitioned_count FROM events;
    SELECT COUNT(*) INTO unpartitioned_count FROM events_unpartitioned;

    IF partitioned_count <> unpartitioned_count THEN
        RAISE EXCEPTION 'rollback integrity check failed: partitioned=% unpartitioned=%', partitioned_count, unpartitioned_count;
    END IF;
END $$;

-- Step 3: Drop the partitioned table (cascades to all partitions)
DROP TABLE events CASCADE;

-- Step 4: Rename back
ALTER TABLE events_unpartitioned RENAME TO events;

-- Step 5: Recreate original indexes
CREATE INDEX idx_events_tenant ON events(tenant_id);
CREATE INDEX idx_events_message ON events(message_id);
CREATE INDEX idx_events_type ON events(event_type);
CREATE INDEX idx_events_timestamp ON events(timestamp);
CREATE INDEX idx_events_recipient ON events(recipient);
