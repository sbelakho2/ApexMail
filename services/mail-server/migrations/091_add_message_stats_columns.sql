-- Add message tracking-statistics columns to `messages`.
--
-- The tracking service (crates/tracking-service/src/processor.rs, write_events)
-- batches per-message open/click/unsubscribe counters into these columns.
-- Production was missing them, which made every WAL flush fail with
-- "batch update message stats" — events never reached Postgres or ClickHouse.

ALTER TABLE messages
    ADD COLUMN IF NOT EXISTS open_count INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS click_count INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS unsubscribe_count INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS first_opened_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS first_clicked_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

-- subscription_preferences: written by the tracking service's unsubscribe
-- path (categorized preferences) — missing in production, blocking
-- per-category unsubscribes. Matches tools/migrations/001_initial_schema.sql.
CREATE TABLE IF NOT EXISTS subscription_preferences (
    id VARCHAR(26) PRIMARY KEY,
    tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    category VARCHAR(100) NOT NULL,
    subscribed BOOLEAN NOT NULL DEFAULT true,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, email, category)
);

CREATE INDEX IF NOT EXISTS idx_sub_prefs_tenant_email
    ON subscription_preferences(tenant_id, email);
