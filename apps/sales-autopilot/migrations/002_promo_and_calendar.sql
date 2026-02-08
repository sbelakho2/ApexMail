-- FIX-500-151: Promo configs/stats persistence
-- FIX-500-152: Demo slots/preferences persistence

-- =============================================================================
-- PROMO CONFIGS (#151)
-- =============================================================================
CREATE TABLE IF NOT EXISTS promo_configs (
    id              VARCHAR(64) PRIMARY KEY,
    tenant_id       VARCHAR(64) NOT NULL,
    name            VARCHAR(200) NOT NULL,
    type            VARCHAR(50) NOT NULL,
    placement       VARCHAR(50) NOT NULL,
    content         JSONB NOT NULL DEFAULT '{}',
    targeting       JSONB NOT NULL DEFAULT '{}',
    schedule        JSONB NOT NULL DEFAULT '{}',
    active          BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_promo_configs_tenant ON promo_configs(tenant_id);
CREATE INDEX IF NOT EXISTS idx_promo_configs_active ON promo_configs(tenant_id, active) WHERE active = true;

CREATE TABLE IF NOT EXISTS promo_stats (
    promo_id        VARCHAR(64) PRIMARY KEY REFERENCES promo_configs(id) ON DELETE CASCADE,
    impressions     BIGINT NOT NULL DEFAULT 0,
    clicks          BIGINT NOT NULL DEFAULT 0,
    conversions     BIGINT NOT NULL DEFAULT 0,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- =============================================================================
-- DEMO SLOTS / SCHEDULING (#152)
-- =============================================================================
CREATE TABLE IF NOT EXISTS demo_slots (
    id              VARCHAR(64) PRIMARY KEY,
    tenant_id       VARCHAR(64),
    user_id         VARCHAR(64),
    title           VARCHAR(200),
    start_time      TIMESTAMPTZ NOT NULL,
    end_time        TIMESTAMPTZ NOT NULL,
    timezone        VARCHAR(50) NOT NULL DEFAULT 'UTC',
    status          VARCHAR(30) NOT NULL DEFAULT 'available',
    booked_by       VARCHAR(200),
    lead_id         VARCHAR(64),
    meeting_type    VARCHAR(50),
    meeting_link    VARCHAR(500),
    notes           TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_demo_slots_user ON demo_slots(user_id, status);
CREATE INDEX IF NOT EXISTS idx_demo_slots_time ON demo_slots(start_time, end_time);

CREATE TABLE IF NOT EXISTS scheduling_preferences (
    user_id             VARCHAR(64) PRIMARY KEY,
    default_duration    INTEGER NOT NULL DEFAULT 30,
    buffer_before       INTEGER NOT NULL DEFAULT 5,
    buffer_after        INTEGER NOT NULL DEFAULT 5,
    available_days      INTEGER[] NOT NULL DEFAULT '{1,2,3,4,5}',
    available_hours     JSONB NOT NULL DEFAULT '{"start": 9, "end": 17}',
    timezone            VARCHAR(50) NOT NULL DEFAULT 'UTC',
    max_bookings_per_day INTEGER NOT NULL DEFAULT 8,
    min_notice_hours    INTEGER NOT NULL DEFAULT 24,
    max_advance_days    INTEGER NOT NULL DEFAULT 30,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
