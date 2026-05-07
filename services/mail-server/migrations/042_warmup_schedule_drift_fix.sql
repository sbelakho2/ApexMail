-- Migration 042: IP-pool warmup schedule storage.
--
-- The api-server admin/warmup routes expect a per-pool, per-day warmup
-- schedule with progress columns (target_volume, actual_volume, status).
-- The earlier `isp_warmup_schedules` table in tools/migrations was only an
-- ISP catalog (one row per provider, no pool linkage). This migration
-- introduces the canonical per-pool table that the routes already query,
-- and a separate ISP catalog table for the templates.

-- Per-pool, per-day warmup state. One row per (pool_id, day).
CREATE TABLE IF NOT EXISTS isp_warmup_schedules (
    id              VARCHAR(40) PRIMARY KEY,
    pool_id         VARCHAR(40) NOT NULL,
    day             INT NOT NULL,
    target_volume   BIGINT NOT NULL,
    actual_volume   BIGINT,
    status          TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'active', 'completed', 'paused', 'failed')),
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    notes           TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (pool_id, day)
);

CREATE INDEX IF NOT EXISTS idx_isp_warmup_schedules_pool
    ON isp_warmup_schedules (pool_id, day);

CREATE INDEX IF NOT EXISTS idx_isp_warmup_schedules_active
    ON isp_warmup_schedules (status, pool_id)
    WHERE status IN ('pending', 'active');

-- ISP-level template catalog (decoupled from any pool).
CREATE TABLE IF NOT EXISTS isp_warmup_templates (
    id              VARCHAR(40) PRIMARY KEY,
    isp_name        VARCHAR(100) NOT NULL UNIQUE,
    mx_patterns     JSONB NOT NULL DEFAULT '[]'::jsonb,
    warmup_schedule JSONB NOT NULL,        -- ordered array of daily volumes
    notes           TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO isp_warmup_templates (id, isp_name, mx_patterns, warmup_schedule, notes) VALUES
    ('isp_gmail', 'Gmail',
     '["*.google.com", "*.googlemail.com"]',
     '[50,100,200,400,800,1500,2500,4000,6000,8000,10000,15000,20000,30000]',
     'Gmail is strict — ramp slowly'),
    ('isp_microsoft', 'Microsoft',
     '["*.outlook.com", "*.hotmail.com", "*.live.com"]',
     '[100,200,400,800,1500,3000,5000,8000,12000,18000,25000,35000,50000]',
     'Microsoft allows faster warmup'),
    ('isp_yahoo', 'Yahoo',
     '["*.yahoodns.net", "*.yahoo.com"]',
     '[50,100,200,400,800,1500,2500,4000,6000,8000,10000,15000,20000]',
     'Yahoo similar to Gmail'),
    ('isp_default', 'Default',
     '["*"]',
     '[100,200,400,800,1500,3000,5000,8000,12000,18000,25000,35000,50000,75000,100000]',
     'Default schedule for other ISPs')
ON CONFLICT (isp_name) DO NOTHING;
