-- =============================================================================
-- 108: analytics-reality fixes — writer support
--
-- 1. system_alerts: add `component`, `source`, `fingerprint` columns so the
--    observability-service alertmanager ingest (POST /alerts) can persist
--    alerts into system_alerts (previously nothing ever wrote the table, so
--    the CP SSE alert stream, dashboard risk counts, and system-health
--    surfaces always saw an empty table). A unique index on (source,
--    fingerprint) makes re-delivered alertmanager webhooks idempotent.
--
-- 2. ent_industry_benchmarks: seed INDUSTRY_BASELINE rows so enterprise QBR
--    benchmark comparisons return data. These are HONEST DEFAULTS — clearly
--    labelled as baseline reference ranges (source = 'INDUSTRY_BASELINE'),
--    NOT customer data, and should be replaced with licensed benchmark
--    datasets when available. Metric values reflect widely-published
--    email-engagement reference ranges for B2B/SaaS senders.
-- =============================================================================


-- ── 1. system_alerts writer columns ────────────────────────────────────────

ALTER TABLE system_alerts ADD COLUMN IF NOT EXISTS component   TEXT;
ALTER TABLE system_alerts ADD COLUMN IF NOT EXISTS source      VARCHAR(64) NOT NULL DEFAULT 'system';
ALTER TABLE system_alerts ADD COLUMN IF NOT EXISTS fingerprint VARCHAR(128);

CREATE UNIQUE INDEX IF NOT EXISTS idx_system_alerts_source_fingerprint
    ON system_alerts (source, fingerprint)
    WHERE source <> 'system' AND fingerprint IS NOT NULL;

-- ── 2. ent_industry_benchmarks INDUSTRY_BASELINE seed ──────────────────────
-- ON CONFLICT (industry, metric_name) DO NOTHING keeps operator-curated
-- overrides intact; the seed only fills gaps.

INSERT INTO ent_industry_benchmarks
    (industry, metric_name, metric_value, percentile_25, percentile_50,
     percentile_75, percentile_90, unit, period, source)
VALUES
    -- SaaS baseline reference ranges (percent scale)
    ('saas', 'delivery_rate',  95.0,  92.0,  95.0,  97.5,  99.0, 'percent', 'INDUSTRY_BASELINE', 'INDUSTRY_BASELINE'),
    ('saas', 'bounce_rate',     2.0,   1.0,   2.0,   4.0,   6.0, 'percent', 'INDUSTRY_BASELINE', 'INDUSTRY_BASELINE'),
    ('saas', 'open_rate',      22.0,  15.0,  22.0,  30.0,  38.0, 'percent', 'INDUSTRY_BASELINE', 'INDUSTRY_BASELINE'),
    ('saas', 'click_rate',      3.0,   1.5,   3.0,   5.0,   8.0, 'percent', 'INDUSTRY_BASELINE', 'INDUSTRY_BASELINE'),
    -- E-commerce baseline reference ranges
    ('ecommerce', 'delivery_rate', 93.0, 90.0, 93.0, 96.0, 98.5, 'percent', 'INDUSTRY_BASELINE', 'INDUSTRY_BASELINE'),
    ('ecommerce', 'bounce_rate',    3.0,  1.5,  3.0,  5.0,  7.0, 'percent', 'INDUSTRY_BASELINE', 'INDUSTRY_BASELINE'),
    ('ecommerce', 'open_rate',     18.0, 12.0, 18.0, 25.0, 32.0, 'percent', 'INDUSTRY_BASELINE', 'INDUSTRY_BASELINE'),
    ('ecommerce', 'click_rate',     2.5,  1.0,  2.5,  4.0,  6.5, 'percent', 'INDUSTRY_BASELINE', 'INDUSTRY_BASELINE'),
    -- Generic fallback for industries without a curated baseline
    ('other', 'delivery_rate',  94.0, 91.0, 94.0, 97.0, 99.0, 'percent', 'INDUSTRY_BASELINE', 'INDUSTRY_BASELINE'),
    ('other', 'bounce_rate',     2.5,  1.0,  2.5, 4.5,  6.5, 'percent', 'INDUSTRY_BASELINE', 'INDUSTRY_BASELINE'),
    ('other', 'open_rate',      20.0, 13.0, 20.0, 28.0, 35.0, 'percent', 'INDUSTRY_BASELINE', 'INDUSTRY_BASELINE'),
    ('other', 'click_rate',      2.8,  1.2,  2.8, 4.5,  7.0, 'percent', 'INDUSTRY_BASELINE', 'INDUSTRY_BASELINE')
ON CONFLICT (industry, metric_name) DO NOTHING;

