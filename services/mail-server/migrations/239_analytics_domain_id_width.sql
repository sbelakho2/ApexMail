-- Migration 239: widen analytics_hourly domain_id
--
-- `domain_id` was sized VARCHAR(26) (nanoid lineage), but production domain
-- ids are UUIDs (36 chars) — the same value `email_queue.domain_id` and
-- `events.domain_id` already carry. Every hourly aggregation roll-up that
-- included a domain dimension failed with "value too long for type
-- character varying(26)" ("Hourly aggregation error", worker log
-- 2026-10-05), so analytics_hourly has been silently EMPTY for
-- domain-scoped stats. VARCHAR(64) matches campaign_id sizing and both id
-- lineages. (Daily aggregates live in ClickHouse, whose schema is string
-- typed — no equivalent defect there.)

ALTER TABLE analytics_hourly ALTER COLUMN domain_id TYPE VARCHAR(64);
