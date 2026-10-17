-- Migration 263: inbound recipient resolution index + verified duplicate index removal.
--
-- 1. mail_accounts (lower(email)) WHERE is_active = true — the inbound
--    MTA's RCPT-time directory lookup
--    (`servers/inbound.rs`: `WHERE LOWER(email) = LOWER($1) AND is_active =
--    true LIMIT 1`) had no usable index: `mail_accounts_email_key` is on the
--    raw spelling, and EXPLAIN (GENERIC_PLAN) with enable_seqscan=off still
--    planned a Seq Scan. The expression index below is the exact predicate
--    pair the resolver uses (lowercased address + active-only), so the
--    lookup becomes an Index Scan instead of a full registry scan on every
--    RCPT command.
--
-- 2. Duplicate / strict-prefix index removal. Every index below was verified
--    on the live canonical schema (pg_indexes) to duplicate another index or
--    to be a strict prefix of one, so it adds write amplification without
--    serving a read path the retained index cannot:
--
--   idx_audit_logs_tenant_timestamp — IDENTICAL (tenant_id, "timestamp" DESC)
--       to idx_audit_logs_tenant_ts; both are partitioned parent indexes, so
--       dropping the parent cascades to every partition child. audit_logs is
--       the hottest audit table; one less btree to maintain per insert.
--   idx_users_email — IDENTICAL to the UNIQUE users_email_key (email).
--   idx_api_keys_key_hash — IDENTICAL to the UNIQUE uq_api_keys_key_hash
--       (key_hash).
--   idx_sub_prefs_tenant_email_category — IDENTICAL to the UNIQUE
--       subscription_preferences_tenant_id_email_category_key
--       (tenant_id, email, category).
--   idx_campaign_arms_campaign — IDENTICAL to campaign_arms_pkey
--       (campaign_id, arm_index): a second btree over the same key.
--   idx_bounce_analytics_daily_tenant_date — (tenant_id, date DESC), a strict
--       prefix-key twin of the UNIQUE (tenant_id, date) index (btree order is
--       reversible for equality/prefix scans); the partition descendants
--       cascade from the parent drop.
--   idx_dunning_records_tenant — strict prefix of the UNIQUE
--       idx_dunning_records_tenant_unique (tenant_id).
--   idx_plan_overrides_tenant — IMAGE of the UNIQUE
--       plan_overrides_tenant_id_key (tenant_id); the non-unique copy adds
--       nothing.
--   idx_feature_flag_overrides_tenant — IDENTICAL to the UNIQUE
--       idx_feature_flag_overrides_unique (tenant_id, flag_key).
--
-- Additive/idempotent (IF NOT EXISTS / IF EXISTS; no DML). Plain CREATE INDEX
-- (not CONCURRENTLY) because migrations run inside a transaction.

-- ---------------------------------------------------------------------------
-- 1. Inbound RCPT->DATA mailbox directory lookup.
-- ---------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_mail_accounts_email_lower
    ON mail_accounts (lower(email))
    WHERE is_active = true;

-- ---------------------------------------------------------------------------
-- 2. Verified duplicate / redundant indexes removed.
-- ---------------------------------------------------------------------------
DROP INDEX IF EXISTS idx_audit_logs_tenant_timestamp;
DROP INDEX IF EXISTS idx_users_email;
DROP INDEX IF EXISTS idx_api_keys_key_hash;
DROP INDEX IF EXISTS idx_sub_prefs_tenant_email_category;
DROP INDEX IF EXISTS idx_campaign_arms_campaign;
DROP INDEX IF EXISTS idx_bounce_analytics_daily_tenant_date;
DROP INDEX IF EXISTS idx_dunning_records_tenant;
DROP INDEX IF EXISTS idx_plan_overrides_tenant;
DROP INDEX IF EXISTS idx_feature_flag_overrides_tenant;
