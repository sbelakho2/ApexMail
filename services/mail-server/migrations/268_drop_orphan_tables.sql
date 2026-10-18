-- Migration 268: drop the orphan tables proven to have no consumer.
--
-- Precedent: 249_drop_orphan_tables.sql. Each table below was created by a
-- migration whose comment claimed a consumer that never shipped (or was
-- deleted); a repo-wide audit on 2026-10-18 found ZERO non-migration
-- readers/writers, zero tests, and no public claim served by it, while a
-- live replacement serves the same capability. Keeping them is not neutral:
-- they read as implemented features to the coverage ledger, the retention
-- registry and every future maintainer.
--
--   * accounts_payable / fixed_assets / fx_rates / fx_revaluations /
--     depreciation_entries (220 accounting core): no writer was ever built;
--     the live accounting surfaces (AR, invoices, credit notes, bank lines)
--     are served by accounting-core adapters/sweeps, and the balance sheet
--     reports fixed assets as a literal 0 (estonia_ou.rs). Dropped.
--   * bounce_bursts / bounce_domain_reputation (030): writers were deleted
--     with crates/bounce-analytics; the live bounce aggregate is
--     bounce_analytics_daily (usage_ingest), and domain reputation is
--     postmaster_reputation_summary (mta postmaster).
--   * campaign_ab_outcomes (238): never written; the live A/B state is
--     campaign_ab_arms + events counters (ab_testing.rs / campaigns.rs).
--   * dunning_states (022): no Rust writer ever existed; rows (if any legacy
--     TS data exists) are ported to dunning_records below, then the table is
--     dropped. dunning_records/dunning_events are the live dunning model.
--   * health_check_history (082): its endpoint module was deleted before it
--     was ever mounted; service_heartbeats + the admin system-health surface
--     are the live implementation.
--   * scim_users (087): never referenced; SCIM writes the canonical users /
--     scim_groups tables.
--   * tenant_alerts (020): superseded by system_alerts (tenant-scoped since
--     031) and usage_alert_configs.
--   * tenant_mail_from (020): never referenced; MAIL FROM is configured on
--     the SES identity itself (domains.rs PutEmailIdentityMailFromAttributes).
--   * transport_routing_cache + its trigger/function (021/208): the DB-backed
--     router cache was deleted (release-blocker 15); the trigger would write
--     a table nothing reads. Trigger + function must go before the table.
--   * hetzner_mta_servers (021): single-server env config + dedicated_ips
--     are the live model.
--   * ip_daily_usage (021): warmup is enforced from Redis counters in the
--     worker and relay admission; the table was never written.
--   * self_hosted_dkim_keys (021): domains.dkim_private_key is the live DKIM
--     store (094), decrypted by the worker.
--
-- Forward-only and idempotent (IF EXISTS everywhere).

-- ── 1. Port any legacy dunning state before dropping it ─────────────────────
-- dunning_records is the live one-record-per-tenant model (unique tenant
-- index); only tenants without a record are ported, so a live row always
-- wins. Status keeps the legacy state name; the columns map 1:1.
DO $$
BEGIN
    IF to_regclass('dunning_states') IS NOT NULL
       AND to_regclass('dunning_records') IS NOT NULL THEN
        INSERT INTO dunning_records (
            id, tenant_id, invoice_id, attempt_number, amount_cents,
            failed_payment_count, first_failed_at, last_failed_at,
            next_retry_at, grace_period_ends_at, suspended_at, status,
            created_at, updated_at
        )
        SELECT
            replace(gen_random_uuid()::text, '-', ''),
            s.tenant_id,
            NULL,
            GREATEST(s.retry_count, 0),
            s.amount_owed::bigint,
            GREATEST(s.retry_count, 0),
            s.last_retry_at,
            s.last_retry_at,
            s.next_retry_at,
            s.grace_period_ends_at,
            s.hard_suspended_at,
            s.dunning_state,
            s.created_at,
            s.updated_at
        FROM dunning_states s
        WHERE NOT EXISTS (
            SELECT 1 FROM dunning_records r WHERE r.tenant_id = s.tenant_id
        );
    END IF;
END $$;

-- ── 2. Drop the transport-routing trigger/function before its table ─────────
DROP TRIGGER IF EXISTS trg_update_transport_routing ON dedicated_ips;
DROP FUNCTION IF EXISTS fn_update_transport_routing();

-- ── 3. Drop the orphan tables ───────────────────────────────────────────────
-- Child tables first: depreciation_entries references fixed_assets and
-- fx_revaluations references fx_rates.
DROP TABLE IF EXISTS accounts_payable;
DROP TABLE IF EXISTS depreciation_entries;
DROP TABLE IF EXISTS fixed_assets;
DROP TABLE IF EXISTS fx_revaluations;
DROP TABLE IF EXISTS fx_rates;

DROP TABLE IF EXISTS bounce_bursts;
DROP TABLE IF EXISTS bounce_domain_reputation;
DROP TABLE IF EXISTS campaign_ab_outcomes;

DROP TABLE IF EXISTS dunning_states;

DROP TABLE IF EXISTS health_check_history;
DROP TABLE IF EXISTS scim_users;
DROP TABLE IF EXISTS tenant_alerts;
DROP TABLE IF EXISTS tenant_mail_from;
DROP TABLE IF EXISTS transport_routing_cache;
DROP TABLE IF EXISTS hetzner_mta_servers;
DROP TABLE IF EXISTS ip_daily_usage;
DROP TABLE IF EXISTS self_hosted_dkim_keys;
