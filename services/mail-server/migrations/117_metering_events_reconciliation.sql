-- Migration 117: Metering events reconciliation
--
-- =============================================================================
-- Reconcile metering_events with the writers that use it.
--
-- Migration 066 dropped and recreated metering_events with:
--   * `value BIGINT`      — but every writer/reader in the tree uses
--                           `quantity` (sales-autopilot/dispatcher.rs:242,
--                           billing-service/usage_ingest.rs:247): inserts
--                           failed with 42703 column-does-not-exist.
--   * `tenant_id TEXT` nullable — 064 had just standardized tenant ids to
--                           VARCHAR(26) NOT NULL; billing aggregation joins
--                           on tenant_id and NULL rows silently drop out of
--                           every usage rollup.
--
-- Repair: restore `quantity` (backfilling from `value` where a lineage wrote
-- it), drop the wrong-name column, and re-tighten tenant_id. Metered rows
-- with no tenant are unusable for billing — they are counted, logged, and
-- removed, not silently kept.
-- Idempotent: safe to re-run.
-- =============================================================================

DO $$
DECLARE
    removed BIGINT;
BEGIN
    IF to_regclass('public.metering_events') IS NULL THEN
        RAISE NOTICE '117: metering_events absent — nothing to reconcile';
        RETURN;
    END IF;

    -- quantity restored; `value` rows (if any lineage wrote them) migrate in
    ALTER TABLE metering_events ADD COLUMN IF NOT EXISTS quantity BIGINT NOT NULL DEFAULT 0;
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'metering_events'
          AND column_name = 'value'
    ) THEN
        UPDATE metering_events SET quantity = value WHERE quantity = 0 AND value IS NOT NULL;
        ALTER TABLE metering_events DROP COLUMN value;
    END IF;

    -- tenant_id: drop tenant-less junk, then re-tighten type + NOT NULL
    SELECT count(*) INTO removed FROM metering_events
    WHERE tenant_id IS NULL OR btrim(tenant_id) = '';
    IF removed > 0 THEN
        DELETE FROM metering_events WHERE tenant_id IS NULL OR btrim(tenant_id) = '';
        RAISE NOTICE '117: removed % tenant-less metering_events rows', removed;
    END IF;
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'metering_events'
          AND column_name = 'tenant_id' AND udt_name = 'text'
    ) THEN
        ALTER TABLE metering_events
            ALTER COLUMN tenant_id TYPE VARCHAR(26) USING btrim(tenant_id);
    END IF;
    ALTER TABLE metering_events ALTER COLUMN tenant_id SET NOT NULL;

    RAISE NOTICE '117: metering_events reconciled (quantity, tenant_id VARCHAR(26) NOT NULL)';
END $$;

