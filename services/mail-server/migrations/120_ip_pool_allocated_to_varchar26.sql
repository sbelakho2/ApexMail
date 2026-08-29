-- 120_ip_pool_allocated_to_varchar26.sql
--
-- =============================================================================
-- ip_pool_available.allocated_to is the LAST tenant-id column still typed
-- UUID. Migration 064 made every tenant id VARCHAR(26) — but the dedicated-IP
-- allocation path REQUIRES a UUID-shaped tenant (private_deploy.rs parses the
-- tenant id into a Uuid to claim the pool row), then inserts the same id into
-- ent_dedicated_ips.tenant_id VARCHAR(26): a 36-char UUID string cannot fit.
-- In production NO real 26-char tenant can allocate a dedicated IP at all,
-- and a UUID-shaped one would fail the record insert. Converge the column to
-- the canonical type and widen... no: STRICTLY converge (existing UUID-era
-- values become 36-char text and are dead rows from the 058 window — they are
-- cleared, matching the dunning_config precedent in migration 116).
-- Idempotent: safe to re-run.
-- =============================================================================

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'ip_pool_available'
          AND column_name = 'allocated_to'
          AND udt_name = 'uuid'
    ) THEN
        DELETE FROM ip_pool_available WHERE allocated_to IS NOT NULL;
        ALTER TABLE ip_pool_available
            ALTER COLUMN allocated_to TYPE VARCHAR(26) USING allocated_to::text;
        RAISE NOTICE '120: ip_pool_available.allocated_to converged UUID -> VARCHAR(26)';
    ELSE
        RAISE NOTICE '120: ip_pool_available.allocated_to already VARCHAR(26) — nothing to do';
    END IF;
END $$;
