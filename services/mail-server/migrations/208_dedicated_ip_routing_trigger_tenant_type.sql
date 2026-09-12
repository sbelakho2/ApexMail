-- Migration 208: Repair the dedicated_ips routing trigger for VARCHAR tenant ids
--
-- =============================================================================
-- `dedicated_ips.tenant_id` was declared UUID in migration 021 and converted to
-- VARCHAR(26) in migration 071 (the code generates 26-char string ids; row ids
-- elsewhere in the platform are VARCHAR(26) too). The routing trigger's
-- function was never updated to match:
--
--   migrations/021_hybrid_infrastructure.sql:96
--     DECLARE v_tenant_id UUID;
--   ... v_tenant_id := NEW.tenant_id;   -- NEW.tenant_id is VARCHAR(26)
--
-- So any INSERT/UPDATE on `dedicated_ips` raised
--
--   invalid input syntax for type uuid: "ten_..."
--
-- for any tenant id that is not 32 hex characters — which is every real tenant
-- id. That blocks dedicated-IP provisioning end to end: the row cannot be
-- written at all, so an allocation could never record its own state no matter
-- how correct the state machine above it was.
--
-- This replaces the function with the same logic against the actual column
-- type. `transport_routing_cache.tenant_id` is already VARCHAR(26), so the
-- upsert target needed no change.
--
-- Note on scope: a sweep of the current schema found `queue_jobs` as the only
-- remaining table with a UUID `tenant_id`. It is the deliberately unwired
-- queue-provider table (no production reader or writer), so it is left alone
-- rather than migrated for no consumer.
-- =============================================================================

CREATE OR REPLACE FUNCTION fn_update_transport_routing()
RETURNS TRIGGER AS $$
DECLARE
    -- VARCHAR(26) to match dedicated_ips.tenant_id (converted in migration 071)
    -- and transport_routing_cache.tenant_id. Declaring this UUID made every
    -- write to dedicated_ips fail at runtime.
    v_tenant_id VARCHAR(26);
    v_count     INTEGER;
    v_best_ip   INET;
BEGIN
    IF TG_OP = 'DELETE' THEN
        v_tenant_id := OLD.tenant_id;
    ELSE
        v_tenant_id := NEW.tenant_id;
    END IF;

    -- A NULL tenant id has nothing to cache; skip rather than upserting a row
    -- keyed on NULL.
    IF v_tenant_id IS NULL THEN
        RETURN COALESCE(NEW, OLD);
    END IF;

    SELECT COUNT(*), (
        SELECT ip_address FROM dedicated_ips
        WHERE tenant_id = v_tenant_id AND status IN ('active', 'warming')
        ORDER BY CASE status WHEN 'active' THEN 0 ELSE 1 END,
                 warmup_progress DESC
        LIMIT 1
    )
    INTO v_count, v_best_ip
    FROM dedicated_ips
    WHERE tenant_id = v_tenant_id AND status IN ('active', 'warming');

    INSERT INTO transport_routing_cache
        (tenant_id, has_dedicated_ips, preferred_dedicated_ip, dedicated_ip_count, updated_at)
    VALUES
        (v_tenant_id, v_count > 0, v_best_ip, v_count, NOW())
    ON CONFLICT (tenant_id) DO UPDATE SET
        has_dedicated_ips      = EXCLUDED.has_dedicated_ips,
        preferred_dedicated_ip = EXCLUDED.preferred_dedicated_ip,
        dedicated_ip_count     = EXCLUDED.dedicated_ip_count,
        updated_at             = NOW();

    RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;

-- The trigger itself is unchanged; recreating it here keeps this migration
-- self-contained for a database where 021's trigger was dropped.
DROP TRIGGER IF EXISTS trg_update_transport_routing ON dedicated_ips;
CREATE TRIGGER trg_update_transport_routing
    AFTER INSERT OR UPDATE OR DELETE ON dedicated_ips
    FOR EACH ROW EXECUTE FUNCTION fn_update_transport_routing();
