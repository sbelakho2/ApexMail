-- Enterprise private deployment, dedicated IP pool, and BYOIP lifecycle tables.
-- These tables back the Rust enterprise::private_deploy service and its routes.


CREATE TABLE IF NOT EXISTS ent_private_deployments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    name VARCHAR(255) NOT NULL,
    deployment_type VARCHAR(50) NOT NULL
        CHECK (deployment_type IN ('dedicated', 'private_cloud', 'hybrid', 'on_premise')),
    status VARCHAR(50) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'provisioning', 'active', 'maintenance', 'decommissioning', 'failed')),
    region VARCHAR(64),
    availability_zones TEXT[],
    vpc_id VARCHAR(255),
    instance_type VARCHAR(100),
    instance_count INTEGER CHECK (instance_count IS NULL OR instance_count > 0),
    storage_gb INTEGER CHECK (storage_gb IS NULL OR storage_gb > 0),
    config JSONB,
    custom_domain VARCHAR(255),
    health_check_url TEXT,
    health_status VARCHAR(50),
    last_health_check_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ent_private_deployments_tenant_created
    ON ent_private_deployments(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ent_private_deployments_status
    ON ent_private_deployments(status, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_ent_private_deployments_type_region
    ON ent_private_deployments(deployment_type, region);

CREATE TABLE IF NOT EXISTS ip_pool_available (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ip_address INET NOT NULL UNIQUE,
    region VARCHAR(64) NOT NULL,
    datacenter VARCHAR(64),
    provider VARCHAR(64) NOT NULL DEFAULT 'hetzner',
    status VARCHAR(50) NOT NULL DEFAULT 'available'
        CHECK (status IN ('available', 'allocated', 'reserved', 'warming', 'retired')),
    is_warmed BOOLEAN NOT NULL DEFAULT FALSE,
    reputation_score DOUBLE PRECISION NOT NULL DEFAULT 100.0
        CHECK (reputation_score >= 0.0 AND reputation_score <= 100.0),
    ptr_record VARCHAR(255),
    allocated_to UUID,
    allocated_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ip_pool_available_status_region
    ON ip_pool_available(status, region, is_warmed DESC, reputation_score DESC);
CREATE INDEX IF NOT EXISTS idx_ip_pool_available_allocated_to
    ON ip_pool_available(allocated_to)
    WHERE allocated_to IS NOT NULL;

CREATE TABLE IF NOT EXISTS ent_dedicated_ips (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    deployment_id UUID REFERENCES ent_private_deployments(id) ON DELETE SET NULL,
    ip_address INET NOT NULL UNIQUE,
    region VARCHAR(64),
    ptr_record VARCHAR(255),
    status VARCHAR(50) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'warming', 'active', 'suspended', 'decommissioned')),
    warming_started_at TIMESTAMPTZ,
    warming_progress_percent INTEGER DEFAULT 0
        CHECK (warming_progress_percent IS NULL OR warming_progress_percent BETWEEN 0 AND 100),
    warming_plan JSONB,
    current_daily_limit INTEGER,
    reputation_score DOUBLE PRECISION CHECK (reputation_score IS NULL OR (reputation_score >= 0.0 AND reputation_score <= 100.0)),
    reputation_history JSONB,
    emails_sent_total BIGINT NOT NULL DEFAULT 0,
    bounces_total INTEGER NOT NULL DEFAULT 0,
    complaints_total INTEGER NOT NULL DEFAULT 0,
    blocklisted BOOLEAN NOT NULL DEFAULT FALSE,
    blocklist_details JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ent_dedicated_ips_tenant_created
    ON ent_dedicated_ips(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ent_dedicated_ips_status
    ON ent_dedicated_ips(status);
CREATE INDEX IF NOT EXISTS idx_ent_dedicated_ips_deployment
    ON ent_dedicated_ips(deployment_id)
    WHERE deployment_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS ent_byoip_ranges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    cidr_block CIDR NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'pending_verification'
        CHECK (status IN ('pending_verification', 'verified', 'importing', 'active', 'failed', 'released')),
    verification_token VARCHAR(255),
    verification_method VARCHAR(50) NOT NULL DEFAULT 'dns_txt',
    verified_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, cidr_block)
);

CREATE INDEX IF NOT EXISTS idx_ent_byoip_ranges_tenant_created
    ON ent_byoip_ranges(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ent_byoip_ranges_status
    ON ent_byoip_ranges(status);

DO $$
DECLARE
    table_name TEXT;
BEGIN
    IF EXISTS (
        SELECT 1
        FROM pg_proc
        WHERE proname = 'enterprise_billing_update_updated_at_column'
    ) THEN
        FOREACH table_name IN ARRAY ARRAY[
            'ent_private_deployments',
            'ip_pool_available'
        ] LOOP
            IF NOT EXISTS (
                SELECT 1
                FROM pg_trigger
                WHERE tgname = 'trg_' || table_name || '_updated_at'
            ) THEN
                EXECUTE format(
                    'CREATE TRIGGER trg_%1$s_updated_at BEFORE UPDATE ON %1$s FOR EACH ROW EXECUTE FUNCTION enterprise_billing_update_updated_at_column()',
                    table_name
                );
            END IF;
        END LOOP;
    END IF;
END;
$$;

