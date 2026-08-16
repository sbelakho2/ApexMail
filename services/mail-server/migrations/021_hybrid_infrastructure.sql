-- Migration 021:Hybrid email infrastructure
-- Architecture:-- • Dedicated IPs → Hetzner floating IPs, self-hosted SMTP
-- • Shared sending → AWS SES shared IP pool
-- There is NO provider choice. Dedicated IPs are always Hetzner,
-- shared sending is always SES.

-- ─── Dedicated IPs (Hetzner-only) ────────────────────────────

-- Extend the existing dedicated_ips table with Hetzner-specific columns.
-- If the table doesn't exist yet, create it; otherwise ALTER.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'dedicated_ips') THEN
        CREATE TABLE dedicated_ips (
            id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id       UUID NOT NULL,
            ip_address      INET NOT NULL UNIQUE,
            region          VARCHAR(64) NOT NULL DEFAULT 'fsn1',
            status          VARCHAR(20) NOT NULL DEFAULT 'warming'
                            CHECK (status IN ('warming', 'active', 'cooldown', 'releasing', 'retired')),
            warmup_progress DOUBLE PRECISION NOT NULL DEFAULT 0.0,

-- Hetzner identifiers (mandatory for all dedicated IPs)
            hetzner_floating_ip_id  BIGINT UNIQUE,
            hetzner_server_id       BIGINT,
            rdns_hostname           VARCHAR(255),

-- Warmup tracking
            warmup_started_at   TIMESTAMPTZ,
            warmup_completed_at TIMESTAMPTZ,

-- Billing
            billing_status  VARCHAR(30) DEFAULT 'included'
                            CHECK (billing_status IN ('included', 'pending_charge', 'active', 'pending_cancel', 'canceled', 'cancelled')),
            allocated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),

            created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );

        CREATE INDEX idx_dedicated_ips_tenant ON dedicated_ips(tenant_id);
        CREATE INDEX idx_dedicated_ips_status ON dedicated_ips(status);
        CREATE INDEX idx_dedicated_ips_hetzner ON dedicated_ips(hetzner_floating_ip_id);
    ELSE
-- Table exists from earlier migration; add Hetzner columns if missing.
        BEGIN ALTER TABLE dedicated_ips ADD COLUMN hetzner_floating_ip_id BIGINT UNIQUE; EXCEPTION WHEN duplicate_column THEN NULL; END;
        BEGIN ALTER TABLE dedicated_ips ADD COLUMN hetzner_server_id BIGINT; EXCEPTION WHEN duplicate_column THEN NULL; END;
        BEGIN ALTER TABLE dedicated_ips ADD COLUMN rdns_hostname VARCHAR(255); EXCEPTION WHEN duplicate_column THEN NULL; END;
        BEGIN ALTER TABLE dedicated_ips ADD COLUMN warmup_started_at TIMESTAMPTZ; EXCEPTION WHEN duplicate_column THEN NULL; END;
        BEGIN ALTER TABLE dedicated_ips ADD COLUMN warmup_completed_at TIMESTAMPTZ; EXCEPTION WHEN duplicate_column THEN NULL; END;
        BEGIN ALTER TABLE dedicated_ips ADD COLUMN billing_status VARCHAR(30) DEFAULT 'included'; EXCEPTION WHEN duplicate_column THEN NULL; END;
        BEGIN ALTER TABLE dedicated_ips ADD COLUMN allocated_at TIMESTAMPTZ DEFAULT NOW(); EXCEPTION WHEN duplicate_column THEN NULL; END;

-- H-02: Reconcile billing_status CHECK constraint — migration 003 uses
-- 'canceled' (one 'l') but this migration defines 'cancelled' (two 'l's).
-- Fix by accepting both spellings to avoid data migration issues.
        IF EXISTS (
            SELECT 1 FROM pg_constraint
            WHERE conrelid = 'public.dedicated_ips'::regclass
              AND conname = 'dedicated_ips_billing_status_check'
              AND pg_get_constraintdef(oid) LIKE '%canceled%'
        ) THEN
            ALTER TABLE dedicated_ips DROP CONSTRAINT dedicated_ips_billing_status_check;
            ALTER TABLE dedicated_ips ADD CONSTRAINT dedicated_ips_billing_status_check
                CHECK (billing_status IN ('included', 'pending_charge', 'active', 'pending_cancel', 'canceled', 'cancelled'));
        END IF;

-- Remove legacy provider column if it exists (no longer needed — all dedicated IPs are Hetzner)
        BEGIN ALTER TABLE dedicated_ips DROP COLUMN IF EXISTS provider; EXCEPTION WHEN undefined_column THEN NULL; END;

-- Add index on Hetzner ID if missing
        IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'idx_dedicated_ips_hetzner') THEN
            CREATE INDEX idx_dedicated_ips_hetzner ON dedicated_ips(hetzner_floating_ip_id);
        END IF;
    END IF;
END $$;


-- ─── Transport routing cache ─────────────────────────────────
-- Materialized view pattern:the trigger keeps this up to date whenever
-- dedicated_ips changes. The transport router reads only this table
-- (fast, no joins).

CREATE TABLE IF NOT EXISTS transport_routing_cache (
    tenant_id           UUID PRIMARY KEY,
    has_dedicated_ips   BOOLEAN NOT NULL DEFAULT false,
    preferred_dedicated_ip  INET,
    dedicated_ip_count  INTEGER NOT NULL DEFAULT 0,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


-- ─── Trigger:auto-update routing cache ──────────────────────

CREATE OR REPLACE FUNCTION fn_update_transport_routing()
RETURNS TRIGGER AS $$
DECLARE
    v_tenant_id UUID;
    v_count     INTEGER;
    v_best_ip   INET;
BEGIN
-- Determine which tenant to update
    IF TG_OP = 'DELETE' THEN
        v_tenant_id := OLD.tenant_id;
    ELSE
        v_tenant_id := NEW.tenant_id;
    END IF;

-- Count active/warming IPs for this tenant
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

-- Upsert routing cache
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

DROP TRIGGER IF EXISTS trg_update_transport_routing ON dedicated_ips;
CREATE TRIGGER trg_update_transport_routing
    AFTER INSERT OR UPDATE OR DELETE ON dedicated_ips
    FOR EACH ROW EXECUTE FUNCTION fn_update_transport_routing();


-- ─── Hetzner MTA servers ─────────────────────────────────────
-- Tracks which Hetzner servers are available for MTA duty.

CREATE TABLE IF NOT EXISTS hetzner_mta_servers (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hetzner_server_id  BIGINT NOT NULL UNIQUE,
    server_name     VARCHAR(100) NOT NULL,
    ipv4_address    INET NOT NULL,
    region          VARCHAR(20) NOT NULL,
    status          VARCHAR(20) NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active', 'draining', 'offline')),
    max_ips         INTEGER NOT NULL DEFAULT 10,
    assigned_ips    INTEGER NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


-- ─── Self-hosted bounces ─────────────────────────────────────
-- Bounces received by self-hosted MTA (for dedicated IP sends).

CREATE TABLE IF NOT EXISTS self_hosted_bounces (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    message_id      UUID,
    source_ip       INET NOT NULL,
    bounce_type     VARCHAR(20) NOT NULL CHECK (bounce_type IN ('hard', 'soft', 'block')),
    smtp_code       INTEGER,
    smtp_enhanced   VARCHAR(20),
    diagnostic      TEXT,
    recipient       VARCHAR(320) NOT NULL,
    received_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_self_hosted_bounces_tenant ON self_hosted_bounces(tenant_id, received_at);
CREATE INDEX IF NOT EXISTS idx_self_hosted_bounces_recipient ON self_hosted_bounces(recipient);
CREATE INDEX IF NOT EXISTS idx_self_hosted_bounces_ip ON self_hosted_bounces(source_ip);


-- ─── Self-hosted complaints (FBL) ────────────────────────────

CREATE TABLE IF NOT EXISTS self_hosted_complaints (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    message_id      UUID,
    source_ip       INET NOT NULL,
    complaint_type  VARCHAR(30) NOT NULL DEFAULT 'abuse',
    feedback_id     VARCHAR(255),
    recipient       VARCHAR(320) NOT NULL,
    received_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_self_hosted_complaints_tenant ON self_hosted_complaints(tenant_id, received_at);


-- ─── DKIM keys for self-hosted sending ───────────────────────
-- Self-hosted SMTP does its own DKIM signing (SES handles DKIM for shared
-- sends via Easy DKIM).

CREATE TABLE IF NOT EXISTS self_hosted_dkim_keys (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    domain          VARCHAR(255) NOT NULL,
    selector        VARCHAR(63) NOT NULL,
    private_key_enc BYTEA NOT NULL,
    public_key      TEXT NOT NULL,
    algorithm       VARCHAR(20) NOT NULL DEFAULT 'rsa-sha256',
    key_size        INTEGER NOT NULL DEFAULT 2048,
    active          BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    rotated_at      TIMESTAMPTZ,
    UNIQUE(tenant_id, domain, selector)
);


-- ─── IP daily usage (warmup enforcement) ─────────────────────

CREATE TABLE IF NOT EXISTS ip_daily_usage (
    ip_address      INET NOT NULL,
    usage_date      DATE NOT NULL DEFAULT CURRENT_DATE,
    messages_sent   BIGINT NOT NULL DEFAULT 0,
    bounces         INTEGER NOT NULL DEFAULT 0,
    complaints      INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (ip_address, usage_date)
);

CREATE INDEX IF NOT EXISTS idx_ip_daily_usage_date ON ip_daily_usage(usage_date);


-- ─── Self-hosted send stats ──────────────────────────────────

CREATE TABLE IF NOT EXISTS self_hosted_send_stats (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    ip_address      INET NOT NULL,
    stat_date       DATE NOT NULL DEFAULT CURRENT_DATE,
    messages_sent   BIGINT NOT NULL DEFAULT 0,
    messages_failed BIGINT NOT NULL DEFAULT 0,
    bytes_sent      BIGINT NOT NULL DEFAULT 0,
    avg_latency_ms  DOUBLE PRECISION,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, ip_address, stat_date)
);

CREATE INDEX IF NOT EXISTS idx_self_hosted_stats_tenant ON self_hosted_send_stats(tenant_id, stat_date);


-- ─── Add transport column to messages table ──────────────────
-- Records which transport was used for each message.
-- C-05: Guard against missing messages table (created later in migration 052).

DO $$
BEGIN
    IF to_regclass('public.messages') IS NOT NULL THEN
        BEGIN
            ALTER TABLE messages ADD COLUMN transport VARCHAR(10)
                CHECK (transport IN ('ses', 'smtp'));
        EXCEPTION WHEN duplicate_column THEN NULL;
        END;
    END IF;
END $$;

DO $$
BEGIN
    IF to_regclass('public.messages') IS NOT NULL THEN
        BEGIN
            ALTER TABLE messages ADD COLUMN source_ip INET;
        EXCEPTION WHEN duplicate_column THEN NULL;
        END;
    END IF;
END $$;

-- ─── Conditional FK constraints ─────────────────────────────
-- C-02: Add FK REFERENCES tenants(id) for tables that expected it inline.
-- These are added conditionally because tenants may not exist yet
-- (it's created in migration 052 for fresh deployments).

DO $$
BEGIN
    IF to_regclass('public.tenants') IS NOT NULL THEN
        -- dedicated_ips.tenant_id -> tenants(id)
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'dedicated_ips_tenant_id_fkey') THEN
            BEGIN
                EXECUTE 'ALTER TABLE dedicated_ips ADD CONSTRAINT dedicated_ips_tenant_id_fkey
                FOREIGN KEY (tenant_id) REFERENCES tenants(id)';
            EXCEPTION WHEN OTHERS THEN
                RAISE NOTICE 'FK dedicated_ips_tenant_id_fkey skipped (%)', SQLERRM;
            END;
        END IF;
        -- transport_routing_cache.tenant_id -> tenants(id)
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'transport_routing_cache_tenant_id_fkey') THEN
            BEGIN
                EXECUTE 'ALTER TABLE transport_routing_cache ADD CONSTRAINT transport_routing_cache_tenant_id_fkey
                FOREIGN KEY (tenant_id) REFERENCES tenants(id)';
            EXCEPTION WHEN OTHERS THEN
                RAISE NOTICE 'FK transport_routing_cache_tenant_id_fkey skipped (%)', SQLERRM;
            END;
        END IF;
        -- self_hosted_bounces.tenant_id -> tenants(id)
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'self_hosted_bounces_tenant_id_fkey') THEN
            BEGIN
                EXECUTE 'ALTER TABLE self_hosted_bounces ADD CONSTRAINT self_hosted_bounces_tenant_id_fkey
                FOREIGN KEY (tenant_id) REFERENCES tenants(id)';
            EXCEPTION WHEN OTHERS THEN
                RAISE NOTICE 'FK self_hosted_bounces_tenant_id_fkey skipped (%)', SQLERRM;
            END;
        END IF;
        -- self_hosted_complaints.tenant_id -> tenants(id)
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'self_hosted_complaints_tenant_id_fkey') THEN
            BEGIN
                EXECUTE 'ALTER TABLE self_hosted_complaints ADD CONSTRAINT self_hosted_complaints_tenant_id_fkey
                FOREIGN KEY (tenant_id) REFERENCES tenants(id)';
            EXCEPTION WHEN OTHERS THEN
                RAISE NOTICE 'FK self_hosted_complaints_tenant_id_fkey skipped (%)', SQLERRM;
            END;
        END IF;
        -- self_hosted_dkim_keys.tenant_id -> tenants(id)
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'self_hosted_dkim_keys_tenant_id_fkey') THEN
            BEGIN
                EXECUTE 'ALTER TABLE self_hosted_dkim_keys ADD CONSTRAINT self_hosted_dkim_keys_tenant_id_fkey
                FOREIGN KEY (tenant_id) REFERENCES tenants(id)';
            EXCEPTION WHEN OTHERS THEN
                RAISE NOTICE 'FK self_hosted_dkim_keys_tenant_id_fkey skipped (%)', SQLERRM;
            END;
        END IF;
        -- self_hosted_send_stats.tenant_id -> tenants(id)
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'self_hosted_send_stats_tenant_id_fkey') THEN
            BEGIN
                EXECUTE 'ALTER TABLE self_hosted_send_stats ADD CONSTRAINT self_hosted_send_stats_tenant_id_fkey
                FOREIGN KEY (tenant_id) REFERENCES tenants(id)';
            EXCEPTION WHEN OTHERS THEN
                RAISE NOTICE 'FK self_hosted_send_stats_tenant_id_fkey skipped (%)', SQLERRM;
            END;
        END IF;
    ELSE
        RAISE WARNING 'Migration 021: tenants table does not exist — skipping FK constraints.';
    END IF;
END $$;

-- C-05: Add FK REFERENCES messages(id) for bounce/complaint tracking.
DO $$
BEGIN
    IF to_regclass('public.messages') IS NOT NULL THEN
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'self_hosted_bounces_message_id_fkey') THEN
            BEGIN
                EXECUTE 'ALTER TABLE self_hosted_bounces ADD CONSTRAINT self_hosted_bounces_message_id_fkey
                FOREIGN KEY (message_id) REFERENCES messages(id)';
            EXCEPTION WHEN OTHERS THEN
                RAISE NOTICE 'FK self_hosted_bounces_message_id_fkey skipped (%)', SQLERRM;
            END;
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'self_hosted_complaints_message_id_fkey') THEN
            BEGIN
                EXECUTE 'ALTER TABLE self_hosted_complaints ADD CONSTRAINT self_hosted_complaints_message_id_fkey
                FOREIGN KEY (message_id) REFERENCES messages(id)';
            EXCEPTION WHEN OTHERS THEN
                RAISE NOTICE 'FK self_hosted_complaints_message_id_fkey skipped (%)', SQLERRM;
            END;
        END IF;
    ELSE
        RAISE WARNING 'Migration 021: messages table does not exist — skipping FK constraints on self_hosted_bounces/complaints.';
    END IF;
END $$;
