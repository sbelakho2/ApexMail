-- Migration 071: Fix schema mismatches found during live simulation
-- These were discovered by running the actual api-server binary against the DB.

-- 1. dedicated_ips: id and tenant_id were UUID, code generates VARCHAR(26)
ALTER TABLE dedicated_ips ALTER COLUMN id TYPE VARCHAR(26) USING id::text;
ALTER TABLE dedicated_ips ALTER COLUMN tenant_id TYPE VARCHAR(26) USING tenant_id::text;
ALTER TABLE dedicated_ips ADD COLUMN IF NOT EXISTS rdns_hostname VARCHAR(255);
ALTER TABLE dedicated_ips ADD COLUMN IF NOT EXISTS region VARCHAR(50);
ALTER TABLE dedicated_ips ADD COLUMN IF NOT EXISTS status VARCHAR(20) DEFAULT 'active';
ALTER TABLE dedicated_ips ADD COLUMN IF NOT EXISTS warmup_enabled BOOLEAN DEFAULT false;
ALTER TABLE dedicated_ips ADD COLUMN IF NOT EXISTS warmup_day INTEGER DEFAULT 0;
ALTER TABLE dedicated_ips ADD COLUMN IF NOT EXISTS warmup_daily_limit INTEGER DEFAULT 0;

-- 2. automations: code uses 'actions', 'conditions', 'status' but table had 'steps', 'enabled'
DO $$
BEGIN
    IF to_regclass('public.automations') IS NOT NULL THEN
        ALTER TABLE automations ADD COLUMN IF NOT EXISTS actions JSONB DEFAULT '[]';
        ALTER TABLE automations ADD COLUMN IF NOT EXISTS conditions JSONB DEFAULT '{}';
        ALTER TABLE automations ADD COLUMN IF NOT EXISTS status VARCHAR(20) DEFAULT 'draft';
        ALTER TABLE automations ALTER COLUMN id TYPE VARCHAR(26) USING id::text;
    END IF;
END $$;

-- 3. support_tickets: code expects 'assigned_to'
DO $$
BEGIN
    IF to_regclass('public.support_tickets') IS NOT NULL THEN
        ALTER TABLE support_tickets ADD COLUMN IF NOT EXISTS assigned_to VARCHAR(26);
    END IF;
END $$;

-- 4. plans: add columns the billing code reads
ALTER TABLE plans ADD COLUMN IF NOT EXISTS display_name VARCHAR(255);
ALTER TABLE plans ADD COLUMN IF NOT EXISTS description TEXT DEFAULT '';
ALTER TABLE plans ADD COLUMN IF NOT EXISTS price_monthly BIGINT DEFAULT 0;
ALTER TABLE plans ADD COLUMN IF NOT EXISTS price_yearly BIGINT DEFAULT 0;
ALTER TABLE plans ADD COLUMN IF NOT EXISTS email_limit BIGINT DEFAULT 30000;
ALTER TABLE plans ADD COLUMN IF NOT EXISTS api_call_limit BIGINT DEFAULT 100000;
ALTER TABLE plans ADD COLUMN IF NOT EXISTS features JSONB DEFAULT '[]';
ALTER TABLE plans ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT true;
ALTER TABLE plans ADD COLUMN IF NOT EXISTS sort_order INTEGER DEFAULT 0;
ALTER TABLE plans ALTER COLUMN id TYPE VARCHAR(26) USING id::text;

-- 5. stripe_subscriptions: add columns code reads
ALTER TABLE stripe_subscriptions ADD COLUMN IF NOT EXISTS stripe_customer_id VARCHAR(128);
ALTER TABLE stripe_subscriptions ADD COLUMN IF NOT EXISTS stripe_price_id VARCHAR(128);
ALTER TABLE stripe_subscriptions ADD COLUMN IF NOT EXISTS billing_interval VARCHAR(20) DEFAULT 'monthly';
ALTER TABLE stripe_subscriptions ADD COLUMN IF NOT EXISTS billing_cycle_start TIMESTAMPTZ DEFAULT NOW();
ALTER TABLE stripe_subscriptions ADD COLUMN IF NOT EXISTS billing_cycle_end TIMESTAMPTZ DEFAULT NOW() + INTERVAL '30 days';
ALTER TABLE stripe_subscriptions ADD COLUMN IF NOT EXISTS cancel_at_period_end BOOLEAN DEFAULT false;
ALTER TABLE stripe_subscriptions ADD COLUMN IF NOT EXISTS canceled_at TIMESTAMPTZ;
ALTER TABLE stripe_subscriptions ADD COLUMN IF NOT EXISTS trial_end TIMESTAMPTZ;

-- 6. self_hosted tables: tenant_id was UUID, needs VARCHAR(26) to match JOINs
ALTER TABLE self_hosted_send_stats ALTER COLUMN tenant_id TYPE VARCHAR(26) USING tenant_id::text;
ALTER TABLE self_hosted_bounces ALTER COLUMN tenant_id TYPE VARCHAR(26) USING tenant_id::text;
ALTER TABLE self_hosted_complaints ALTER COLUMN tenant_id TYPE VARCHAR(26) USING tenant_id::text;

-- 7. contacts: drop generated column and make name a regular column
DO $$
BEGIN
    IF to_regclass('public.contacts') IS NOT NULL THEN
        ALTER TABLE contacts DROP COLUMN IF EXISTS name;
        ALTER TABLE contacts ADD COLUMN name VARCHAR(512);
    END IF;
END $$;

-- 8. templates: slug NOT NULL but code doesn't always provide it
DO $$
BEGIN
    IF to_regclass('public.templates') IS NOT NULL THEN
        -- slug is absent on runtime-provisioned (apexmail-db SCHEMA) templates
        IF EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_schema='public' AND table_name='templates'
                     AND column_name='slug') THEN
            ALTER TABLE templates ALTER COLUMN slug DROP NOT NULL;
        END IF;
        ALTER TABLE templates ADD COLUMN IF NOT EXISTS status VARCHAR(20) DEFAULT 'active';
    END IF;
END $$;
