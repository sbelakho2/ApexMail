-- Schema alignment migration
-- Aligns packages/db schema with the canonical Rust/tools/migrations schema
-- //organizations → tenants, organization_id → tenant_id, to_email → to_emails

-- 1. Rename organizations → tenants (if organizations exists and tenants does not).
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'organizations')
       AND NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'tenants')
    THEN
        ALTER TABLE organizations RENAME TO tenants;
    END IF;
END $$;

-- 2. Rename organization_id → tenant_id in users table.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'users' AND column_name = 'organization_id'
    ) THEN
        ALTER TABLE users RENAME COLUMN organization_id TO tenant_id;
    END IF;
END $$;

-- 3. Rename organization_id → tenant_id in messages table.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'messages' AND column_name = 'organization_id'
    ) THEN
        ALTER TABLE messages RENAME COLUMN organization_id TO tenant_id;
    END IF;
END $$;

-- 4. Rename organization_id → tenant_id in suppressions table.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'suppressions' AND column_name = 'organization_id'
    ) THEN
        ALTER TABLE suppressions RENAME COLUMN organization_id TO tenant_id;
    END IF;
END $$;

-- 5. Rename organization_id → tenant_id in audit_logs table.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'audit_logs' AND column_name = 'organization_id'
    ) THEN
        ALTER TABLE audit_logs RENAME COLUMN organization_id TO tenant_id;
    END IF;
END $$;

-- 6. Add to_emails JSONB column alongside to_email for multi-recipient support.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'messages' AND column_name = 'to_email'
    ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'messages' AND column_name = 'to_emails'
    ) THEN
-- Add the JSONB array column and populate from the existing single-value column.
        ALTER TABLE messages ADD COLUMN to_emails JSONB;
        UPDATE messages SET to_emails = jsonb_build_array(to_email) WHERE to_emails IS NULL;
    END IF;
END $$;

-- 7. Ensure tenants table has a plan column.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'tenants')
       AND NOT EXISTS (
           SELECT 1 FROM information_schema.columns
           WHERE table_name = 'tenants' AND column_name = 'plan'
       )
    THEN
        ALTER TABLE tenants ADD COLUMN plan VARCHAR(50) NOT NULL DEFAULT 'free';
    END IF;
END $$;

-- 8. Add MFA columns to users if missing .
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'users' AND column_name = 'mfa_enabled'
    ) THEN
        ALTER TABLE users ADD COLUMN mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'users' AND column_name = 'mfa_secret'
    ) THEN
        ALTER TABLE users ADD COLUMN mfa_secret VARCHAR(255);
    END IF;
END $$;

-- 9. Create backwards-compatible view for any code still referencing organizations.
CREATE OR REPLACE VIEW organizations AS SELECT * FROM tenants;
