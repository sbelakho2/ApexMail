-- 063_add_db_audit_fixes.sql
--
-- =============================================================================
-- REMAINING DB AUDIT FIXES (DB-105, DB-106, DB-110, DB-115)
-- =============================================================================
-- Addresses remaining database audit items from the comprehensive migration
-- audit (faults.md §41):
--
--   DB-105: Financial tables missing CHECK constraints (prevent negative amounts)
--   DB-106: DKIM private key stored as plain TEXT — add encryption comment
--   DB-110: Missing indexes on scheduled_at/locked_until columns
--   DB-115: Webhook retry missing tenant isolation index
--
-- Every statement uses IF NOT EXISTS / IF EXISTS guards and/or DO $$ blocks so
-- this migration is safe to run multiple times on any deployment.
-- =============================================================================

-- =============================================================================
-- DB-105: Add CHECK constraints preventing negative amounts on financial columns
-- =============================================================================
-- Financial columns in enterprise billing tables should never have negative
-- values. These CHECK constraints enforce this at the database level.

DO $$
BEGIN
    -- enterprise_contracts: base_price, committed_volume, overage_rate, annual_prepay_discount
    IF to_regclass('public.enterprise_contracts') IS NOT NULL THEN
        -- base_price >= 0 is already enforced by the existing CHECK in migration 022
        -- committed_volume >= 0 is already enforced by the existing CHECK
        -- overage_rate >= 0 is already enforced by the existing CHECK
        -- annual_prepay_discount >= 0 is already enforced by the existing CHECK
        -- payment_terms_days >= 0 is already enforced by the existing CHECK
        -- sla_credit_percentage >= 0 is already enforced by the existing CHECK
        RAISE NOTICE 'DB-105: enterprise_contracts financial CHECKs already exist from migration 022';
    END IF;

    -- wallets: balance and reserved should not be negative
    IF to_regclass('public.wallets') IS NOT NULL THEN
        IF NOT EXISTS (
            SELECT 1 FROM pg_constraint
            WHERE conname = 'chk_wallets_balance_nonneg'
              AND conrelid = 'public.wallets'::regclass
        ) THEN
            ALTER TABLE wallets ADD CONSTRAINT chk_wallets_balance_nonneg
                CHECK (balance >= 0);
            RAISE NOTICE 'DB-105: Added chk_wallets_balance_nonneg';
        END IF;
        IF NOT EXISTS (
            SELECT 1 FROM pg_constraint
            WHERE conname = 'chk_wallets_reserved_nonneg'
              AND conrelid = 'public.wallets'::regclass
        ) THEN
            ALTER TABLE wallets ADD CONSTRAINT chk_wallets_reserved_nonneg
                CHECK (reserved >= 0);
            RAISE NOTICE 'DB-105: Added chk_wallets_reserved_nonneg';
        END IF;
    END IF;

    -- wallet_transactions: amount should be positive
    IF to_regclass('public.wallet_transactions') IS NOT NULL THEN
        IF NOT EXISTS (
            SELECT 1 FROM pg_constraint
            WHERE conname = 'chk_wallet_transactions_amount_pos'
              AND conrelid = 'public.wallet_transactions'::regclass
        ) THEN
            ALTER TABLE wallet_transactions ADD CONSTRAINT chk_wallet_transactions_amount_pos
                CHECK (amount > 0);
            RAISE NOTICE 'DB-105: Added chk_wallet_transactions_amount_pos';
        END IF;
    END IF;

    -- wallet_reservations: amount should be positive
    IF to_regclass('public.wallet_reservations') IS NOT NULL THEN
        IF NOT EXISTS (
            SELECT 1 FROM pg_constraint
            WHERE conname = 'chk_wallet_reservations_amount_pos'
              AND conrelid = 'public.wallet_reservations'::regclass
        ) THEN
            ALTER TABLE wallet_reservations ADD CONSTRAINT chk_wallet_reservations_amount_pos
                CHECK (amount > 0);
            RAISE NOTICE 'DB-105: Added chk_wallet_reservations_amount_pos';
        END IF;
    END IF;

    -- invoices: amount should be non-negative
    IF to_regclass('public.invoices') IS NOT NULL THEN
        IF NOT EXISTS (
            SELECT 1 FROM pg_constraint
            WHERE conname = 'chk_invoices_amount_nonneg'
              AND conrelid = 'public.invoices'::regclass
        ) THEN
            ALTER TABLE invoices ADD CONSTRAINT chk_invoices_amount_nonneg
                CHECK (amount >= 0);
            RAISE NOTICE 'DB-105: Added chk_invoices_amount_nonneg';
        END IF;
    END IF;

    -- sla_credits: credit_amount should be non-negative
    IF to_regclass('public.sla_credits') IS NOT NULL THEN
        IF NOT EXISTS (
            SELECT 1 FROM pg_constraint
            WHERE conname = 'chk_sla_credits_amount_nonneg'
              AND conrelid = 'public.sla_credits'::regclass
        ) THEN
            ALTER TABLE sla_credits ADD CONSTRAINT chk_sla_credits_amount_nonneg
                CHECK (credit_amount >= 0);
            RAISE NOTICE 'DB-105: Added chk_sla_credits_amount_nonneg';
        END IF;
    END IF;

    -- tenant_costs: cost columns should be non-negative
    IF to_regclass('public.tenant_costs') IS NOT NULL THEN
        IF NOT EXISTS (
            SELECT 1 FROM pg_constraint
            WHERE conname = 'chk_tenant_costs_nonneg'
              AND conrelid = 'public.tenant_costs'::regclass
        ) THEN
            ALTER TABLE tenant_costs ADD CONSTRAINT chk_tenant_costs_nonneg
                CHECK (storage_cost >= 0 AND bandwidth_cost >= 0
                    AND compute_cost >= 0 AND dedicated_ip_cost >= 0
                    AND total_cost >= 0 AND revenue >= 0);
            RAISE NOTICE 'DB-105: Added chk_tenant_costs_nonneg';
        END IF;
    END IF;

    -- dunning_states: amount_owed should be non-negative
    IF to_regclass('public.dunning_states') IS NOT NULL THEN
        IF NOT EXISTS (
            SELECT 1 FROM pg_constraint
            WHERE conname = 'chk_dunning_states_amount_nonneg'
              AND conrelid = 'public.dunning_states'::regclass
        ) THEN
            ALTER TABLE dunning_states ADD CONSTRAINT chk_dunning_states_amount_nonneg
                CHECK (amount_owed >= 0);
            RAISE NOTICE 'DB-105: Added chk_dunning_states_amount_nonneg';
        END IF;
    END IF;

    -- purchase_orders: amount should be non-negative
    IF to_regclass('public.purchase_orders') IS NOT NULL THEN
        IF NOT EXISTS (
            SELECT 1 FROM pg_constraint
            WHERE conname = 'chk_purchase_orders_amount_nonneg'
              AND conrelid = 'public.purchase_orders'::regclass
        ) THEN
            ALTER TABLE purchase_orders ADD CONSTRAINT chk_purchase_orders_amount_nonneg
                CHECK (amount >= 0);
            RAISE NOTICE 'DB-105: Added chk_purchase_orders_amount_nonneg';
        END IF;
    END IF;
END $$;

-- =============================================================================
-- DB-106: DKIM private key encryption comment
-- =============================================================================
-- The dkim_keys table stores private_key_encrypted as BYTEA, suggesting
-- encryption at the application layer. Add a comment documenting this.

DO $$
BEGIN
    IF to_regclass('public.dkim_keys') IS NOT NULL THEN
        EXECUTE 'COMMENT ON COLUMN dkim_keys.private_key_encrypted IS
                 ''DKIM private key stored as encrypted BYTEA. Must be encrypted
                  at the application layer before storage. Never store raw PEM/PKCS8
                  keys. Use AES-256-GCM or equivalent envelope encryption with
                  a KMS-managed key.''';
        RAISE NOTICE 'DB-106: Added encryption comment on dkim_keys.private_key_encrypted';
    END IF;

    IF to_regclass('public.self_hosted_dkim_keys') IS NOT NULL THEN
        EXECUTE 'COMMENT ON COLUMN self_hosted_dkim_keys.private_key_enc IS
                 ''DKIM private key stored as encrypted BYTEA. Must be encrypted
                  at the application layer before storage. Never store raw PEM/PKCS8
                  keys. Use AES-256-GCM or equivalent envelope encryption with
                  a KMS-managed key.''';
        RAISE NOTICE 'DB-106: Added encryption comment on self_hosted_dkim_keys.private_key_enc';
    END IF;
END $$;

-- =============================================================================
-- DB-110: Missing indexes on scheduled_at/locked_until columns
-- =============================================================================
-- Migration 062 adds scheduled_at and locked_until to email_queue but does not
-- create indexes. These columns are used for delayed delivery scheduling and
-- multi-worker visibility timeout locking.

DO $$
BEGIN
    IF to_regclass('public.email_queue') IS NOT NULL THEN
        -- Index for scheduled delivery: find emails ready to send
        IF EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'email_queue' AND column_name = 'scheduled_at'
        ) AND NOT EXISTS (
            SELECT 1 FROM pg_class WHERE relname = 'idx_email_queue_scheduled_at'
        ) THEN
            EXECUTE 'CREATE INDEX IF NOT EXISTS idx_email_queue_scheduled_at
                     ON email_queue (scheduled_at)
                     WHERE scheduled_at IS NOT NULL';
            RAISE NOTICE 'DB-110: Created idx_email_queue_scheduled_at';
        END IF;

        -- Index for visibility timeout: find unlocked emails for processing
        IF EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'email_queue' AND column_name = 'locked_until'
        ) AND NOT EXISTS (
            SELECT 1 FROM pg_class WHERE relname = 'idx_email_queue_locked_until'
        ) THEN
            EXECUTE 'CREATE INDEX IF NOT EXISTS idx_email_queue_locked_until
                     ON email_queue (locked_until)
                     WHERE locked_until IS NOT NULL';
            RAISE NOTICE 'DB-110: Created idx_email_queue_locked_until';
        END IF;
    END IF;
END $$;

-- =============================================================================
-- DB-115: Webhook retry tenant isolation
-- =============================================================================
-- Ensure webhook retry queries are properly scoped by tenant_id.
-- Add a composite index that supports the common retry pattern:
--   SELECT * FROM webhook_events
--   WHERE tenant_id = $1 AND delivery_status = 'failed'
--   ORDER BY created_at FOR UPDATE SKIP LOCKED

DO $$
BEGIN
    IF to_regclass('public.webhook_events') IS NOT NULL THEN
        IF NOT EXISTS (
            SELECT 1 FROM pg_class WHERE relname = 'idx_webhook_events_tenant_failed'
        ) THEN
            EXECUTE 'CREATE INDEX IF NOT EXISTS idx_webhook_events_tenant_failed
                     ON webhook_events (tenant_id, delivery_status, created_at)
                     WHERE delivery_status IN (''failed'', ''pending'')';
            RAISE NOTICE 'DB-115: Created idx_webhook_events_tenant_failed for tenant-isolated retry';
        END IF;
    END IF;
END $$;

-- =============================================================================
-- Summary
-- =============================================================================
DO $$
BEGIN
    RAISE NOTICE '063_add_db_audit_fixes.sql: Completed DB-105, DB-106, DB-110, DB-115 fixes';
END $$;
