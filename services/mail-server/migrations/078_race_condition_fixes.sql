-- ============================================================================
-- Jul 2026 Race Condition & Concurrency Audit Fixes
-- ============================================================================
-- Fixes across wallet_transactions, subscriptions, webhooks, and pagination.

BEGIN;

-- ── 1. wallet_transactions: idempotency via UNIQUE constraint on reference ──
-- The admin_apply_credit handler passes idempotency_key as `reference` but
-- duplicate credit could be created without this constraint.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_class
        WHERE relname = 'uq_wallet_transactions_reference'
          AND relnamespace = 'public'::regnamespace
    ) AND to_regclass('public.wallet_transactions') IS NOT NULL THEN
        -- Filter out NULLs so non-idempotent transactions still work.
        CREATE UNIQUE INDEX uq_wallet_transactions_reference
            ON wallet_transactions(reference)
            WHERE reference IS NOT NULL;
        RAISE NOTICE 'RC-001: Added uq_wallet_transactions_reference for idempotent wallet credits';
    END IF;
END $$;

-- ── 2. webhook_queue: cascade delete when webhook is removed ──
-- If a webhook is deleted while entries exist in the queue, the webhook
-- processor cannot JOIN on the deleted webhook. Add FK with ON DELETE CASCADE.
DO $$
BEGIN
    IF to_regclass('public.webhook_queue') IS NOT NULL THEN
        IF NOT EXISTS (
            SELECT 1 FROM pg_constraint
            WHERE conname = 'webhook_queue_webhook_id_fkey'
              AND conrelid = 'public.webhook_queue'::regclass
        ) THEN
            BEGIN
                ALTER TABLE webhook_queue
                    ADD CONSTRAINT webhook_queue_webhook_id_fkey
                    FOREIGN KEY (webhook_id) REFERENCES webhooks(id) ON DELETE CASCADE;
                RAISE NOTICE 'RC-002: Added cascading FK from webhook_queue to webhooks';
            EXCEPTION WHEN OTHERS THEN
                -- webhooks.id is UUID on runtime-provisioned (apexmail-db
                -- SCHEMA) databases while webhook_queue.webhook_id is
                -- VARCHAR(26) — "cannot be implemented"; skip tolerantly.
                RAISE NOTICE 'RC-002: FK webhook_queue_webhook_id_fkey skipped (%)', SQLERRM;
            END;
        END IF;
    END IF;
END $$;

-- ── 3. stripe_subscriptions: add tenant_id unique constraint to prevent races ──
-- Ensures concurrent Stripe webhook events for the same tenant don't create
-- duplicate subscription records.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_class
        WHERE relname = 'uq_stripe_subscriptions_tenant'
          AND relnamespace = 'public'::regnamespace
    ) AND to_regclass('public.stripe_subscriptions') IS NOT NULL THEN
        CREATE UNIQUE INDEX uq_stripe_subscriptions_tenant
            ON stripe_subscriptions(tenant_id)
            WHERE status = 'active';
        RAISE NOTICE 'RC-003: Added uq_stripe_subscriptions_tenant for race-free subscription upserts';
    END IF;
END $$;

-- ── 4. wallets: ensure balance never goes below 0 after credit race ──
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'chk_wallet_balance_non_negative'
          AND conrelid = 'public.wallets'::regclass
    ) AND to_regclass('public.wallets') IS NOT NULL THEN
        ALTER TABLE wallets ADD CONSTRAINT chk_wallet_balance_non_negative
            CHECK (balance >= 0);
        RAISE NOTICE 'RC-004: Added non-negative balance constraint on wallets';
    END IF;
END $$;

-- ── 5. domains: prevent verification race with unique constraint on name+tenant ──
-- Already exists from earlier migrations; verify it's in place.
DO $$
BEGIN
    IF to_regclass('public.domains') IS NOT NULL THEN
        IF NOT EXISTS (
            SELECT 1 FROM pg_class
        WHERE relname = 'uq_domains_tenant_name'
          AND relnamespace = 'public'::regnamespace
        ) THEN
            -- Create index if it doesn't already exist outside of constraint
            BEGIN
                CREATE UNIQUE INDEX uq_domains_tenant_name
                    ON domains(tenant_id, LOWER(name));
                RAISE NOTICE 'RC-005: Added uq_domains_tenant_name for concurrent domain creation safety';
            EXCEPTION WHEN duplicate_table THEN
                RAISE NOTICE 'RC-005: uq_domains_tenant_name already exists';
            END;
        END IF;
    END IF;
END $$;

-- ── 6. webhooks: prevent duplicate URLs per tenant ──
DO $$
BEGIN
    IF to_regclass('public.webhooks') IS NOT NULL THEN
        IF NOT EXISTS (
            SELECT 1 FROM pg_class
        WHERE relname = 'uq_webhooks_tenant_url'
          AND relnamespace = 'public'::regnamespace
        ) THEN
            BEGIN
                CREATE UNIQUE INDEX uq_webhooks_tenant_url
                    ON webhooks(tenant_id, url);
                RAISE NOTICE 'RC-006: Added uq_webhooks_tenant_url for race-free webhook creation';
            EXCEPTION WHEN duplicate_table THEN
                RAISE NOTICE 'RC-006: uq_webhooks_tenant_url already exists';
            END;
        END IF;
    END IF;
END $$;

COMMIT;
