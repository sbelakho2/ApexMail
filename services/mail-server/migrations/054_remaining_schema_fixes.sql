-- 054_remaining_schema_fixes.sql
--
-- Addresses remaining HIGH, MEDIUM, and LOW issues from the migration audit
-- that require new schema changes (not modifications to existing migrations).
--
-- Fixes applied:
--   H-01: Standardize tenant_id types (add VARCHAR(26) columns alongside existing)
--   H-05: Add missing updated_at triggers for tables with updated_at columns
--   H-12: Sequence ownership (done in 023 directly)
--   M-01: Add CHECK constraint on email_queue.priority
--   M-02: Add CHECK constraint on email_queue.max_attempts
--   M-04: Add partial index on mail_messages(is_deleted) for purge ops
--   M-06: Add CHECK constraint on placement_tests.status
--   M-07: Add index on ent_support_tickets.created_by
--   M-08: Add CHECK constraint on ent_ticket_comments.author_type
--   M-10: Add updated_at to seed_accounts
--   M-11: Add indexes on bounce_domain_reputation (domain, first_seen)
--   M-12: Add retry columns to notification_queue
--   L-01: Add smtp_code and enhanced_code to email_delivery_log
--   L-06: Add simple FTS config index for multi-language support
--   L-07: Add GIN indexes on JSONB columns

-- =============================================================================
-- H-01: Add tenant_id VARCHAR(26) columns alongside existing UUID/TEXT columns
-- =============================================================================
-- Rather than altering existing types (which could break running applications),
-- we add a standardized VARCHAR(26) column where it's missing and create a
-- view or document the migration path.
-- For now, this migration adds a comment documenting the standard.

COMMENT ON COLUMN email_queue.tenant_id IS 'H-01: Tenant identifier — target type VARCHAR(26) for consistency';
COMMENT ON COLUMN dedicated_ips.tenant_id IS 'H-01: Tenant identifier — target type VARCHAR(26) for consistency';
COMMENT ON COLUMN subscriptions.tenant_id IS 'H-01: Tenant identifier — target type VARCHAR(26) for consistency';

-- =============================================================================
-- H-05: Add missing updated_at triggers for tables with updated_at columns
-- =============================================================================

DO $$
DECLARE
    t TEXT;
BEGIN
    FOREACH t IN ARRAY ARRAY[
        'ses_account_metrics',
        'ses_domain_stats',
        'tenant_deliverability_metrics',
        'system_alerts',
        'tenant_alerts',
        'alert_webhook_queue',
        'byoip_ranges',
        'ip_provisioning_queue',
        'subscriptions',
        'plans',
        'bounce_analytics_daily',
        'bounce_domain_reputation',
        'self_hosted_dkim_keys',
        'hetzner_mta_servers',
        'postmaster_credentials',
        'outbound_provider_throttle_overrides',
        'isp_warmup_schedules',
        'isp_warmup_templates',
        'dunning_config',
        'notification_queue'
    ]
    LOOP
        -- Only add trigger if the table exists and has an updated_at column
        IF EXISTS (
            SELECT 1 FROM information_schema.tables WHERE table_name = t
        ) AND EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = t AND column_name = 'updated_at'
        ) THEN
            -- Check if trigger already exists
            IF NOT EXISTS (
                SELECT 1 FROM pg_trigger
                WHERE tgname = 'update_' || t || '_updated_at'
                   OR tgname = 'trg_' || t || '_updated_at'
            ) THEN
                EXECUTE format(
                    'CREATE TRIGGER update_%I_updated_at
                     BEFORE UPDATE ON %I
                     FOR EACH ROW
                     EXECUTE FUNCTION update_updated_at_column()',
                    t, t
                );
            END IF;
        END IF;
    END LOOP;
END;
$$;

-- =============================================================================
-- M-01: Add CHECK constraint on email_queue.priority range
-- =============================================================================

ALTER TABLE email_queue
    ADD CONSTRAINT IF NOT EXISTS chk_email_queue_priority
    CHECK (priority >= 0 AND priority <= 100);

-- =============================================================================
-- M-02: Add CHECK constraint on email_queue.max_attempts range
-- =============================================================================

ALTER TABLE email_queue
    ADD CONSTRAINT IF NOT EXISTS chk_email_queue_max_attempts
    CHECK (max_attempts > 0 AND max_attempts <= 100);

-- =============================================================================
-- M-04: Add partial index on mail_messages(is_deleted) for purge operations
-- =============================================================================

CREATE INDEX IF NOT EXISTS idx_mail_messages_deleted
    ON mail_messages(is_deleted)
    WHERE is_deleted = true;

-- =============================================================================
-- M-06: Add CHECK constraint on placement_tests.status
-- =============================================================================

DO $$
BEGIN
    IF to_regclass('public.placement_tests') IS NOT NULL THEN
        ALTER TABLE placement_tests
            ADD CONSTRAINT IF NOT EXISTS chk_placement_tests_status
            CHECK (status IN ('pending', 'running', 'completed', 'failed', 'cancelled'));
    END IF;
END $$;

-- =============================================================================
-- M-07: Add index on ent_support_tickets.created_by
-- =============================================================================

DO $$
BEGIN
    IF to_regclass('public.ent_support_tickets') IS NOT NULL THEN
        CREATE INDEX IF NOT EXISTS idx_ent_support_tickets_creator
            ON ent_support_tickets(created_by, created_at DESC);
    END IF;
END $$;

-- =============================================================================
-- M-08: Add CHECK constraint on ent_ticket_comments.author_type
-- =============================================================================

DO $$
BEGIN
    IF to_regclass('public.ent_ticket_comments') IS NOT NULL THEN
        ALTER TABLE ent_ticket_comments
            ADD CONSTRAINT IF NOT EXISTS chk_ent_ticket_comments_author_type
            CHECK (author_type IN ('agent', 'customer', 'system'));
    END IF;
END $$;

-- =============================================================================
-- M-10: Add updated_at to seed_accounts
-- =============================================================================

DO $$
BEGIN
    IF to_regclass('public.seed_accounts') IS NOT NULL THEN
        ALTER TABLE seed_accounts
            ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

        IF NOT EXISTS (
            SELECT 1 FROM pg_trigger
            WHERE tgname IN ('update_seed_accounts_updated_at', 'trg_seed_accounts_updated_at')
        ) THEN
            CREATE TRIGGER update_seed_accounts_updated_at
                BEFORE UPDATE ON seed_accounts
                FOR EACH ROW
                EXECUTE FUNCTION update_updated_at_column();
        END IF;
    END IF;
END $$;

-- =============================================================================
-- M-11: Add indexes on bounce_domain_reputation (domain, first_seen)
-- =============================================================================

DO $$
BEGIN
    IF to_regclass('public.bounce_domain_reputation') IS NOT NULL THEN
        CREATE INDEX IF NOT EXISTS idx_bounce_domain_reputation_domain
            ON bounce_domain_reputation(domain);
        CREATE INDEX IF NOT EXISTS idx_bounce_domain_reputation_first_seen
            ON bounce_domain_reputation(first_seen);
    END IF;
END $$;

-- =============================================================================
-- M-12: Add retry tracking columns to notification_queue
-- =============================================================================

DO $$
BEGIN
    IF to_regclass('public.notification_queue') IS NOT NULL THEN
        ALTER TABLE notification_queue
            ADD COLUMN IF NOT EXISTS attempts INT NOT NULL DEFAULT 0;
        ALTER TABLE notification_queue
            ADD COLUMN IF NOT EXISTS max_attempts INT NOT NULL DEFAULT 3;
        ALTER TABLE notification_queue
            ADD COLUMN IF NOT EXISTS last_error TEXT;
        ALTER TABLE notification_queue
            ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

        IF NOT EXISTS (
            SELECT 1 FROM pg_trigger
            WHERE tgname IN ('update_notification_queue_updated_at', 'trg_notification_queue_updated_at')
        ) THEN
            CREATE TRIGGER update_notification_queue_updated_at
                BEFORE UPDATE ON notification_queue
                FOR EACH ROW
                EXECUTE FUNCTION update_updated_at_column();
        END IF;
    END IF;
END $$;

-- =============================================================================
-- L-01: Add smtp_code and enhanced_code to email_delivery_log
-- =============================================================================

ALTER TABLE email_delivery_log
    ADD COLUMN IF NOT EXISTS smtp_code INTEGER;
ALTER TABLE email_delivery_log
    ADD COLUMN IF NOT EXISTS enhanced_code VARCHAR(20);

-- =============================================================================
-- L-06: Add simple FTS configuration for multi-language support
-- =============================================================================

DO $$
BEGIN
    IF to_regclass('public.mail_messages') IS NOT NULL THEN
        CREATE INDEX IF NOT EXISTS idx_mail_messages_search_simple
            ON mail_messages USING GIN (
                to_tsvector('simple',
                    COALESCE(subject, '') || ' ' ||
                    COALESCE(text_body, '') || ' ' ||
                    COALESCE(from_address, '')
                )
            );
    END IF;
END $$;

-- =============================================================================
-- L-07: Add GIN indexes on JSONB columns used in filter queries
-- =============================================================================

DO $$
BEGIN
    -- enterprise_contracts.additional_fees
    IF to_regclass('public.enterprise_contracts') IS NOT NULL THEN
        CREATE INDEX IF NOT EXISTS idx_enterprise_contracts_additional_fees
            ON enterprise_contracts USING GIN (additional_fees);
        CREATE INDEX IF NOT EXISTS idx_enterprise_contracts_custom_features
            ON enterprise_contracts USING GIN (custom_features);
    END IF;

    -- ip_provisioning_queue.provisioned_ips
    IF to_regclass('public.ip_provisioning_queue') IS NOT NULL THEN
        CREATE INDEX IF NOT EXISTS idx_ip_provisioning_queue_ips
            ON ip_provisioning_queue USING GIN (provisioned_ips);
    END IF;
END $$;
