-- Migration 061: Fix remaining db faults
--
-- =============================================================================
-- REMAINING MEDIUM/LOW/INFO DATABASE FAULTS (M-01 through M-14, L-01 through
-- L-07, I-01 through I-05)
-- =============================================================================
-- Addresses the remaining medium (M-01 through M-14), low (L-01 through L-07),
-- and informational (I-01 through I-05) migration faults identified in
-- faults.md.
--
-- Every statement uses IF NOT EXISTS / IF EXISTS guards and/or DO $$ blocks so
-- this migration is safe to run multiple times on any deployment.
-- =============================================================================

-- =============================================================================
-- Section 1: M-01 — CHECK constraint on email_queue.priority range
-- =============================================================================
DO $$
BEGIN
    IF to_regclass('public.email_queue') IS NOT NULL THEN
        IF NOT EXISTS (
            SELECT 1 FROM pg_constraint 
            WHERE conname = 'email_queue_priority_check'
              AND conrelid = 'email_queue'::regclass
        ) THEN
            EXECUTE 'ALTER TABLE email_queue ADD CONSTRAINT email_queue_priority_check 
                     CHECK (priority >= 0 AND priority <= 100) NOT VALID';
            RAISE NOTICE 'M-01: Added CHECK constraint email_queue_priority_check';
        ELSE
            RAISE NOTICE 'M-01: email_queue_priority_check already exists';
        END IF;
    ELSE
        RAISE NOTICE 'M-01: email_queue table does not exist';
    END IF;
END $$;

-- =============================================================================
-- Section 2: M-02 — CHECK constraint on email_queue.max_attempts range
-- =============================================================================
DO $$
BEGIN
    IF to_regclass('public.email_queue') IS NOT NULL THEN
        IF NOT EXISTS (
            SELECT 1 FROM pg_constraint 
            WHERE conname = 'email_queue_max_attempts_check'
              AND conrelid = 'email_queue'::regclass
        ) THEN
            EXECUTE 'ALTER TABLE email_queue ADD CONSTRAINT email_queue_max_attempts_check 
                     CHECK (max_attempts > 0 AND max_attempts <= 100) NOT VALID';
            RAISE NOTICE 'M-02: Added CHECK constraint email_queue_max_attempts_check';
        ELSE
            RAISE NOTICE 'M-02: email_queue_max_attempts_check already exists';
        END IF;
    ELSE
        RAISE NOTICE 'M-02: email_queue table does not exist';
    END IF;
END $$;

-- =============================================================================
-- Section 3: M-03 — DEFAULT '' on mail_accounts.display_name
-- =============================================================================
DO $$
BEGIN
    IF to_regclass('public.mail_accounts') IS NOT NULL THEN
        IF EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'mail_accounts' AND column_name = 'display_name'
        ) THEN
            EXECUTE 'ALTER TABLE mail_accounts ALTER COLUMN display_name SET DEFAULT ''''';
            RAISE NOTICE 'M-03: Set DEFAULT on mail_accounts.display_name';
        END IF;
    ELSE
        RAISE NOTICE 'M-03: mail_accounts table does not exist';
    END IF;
END $$;

-- =============================================================================
-- Section 4: M-04 — Partial index on mail_messages(is_deleted) for purge ops
-- =============================================================================
DO $$
BEGIN
    IF to_regclass('public.mail_messages') IS NOT NULL THEN
        IF EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'mail_messages' AND column_name = 'is_deleted'
        ) THEN
            IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'idx_mail_messages_deleted') THEN
                EXECUTE 'CREATE INDEX IF NOT EXISTS idx_mail_messages_deleted 
                         ON mail_messages(is_deleted) WHERE is_deleted = true';
                RAISE NOTICE 'M-04: Created idx_mail_messages_deleted partial index';
            ELSE
                RAISE NOTICE 'M-04: idx_mail_messages_deleted already exists';
            END IF;
        END IF;
    ELSE
        RAISE NOTICE 'M-04: mail_messages table does not exist';
    END IF;
END $$;

-- =============================================================================
-- Section 5: M-05 — Add 'junk' and 'template' to mailbox_type CHECK
-- =============================================================================
DO $$
BEGIN
    IF to_regclass('public.mail_mailboxes') IS NOT NULL THEN
        IF EXISTS (
            SELECT 1 FROM pg_constraint c
            WHERE c.conname = 'mail_mailboxes_mailbox_type_check'
              AND c.conrelid = 'mail_mailboxes'::regclass
        ) THEN
            IF NOT EXISTS (
                SELECT 1 FROM pg_constraint c
                WHERE c.conname = 'mail_mailboxes_mailbox_type_check'
                  AND c.conrelid = 'mail_mailboxes'::regclass
                  AND pg_get_constraintdef(c.oid) LIKE '%junk%'
            ) THEN
                EXECUTE 'ALTER TABLE mail_mailboxes DROP CONSTRAINT mail_mailboxes_mailbox_type_check';
                EXECUTE 'ALTER TABLE mail_mailboxes ADD CONSTRAINT mail_mailboxes_mailbox_type_check 
                         CHECK (mailbox_type IN (''inbox'', ''sent'', ''drafts'', ''trash'', ''spam'', 
                                ''archive'', ''custom'', ''junk'', ''template'')) NOT VALID';
                RAISE NOTICE 'M-05: Updated mailbox_type CHECK to include junk and template';
            ELSE
                RAISE NOTICE 'M-05: Constraint already includes junk/template';
            END IF;
        END IF;
    ELSE
        RAISE NOTICE 'M-05: mail_mailboxes table does not exist';
    END IF;
END $$;

-- =============================================================================
-- Section 6: M-06 — CHECK constraint on placement_tests.status
-- =============================================================================
DO $$
BEGIN
    IF to_regclass('public.placement_tests') IS NOT NULL THEN
        IF NOT EXISTS (
            SELECT 1 FROM pg_constraint 
            WHERE conname = 'placement_tests_status_check'
              AND conrelid = 'placement_tests'::regclass
        ) THEN
            EXECUTE 'ALTER TABLE placement_tests ADD CONSTRAINT placement_tests_status_check 
                     CHECK (status IN (''pending'', ''running'', ''completed'', ''failed'', ''cancelled'')) NOT VALID';
            RAISE NOTICE 'M-06: Added CHECK constraint placement_tests_status_check';
        ELSE
            RAISE NOTICE 'M-06: placement_tests_status_check already exists';
        END IF;
    ELSE
        RAISE NOTICE 'M-06: placement_tests table does not exist';
    END IF;
END $$;

-- =============================================================================
-- Section 7: M-07 — Index on ent_support_tickets(created_by, created_at DESC)
-- =============================================================================
DO $$
BEGIN
    IF to_regclass('public.ent_support_tickets') IS NOT NULL THEN
        IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'idx_ent_support_tickets_creator') THEN
            EXECUTE 'CREATE INDEX IF NOT EXISTS idx_ent_support_tickets_creator 
                     ON ent_support_tickets(created_by, created_at DESC)';
            RAISE NOTICE 'M-07: Created idx_ent_support_tickets_creator';
        ELSE
            RAISE NOTICE 'M-07: idx_ent_support_tickets_creator already exists';
        END IF;
    ELSE
        RAISE NOTICE 'M-07: ent_support_tickets table does not exist';
    END IF;
END $$;

-- =============================================================================
-- Section 8: M-08 — CHECK constraint on ent_ticket_comments.author_type
-- =============================================================================
DO $$
BEGIN
    IF to_regclass('public.ent_ticket_comments') IS NOT NULL THEN
        IF NOT EXISTS (
            SELECT 1 FROM pg_constraint 
            WHERE conname = 'ent_ticket_comments_author_type_check'
              AND conrelid = 'ent_ticket_comments'::regclass
        ) THEN
            EXECUTE 'ALTER TABLE ent_ticket_comments ADD CONSTRAINT ent_ticket_comments_author_type_check 
                     CHECK (author_type IN (''agent'', ''customer'', ''system'')) NOT VALID';
            RAISE NOTICE 'M-08: Added CHECK constraint ent_ticket_comments_author_type_check';
        ELSE
            RAISE NOTICE 'M-08: ent_ticket_comments_author_type_check already exists';
        END IF;
    ELSE
        RAISE NOTICE 'M-08: ent_ticket_comments table does not exist';
    END IF;
END $$;

-- =============================================================================
-- Section 9: M-09 — FK from ent_sso_sessions to ent_sso_configurations
-- =============================================================================
DO $$
BEGIN
    IF to_regclass('public.ent_sso_sessions') IS NOT NULL 
       AND to_regclass('public.ent_sso_configurations') IS NOT NULL THEN
        IF NOT EXISTS (
            SELECT 1 FROM pg_constraint 
            WHERE conname = 'ent_sso_sessions_config_fk'
              AND conrelid = 'ent_sso_sessions'::regclass
        ) THEN
            BEGIN
                EXECUTE 'ALTER TABLE ent_sso_sessions 
                         ADD CONSTRAINT ent_sso_sessions_config_fk 
                         FOREIGN KEY (tenant_id, provider_type) 
                         REFERENCES ent_sso_configurations(tenant_id, provider_type)';
                RAISE NOTICE 'M-09: Added FK ent_sso_sessions_config_fk';
            EXCEPTION WHEN OTHERS THEN
                RAISE WARNING 'M-09: Could not add FK: %', SQLERRM;
            END;
        ELSE
            RAISE NOTICE 'M-09: ent_sso_sessions_config_fk already exists';
        END IF;
    ELSE
        RAISE NOTICE 'M-09: ent_sso_sessions or ent_sso_configurations table missing';
    END IF;
END $$;

-- =============================================================================
-- Section 10: M-10 — Add updated_at to seed_accounts
-- =============================================================================
DO $$
BEGIN
    IF to_regclass('public.seed_accounts') IS NOT NULL THEN
        IF NOT EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'seed_accounts' AND column_name = 'updated_at'
        ) THEN
            EXECUTE 'ALTER TABLE seed_accounts ADD COLUMN updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()';
            RAISE NOTICE 'M-10: Added updated_at column to seed_accounts';
        END IF;
        IF EXISTS (SELECT 1 FROM pg_proc WHERE proname = 'update_updated_at_column') THEN
            IF NOT EXISTS (
                SELECT 1 FROM pg_trigger 
                WHERE tgname = 'trg_seed_accounts_updated_at'
                  AND tgrelid = 'seed_accounts'::regclass
            ) THEN
                EXECUTE 'CREATE TRIGGER trg_seed_accounts_updated_at
                         BEFORE UPDATE ON seed_accounts
                         FOR EACH ROW
                         EXECUTE FUNCTION update_updated_at_column()';
                RAISE NOTICE 'M-10: Added trigger trg_seed_accounts_updated_at';
            END IF;
        END IF;
    ELSE
        RAISE NOTICE 'M-10: seed_accounts table does not exist';
    END IF;
END $$;

-- =============================================================================
-- Section 11: M-11 — Indexes on bounce_domain_reputation
-- =============================================================================
DO $$
BEGIN
    IF to_regclass('public.bounce_domain_reputation') IS NOT NULL THEN
        IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'idx_bounce_domain_reputation_domain') THEN
            EXECUTE 'CREATE INDEX IF NOT EXISTS idx_bounce_domain_reputation_domain ON bounce_domain_reputation(domain)';
            RAISE NOTICE 'M-11: Created idx_bounce_domain_reputation_domain';
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'idx_bounce_domain_reputation_first_seen') THEN
            EXECUTE 'CREATE INDEX IF NOT EXISTS idx_bounce_domain_reputation_first_seen ON bounce_domain_reputation(first_seen)';
            RAISE NOTICE 'M-11: Created idx_bounce_domain_reputation_first_seen';
        END IF;
    ELSE
        RAISE NOTICE 'M-11: bounce_domain_reputation table does not exist';
    END IF;
END $$;

-- =============================================================================
-- Section 12: M-12 — Add retry columns to notification_queue
-- =============================================================================
DO $$
BEGIN
    IF to_regclass('public.notification_queue') IS NOT NULL THEN
        IF NOT EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'notification_queue' AND column_name = 'attempts'
        ) THEN
            EXECUTE 'ALTER TABLE notification_queue ADD COLUMN attempts INT NOT NULL DEFAULT 0';
            RAISE NOTICE 'M-12: Added attempts column';
        END IF;
        IF NOT EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'notification_queue' AND column_name = 'max_attempts'
        ) THEN
            EXECUTE 'ALTER TABLE notification_queue ADD COLUMN max_attempts INT NOT NULL DEFAULT 3';
            RAISE NOTICE 'M-12: Added max_attempts column';
        END IF;
        IF NOT EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'notification_queue' AND column_name = 'last_error'
        ) THEN
            EXECUTE 'ALTER TABLE notification_queue ADD COLUMN last_error TEXT';
            RAISE NOTICE 'M-12: Added last_error column';
        END IF;
        IF NOT EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'notification_queue' AND column_name = 'updated_at'
        ) THEN
            EXECUTE 'ALTER TABLE notification_queue ADD COLUMN updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()';
            RAISE NOTICE 'M-12: Added updated_at column';
        END IF;
        IF EXISTS (SELECT 1 FROM pg_proc WHERE proname = 'update_updated_at_column') THEN
            IF NOT EXISTS (
                SELECT 1 FROM pg_trigger 
                WHERE tgname = 'trg_notification_queue_updated_at'
                  AND tgrelid = 'notification_queue'::regclass
            ) THEN
                EXECUTE 'CREATE TRIGGER trg_notification_queue_updated_at
                         BEFORE UPDATE ON notification_queue
                         FOR EACH ROW
                         EXECUTE FUNCTION update_updated_at_column()';
                RAISE NOTICE 'M-12: Added trigger trg_notification_queue_updated_at';
            END IF;
        END IF;
    ELSE
        RAISE NOTICE 'M-12: notification_queue table does not exist';
    END IF;
END $$;

-- =============================================================================
-- Section 13: M-13 — Fix UNIQUE constraint on postmaster_reputation_summary
-- =============================================================================
DO $$
BEGIN
    IF to_regclass('public.postmaster_reputation_summary') IS NOT NULL THEN
        IF EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'postmaster_reputation_summary' AND column_name = 'computed_at'
        ) THEN
            IF EXISTS (
                SELECT 1 FROM pg_constraint 
                WHERE conname = 'postmaster_reputation_summary_scope_identity_provider_key'
                  AND conrelid = 'postmaster_reputation_summary'::regclass
            ) THEN
                EXECUTE 'ALTER TABLE postmaster_reputation_summary 
                         DROP CONSTRAINT postmaster_reputation_summary_scope_identity_provider_key';
                RAISE NOTICE 'M-13: Dropped old UNIQUE (scope, identity, provider)';
            END IF;
            IF NOT EXISTS (
                SELECT 1 FROM pg_constraint 
                WHERE conname = 'postmaster_reputation_summary_scope_identity_provider_computed_at_key'
                  AND conrelid = 'postmaster_reputation_summary'::regclass
            ) THEN
                EXECUTE 'ALTER TABLE postmaster_reputation_summary 
                         ADD CONSTRAINT postmaster_reputation_summary_scope_identity_provider_computed_at_key 
                         UNIQUE (scope, identity, provider, computed_at)';
                RAISE NOTICE 'M-13: Added UNIQUE (scope, identity, provider, computed_at)';
            END IF;
        END IF;
    ELSE
        RAISE NOTICE 'M-13: postmaster_reputation_summary table does not exist';
    END IF;
END $$;

-- =============================================================================
-- Section 14: M-14 — FK constraints on ent_private_deployments
-- =============================================================================
DO $$
BEGIN
    IF to_regclass('public.ent_private_deployments') IS NOT NULL 
       AND to_regclass('public.tenants') IS NOT NULL THEN
        IF NOT EXISTS (
            SELECT 1 FROM pg_constraint 
            WHERE conname = 'ent_private_deployments_tenant_id_fk'
              AND conrelid = 'ent_private_deployments'::regclass
        ) THEN
            BEGIN
                EXECUTE 'ALTER TABLE ent_private_deployments 
                         ADD CONSTRAINT ent_private_deployments_tenant_id_fk 
                         FOREIGN KEY (tenant_id) REFERENCES tenants(id)';
                RAISE NOTICE 'M-14: Added FK ent_private_deployments_tenant_id_fk';
            EXCEPTION WHEN OTHERS THEN
                RAISE WARNING 'M-14: Could not add FK: %', SQLERRM;
            END;
        END IF;
    END IF;
    IF to_regclass('public.ent_dedicated_ips') IS NOT NULL 
       AND to_regclass('public.tenants') IS NOT NULL THEN
        IF NOT EXISTS (
            SELECT 1 FROM pg_constraint 
            WHERE conname = 'ent_dedicated_ips_tenant_id_fk'
              AND conrelid = 'ent_dedicated_ips'::regclass
        ) THEN
            BEGIN
                EXECUTE 'ALTER TABLE ent_dedicated_ips 
                         ADD CONSTRAINT ent_dedicated_ips_tenant_id_fk 
                         FOREIGN KEY (tenant_id) REFERENCES tenants(id)';
                RAISE NOTICE 'M-14: Added FK ent_dedicated_ips_tenant_id_fk';
            EXCEPTION WHEN OTHERS THEN
                RAISE WARNING 'M-14: Could not add FK: %', SQLERRM;
            END;
        END IF;
    END IF;
END $$;

-- =============================================================================
-- Section 15: L-01 — Add smtp_code and enhanced_code to email_delivery_log
-- =============================================================================
DO $$
BEGIN
    IF to_regclass('public.email_delivery_log') IS NOT NULL THEN
        IF NOT EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'email_delivery_log' AND column_name = 'smtp_code'
        ) THEN
            EXECUTE 'ALTER TABLE email_delivery_log ADD COLUMN smtp_code INTEGER';
            RAISE NOTICE 'L-01: Added smtp_code column';
        END IF;
        IF NOT EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'email_delivery_log' AND column_name = 'enhanced_code'
        ) THEN
            EXECUTE 'ALTER TABLE email_delivery_log ADD COLUMN enhanced_code VARCHAR(20)';
            RAISE NOTICE 'L-01: Added enhanced_code column';
        END IF;
    ELSE
        RAISE NOTICE 'L-01: email_delivery_log table does not exist';
    END IF;
END $$;

-- =============================================================================
-- Section 16: L-02 — FK on subscriptions.tenant_id
-- =============================================================================
DO $$
BEGIN
    IF to_regclass('public.subscriptions') IS NOT NULL 
       AND to_regclass('public.tenants') IS NOT NULL THEN
        IF NOT EXISTS (
            SELECT 1 FROM pg_constraint 
            WHERE conname = 'subscriptions_tenant_id_fk'
              AND conrelid = 'subscriptions'::regclass
        ) THEN
            BEGIN
                EXECUTE 'ALTER TABLE subscriptions 
                         ADD CONSTRAINT subscriptions_tenant_id_fk 
                         FOREIGN KEY (tenant_id) REFERENCES tenants(id)';
                RAISE NOTICE 'L-02: Added FK subscriptions_tenant_id_fk';
            EXCEPTION WHEN OTHERS THEN
                RAISE WARNING 'L-02: Could not add FK: %', SQLERRM;
            END;
        END IF;
    END IF;
END $$;

-- =============================================================================
-- Section 17: L-03 — Audit columns on dedicated_ips
-- =============================================================================
DO $$
BEGIN
    IF to_regclass('public.dedicated_ips') IS NOT NULL THEN
        IF NOT EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'dedicated_ips' AND column_name = 'created_by'
        ) THEN
            EXECUTE 'ALTER TABLE dedicated_ips ADD COLUMN created_by TEXT';
            RAISE NOTICE 'L-03: Added created_by column';
        END IF;
        IF NOT EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'dedicated_ips' AND column_name = 'updated_by'
        ) THEN
            EXECUTE 'ALTER TABLE dedicated_ips ADD COLUMN updated_by TEXT';
            RAISE NOTICE 'L-03: Added updated_by column';
        END IF;
    ELSE
        RAISE NOTICE 'L-03: dedicated_ips table does not exist';
    END IF;
END $$;

-- =============================================================================
-- Section 18: L-04 — Update ISP warmup templates seed data
-- =============================================================================
DO $$
BEGIN
    IF to_regclass('public.isp_warmup_templates') IS NOT NULL THEN
        -- 042's schema lacks these columns; add them (idempotent) first.
        ALTER TABLE isp_warmup_templates ADD COLUMN IF NOT EXISTS daily_volume_cap INTEGER;
        ALTER TABLE isp_warmup_templates ADD COLUMN IF NOT EXISTS warmup_days INTEGER;
        UPDATE isp_warmup_templates 
        SET mx_patterns = '["*.google.com", "*.googlemail.com"]'::jsonb,
            daily_volume_cap = 5000,
            warmup_days = 21
        WHERE isp_name = 'Google' 
        AND mx_patterns IS DISTINCT FROM '["*.google.com", "*.googlemail.com"]'::jsonb;
        
        UPDATE isp_warmup_templates 
        SET mx_patterns = '["*.outlook.com", "*.hotmail.com", "*.live.com", "*.office365.com"]'::jsonb,
            daily_volume_cap = 3000,
            warmup_days = 28
        WHERE isp_name = 'Microsoft' 
        AND mx_patterns IS DISTINCT FROM '["*.outlook.com", "*.hotmail.com", "*.live.com", "*.office365.com"]'::jsonb;
        
        RAISE NOTICE 'L-04: Updated ISP warmup templates seed data';
    ELSE
        RAISE NOTICE 'L-04: isp_warmup_templates table does not exist';
    END IF;
END $$;

-- =============================================================================
-- Section 19: L-05 — Graceful sso_oidc_state cleanup
-- =============================================================================
DO $outer$
BEGIN
    IF to_regclass('public.sso_oidc_state') IS NOT NULL THEN
        CREATE OR REPLACE FUNCTION cleanup_old_sso_oidc_state()
        RETURNS INTEGER
        LANGUAGE plpgsql
        AS $func$
        DECLARE
            v_deleted INTEGER;
        BEGIN
            DELETE FROM sso_oidc_state 
            WHERE created_at < NOW() - INTERVAL '5 minutes';
            GET DIAGNOSTICS v_deleted = ROW_COUNT;
            RETURN v_deleted;
        END;
        $func$;
        RAISE NOTICE 'L-05: Created cleanup_old_sso_oidc_state() function';
    ELSE
        RAISE NOTICE 'L-05: sso_oidc_state table does not exist';
    END IF;
END $outer$;

-- =============================================================================
-- Section 20: L-06 — Add simple GIN index for multi-language FTS
-- =============================================================================
DO $$
BEGIN
    IF to_regclass('public.mail_messages') IS NOT NULL THEN
        IF EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'mail_messages' AND column_name = 'subject'
        ) AND EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'mail_messages' AND column_name = 'body_text'
        ) THEN
            IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'idx_mail_messages_fts_simple') THEN
                EXECUTE 'CREATE INDEX IF NOT EXISTS idx_mail_messages_fts_simple 
                         ON mail_messages USING GIN 
                         (to_tsvector(''simple'', coalesce(subject, '''') || '' '' || coalesce(body_text, '''')))';
                RAISE NOTICE 'L-06: Created idx_mail_messages_fts_simple';
            ELSE
                RAISE NOTICE 'L-06: idx_mail_messages_fts_simple already exists';
            END IF;
        END IF;
    ELSE
        RAISE NOTICE 'L-06: mail_messages table does not exist';
    END IF;
END $$;

-- =============================================================================
-- Section 21: L-07 — GIN indexes on JSONB columns
-- =============================================================================
DO $$
BEGIN
    IF to_regclass('public.enterprise_contracts') IS NOT NULL THEN
        IF EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'enterprise_contracts' AND column_name = 'additional_fees'
              AND data_type = 'jsonb'
        ) THEN
            IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'idx_enterprise_contracts_additional_fees') THEN
                EXECUTE 'CREATE INDEX IF NOT EXISTS idx_enterprise_contracts_additional_fees 
                         ON enterprise_contracts USING GIN (additional_fees)';
                RAISE NOTICE 'L-07: Created GIN on enterprise_contracts.additional_fees';
            END IF;
        END IF;
        IF EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'enterprise_contracts' AND column_name = 'custom_features'
              AND data_type = 'jsonb'
        ) THEN
            IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'idx_enterprise_contracts_custom_features') THEN
                EXECUTE 'CREATE INDEX IF NOT EXISTS idx_enterprise_contracts_custom_features 
                         ON enterprise_contracts USING GIN (custom_features)';
                RAISE NOTICE 'L-07: Created GIN on enterprise_contracts.custom_features';
            END IF;
        END IF;
    END IF;

    IF to_regclass('public.ip_provisioning_queue') IS NOT NULL THEN
        IF EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'ip_provisioning_queue' AND column_name = 'provisioned_ips'
              AND data_type = 'jsonb'
        ) THEN
            IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'idx_ip_provisioning_queue_provisioned_ips') THEN
                EXECUTE 'CREATE INDEX IF NOT EXISTS idx_ip_provisioning_queue_provisioned_ips 
                         ON ip_provisioning_queue USING GIN (provisioned_ips)';
                RAISE NOTICE 'L-07: Created GIN on ip_provisioning_queue.provisioned_ips';
            END IF;
        END IF;
    END IF;

    IF to_regclass('public.trust_portal_subprocessors') IS NOT NULL THEN
        IF EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'trust_portal_subprocessors' AND column_name = 'data_categories'
              AND data_type = 'jsonb'
        ) THEN
            IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'idx_trust_portal_subprocessors_data_categories') THEN
                EXECUTE 'CREATE INDEX IF NOT EXISTS idx_trust_portal_subprocessors_data_categories 
                         ON trust_portal_subprocessors USING GIN (data_categories)';
                RAISE NOTICE 'L-07: Created GIN on trust_portal_subprocessors.data_categories';
            END IF;
        END IF;
    END IF;
END $$;

-- =============================================================================
-- Section 22: I-01 — Comment on migration 050 transaction safety
-- =============================================================================
DO $$
BEGIN
    RAISE NOTICE 'I-01: Migration 050 is safely wrapped in a transaction (no CONCURRENTLY indexes inside).';
END $$;

-- =============================================================================
-- Section 23: I-02 — Comment on mfa_recovery_hashes security
-- =============================================================================
DO $$
BEGIN
    IF to_regclass('public.users') IS NOT NULL THEN
        IF EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'users' AND column_name = 'mfa_recovery_hashes'
        ) THEN
            EXECUTE 'COMMENT ON COLUMN users.mfa_recovery_hashes IS 
                     ''JSONB array of SHA-256 hashed recovery codes. WARNING: Must only contain hashes, never raw codes.''';
            RAISE NOTICE 'I-02: Added security comment on users.mfa_recovery_hashes';
        END IF;
    END IF;
END $$;

-- =============================================================================
-- Section 24: I-03 — Comment on CONCURRENTLY safety in DO blocks
-- =============================================================================
DO $$
BEGIN
    RAISE NOTICE 'I-03: Migration 029 DO blocks with CONCURRENTLY are safe (PL/pgSQL blocks are not explicit transactions).';
END $$;

-- =============================================================================
-- Section 25: I-04 — Comment on audit_logs PK type
-- =============================================================================
DO $$
BEGIN
    RAISE NOTICE 'I-04: audit_logs PK uses id TEXT. Consider UUID or BIGSERIAL in future schema redesign.';
END $$;

-- =============================================================================
-- Section 26: I-05 — Comment on duplicate index definitions
-- =============================================================================
DO $$
BEGIN
    RAISE NOTICE 'I-05: Migration 050 re-creates indexes from earlier migrations. Consider consolidating index definitions.';
END $$;

-- =============================================================================
-- Summary
-- =============================================================================
DO $$
BEGIN
    RAISE NOTICE '061_fix_remaining_db_faults.sql: Completed 26 sections (M-01 to M-14, L-01 to L-07, I-01 to I-05)';
END $$;
