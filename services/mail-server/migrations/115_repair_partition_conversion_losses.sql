-- Migration 115: Repair partition conversion losses
--
-- =============================================================================
-- Fix-forward repair for databases that ran the canonical chain while
-- migrations 050/058/088 carried their index/trigger/table-loss defects.
-- The defects are ALSO folded into 050/058/088 themselves (fresh chains get
-- the correct shapes directly); this migration repairs already-migrated
-- databases. Every statement is idempotent and guarded — safe to re-run.
--
-- Repairs:
--   1. Stray *_old remnants of an interrupted migration 050 conversion.
--   2. Indexes silently destroyed by 050's RENAME + CREATE IF NOT EXISTS +
--      DROP TABLE *_old sequence (the IF NOT EXISTS no-opped against the
--      names still attached to the renamed table, then the names were
--      deleted with it). None of these were recreated by 001-114.
--   3. updated_at auto-maintenance triggers destroyed by 058's
--      DROP FUNCTION update_updated_at_column() CASCADE (which cascade-dropped
--      every dependent trigger and restored only 14).
--   4. mail_messages foreign keys to mail_accounts/mail_mailboxes, lost with
--      mail_messages_old in the 050 conversion (109's guarded CREATE no-ops
--      against the existing partitioned shape).
--   5. status_page_incidents / status_page_incident_updates — the apexmail-db
--      incidents repo's tables, which existed in no SQL migration at all.
--   6. Partition runway extension (create_future_partitions() has no runtime
--      caller; static partitions end 2027-12/2030-Q1 and inserts would fall
--      into the *_default partitions, which blocks future ATTACHes).
-- =============================================================================

-- ── 0. Tables the canonical chain never created on legacy databases ───────
-- 088 created suppressions (and, on fresh chains, inbound_messages and
-- analytics_queue) only after its guard bug was folded — databases that
-- already ran the pre-fix 088 have none of them. Same canonical shapes as
-- the folded 088; every statement no-ops when the object exists.
CREATE TABLE IF NOT EXISTS suppressions (
    id         VARCHAR(26) PRIMARY KEY,
    tenant_id  VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email      VARCHAR(255) NOT NULL,
    reason     VARCHAR(50) NOT NULL,
    subtype    VARCHAR(100),
    source     VARCHAR(100),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ,
    UNIQUE (tenant_id, email)
);
CREATE INDEX IF NOT EXISTS idx_suppressions_tenant ON suppressions (tenant_id);
CREATE INDEX IF NOT EXISTS idx_suppressions_email ON suppressions (email);
CREATE INDEX IF NOT EXISTS idx_suppressions_reason ON suppressions (reason);

CREATE TABLE IF NOT EXISTS analytics_queue (
    id            BIGSERIAL PRIMARY KEY,
    tenant_id     VARCHAR(26) NOT NULL,
    event_type    TEXT NOT NULL,
    message_id    VARCHAR(26),
    domain_id     VARCHAR(26),
    campaign_id   VARCHAR(64),
    recipient     TEXT,
    metadata      JSONB,
    "timestamp"   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    processed     BOOLEAN NOT NULL DEFAULT FALSE,
    processed_at  TIMESTAMPTZ,
    processing    BOOLEAN NOT NULL DEFAULT FALSE,
    processing_at TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_analytics_queue_pending
    ON analytics_queue (processed, processing, "timestamp");

-- Legacy inbound_messages (tools/initdb lineage) lacks the MTA-writer and
-- AI-agent columns the pre-fix 088 ALTERs were supposed to add.
DO $$
BEGIN
    IF to_regclass('public.inbound_messages') IS NOT NULL THEN
        ALTER TABLE inbound_messages ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(26);
        ALTER TABLE inbound_messages ADD COLUMN IF NOT EXISTS mail_from TEXT;
        ALTER TABLE inbound_messages ADD COLUMN IF NOT EXISTS rcpt_to TEXT[];
        ALTER TABLE inbound_messages ADD COLUMN IF NOT EXISTS client_ip TEXT;
        ALTER TABLE inbound_messages ADD COLUMN IF NOT EXISTS helo_hostname TEXT;
        ALTER TABLE inbound_messages ADD COLUMN IF NOT EXISTS raw_size BIGINT;
        ALTER TABLE inbound_messages ADD COLUMN IF NOT EXISTS auth_results TEXT;
        ALTER TABLE inbound_messages ADD COLUMN IF NOT EXISTS disposition TEXT;
        ALTER TABLE inbound_messages ADD COLUMN IF NOT EXISTS is_verp_reply BOOLEAN NOT NULL DEFAULT false;
        ALTER TABLE inbound_messages ADD COLUMN IF NOT EXISTS lead_id VARCHAR(26);
        ALTER TABLE inbound_messages ADD COLUMN IF NOT EXISTS classification TEXT;
        ALTER TABLE inbound_messages ADD COLUMN IF NOT EXISTS classification_confidence DOUBLE PRECISION;
        ALTER TABLE inbound_messages ADD COLUMN IF NOT EXISTS suggested_action JSONB;
        ALTER TABLE inbound_messages ADD COLUMN IF NOT EXISTS action_taken TEXT;
        ALTER TABLE inbound_messages ADD COLUMN IF NOT EXISTS processed BOOLEAN NOT NULL DEFAULT false;
        ALTER TABLE inbound_messages ADD COLUMN IF NOT EXISTS processing BOOLEAN NOT NULL DEFAULT false;
        ALTER TABLE inbound_messages ADD COLUMN IF NOT EXISTS processed_at TIMESTAMPTZ;
        ALTER TABLE inbound_messages ADD COLUMN IF NOT EXISTS ai_response TEXT;
        ALTER TABLE inbound_messages ADD COLUMN IF NOT EXISTS ai_tokens_used INTEGER;
        ALTER TABLE inbound_messages ADD COLUMN IF NOT EXISTS pending_approval BOOLEAN NOT NULL DEFAULT false;
    END IF;
END $$;

-- ── 1. Stray *_old remnants (interrupted 050) ──────────────────────────────
-- A crash between RENAME and DROP left the un-partitioned *_old table behind
-- AND left the production table empty. Dropping the remnant is the recovery
-- the interrupted migration never reached; only do it when the real
-- (partitioned) table also exists, so this can never delete the only copy.
DO $$
DECLARE
    old_table TEXT;
BEGIN
    FOREACH old_table IN ARRAY ARRAY[
        'email_queue_old', 'email_delivery_log_old', 'mail_messages_old',
        'audit_logs_old', 'bounce_analytics_daily_old'
    ]
    LOOP
        IF to_regclass(format('public.%I', old_table)) IS NOT NULL THEN
            -- count rows for the ops log before dropping
            RAISE NOTICE '115: dropping stray remnant %', old_table;
            EXECUTE format('DROP TABLE IF EXISTS %I', old_table);
        END IF;
    END LOOP;
END $$;

-- ── 2. Indexes lost to the 050 rename-collision ────────────────────────────
-- email_queue: the retry-worker dequeue index — every queue poll full-scans
-- ~25 partitions without it.
CREATE INDEX IF NOT EXISTS idx_email_queue_status_retry
    ON email_queue (status, next_retry_at, priority DESC)
    WHERE status IN ('pending', 'deferred');

-- mail_messages: unread counts + labels containment filter.
CREATE INDEX IF NOT EXISTS idx_mail_messages_unread
    ON mail_messages (account_id, mailbox_id) WHERE NOT is_read;
CREATE INDEX IF NOT EXISTS idx_mail_messages_labels_gin
    ON mail_messages USING GIN (labels);

-- audit_logs: every tenant/user/action-scoped audit surface. (Comments in
-- migrations 058/083 claim these exist; on 050-converted databases they do
-- not.)
CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant_ts
    ON audit_logs (tenant_id, "timestamp" DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_ts
    ON audit_logs (user_id, "timestamp" DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action_ts
    ON audit_logs (action, "timestamp" DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_resource
    ON audit_logs (resource, resource_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_outcome
    ON audit_logs (outcome);

-- bounce_analytics_daily: the tenant/date rollup lookup.
CREATE INDEX IF NOT EXISTS idx_bounce_analytics_daily_tenant_date
    ON bounce_analytics_daily (tenant_id, date DESC);

-- ── 3. Restore update_updated_at_column() triggers everywhere ──────────────
-- 058's DROP FUNCTION ... CASCADE removed every trigger depending on the
-- function and its Section 5 restored a hand-listed 14. Recreate the trigger
-- for EVERY table that has an updated_at column and no trigger already
-- calling update_updated_at_column — derived from the catalog, so nothing is
-- missed and nothing already-correct is duplicated.
DO $$
DECLARE
    target RECORD;
    trigger_name TEXT;
BEGIN
    FOR target IN
        SELECT c.table_name
        FROM information_schema.columns c
        JOIN information_schema.tables t
          ON t.table_schema = c.table_schema AND t.table_name = c.table_name
        WHERE c.table_schema = 'public'
          AND c.column_name = 'updated_at'
          AND t.table_type = 'BASE TABLE'
        ORDER BY c.table_name
    LOOP
        trigger_name := format('trg_%s_updated_at', target.table_name);
        IF NOT EXISTS (
            SELECT 1
            FROM information_schema.triggers
            WHERE event_object_table = target.table_name
              AND action_statement LIKE '%update_updated_at_column%'
        ) THEN
            EXECUTE format(
                'CREATE TRIGGER %I BEFORE UPDATE ON %I '
                'FOR EACH ROW EXECUTE FUNCTION update_updated_at_column()',
                trigger_name, target.table_name
            );
            RAISE NOTICE '115: restored updated_at trigger on %', target.table_name;
        END IF;
    END LOOP;
END $$;

-- ── 4. mail_messages FKs lost with mail_messages_old ───────────────────────
-- Orphaned message rows block the re-add; surface them loudly instead of
-- silently keeping the FK absent. Messages orphaned against BOTH account and
-- mailbox are deleted (unreachable by any legitimate path); rows reachable
-- from either side abort with a clear message for manual review.
DO $$
DECLARE
    orphan_count BIGINT;
    unreachable_count BIGINT;
BEGIN
    IF to_regclass('public.mail_messages') IS NULL
       OR to_regclass('public.mail_accounts') IS NULL
       OR to_regclass('public.mail_mailboxes') IS NULL THEN
        RAISE NOTICE '115: mailstore tables absent — skipping FK restore';
        RETURN;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'mail_messages'::regclass
          AND conname = 'fk_mail_messages_account'
    ) THEN
        SELECT count(*) INTO orphan_count
        FROM mail_messages m
        WHERE NOT EXISTS (SELECT 1 FROM mail_accounts a WHERE a.id = m.account_id);
        IF orphan_count > 0 THEN
            SELECT count(*) INTO unreachable_count
            FROM mail_messages m
            WHERE NOT EXISTS (SELECT 1 FROM mail_accounts a WHERE a.id = m.account_id)
              AND NOT EXISTS (SELECT 1 FROM mail_mailboxes b WHERE b.id = m.mailbox_id);
            DELETE FROM mail_messages m
            WHERE NOT EXISTS (SELECT 1 FROM mail_accounts a WHERE a.id = m.account_id)
              AND NOT EXISTS (SELECT 1 FROM mail_mailboxes b WHERE b.id = m.mailbox_id);
            RAISE NOTICE '115: deleted % unreachable orphaned mail_messages rows', unreachable_count;
            SELECT count(*) INTO orphan_count
            FROM mail_messages m
            WHERE NOT EXISTS (SELECT 1 FROM mail_accounts a WHERE a.id = m.account_id);
            IF orphan_count > 0 THEN
                RAISE EXCEPTION '115: % mail_messages rows reference missing mail_accounts but an existing mail_mailboxes row — resolve manually before FK restore', orphan_count;
            END IF;
        END IF;
        ALTER TABLE mail_messages
            ADD CONSTRAINT fk_mail_messages_account
            FOREIGN KEY (account_id) REFERENCES mail_accounts(id) ON DELETE CASCADE;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'mail_messages'::regclass
          AND conname = 'fk_mail_messages_mailbox'
    ) THEN
        SELECT count(*) INTO orphan_count
        FROM mail_messages m
        WHERE NOT EXISTS (SELECT 1 FROM mail_mailboxes b WHERE b.id = m.mailbox_id);
        IF orphan_count > 0 THEN
            RAISE EXCEPTION '115: % mail_messages rows reference missing mail_mailboxes — resolve manually before FK restore', orphan_count;
        END IF;
        ALTER TABLE mail_messages
            ADD CONSTRAINT fk_mail_messages_mailbox
            FOREIGN KEY (mailbox_id) REFERENCES mail_mailboxes(id) ON DELETE CASCADE;
    END IF;
END $$;

-- ── 5. status_page_incidents — canonical home for the incidents repo ───────
-- crates/apexmail-db/src/repos/incidents.rs reads/writes these; they existed
-- only in the runtime SCHEMA constant, never in a migration, so every
-- migration-provisioned database 500s on the incidents surface.
CREATE TABLE IF NOT EXISTS status_page_incidents (
    id                  TEXT PRIMARY KEY,
    title               TEXT        NOT NULL,
    status              TEXT        NOT NULL DEFAULT 'investigating',
    impact              TEXT        NOT NULL DEFAULT 'minor',
    affected_components TEXT[]      NOT NULL DEFAULT '{}',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS status_page_incident_updates (
    id          TEXT PRIMARY KEY,
    incident_id TEXT        NOT NULL REFERENCES status_page_incidents(id) ON DELETE CASCADE,
    status      TEXT        NOT NULL,
    body        TEXT        NOT NULL,
    author      TEXT        NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_status_page_incident_updates_incident
    ON status_page_incident_updates (incident_id, created_at DESC);

-- ── 6. Partition runway extension ──────────────────────────────────────────
-- create_future_partitions() exists (050/058) but nothing calls it at
-- runtime; the migrator now invokes it after every successful run (see
-- crates/migrator). Call it here as well so one deployment of this migration
-- immediately extends the static runway for already-provisioned databases.
DO $$
BEGIN
    -- to_regprocedure, not to_regclass: functions are not relations and
    -- to_regclass on a function name returns NULL even when it exists.
    IF to_regprocedure('public.create_future_partitions()') IS NOT NULL THEN
        PERFORM create_future_partitions();
        RAISE NOTICE '115: partition runway extended';
    ELSE
        RAISE NOTICE '115: create_future_partitions() absent — skipping runway extension';
    END IF;
END $$;

