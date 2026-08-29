-- 116_financial_integrity_constraints.sql
--
-- =============================================================================
-- Integrity constraints the chain never enforced, plus data repairs that
-- make the constraints addable. Idempotent and guarded — safe to re-run.
--
--   1. invoices.invoice_number UNIQUE — EU/Estonian VAT requires unique,
--      sequential invoice numbers; two writer paths (sequence + admin
--      random) could collide silently. Duplicate numbers are renumbered
--      deterministically before the index is added.
--   2. api_keys.key_hash UNIQUE — the hottest auth lookup assumed
--      uniqueness; double-provisioning could mint ambiguous keys.
--   3. users case-insensitive email uniqueness — login matches on
--      LOWER(email) while the column UNIQUE was case-sensitive, so
--      Alice@x.com and alice@x.com could both exist and race the login
--      fetch_one. Later case-duplicates are RENAMED (never deleted).
--   4. billing_addresses UNIQUE(tenant_id) — the KMD VAT rate breakdown
--      joins billing_addresses; multiple rows per tenant double-count
--      every invoice in the per-rate buckets. Keep the newest row.
--   5. dunning_config.tenant_id UUID → VARCHAR(26) — 058 converted it to
--      UUID while real tenant ids are 26-char ULID-style strings, so the
--      per-tenant dunning lookup ALWAYS errored and silently fell back to
--      defaults. Rows whose id matches no real tenant are dead config from
--      the UUID era and are dropped.
--   6. Financial FKs ON DELETE CASCADE → RESTRICT — deleting a tenant must
--      never destroy wallets, ledgers, contracts, SLA credits or dunning
--      history (Estonian bookkeeping retention is 7 years). The admin
--      tenant-deletion path deletes child rows explicitly first, so
--      RESTRICT only turns "silently destroyed ledger" into a loud error.
--
-- NOTE on campaign_recipients.campaign_id: an audit pass flagged 093's FK
-- (campaign_id → drip_campaigns.id) as pointing at "the wrong table" and
-- proposed retargeting to campaigns(id). That is incorrect: the sales
-- pipeline writes 22-char TEXT campaign ids (generate_id("cmp", 22)), reads
-- recipients by joining drip_campaigns (routes/admin/sales.rs: "FROM
-- drip_campaigns c LEFT JOIN campaign_recipients cr ON cr.campaign_id =
-- c.id"), and its own bootstrap DDL declares the exact same FK (campaign_id
-- TEXT NOT NULL REFERENCES drip_campaigns(id)). The UUID-keyed `campaigns`
-- table is a separate console feature. No change made.
-- =============================================================================

-- ── 1. invoices.invoice_number UNIQUE ──────────────────────────────────────
DO $$
DECLARE
    dup RECORD;
    suffix INT;
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_indexes
        WHERE indexname = 'uq_invoices_invoice_number'
    ) THEN
        -- Renumber later duplicates deterministically: the earliest row per
        -- number keeps it, later rows (by created_at, then id) get -2, -3, ...
        FOR dup IN
            SELECT id, invoice_number,
                   ROW_NUMBER() OVER (
                       PARTITION BY invoice_number
                       ORDER BY created_at NULLS LAST, id
                   ) AS dup_rank
            FROM invoices
            WHERE invoice_number IS NOT NULL
        LOOP
            IF dup.dup_rank > 1 THEN
                suffix := dup.dup_rank::int;
                UPDATE invoices
                SET invoice_number = left(dup.invoice_number, 56) || '-' || suffix::text
                WHERE id = dup.id;
                RAISE NOTICE '116: renumbered duplicate invoice % (rank %)', dup.id, suffix;
            END IF;
        END LOOP;
        -- Any residual collision (e.g. the renumbering itself collided with
        -- an existing number) must abort, not silently index over.
        IF EXISTS (
            SELECT 1
            FROM (
                SELECT invoice_number FROM invoices
                WHERE invoice_number IS NOT NULL
                GROUP BY invoice_number HAVING count(*) > 1
            ) d
        ) THEN
            RAISE EXCEPTION '116: duplicate invoice_number survives renumbering — resolve manually';
        END IF;
        CREATE UNIQUE INDEX uq_invoices_invoice_number ON invoices (invoice_number);
    END IF;
END $$;

-- ── 2. api_keys.key_hash UNIQUE ────────────────────────────────────────────
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_indexes WHERE indexname = 'uq_api_keys_key_hash'
    ) THEN
        -- Two rows with the same key_hash are a double-provisioned key: the
        -- same secret represented twice. Keep the ORIGINAL (earliest
        -- created_at, id tiebreak) — it is the credential callers have been
        -- using since first issue.
        DELETE FROM api_keys a
        USING api_keys b
        WHERE a.key_hash = b.key_hash
          AND (a.created_at, a.id) > (b.created_at, b.id);
        CREATE UNIQUE INDEX uq_api_keys_key_hash ON api_keys (key_hash);
    END IF;
END $$;

-- ── 3. users case-insensitive email uniqueness ─────────────────────────────
DO $$
DECLARE
    dup RECORD;
    suffix INT;
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_indexes WHERE indexname = 'uq_users_email_lower'
    ) THEN
        -- Case-variant duplicate accounts (Alice@x.com vs alice@x.com) race
        -- the LOWER(email) login fetch_one. Rename the LATER registration
        -- (created_at, id) conservatively — never merge, never delete: the
        -- operator can review and merge deliberately. The renamed address is
        -- not deliverable, so it cannot be used to reset the original.
        FOR dup IN
            SELECT id, email,
                   ROW_NUMBER() OVER (
                       PARTITION BY LOWER(email)
                       ORDER BY created_at NULLS LAST, id
                   ) AS dup_rank
            FROM users
        LOOP
            IF dup.dup_rank > 1 THEN
                suffix := dup.dup_rank::int;
                UPDATE users
                SET email = left(dup.email, 200) || '.case-dup-' || suffix::text
                WHERE id = dup.id;
                RAISE NOTICE '116: renamed case-duplicate account % (rank %)', dup.id, suffix;
            END IF;
        END LOOP;
        IF EXISTS (
            SELECT 1 FROM users GROUP BY LOWER(email) HAVING count(*) > 1
        ) THEN
            RAISE EXCEPTION '116: case-duplicate emails survive rename — resolve manually';
        END IF;
        CREATE UNIQUE INDEX uq_users_email_lower ON users (LOWER(email));
    END IF;
END $$;

-- ── 4. billing_addresses UNIQUE(tenant_id) ─────────────────────────────────
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_indexes WHERE indexname = 'uq_billing_addresses_tenant'
    ) THEN
        -- Keep the most recently updated address (greatest updated_at, then
        -- created_at, then id) — the row the billing UI last wrote is the
        -- tenant's current address.
        DELETE FROM billing_addresses a
        USING billing_addresses b
        WHERE a.tenant_id = b.tenant_id
          AND (a.updated_at, a.created_at, a.id) < (b.updated_at, b.created_at, b.id);
        CREATE UNIQUE INDEX uq_billing_addresses_tenant ON billing_addresses (tenant_id);
    END IF;
END $$;

-- ── 5. dunning_config.tenant_id UUID → VARCHAR(26) ─────────────────────────
DO $$
BEGIN
    IF to_regclass('public.dunning_config') IS NOT NULL THEN
        IF EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_schema = 'public' AND table_name = 'dunning_config'
              AND column_name = 'tenant_id' AND udt_name = 'uuid'
        ) THEN
            -- tenant_id is the PRIMARY KEY of dunning_config. Rows whose id
            -- is not a real tenant id are unreachable dead config from the
            -- UUID era (the billing lookup binds 26-char strings and never
            -- matched); drop them, then widen the type.
            DELETE FROM dunning_config d
            WHERE d.tenant_id::text NOT IN (SELECT id FROM tenants);
            ALTER TABLE dunning_config
                ALTER COLUMN tenant_id TYPE VARCHAR(26) USING tenant_id::text;
            RAISE NOTICE '116: dunning_config.tenant_id converted UUID -> VARCHAR(26)';
        END IF;
    END IF;
END $$;

-- ── 6. Financial FKs CASCADE → RESTRICT ────────────────────────────────────
-- Every FK from a financial/ledger table to tenants(id) that still says
-- CASCADE is flipped to RESTRICT in place. ALTER CONSTRAINT keeps the FK's
-- identity; NOT VALID state is preserved.
--
-- On chains where the FK was conditionally skipped and never retried
-- (022/064 guard races — the fresh chain simply lacks these FKs), the
-- missing FK is ADDED here directly as RESTRICT after an orphan check.
DO $$
DECLARE
    fk RECORD;
    fin_table TEXT;
    orphan_count BIGINT;
    financial_tables CONSTANT TEXT[] := ARRAY[
        'enterprise_contracts', 'contract_signatures', 'contract_amendments',
        'purchase_orders', 'dunning_states', 'dunning_records',
        'dunning_history', 'sla_metrics', 'sla_credits', 'wallets',
        'wallet_transactions', 'wallet_reservations', 'tenant_costs',
        'cost_alerts'
    ];
BEGIN
    FOR fk IN
        SELECT con.conname, rel.relname AS table_name, con.convalidated
        FROM pg_constraint con
        JOIN pg_class rel ON rel.oid = con.conrelid
        JOIN pg_namespace nsp ON nsp.oid = rel.relnamespace
        JOIN pg_class tgt ON tgt.oid = con.confrelid
        WHERE con.contype = 'f'
          AND con.confdeltype = 'c'   -- CASCADE
          AND nsp.nspname = 'public'
          AND tgt.relname = 'tenants'
          AND rel.relname = ANY (financial_tables)
    LOOP
        -- NOTE: PostgreSQL has no `ALTER CONSTRAINT ... ON DELETE ...`
        -- (ALTER CONSTRAINT only takes DEFERRABLE/NOT VALID — the parser
        -- fails with "syntax error at or near ON"). Flip the action by
        -- replacing the constraint: drop and re-add it as RESTRICT under
        -- the SAME name, preserving its validation state. These FKs are all
        -- single-column (tenant_id -> tenants.id); the loop's WHERE clause
        -- selected exactly the tenants-targeting FKs of these tables.
        EXECUTE format(
            'ALTER TABLE %I DROP CONSTRAINT %I',
            fk.table_name, fk.conname
        );
        EXECUTE format(
            'ALTER TABLE %I ADD CONSTRAINT %I FOREIGN KEY (tenant_id) '
                'REFERENCES tenants(id) ON DELETE RESTRICT%s',
            fk.table_name, fk.conname,
            CASE WHEN fk.convalidated THEN '' ELSE ' NOT VALID' END
        );
        RAISE NOTICE '116: % on % now ON DELETE RESTRICT', fk.conname, fk.table_name;
    END LOOP;

    -- Add FKs the chain never managed to create (fresh-chain reality).
    FOREACH fin_table IN ARRAY financial_tables LOOP
        CONTINUE WHEN to_regclass(format('public.%I', fin_table)) IS NULL;
        CONTINUE WHEN NOT EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_schema = 'public' AND table_name = fin_table
              AND column_name = 'tenant_id'
        );
        CONTINUE WHEN EXISTS (   -- already covered by the loop above or a sibling
            SELECT 1
            FROM pg_constraint con
            JOIN pg_class rel ON rel.oid = con.conrelid
            JOIN pg_class tgt ON tgt.oid = con.confrelid
            WHERE con.contype = 'f'
              AND rel.relname = fin_table
              AND tgt.relname = 'tenants'
        );
        -- orphan check via dynamic SQL (composite row cast is not portable)
        EXECUTE format(
            'SELECT count(*) FROM %I f WHERE NOT EXISTS (SELECT 1 FROM tenants t WHERE t.id::text = f.tenant_id::text)',
            fin_table
        ) INTO orphan_count;
        IF orphan_count > 0 THEN
            RAISE EXCEPTION '116: % rows in % reference missing tenants — resolve manually before adding the RESTRICT FK', orphan_count, fin_table;
        END IF;
        EXECUTE format(
            'ALTER TABLE %I ADD CONSTRAINT %I FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT',
            fin_table, format('fk_%s_tenant', fin_table)
        );
        RAISE NOTICE '116: added missing FK % -> tenants(id) ON DELETE RESTRICT', fin_table;
    END LOOP;
END $$;

