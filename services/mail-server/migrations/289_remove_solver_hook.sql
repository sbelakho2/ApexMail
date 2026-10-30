-- Migration 289: remove the CAPTCHA-solving hook; make host exclusion permanent.
-- =============================================================================
-- Work package S10 (audit SAI-1): the owner's sourcing decision is absolute —
-- no CAPTCHA solving, outsourcing or evasion, no rotating/residential proxy
-- after a block, no stealth browser, no page behind a login, and no setting
-- may re-enable any of it.
--
-- Migration 258 (scrape challenge readiness) landed the storage for an
-- OPT-IN solver hook: `sales_scrape_host_health.solver_enabled*` and the
-- `sales_scrape_solver_audit` trail. The hook is deleted in this wave
-- (client, settings, routes and audit path all removed from the crate), so
-- the storage goes with it. A database that still carries these columns or
-- the table is a half-applied deployment; the proof block at the end refuses
-- to complete while any of them survives.
--
-- The replacement is a permanent, one-way host exclusion, recorded on the
-- same `sales_scrape_host_health` row:
--
--   * `consecutive_429` counts 429 responses in a row (reset by any other
--     outcome); the third one excludes the host;
--   * `excluded_at` / `exclusion_reason` are the exclusion state. The reasons
--     are the closed vocabulary owned by the fetch layer: `captcha`,
--     `robots_disallow`, `http_401`, `http_403`, `http_429_repeated`.
--
-- `sales_scrape_host_exclusion_audit` is the written record: every automatic
-- exclusion (`actor = 'system'`) and every owner lift, which is the ONLY way
-- out of the excluded state and requires a non-empty owner identity plus a
-- written reason (stored verbatim).
--
-- `sales_discovery_candidates.source_notice_required` carries the GDPR
-- Article 14 flag: a named person's address is stored only when the resolved
-- jurisdiction has an authoritative `allowed` policy row, and the first email
-- to that person must identify the source document.
--
-- Idempotent by construction: every DDL statement is guarded, and the proof
-- block asserts the end state.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- 1. Permanent host exclusion state (replaces the opt-in solver columns).
-- ---------------------------------------------------------------------------
ALTER TABLE sales_scrape_host_health
    ADD COLUMN IF NOT EXISTS consecutive_429 INTEGER NOT NULL DEFAULT 0;

ALTER TABLE sales_scrape_host_health
    ADD COLUMN IF NOT EXISTS excluded_at TIMESTAMPTZ;

ALTER TABLE sales_scrape_host_health
    ADD COLUMN IF NOT EXISTS exclusion_reason TEXT;

-- ---------------------------------------------------------------------------
-- 2. The exclusion audit log: automatic exclusions and owner lifts.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sales_scrape_host_exclusion_audit (
    id          UUID        PRIMARY KEY,
    tenant_id   TEXT        NOT NULL,
    host        TEXT        NOT NULL,
    action      TEXT        NOT NULL,
    reason      TEXT        NOT NULL,
    detail      TEXT,
    actor       TEXT        NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sales_scrape_host_exclusion_audit
    ON sales_scrape_host_exclusion_audit (tenant_id, host, created_at DESC);

-- ---------------------------------------------------------------------------
-- 3. Drop the solver hook's storage (the hook no longer exists in code).
-- ---------------------------------------------------------------------------
ALTER TABLE sales_scrape_host_health
    DROP COLUMN IF EXISTS solver_enabled;
ALTER TABLE sales_scrape_host_health
    DROP COLUMN IF EXISTS solver_enabled_at;
ALTER TABLE sales_scrape_host_health
    DROP COLUMN IF EXISTS solver_enabled_by;

DROP TABLE IF EXISTS sales_scrape_solver_audit;

-- ---------------------------------------------------------------------------
-- 4. The Article 14 source-notice flag for named persons.
-- ---------------------------------------------------------------------------
ALTER TABLE sales_discovery_candidates
    ADD COLUMN IF NOT EXISTS source_notice_required BOOLEAN NOT NULL DEFAULT FALSE;

-- ---------------------------------------------------------------------------
-- 5. Proof block: the exclusion state exists and the solver storage is gone.
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    missing_columns int;
    leftover_columns int;
    leftover_table int;
    name_missing int;
BEGIN
    SELECT count(*) INTO missing_columns
    FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name = 'sales_scrape_host_health'
      AND column_name IN ('consecutive_429', 'excluded_at', 'exclusion_reason');
    IF missing_columns <> 3 THEN
        RAISE EXCEPTION
            'migration 289: the permanent exclusion columns are incomplete (% of 3 present)',
            missing_columns;
    END IF;

    SELECT count(*) INTO leftover_columns
    FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name = 'sales_scrape_host_health'
      AND column_name LIKE 'solver_%';
    IF leftover_columns <> 0 THEN
        RAISE EXCEPTION
            'migration 289: % solver opt-in column(s) survived the removal',
            leftover_columns;
    END IF;

    SELECT count(*) INTO leftover_table
    FROM pg_catalog.pg_class c
    JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public'
      AND c.relname = 'sales_scrape_solver_audit';
    IF leftover_table <> 0 THEN
        RAISE EXCEPTION
            'migration 289: the sales_scrape_solver_audit table survived the removal';
    END IF;

    SELECT count(*) INTO name_missing
    FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name = 'sales_discovery_candidates'
      AND column_name = 'source_notice_required';
    IF name_missing <> 1 THEN
        RAISE EXCEPTION
            'migration 289: sales_discovery_candidates.source_notice_required is missing';
    END IF;
END $$;
