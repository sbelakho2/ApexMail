-- Migration 225: bank statement ingestion — the bank feed's first writer.
--
-- Migration 220 created `bank_statement_lines` and left it with no production
-- writer: there was no bank feed and no statement importer, so the ledger
-- sweep `accounting_core::sweeps::sweep_unposted_bank_statement_lines` could
-- only ever fire for rows inserted by hand. This migration closes that gap on
-- the storage side; the ingest path
-- (`accounting_core::bank_ingest::ingest_bank_statement`, exposed by the
-- compliance service at `POST /accounting/bank-statements/import`) is its
-- writer, and the compliance cron hosts the sweep.
--
-- # Identity (the idempotency contract, enforced by the database)
--
-- Statement/import identity — one bank statement file per account:
--
--     UNIQUE (bank_account_id, file_digest)  on bank_statement_imports
--
-- `file_digest` is the sha256 hex of the exact CSV bytes received, computed by
-- the server (never supplied by the caller). Importing the same statement
-- twice therefore cannot create a second import row; the second request is an
-- idempotent no-op that reports the existing import. Application logic cannot
-- bypass this: the constraint is the identity.
--
-- Line identity — a bank statement line is identified by the bank's own id:
--
--     UNIQUE (bank_account_id, external_id)  on bank_statement_lines
--     (created by migration 220; unchanged here)
--
-- Even a re-issued file with different bytes but repeated `external_id`s
-- cannot duplicate a line. The ingest path detects that case first and
-- reports the conflicting rows instead of attempting the insert.
--
-- # What this migration adds
--
--   * bank_statement_imports — the import record: which bank account, which
--     statement period, the file digest, the line count, the signed totals,
--     who imported it, and the retention class.
--   * bank_statement_lines.import_id — which import carried each line
--     (nullable: lines written by any future feed or by psql remain valid;
--     the sweep posts every unreconciled non-zero line regardless).
--   * The migration-220 retention delete guard, extended to the new table.
--
-- No runtime DDL: this file is the only writer of this schema, and the
-- compliance service boots with a DML-only role.

-- ===========================================================================
-- 1. Import records
-- ===========================================================================

CREATE TABLE IF NOT EXISTS bank_statement_imports (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    bank_account_id    UUID NOT NULL REFERENCES bank_accounts(id) ON DELETE RESTRICT,
    -- The statement period the operator declares; every line's booking date
    -- must fall inside it (enforced by the ingest path, which refuses the
    -- whole file with per-row errors otherwise).
    period_start       DATE NOT NULL,
    period_end         DATE NOT NULL,
    -- sha256 hex of the received CSV bytes — the statement identity together
    -- with bank_account_id (UNIQUE below).
    file_digest        TEXT NOT NULL CHECK (file_digest ~ '^[0-9a-f]{64}$'),
    filename           TEXT,
    source_kind        TEXT NOT NULL DEFAULT 'csv_upload'
        CHECK (source_kind IN ('csv_upload', 'feed')),
    line_count         INTEGER NOT NULL CHECK (line_count >= 0),
    credit_total_cents BIGINT NOT NULL DEFAULT 0 CHECK (credit_total_cents >= 0),
    debit_total_cents  BIGINT NOT NULL DEFAULT 0 CHECK (debit_total_cents >= 0),
    imported_by        TEXT NOT NULL,
    retention_class    TEXT NOT NULL DEFAULT 'legal_7y'
        REFERENCES accounting_retention_classes(code),
    imported_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (period_end >= period_start),
    -- Statement identity: the same bytes for the same account can only be
    -- imported once. The ingest path resolves the conflict to an idempotent
    -- no-op; it may not create a duplicate import.
    UNIQUE (bank_account_id, file_digest)
);

CREATE INDEX IF NOT EXISTS idx_bank_statement_imports_account_period
    ON bank_statement_imports (bank_account_id, period_start, period_end);

-- ===========================================================================
-- 2. Link lines to the import that carried them
-- ===========================================================================

ALTER TABLE bank_statement_lines
    ADD COLUMN IF NOT EXISTS import_id UUID
        REFERENCES bank_statement_imports(id) ON DELETE RESTRICT;

CREATE INDEX IF NOT EXISTS idx_bank_statement_lines_import
    ON bank_statement_lines (import_id);

-- ===========================================================================
-- 3. Retention guard for the new table (same function as migration 220)
-- ===========================================================================

DO $$
BEGIN
    EXECUTE 'DROP TRIGGER IF EXISTS trg_bank_statement_imports_retention ON bank_statement_imports';
    EXECUTE 'CREATE TRIGGER trg_bank_statement_imports_retention BEFORE DELETE ON bank_statement_imports '
            'FOR EACH ROW EXECUTE FUNCTION accounting_retention_delete_guard()';
END;
$$;
