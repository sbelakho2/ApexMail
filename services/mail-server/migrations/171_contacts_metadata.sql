-- 171: canonical contacts.metadata column (audit F07).
--
-- DEFECT: every contact writer/reader (api-server contacts CRUD, the CSV
-- import, apexmail-db ContactsRepo) selects or writes contacts.metadata,
-- but NO canonical migration ever added it — the 068 creation shape has no
-- metadata column and 075's CREATE TABLE IF NOT EXISTS is a no-op on the
-- canonical chain — so each of those statements failed with 42703
-- (undefined column) on any database a deploy actually produces.
--
-- CONTRACT: metadata is JSONB and is either
--   * a JSON OBJECT (arbitrary keys, tenant-defined), or
--   * NULL, meaning "no metadata" (the default; absence is NULL, not '{}').
-- Scalars, arrays and JSON-null-typed values are rejected by the CHECK.
--
-- DELIBERATE LEGACY BACKFILL: on databases whose contacts table pre-dates
-- this migration with a metadata column from a non-canonical lineage
-- (e.g. the 075 shape, where metadata JSONB DEFAULT '{}' existed with no
-- shape constraint), OBJECT values are preserved verbatim and every
-- nonobject value (scalar, array) is reconciled to NULL — silently coercing
-- a legacy scalar into a synthetic {"value": ...} object would invent
-- structure the API contract cannot describe, so it is dropped instead.

ALTER TABLE contacts ADD COLUMN IF NOT EXISTS metadata JSONB;

-- Backfill/reconciliation (no-op on the canonical 068 shape, where the
-- column was just added and is NULL everywhere).
UPDATE contacts
SET metadata = NULL
WHERE metadata IS NOT NULL
  AND jsonb_typeof(metadata) <> 'object';

ALTER TABLE contacts DROP CONSTRAINT IF EXISTS contacts_metadata_shape_check;
ALTER TABLE contacts
    ADD CONSTRAINT contacts_metadata_shape_check
    CHECK (metadata IS NULL OR jsonb_typeof(metadata) = 'object');

COMMENT ON COLUMN contacts.metadata IS
    'Contact metadata: a JSON object, or NULL when absent (never a scalar/array; migration 171).';
