-- Migration 150: canonical contacts.tags column (audit F07).
--
-- contacts has two creation shapes in the chain and neither gives bulk
-- tagging a usable column:
--   - migration 068 creates the table WITHOUT tags (and 075's
--     CREATE IF NOT EXISTS is then a no-op), so `UPDATE contacts SET tags`
--     fails with "column does not exist";
--   - where the 075 shape won, tags is a nullable JSONB with no shape
--     constraint, so nothing forces the array-of-bounded-strings
--     representation the API promises.
--
-- This migration establishes ONE representation everywhere:
--   tags JSONB NOT NULL DEFAULT '[]'::jsonb
--   - a JSON array,
--   - at most 50 elements,
--   - every element a string of 1..64 characters.
--
-- Pre-existing values that already conform are preserved; NULL, non-array,
-- or non-conforming values are normalised (string elements within bounds
-- are kept — deduplicated and capped at 50 — everything else collapses to
-- '[]') so the NOT NULL + CHECK constraints cannot fail on old rows.

-- Shape validator used by the CHECK constraint below. IMMUTABLE so Postgres
-- may inline it; kept permanently because the constraint evaluates it on
-- every future INSERT/UPDATE of contacts.
CREATE OR REPLACE FUNCTION apexmail_contact_tags_valid(candidate JSONB)
RETURNS BOOLEAN
LANGUAGE SQL
IMMUTABLE
AS $$
    SELECT jsonb_typeof(candidate) = 'array'
       AND jsonb_array_length(candidate) <= 50
       AND COALESCE((
           -- bool_and ignores NULLs, so null-ness is tested explicitly:
           -- a JSON null element must violate the bounded-strings shape.
           SELECT bool_and(tag IS NOT NULL AND char_length(tag) BETWEEN 1 AND 64)
           FROM jsonb_array_elements_text(candidate) AS tag
       ), TRUE)
$$;

-- Add the column where the 068 shape left it missing entirely.
ALTER TABLE contacts ADD COLUMN IF NOT EXISTS tags JSONB;

-- Normalise every value the CHECK would reject: NULL / non-array collapse
-- to '[]'; arrays keep their bounded string elements, deduplicated, capped.
UPDATE contacts
SET tags = COALESCE((
    SELECT jsonb_agg(DISTINCT elem ORDER BY elem)
    FROM (
        SELECT elem
        FROM jsonb_array_elements(tags) AS elem
        WHERE jsonb_typeof(elem) = 'string'
          AND char_length(elem #>> '{}') BETWEEN 1 AND 64
        LIMIT 50
    ) AS bounded
), '[]'::jsonb)
WHERE tags IS NULL
   OR jsonb_typeof(tags) <> 'array'
   OR NOT apexmail_contact_tags_valid(tags);

ALTER TABLE contacts ALTER COLUMN tags SET DEFAULT '[]'::jsonb;
ALTER TABLE contacts ALTER COLUMN tags SET NOT NULL;

ALTER TABLE contacts DROP CONSTRAINT IF EXISTS contacts_tags_shape_check;
ALTER TABLE contacts
    ADD CONSTRAINT contacts_tags_shape_check
    CHECK (apexmail_contact_tags_valid(tags));

COMMENT ON COLUMN contacts.tags IS
    'Contact tags: JSON array of at most 50 unique strings, each 1..64 chars (migration 150).';
