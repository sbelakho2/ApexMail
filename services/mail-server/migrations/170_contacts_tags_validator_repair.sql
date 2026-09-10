-- 170: contacts.tags validator repair + conservative data reconciliation
-- (audit F70).
--
-- DEFECT BEING REPAIRED (migration 150, already APPLIED in production — its
-- checksum must not change, so the fix lands here as a new numbered repair):
--
--   1. apexmail_contact_tags_valid iterated jsonb_array_elements_text,
--      which stringifies numbers, booleans and objects BEFORE the bounds
--      check — the database therefore ACCEPTED nonstring JSON tag elements
--      like [42, true, {"a":1}].
--   2. 150's normalisation UPDATE invoked jsonb_array_elements(tags)
--      unguarded, so a populated upgrade over legacy SCALAR values aborted
--      with SQLSTATE 22023 (argument of jsonb_array_elements must be an
--      array).
--
-- RECONCILIATION POLICY for already-stored invalid values (canonical rule,
-- deliberately conservative — nothing is invented, only ever mapped to a
-- plainly-valid string or dropped):
--
--   * array elements that are JSON strings  -> their TRIMMED form, when the
--     trimmed value is 1..64 characters; otherwise dropped;
--   * array elements that are numbers or booleans (nonstring SCALARS)
--     -> their trimmed string form ("42", "true") when that string is
--     1..64 characters; otherwise dropped;
--   * object / JSON-null elements           -> dropped (a string form of an
--     object is not a tag the user typed);
--   * values are DEDUPLICATED on their trimmed form BEFORE the 50-element
--     count cap is applied (so ["a","a",...51 more] keeps 50 distinct tags,
--     not 50 slots with a duplicate);
--   * NULL / non-array values               -> '[]' (the canonical empty
--     array, via the CASE that feeds an empty array to the set-returning
--     function for nonarrays).
--
-- PENDING-UPGRADE PREFLIGHT (databases that have NOT yet applied 150):
-- 150's own normalisation UPDATE still aborts 22023 on scalar legacy values.
-- Operators upgrading a database whose contacts.tags predates 150 and may
-- carry scalar/object values MUST run this migration's reconciliation
-- statement (the UPDATE below) as a preflight BEFORE the 150 step of the
-- upgrade, or reconcile by hand:
--
--     UPDATE contacts SET tags = '[]'::jsonb
--     WHERE tags IS NOT NULL AND jsonb_typeof(tags) IS DISTINCT FROM 'array';
--
-- The migration-checksum policy is unchanged: applied migrations are never
-- rewritten; repairs ship as new numbered migrations.

-- 1. Corrected validator: element TYPES are checked with jsonb_typeof over
--    jsonb_array_elements (no stringification), and the actual strings are
--    validated AFTER TRIMMING — nonempty, 1..64 characters, unique across
--    their trimmed forms, at most 50 elements.
CREATE OR REPLACE FUNCTION apexmail_contact_tags_valid(candidate JSONB)
RETURNS BOOLEAN
LANGUAGE SQL
IMMUTABLE
AS $$
    SELECT jsonb_typeof(candidate) = 'array'
       AND jsonb_array_length(candidate) <= 50
       AND COALESCE((
           -- bool_and ignores NULLs, so null-ness is tested explicitly via
           -- the type check: a JSON null element violates the shape.
           -- count(DISTINCT trimmed) = count(*) enforces uniqueness of the
           -- trimmed forms.
           SELECT bool_and(jsonb_typeof(elem) = 'string'
                           AND char_length(btrim(elem #>> '{}')) BETWEEN 1 AND 64)
              AND count(DISTINCT btrim(elem #>> '{}')) = count(*)
           FROM jsonb_array_elements(candidate) AS elem
       ), TRUE)
$$;

-- 2. Reconcile every stored value the corrected validator rejects, per the
--    policy in the header. The CASE feeds an empty array to
--    jsonb_array_elements for nonarray values (no 22023 abort); DISTINCT
--    dedupes BEFORE the LIMIT 50 count cap.
UPDATE contacts
SET tags = COALESCE((
    SELECT jsonb_agg(tag ORDER BY tag)
    FROM (
        SELECT DISTINCT tag
        FROM (
            SELECT CASE
                       WHEN jsonb_typeof(elem) IN ('string', 'number', 'boolean')
                           THEN btrim(elem #>> '{}')
                       ELSE NULL
                   END AS tag
            FROM jsonb_array_elements(
                     CASE WHEN jsonb_typeof(tags) = 'array'
                          THEN tags
                          ELSE '[]'::jsonb
                     END
                 ) AS elem
        ) AS candidate
        WHERE tag IS NOT NULL
          AND char_length(tag) BETWEEN 1 AND 64
        LIMIT 50
    ) AS bounded
), '[]'::jsonb)
WHERE tags IS NULL
   OR jsonb_typeof(tags) <> 'array'
   OR NOT apexmail_contact_tags_valid(tags);

-- 3. Re-establish the CHECK against the corrected function. The constraint
--    text references the function by name, but re-adding it forces a fresh
--    validation pass over every row AFTER the reconciliation above, proving
--    no invalid value survived.
ALTER TABLE contacts DROP CONSTRAINT IF EXISTS contacts_tags_shape_check;
ALTER TABLE contacts
    ADD CONSTRAINT contacts_tags_shape_check
    CHECK (apexmail_contact_tags_valid(tags));

COMMENT ON CONSTRAINT contacts_tags_shape_check ON contacts IS
    'Tags: JSON array of at most 50 unique trimmed strings, each 1..64 chars after trimming; nonstring elements rejected (migration 170 repair of 150).';
