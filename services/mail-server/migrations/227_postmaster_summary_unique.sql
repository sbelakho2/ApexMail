-- Migration 227: one current reputation summary per (scope, identity, provider).
--
-- History: migration 040 created postmaster_reputation_summary with
--   UNIQUE (scope, identity, provider)
-- and the postmaster aggregator upserted on exactly those columns. Migration
-- 061 (Section 13, M-13) DROPPED that constraint and replaced it with
--   UNIQUE (scope, identity, provider, computed_at)
-- to retain one row per computation, which left the aggregator with no index
-- matching `ON CONFLICT (scope, identity, provider)` — every recompute died
-- with "there is no unique or exclusion constraint matching the ON CONFLICT
-- specification". The aggregator was subsequently worked around in Rust
-- (SELECT newest row, UPDATE it, INSERT when absent), which is correct only
-- while no duplicates exist. This migration restores the uniqueness the
-- summary's consumers depend on: one CURRENT summary per key.
--
-- Schema shape this index relies on (verified in the guards below):
--   * postmaster_reputation_summary is a plain table, NOT partitioned
--     (040 created it as an ordinary table; 050 never partitioned it). A
--     unique index on the parent of a partitioned table cannot be created
--     without including the partition key, so a partitioned table is refused
--     explicitly rather than half-fixed.
--   * scope, identity and provider are all NOT NULL (040). A plain unique
--     btree index therefore covers every row; NULL keys (which a unique
--     index treats as distinct) cannot occur. If a key column ever becomes
--     nullable, this migration refuses to run: the index would no longer
--     deduplicate NULL keys, and PostgreSQL 15+'s NULLS NOT DISTINCT (not
--     available on this project's PostgreSQL 14 floor) would be required.
--
-- ORDER OF WORK: the duplicate pre-check runs BEFORE `CREATE UNIQUE INDEX`,
-- and RAISEs with the offending keys. `CREATE UNIQUE INDEX` on a table with
-- duplicates would fail with a bare "could not create unique index", naming
-- no rows; operators need to know exactly which (scope, identity, provider)
-- groups to merge before the deploy gate can proceed. The migration is
-- idempotent: if the index already exists (any equivalent 3-column unique
-- index) it is a no-op.
--
-- The older UNIQUE (scope, identity, provider, computed_at) constraint is
-- deliberately left in place: once this index exists it is logically
-- subsumed, and dropping it is a separate, destructive change operators can
-- make deliberately later. It cannot accept a second row for the same key
-- any more either.

DO $$
DECLARE
    v_dupes TEXT;
BEGIN
    IF to_regclass('public.postmaster_reputation_summary') IS NULL THEN
        RAISE NOTICE '227: postmaster_reputation_summary does not exist; nothing to do';
        RETURN;
    END IF;

    -- Partitioned parent? A bounded unique index is impossible there without
    -- the partition key; refuse instead of creating a partial guarantee.
    IF EXISTS (
        SELECT 1 FROM pg_class
        WHERE oid = 'public.postmaster_reputation_summary'::regclass
          AND relkind = 'p'
    ) THEN
        RAISE EXCEPTION
            '227: postmaster_reputation_summary is partitioned; a unique index on (scope, identity, provider) must include the partition key. The aggregator''s ON CONFLICT target cannot be satisfied on this shape.';
    END IF;

    -- Nullable key column? A plain unique index lets NULLs duplicate, so the
    -- invariant would be silently weaker than the aggregator assumes.
    IF EXISTS (
        SELECT 1 FROM pg_attribute
        WHERE attrelid = 'public.postmaster_reputation_summary'::regclass
          AND attname IN ('scope', 'identity', 'provider')
          AND attnum > 0
          AND NOT attisdropped
          AND NOT attnotnull
    ) THEN
        RAISE EXCEPTION
            '227: a postmaster_reputation_summary key column is nullable; a plain unique index does not deduplicate NULL keys. Make scope/identity/provider NOT NULL, or use a NULLS NOT DISTINCT index on PostgreSQL 15+, before applying this migration.';
    END IF;

    -- Already present under any name/column order? No-op.
    IF EXISTS (
        SELECT 1
        FROM pg_index i
        WHERE i.indrelid = 'public.postmaster_reputation_summary'::regclass
          AND i.indisunique
          AND i.indnatts = 3
          AND (
                SELECT array_agg(a.attname::text ORDER BY a.attname::text)
                FROM unnest(i.indkey) AS k(attnum)
                JOIN pg_attribute a
                  ON a.attrelid = i.indrelid AND a.attnum = k.attnum
              ) = ARRAY['identity', 'provider', 'scope']
    ) THEN
        RAISE NOTICE '227: a unique index on (scope, identity, provider) already exists; nothing to do';
        RETURN;
    END IF;

    -- Duplicate pre-check: report EVERY offending key group so the operator
    -- can merge them in one pass.
    SELECT string_agg(
               format(
                   '  scope=%L identity=%L provider=%L rows=%s',
                   scope, identity, provider, row_count
               ),
               E'\n'
               ORDER BY scope, identity, provider
           )
      INTO v_dupes
      FROM (
          SELECT scope, identity, provider, count(*) AS row_count
          FROM postmaster_reputation_summary
          GROUP BY scope, identity, provider
          HAVING count(*) > 1
      ) dupes;

    IF v_dupes IS NOT NULL THEN
        RAISE EXCEPTION
            E'227: postmaster_reputation_summary contains duplicate (scope, identity, provider) rows; the unique index cannot be created until each group is merged to its newest row.\nOffending keys:\n%',
            v_dupes
            USING HINT = 'For each group keep the row with the greatest computed_at (tie-break id DESC), delete the rest, then re-run migration 227.';
    END IF;
END $$;

CREATE UNIQUE INDEX IF NOT EXISTS postmaster_reputation_summary_scope_identity_provider_uidx
    ON postmaster_reputation_summary (scope, identity, provider);

COMMENT ON INDEX postmaster_reputation_summary_scope_identity_provider_uidx IS
    'One current reputation summary per (scope, identity, provider): the exact conflict target the postmaster aggregator recomputes against. Restored after migration 061 dropped the original UNIQUE constraint.';
