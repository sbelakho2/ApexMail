-- Migration 168: Compliance contact persons
--
-- =============================================================================
-- F63: canonical schema for the compliance crate's Estonian OÜ contact
-- person registry. estonia_ou.rs register_contact_person upserts
-- contact_persons ON CONFLICT (email) and reads the row back via RETURNING
-- (decoded through ContactPersonRow) — but no migration ever created the
-- table, so registering the statutory contact person failed at runtime
-- while the corresponding compliance_deadlines rows (079) kept piling up
-- as 'pending'.
--
-- Shape derived from the exact INSERT/RETURNING column list: id UUID
-- (bound Uuid), full_name NOT NULL, personal_code / phone NULLable
-- (Option<&str>), email NOT NULL UNIQUE (the upsert conflict target),
-- last_verified_at always written as NOW(), registry_code written as the
-- literal company registry code ('16588745' — BEL CONSULTING OÜ, see 079),
-- created_at / updated_at NOT NULL.
-- =============================================================================

CREATE TABLE IF NOT EXISTS contact_persons (
    id                UUID        PRIMARY KEY,
    full_name         TEXT        NOT NULL,
    personal_code     TEXT,
    email             TEXT        NOT NULL UNIQUE,
    phone             TEXT,
    last_verified_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    registry_code     VARCHAR(20) NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_contact_persons_registry_code
    ON contact_persons (registry_code);

-- ── Reconcile compliance_deadlines.submission_id with the code ──────────────
-- record_contact_person_verification stores the contact person's id in
-- compliance_deadlines.submission_id for 'contact_person_verification'
-- deadlines. 079 declared that column as UUID REFERENCES
-- compliance_submissions(id), which rejects any value that is not a
-- submission id. Schema follows code here: the column intentionally holds
-- either a compliance_submissions.id or a contact_persons.id, so the
-- cross-table FK is replaced by an unenforced reference (guarded, so a
-- database where the constraint is already absent is a no-op).
DO $$
DECLARE
    fk_name TEXT;
BEGIN
    SELECT tc.constraint_name INTO fk_name
    FROM information_schema.table_constraints tc
    JOIN information_schema.key_column_usage kcu
      ON kcu.constraint_name = tc.constraint_name
     AND kcu.table_schema = tc.table_schema
    JOIN information_schema.constraint_column_usage ccu
      ON ccu.constraint_name = tc.constraint_name
     AND ccu.table_schema = tc.table_schema
    WHERE tc.constraint_type = 'FOREIGN KEY'
      AND tc.table_name = 'compliance_deadlines'
      AND kcu.column_name = 'submission_id'
      AND ccu.table_name = 'compliance_submissions'
    LIMIT 1;

    IF fk_name IS NOT NULL THEN
        EXECUTE format('ALTER TABLE compliance_deadlines DROP CONSTRAINT %I', fk_name);
    END IF;
END;
$$;
