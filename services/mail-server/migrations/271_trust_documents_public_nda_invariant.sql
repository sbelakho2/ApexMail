-- Migration 271: a public trust document can never require an NDA.
--
-- External audit 2026-10-26 (finding 11): the schema allowed
-- public = TRUE and requires_nda = TRUE independently, so a future writer
-- could publish an NDA-gated document to the anonymous public list (and
-- the public query filtered on public alone). Two guards:
--   1. the table now refuses the contradictory state outright;
--   2. existing contradictory rows (none expected) are made non-public
--      first, conservatively, before the constraint is added.
UPDATE trust_portal_documents
   SET public = FALSE
 WHERE public = TRUE AND requires_nda = TRUE;

DO $$
BEGIN
    ALTER TABLE trust_portal_documents
        DROP CONSTRAINT IF EXISTS chk_trust_documents_public_not_nda;
    ALTER TABLE trust_portal_documents
        ADD CONSTRAINT chk_trust_documents_public_not_nda
        CHECK (NOT (public AND requires_nda));
EXCEPTION
    WHEN check_violation THEN
        RAISE EXCEPTION 'trust_portal_documents contains rows public AND requires_nda after the conservative update; reconcile manually before applying 271';
END
$$;
