-- Migration 226: filing-submission packages become validated artefacts.
--
-- The VD/OSS transport already persisted the exact package handed to the
-- machine endpoint or the human operator. What was missing is that the
-- PACKAGE ITSELF is checked and anchored:
--
--   * every legally required field must be present before an operator or the
--     machine transport can submit (filing_package.rs validation report);
--   * fields no repository model can supply are recorded as named gaps and
--     make the package non-submittable instead of being skipped;
--   * when a TSA is configured, the RFC 3161 evidence for the package digest
--     is attached to the submission record; when none is configured, the
--     record says so plainly ("no trusted timestamp obtained (no TSA
--     configured)") and never claims to be timestamped.
--
-- The existing `payload` column is the exact package that is POSTed and
-- receipt-checked by hash; it must not be polluted with transport evidence.
-- The validation report and the timestamp record therefore get their own
-- JSONB columns, which round-trip through the existing sqlx/JSONB storage.
--
-- No defaults are invented: pre-existing rows keep NULL in the new columns
-- (they predate package validation) and the transport treats them as not
-- validated rather than silently upgrading them.

ALTER TABLE filing_submission_packages
    ADD COLUMN IF NOT EXISTS form TEXT,
    ADD COLUMN IF NOT EXISTS validation_report JSONB,
    ADD COLUMN IF NOT EXISTS validation_outcome TEXT,
    ADD COLUMN IF NOT EXISTS named_gaps JSONB NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS timestamp_status TEXT,
    ADD COLUMN IF NOT EXISTS timestamp_evidence JSONB;

-- Backstops against raw SQL: a package row may only claim a validation
-- outcome this build knows, and a timestamp status only one of the three
-- honestly reachable states. A non-empty named-gap list rules out 'valid'
-- because a package carrying a named gap is not submittable.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'filing_submission_packages_validation_outcome_check'
    ) THEN
        ALTER TABLE filing_submission_packages
            ADD CONSTRAINT filing_submission_packages_validation_outcome_check
            CHECK (
                validation_outcome IS NULL
                OR validation_outcome IN ('valid', 'invalid')
            );
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'filing_submission_packages_timestamp_status_check'
    ) THEN
        ALTER TABLE filing_submission_packages
            ADD CONSTRAINT filing_submission_packages_timestamp_status_check
            CHECK (
                timestamp_status IS NULL
                OR timestamp_status IN ('obtained', 'not_configured', 'failed')
            );
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'filing_submission_packages_valid_outcome_has_no_gaps'
    ) THEN
        ALTER TABLE filing_submission_packages
            ADD CONSTRAINT filing_submission_packages_valid_outcome_has_no_gaps
            CHECK (
                validation_outcome IS DISTINCT FROM 'valid'
                OR named_gaps = '[]'::jsonb
            );
    END IF;
END $$;

COMMENT ON COLUMN filing_submission_packages.form IS
    'Filing form identity (kmd, kmd_inf, tsd, vd, oss) recorded with the package; NULL only for rows created before package validation.';
COMMENT ON COLUMN filing_submission_packages.validation_report IS
    'Per-field validation report (filing_package::ValidationReport) as JSONB: every required field with present/absent, refusal problems, warnings.';
COMMENT ON COLUMN filing_submission_packages.validation_outcome IS
    'Overall verdict: valid or invalid. NULL for rows created before package validation; the transport treats NULL as not validated.';
COMMENT ON COLUMN filing_submission_packages.named_gaps IS
    'Legally required fields no repository model can supply (filing_package::NamedGap list). A non-empty list makes the package non-submittable.';
COMMENT ON COLUMN filing_submission_packages.timestamp_status IS
    'RFC 3161 timestamp outcome for the package digest: obtained, not_configured (no TSA configured) or failed. Never NULL for packages created by this build.';
COMMENT ON COLUMN filing_submission_packages.timestamp_evidence IS
    'The RFC 3161 evidence record (filing_package::TimestampRecord): nonce, genTime, policy OID, signer certificate summary, per-check verdicts, proven/not-proven property lists. Null when no timestamp was obtained.';
