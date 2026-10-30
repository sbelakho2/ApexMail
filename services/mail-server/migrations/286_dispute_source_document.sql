-- Migration 286: the dispute evidence document (payment-neutrality step 10,
-- NEUTRALITY_DEBT row N-13).
--
-- The generic dispute path (payments::engine::observe_dispute) ledgers the
-- dispute FACT (`payment_disputes` + `payment_provider_events`) and posts
-- the statutory debit/restoration journals, but those journals carried NO
-- registered source document: `accounting_source_documents.source_type` had
-- no dispute value in the allowlist, so the entries fell back to the
-- manual-entry content hash with only the `dispute:{provider}:{id}:{outcome}`
-- idempotency key anchoring them. This migration adds the `dispute`
-- source_type to the allowlist; the engine writer (this same wave) then
-- registers a REAL evidence row per dispute outcome whose content is the
-- dispute fact JSON.
--
-- Additive and guarded (the migration-269/281 pattern): the CHECK is dropped
-- and re-added by constraint name, every historical value stays, a re-run or
-- a partially migrated database converges to the same schema.

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_constraint
               WHERE conname = 'accounting_source_documents_source_type_check') THEN
        ALTER TABLE accounting_source_documents DROP CONSTRAINT accounting_source_documents_source_type_check;
    END IF;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conname = 'accounting_source_documents_source_type_check') THEN
        ALTER TABLE accounting_source_documents ADD CONSTRAINT accounting_source_documents_source_type_check
            CHECK (source_type = ANY (ARRAY[
                'invoice','credit_note','credit_note_refund','stripe_settlement',
                'mollie_settlement','processor_settlement','wallet_settlement',
                'manual_settlement','expense','bank_statement_line','payroll','tax',
                'manual','opening_balance','depreciation','fx_revaluation','reversal',
                'closing','dispute']));
    END IF;
END $$;

COMMENT ON CONSTRAINT accounting_source_documents_source_type_check ON accounting_source_documents IS
    'Registered statutory source-document types (migration 286 added `dispute`): the chargeback debit/restoration journals register their evidence on accounting_source_documents with source_type=dispute, keyed by the dispute outcome idempotency, instead of the manual-entry fallback (NEUTRALITY-DEBT N-13).';

-- Proof: the allowlist accepts the dispute evidence type and the historical
-- values are intact.
DO $$
DECLARE
    constraint_def TEXT;
    kept INTEGER;
BEGIN
    SELECT pg_get_constraintdef(oid) INTO constraint_def
    FROM pg_constraint
    WHERE conname = 'accounting_source_documents_source_type_check';
    IF constraint_def IS NULL THEN
        RAISE EXCEPTION 'migration 286: accounting_source_documents_source_type_check must exist';
    END IF;
    IF constraint_def NOT ILIKE '%dispute%' THEN
        RAISE EXCEPTION 'migration 286: the source_type allowlist must accept dispute evidence';
    END IF;
    SELECT count(*) INTO kept
    FROM pg_constraint
    WHERE conname = 'accounting_source_documents_source_type_check'
      AND pg_get_constraintdef(oid) ILIKE '%mollie_settlement%'
      AND pg_get_constraintdef(oid) ILIKE '%processor_settlement%'
      AND pg_get_constraintdef(oid) ILIKE '%manual%';
    IF kept <> 1 THEN
        RAISE EXCEPTION 'migration 286: the historical source_type values must stay in the allowlist';
    END IF;
END $$;
