-- Migration 287: the accounting ledger's chart vocabulary goes
-- provider-generic (NEUTRALITY-DEBT row N-12).
-- =============================================================================
-- Audit wave "finish all" (eighth external audit, item 10 / NEUTRALITY-DEBT
-- row N-12). Migration 281 added the GENERIC chart roles
-- ('processor_clearing', 'processor_fees') and settlement source types
-- ('processor_settlement') to the ledger's CHECK allowlists and stamped the
-- provider dimension on every ledger table; step 10 moved billing-service's
-- writers onto the generic vocabulary. This migration moves the SEEDED chart
-- rows themselves: the per-provider role names were the last provider-tagged
-- vocabulary the statutory ledger carries.
--
-- * chart_of_accounts rows seeded as 'mollie_clearing'/'mollie_fees' (and the
--   symmetric 'stripe_*' names the pre-neutrality era allowed) become
--   'processor_clearing'/'processor_fees'. The role is the LOOKUP key
--   (resolve_account_role), not a historical fact: journal lines reference
--   account_id, so renaming the role re-points future postings onto the SAME
--   accounts with a provider-neutral name. No journal history is rewritten.
-- * accounting_source_documents source types are HISTORY and are NOT
--   rewritten ('mollie_settlement' documents stay what they were). New
--   settlement documents are written as 'processor_settlement' (in the 281
--   allowlist), and the settlement sweep's claim filter accepts BOTH
--   spellings so historical documents keep satisfying their allocations'
--   idempotency probes.
--
-- Idempotent by construction (guarded UPDATEs, migration-269 house pattern).
-- =============================================================================

-- 1. Chart roles → the generic vocabulary (rows may not exist in ledgers
--    provisioned after 281; guarded anyway).
UPDATE chart_of_accounts SET account_role = 'processor_clearing'
WHERE account_role IN ('mollie_clearing', 'stripe_clearing');

UPDATE chart_of_accounts SET account_role = 'processor_fees'
WHERE account_role IN ('mollie_fees', 'stripe_fees');

-- 2. Processor clearing accounts: the provider dimension (281) already
--    carries WHICH processor each row clears for; nothing to rewrite here —
--    the table is the provider-aware structure and stays provider-keyed.

-- 3. Proof block: no provider-tagged chart role survives.
DO $$
DECLARE
    leftover int;
BEGIN
    SELECT count(*) INTO leftover FROM chart_of_accounts
    WHERE account_role IN ('mollie_clearing', 'mollie_fees',
                           'stripe_clearing', 'stripe_fees');
    IF leftover <> 0 THEN
        RAISE EXCEPTION 'migration 287: % provider-tagged chart role(s) survived the rename', leftover;
    END IF;
END $$;
