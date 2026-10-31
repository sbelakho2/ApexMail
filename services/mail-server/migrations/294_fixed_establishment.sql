-- Migration 294: customer fixed-establishment declaration (VAT Directive
-- Art. 44 second limb).
-- ============================================================================
-- The 30 Oct 2026 deep legal review (VATDEEP-B) found the one FE direction
-- that costs the SUPPLIER money: a customer whose business establishment is
-- abroad but whose fixed establishment receiving the service is in Estonia.
-- The supply is then Estonian (Art. 44: the establishment FOR WHICH the
-- service is supplied), Art. 196 does not apply, and the supplier owes the
-- 24 % EE VAT out of its own pocket — with interest and penalties — if it
-- reverse-charged instead.
--
-- Minimal viable policy (the memo's recommendation, matching what
-- Stripe-Tax-style engines implement):
--   * one written declaration at checkout/business signup, stored here;
--   * the quoting branch: declared FE in Estonia -> charge 24 % EE VAT;
--     declared FE in another member state -> reverse charge against that
--     state (invoice shows the FE country's VAT number per Art. 226(4) —
--     a follow-up collects that number; today the declared number rides);
--     no declaration -> the business establishment stands (Art. 22(3)
--     safe harbour: subscriptions used in an unidentifiable, non-quantifiable
--     manner).
-- Red flags (billing/VAT country mismatch, third-country payer) raise a
-- review question, never an automatic reclassification (Dong Yang).
-- ============================================================================

ALTER TABLE billing_addresses
    ADD COLUMN IF NOT EXISTS fixed_establishment_country VARCHAR(2);
ALTER TABLE billing_addresses
    ADD COLUMN IF NOT EXISTS fe_declared_at TIMESTAMPTZ;
ALTER TABLE billing_addresses
    ADD COLUMN IF NOT EXISTS fe_declaration_terms_version TEXT;

COMMENT ON COLUMN billing_addresses.fixed_establishment_country IS
    'ISO country of the fixed establishment that RECEIVES the service, per the customer''s written declaration (VAT Directive Art. 44 second limb; Reg 282/2011 Art. 11(1)). NULL = the business establishment stands (Art. 22(3) safe harbour). An EE value flips the supply domestic: the supplier charges 24 % EE VAT instead of reverse-charging.';
COMMENT ON COLUMN billing_addresses.fe_declared_at IS
    'When the customer made the fixed-establishment declaration (the audit trail; Art 23(2) due diligence).';
COMMENT ON COLUMN billing_addresses.fe_declaration_terms_version IS
    'Version of the declaration wording the customer accepted, so the terms in force at the tax point can be reconstructed.';

-- Proof block: the country code shape is what the quoting branch keys on.
DO $$
DECLARE
    bad int;
BEGIN
    SELECT count(*) INTO bad FROM billing_addresses
    WHERE fixed_establishment_country IS NOT NULL
      AND fixed_establishment_country !~ '^[A-Z]{2}$';
    IF bad <> 0 THEN
        RAISE EXCEPTION 'migration 294: % fixed_establishment_country value(s) are not ISO-2', bad;
    END IF;
END $$;
