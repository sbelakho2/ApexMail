-- Migration 288: the buyer's tax status is a stored billing fact (V30 / MON-10).
-- =============================================================================
-- The VAT rule for list prices depends on WHO buys:
--
--   * a BUSINESS with a VIES-verified cross-border EU VAT number pays the
--     net list price (reverse charge, 0 %);
--   * an Estonian business or an unverified business pays list + VAT;
--   * a CONSUMER pays list + destination VAT, displayed and charged as one
--     VAT-inclusive total;
--   * a non-EU business pays the net list price.
--
-- Deciding that per invoice requires the buyer's BUSINESS status to survive
-- from checkout to the tax point (renewals included): the VAT number alone
-- cannot distinguish a consumer from a business, and inferring it from a
-- non-empty company name would silently reverse-charge consumers. The
-- billing address therefore carries the buyer's declaration.
--
-- `billing_addresses.vat_number` and `.country` already exist (migrations
-- 069/132); authoritative VIES evidence continues to live in
-- `vat_validation_evidence` (migration 213), and invoices snapshot the
-- evidence id they relied on (`invoices.vat_evidence_id`, migration 218).
--
-- Idempotent (ADD COLUMN IF NOT EXISTS), safe on a live table: the default
-- keeps every existing row on the consumer branch (VAT added, never
-- reverse-charged) until an operator/business declaration flips it.
-- =============================================================================

ALTER TABLE billing_addresses
    ADD COLUMN IF NOT EXISTS is_business BOOLEAN NOT NULL DEFAULT FALSE;

COMMENT ON COLUMN billing_addresses.is_business IS
    'Buyer-declared business status used by the V30 list-price VAT rule: '
    'business prices are net (reverse charge only with VIES evidence); '
    'consumers are charged list + destination VAT as one total.';
